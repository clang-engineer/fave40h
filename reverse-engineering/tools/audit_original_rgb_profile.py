#!/usr/bin/env python3
"""Read-only original RGB defaults/catalog audit; NOT an animation/HAL test.

Default mode compiles the proposed enum-compatible profile; --target compiles
actual target config/post-config. Neither identifies manufacturer source revision
or proves effect behavior; separate execution probes establish selected cases.
No target configuration, source checkout, EEPROM or device is changed.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from prepare_original_target import REVISION, validate_reference
from recover_original_vial import parse_uf2, recover

WITNESSES = {
    0x08013CD8: "08b5082203481721fff7deff024b00221a7008bde01c002006170020",
    0x08013CF4: "10b5084c084920463d2300f8013b0322fdf7c4fd4ff68073a380bde81040fff7e1bf00bfe01c002008d90108",
    # LDR r8,[198D0] -> E5EC; indexed halfwords stride4; loop count45.
    0x08019772: "dff85c81adf836301e22ff210df15200f8f79bf900270df152031e2538f82720bdf83610adf8442091420ad2012d08d91846022211a9f8f772f8023d0346edb2023301372d2fe9d113e7",
}
TABLE_ADDRESS = 0x0801E5EC
TABLE_COUNT = 45


def original_profile(raw):
    recover(raw)  # Strict original-only UF2/payload identity and instruction guards.
    image = parse_uf2(raw)
    for address, witness in WITNESSES.items():
        if image.read(address, len(witness) // 2) != bytes.fromhex(witness):
            raise ValueError(f"Changed original RGB instruction witness: {address:08X}")
    hsv = image.read(0x0801D908, 3)
    if hsv != bytes.fromhex("00ffff"):
        raise ValueError("Changed original RGB HSV literal")
    table = image.read(TABLE_ADDRESS, TABLE_COUNT * 4)
    rows = list(struct.iter_unpack("<HH", table))
    if [row[0] for row in rows] != list(range(45)):
        raise ValueError("Unmodeled VialRGB catalog order")
    return {
        "reset_entry": "0x08013CF4", "config_ram": "0x20001CE0",
        "written_prefix_hex": (b"\x3d" + hsv + b"\x80\xff").hex(),
        "written_byte_offsets": list(range(6)),
        "padding_byte_offsets_untouched": [6, 7],
        "save_logical_address": "0x17", "save_length": 8,
        "vialrgb_table_address": f"0x{TABLE_ADDRESS:08X}", "vialrgb_table_hex": table.hex(),
        "vialrgb_pairs": rows,
        "scope": "static reset/save/45-entry-reader witnesses; no original Thumb execution or physical storage IO in this audit",
    }


def checked_source(reference, relative, hashes):
    """Validate even animation headers against the selected immutable git object."""
    expected = subprocess.check_output(["git", "-C", str(reference), "show", f"{REVISION}:{relative}"])
    actual = (reference / relative).read_bytes()
    if actual != expected:
        raise ValueError(f"Changed candidate profile source: {relative}")
    hashes[relative] = hashlib.sha256(actual).hexdigest()
    return actual.decode()


def match(pattern, content):
    found = re.search(pattern, content, re.S | re.M)
    if not found:
        raise ValueError(f"Unmodeled pinned RGB source pattern: {pattern}")
    return found[0]


def candidate_program(reference, temp, target=None):
    hashes = {}
    read = lambda path: checked_source(reference, path, hashes)
    matrix_header = read("quantum/rgb_matrix/rgb_matrix.h")
    types = read("quantum/rgb_matrix/rgb_matrix_types.h")
    color = read("quantum/color.h")
    implementation = read("quantum/rgb_matrix/rgb_matrix.c")
    vial = read("quantum/vialrgb_effects.inc")
    effects = read("quantum/rgb_matrix/animations/rgb_matrix_effects.inc")
    (temp / "rgb_matrix_effects.inc").write_text(effects)
    (temp / "vialrgb_effects.inc").write_text(vial)
    for name in re.findall(r'^#include "([a-z_]+\.h)"', effects, re.M):
        (temp / name).write_text(read("quantum/rgb_matrix/animations/" + name))
    # Only stable Vial-mapped names, NOT every effect offered by the newer base.
    names = sorted(set(re.findall(r'\{ VIALRGB_EFFECT_\w+, RGB_MATRIX_(\w+) \}', vial)))
    optional = [name for name in names if name not in ("SOLID_COLOR", "VIALRGB_DIRECT")]
    defines = "\n".join("#define ENABLE_RGB_MATRIX_" + name for name in optional)
    support = '#define RGB_MATRIX_FRAMEBUFFER_EFFECTS\n#define RGB_MATRIX_KEYREACTIVE_ENABLED\n#define VIALRGB_ENABLE\n'
    flow_define = '''#ifndef PROBE_OMIT_PIXEL_FLOW
#define ENABLE_RGB_MATRIX_PIXEL_FLOW
#endif
'''
    if target is not None:
        config = (target / "config.h").read_text()
        rules = (target / "keymaps/vial/rules.mk").read_text()
        if not re.search(r"(?m)^VIALRGB_ENABLE\s*=\s*yes\s*$", rules):
            raise ValueError("Target does not declare VialRGB enabled")
        (temp / "target_config.h").write_text(config)
        (temp / "rgb_post_config.h").write_text(read("quantum/rgb_matrix/post_config.h"))
        reactive = match(r"#if defined\(RGB_MATRIX_KEYPRESSES\).*?^#endif", types)
        support = '#include "target_config.h"\n#include "rgb_post_config.h"\n' + reactive + '\n#define VIALRGB_ENABLE\n'
        defines = ""  # Never inject the proposed effect list into target probe.
        flow_define = '''#ifdef PROBE_OMIT_PIXEL_FLOW
#undef ENABLE_RGB_MATRIX_PIXEL_FLOW
#endif
'''
    enum = match(r'enum rgb_matrix_effects \{.*?^\};', matrix_header)
    config_type = match(r'typedef union rgb_config_t \{.*?\} rgb_config_t;', types)
    hsv_type = match(r'typedef struct PACKED hsv_t \{.*?\} hsv_t;', color)
    default_macros = matrix_header[matrix_header.index("#ifndef RGB_MATRIX_DEFAULT_ON"):
                                   matrix_header.index("#ifndef RGB_MATRIX_LED_FLUSH_LIMIT")]
    reset = match(r'void eeconfig_update_rgb_matrix_default\(void\) \{.*?^\}', implementation)
    program = '''#include <stdint.h>
#include <stdbool.h>
#define PACKED __attribute__((packed))
#define PROGMEM
''' + support + '''
#define RGB_MATRIX_MAXIMUM_BRIGHTNESS UINT8_MAX
#define LED_FLAG_ALL 0xFF
#define dprintf(...)
''' + defines + '''
// Unmapped slot29: candidate PIXEL_FLOW is required for enum compatibility.
// This does NOT identify the original hidden animation implementation.
''' + flow_define + enum + '\n' + hsv_type + '\ntypedef uint8_t led_flags_t;\n' + config_type + '''
_Static_assert(sizeof(rgb_config_t)==8,"RGB config size");
typedef struct { uint16_t vialrgb_id,qmk_id; } vialrgb_supported_mode_t;
#include "vialrgb_effects.inc"
#ifdef PROBE_DROP_DEFAULTS
#undef RGB_MATRIX_DEFAULT_MODE
#undef RGB_MATRIX_DEFAULT_SPD
#endif
#ifdef PROBE_CORRECT_DEFAULTS
#define RGB_MATRIX_DEFAULT_MODE RGB_MATRIX_RAINBOW_MOVING_CHEVRON
#define RGB_MATRIX_DEFAULT_SPD 128
#endif
''' + default_macros + '''
rgb_config_t rgb_matrix_config;
uint8_t probe_saved[8];
uint32_t probe_save_calls,probe_force;
static void eeconfig_flush_rgb_matrix(bool force) {
    ++probe_save_calls; probe_force=force;
    for(unsigned i=0;i<8;i++) probe_saved[i]=((uint8_t *)&rgb_matrix_config)[i];
}
''' + reset + '''
void probe_reset(uint8_t fill) {
    for(unsigned i=0;i<8;i++) ((uint8_t *)&rgb_matrix_config)[i]=fill;
    ((uint8_t *)&rgb_matrix_config)[7]=(uint8_t)(fill^0x5A);
    probe_save_calls=probe_force=0;
    eeconfig_update_rgb_matrix_default();
}
const void *probe_modes(void) { return supported_modes; }
uint32_t probe_modes_size(void) { return sizeof(supported_modes); }
uint32_t probe_mode_limit(void) { return RGB_MATRIX_EFFECT_MAX; }
uint32_t probe_support_flags(void) {
    uint32_t flags=0;
#ifdef RGB_MATRIX_FRAMEBUFFER_EFFECTS
    flags|=1;
#endif
#ifdef RGB_MATRIX_KEYREACTIVE_ENABLED
    flags|=2;
#endif
#ifdef RGB_MATRIX_KEYPRESSES
    flags|=4;
#endif
#ifdef RGB_MATRIX_KEYRELEASES
    flags|=8;
#endif
#ifdef VIALRGB_ENABLE
    flags|=16;
#endif
    return flags;
}
uint32_t probe_dimensions(void) {
#if defined(RGB_MATRIX_LED_COUNT) && defined(RGB_MATRIX_LED_PROCESS_LIMIT) && defined(LED_HITS_TO_REMEMBER)
    return (RGB_MATRIX_LED_COUNT<<16)|(RGB_MATRIX_LED_PROCESS_LIMIT<<8)|LED_HITS_TO_REMEMBER;
#else
    return 0;
#endif
}
'''
    source = temp / "profile.c"
    source.write_text(program)
    return source, hashes, optional


def run_profile(cc, source, temp, tag, definitions):
    library = temp / (tag + ".dylib")
    subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    "-I", str(temp), *definitions, str(source), "-o", str(library)], check=True)
    lib = ctypes.CDLL(str(library))
    lib.probe_modes.restype = ctypes.c_void_p
    lib.probe_modes_size.restype = ctypes.c_uint32
    lib.probe_reset.argtypes = [ctypes.c_uint8]
    lib.probe_reset.restype = None
    table = ctypes.string_at(lib.probe_modes(), lib.probe_modes_size())
    prefix = None
    for fill in range(256):
        lib.probe_reset(fill)
        saved = bytes((ctypes.c_uint8 * 8).in_dll(lib, "probe_saved"))
        if saved[6:] != bytes([fill, fill ^ 0x5A]) or ctypes.c_uint32.in_dll(lib, "probe_save_calls").value != 1 or ctypes.c_uint32.in_dll(lib, "probe_force").value != 1:
            raise AssertionError("Reset changed padding or captured save request")
        if prefix is not None and saved[:6] != prefix:
            raise AssertionError("Factory fields depend on pre-reset bytes")
        prefix = saved[:6]
    return {"table_hex": table.hex(), "default_prefix_hex": prefix.hex(),
            "mode_limit": lib.probe_mode_limit(), "padding_fill_cases": 256,
            "support_flags": lib.probe_support_flags(), "dimensions": lib.probe_dimensions()}


def validate_target_profile(actual, original, enabled, expected):
    if len(enabled) != 43 or set(enabled) != set(expected):
        raise AssertionError("Target effect bindings differ from pinned Vial catalog")
    if (actual["table_hex"] != original["vialrgb_table_hex"] or actual["mode_limit"] != 46 or
            actual["default_prefix_hex"] != original["written_prefix_hex"] or actual["support_flags"] != 23 or
            actual["dimensions"] != 0x480F08):
        raise AssertionError(f"Target config/catalog/default/support mismatch: {actual}")


def audit_target(raw, reference, target, arm_object=None):
    """Compile actual target config/post-config, NOT the proposed manual profile."""
    original = original_profile(raw)
    validate_reference(reference)
    cc = shutil.which("cc")
    if not cc:
        raise RuntimeError("Existing host C compiler required; nothing installed")
    target_inputs = {p: (target / p).read_bytes() for p in ("config.h", "rules.mk", "keymaps/vial/rules.mk")}
    root_rules = target_inputs["rules.mk"].decode()
    active = [line.strip() for line in root_rules.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not active or not active[0].startswith("$(error ORIGINAL_TARGET_INCOMPLETE:") or not re.search(r"(?m)^RGB_MATRIX_ENABLE\s*=\s*yes\s*$", root_rules):
        raise ValueError("Target must retain unconditional guard and declare RGB matrix enabled")
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-target-profile-") as folder:
        temp = Path(folder)
        source, hashes, optional = candidate_program(reference, temp, target)
        base = run_profile(cc, source, temp, "target", [])
        missing = run_profile(cc, source, temp, "without-flow", ["-DPROBE_OMIT_PIXEL_FLOW"])
        defaults = run_profile(cc, source, temp, "without-defaults", ["-DPROBE_DROP_DEFAULTS"])
        if arm_object:
            clang = shutil.which("clang")
            if not clang:
                raise RuntimeError("Existing Clang required for optional ARM declaration/reset probe")
            output = temp / "target-profile.o"
            subprocess.run([clang, "--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-ffreestanding",
                            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", str(temp),
                            "-c", str(source), "-o", str(output)], check=True)
            with arm_object.open("xb") as stream:
                stream.write(output.read_bytes())
    if any((target / p).read_bytes() != content for p, content in target_inputs.items()):
        raise ValueError("Target profile inputs changed during native verification")
    enabled = re.findall(r"(?m)^#define ENABLE_RGB_MATRIX_(\w+)\s*$", target_inputs["config.h"].decode())
    validate_target_profile(base, original, enabled, optional + ["PIXEL_FLOW"])
    if missing["table_hex"] == base["table_hex"] or defaults["default_prefix_hex"] == base["default_prefix_hex"]:
        raise AssertionError("Target catalog/default negative controls ineffective")
    return {"candidate_revision": REVISION, "source_sha256": hashes,
            "target_sha256": {p: hashlib.sha256(content).hexdigest() for p, content in target_inputs.items()},
            "target_profile": base, "negative_without_flow_differs": True, "arm_probe_object": str(arm_object) if arm_object else None,
            "negative_without_defaults_prefix": defaults["default_prefix_hex"],
            "scope": "actual target config plus actual post_config and reactive guard, declared RGB/VialRGB flags and unconditional guard, unmodified enum/Vial table/reset body with256 padding canaries; not full Make resolution, effect body/pipeline/storage/clock/HAL/firmware or device execution",
            "sentinel": "ORIGINAL_RGB_TARGET_PROFILE_AUDIT_COMPLETE"}


def audit(raw, reference, arm_object=None):
    original = original_profile(raw)
    validate_reference(reference)
    cc = shutil.which("cc")
    if not cc:
        raise RuntimeError("Existing host C compiler required; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-profile-") as folder:
        temp = Path(folder)
        source, hashes, optional = candidate_program(reference, temp)
        base = run_profile(cc, source, temp, "base", [])
        corrected = run_profile(cc, source, temp, "corrected", ["-DPROBE_CORRECT_DEFAULTS"])
        without_flow = run_profile(cc, source, temp, "without-flow", ["-DPROBE_OMIT_PIXEL_FLOW"])
        if base["table_hex"] != original["vialrgb_table_hex"] or corrected["table_hex"] != original["vialrgb_table_hex"]:
            raise AssertionError("Candidate enum/VialRGB table differs from original")
        if corrected["default_prefix_hex"] != original["written_prefix_hex"]:
            raise AssertionError("Proposed corrected defaults do not match original fields")
        if without_flow["table_hex"] == original["vialrgb_table_hex"]:
            raise AssertionError("Missing hidden slot did not change catalog")
        if arm_object:
            clang = shutil.which("clang")
            if not clang:
                raise RuntimeError("Existing Clang required for optional ARM object")
            output = temp / "profile.o"
            subprocess.run([clang, "--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-ffreestanding",
                            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DPROBE_CORRECT_DEFAULTS", "-I", str(temp),
                            "-c", str(source), "-o", str(output)], check=True)
            with arm_object.open("xb") as stream:
                stream.write(output.read_bytes())
    return {"original": original, "candidate_revision": REVISION, "source_sha256": hashes,
            "proposed_enable_effects": optional + ["PIXEL_FLOW"],
            "probe_only_support_flags": ["RGB_MATRIX_FRAMEBUFFER_EFFECTS", "RGB_MATRIX_KEYREACTIVE_ENABLED", "VIALRGB_ENABLE"],
            "candidate_uncorrected_defaults": base, "candidate_corrected_defaults": corrected,
            "negative_without_pixel_flow_differs": True,
            "target_changes_applied": False, "original_thumb_executed": False,
            "animation_implementations_executed": False, "physical_eeprom_or_device_io": False,
            "scope": "enum/catalog and six reset-field compatibility only; candidate PixelFlow fills unexposed slot29 but original hidden-mode name/behavior is NOT established; reactive edge policy is outside this audit (see separate event oracle); full effects/pipeline/flush/storage unverified",
            "arm_probe_object": str(arm_object) if arm_object else None,
            "sentinel": "ORIGINAL_RGB_PROFILE_AUDIT_COMPLETE"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--arm-object", type=Path)
    parser.add_argument("--target", type=Path, help="Compare actual target config/post-config, not the proposed profile")
    args = parser.parse_args()
    if args.arm_object and args.arm_object.exists():
        parser.error("Refusing to overwrite ARM object")
    result = (audit_target(args.uf2.read_bytes(), args.reference_dir, args.target, args.arm_object) if args.target else
              audit(args.uf2.read_bytes(), args.reference_dir, args.arm_object))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
