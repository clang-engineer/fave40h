#!/usr/bin/env python3
"""Original hidden mode29 static signature + bounded interval differential probe.

NOT a full animation, QMK/HAL, clock or device test. No target files are changed.
"""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from prepare_original_target import REVISION, validate_reference
from recover_original_vial import parse_uf2, recover

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_SHA = "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4"
WITNESSES = {
    0x08014ADE: "019b2d2b33d8dfe813f0",
    0x08014F58: "dff83c91dff808a1d9f80020daf800309a423ff6efadab78464e43bb",
    0x08014F96: "b8f1470f94bf0124002400f2ac80",
    0x08014FC6: "002211461046fdf7fcff34464ff048084ff0000bfff791fc83070dd584f800b084f801b084f802b008f1ff3818f0ff0804f10304eed1bae7fff77ffc0290",
    0x08015004: "8020fff78dfcfa78029b8df844307f308df846208df845001198fff7cffbc0f30722c0f3074320706270a370dde7",
    0x08015032: "0beb000393f8c0206b781a4206d0a378627821780290fff716fd0298033401309de7",
    0x0801509C: "01eb4100013101eb4101032231443044fcf7f0fbe9b2414505f10105f0db",
    0x080150D8: "3b791033ff2b28bfff2303eb031340f6b8321b12b2fbf3f3daf800201344c9f80030",
    0x080150FC: "002508f1ff38d5e7",
}
LITERALS = {0x08015098: 0x20002180, 0x08015068: 0x200018E0,
            0x0801508C: 0x20001B55, 0x08015088: 0x0801DEA0}


def inspect_mode29_image(image):
    """Instruction-backed facts, separately callable for mutation regressions."""
    for address, witness in WITNESSES.items():
        if image.read(address, len(witness) // 2) != bytes.fromhex(witness):
            raise ValueError(f"Changed original mode29 instruction witness: {address:08X}")
    target = 0x08014AE8 + 2 * struct.unpack("<H", image.read(0x08014AE8 + 29 * 2, 2))[0]
    if target != 0x08014F58:
        raise ValueError("Changed original mode29 jump-table target")
    for address, value in LITERALS.items():
        if struct.unpack("<I", image.read(address, 4))[0] != value:
            raise ValueError(f"Changed original mode29 literal: {address:08X}")
    return {"renderer_entry": "0x08015618", "effect_dispatch_entry": "0x08014AA4",
            "jump_table": "0x08014AE8", "mode": 29, "case_entry": f"0x{target:08X}",
            "led_state_ram": "0x20001B55", "led_state_bytes": 216, "led_count": 72,
            "wait_timer_ram": "0x20002180", "rgb_frame_timer_ram": "0x200018E0",
            "wait_gate": "unsigned wait_timer > frame_timer skips before init",
            "init": "clear output, then fill72 RGB states with black or HSV conversion; byte RNG bit1 selects black",
            "render": "15-LED chunks; emit stored RGB for matching LED flags",
            "finish": "after last chunk, shift71 three-byte states toward index0 and refill index71",
            "next_wait": "uint32(now + 3000 / ((min(speed+16,255)*17)>>8))",
            "instruction_witnesses": {f"0x{a:08X}": v for a, v in WITNESSES.items()},
            "scope": "instruction-backed structural PixelFlow match, not manufacturer source/name/version or full execution parity"}


def pinned_source(reference, relative, hashes):
    # Sparse reference checkout: missing working files may be read from the
    # already-local immutable git object; no checkout, download or installation.
    expected = subprocess.check_output(["git", "-C", str(reference), "show", f"{REVISION}:{relative}"])
    path = reference / relative
    if path.exists() and path.read_bytes() != expected:
        raise ValueError(f"Changed pinned mode29 source: {relative}")
    hashes[relative] = hashlib.sha256(expected).hexdigest()
    return expected.decode()


def math_sources(reference, temp):
    hashes = {}
    for name in ("lib8tion.h", "math8.h", "scale8.h", "random8.h", "trig8.h"):
        (temp / name).write_text(pinned_source(reference, "lib/lib8tion/" + name, hashes))
    common = pinned_source(reference, "builddefs/common_features.mk", hashes)
    if "OPT_DEFS += -DFASTLED_SCALE8_FIXED=1 -DFASTLED_BLEND_FIXED=1" not in common:
        raise ValueError("Unmodeled QMK fixed-scale build flags")
    return hashes


def interval_program(reference, temp):
    hashes = math_sources(reference, temp)
    flow = pinned_source(reference, "quantum/rgb_matrix/animations/pixel_flow_anim.h", hashes)
    interval = re.search(r"inline uint32_t interval\(void\) \{[^}]+\}", flow)
    if not interval:
        raise ValueError("Missing actual PixelFlow nested interval function")
    for signature in ("static rgb_t led[RGB_MATRIX_LED_COUNT]", "if (wait_timer > g_rgb_timer)",
                      "led[j] = led[j + 1]", "random8_min_max(127, 255)"):
        if signature not in flow:
            raise ValueError("Changed candidate PixelFlow structure")
    source = temp / "interval.c"
    source.write_text('#include "lib8tion.h"\n'
                      'static struct { uint8_t speed; } rgb_matrix_config;\n'
                      'uint32_t probe_wait(uint8_t speed,uint32_t now) {\n'
                      'rgb_matrix_config.speed=speed;\n' + interval[0] + '\nreturn now+interval();\n}\n')
    return source, hashes


def compare_interval(lib, cases):
    lib.probe_wait.argtypes = [ctypes.c_uint8, ctypes.c_uint32]
    lib.probe_wait.restype = ctypes.c_uint32
    return sum(lib.probe_wait(c["speed"], c["now"]) != c["next_wait"] for c in cases)


def audit(raw, reference):
    recover(raw)
    original = inspect_mode29_image(parse_uf2(raw))
    validate_reference(reference)
    oracle = json.loads((ROOT / "tests/fixtures/original-rgb-mode29-interval.json").read_text())
    cases = oracle["rgb_mode29_interval"]
    expected = set(itertools.product(range(256), (0, 1, 0xFFFFFF00, 0xFFFFFFFF)))
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(cases) != 1024 or {(c["speed"], c["now"]) for c in cases} != expected:
        raise ValueError("Incomplete original mode29 interval oracle")
    gcc = next((shutil.which(name) for name in ("gcc-16", "gcc-15", "gcc-14", "gcc-13") if shutil.which(name)), None)
    if not gcc:
        raise RuntimeError("Existing GNU host compiler required for unmodified nested function; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-mode29-") as folder:
        temp = Path(folder)
        source, hashes = interval_program(reference, temp)
        differences = {}
        for tag, fixed, opt in (("fixed", 1, "-O0"), ("optimized", 1, "-O2"), ("nonfixed", 0, "-O0")):
            output = temp / (tag + ".so")
            subprocess.run([gcc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt,
                            f"-DFASTLED_SCALE8_FIXED={fixed}", "-DFASTLED_BLEND_FIXED=1",
                            "-shared", "-fPIC", "-I", str(temp), str(source), "-o", str(output)], check=True)
            differences[tag] = compare_interval(ctypes.CDLL(str(output)), cases)
        if differences["fixed"] or differences["optimized"] or not differences["nonfixed"]:
            raise AssertionError(f"Mode29 interval differential failed: {differences}")
    return {"original": original, "candidate_revision": REVISION, "source_sha256": hashes,
            "host_compiler": gcc, "interval_cases_matched": 1024, "optimized_interval_cases_matched": 1024,
            "nonfixed_scale_negative_differences": differences["nonfixed"],
            "candidate_nested_interval_and_math_executed": True, "full_animation_executed": False,
            "original_thumb_executed_by_this_command": False, "target_changes_applied": False,
            "scope": "original interval fixture vs exact candidate nested interval + pinned lib8tion math headers; speed field is a controlled shim, no complete config ABI, RNG/HSV/init/state/render/clock/HAL/device validation",
            "sentinel": "ORIGINAL_RGB_MODE29_AUDIT_COMPLETE"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir), indent=2))


if __name__ == "__main__":
    main()
