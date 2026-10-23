#!/usr/bin/env python3
"""Original pre-dispatch init/enable/flags clear vs actual SDK source prefix.

Stops before effects; not caller selection, whole rendering/task/HAL or firmware.
"""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from audit_original_rgb_mode15_staging import stage_program
from audit_original_rgb_mode29_staging import inspect_all_staging
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA
from audit_original_rgb_profile import audit_target, checked_source, match
from prepare_original_target import REVISION, REFERENCE_HASHES, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2

FLAG_LEVELS = (0, 1, 2, 4, 128, 255)
ITER_LEVELS = (0, 4, 255)
CONTEXTS = ((15, 15, 1, 1), (29, 15, 1, 1), (15, 15, 2, 1))


def grid():
    init = [("init", *values, 255, 255, it) for values in itertools.product((0, 15, 29, 45), (0, 15, 29, 45, 255), range(4), (0, 1, 2, 3, 255)) for it in ITER_LEVELS]
    flags = [("flags", *ctx, old, new, it) for ctx in CONTEXTS for old, new, it in itertools.product(FLAG_LEVELS, FLAG_LEVELS, ITER_LEVELS)]
    return init + flags


def inspect_begin(image):
    inspect_all_staging(image)
    for address, expected in ((0x08014AA4, "2de9f04fac4bad4f1b7893b08342019046d1ab4a3b78127803f003039b1a18bf0123a84d6a78ab707b799a4205d00022114610466b70fef775fa"),
                              (0x08014B44, "0123bee7"), (0x08014D5C, "eb0e0020e01c0020ec0e0020e80e0020")):
        if image.read(address, len(expected) // 2).hex() != expected:
            raise ValueError("Changed original pre-dispatch code/literals")


def validate_oracle(oracle):
    rows = oracle["rgb_render_begin"]
    keys = ("grid", "effect", "last_effect", "enable", "last_enable", "old_flags", "new_flags", "iter")
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(rows) != 1524 or [tuple(r[k] for k in keys) for r in rows] != grid():
        raise ValueError("Incomplete render-begin grid")
    return rows


def program(reference, target, temp, negative=None):
    source = stage_program(temp, reference, target)
    hashes = {}
    color = checked_source(reference, "quantum/color.h", hashes)
    types = checked_source(reference, "quantum/rgb_matrix/rgb_matrix_types.h", hashes)
    implementation = checked_source(reference, "quantum/rgb_matrix/rgb_matrix.c", hashes)
    declarations = [match(r"typedef struct PACKED " + name + r" \{.*?\} " + name + ";", color) for name in ("rgb_t", "hsv_t")]
    declarations.append(match(r"typedef union rgb_config_t \{.*?\} rgb_config_t;", types))
    for name in ("rgb_last_effect", "rgb_last_enable"):
        declarations.append(match(r"static uint8_t\s+" + name + r"\s*=\s*UINT8_MAX;", implementation))
    prefix = match(r"    rgb_effect_params.init = .*?(?=    // each effect)", implementation)
    if negative == "ignore_enable":
        prefix = prefix.replace(" || (rgb_matrix_config.enable != rgb_last_enable)", "")
    elif negative == "boolean_enable":
        prefix = prefix.replace("(rgb_matrix_config.enable != rgb_last_enable)", "(!!rgb_matrix_config.enable != !!rgb_last_enable)")
    elif negative == "skip_clear":
        prefix = prefix.replace("rgb_matrix_set_color_all(0, 0, 0);", "(void)0;")
    source.write_text(source.read_text() + '\n' + '\n'.join(declarations) + '''
static rgb_config_t rgb_matrix_config;
static uint32_t begin_clears;
void rgb_matrix_set_color_all(uint8_t r,uint8_t g,uint8_t b) {
    ++begin_clears; ws2812_set_color_all(r,g,b); // Established nonsplit API adapter.
}
static void candidate_render_begin(uint8_t effect) {
''' + prefix + '''
}
STAGE_API void begin_run(uint8_t effect,uint8_t last_effect,uint8_t enable,uint8_t last_enable,uint8_t old_flags,uint8_t new_flags,uint8_t iter) {
    uint8_t cfg[8]={(uint8_t)(60|enable),0,255,255,128,new_flags,0xA5,0xA5};
    uint8_t pixels[216]; for(unsigned i=0;i<216;i++) pixels[i]=(uint8_t)(i*73+19);
    stage_seed(pixels,0xA5B6FF02U,2);
    for(unsigned i=0;i<8;i++) ((uint8_t *)&rgb_matrix_config)[i]=cfg[i];
    rgb_last_effect=last_effect; rgb_last_enable=last_enable;
    rgb_effect_params=(effect_params_t){iter,old_flags,false}; begin_clears=0;
    candidate_render_begin(effect);
    for(unsigned i=0;i<8;i++) if(((uint8_t *)&rgb_matrix_config)[i]!=cfg[i]) __builtin_trap();
    if(rgb_last_effect!=last_effect || rgb_last_enable!=last_enable) __builtin_trap();
}
STAGE_API uint32_t begin_params(void) { return rgb_effect_params.iter | ((uint32_t)rgb_effect_params.flags<<8) | ((uint32_t)rgb_effect_params.init<<16); }
STAGE_API uint32_t begin_clear_calls(void) { return begin_clears; }
_Static_assert(sizeof(rgb_config_t)==8 && sizeof(effect_params_t)==3,"actual SDK packed types");
''')
    return source, hashes


def compare(lib, rows):
    lib.begin_run.argtypes = [ctypes.c_uint8] * 7
    lib.begin_run.restype = None
    lib.begin_params.restype = lib.begin_clear_calls.restype = lib.stage_unexpected_io.restype = ctypes.c_uint32
    lib.stage_group.restype = ctypes.c_uint32
    lib.stage_grb.restype = ctypes.POINTER(ctypes.c_uint8)
    differences = 0
    for row in rows:
        lib.begin_run(*(row[k] for k in ("effect", "last_effect", "enable", "last_enable", "old_flags", "new_flags", "iter")))
        value = lib.begin_params()
        params = bytes((value & 255, (value >> 8) & 255, (value >> 16) & 255))
        digest = hashlib.sha256(bytes(lib.stage_grb()[:216])).hexdigest()
        if lib.stage_unexpected_io() or lib.stage_group() != 0xA5B6FF02:
            raise AssertionError("Render-begin requested EEPROM/HID/timer/DMA IO or changed group")
        differences += params.hex() != row["params_after_hex"] or lib.begin_clear_calls() != row["clear_calls"] or digest != row["grb_sha256"]
    return differences


def audit(raw, reference, target):
    recover(raw); validate_reference(reference); inspect_begin(parse_uf2(raw))
    expected_target = artifacts(raw)
    inputs = {name: (target / name).read_bytes() for name in expected_target}
    if any(content.decode() != expected_target[name] for name, content in inputs.items()):
        raise ValueError("Changed generated target")
    profile = audit_target(raw, reference, target)
    oracle = json.loads((ROOT / "tests/fixtures/original-rgb-render-begin.json").read_text())
    rows = validate_oracle(oracle)
    clang = shutil.which("clang")
    if not clang:
        raise RuntimeError("Existing Clang host compiler required; nothing installed")
    differences = {}
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-render-begin-") as folder:
        for label, opt, negative in (("base", "-O0", None), ("optimized", "-O2", None), ("ignore_enable", "-O0", "ignore_enable"),
                                     ("boolean_enable", "-O0", "boolean_enable"), ("skip_clear", "-O0", "skip_clear")):
            temp = Path(folder) / label; temp.mkdir()
            source, hashes = program(reference, target, temp, negative)
            output = temp / "begin.so"
            subprocess.run([clang, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-error=initializer-overrides", "-Wno-error=unused-parameter",
                            opt, "-fvisibility=hidden", "-shared", "-fPIC", "-I", str(temp), "-I", str(temp / "platform_headers"),
                            "-I", str(reference / "drivers/led"), str(source), "-o", str(output)], check=True)
            differences[label] = compare(ctypes.CDLL(str(output)), rows)
    if differences != {"base": 0, "optimized": 0, "ignore_enable": 300, "boolean_enable": 216, "skip_clear": 270}:
        raise AssertionError(f"Render-begin differential failed: {differences}")
    if any((target / name).read_bytes() != content for name, content in inputs.items()):
        raise ValueError("Target changed during verification")
    return {"candidate_revision": REVISION, "prefix_source_sha256": hashes, "stage_reference_sha256": REFERENCE_HASHES,
            "profile_source_sha256": profile["source_sha256"], "target_profile": profile["target_profile"],
            "target_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in inputs.items()},
            "probe_builder_sha256": {name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest() for name in
                                     ("audit_original_rgb_render_begin.py", "audit_original_rgb_mode15_staging.py", "verify_original_target_rgb.py", "EmulateOriginalVial.java")},
            "cases_matched": 1524, "optimized_cases_matched": 1524, "negative_differences": differences,
            "native_io_requests": 0, "whole_renderer_caller_executed": False, "target_changes_applied": False,
            "original_thumb_executed_by_this_command": False,
            "scope": "original pre-dispatch14aa4..14ade including real RAM all/single setter vs unmodified SDK init/flags prefix with actual packed types, target config and SDK WS2812 staging via nonsplit API adapter. No caller effect selection, effects/last-state commit/post-indicators/start/sync/task/clock/scan/flush/DMA/HAL/device or source provenance. Iter255 byte-preservation only; no valid-chunk claim",
            "sentinel": "ORIGINAL_RGB_RENDER_BEGIN_AUDIT_COMPLETE"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir, args.target), indent=2))
