#!/usr/bin/env python3
"""Full RAM flush: last trackers -> actual SDK vtable/WS2812 encoding -> SYNCING.

No physical DMA, timer/HAL startup, renderer caller or whole firmware execution.
"""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_original_rgb_render_begin import program as begin_program
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA
from audit_original_rgb_profile import audit_target, checked_source, match
from prepare_original_target import REVISION, REFERENCE_HASHES, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2


def inspect_flush(image):
    for address, expected in ((0x08012FCC, "08b5074b074a1870074b1b78c3f30103137000f09ff9054b03221a7008bd00bf"),
                              (0x08012FEC, "eb0e0020ec0e0020e01c0020ed0e0020"), (0x08013380, "64500020fc310020")):
        if image.read(address, len(expected) // 2).hex() != expected:
            raise ValueError("Changed original flush/encoder branch/literals")


def validate_oracle(oracle):
    rows = oracle["rgb_flush"]
    expected = [(effect, enable, *old, pattern) for effect, enable, old, pattern in
                itertools.product((0, 15, 29, 45), range(4), ((255, 255), (15, 1)), ("ramp", "black", "white"))]
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(rows) != 96 or [tuple(r[k] for k in ("effect", "enable", "old_effect", "old_enable", "pattern")) for r in rows] != expected:
        raise ValueError("Incomplete flush grid")
    for row in rows:
        pixels = bytes((i*73+19) & 255 for i in range(216)) if row["pattern"] == "ramp" else bytes([255 if row["pattern"] == "white" else 0]) * 216
        if bytes.fromhex(row["input_grb_hex"]) != pixels:
            raise ValueError("Changed controlled GRB input")
    return rows


def program(reference, target, temp, negative=None):
    source, hashes = begin_program(reference, target, temp)
    # Observation-only name redirection. The actual PWM encoder body is not
    # patched; its public name below records entry/exit state around that body.
    source.write_text(source.read_text().replace('#include "pwm_driver.c"',
                      '#define ws2812_flush candidate_ws2812_flush\n#include "pwm_driver.c"\n#undef ws2812_flush'))
    implementation = checked_source(reference, "quantum/rgb_matrix/rgb_matrix.c", hashes)
    driver_header = checked_source(reference, "quantum/rgb_matrix/rgb_matrix_drivers.h", hashes)
    driver_source = checked_source(reference, "quantum/rgb_matrix/rgb_matrix_drivers.c", hashes)
    driver_type = match(r"typedef struct \{.*?\} rgb_matrix_driver_t;", driver_header)
    ws_branch = driver_source.split("#elif defined(RGB_MATRIX_WS2812)", 1)[1]
    driver = match(r"const rgb_matrix_driver_t rgb_matrix_driver = \{.*?\};", ws_branch)
    update = match(r"void rgb_matrix_update_pwm_buffers\(void\) \{.*?^\}", implementation)
    flush = match(r"static void rgb_task_flush\(uint8_t effect\) \{.*?^\}", implementation)
    assignments = "    rgb_last_effect = effect;\n    rgb_last_enable = rgb_matrix_config.enable;"
    if negative == "late_trackers":
        flush = flush.replace(assignments, "")
        flush = flush.replace("    rgb_matrix_update_pwm_buffers();", "    rgb_matrix_update_pwm_buffers();\n" + assignments)
    elif negative == "early_sync":
        flush = flush.replace("    rgb_matrix_update_pwm_buffers();", "    rgb_task_state = SYNCING;\n    rgb_matrix_update_pwm_buffers();")
    elif negative == "missing_encode":
        flush = flush.replace("    rgb_matrix_update_pwm_buffers();", "    (void)0;")
    source.write_text(source.read_text() + '''
static uint32_t flush_calls,flush_observed[6],flush_before[1952],flush_after[1952];
void ws2812_flush(void) {
    ++flush_calls;
    flush_observed[0]=rgb_last_effect; flush_observed[1]=rgb_last_enable; flush_observed[2]=rgb_task_state;
    for(unsigned i=0;i<1952;i++) flush_before[i]=ws2812_frame_buffer[i];
    candidate_ws2812_flush();
    flush_observed[3]=rgb_last_effect; flush_observed[4]=rgb_last_enable; flush_observed[5]=rgb_task_state;
    for(unsigned i=0;i<1952;i++) flush_after[i]=ws2812_frame_buffer[i];
}
''' + driver_type + '\n' + driver + '\n' + update + '\n' + flush + '''
STAGE_API void flush_run(const uint8_t *pixels,uint8_t effect,uint8_t enable,uint8_t old_effect,uint8_t old_enable) {
    stage_seed(pixels,0xA5B6FF02U,2);
    uint8_t cfg[8]={(uint8_t)(60|enable),0,255,255,128,255,0xA5,0xA5};
    for(unsigned i=0;i<8;i++) ((uint8_t *)&rgb_matrix_config)[i]=cfg[i];
    rgb_last_effect=old_effect; rgb_last_enable=old_enable;
    rgb_effect_params=(effect_params_t){4,255,false}; rgb_task_state=FLUSHING;
    flush_calls=0; for(unsigned i=0;i<6;i++) flush_observed[i]=0;
    for(unsigned i=0;i<1953;i++) ws2812_frame_buffer[i]=0xA5A5A5A5U;
    for(unsigned i=0;i<1952;i++) flush_before[i]=flush_after[i]=0;
    rgb_task_flush(effect);
    for(unsigned i=0;i<8;i++) if(((uint8_t *)&rgb_matrix_config)[i]!=cfg[i]) __builtin_trap();
    if(rgb_effect_params.iter!=4 || rgb_effect_params.flags!=255 || rgb_effect_params.init) __builtin_trap();
    if(ws2812_frame_buffer[1952]!=0xA5A5A5A5U) __builtin_trap();
}
STAGE_API uint32_t flush_count(void) { return flush_calls; }
STAGE_API const uint32_t *flush_events(void) { return flush_observed; }
STAGE_API const uint32_t *flush_before_words(void) { return flush_before; }
STAGE_API const uint32_t *flush_after_words(void) { return flush_after; }
STAGE_API const uint32_t *flush_pwm_words(void) { return ws2812_frame_buffer; }
STAGE_API uint32_t flush_final(void) { return rgb_last_effect|((uint32_t)rgb_last_enable<<8)|((uint32_t)rgb_task_state<<16); }
_Static_assert(WS2812_BIT_N==1952 && sizeof(ws2812_leds)==216,"original buffer sizes");
''')
    return source, hashes


def pwm_digest(words):
    return hashlib.sha256(b"".join(int(v).to_bytes(4, "little") for v in words[:1952])).hexdigest()


def compare(lib, rows):
    lib.flush_run.argtypes = [ctypes.POINTER(ctypes.c_uint8)] + [ctypes.c_uint8] * 4
    lib.flush_run.restype = None
    for name in ("flush_count", "flush_final", "stage_unexpected_io", "stage_group"):
        getattr(lib, name).restype = ctypes.c_uint32
    for name in ("flush_events", "flush_before_words", "flush_after_words", "flush_pwm_words"):
        getattr(lib, name).restype = ctypes.POINTER(ctypes.c_uint32)
    lib.stage_grb.restype = ctypes.POINTER(ctypes.c_uint8)
    differences = 0
    for row in rows:
        pixels = bytes.fromhex(row["input_grb_hex"])
        lib.flush_run((ctypes.c_uint8 * 216).from_buffer_copy(pixels), *(row[k] for k in ("effect", "enable", "old_effect", "old_enable")))
        observed = lib.flush_events()
        observations = [{"phase": name, "trackers_state": list(observed[i*3:i*3+3]), "pwm_sha256": pwm_digest(getattr(lib, getter)())}
                        for i, (name, getter) in enumerate((("before", "flush_before_words"), ("after", "flush_after_words")))]
        value = lib.flush_final()
        final = [value & 255, (value >> 8) & 255, (value >> 16) & 255]
        if bytes(lib.stage_grb()[:216]) != pixels or lib.stage_unexpected_io() or lib.stage_group() != 0xA5B6FF02:
            raise AssertionError("Flush changed GRB/group or requested EEPROM/HID/timer/DMA IO")
        differences += (observations != row["observations"] or final != row["final_trackers_state"] or
                        lib.flush_count() != row["encoder_calls"] or pwm_digest(lib.flush_pwm_words()) != row["final_pwm_sha256"])
    return differences


def audit(raw, reference, target):
    recover(raw); validate_reference(reference); inspect_flush(parse_uf2(raw))
    expected = artifacts(raw); inputs = {name: (target / name).read_bytes() for name in expected}
    if any(value.decode() != expected[name] for name, value in inputs.items()):
        raise ValueError("Changed generated target")
    profile = audit_target(raw, reference, target)
    rows = validate_oracle(json.loads((ROOT / "tests/fixtures/original-rgb-flush.json").read_text()))
    clang = shutil.which("clang")
    if not clang:
        raise RuntimeError("Existing host Clang required; nothing installed")
    differences = {}
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-flush-") as directory:
        for label, opt, negative in (("base", "-O0", None), ("optimized", "-O2", None), ("late_trackers", "-O0", "late_trackers"),
                                     ("early_sync", "-O0", "early_sync"), ("missing_encode", "-O0", "missing_encode")):
            temp = Path(directory) / label; temp.mkdir()
            source, hashes = program(reference, target, temp, negative)
            output = temp / "flush.so"
            subprocess.run([clang, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-error=initializer-overrides", "-Wno-error=unused-parameter",
                            opt, "-fvisibility=hidden", "-shared", "-fPIC", "-I", str(temp), "-I", str(temp / "platform_headers"),
                            "-I", str(reference / "drivers/led"), str(source), "-o", str(output)], check=True)
            differences[label] = compare(ctypes.CDLL(str(output)), rows)
    if differences != {"base": 0, "optimized": 0, "late_trackers": 93, "early_sync": 96, "missing_encode": 96}:
        raise AssertionError(f"Flush differential failed: {differences}")
    if any((target / name).read_bytes() != content for name, content in inputs.items()):
        raise ValueError("Target changed during verification")
    return {"candidate_revision": REVISION, "flush_source_sha256": hashes, "stage_reference_sha256": REFERENCE_HASHES,
            "profile_source_sha256": profile["source_sha256"], "target_profile": profile["target_profile"],
            "target_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in inputs.items()},
            "probe_builder_sha256": {name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest() for name in
                                     ("audit_original_rgb_flush.py", "audit_original_rgb_render_begin.py", "audit_original_rgb_mode15_staging.py", "verify_original_target_rgb.py", "EmulateOriginalVial.java")},
            "cases_matched": 96, "optimized_cases_matched": 96, "negative_differences": differences,
            "pwm_words_per_case": 1952, "encoded_words": 1728, "unchanged_reset_words": 224,
            "actual_sdk_flush_function_driver_vtable_and_ws2812_encoder_executed": True,
            "native_io_requests": 0, "whole_renderer_caller_executed": False, "physical_dma_executed": False,
            "original_thumb_executed_by_this_command": False, "target_changes_applied": False,
            "scope": "entire original RAM flush12fcc..12fea + encoder13320..13380 vs actual unmodified SDK rgb_task_flush/update helper/WS2812 vtable/encoder; observational encoder wrapper only, actual body unchanged. Last trackers updated before encoding and task SYNCING after it. Not startup timer/DMA/clock, complete caller/render/sync scheduling, EEPROM/physical output or source provenance",
            "sentinel": "ORIGINAL_RGB_FLUSH_AUDIT_COMPLETE"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir, args.target), indent=2))
