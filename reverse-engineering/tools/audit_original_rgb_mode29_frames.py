#!/usr/bin/env python3
"""Mode29 original/candidate persistent-frame differential at controlled HSV/RGB APIs.

Actual candidate PixelFlow and RNG/math run. --real-hsv additionally compares
actual HSV/CIE conversion; default keeps the diagnostic HSV fixture unchanged.
No physical RGB output, complete renderer, QMK/HAL build, target or device changes.
"""
import argparse
import ctypes
import itertools
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from audit_original_rgb_mode29 import PAYLOAD_SHA, ROOT, inspect_mode29_image, interval_program, pinned_source
from audit_original_rgb_hsv import color_program, original_hsv_profile
from prepare_original_target import REVISION, validate_reference
from recover_original_vial import parse_uf2, recover


def extract(pattern, content):
    found = re.search(pattern, content, re.S | re.M)
    if not found:
        raise ValueError(f"Unmodeled frame-probe source: {pattern}")
    return found[0]


def frame_program(reference, temp, flags, real_hsv=False):
    _, hashes = interval_program(reference, temp)
    read = lambda path: pinned_source(reference, path, hashes)
    color = read("quantum/color.h")
    types = read("quantum/rgb_matrix/rgb_matrix_types.h")
    header = read("quantum/rgb_matrix/rgb_matrix.h")
    implementation = read("quantum/rgb_matrix/rgb_matrix.c")
    flow = read("quantum/rgb_matrix/animations/pixel_flow_anim.h")
    (temp / "pixel_flow_anim.h").write_text(flow)  # Unmodified complete effect.
    declarations = [extract(r"typedef struct PACKED " + name + r" \{.*?\} " + name + ";", color) for name in ("rgb_t", "hsv_t")]
    hsv_wrapper = ""
    hsv_result = "rgb_t result={(uint8_t)(hsv.h+hsv.v),(uint8_t)(hsv.s^hsv.v),(uint8_t)(hsv.h^hsv.s)};"
    curve_probe = ""
    if real_hsv:
        _, color_hashes = color_program(reference, temp)
        hashes.update(color_hashes)
        declarations = ['#include "color.h"', '#include "led_tables.h"']
        # Rename only the SDK default wrapper at preprocessing time so the
        # external tracing wrapper can call it without interposition/recursion.
        # The actual color implementation, LUT and complete PixelFlow stay intact.
        hsv_wrapper = ('#define rgb_matrix_hsv_to_rgb candidate_default_hsv_to_rgb\n' +
                       extract(r"__attribute__\(\(weak\)\) rgb_t rgb_matrix_hsv_to_rgb\(hsv_t hsv\) \{.*?^\}", implementation) +
                       '\n#undef rgb_matrix_hsv_to_rgb\n')
        hsv_result = '''#ifdef PROBE_NOCIE
    rgb_t result=hsv_to_rgb_nocie(hsv);
#else
    rgb_t result=candidate_default_hsv_to_rgb(hsv);
#endif'''
        curve_probe = 'API const uint8_t *probe_cie_curve(void) { return CIE1931_CURVE; }\n'
    declarations.append(extract(r"typedef uint8_t led_flags_t;", types))
    for name in ("effect_params_t", "led_point_t", "led_config_t"):
        declarations.append(extract(r"typedef struct PACKED \{[^}]+\} " + name + ";", types))
    declarations.append(extract(r"typedef union rgb_config_t \{.*?\} rgb_config_t;", types))
    declarations.append(extract(r"#define HAS_ANY_FLAGS[^\n]+", types))
    declarations.append(extract(r"struct rgb_matrix_limits_t \{.*?\};", header))
    declarations.append(header[header.index("#define RGB_MATRIX_USE_LIMITS_ITER"):header.index("enum rgb_matrix_effects")])
    declarations.append(extract(r"struct rgb_matrix_limits_t rgb_matrix_get_limits\([^)]*\) \{.*?^\}", implementation))
    declarations.append(extract(r"static inline bool rgb_matrix_check_finished_leds\([^)]*\) \{.*?^\}", header))
    source = temp / "frames.c"
    source.write_text('''#include <stdint.h>
#include <stdbool.h>
#include "lib8tion.h"
#define PACKED __attribute__((packed))
#define RGB_MATRIX_LED_COUNT 72
#ifndef RGB_MATRIX_LED_PROCESS_LIMIT
#define RGB_MATRIX_LED_PROCESS_LIMIT 15
#endif
#define MATRIX_ROWS 4
#define MATRIX_COLS 12
#define API __attribute__((visibility("default")))
''' + "\n".join(declarations) + '''
_Static_assert(sizeof(rgb_config_t)==8 && sizeof(rgb_t)==3 && sizeof(effect_params_t)==3,"packed source types");
_Static_assert(sizeof(led_config_t)==264,"original map shape");
uint16_t rand16seed;
rgb_config_t rgb_matrix_config;
uint32_t g_rgb_timer;
led_config_t g_led_config = {.flags={''' + ",".join(map(str, flags)) + '''}};
static uint32_t trace[2048], trace_len, overflow;
static void push(uint32_t value) { if(trace_len<2048) trace[trace_len++]=value; else overflow++; }
void rgb_matrix_set_color(int index,uint8_t r,uint8_t g,uint8_t b) {
    push(1); push(index); push(r); push(g); push(b);
}
void rgb_matrix_set_color_all(uint8_t r,uint8_t g,uint8_t b) {
    push(0); push(r); push(g); push(b);
}
''' + hsv_wrapper + '''
rgb_t rgb_matrix_hsv_to_rgb(hsv_t hsv) {
    ''' + hsv_result + '''
    push(2); push(hsv.h); push(hsv.s); push(hsv.v); push(result.r); push(result.g); push(result.b);
    return result; // Trace-only wrapper; selected conversion above.
}
#define ENABLE_RGB_MATRIX_PIXEL_FLOW
#define RGB_MATRIX_CUSTOM_EFFECT_IMPLS
#define RGB_MATRIX_EFFECT(name)
#include "pixel_flow_anim.h"
API void probe_init(uint16_t seed,uint8_t speed,uint8_t value) {
    rand16seed=seed; rgb_matrix_config.raw=0; rgb_matrix_config.enable=1; rgb_matrix_config.mode=29;
    rgb_matrix_config.hsv=(hsv_t){17,254,value}; rgb_matrix_config.speed=speed;
}
API bool probe_step(uint8_t iter,uint8_t flags,bool init,uint32_t now) {
    trace_len=0; overflow=0; g_rgb_timer=now; rgb_matrix_config.flags=flags;
    effect_params_t params={iter,flags,init}; return PIXEL_FLOW(&params);
}
API uint16_t probe_seed(void) { return rand16seed; }
API const uint32_t *probe_trace(void) { return trace; }
API uint32_t probe_trace_len(void) { return trace_len; }
API uint32_t probe_overflow(void) { return overflow; }
''' + curve_probe)
    return source, hashes


def compare_sequence(lib, sequence):
    lib.probe_init.argtypes = [ctypes.c_uint16, ctypes.c_uint8, ctypes.c_uint8]
    lib.probe_init.restype = None
    lib.probe_step.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_bool, ctypes.c_uint32]
    lib.probe_step.restype = ctypes.c_bool
    lib.probe_seed.restype = ctypes.c_uint16
    lib.probe_trace.restype = ctypes.POINTER(ctypes.c_uint32)
    lib.probe_trace_len.restype = ctypes.c_uint32
    lib.probe_overflow.restype = ctypes.c_uint32
    lib.probe_init(sequence["initial_seed"], sequence["speed"], sequence["value"])
    mismatches = 0
    for row in sequence["steps"]:
        rendering = lib.probe_step(row["iter"], row["flags"], row["init"], row["now"])
        if lib.probe_overflow():
            raise AssertionError("Native frame trace overflow")
        length = lib.probe_trace_len()
        if length > 2048:
            raise AssertionError("Native frame trace outside owned buffer")
        data = lib.probe_trace()
        trace, offset = [], 0
        while offset < length:
            kind = data[offset]
            if kind not in (0, 1, 2) or offset + (4, 5, 7)[kind] > length:
                raise AssertionError("Malformed native frame trace")
            size = (4, 5, 7)[kind]
            trace.append(list(data[offset:offset + size])); offset += size
        mismatches += int(trace != row["trace"] or rendering != row["rendering"] or lib.probe_seed() != row["seed_after"])
    return mismatches


def audit(raw, reference, real_hsv=False):
    recover(raw)
    image = parse_uf2(raw)
    inspect_mode29_image(image)
    if int.from_bytes(image.read(0x08014920, 4), "little") != 0x20000EE6:
        raise ValueError("Changed original RNG seed pointer")
    validate_reference(reference)
    suffix = "-real-hsv" if real_hsv else ""
    oracle = json.loads((ROOT / f"tests/fixtures/original-rgb-mode29-frames{suffix}.json").read_text())
    original_table = original_hsv_profile(raw) if real_hsv else None
    if real_hsv and (oracle.get("actual_hsv_conversion_executed") is not True or
                     bytes.fromhex(oracle["cie_table_hex"]) != original_table):
        raise ValueError("Missing actual original HSV/CIE evidence")
    sequences = oracle["rgb_mode29_frames"]
    if (oracle["payload_sha256"] != PAYLOAD_SHA or len(sequences) != 6 or
            {(s["speed"], s["initial_seed"]) for s in sequences} != set(itertools.product((0, 128, 255), (0, 65535))) or
            any(len(s["steps"]) != 16 for s in sequences)):
        raise ValueError("Incomplete mode29 frame oracle")
    for sequence in sequences:
        if sequence["value"] not in (128, 255):
            raise ValueError("Out-of-scope mode29 value")
        for row in sequence["steps"]:
            if not (0 <= row["iter"] <= 4 and row["flags"] in (0, 2, 4, 255) and
                    isinstance(row["init"], bool) and 0 <= row["now"] <= 0xFFFFFFFF):
                raise ValueError("Out-of-scope mode29 frame input")
    flags = list(image.read(0x0801DEA0 + 192, 72))
    gcc = next((shutil.which(n) for n in ("gcc-16", "gcc-15", "gcc-14", "gcc-13") if shutil.which(n)), None)
    if not gcc:
        raise RuntimeError("Existing GNU host compiler required; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-mode29-frames-") as folder:
        temp = Path(folder)
        source, hashes = frame_program(reference, temp, flags, real_hsv)
        differences = {}
        profiles = [("base", "-O0", 15), ("optimized", "-O2", 15), ("wrong_limit", "-O0", 14)]
        if real_hsv:
            profiles.append(("nocie_api", "-O0", 15))
        for tag, opt, limit in profiles:
            count = 0
            for index, sequence in enumerate(sequences):
                # Fresh hidden private state for each sequence. No SDK symbol
                # interposition/coalescing between the independently loaded libs.
                output = temp / f"{tag}-{index}.so"
                color_flags = (["-DUSE_CIE1931_CURVE"] + (["-DPROBE_NOCIE"] if tag == "nocie_api" else [])) if real_hsv else []
                color_sources = [str(temp / name) for name in ("color.c", "led_tables.c")] if real_hsv else []
                subprocess.run([gcc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt, *color_flags,
                                "-DFASTLED_SCALE8_FIXED=1", "-DFASTLED_BLEND_FIXED=1",
                                f"-DRGB_MATRIX_LED_PROCESS_LIMIT={limit}", "-fvisibility=hidden",
                                "-shared", "-fPIC", "-I", str(temp), str(source), *color_sources, "-o", str(output)], check=True)
                lib = ctypes.CDLL(str(output))
                if real_hsv:
                    lib.probe_cie_curve.restype = ctypes.POINTER(ctypes.c_uint8)
                    if bytes(lib.probe_cie_curve()[:256]) != original_table:
                        raise AssertionError("Compiled frame CIE table differs from original")
                count += compare_sequence(lib, sequence)
            differences[tag] = count
        # For V128, CIE maps the primary channel to48 instead of128. A
        # conversion event or nonblack cached output must therefore differ.
        expected_nocie = sum(seq["value"] == 128 and any(
            event[0] == 2 or (event[0] == 1 and any(event[2:])) for event in row["trace"])
            for seq in sequences for row in seq["steps"]) if real_hsv else 0
        if (differences["base"] or differences["optimized"] or differences["wrong_limit"] != 90 or
                (real_hsv and (not expected_nocie or differences["nocie_api"] != expected_nocie))):
            raise AssertionError(f"Mode29 frame differential failed: {differences}")
    return {"candidate_revision": REVISION, "source_sha256": hashes, "host_compiler": gcc,
            "persistent_sequences_matched": 6, "original_frame_calls_matched": 96,
            "optimized_frame_calls_matched": 96, "wrong_chunk_limit_negative_differences": differences["wrong_limit"],
            "actual_candidate_pixel_flow_and_rng_executed": True,
            "actual_hsv_conversion_executed": real_hsv, "physical_rgb_output_executed": False,
            "original_actual_hsv_calls_in_fixture": sum(row.get("original_hsv_calls", 0) for seq in sequences for row in seq["steps"]),
            "compiled_original_cie_bytes_matched": 256 if real_hsv else 0,
            "nocie_api_negative_differences": differences.get("nocie_api"),
            "native_private_cache_bytes_directly_compared": False, "native_private_wait_directly_compared": False,
            "original_thumb_executed_by_this_command": False, "target_changes_applied": False,
            "scope": "original selected mode29 dispatch/effect/RNG/memcpy vs complete unmodified candidate PixelFlow + actual limits/RNG/math; ordered HSV/RGB API traces, return and seed compared across persistent sequences. Native private state observed indirectly via later rendering; actual HSV only with --real-hsv, never full render/scan/indicator/flush/clock/HAL/device or source provenance proof",
            "sentinel": "ORIGINAL_RGB_MODE29_FRAMES_REAL_HSV_AUDIT_COMPLETE" if real_hsv else "ORIGINAL_RGB_MODE29_FRAMES_AUDIT_COMPLETE"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--real-hsv", action="store_true", help="Use separate actual HSV/CIE frame fixture, preserving diagnostic probe")
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir, args.real_hsv), indent=2))


if __name__ == "__main__":
    main()
