#!/usr/bin/env python3
"""Original factory mode15 versus actual candidate Chevron/runner/HSV code.

Controlled complete ROM LED geometry and supplied config/time/iter/flags; not the
complete renderer/indicator/flush, QMK/HAL build, linked firmware or hardware.
"""
import argparse
import ctypes
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_original_rgb_hsv import color_program, original_hsv_profile
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA, math_sources, pinned_source
from audit_original_rgb_mode29_frames import extract
from prepare_original_target import REVISION, validate_reference
from recover_original_vial import parse_uf2, recover

LEVELS = ((0, 128, 255), (0, 1, 255, 256, 65535, 65536, 0xFFFFFFFF),
          (0xFFFF00, 0x8080FF, 0x000080), (255, 4, 2, 0), range(5))


def inspect_mode15(image):
    witnesses = {0x08014D4E: "1348e3e7", 0x08012B48: "30b5134d183105eb410385b05b780190",
                 0x0801BE50: "ad081b8802355d43c0f30728c5f30725"}
    for address, value in witnesses.items():
        if image.read(address, len(value) // 2) != bytes.fromhex(value):
            raise ValueError("Changed original mode15 instruction witness")
    for address, expected in ((0x08014D9C, 0x08012B49), (0x08012B98, 0x0801DEA0),
                              (0x0801BED0, 0x20001CE0), (0x0801BED4, 0x200018E0),
                              (0x0801BED8, 0x20000EE8), (0x0801BEDC, 0x0801DF60)):
        if int.from_bytes(image.read(address, 4), "little") != expected:
            raise ValueError("Changed original mode15 runner/math literal")
    branch = 0x08014AE8 + 2 * int.from_bytes(image.read(0x08014AE8 + 30, 2), "little")
    if branch != 0x08014D4E:
        raise ValueError("Changed original mode15 jump-table entry")


def program(reference, temp):
    hashes = math_sources(reference, temp)
    _, colors = color_program(reference, temp)
    hashes.update(colors)
    read = lambda path: pinned_source(reference, path, hashes)
    types = read("quantum/rgb_matrix/rgb_matrix_types.h")
    header = read("quantum/rgb_matrix/rgb_matrix.h")
    impl = read("quantum/rgb_matrix/rgb_matrix.c")
    runner = read("quantum/rgb_matrix/animations/runners/effect_runner_i.h")
    effect = read("quantum/rgb_matrix/animations/rainbow_moving_chevron_anim.h")
    (temp / "effect_runner_i.h").write_text(runner)
    (temp / "chevron.h").write_text(effect)
    decl = [extract(r"typedef uint8_t led_flags_t;", types)]
    for name in ("effect_params_t", "led_point_t", "led_config_t"):
        decl.append(extract(r"typedef struct PACKED \{[^}]+\} " + name + ";", types))
    decl += [extract(r"typedef union rgb_config_t \{.*?\} rgb_config_t;", types),
             extract(r"#define HAS_ANY_FLAGS[^\n]+", types),
             extract(r"struct rgb_matrix_limits_t \{.*?\};", header),
             header[header.index("#define RGB_MATRIX_USE_LIMITS_ITER"):header.index("enum rgb_matrix_effects")]]
    limits = extract(r"struct rgb_matrix_limits_t rgb_matrix_get_limits\([^)]*\) \{.*?^\}", impl)
    finished = extract(r"static inline bool rgb_matrix_check_finished_leds\([^)]*\) \{.*?^\}", header)
    center = extract(r"#ifndef RGB_MATRIX_CENTER\n.*?^#endif", impl)
    wrapper = extract(r"__attribute__\(\(weak\)\) rgb_t rgb_matrix_hsv_to_rgb\(hsv_t hsv\) \{.*?^\}", impl)
    phase = extract(r"uint8_t time = [^;]+;", runner).split("=", 1)[1].strip().rstrip(";")
    source = temp / "mode15.c"
    source.write_text('''#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "color.h"
#include "led_tables.h"
#include "lib8tion.h"
#define API __attribute__((visibility("default")))
#define RGB_MATRIX_LED_COUNT 72
#define MATRIX_ROWS 4
#define MATRIX_COLS 12
''' + "\n".join(decl) + '''
_Static_assert(sizeof(rgb_config_t)==8 && sizeof(rgb_t)==3 && sizeof(effect_params_t)==3,"source color/config types");
_Static_assert(sizeof(led_config_t)==264 && offsetof(led_config_t,point)==48 && offsetof(led_config_t,flags)==192,"source map layout");
rgb_config_t rgb_matrix_config;
uint32_t g_rgb_timer;
led_config_t g_led_config;
''' + center + '\n' + limits + '\n' + finished + '''
#define rgb_matrix_hsv_to_rgb candidate_default_hsv_to_rgb
''' + wrapper + '''
#undef rgb_matrix_hsv_to_rgb
static uint32_t trace[2048],length;
static void push(uint32_t v) { if(length>=2048) __builtin_trap(); trace[length++]=v; }
rgb_t rgb_matrix_hsv_to_rgb(hsv_t hsv) {
#ifdef PROBE_NOCIE
    rgb_t result=hsv_to_rgb_nocie(hsv);
#else
    rgb_t result=candidate_default_hsv_to_rgb(hsv);
#endif
    push(2); push(hsv.h); push(hsv.s); push(hsv.v); push(result.r); push(result.g); push(result.b);
    return result;
}
void rgb_matrix_set_color(int i,uint8_t r,uint8_t g,uint8_t b) { push(1);push(i);push(r);push(g);push(b); }
#include "effect_runner_i.h"
#define ENABLE_RGB_MATRIX_RAINBOW_MOVING_CHEVRON
#define RGB_MATRIX_CUSTOM_EFFECT_IMPLS
#define RGB_MATRIX_EFFECT(name)
#include "chevron.h"
API void probe_map(const uint8_t *map) { for(unsigned i=0;i<264;i++) ((uint8_t *)&g_led_config)[i]=map[i]; }
API bool probe_step(uint8_t speed,uint32_t now,uint32_t hsv,uint8_t flags,uint8_t iter,bool init) {
    length=0; rgb_matrix_config.raw=0; rgb_matrix_config.enable=1; rgb_matrix_config.mode=15;
    rgb_matrix_config.hsv=(hsv_t){hsv&255,(hsv>>8)&255,(hsv>>16)&255};
    rgb_matrix_config.speed=speed; rgb_matrix_config.flags=flags; g_rgb_timer=now;
    effect_params_t params={iter,flags,init}; return RAINBOW_MOVING_CHEVRON(&params);
}
API uint8_t probe_phase(void) { return ''' + phase + '''; }
API const uint32_t *probe_trace(void) { return trace; }
API uint32_t probe_length(void) { return length; }
API const uint8_t *probe_curve(void) { return CIE1931_CURVE; }
''')
    return source, hashes


def compare(lib, rows, led_map, table):
    lib.probe_map.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
    lib.probe_map((ctypes.c_uint8 * 264).from_buffer_copy(led_map))
    lib.probe_step.argtypes = [ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_bool]
    lib.probe_step.restype = ctypes.c_bool
    lib.probe_phase.restype = ctypes.c_uint8
    lib.probe_trace.restype = ctypes.POINTER(ctypes.c_uint32)
    lib.probe_length.restype = ctypes.c_uint32
    lib.probe_curve.restype = ctypes.POINTER(ctypes.c_uint8)
    if bytes(lib.probe_curve()[:256]) != table:
        raise AssertionError("Changed compiled CIE table")
    mismatches = 0
    for row in rows:
        rendering = lib.probe_step(*(row[k] for k in ("speed", "now", "hsv", "flags", "iter", "init")))
        data, length = lib.probe_trace(), lib.probe_length()
        if length > 2048 or length % 12:
            raise AssertionError("Unmodeled mode15 trace length")
        trace = []
        for start in range(0, length, 12):
            if data[start] != 2 or data[start + 7] != 1:
                raise AssertionError("Unmodeled mode15 HSV/RGB pair")
            trace.extend([list(data[start:start+7]), list(data[start+7:start+12])])
        mismatches += rendering != row["rendering"] or lib.probe_phase() != row["phase"] or trace != row["trace"]
    return mismatches


def audit(raw, reference):
    recover(raw)
    image = parse_uf2(raw)
    inspect_mode15(image)
    table = original_hsv_profile(raw)
    validate_reference(reference)
    oracle = json.loads((ROOT / "tests/fixtures/original-rgb-mode15.json").read_text())
    rows = oracle["rgb_mode15"]
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(rows) != 1260 or {
            tuple(r[k] for k in ("speed", "now", "hsv", "flags", "iter")) for r in rows} != set(itertools.product(*LEVELS)):
        raise ValueError("Incomplete original mode15 grid")
    # Pinned trig8.h defines an unused AVR asm inline function even on
    # non-AVR hosts. Clang validates its constraints eagerly; GNU accepts the
    # unused body. Reuse the existing GNU compiler, never patch/suppress/install.
    cc = next((shutil.which(n) for n in ("gcc-16", "gcc-15", "gcc-14", "gcc-13") if shutil.which(n)), None)
    if not cc:
        raise RuntimeError("Existing GNU host compiler required; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-mode15-") as folder:
        temp = Path(folder)
        source, hashes = program(reference, temp)
        differences = {}
        for tag, opt, fixed in (("base", "-O0", 1), ("optimized", "-O2", 1), ("nonfixed", "-O0", 0), ("nocie", "-O0", 1)):
            output = temp / (tag + ".so")
            extra = ["-DPROBE_NOCIE"] if tag == "nocie" else []
            subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt, "-fvisibility=hidden", "-shared", "-fPIC",
                            "-DUSE_CIE1931_CURVE", "-DFASTLED_BLEND_FIXED=1", f"-DFASTLED_SCALE8_FIXED={fixed}",
                            "-DRGB_MATRIX_LED_PROCESS_LIMIT=15", *extra, "-I", str(temp), str(source),
                            str(temp / "color.c"), str(temp / "led_tables.c"), "-o", str(output)], check=True)
            differences[tag] = compare(ctypes.CDLL(str(output)), rows, image.read(0x0801DEA0, 264), table)
        expected_nocie = sum(r["hsv"] == 0x8080FF and bool(r["trace"]) for r in rows)
        if differences["base"] or differences["optimized"] or differences["nonfixed"] != 360 or differences["nocie"] != expected_nocie:
            raise AssertionError(f"Mode15 differential failed: {differences}")
    return {"candidate_revision": REVISION, "source_sha256": hashes, "host_compiler": cc,
            "mode15_cases_matched": 1260, "optimized_cases_matched": 1260,
            "actual_original_hsv_calls_in_fixture": sum(e[0] == 2 for r in rows for e in r["trace"]),
            "compiled_cie_bytes_matched": 256, "negative_differences": differences,
            "original_thumb_executed_by_this_command": False, "target_changes_applied": False,
            "scope": "selected original mode15 dispatch/runner/Chevron math/HSV vs complete unmodified candidate Chevron/runner/color/math with controlled full264 ROM map; phase, ordered HSV/RGB APIs and return. Not full dispatcher integration/renderer/indicator/group/flush/clock/HAL/physical output or manufacturer source provenance",
            "sentinel": "ORIGINAL_RGB_MODE15_AUDIT_COMPLETE"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir), indent=2))
