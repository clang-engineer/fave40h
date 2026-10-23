#!/usr/bin/env python3
"""Bounded STARTING slice vs unmodified SDK start function, RAM only.

Supplied active-frame r5 snapshot/SP/r6; not clock reads, aging or full task.
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

from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA, pinned_source
from audit_original_rgb_profile import candidate_program, audit_target, match
from prepare_original_target import REVISION, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2

TIMERS = (0, 1, 15, 16, 65535, 0xFFFFFFFF)


def grid():
    return list(itertools.product(TIMERS, (0, 4, 255), (0, 4, 255), (0, 1), range(4)))


def hit_bytes(pattern):
    data = bytearray((0 if pattern == 0 else (i*73+50)&255 if pattern == 1 else 255 if pattern == 2 else 0 if i%2 == 0 else 255) for i in range(41))
    data[0] = (0, 1, 8, 255)[pattern]
    return bytes(data)


def inspect_start(image):
    # Static parent switch witness only: STARTING0 CMP3 has OV=0 and TBB0
    # selects156AE. The parent dispatch itself is not executed by this probe.
    if image.read(0x0801566A, 16).hex() != "494e3378032b53d8dfe803f01c297076":
        raise ValueError("Changed original STARTING parent switch")
    code = "394b3449394800221a70384b29221d60fcf7e7f80123337028e0"
    if image.read(0x080156AE, 26).hex() != code:
        raise ValueError("Changed original STARTING instructions")
    for address, value in ((0x08015780, 0x20001CE8), (0x08015784, 0x20001AC6), (0x08015790, 0x20000EED),
                           (0x08015794, 0x20000EE8), (0x08015798, 0x20001886), (0x0801579C, 0x200018E0)):
        if int.from_bytes(image.read(address, 4), "little") != value:
            raise ValueError("Changed original STARTING literal")


def validate_oracle(oracle):
    rows = oracle["rgb_start"]
    if oracle["payload_sha256"] != PAYLOAD_SHA or [tuple(r[k] for k in ("timer_buffer", "iter", "flags", "init", "pattern")) for r in rows] != grid():
        raise ValueError("Incomplete STARTING grid")
    for row in rows:
        hits = hit_bytes(row["pattern"])
        if row["input_hits_hex"] != hits.hex() or row["old_tracker_hex"] != bytes(b^255 for b in hits).hex() or row["old_frame_timer"] != row["timer_buffer"] ^ 0xFFFFFFFF:
            raise ValueError("Changed STARTING inputs")
    return rows


def program(reference, target, temp, negative=None):
    _, hashes, _ = candidate_program(reference, temp, target)
    read = lambda path: pinned_source(reference, path, hashes)
    types = read("quantum/rgb_matrix/rgb_matrix_types.h")
    implementation = read("quantum/rgb_matrix/rgb_matrix.c")
    reactive = match(r"#if defined\(RGB_MATRIX_KEYPRESSES\) \|\| defined\(RGB_MATRIX_KEYRELEASES\).*?^#endif", types)
    declarations = match(r"typedef enum rgb_task_states[^;]+;", types) + "\n" + match(r"typedef uint8_t led_flags_t;", types)
    for name in ("effect_params_t", "last_hit_t"):
        declarations += "\n" + match(r"typedef struct PACKED \{[^}]+\} " + name + ";", types)
    start = match(r"static void rgb_task_start\(void\) \{.*?^\}", implementation)
    changes = {"skip_iter": ("rgb_effect_params.iter = 0;", "(void)rgb_effect_params.iter;"),
               "stale_timer": ("g_rgb_timer = rgb_timer_buffer;", "(void)rgb_timer_buffer;"),
               "skip_tracker": ("g_last_hit_tracker = last_hit_buffer;", "(void)last_hit_buffer;")}
    if negative is not None:
        old, new = changes[negative]
        if start.count(old) != 1:
            raise ValueError("Changed SDK start statement")
        start = start.replace(old, new)
    source = temp / "start.c"
    source.write_text('''#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define PACKED __attribute__((packed))
#define API __attribute__((visibility("default")))
#include "target_config.h"
#include "rgb_post_config.h"
''' + reactive + '''
#ifndef RGB_MATRIX_KEYREACTIVE_ENABLED
#error Expected actual target reactive profile
#endif
''' + declarations + '''
_Static_assert(sizeof(last_hit_t)==41 && offsetof(last_hit_t,tick)==25 && sizeof(effect_params_t)==3,"actual packed types");
static struct PACKED { uint32_t before; last_hit_t value; uint32_t after; } hit_source,hit_dest;
static struct PACKED { uint32_t before; effect_params_t value; uint32_t after; } params;
static struct { uint32_t before,value,after; } frame_clock,input_clock;
static struct { uint32_t before; rgb_task_states value; uint32_t after; } state;
#define rgb_effect_params params.value
#define rgb_task_state state.value
#define g_rgb_timer frame_clock.value
#define rgb_timer_buffer input_clock.value
#define g_last_hit_tracker hit_dest.value
#define last_hit_buffer hit_source.value
''' + start + '''
API void start_run(uint32_t clock,uint8_t iter,uint8_t flags,bool init,const uint8_t *hits,const uint8_t *old) {
    hit_source.before=hit_source.after=hit_dest.before=hit_dest.after=params.before=params.after=0xA5A5A5A5U;
    frame_clock.before=frame_clock.after=input_clock.before=input_clock.after=state.before=state.after=0xA5A5A5A5U;
    for(unsigned i=0;i<41;i++) { ((uint8_t *)&last_hit_buffer)[i]=hits[i]; ((uint8_t *)&g_last_hit_tracker)[i]=old[i]; }
    rgb_effect_params=(effect_params_t){iter,flags,init}; rgb_task_state=STARTING;
    g_rgb_timer=clock^UINT32_MAX; rgb_timer_buffer=clock;
    rgb_task_start();
    if(hit_source.before!=0xA5A5A5A5U || hit_source.after!=0xA5A5A5A5U || hit_dest.before!=0xA5A5A5A5U || hit_dest.after!=0xA5A5A5A5U ||
       params.before!=0xA5A5A5A5U || params.after!=0xA5A5A5A5U || frame_clock.before!=0xA5A5A5A5U || frame_clock.after!=0xA5A5A5A5U ||
       input_clock.before!=0xA5A5A5A5U || input_clock.after!=0xA5A5A5A5U || state.before!=0xA5A5A5A5U || state.after!=0xA5A5A5A5U || rgb_timer_buffer!=clock) __builtin_trap();
    for(unsigned i=0;i<41;i++) if(((const uint8_t *)&last_hit_buffer)[i]!=hits[i]) __builtin_trap();
}
API const uint8_t *start_tracker(void) { return (const uint8_t *)&g_last_hit_tracker; }
API uint32_t start_clock(void) { return g_rgb_timer; }
API uint32_t start_state(void) { return rgb_task_state; }
API uint32_t start_params(void) { return rgb_effect_params.iter|((uint32_t)rgb_effect_params.flags<<8)|((uint32_t)rgb_effect_params.init<<16); }
''')
    return source, hashes


def compare(lib, rows):
    lib.start_run.argtypes = [ctypes.c_uint32, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_bool, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
    lib.start_run.restype = None
    lib.start_tracker.restype = ctypes.POINTER(ctypes.c_uint8)
    for name in ("start_clock", "start_state", "start_params"):
        getattr(lib, name).restype = ctypes.c_uint32
    differences = 0
    for row in rows:
        array = lambda key: (ctypes.c_uint8*41).from_buffer_copy(bytes.fromhex(row[key]))
        lib.start_run(row["timer_buffer"], row["iter"], row["flags"], row["init"], array("input_hits_hex"), array("old_tracker_hex"))
        params = lib.start_params().to_bytes(4, "little")[:3].hex()
        differences += (bytes(lib.start_tracker()[:41]).hex() != row["tracker_after_hex"] or lib.start_clock() != row["frame_timer_after"] or
                        lib.start_state() != row["task_state_after"] or params != row["params_after_hex"])
    return differences


def audit(raw, reference, target):
    recover(raw); validate_reference(reference); inspect_start(parse_uf2(raw))
    expected = artifacts(raw); inputs = {name: (target/name).read_bytes() for name in expected}
    if any(v.decode() != expected[k] for k, v in inputs.items()): raise ValueError("Changed target")
    profile = audit_target(raw, reference, target)
    oracle = ROOT/"tests/fixtures/original-rgb-start.json"; oracle_bytes = oracle.read_bytes()
    rows = validate_oracle(json.loads(oracle_bytes))
    builders = {name: (ROOT/"tools"/name).read_bytes() for name in ("audit_original_rgb_start.py", "audit_original_rgb_profile.py", "EmulateOriginalVial.java")}
    cc = shutil.which("clang")
    if not cc: raise RuntimeError("Existing Clang required; nothing installed")
    differences = {}
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-start-") as folder:
        for tag, opt, negative in (("base", "-O0", None), ("optimized", "-O2", None), ("skip_iter", "-O0", "skip_iter"),
                                   ("stale_timer", "-O0", "stale_timer"), ("skip_tracker", "-O0", "skip_tracker")):
            temp = Path(folder)/tag; temp.mkdir(); source, hashes = program(reference, target, temp, negative)
            output = temp/"start.so"
            subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt, "-shared", "-fPIC", "-fvisibility=hidden", "-I", str(temp), str(source), "-o", str(output)], check=True)
            differences[tag] = compare(ctypes.CDLL(str(output)), rows)
    if differences != {"base": 0, "optimized": 0, "skip_iter": 288, "stale_timer": 432, "skip_tracker": 432}:
        raise AssertionError(f"STARTING differential failed: {differences}")
    if any((target/name).read_bytes() != data for name, data in inputs.items()) or oracle.read_bytes() != oracle_bytes or any((ROOT/"tools"/name).read_bytes() != data for name, data in builders.items()):
        raise ValueError("Inputs changed during verification")
    return {"candidate_revision": REVISION, "start_source_sha256": hashes, "profile_source_sha256": profile["source_sha256"], "target_profile": profile["target_profile"],
        "target_sha256": {k: hashlib.sha256(v).hexdigest() for k,v in inputs.items()}, "probe_builder_sha256": {k: hashlib.sha256(v).hexdigest() for k,v in builders.items()},
        "oracle_sha256": hashlib.sha256(oracle_bytes).hexdigest(), "cases_matched": 432, "optimized_cases_matched": 432, "negative_differences": differences,
        "actual_sdk_start_function_executed": True, "copied_tracker_bytes": 41, "target_changes_applied": False, "hardware_apis_linked": False,
        "original_thumb_executed_by_this_command": False,
        "scope": "bounded original STARTING active-frame slice with actual original memcpy vs actual SDK start function/packed types/target-derived reactive guard; r5 snapshot/SP/r6 supplied, not parent clock reads/aging/mode selection/dispatch or full task/start-to-render/flush/sync/HAL/device. Raw count255 is copy-only, not a valid collector state",
        "sentinel": "ORIGINAL_RGB_START_AUDIT_COMPLETE"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("uf2", type=Path); p.add_argument("--reference-dir", type=Path, required=True); p.add_argument("--target", type=Path, required=True)
    a = p.parse_args(); print(json.dumps(audit(a.uf2.read_bytes(), a.reference_dir, a.target), indent=2))
