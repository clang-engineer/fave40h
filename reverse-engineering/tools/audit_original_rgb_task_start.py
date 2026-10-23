#!/usr/bin/env python3
"""Genuine task entry/clock/aging/selection/STARTING/return, no render/flush/sync."""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_original_rgb_timers import program as timers_program, inspect_timers, hits
from audit_original_rgb_start import inspect_start
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA, pinned_source
from audit_original_rgb_profile import audit_target, match
from prepare_original_target import REVISION, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2


def grid():
    return list(itertools.product((0,15,29,45),range(4),(0,1),(0,0xFFFFFFFF),(0,8),(0,4,255)))


def inspect_task_start(image):
    inspect_timers(image);inspect_start(image)
    for address,size,digest in TASK_WITNESSES:
        if hashlib.sha256(image.read(address,size)).hexdigest()!=digest:raise ValueError("Changed task selection/return witness")
    for address,value in ((0x08015788,0x20001D01),(0x0801578C,0x20001CE0)):
        if int.from_bytes(image.read(address,4),"little")!=value:raise ValueError("Changed task selection pointer")


TASK_WITNESSES = ((0x08015658,34,"ee0d3bcd4251ef1b89305d5a098935d0a7f152bbe2bb54b896be3059c0749712"),
                  (0x080156AA,4,"1454ffba33a93f08d19372b322a53738d254dddfbc17d3a8012d192d04cb544e"),
                  (0x0801571A,6,"d020f9557dd744333a3ec78677af94b301b745a8556db834ddda1ab95ae27908"))


def validate_oracle(oracle):
    rows=oracle["rgb_task_start"]
    if oracle["payload_sha256"]!=PAYLOAD_SHA or [tuple(r[k] for k in ("mode","enable","suspend","old_timer","count","iter")) for r in rows]!=grid():raise ValueError("Incomplete task STARTING grid")
    for r in rows:
        if r["input_hits_hex"]!=hits(r["count"],2).hex() or r["first_clock"]!=(r["old_timer"]+1)&0xFFFFFFFF or r["second_clock"]!=(r["old_timer"]+4)&0xFFFFFFFF:raise ValueError("Changed task STARTING inputs")
    return rows


def program(reference,target,temp,negative=None):
    source,hashes=timers_program(reference,target,temp)
    read=lambda path:pinned_source(reference,path,hashes)
    impl=read("quantum/rgb_matrix/rgb_matrix.c");types=read("quantum/rgb_matrix/rgb_matrix_types.h");color=read("quantum/color.h");header=read("quantum/rgb_matrix/rgb_matrix.h")
    body=match(r"void rgb_matrix_task\(void\) \{.*?^\}",impl)
    if negative=="ignore_suspend":body=body.replace("suspend_backlight = suspend_state ||","suspend_backlight = false ||")
    elif negative=="enable1_only":body=body.replace("!rgb_matrix_config.enable","rgb_matrix_config.enable != 1")
    body=body.replace("switch (rgb_task_state)","task_selected_effect=effect;\n    switch (rgb_task_state)")
    body=body.replace("rgb_task_start();","task_observed_start();")
    text=source.read_text()
    if negative=="stale_tracker":
        text=text.replace("g_last_hit_tracker = last_hit_buffer;","g_last_hit_tracker = task_pre_age;")
        marker="static void rgb_task_start(void)"
        text=text.replace(marker,"static last_hit_t task_pre_age;\n"+marker)
    extra='''
''' + match(r"typedef struct PACKED hsv_t \{.*?\} hsv_t;",color) + '\n' + match(r"typedef union rgb_config_t \{.*?\} rgb_config_t;",types) + '\n' + match(r"#ifndef RGB_MATRIX_TIMEOUT\n.*?^#endif",header) + '''
#if RGB_MATRIX_TIMEOUT != 0
#error This bounded task profile requires the actual zero timeout
#endif
static rgb_config_t rgb_matrix_config;
''' + match(r"static bool\s+suspend_state\s*=\s*false;",impl) + '''
static uint32_t task_selected_effect,task_start_calls;
// Only STARTING is authorized in this harness. No mock completion or sync/save.
static void rgb_task_render(uint8_t effect) { (void)effect;__builtin_trap(); }
static void rgb_task_flush(uint8_t effect) { (void)effect;__builtin_trap(); }
static void rgb_task_sync(void) { __builtin_trap(); }
void rgb_matrix_indicators(void) { __builtin_trap(); }
void rgb_matrix_indicators_advanced(effect_params_t *p) { (void)p;__builtin_trap(); }
static void task_observed_start(void) { ++task_start_calls;if(clock_count!=2) __builtin_trap();rgb_task_start(); }
''' + body + '''
API void task_run(uint8_t mode,uint8_t enable,bool suspend,uint32_t old,uint8_t count,uint8_t iter,const uint8_t *input) {
    if(mode!=0 && mode!=15 && mode!=29 && mode!=45) __builtin_trap();
    if(enable>3 || (count!=0 && count!=8) || input[0]!=count) __builtin_trap();
    hit_source.before=hit_source.after=hit_dest.before=hit_dest.after=params.before=params.after=0xA5A5A5A5U;
    frame_clock.before=frame_clock.after=input_clock.before=input_clock.after=state.before=state.after=0xA5A5A5A5U;
    for(unsigned i=0;i<41;i++) { ((uint8_t *)&last_hit_buffer)[i]=input[i]; ((uint8_t *)&g_last_hit_tracker)[i]=0x5A; }
    uint8_t cfg[8]={(uint8_t)((mode<<2)|enable),17,254,255,128,4,0xA5,0xA5};
    for(unsigned i=0;i<8;i++) ((uint8_t *)&rgb_matrix_config)[i]=cfg[i];
    suspend_state=suspend;rgb_effect_params=(effect_params_t){iter,0xA5,true};rgb_task_state=STARTING;
    g_rgb_timer=old^UINT32_MAX;rgb_timer_buffer=old;clock_values[0]=old+1;clock_values[1]=old+4;clock_count=0;
    task_start_calls=0;task_selected_effect=UINT32_MAX;
''' + ("    task_pre_age=last_hit_buffer;\n" if negative=="stale_tracker" else "") + '''
    rgb_matrix_task();
    if(clock_count!=2 || task_start_calls!=1 || rgb_task_state!=RENDERING || suspend_state!=suspend ||
       hit_source.before!=0xA5A5A5A5U || hit_source.after!=0xA5A5A5A5U || hit_dest.before!=0xA5A5A5A5U || hit_dest.after!=0xA5A5A5A5U ||
       params.before!=0xA5A5A5A5U || params.after!=0xA5A5A5A5U || frame_clock.before!=0xA5A5A5A5U || frame_clock.after!=0xA5A5A5A5U ||
       input_clock.before!=0xA5A5A5A5U || input_clock.after!=0xA5A5A5A5U || state.before!=0xA5A5A5A5U || state.after!=0xA5A5A5A5U) __builtin_trap();
    for(unsigned i=0;i<8;i++) if(((uint8_t *)&rgb_matrix_config)[i]!=cfg[i]) __builtin_trap();
}
API uint32_t task_effect(void) { return task_selected_effect; }
API uint32_t task_starts(void) { return task_start_calls; }
'''
    source.write_text(text+extra)
    return source,hashes


def compare(lib,rows):
    lib.task_run.argtypes=[ctypes.c_uint8,ctypes.c_uint8,ctypes.c_bool,ctypes.c_uint32,ctypes.c_uint8,ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8)];lib.task_run.restype=None
    for name in ("task_effect","task_starts","start_clock","start_state","start_params","timers_clock","timers_reads"):getattr(lib,name).restype=ctypes.c_uint32
    lib.start_tracker.restype=lib.timers_hits.restype=ctypes.POINTER(ctypes.c_uint8)
    differences=0
    for r in rows:
        data=(ctypes.c_uint8*41).from_buffer_copy(bytes.fromhex(r["input_hits_hex"]))
        lib.task_run(*(r[k] for k in ("mode","enable","suspend","old_timer","count","iter")),data)
        differences+=(lib.task_effect()!=r["selected_effect"] or lib.task_starts()!=r["memcpy_calls"] or lib.timers_reads()!=r["clock_reads"] or
            lib.start_clock()!=r["frame_timer_after"] or lib.timers_clock()!=r["timer_buffer_after"] or lib.start_state()!=r["state_after"] or
            lib.start_params().to_bytes(4,"little")[:3].hex()!=r["params_after_hex"] or bytes(lib.start_tracker()[:41]).hex()!=r["tracker_after_hex"] or bytes(lib.timers_hits()[:41]).hex()!=r["aged_hits_hex"])
    return differences


def audit(raw,reference,target):
    recover(raw);validate_reference(reference);inspect_task_start(parse_uf2(raw));expected=artifacts(raw);inputs={name:(target/name).read_bytes() for name in expected}
    if any(v.decode()!=expected[k] for k,v in inputs.items()):raise ValueError("Changed target")
    profile=audit_target(raw,reference,target);path=ROOT/"tests/fixtures/original-rgb-task-start.json";data=path.read_bytes();rows=validate_oracle(json.loads(data))
    builders={name:(ROOT/"tools"/name).read_bytes() for name in ("audit_original_rgb_task_start.py","audit_original_rgb_timers.py","audit_original_rgb_start.py","audit_original_rgb_profile.py","EmulateOriginalVial.java")}
    cc=shutil.which("clang")
    if not cc:raise RuntimeError("Existing Clang required; nothing installed")
    differences={}
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-task-start-") as folder:
        for tag,opt,negative in (("base","-O0",None),("optimized","-O2",None),("ignore_suspend","-O0","ignore_suspend"),("enable1_only","-O0","enable1_only"),("stale_tracker","-O0","stale_tracker")):
            temp=Path(folder)/tag;temp.mkdir();source,hashes=program(reference,target,temp,negative);output=temp/"task-start.so"
            subprocess.run([cc,"-std=gnu11","-Wall","-Wextra","-Werror",opt,"-shared","-fPIC","-fvisibility=hidden","-I",str(temp),str(source),"-o",str(output)],check=True)
            differences[tag]=compare(ctypes.CDLL(str(output)),rows)
    if differences!={"base":0,"optimized":0,"ignore_suspend":108,"enable1_only":72,"stale_tracker":192}:raise AssertionError(f"Task STARTING differential failed:{differences}")
    if any((target/name).read_bytes()!=value for name,value in inputs.items()) or path.read_bytes()!=data or any((ROOT/"tools"/name).read_bytes()!=value for name,value in builders.items()):raise ValueError("Inputs changed during verification")
    return {"candidate_revision":REVISION,"source_sha256":hashes,"profile_source_sha256":profile["source_sha256"],"target_profile":profile["target_profile"],"target_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in inputs.items()},
        "oracle_sha256":hashlib.sha256(data).hexdigest(),"probe_builder_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in builders.items()},"cases_matched":384,"optimized_cases_matched":384,"negative_differences":differences,
        "actual_task_timers_selection_start_return_connected":True,"unsupported_render_flush_sync_paths_trap":True,"separately_entered_original_start":False,
        "physical_hardware_clock_executed":False,"original_thumb_executed_by_this_command":False,"target_changes_applied":False,
        "scope":"complete original task invocation from prologue through clock/aging/mode selection/STARTING/real epilogue/return vs actual SDK task/timers/start, clock getter only supplied. State0 only; modes0/15/29/45 are selection probes, not effect execution; render/flush/SYNCING/EEPROM/device not exercised",
        "sentinel":"ORIGINAL_RGB_TASK_START_AUDIT_COMPLETE"}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("uf2",type=Path);p.add_argument("--reference-dir",type=Path,required=True);p.add_argument("--target",type=Path,required=True)
    a=p.parse_args();print(json.dumps(audit(a.uf2.read_bytes(),a.reference_dir,a.target),indent=2))
