#!/usr/bin/env python3
"""Actual selected task calls, including independently reselected FLUSHING.

Clock/host APIs modeled; frame boundaries supplied, SYNCING unsupported.
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

from audit_original_rgb_cycle import program as cycle_program
from audit_original_rgb_timers import hits
from audit_original_rgb_task_start import inspect_task_start
from audit_original_rgb_flush import inspect_flush, pwm_digest
from audit_original_rgb_hsv import original_hsv_profile
from audit_original_rgb_mode15 import inspect_mode15
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA, pinned_source, inspect_mode29_image
from audit_original_rgb_profile import audit_target, match
from prepare_original_target import REVISION, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2

FRAMES=((15,1,32),(29,1,1000),(29,2,2000),(29,2,2004),(15,0,3000),(15,1,4000),(29,3,5000))
CALLS=(7,7,7,3,2,7,7)


def validate_oracle(oracle):
    sequences=oracle["rgb_task_cycles"]
    if oracle["payload_sha256"]!=PAYLOAD_SHA or len(sequences)!=8 or {(s["initial_seed"],s["caps"],s["group_word"]) for s in sequences}!=set(itertools.product((0,65535),(0,2),(0xA5B60000,0xA5B60101))):raise ValueError("Incomplete task cycle grid")
    schedule=[(frame,call) for frame,n in enumerate(CALLS) for call in range(n)]
    for seq in sequences:
        if seq["initial_hits_hex"]!=hits(8,2).hex() or seq["value"]!=(255 if seq["initial_seed"]==0 else 128) or [(r["frame"],r["call"]) for r in seq["steps"]]!=schedule:raise ValueError("Changed task cycle schedule")
        for r in seq["steps"]:
            f,c=r["frame"],r["call"];mode,enable,now=FRAMES[f];state=0 if c==0 else (2 if c==CALLS[f]-1 and f!=4 else 1);suspend=0
            if state==2:
                if f==0:mode=29
                if f==2:suspend=1
                if f==3:mode,enable=15,0
                if f==5:mode,enable=29,3
            if (r["state_before"],r["mode"],r["enable"],r["suspend"],r["flags"],r["first_clock"])!=(state,mode,enable,suspend,4 if f==5 and c>=3 else 255,now+c*4):raise ValueError("Changed task cycle inputs")
    return sequences


def inspect_task_cycle(image):
    inspect_task_start(image);inspect_flush(image);inspect_mode15(image);inspect_mode29_image(image)
    for address,size,expected in ((0x08015618,0x14A,"9bc2dd75347eb1fb413ca4b5ca8269f7e8d800fc56663dc6fe5eab92c0c15c03"),(0x08013320,96,"ec46c6ec912e8816cf535499d7289ea695f72210efc216e7504f65f7fff35d43")):
        if hashlib.sha256(image.read(address,size)).hexdigest()!=expected:raise ValueError("Changed selected task caller/encoder body")


def program(reference,target,temp,negative=None):
    source,hashes=cycle_program(reference,target,temp)
    read=lambda path:pinned_source(reference,path,hashes)
    impl=read("quantum/rgb_matrix/rgb_matrix.c");header=read("quantum/rgb_matrix/rgb_matrix.h");sync=read("quantum/sync_timer.h");timer_header=read("platforms/timer.h");timer=read("platforms/timer.c")
    macros="\n".join(match(p,t) for p,t in ((r"#define TIMER_DIFF_32[^\n]+",timer_header),(r"#\s+define sync_timer_read32\(\)[^\n]+",sync),(r"#\s+define sync_timer_elapsed32\(t\)[^\n]+",sync)))
    task=match(r"void rgb_matrix_task\(void\) \{.*?^\}",impl)
    if negative=="ignore_suspend":task=task.replace("suspend_backlight = suspend_state ||","suspend_backlight = false ||")
    if negative=="live_frame_clock":task=task.replace("rgb_task_timers();","rgb_task_timers();\n    g_rgb_timer=rgb_timer_buffer;")
    task=task.replace("switch (rgb_task_state)","task_selected=effect;\n    switch (rgb_task_state)").replace("rgb_task_render(effect);","cycle_observed_render(effect);")
    if source.read_text().count("uint32_t g_rgb_timer;")!=1:raise ValueError("Changed frame clock probe declaration")
    text=source.read_text().replace("uint32_t g_rgb_timer;",'''static struct { uint32_t before,value,after; } task_frame_clock;
#define g_rgb_timer task_frame_clock.value''')
    extra='''
#if defined(SPLIT_KEYBOARD) && !defined(DISABLE_SYNC_TIMER)
#error Only the actual nonsplit clock profile is supported
#endif
''' + match(r"#ifndef RGB_MATRIX_TIMEOUT\n.*?^#endif",header) + '''
#if RGB_MATRIX_TIMEOUT != 0
#error Only the actual zero-timeout profile is supported
#endif
''' + macros + '''
static struct { uint32_t before,value,after; } task_input_clock;
#define rgb_timer_buffer task_input_clock.value
static struct PACKED { uint8_t before[4];last_hit_t value;uint8_t after[4]; } task_tracker_storage;
#define g_last_hit_tracker task_tracker_storage.value
_Static_assert(sizeof(task_tracker_storage)==49 && sizeof(task_frame_clock)==12 && sizeof(task_input_clock)==12,"guarded actual tracker/timer sizes");
''' + match(r"static bool\s+suspend_state\s*=\s*false;",impl) + '''
static uint32_t clock_values[2],clock_count,task_selected,task_before;
''' + match(r"uint32_t timer_read32\(void\);",timer_header) + '''
uint32_t timer_read32(void) { if(clock_count>=2) __builtin_trap();return clock_values[clock_count++]; }
''' + match(r"uint32_t timer_elapsed32\([^\{]+\{.*?^\}",timer) + '\n' + match(r"static void rgb_task_timers\(void\) \{.*?^\}",impl) + '\n' + match(r"static void rgb_task_start\(void\) \{.*?^\}",impl) + '''
static void rgb_task_sync(void) { __builtin_trap(); } // No EEPROM/save/sync gate in this probe.
''' + task + '''
STAGE_API void task_cycle_reset(uint16_t seed,uint32_t group,uint8_t caps,const uint8_t *input) {
    cycle_reset(seed,group,caps);rgb_timer_buffer=31;g_rgb_timer=0;
    task_frame_clock.before=task_frame_clock.after=task_input_clock.before=task_input_clock.after=0xA5A5A5A5U;
    for(unsigned i=0;i<41;i++) { ((uint8_t *)&last_hit_buffer)[i]=input[i];((uint8_t *)&g_last_hit_tracker)[i]=0; }
    if(last_hit_buffer.count!=8) __builtin_trap();
    for(unsigned i=0;i<4;i++) { probe_hit_storage.before[i]=probe_hit_storage.after[i]=0xA5;task_tracker_storage.before[i]=task_tracker_storage.after[i]=0xA5; }
}
STAGE_API void task_cycle_step(uint8_t mode,uint8_t enable,uint8_t flags,bool suspend,uint32_t first,bool start,uint8_t value) {
    if((mode!=15 && mode!=29) || enable>3 || last_hit_buffer.count>8) __builtin_trap();
    if(start) { if(rgb_task_state!=SYNCING) __builtin_trap();rgb_task_state=STARTING; }
    if(rgb_task_state>FLUSHING) __builtin_trap();
    task_before=rgb_task_state;
    uint8_t cfg[8]={(uint8_t)((mode<<2)|enable),(uint8_t)(mode==29?17:0),(uint8_t)(mode==29?254:255),value,128,flags,0xA5,0xA5};
    for(unsigned i=0;i<8;i++) ((uint8_t *)&rgb_matrix_config)[i]=cfg[i];
    suspend_state=suspend;
    clock_values[0]=first;clock_values[1]=first+1;clock_count=0;task_selected=UINT32_MAX;
    cycle_len=cycle_render_len=cycle_hsv=probe_white_calls=flush_calls=0;
    rgb_matrix_task();
    if(clock_count!=2 || ws2812_frame_buffer[1952]!=0xA5A5A5A5U || suspend_state!=suspend) __builtin_trap();
    if(task_frame_clock.before!=0xA5A5A5A5U || task_frame_clock.after!=0xA5A5A5A5U || task_input_clock.before!=0xA5A5A5A5U || task_input_clock.after!=0xA5A5A5A5U) __builtin_trap();
    for(unsigned i=0;i<4;i++) if(probe_hit_storage.before[i]!=0xA5 || probe_hit_storage.after[i]!=0xA5 || task_tracker_storage.before[i]!=0xA5 || task_tracker_storage.after[i]!=0xA5) __builtin_trap();
    for(unsigned i=0;i<8;i++) if(((uint8_t *)&rgb_matrix_config)[i]!=cfg[i]) __builtin_trap();
}
STAGE_API uint32_t task_cycle_meta(unsigned i) {
    uint32_t values[]={rgb_effect_params.iter|((uint32_t)rgb_effect_params.flags<<8)|((uint32_t)rgb_effect_params.init<<16),
        rgb_last_effect|((uint32_t)rgb_last_enable<<8)|((uint32_t)rgb_task_state<<16),rand16seed,probe_white_calls,flush_calls,
        task_selected,clock_count,g_rgb_timer,rgb_timer_buffer,cycle_hsv,cycle_render_len,task_before};
    if(i>=12) __builtin_trap();
    return values[i];
}
STAGE_API const uint8_t *task_hits(bool tracker) { return tracker?(const uint8_t *)&g_last_hit_tracker:(const uint8_t *)&last_hit_buffer; }
'''
    # Keep the actual task and all selected bodies in one TU. Legacy cycle_step
    # exists but is not called; this API never writes frame timer or iter directly.
    source.write_text(text+extra)
    return source,hashes


def compare(lib,seq,curve):
    lib.task_cycle_reset.argtypes=[ctypes.c_uint16,ctypes.c_uint32,ctypes.c_uint8,ctypes.POINTER(ctypes.c_uint8)];lib.task_cycle_reset.restype=None
    lib.task_cycle_step.argtypes=[ctypes.c_uint8]*3+[ctypes.c_bool,ctypes.c_uint32,ctypes.c_bool,ctypes.c_uint8];lib.task_cycle_step.restype=None
    lib.task_cycle_meta.argtypes=[ctypes.c_uint];lib.task_cycle_meta.restype=ctypes.c_uint32
    lib.task_hits.argtypes=[ctypes.c_bool];lib.task_hits.restype=lib.stage_grb.restype=lib.cycle_curve.restype=ctypes.POINTER(ctypes.c_uint8)
    lib.cycle_records.restype=lib.flush_pwm_words.restype=ctypes.POINTER(ctypes.c_uint32)
    lib.stage_unexpected_io.restype=lib.stage_group.restype=ctypes.c_uint32
    if bytes(lib.cycle_curve()[:256])!=curve:raise AssertionError("Changed CIE table")
    data=(ctypes.c_uint8*41).from_buffer_copy(bytes.fromhex(seq["initial_hits_hex"]))
    lib.task_cycle_reset(seq["initial_seed"],seq["group_word"],seq["caps"],data)
    differences=0
    for r in seq["steps"]:
        lib.task_cycle_step(r["mode"],r["enable"],r["flags"],r["suspend"],r["first_clock"],r["call"]==0,seq["value"])
        m=[lib.task_cycle_meta(i) for i in range(12)];trace=[];offset=0;p=lib.cycle_records()
        if m[10]>2048:raise AssertionError("Render trace out of bounds")
        while offset<m[10]:
            kind=p[offset];n=4 if kind==0 else 5 if kind==1 else 0
            if not n or offset+n>m[10]:raise AssertionError("Bad render trace")
            trace.append(list(p[offset:offset+n]));offset+=n
        if lib.stage_unexpected_io() or lib.stage_group()!=seq["group_word"]:raise AssertionError("Task requested IO/changed group")
        differences+=(m[0].to_bytes(4,"little")[:3].hex()!=r["params_after_hex"] or [m[1]&255,(m[1]>>8)&255,(m[1]>>16)&255]!=r["trackers_state"] or
            m[2]!=r["seed_after"] or m[3]!=r["caps_white_calls"] or m[4]!=r["flush_calls"] or m[5]!=r["selected_effect"] or m[6]!=r["clock_reads"] or
            m[7]!=r["frame_timer_after"] or m[8]!=r["timer_buffer_after"] or m[9]!=r["hsv_calls"] or m[11]!=r["state_before"] or trace!=r["render_trace"] or
            bytes(lib.task_hits(False)[:41]).hex()!=r["hits_after_hex"] or bytes(lib.task_hits(True)[:41]).hex()!=r["hit_tracker_hex"] or
            bytes(lib.stage_grb()[:216]).hex()!=r["grb_hex"] or pwm_digest(lib.flush_pwm_words())!=r["pwm_sha256"])
    return differences


def audit(raw,reference,target):
    recover(raw);validate_reference(reference);inspect_task_cycle(parse_uf2(raw));expected=artifacts(raw);inputs={name:(target/name).read_bytes() for name in expected}
    if any(v.decode()!=expected[k] for k,v in inputs.items()):raise ValueError("Changed target")
    profile=audit_target(raw,reference,target);path=ROOT/"tests/fixtures/original-rgb-task-cycle.json";data=path.read_bytes();sequences=validate_oracle(json.loads(data))
    builders={name:(ROOT/"tools"/name).read_bytes() for name in ("audit_original_rgb_task_cycle.py","audit_original_rgb_cycle.py","audit_original_rgb_flush.py","audit_original_rgb_render_begin.py","audit_original_rgb_mode15_staging.py","audit_original_rgb_task_start.py","audit_original_rgb_timers.py","audit_original_rgb_mode15.py","audit_original_rgb_mode29.py","prepare_original_target.py","verify_original_target_rgb.py","EmulateOriginalVial.java")}
    cc=next((shutil.which(n) for n in ("gcc-16","gcc-15","gcc-14","gcc-13") if shutil.which(n)),None)
    if not cc:raise RuntimeError("Existing GNU compiler required; nothing installed")
    curve=original_hsv_profile(raw);differences={}
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-task-cycle-") as folder:
        for tag,opt,negative in (("base","-O0",None),("optimized","-O2",None),("ignore_suspend","-O0","ignore_suspend"),("live_frame_clock","-O0","live_frame_clock")):
            temp=Path(folder)/tag;temp.mkdir();source,hashes=program(reference,target,temp,negative);count=0
            for index,seq in enumerate(sequences):
                output=temp/f"task-{index}.so"
                subprocess.run([cc,"-std=gnu11","-Wall","-Wextra","-Werror","-Wno-error=override-init","-Wno-error=unused-parameter",opt,"-shared","-fPIC","-fvisibility=hidden","-DUSE_CIE1931_CURVE","-DFASTLED_SCALE8_FIXED=1","-DFASTLED_BLEND_FIXED=1","-I",str(temp),"-I",str(temp/"platform_headers"),"-I",str(reference/"drivers/led"),str(source),str(temp/"color.c"),str(temp/"led_tables.c"),"-o",str(output)],check=True)
                count+=compare(ctypes.CDLL(str(output)),seq,curve)
            differences[tag]=count
    if differences!={"base":0,"optimized":0,"ignore_suspend":40,"live_frame_clock":272}:raise AssertionError(f"Task cycle differential failed:{differences}")
    if any((target/name).read_bytes()!=value for name,value in inputs.items()) or path.read_bytes()!=data or any((ROOT/"tools"/name).read_bytes()!=value for name,value in builders.items()):raise ValueError("Inputs changed during verification")
    return {"candidate_revision":REVISION,"source_sha256":hashes,"profile_source_sha256":profile["source_sha256"],"target_profile":profile["target_profile"],"target_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in inputs.items()},
        "oracle_sha256":hashlib.sha256(data).hexdigest(),"probe_builder_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in builders.items()},"sequences_matched":8,"calls_matched":320,"optimized_calls_matched":320,"negative_differences":differences,
        "actual_task_start_render_post_following_flush_connected":True,"original_post_separately_entered":False,"sync_executed":False,"target_changes_applied":False,"native_io_requests":0,"native_private_cache_wait_directly_compared":False,
        "original_thumb_executed_by_this_command":False,"scope":"genuine task calls with actual clock/aging/selection/start/render/post and separate next-call flush; clock/host getters only modeled. Frame state0 supplied after state3; SYNCING/EEPROM/save/scheduler/device unsupported. Only0/15/29 execute, all other effects/cadet/sync trap; render-only traces plus final GRB/PWM, not post API ordering",
        "sentinel":"ORIGINAL_RGB_TASK_CYCLE_AUDIT_COMPLETE"}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("uf2",type=Path);p.add_argument("--reference-dir",type=Path,required=True);p.add_argument("--target",type=Path,required=True)
    a=p.parse_args();print(json.dumps(audit(a.uf2.read_bytes(),a.reference_dir,a.target),indent=2))
