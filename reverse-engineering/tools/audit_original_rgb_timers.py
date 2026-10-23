#!/usr/bin/env python3
"""Actual RGB timer/aging prefix, getter-only clock model; no hardware/task."""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_original_rgb_start import program as start_program
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA, pinned_source
from audit_original_rgb_profile import audit_target, match
from prepare_original_target import REVISION, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2

DELTAS = (0,1,15,16,65534,65535,65536,65537,0xFFFFFFFF)
TICKS = ((0,)*8,(0,1,65534,65535,5,65530,7,65520),(65535,0,65534,1,65535,2,65530,3))


def grid():
    return list(itertools.product((0,0xFFFFFFF0),DELTAS,(0,3),(0,1,4,8),range(3)))


def hits(count,pattern):
    data=bytearray((i*73+19)&255 for i in range(41));data[0]=count
    for i,tick in enumerate(TICKS[pattern]):data[25+2*i:27+2*i]=tick.to_bytes(2,"little")
    return bytes(data)


def age_model(data,delta,saturate=False,zero_expired=False):
    """Independent byte-level replay/counterfactual, not candidate execution."""
    result=bytearray(data);limit=(65535-delta)&0xFFFFFFFF
    for i in range(data[0]):
        start=25+2*i;tick=int.from_bytes(data[start:start+2],"little")
        if (saturate and delta>65535) or limit<tick:
            result[0]-=1
            if zero_expired:result[start:start+2]=b"\0\0"
        else:result[start:start+2]=((tick+delta)&65535).to_bytes(2,"little")
    return bytes(result)


def inspect_timers(image):
    # Pin independently inspected complete ranges, not just clock BL sites.
    for address,size,expected in TIMER_WITNESSES:
        if hashlib.sha256(image.read(address,size)).hexdigest()!=expected:raise ValueError("Changed timer/aging instruction witness")
    for address,value in ((0x08015780,0x20001CE8),(0x08015784,0x20001AC6)):
        if int.from_bytes(image.read(address,4),"little")!=value:raise ValueError("Changed timer/aging pointer")


TIMER_WITNESSES = ((0x08015618,64,"f26f499d902e68820cc96d0c9a816a38849a6cf8fd918cfd5e3f2740b3e2f29d"),
                   (0x0801567A,48,"27b78d867ebb6aeab4934a426774c3d2ac547f2e8dce35dc8cf5ae2979b9ef96"))


def validate_oracle(oracle):
    rows=oracle["rgb_timers"]
    if oracle["payload_sha256"]!=PAYLOAD_SHA or [tuple(r[k] for k in ("old_timer","delta","skew","count","pattern")) for r in rows]!=grid():raise ValueError("Incomplete clock/aging grid")
    for r in rows:
        first=(r["old_timer"]+r["delta"])&0xFFFFFFFF
        if r["input_hits_hex"]!=hits(r["count"],r["pattern"]).hex() or r["first_clock"]!=first or r["second_clock"]!=(first+r["skew"])&0xFFFFFFFF:raise ValueError("Changed clock/aging input")
    return rows


def program(reference,target,temp,negative=None):
    source,hashes=start_program(reference,target,temp)
    read=lambda path:pinned_source(reference,path,hashes)
    impl=read("quantum/rgb_matrix/rgb_matrix.c");sync=read("quantum/sync_timer.h");header=read("platforms/timer.h");timer=read("platforms/timer.c")
    macros="\n".join(match(pattern,content) for pattern,content in (
        (r"#define TIMER_DIFF_32[^\n]+",header),(r"#\s+define sync_timer_read32\(\)[^\n]+",sync),(r"#\s+define sync_timer_elapsed32\(t\)[^\n]+",sync)))
    elapsed=match(r"uint32_t timer_elapsed32\([^\{]+\{.*?^\}",timer)
    body=match(r"static void rgb_task_timers\(void\) \{.*?^\}",impl)
    if negative=="delta_from_second":
        body=body.replace("uint32_t deltaTime = sync_timer_elapsed32(rgb_timer_buffer);","uint32_t previous = rgb_timer_buffer;\n    uint32_t deltaTime = sync_timer_elapsed32(rgb_timer_buffer);")
        body=body.replace("rgb_timer_buffer = sync_timer_read32();","rgb_timer_buffer = sync_timer_read32();\n    deltaTime = TIMER_DIFF_32(rgb_timer_buffer, previous);")
    elif negative=="saturate_age":body=body.replace("UINT16_MAX - deltaTime <", "deltaTime > UINT16_MAX || UINT16_MAX - deltaTime <")
    elif negative=="zero_expired":body=body.replace("last_hit_buffer.count--;", "last_hit_buffer.count--;\n            last_hit_buffer.tick[i] = 0;")
    source.write_text(source.read_text()+'''
#if defined(SPLIT_KEYBOARD) && !defined(DISABLE_SYNC_TIMER)
#error This probe requires the actual nonsplit timer profile
#endif
''' + macros + '''
static uint32_t clock_values[2],clock_count;
''' + match(r"uint32_t timer_read32\(void\);",header) + '''
uint32_t timer_read32(void) { if(clock_count>=2) __builtin_trap(); return clock_values[clock_count++]; }
''' + elapsed + '\n' + body + '''
API void timers_run(uint32_t old,uint32_t first,uint32_t second,const uint8_t *input) {
    hit_source.before=hit_source.after=hit_dest.before=hit_dest.after=params.before=params.after=0xA5A5A5A5U;
    frame_clock.before=frame_clock.after=input_clock.before=input_clock.after=state.before=state.after=0xA5A5A5A5U;
    for(unsigned i=0;i<41;i++) { ((uint8_t *)&last_hit_buffer)[i]=input[i]; ((uint8_t *)&g_last_hit_tracker)[i]=0x5A; }
    rgb_effect_params=(effect_params_t){4,0xA5,true}; rgb_task_state=SYNCING;
    g_rgb_timer=old^UINT32_MAX;rgb_timer_buffer=old;clock_values[0]=first;clock_values[1]=second;clock_count=0;
    rgb_task_timers();
    if(clock_count!=2 || hit_source.before!=0xA5A5A5A5U || hit_source.after!=0xA5A5A5A5U || hit_dest.before!=0xA5A5A5A5U || hit_dest.after!=0xA5A5A5A5U ||
       params.before!=0xA5A5A5A5U || params.after!=0xA5A5A5A5U || frame_clock.before!=0xA5A5A5A5U || frame_clock.after!=0xA5A5A5A5U ||
       input_clock.before!=0xA5A5A5A5U || input_clock.after!=0xA5A5A5A5U || state.before!=0xA5A5A5A5U || state.after!=0xA5A5A5A5U ||
       g_rgb_timer!=(old^UINT32_MAX) || rgb_task_state!=SYNCING || rgb_effect_params.iter!=4 || rgb_effect_params.flags!=0xA5 || !rgb_effect_params.init) __builtin_trap();
    for(unsigned i=0;i<41;i++) if(((const uint8_t *)&g_last_hit_tracker)[i]!=0x5A) __builtin_trap();
}
API const uint8_t *timers_hits(void) { return (const uint8_t *)&last_hit_buffer; }
API uint32_t timers_clock(void) { return rgb_timer_buffer; }
API uint32_t timers_reads(void) { return clock_count; }
''')
    return source,hashes


def compare(lib,rows):
    lib.timers_run.argtypes=[ctypes.c_uint32]*3+[ctypes.POINTER(ctypes.c_uint8)];lib.timers_run.restype=None
    lib.timers_hits.restype=ctypes.POINTER(ctypes.c_uint8)
    lib.timers_clock.restype=lib.timers_reads.restype=ctypes.c_uint32
    differences=0
    for r in rows:
        data=(ctypes.c_uint8*41).from_buffer_copy(bytes.fromhex(r["input_hits_hex"]))
        lib.timers_run(r["old_timer"],r["first_clock"],r["second_clock"],data)
        differences+=(bytes(lib.timers_hits()[:41]).hex()!=r["hits_after_hex"] or lib.timers_clock()!=r["timer_buffer_after"] or lib.timers_reads()!=r["clock_reads"])
    return differences


def audit(raw,reference,target):
    recover(raw);validate_reference(reference);inspect_timers(parse_uf2(raw))
    expected=artifacts(raw);inputs={name:(target/name).read_bytes() for name in expected}
    if any(v.decode()!=expected[k] for k,v in inputs.items()):raise ValueError("Changed target")
    profile=audit_target(raw,reference,target)
    path=ROOT/"tests/fixtures/original-rgb-timers.json";data=path.read_bytes();rows=validate_oracle(json.loads(data))
    builders={name:(ROOT/"tools"/name).read_bytes() for name in ("audit_original_rgb_timers.py","audit_original_rgb_start.py","audit_original_rgb_profile.py","EmulateOriginalVial.java")}
    cc=shutil.which("clang")
    if not cc:raise RuntimeError("Existing Clang required; nothing installed")
    differences={}
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-timers-") as folder:
        for tag,opt,negative in (("base","-O0",None),("optimized","-O2",None),("delta_from_second","-O0","delta_from_second"),("saturate_age","-O0","saturate_age"),("zero_expired","-O0","zero_expired")):
            temp=Path(folder)/tag;temp.mkdir();source,hashes=program(reference,target,temp,negative);output=temp/"timers.so"
            subprocess.run([cc,"-std=gnu11","-Wall","-Wextra","-Werror",opt,"-shared","-fPIC","-fvisibility=hidden","-I",str(temp),str(source),"-o",str(output)],check=True)
            differences[tag]=compare(ctypes.CDLL(str(output)),rows)
    expected={"base":0,"optimized":0}
    for tag in ("delta_from_second","saturate_age","zero_expired"):
        expected[tag]=sum(age_model(bytes.fromhex(r["input_hits_hex"]),(r["delta"]+r["skew"])&0xFFFFFFFF if tag=="delta_from_second" else r["delta"],tag=="saturate_age",tag=="zero_expired").hex()!=r["hits_after_hex"] for r in rows)
    if differences!=expected or not all(differences[k] for k in expected if k not in ("base","optimized")):raise AssertionError(f"Timers differential failed:{differences},expected{expected}")
    if any((target/name).read_bytes()!=value for name,value in inputs.items()) or path.read_bytes()!=data or any((ROOT/"tools"/name).read_bytes()!=value for name,value in builders.items()):raise ValueError("Inputs changed during verification")
    return {"candidate_revision":REVISION,"timer_source_sha256":hashes,"profile_source_sha256":profile["source_sha256"],"target_profile":profile["target_profile"],"target_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in inputs.items()},
        "oracle_sha256":hashlib.sha256(data).hexdigest(),"probe_builder_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in builders.items()},"cases_matched":432,"optimized_cases_matched":432,"negative_differences":differences,
        "actual_sdk_timers_and_elapsed32_executed":True,"clock_getter_only_modeled":True,"physical_hardware_clock_executed":False,"original_thumb_executed_by_this_command":False,"target_changes_applied":False,
        "scope":"actual original prologue/clock/aging prefix vs actual SDK timers/nonsplit sync macros/elapsed32; getter returns two supplied uint32 snapshots. Stops before selection/task/start/render/flush/sync, no physical/HAL/EEPROM. Count0/1/4/8, opaque XY/index bytes not used for LED lookup; raw count255 excluded",
        "sentinel":"ORIGINAL_RGB_TIMERS_AUDIT_COMPLETE"}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("uf2",type=Path);p.add_argument("--reference-dir",type=Path,required=True);p.add_argument("--target",type=Path,required=True)
    a=p.parse_args();print(json.dumps(audit(a.uf2.read_bytes(),a.reference_dir,a.target),indent=2))
