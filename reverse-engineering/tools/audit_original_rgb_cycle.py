#!/usr/bin/env python3
"""Selected actual render/post/flush cycles in one native library, no completion stub.

Only modes0/15/29 execute. Other effects fail closed. Not complete task/HAL/device.
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

from audit_original_rgb_flush import program as flush_program, pwm_digest, inspect_flush
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA, math_sources, pinned_source, inspect_mode29_image
from audit_original_rgb_mode15 import inspect_mode15
from audit_original_rgb_hsv import color_program, original_hsv_profile
from audit_original_rgb_profile import candidate_program, audit_target, match
from prepare_original_target import REVISION, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2

FRAMES = ((15,0,255,0),(15,0,255,16),(15,1,255,32),(15,1,4,48),(29,1,255,1000),(29,1,255,1001),(29,2,255,1002),(29,2,255,5000),(29,0,255,5016),(29,0,255,5032))


def validate_oracle(oracle):
    sequences = oracle["rgb_cycles"]
    expected = set(itertools.product((0,65535),(0,2),((0,0),(0,1),(1,0),(1,1))))
    actual = {(s["initial_seed"],s["caps"],(s["group_word"]&255,(s["group_word"]>>8)&255)) for s in sequences}
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(sequences) != 16 or actual != expected:
        raise ValueError("Incomplete selected cycle grid")
    for seq in sequences:
        if (len(seq["steps"]) != 26 or seq["group_word"] >> 16 != 0xA5B6 or seq["value"] != (255 if seq["initial_seed"] == 0 else 128) or
            seq["initial_grb_hex"] != bytes((i*73+19)&255 for i in range(216)).hex()):
            raise ValueError("Changed cycle scenario")
        schedule = [(frame,chunk) for frame in range(10) for chunk in range(5 if frame in (2,3,4,7) else 1)]
        if [(r["frame"],r["chunk"]) for r in seq["steps"]] != schedule:
            raise ValueError("Changed cycle chunk schedule")
        for row in seq["steps"]:
            mode, enable, flags, now = FRAMES[row["frame"]]
            if (row["mode"],row["enable"],row["flags"],row["now"],row["effect"]) != (mode,enable,flags,now,mode if enable else 0):
                raise ValueError("Changed selected cycle frame input")
    return sequences


def program(reference,target,temp,negative=None):
    source,hashes = flush_program(reference,target,temp)
    _,profile_hashes,_ = candidate_program(reference,temp,target)
    hashes.update(profile_hashes)
    hashes.update(math_sources(reference,temp))
    _,colors = color_program(reference,temp); hashes.update(colors)
    read = lambda path: pinned_source(reference,path,hashes)
    implementation=read("quantum/rgb_matrix/rgb_matrix.c")
    header=read("quantum/rgb_matrix/rgb_matrix.h")
    color=read("quantum/color.h")
    types=read("quantum/rgb_matrix/rgb_matrix_types.h")
    # Replace the legacy completion-only renderer definition, not its callers.
    weak_path=temp/"weak_dispatch.c"; weak=weak_path.read_text()
    stub=match(r"static void rgb_task_render\(uint8_t effect\) \{.*?^\}",weak)
    if "probe_render_complete ? FLUSHING : RENDERING" not in stub:
        raise ValueError("Changed legacy completion stub")
    weak=weak.replace(stub,"static void rgb_task_render(uint8_t effect);")
    weak=weak.replace(match(r"void probe_render_chunk\([^\{]+\{.*?^\}",weak),"").replace("static uint8_t probe_render_complete;","")
    weak_path.write_text(weak)
    text=source.read_text()
    text=text.replace(match(r"STAGE_API void stage_post\([^\{]+\{.*?^\}",text),"")
    # This harness executes RGB only. Do not drag the unrelated cadet timer
    # inline declarations into GNU's RGB TU or weaken its diagnostics.
    # Exact SDK API signatures remain; accidental feature execution traps.
    cadet_header=read("quantum/process_keycode/process_space_cadet.h")
    for declaration in ("void perform_space_cadet(keyrecord_t *record, uint16_t sc_keycode, uint8_t holdMod, uint8_t tapMod, uint8_t keycode);",
                        "bool process_space_cadet(uint16_t keycode, keyrecord_t *record);", "void reset_space_cadet(void);"):
        if declaration not in cadet_header: raise ValueError("Changed cadet boundary declaration")
    text=text.replace('#include "space_cadet.c"', '''
void perform_space_cadet(keyrecord_t *r,uint16_t sc,uint8_t hold,uint8_t tap,uint8_t key) { (void)r;(void)sc;(void)hold;(void)tap;(void)key;__builtin_trap(); }
bool process_space_cadet(uint16_t key,keyrecord_t *r) { (void)key;(void)r;__builtin_trap(); }
void reset_space_cadet(void) { __builtin_trap(); }
''')
    text=text.replace(match(r"void probe_cadet_seed\([^{]+\{.*?^\}",text),"")
    text=re.sub(r"uint32_t probe_cadet_state\(void\) \{[^\n]+\n","",text)
    for name in ("rgb_t","hsv_t"):
        declaration=match(r"typedef struct PACKED "+name+r" \{.*?\} "+name+";",color)
        text=text.replace(declaration,'#include "color.h"' if name=="rgb_t" else "")
    # Remove legacy nonsplit setter adapters; actual SDK wrappers use its vtable.
    old_single=match(r"void rgb_matrix_set_color\(int index,[^\{]+\{.*?^\}",text)
    text=text.replace(old_single,"void rgb_matrix_set_color(int index,uint8_t r,uint8_t g,uint8_t b);")
    old_all=match(r"void rgb_matrix_set_color_all\(uint8_t r,uint8_t g,uint8_t b\) \{.*?^\}",text)
    text=text.replace(old_all,"void rgb_matrix_set_color_all(uint8_t r,uint8_t g,uint8_t b);")
    led_index=match(r"__attribute__\(\(weak\)\) int rgb_matrix_led_index\(int index\) \{.*?^\}",implementation)
    single=match(r"void rgb_matrix_set_color\(int index,[^\{]+\{.*?^\}",implementation)
    all_color=match(r"void rgb_matrix_set_color_all\([^\{]+\{.*?^\}",implementation)
    render=match(r"static void rgb_task_render\(uint8_t effect\) \{.*?^\}",implementation)
    if negative=="boolean_enable":
        render=render.replace("(rgb_matrix_config.enable != rgb_last_enable)","(!!rgb_matrix_config.enable != !!rgb_last_enable)")
    none=match(r"static bool rgb_matrix_none\([^\{]+\{.*?^\}",implementation)
    enum=match(r"enum rgb_matrix_effects \{.*?^\};",header)
    macros=header[header.index("#define RGB_MATRIX_USE_LIMITS_ITER"):header.index("enum rgb_matrix_effects")]
    finished=match(r"static inline bool rgb_matrix_check_finished_leds\([^\{]+\{.*?^\}",header)
    center=match(r"#ifndef RGB_MATRIX_CENTER\n.*?^#endif",implementation)
    hsv=match(r"__attribute__\(\(weak\)\) rgb_t rgb_matrix_hsv_to_rgb\([^\{]+\{.*?^\}",implementation)
    rendering=match(r"        case RENDERING:.*?(?=        case FLUSHING:)",implementation)
    rendering=rendering.replace("rgb_task_render(effect);","cycle_observed_render(effect);")
    runner=read("quantum/rgb_matrix/animations/runners/effect_runner_i.h"); (temp/"effect_runner_i.h").write_text(runner)
    # Catalog headers staged by the real target profile. Only selected bodies
    # instantiate; every other callable name maps to an explicit trap.
    names=set()
    effects=(temp/"rgb_matrix_effects.inc").read_text()
    for filename in re.findall(r'#include "([a-z_]+\.h)"',effects):
        names.update(re.findall(r'RGB_MATRIX_EFFECT\((\w+)',(temp/filename).read_text()))
    aliases="\n".join(f"#define {name}(params) cycle_unsupported(params)" for name in sorted(names-{"PIXEL_FLOW","RAINBOW_MOVING_CHEVRON"}))
    extra='''
#include "lib8tion.h"
#include "led_tables.h"
#define VIALRGB_ENABLE
#include "rgb_post_config.h"
''' + enum + '''
_Static_assert(RGB_MATRIX_RAINBOW_MOVING_CHEVRON==15 && RGB_MATRIX_PIXEL_FLOW==29 && RGB_MATRIX_EFFECT_MAX==46,"actual target enum");
uint16_t rand16seed;
uint32_t g_rgb_timer;
static uint32_t cycle_trace[2048],cycle_len,cycle_render_len,cycle_hsv,cycle_render_state,cycle_last,cycle_flush;
static uint8_t cycle_before[216],cycle_after[216];
static void cycle_push(uint32_t v) { if(cycle_len>=2048) __builtin_trap(); cycle_trace[cycle_len++]=v; }
''' + led_index + '''
#define rgb_matrix_set_color cycle_sdk_color
''' + single + '''
#undef rgb_matrix_set_color
void rgb_matrix_set_color(int index,uint8_t r,uint8_t g,uint8_t b) {
    cycle_push(1);cycle_push(index);cycle_push(r);cycle_push(g);cycle_push(b);
    if(index==22 && r==255 && g==255 && b==255) ++probe_white_calls;
    cycle_sdk_color(index,r,g,b);
}
#define rgb_matrix_set_color_all cycle_sdk_all
''' + all_color + '''
#undef rgb_matrix_set_color_all
void rgb_matrix_set_color_all(uint8_t r,uint8_t g,uint8_t b) {
    cycle_push(0);cycle_push(r);cycle_push(g);cycle_push(b);cycle_sdk_all(r,g,b);
}
#define rgb_matrix_hsv_to_rgb cycle_sdk_hsv
''' + hsv + '''
#undef rgb_matrix_hsv_to_rgb
rgb_t rgb_matrix_hsv_to_rgb(hsv_t value) { ++cycle_hsv; return cycle_sdk_hsv(value); }
#undef RGB_MATRIX_USE_LIMITS_ITER
#undef RGB_MATRIX_USE_LIMITS
#undef RGB_MATRIX_TEST_LED_FLAGS
''' + match(r"#define HAS_ANY_FLAGS[^\n]+",types) + '\n' + macros + '\n' + finished + '\n' + center + '''
#include "effect_runner_i.h"
#define RGB_MATRIX_EFFECT(name,...)
#define RGB_MATRIX_CUSTOM_EFFECT_IMPLS
#include "rainbow_moving_chevron_anim.h"
#include "pixel_flow_anim.h"
#undef RGB_MATRIX_CUSTOM_EFFECT_IMPLS
#undef RGB_MATRIX_EFFECT
static bool cycle_unsupported(effect_params_t *p) { (void)p; __builtin_trap(); }
void rgb_matrix_test(void) { __builtin_trap(); }
''' + aliases + '\n' + none + '\n' + render + '''
static void cycle_observed_render(uint8_t effect) {
    cycle_len=cycle_hsv=0;
    rgb_task_render(effect);
    cycle_render_len=cycle_len; cycle_render_state=rgb_task_state;
    cycle_last=rgb_last_effect|((uint32_t)rgb_last_enable<<8);
    for(unsigned i=0;i<216;i++) cycle_before[i]=((uint8_t *)ws2812_leds)[i];
    probe_white_calls=0;
}
STAGE_API void cycle_reset(uint16_t seed,uint32_t group,uint8_t caps) {
    uint8_t pixels[216]; for(unsigned i=0;i<216;i++) pixels[i]=(uint8_t)(i*73+19);
    stage_seed(pixels,group,caps); rand16seed=seed;
    rgb_effect_params=(effect_params_t){0,0,false}; rgb_last_effect=rgb_last_enable=255; rgb_task_state=SYNCING;
    for(unsigned i=0;i<1953;i++) ws2812_frame_buffer[i]=0xA5A5A5A5U;
}
#ifdef PROBE_SKIP_POST
#define rgb_matrix_indicators() ((void)0)
#define rgb_matrix_indicators_advanced(params) ((void)0)
#endif
STAGE_API void cycle_step(uint8_t mode,uint8_t enable,uint8_t flags,uint32_t now,uint8_t value,bool start) {
    if(mode!=15 && mode!=29) __builtin_trap();
    uint8_t cfg[8]={(uint8_t)((mode<<2)|enable),(uint8_t)(mode==29?17:0),(uint8_t)(mode==29?254:255),value,128,flags,0xA5,0xA5};
    for(unsigned i=0;i<8;i++) ((uint8_t *)&rgb_matrix_config)[i]=cfg[i];
    g_rgb_timer=now;
    if(start) { rgb_effect_params.iter=0; rgb_task_state=RENDERING; }
    if(rgb_task_state!=RENDERING) __builtin_trap();
    uint8_t effect=enable?mode:0;
    switch(rgb_task_state) {
''' + rendering + '''
    default: __builtin_trap();
    }
    for(unsigned i=0;i<216;i++) cycle_after[i]=((uint8_t *)ws2812_leds)[i];
    cycle_flush=rgb_task_state==FLUSHING; flush_calls=0;
    if(cycle_flush) rgb_task_flush(effect);
    if(flush_calls!=cycle_flush || ws2812_frame_buffer[1952]!=0xA5A5A5A5U) __builtin_trap();
    for(unsigned i=0;i<8;i++) if(((uint8_t *)&rgb_matrix_config)[i]!=cfg[i]) __builtin_trap();
}
STAGE_API uint32_t cycle_meta(unsigned i) {
    uint32_t values[]={rgb_effect_params.iter|((uint32_t)rgb_effect_params.flags<<8)|((uint32_t)rgb_effect_params.init<<16),cycle_render_state,
        cycle_last,rand16seed,probe_white_calls,cycle_flush,rgb_last_effect|((uint32_t)rgb_last_enable<<8)|((uint32_t)rgb_task_state<<16),cycle_hsv,cycle_render_len};
    if(i>=9) __builtin_trap();
    return values[i];
}
STAGE_API const uint32_t *cycle_records(void) { return cycle_trace; }
STAGE_API const uint8_t *cycle_pixels(bool after) { return after?cycle_after:cycle_before; }
STAGE_API const uint8_t *cycle_curve(void) { return CIE1931_CURVE; }
'''
    source.write_text(text+extra)
    return source,hashes


def compare(lib,seq,curve):
    lib.cycle_reset.argtypes=[ctypes.c_uint16,ctypes.c_uint32,ctypes.c_uint8];lib.cycle_reset.restype=None
    lib.cycle_step.argtypes=[ctypes.c_uint8,ctypes.c_uint8,ctypes.c_uint8,ctypes.c_uint32,ctypes.c_uint8,ctypes.c_bool];lib.cycle_step.restype=None
    lib.cycle_meta.argtypes=[ctypes.c_uint];lib.cycle_meta.restype=ctypes.c_uint32
    lib.cycle_records.restype=lib.flush_pwm_words.restype=ctypes.POINTER(ctypes.c_uint32)
    lib.cycle_pixels.argtypes=[ctypes.c_bool];lib.cycle_pixels.restype=ctypes.POINTER(ctypes.c_uint8)
    lib.cycle_curve.restype=ctypes.POINTER(ctypes.c_uint8)
    lib.stage_unexpected_io.restype=lib.stage_group.restype=ctypes.c_uint32
    if bytes(lib.cycle_curve()[:256])!=curve:raise AssertionError("CIE table differs")
    lib.cycle_reset(seq["initial_seed"],seq["group_word"],seq["caps"])
    differences=0
    for row in seq["steps"]:
        lib.cycle_step(row["mode"],row["enable"],row["flags"],row["now"],seq["value"],row["chunk"]==0)
        m=[lib.cycle_meta(i) for i in range(9)];raw=lib.cycle_records();trace=[];offset=0
        if m[8]>2048:raise AssertionError("Cycle trace out of bounds")
        while offset<m[8]:
            kind=raw[offset];size=4 if kind==0 else 5 if kind==1 else 0
            if not size or offset+size>m[8]:raise AssertionError("Malformed cycle trace")
            trace.append(list(raw[offset:offset+size]));offset+=size
        params=bytes((m[0]&255,(m[0]>>8)&255,(m[0]>>16)&255)).hex()
        final=[m[6]&255,(m[6]>>8)&255,(m[6]>>16)&255]
        if lib.stage_unexpected_io() or lib.stage_group()!=seq["group_word"]:raise AssertionError("Cycle IO/group changed")
        differences+=(params!=row["params_after_hex"] or m[1]!=row["render_state"] or [m[2]&255,(m[2]>>8)&255]!=row["last_before_flush"] or
            m[3]!=row["seed_after"] or m[4]!=row["caps_white_calls"] or bool(m[5])!=row["did_flush"] or final!=row["final_trackers_state"] or
            m[7]!=row["hsv_calls"] or trace!=row["render_trace"] or bytes(lib.cycle_pixels(False)[:216]).hex()!=row["effect_grb_hex"] or
            bytes(lib.cycle_pixels(True)[:216]).hex()!=row["post_grb_hex"] or pwm_digest(lib.flush_pwm_words())!=row["pwm_sha256"])
    return differences


def audit(raw,reference,target):
    recover(raw);validate_reference(reference);image=parse_uf2(raw);inspect_flush(image);inspect_mode15(image);inspect_mode29_image(image)
    expected=artifacts(raw);inputs={name:(target/name).read_bytes() for name in expected}
    if any(v.decode()!=expected[k] for k,v in inputs.items()):raise ValueError("Changed target")
    profile=audit_target(raw,reference,target)
    oracle_path=ROOT/"tests/fixtures/original-rgb-cycle.json"; oracle_bytes=oracle_path.read_bytes()
    sequences=validate_oracle(json.loads(oracle_bytes))
    builders=("audit_original_rgb_cycle.py","audit_original_rgb_flush.py","audit_original_rgb_render_begin.py","audit_original_rgb_mode15_staging.py","verify_original_target_rgb.py","EmulateOriginalVial.java")
    builder_inputs={name:(ROOT/"tools"/name).read_bytes() for name in builders}
    cc=next((shutil.which(n) for n in ("gcc-16","gcc-15","gcc-14","gcc-13") if shutil.which(n)),None)
    if not cc:raise RuntimeError("Existing GNU compiler required; nothing installed")
    differences={};curve=original_hsv_profile(raw)
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-cycle-") as folder:
        for tag,opt,negative in (("base","-O0",None),("optimized","-O2",None),("skip_post","-O0","skip_post"),("boolean_enable","-O0","boolean_enable")):
            temp=Path(folder)/tag;temp.mkdir();source,hashes=program(reference,target,temp,negative)
            count=0
            for index,seq in enumerate(sequences):
                output=temp/f"cycle-{index}.so"
                subprocess.run([cc,"-std=gnu11","-Wall","-Wextra","-Werror","-Wno-error=override-init","-Wno-error=unused-parameter",opt,
                    "-fvisibility=hidden","-shared","-fPIC","-DUSE_CIE1931_CURVE","-DFASTLED_SCALE8_FIXED=1","-DFASTLED_BLEND_FIXED=1",
                    *(["-DPROBE_SKIP_POST"] if negative=="skip_post" else []),"-I",str(temp),"-I",str(temp/"platform_headers"),"-I",str(reference/"drivers/led"),
                    str(source),str(temp/"color.c"),str(temp/"led_tables.c"),"-o",str(output)],check=True)
                count+=compare(ctypes.CDLL(str(output)),seq,curve)
            differences[tag]=count
    if differences != {"base":0,"optimized":0,"skip_post":279,"boolean_enable":16}:
        raise AssertionError(f"Selected cycle differential failed: {differences}")
    if any((target/name).read_bytes()!=content for name,content in inputs.items()):raise ValueError("Target changed during verification")
    if oracle_path.read_bytes()!=oracle_bytes or any((ROOT/"tools"/name).read_bytes()!=content for name,content in builder_inputs.items()):
        raise ValueError("Oracle/probe builder changed during verification")
    return {"candidate_revision":REVISION,"source_sha256":hashes,"profile_source_sha256":profile["source_sha256"],"target_profile":profile["target_profile"],
        "target_sha256":{k:hashlib.sha256(v).hexdigest() for k,v in inputs.items()},"sequences_matched":16,"calls_matched":416,"optimized_calls_matched":416,
        "negative_differences":differences,"completion_only_renderer_stub_removed":True,"actual_native_render_post_flush_same_library":True,
        "probe_builder_sha256":{name:hashlib.sha256(content).hexdigest() for name,content in builder_inputs.items()},
        "oracle_sha256":hashlib.sha256(oracle_bytes).hexdigest(),"nested_actual_hsv_calls":4800,"flushes_matched":128,
        "unsupported_effects_and_unrelated_cadet_api_fail_closed":True,"native_private_cache_wait_directly_compared":False,"native_io_requests":0,"target_changes_applied":False,
        "original_thumb_executed_by_this_command":False,
        "scope":"selected actual SDK render/None/Chevron/PixelFlow -> actual RENDERING/weak delegates/target hooks -> actual flush/vtable/WS2812 encoder in one hidden library. Unsupported effects/factory-test trap; frame-start/mode/clock inputs supplied. Not full task/start/sync/scan/feature/HAL/DMA/device or all effects; original post slice separately entered with supplied register context",
        "sentinel":"ORIGINAL_RGB_CYCLE_AUDIT_COMPLETE"}


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("uf2",type=Path);p.add_argument("--reference-dir",type=Path,required=True);p.add_argument("--target",type=Path,required=True)
    a=p.parse_args();print(json.dumps(audit(a.uf2.read_bytes(),a.reference_dir,a.target),indent=2))
