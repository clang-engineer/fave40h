#!/usr/bin/env python3
"""Pinned PWM/Space Cadet source + target RGB/input hooks with captured APIs.

Not a complete QMK/HAL build or feature pipeline. No physical HID/USB, GPIO,
timer, DMA, ISR or LED operation; timer/term/modifier/tap boundaries are shims.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from prepare_original_target import artifacts, validate_reference
from recover_original_vial import parse_uf2, recover

ROOT = Path(__file__).resolve().parents[1]

# Controlled hardware-API shims, NOT ChibiOS implementations or ABI validation.
# Pin is an opaque numeric tag. Timer/stream objects are ordinary process RAM.
HARDWARE = r'''
#pragma once
#include <stddef.h>
void *memcpy(void *,const void *,size_t);
#define TRUE 1
#define FALSE 0
#define CPU_CLOCK 48000000
#define STM32F4XX
#define RGB_MATRIX_WS2812
#define STM32_DMA_SUPPORTS_DMAMUX 0
#define AT32_DMA_SUPPORTS_DMAMUX 0
#define B10 0x4002040AU
#define PAL_MODE_ALTERNATE(n) (2U | ((n) << 7))
#define PAL_OUTPUT_TYPE_PUSHPULL 0U
#define PAL_OUTPUT_SPEED_HIGHEST 24U
#define PAL_PUPDR_FLOATING 0U
#define PWM_OUTPUT_DISABLED 0
#define PWM_OUTPUT_ACTIVE_HIGH 1
#define TIM_DIER_UDE 0x100U
#define STM32_DMA_CR_CHSEL(n) ((n) << 25U)
#define STM32_DMA_CR_DIR_M2P (1U << 6)
#define STM32_DMA_CR_PSIZE_WORD (1U << 12)
#define STM32_DMA_CR_MSIZE_WORD (1U << 14)
#define STM32_DMA_CR_MINC (1U << 10)
#define STM32_DMA_CR_CIRC (1U << 8)
#define STM32_DMA_CR_PL(n) ((n) << 16U)
static uint32_t fake_dma[16];
#define STM32_DMA_STREAM(n) (&fake_dma[n])
#define STM32_DMA1_STREAM1 STM32_DMA_STREAM(1)
typedef struct { uint32_t pad[13]; uint32_t CCR[4]; } FakeTimer;
static FakeTimer fake_timer;
static struct { FakeTimer *tim; } PWMD2 = { &fake_timer };
typedef struct {
    uint32_t frequency, period;
    void *callback;
    struct { uint32_t mode; void *callback; } channels[4];
    uint32_t cr2, dier;
} PWMConfig;
uint32_t probe_requests[25];
static void *saved_buffer;
uint8_t probe_caps;
uint32_t probe_white_calls;
bool is_keyboard_master(void) { return true; } // Controlled nonsplit role.
struct PACKED { uint8_t before[4]; last_hit_t buffer; uint8_t after[4]; } probe_hit_storage;
#define last_hit_buffer probe_hit_storage.buffer
_Static_assert(sizeof(last_hit_t)==41,"original eight-hit packed profile");
_Static_assert(sizeof(probe_hit_storage)==49,"hit guards");
// Controlled timer/term and modifier/tap API boundaries, not kernel or HID.
uint16_t probe_cadet_now,probe_cadet_term;
uint32_t probe_cadet_reads,probe_cadet_trace[9];
static void cadet_effect(uint32_t kind,uint8_t argument) {
    uint32_t count=probe_cadet_trace[0];
    if(count<4) { probe_cadet_trace[1+2*count]=kind; probe_cadet_trace[2+2*count]=argument; }
    ++probe_cadet_trace[0];
}
uint16_t timer_read(void) { ++probe_cadet_reads; return probe_cadet_now; }
uint16_t timer_elapsed(uint16_t last) { return (uint16_t)(timer_read()-last); }
uint16_t get_tapping_term(uint16_t keycode,keyrecord_t *record) {
    (void)keycode; (void)record; return probe_cadet_term;
}
void register_mods(uint8_t mods) { cadet_effect(1,mods); }
void unregister_mods(uint8_t mods) { cadet_effect(2,mods); }
void tap_code(uint8_t code) { cadet_effect(3,code); }
// HID API intent capture only: no actual reports or USB operations.
uint32_t probe_hid[5];
static void capture_code(uint32_t pressed,uint8_t code) {
    uint32_t count=probe_hid[0];
    if (count<2) { probe_hid[1+count*2]=pressed; probe_hid[2+count*2]=code; }
    ++probe_hid[0];
}
void register_code(uint8_t code) { capture_code(1,code); }
void unregister_code(uint8_t code) { capture_code(0,code); }
uint8_t host_keyboard_leds(void) { return probe_caps; }
// Logical user-word capture only. These are NOT real EEPROM API backends.
extern uint32_t original_rgb_group_state;
uint32_t probe_group_io[10]; // count, stored word, up to two (write,offset,word,state) events
static void group_event(uint32_t write, uint32_t offset, uint32_t word) {
    uint32_t count=probe_group_io[0];
    if (count<2) {
        uint32_t *event=&probe_group_io[2+count*4];
        event[0]=write; event[1]=offset; event[2]=word; event[3]=original_rgb_group_state;
    }
    ++probe_group_io[0];
}
uint32_t eeconfig_read_user(void) {
    group_event(0,0x13,probe_group_io[1]); return probe_group_io[1];
}
void eeconfig_update_user(uint32_t word) {
    group_event(1,0x13,word); probe_group_io[1]=word;
}
void eeconfig_update_kb(uint32_t word) { group_event(1,0x0F,word); }
static int bad_stream;
static void event(uint32_t value) {
    if (probe_requests[15] < 9) probe_requests[16 + probe_requests[15]] = value;
    ++probe_requests[15];
}
static void check_stream(uint32_t *s) { if (s != STM32_DMA1_STREAM1) bad_stream = 1; }
static void palSetLineMode(uint32_t pin, uint32_t mode) {
    probe_requests[0]=pin; probe_requests[1]=mode; event(1);
}
static void dmaStreamAlloc(int stream, int priority, void *callback, void *parameter) {
    probe_requests[2]=(uint32_t)stream; probe_requests[3]=(uint32_t)priority;
    if (callback || parameter) bad_stream=1;
    event(2);
}
static void dmaStreamSetPeripheral(uint32_t *s, void *address) {
    check_stream(s); probe_requests[4]=(uint32_t)((char *)address-(char *)&fake_timer); event(3);
}
static void dmaStreamSetMemory0(uint32_t *s, void *address) {
    check_stream(s); saved_buffer=address; event(4);
}
static void dmaStreamSetMode(uint32_t *s, uint32_t mode) {
    check_stream(s); probe_requests[6]=mode; event(5);
}
static void dmaStreamSetTransactionSize(uint32_t *s, uint32_t count) {
    check_stream(s); probe_requests[7]=count; event(6);
}
static void dmaStreamEnable(uint32_t *s) { check_stream(s); event(7); }
static void pwmStart(void *driver, const PWMConfig *config) {
    if (driver != &PWMD2) bad_stream=1;
    probe_requests[8]=config->frequency; probe_requests[9]=config->period;
    probe_requests[10]=config->channels[2].mode; probe_requests[11]=config->dier;
    probe_requests[14]=!config->cr2 && !config->callback;
    for (int i=0;i<4;i++) {
        if (config->channels[i].callback || (i!=2 && config->channels[i].mode)) probe_requests[14]=0;
    }
    event(8);
}
static void pwmEnableChannel(void *driver, uint32_t channel, uint32_t duty) {
    if (driver != &PWMD2) bad_stream=1;
    probe_requests[12]=channel; probe_requests[13]=duty; event(9);
}
'''


def prepare_probe(temp, reference, target):
    types = (reference / "quantum/rgb_matrix/rgb_matrix_types.h").read_text()
    matrix_header = (reference / "quantum/rgb_matrix/rgb_matrix.h").read_text()
    host_header = (reference / "tmk_core/protocol/host.h").read_text()
    declarations = []
    for pattern, content in ((r"typedef enum rgb_task_states[^;]+;", types),
            (r"typedef uint8_t led_flags_t;", types),
            (r"#define NO_LED 255", types),
            (r"#if defined\(RGB_MATRIX_KEYPRESSES\) \|\| defined\(RGB_MATRIX_KEYRELEASES\)[\s\S]*?#endif", types),
            (r"uint8_t\s+host_keyboard_leds\(void\);", host_header),
            (r"void rgb_matrix_set_color\([^;]+;", matrix_header)):
        match = re.search(pattern, content)
        if not match:
            raise ValueError("Unmodeled pinned RGB/host declaration")
        declarations.append(match[0])
    keyboard_header=(reference / "quantum/keyboard.h").read_text()
    action_header=(reference / "quantum/action.h").read_text()
    for pattern, content in ((r"void register_code\(uint8_t code\);",action_header),
            (r"void unregister_code\(uint8_t code\);",action_header),
            (r"void tap_code\(uint8_t code\);",action_header),
            (r"void register_mods\(uint8_t mods\);",action_header),
            (r"void unregister_mods\(uint8_t mods\);",action_header),
            (r"bool is_keyboard_master\(void\);",keyboard_header),
            (r"typedef struct \{[^}]+\} keypos_t;",keyboard_header),
            (r"typedef enum keyevent_type_t[^;]+;",keyboard_header),
            (r"typedef struct \{[^}]+\} keyevent_t;",keyboard_header),
            (r"typedef struct \{[^}]+\} tap_t;",action_header),
            (r"typedef struct keyrecord_t \{[^}]+\} keyrecord_t;",action_header)):
        match=re.search(pattern,content)
        if not match:
            raise ValueError("Unmodeled pinned record declaration")
        declarations.append(match[0])
    for name in ("led_point_t", "led_config_t", "effect_params_t", "last_hit_t"):
        match = re.search(r"typedef struct PACKED \{[^}]+\} " + name + ";", types)
        if not match:
            raise ValueError(f"Unmodeled pinned RGB type: {name}")
        declarations.append(match[0])
    (temp / "quantum.h").write_text('#pragma once\n#include <stdint.h>\n#include <stdbool.h>\n#define PACKED __attribute__((packed))\n#define MATRIX_ROWS 4\n#define MATRIX_COLS 12\n#define COMBO_ENABLE\n#define RGB_MATRIX_ENABLE\n#ifdef PROBE_KEYRELEASES\n#define RGB_MATRIX_KEYRELEASES\n#endif\n#define SPACE_CADET_ENABLE\n#define TAPPING_TERM_PER_KEY\n#define FAST_TIMER_T_SIZE 16\n#include "config.h"\n' + "\n".join(declarations) + '\n#include "eeconfig.h"\n#include "process_space_cadet.h"\n')
    for name,relative in (("process_space_cadet.h","quantum/process_keycode/process_space_cadet.h"),
            ("space_cadet.c","quantum/process_keycode/process_space_cadet.c"),
            ("keycodes.h","quantum/keycodes.h"),("keycode.h","quantum/keycode.h"),
            ("modifiers.h","quantum/modifiers.h"),("action_tapping.h","quantum/action_tapping.h")):
        (temp/name).write_bytes((reference/relative).read_bytes())
    # timer.h uses __has_include_next: it must be found by -I, not relative to
    # the primary source. Preserve upstream bytes and strict include diagnostics.
    (temp/"platform_headers").mkdir()
    (temp/"platform_headers/timer.h").write_bytes((reference/"platforms/timer.h").read_bytes())
    (temp/"action.h").write_text('#pragma once\n#include "quantum.h"\n')
    (temp/"action_util.h").write_text('#pragma once\n#include "quantum.h"\n#include "keycode.h"\n')
    (temp / "eeconfig.h").write_bytes((reference / "quantum/eeconfig.h").read_bytes())
    (temp / "action_layer.h").write_text('#pragma once\n#include <stdint.h>\ntypedef uint32_t layer_state_t;\n')
    dispatch = []
    for filename, name in (("eeconfig.c", "eeconfig_init_kb"), ("keyboard.c", "keyboard_post_init_kb")):
        content = (reference / "quantum" / filename).read_text()
        match = re.search(r"__attribute__\(\(weak\)\) void " + name + r"\(void\) \{[^}]+\}", content)
        if not match:
            raise ValueError(f"Unmodeled pinned weak dispatcher: {name}")
        dispatch.append(match[0])
    matrix_source = (reference / "quantum/rgb_matrix/rgb_matrix.c").read_text()
    limits = re.search(r"struct rgb_matrix_limits_t rgb_matrix_get_limits\(uint8_t iter\) \{.*?^\}", matrix_source, re.S | re.M)
    matrix_header = (reference / "quantum/rgb_matrix/rgb_matrix.h").read_text()
    limits_type = re.search(r"struct rgb_matrix_limits_t \{[^}]+\};", matrix_header)
    if not limits or not limits_type:
        raise ValueError("Unmodeled pinned RGB limits function/type")
    dispatch.extend([limits_type[0], limits[0]])
    for name in ("rgb_matrix_map_row_column_to_led_kb", "rgb_matrix_map_row_column_to_led", "rgb_matrix_handle_key_event",
            "rgb_matrix_indicators_modules", "rgb_matrix_indicators_kb", "rgb_matrix_indicators",
            "rgb_matrix_indicators_advanced_modules", "rgb_matrix_indicators_advanced_kb", "rgb_matrix_indicators_advanced"):
        match = re.search(r"(?:__attribute__\(\(weak\)\) )?(?:bool|void|uint8_t) " + name + r"\([^)]*\) \{.*?^\}", matrix_source, re.S | re.M)
        if not match:
            raise ValueError(f"Unmodeled pinned indicator dispatcher: {name}")
        if name == "rgb_matrix_indicators_advanced":
            macro = matrix_header.split("#define RGB_MATRIX_USE_LIMITS_ITER",1)[1].split("\n\n",1)[0]
            dispatch.append("#define RGB_MATRIX_USE_LIMITS_ITER" + macro)
        dispatch.append(match[0])
    rendering = re.search(r"        case RENDERING:.*?(?=        case FLUSHING:)", matrix_source, re.S)
    if not rendering:
        raise ValueError("Unmodeled pinned RENDERING case")
    dispatch.append('''
// Controlled renderer completion; actual effects/timing are not executed.
static rgb_task_states rgb_task_state;
static effect_params_t rgb_effect_params;
static uint8_t probe_render_complete;
static void rgb_task_render(uint8_t effect) {
    (void)effect;
    rgb_task_state=probe_render_complete ? FLUSHING : RENDERING;
}
void probe_render_chunk(uint8_t iter, uint8_t complete) {
    rgb_effect_params.iter=iter+1;
    probe_render_complete=complete;
    rgb_task_state=RENDERING;
    uint8_t effect=1;
    switch (rgb_task_state) {
''' + rendering[0] + '    default: break;\n    }\n}\n')
    keyboard_source=(reference / "quantum/keyboard.c").read_text()
    switch_events=re.search(r"void switch_events\([^)]*\) \{.*?^\}",keyboard_source,re.S|re.M)
    if not switch_events or not re.search(r"action_exec\(MAKE_KEYEVENT\(row, col, key_pressed\)\);\s*\}\s*switch_events\(row, col, key_pressed\);",keyboard_source):
        raise ValueError("Unmodeled candidate action/switch-events ordering")
    dispatch.append(switch_events[0])
    quantum_source=(reference / "quantum/quantum.c").read_text()
    record_delegate=re.search(r"__attribute__\(\(weak\)\) bool process_record_kb\([^)]*\) \{[^}]+\}",quantum_source)
    record_gate=re.search(r"process_record_modules\(keycode, record\) &&[^\n]*\n\s*process_record_kb\(keycode, record\)",quantum_source)
    cadet_gate=re.search(r"#ifdef SPACE_CADET_ENABLE\s+(process_space_cadet\(keycode, record\)) &&",quantum_source)
    if not record_delegate or not record_gate or not cadet_gate:
        raise ValueError("Unmodeled pinned module/KB record gate")
    dispatch.append(record_delegate[0])
    dispatch.append('''
// Selected module/KB prefix then actual Space Cadet stage. Intervening features
// and preprocessors are deliberately omitted: this is NOT the full chain.
uint32_t probe_module_calls,probe_later_calls,probe_record_changed;
uint8_t probe_module_allow=1;
static bool process_record_modules(uint16_t keycode,keyrecord_t *record) {
    (void)keycode; (void)record; ++probe_module_calls; return probe_module_allow;
}
static bool probe_gate(uint16_t keycode,keyrecord_t *record) {
    if (!(''' + record_gate[0] + ''')) return false;
    if (!(''' + cadet_gate[1] + ''')) return false;
    ++probe_later_calls; return true;
}
bool probe_process_record(uint16_t keycode,uint8_t pressed) {
    struct { uint32_t before; keyrecord_t record; uint32_t after; } guarded;
    for (unsigned i=0;i<sizeof(guarded);i++) ((uint8_t *)&guarded)[i]=0;
    guarded.before=guarded.after=0xA5A5A5A5U;
    guarded.record.event.pressed=pressed;
    guarded.record.event.type=KEY_EVENT;
    guarded.record.event.key.row=1; guarded.record.event.key.col=2;
    guarded.record.event.time=123;
    uint8_t saved[sizeof(keyrecord_t)];
    for (unsigned i=0;i<sizeof(saved);i++) saved[i]=((uint8_t *)&guarded.record)[i];
    bool result=probe_gate(keycode,&guarded.record);
    for (unsigned i=0;i<sizeof(saved);i++)
        if (saved[i]!=((uint8_t *)&guarded.record)[i]) ++probe_record_changed;
    if (guarded.before!=0xA5A5A5A5U || guarded.after!=0xA5A5A5A5U) ++probe_record_changed;
    return result;
}
''')
    (temp / "weak_dispatch.c").write_text("\n".join(dispatch))
    (temp / "config.h").write_bytes((target / "config.h").read_bytes())
    (temp / "util.h").write_text('#pragma once\n#include "quantum.h"\n')
    (temp / "hardware.h").write_text(HARDWARE)
    (temp / "gpio.h").write_text('#pragma once\n#include "hardware.h"\n')
    (temp / "chibios_config.h").write_text('// Hardware APIs intentionally replaced by capture shims.\n')
    (temp / "pwm_driver.c").write_bytes((reference / "platforms/chibios/drivers/ws2812_pwm.c").read_bytes())
    (temp / "target_map.c").write_bytes((target / "fave40h_original.c").read_bytes())
    source = temp / "probe.c"
    source.write_text('''#include "quantum.h"
#include "hardware.h"
#include "space_cadet.c"
#include "target_map.c"
#include "weak_dispatch.c"
#include "pwm_driver.c"
// Nonsplit color-output boundary mapped to the actual candidate WS2812 staging API.
void rgb_matrix_set_color(int index, uint8_t red, uint8_t green, uint8_t blue) {
    if (index==22 && red==255 && green==255 && blue==255) ++probe_white_calls;
    ws2812_set_color(index,red,green,blue);
}
_Static_assert(sizeof(g_led_config)==264, "original LED table width");
_Static_assert(sizeof(ws2812_buffer_t)==4, "original DMA word width");
_Static_assert(WS2812_CHANNELS==3, "original RGB, not RGBW");
_Static_assert(WS2812_BIT_N==1952, "original transfer length");
// Inspect/seed the same TU's private upstream state without editing its source.
void probe_cadet_seed(uint8_t last,uint16_t stamp,uint16_t now,uint16_t term) {
    sc_last=last; sc_timer=stamp; probe_cadet_now=now; probe_cadet_term=term;
    probe_cadet_reads=0;
    for(unsigned i=0;i<9;i++) probe_cadet_trace[i]=0;
}
uint32_t probe_cadet_state(void) { return sc_last|((uint32_t)sc_timer<<8); }
uint32_t *probe_buffer(void) { return ws2812_frame_buffer; }
uint16_t probe_rgb_limits(uint8_t iter) {
    struct rgb_matrix_limits_t limits=rgb_matrix_get_limits(iter);
    return (uint16_t)(limits.led_min_index | ((uint16_t)limits.led_max_index << 8));
}
void probe_init(void) {
    ws2812_init();
    probe_requests[5]=(saved_buffer==ws2812_frame_buffer && !bad_stream);
}
''')
    return source


def check_native(lib, raw, oracle):
    table = bytes((ctypes.c_uint8 * 264).in_dll(lib, "g_led_config"))
    if table != parse_uf2(raw).read(0x0801DEA0, 264):
        raise AssertionError("Compiled LED table differs from original ROM bytes")
    lib.probe_buffer.restype = ctypes.POINTER(ctypes.c_uint32)
    buffer = lib.probe_buffer()
    buffer[1952] = 0x12345678  # Upstream allocation has one unused extra word.
    lib.probe_init()
    expected = [0x4002040A, 0x9A, 1, 10, 0x3C, 1, 0x06035540, 1952,
                24000000, 30, 1, 0x100, 2, 0, 1, 9, *range(1,10)]
    if list((ctypes.c_uint32 * 25).in_dll(lib, "probe_requests")) != expected:
        raise AssertionError("Captured PWM/DMA initialization request differs")
    if list(buffer[:1952]) != [8] * 1728 + [0] * 224:
        raise AssertionError("PWM black/reset initialization differs")
    lib.ws2812_set_color.argtypes = [ctypes.c_int, *([ctypes.c_uint8] * 3)]
    lib.ws2812_set_color.restype = None
    lib.ws2812_flush.restype = None
    if len(oracle["encodings"]) != 51:
        raise ValueError("Expected complete 51-case original PWM oracle")
    for case in oracle["encodings"]:
        grb = bytes.fromhex(case["input_grb_hex"])
        if len(grb) != 216:
            raise ValueError("Expected complete original 72-LED GRB input")
        ctypes.memset(buffer, case["initial_pwm_byte"], 1952 * 4)
        for led in range(72):
            g, r, b = grb[led*3:led*3+3]
            lib.ws2812_set_color(led, r, g, b)
        if bytes((ctypes.c_uint8 * 216).in_dll(lib, "ws2812_leds")) != grb:
            raise AssertionError("Candidate color staging is not original GRB")
        lib.ws2812_flush()
        actual = hashlib.sha256(struct.pack("<1952I", *buffer[:1952])).hexdigest()
        if actual != case["expected_pwm_sha256"] or buffer[1952] != 0x12345678:
            raise AssertionError(f"PWM encoder/reset-tail mismatch: {case['name']}")
    return len(oracle["encodings"])


def check_group_lifecycle(lib, oracle):
    cases = oracle["rgb_group_lifecycle"]
    if len(cases) != 13:
        raise ValueError("Expected complete 13-case RGB group lifecycle oracle")
    state = ctypes.c_uint32.in_dll(lib, "original_rgb_group_state")
    io = (ctypes.c_uint32 * 10).in_dll(lib, "probe_group_io")
    for case in cases:
        state.value = case["initial_word"]
        for i in range(10):
            io[i] = 0
        io[1] = case["stored_word"]
        # Actual hash-bound weak delegation bodies, target strong user hooks.
        if case["kind"] == "reset":
            lib.eeconfig_init_kb()
        else:
            lib.keyboard_post_init_kb()
        expected = []
        for event in case["io"]:
            expected.extend([int(event["kind"] == "write"), event["offset"], event["word"], event["state_at_io"]])
        if io[0] != len(case["io"]) or list(io[2:2+4*io[0]]) != expected or state.value != case["state_after"]:
            raise AssertionError(f"RGB group callback/reset/load mismatch: {case}")
    return len(cases)


def check_rgb_limits(lib, oracle):
    cases = oracle["rgb_limits"]
    if len(cases) != 256 or [c["iter"] for c in cases] != list(range(256)):
        raise ValueError("Expected all 256 original RGB limits inputs")
    lib.probe_rgb_limits.argtypes = [ctypes.c_uint8]
    lib.probe_rgb_limits.restype = ctypes.c_uint16
    for case in cases:
        if lib.probe_rgb_limits(case["iter"]) != case["packed_limits"]:
            raise AssertionError(f"RGB chunk limits mismatch: {case}")
    return len(cases)


def check_indicators(lib, oracle):
    if len(oracle["filters"]) != 25 or len(oracle["rgb_composed_chunks"]) != 24:
        raise ValueError("Expected complete filter/composed RGB oracles")
    state=ctypes.c_uint32.in_dll(lib,"original_rgb_group_state")
    caps=ctypes.c_uint8.in_dll(lib,"probe_caps")
    white=ctypes.c_uint32.in_dll(lib,"probe_white_calls")
    colors=(ctypes.c_uint8*216).in_dll(lib,"ws2812_leds")
    io=(ctypes.c_uint32*10).in_dll(lib,"probe_group_io")
    lib.rgb_matrix_indicators_advanced_user.argtypes=[ctypes.c_uint8,ctypes.c_uint8]
    lib.rgb_matrix_indicators_advanced_user.restype=ctypes.c_bool
    lib.probe_render_chunk.argtypes=[ctypes.c_uint8,ctypes.c_uint8]
    lib.probe_render_chunk.restype=None
    for composed, cases in ((False,oracle["filters"]),(True,oracle["rgb_composed_chunks"])):
        for case in cases:
            raw=bytes.fromhex(case["input_grb_hex"])
            for led in range(72):
                g,r,b=raw[led*3:led*3+3]
                lib.ws2812_set_color(led,r,g,b)
            enabled=(case["keylight"],case["underglow"]) if composed else case["enabled"]
            state.value=0xA5B60000 | enabled[0] | (enabled[1]<<8)
            before=state.value
            caps.value=case["caps"] if composed else 0
            white.value=0
            io_before=list(io)
            if composed:
                lib.probe_render_chunk(case["iter"],int(case["iter"]==4))
                if white.value != case["caps_white_calls"]:
                    raise AssertionError("Caps/RENDERING/FLUSHING call mismatch")
            elif not lib.rgb_matrix_indicators_advanced_user(case["begin"],case["end"]):
                raise AssertionError("Target filter hook return changed")
            if hashlib.sha256(bytes(colors)).hexdigest()!=case["expected_grb_sha256"]:
                raise AssertionError(f"Target RGB indicator/filter mismatch: {case}")
            if state.value!=before or list(io)!=io_before:
                raise AssertionError("RGB indicators changed group word or requested EEPROM IO")
    return 25,24


def check_controls(lib,oracle):
    cases=oracle["rgb_controls"]
    if len(cases)!=48:
        raise ValueError("Expected complete 48-case RGB command oracle")
    state=ctypes.c_uint32.in_dll(lib,"original_rgb_group_state")
    modules=ctypes.c_uint32.in_dll(lib,"probe_module_calls")
    later=ctypes.c_uint32.in_dll(lib,"probe_later_calls")
    allow=ctypes.c_uint8.in_dll(lib,"probe_module_allow")
    io=(ctypes.c_uint32*10).in_dll(lib,"probe_group_io")
    colors=(ctypes.c_uint8*216).in_dll(lib,"ws2812_leds")
    hid=(ctypes.c_uint32*5).in_dll(lib,"probe_hid")
    lib.probe_process_record.argtypes=[ctypes.c_uint16,ctypes.c_uint8]
    lib.probe_process_record.restype=ctypes.c_bool
    for case in cases:
        state.value=0xA5B60000|case["before"][0]|(case["before"][1]<<8)
        allow.value=1; modules.value=later.value=0
        io_before=list(io); colors_before=bytes(colors); hid_before=list(hid)
        if lib.probe_process_record(case["keycode"],case["pressed"]):
            raise AssertionError("RGB command was not consumed")
        expected=0xA5B60000|case["after"][0]|(case["after"][1]<<8)
        if state.value!=expected or modules.value!=1 or later.value!=0:
            raise AssertionError(f"RGB command byte/early-gate mismatch: {case}")
        if list(io)!=io_before or bytes(colors)!=colors_before or list(hid)!=hid_before:
            raise AssertionError("RGB command unexpectedly requested IO/color output")
    # Unrelated keys pass this hook; sentinel is NOT actual core/HID execution.
    for keycode in (0,4,0xE1,0x7DFF,0x7E16,0xFFFF):
        for pressed in (0,1):
            state.value=0xA5B60280; modules.value=later.value=0
            if not lib.probe_process_record(keycode,pressed) or state.value!=0xA5B60280 or later.value!=1:
                raise AssertionError("Unrelated key did not pass through RGB user hook")
    allow.value=0; state.value=0xA5B60101; modules.value=later.value=0
    if lib.probe_process_record(0x7E10,1) or state.value!=0xA5B60101 or later.value:
        raise AssertionError("Blocked module did not short-circuit before user hook")
    allow.value=1
    if ctypes.c_uint32.in_dll(lib,"probe_record_changed").value:
        raise AssertionError("RGB record input/guards changed")
    return len(cases)


def check_backspace_delete(lib,oracle):
    if len(oracle["shift_edges"])!=8 or len(oracle["backspace_delete"])!=8:
        raise ValueError("Expected complete original Shift/Backspace-Delete cases")
    shift=ctypes.c_uint8.in_dll(lib,"original_last_shift_edge")
    hid=(ctypes.c_uint32*5).in_dll(lib,"probe_hid")
    later=ctypes.c_uint32.in_dll(lib,"probe_later_calls")
    io=(ctypes.c_uint32*10).in_dll(lib,"probe_group_io")
    state=ctypes.c_uint32.in_dll(lib,"original_rgb_group_state")
    io_before=list(io); state_before=state.value
    def clear():
        for i in range(5): hid[i]=0
        later.value=0
    for case in oracle["shift_edges"]:
        shift.value=case["before"]; clear()
        if not lib.probe_process_record(case["keycode"],case["pressed"]) or shift.value!=case["after"] or hid[0] or later.value!=1:
            raise AssertionError(f"Shift edge/passthrough mismatch: {case}")
    for case in oracle["backspace_delete"]:
        shift.value=case["selector"]; clear()
        if lib.probe_process_record(0x7E00,case["pressed"]) or later.value:
            raise AssertionError("Backspace/Delete command did not consume event")
        if list(hid[:3])!=[1,int(case["pressed"]),case["keycode"]] or shift.value!=case["selector"]:
            raise AssertionError(f"Backspace/Delete intent mismatch: {case}")
    # Compositions of already-observed edge/mapping semantics, not additional
    # original-Thumb whole-pipeline cases or actual HID reports.
    shift.value=0; clear()
    for key,pressed in ((0xE1,1),(0xE5,1),(0xE1,0),(0x7E00,1)):
        lib.probe_process_record(key,pressed)
    if shift.value!=0 or list(hid[:3])!=[1,1,0x2A]:
        raise AssertionError("Overlapping Shift last-edge behavior changed")
    shift.value=0; clear()
    for key,pressed in ((0xE1,1),(0x7E00,1),(0xE1,0),(0x7E00,0)):
        lib.probe_process_record(key,pressed)
    if list(hid)!=[2,1,0x4C,0,0x2A]:
        raise AssertionError("Release-time key reselection was changed")
    if list(io)!=io_before or state.value!=state_before or ctypes.c_uint32.in_dll(lib,"probe_record_changed").value:
        raise AssertionError("Shift/Backspace-Delete changed unrelated state, IO or record")
    return 8,8


def check_cadet(lib,oracle):
    lib.probe_cadet_seed.argtypes=[ctypes.c_uint8,*([ctypes.c_uint16]*3)]
    lib.probe_cadet_seed.restype=None
    lib.probe_cadet_state.restype=ctypes.c_uint32
    reads=ctypes.c_uint32.in_dll(lib,"probe_cadet_reads")
    trace=(ctypes.c_uint32*9).in_dll(lib,"probe_cadet_trace")
    hid=(ctypes.c_uint32*5).in_dll(lib,"probe_hid")
    modules=ctypes.c_uint32.in_dll(lib,"probe_module_calls")
    later=ctypes.c_uint32.in_dll(lib,"probe_later_calls")
    state=ctypes.c_uint32.in_dll(lib,"original_rgb_group_state")
    shift=ctypes.c_uint8.in_dll(lib,"original_last_shift_edge")
    io=(ctypes.c_uint32*10).in_dll(lib,"probe_group_io")
    colors=(ctypes.c_uint8*216).in_dll(lib,"ws2812_leds")
    io_before=list(io); colors_before=bytes(colors)
    kinds={"register_mods":1,"unregister_mods":2,"tap_code":3}
    expected_counts={"cadet":196,"builtin_cadet":98,"cadet_core_defaults":16,"cadet_vendor_bypasses":14}
    for name,count in expected_counts.items():
        if len(oracle[name])!=count:
            raise ValueError(f"Expected complete original {name} oracle")
        for case in oracle[name]:
            lib.probe_cadet_seed(case["before_last_modifier"],case["before_pressed_at"],case.get("now",0),case.get("tapping_term",200))
            for i in range(5): hid[i]=0
            modules.value=later.value=0
            state.value=0xA5B60101; shift.value=1
            passed=lib.probe_process_record(case["keycode"],case["pressed"])
            core_default=name=="cadet_core_defaults"
            if passed!=core_default or modules.value!=1 or later.value!=int(core_default):
                raise AssertionError(f"Cadet selected-gate routing mismatch: {name} {case}")
            expected_state=case["after_last_modifier"]|(case["after_pressed_at"]<<8)
            if lib.probe_cadet_state()!=expected_state or reads.value!=case.get("timer_reads",0):
                raise AssertionError(f"Shared candidate cadet state/timer mismatch: {name} {case}")
            expected=[(kinds[e["kind"]],e["argument"]) for e in case.get("effects",[]) if e["kind"] in kinds]
            actual=[(trace[1+2*i],trace[2+2*i]) for i in range(min(trace[0],4))]
            if trace[0]!=len(expected) or actual!=expected:
                raise AssertionError(f"Candidate modifier/tap intents mismatch: {name} {case}")
            other=[e for e in case.get("effects",[]) if e["kind"] not in kinds]
            expected_hid=[1,int(case["pressed"]),other[0]["argument"]] if other else [0,0,0]
            if list(hid[:3])!=expected_hid or len(other)>1:
                raise AssertionError(f"Vendor bypass HID API intent mismatch: {case}")
            flags=case.get("after_flags",[1,1])
            if state.value!=(0xA5B60000|flags[0]|(flags[1]<<8)):
                raise AssertionError("Cadet/bypass changed unrelated group bytes")
    # Native compositions of observed rules, not extra original Thumb cases.
    # Both directions must share the SAME private upstream state across hooks.
    now=ctypes.c_uint16.in_dll(lib,"probe_cadet_now")
    for press_key,release_key,tap in ((0x7E03,0x7C18,0x26),(0x7C18,0x7E03,0x2F)):
        lib.probe_cadet_seed(0,0,1234,200)
        if lib.probe_process_record(press_key,1):
            raise AssertionError("Cadet press escaped selected stage")
        for i in range(9): trace[i]=0
        now.value=1239
        if lib.probe_process_record(release_key,0):
            raise AssertionError("Cadet release escaped selected stage")
        if list(trace)!=[4,2,1,1,2,3,tap,2,2] or reads.value!=2 or lib.probe_cadet_state()!=(0xE0|(1234<<8)):
            raise AssertionError("Custom/builtin cadet state was split or release state cleared")
    lib.probe_cadet_seed(0,0,1234,200)
    lib.probe_process_record(0x7E03,1)
    if not lib.probe_process_record(4,1):
        raise AssertionError("Normal interrupt key was consumed")
    for i in range(9): trace[i]=0
    now.value=1239
    lib.probe_process_record(0x7E03,0)
    if list(trace[:3])!=[1,2,1] or reads.value!=1 or lib.probe_cadet_state()!=(1234<<8):
        raise AssertionError("Normal pressed key did not interrupt shared cadet state")
    if list(io)!=io_before or bytes(colors)!=colors_before or ctypes.c_uint32.in_dll(lib,"probe_record_changed").value:
        raise AssertionError("Cadet dispatch changed IO, pixels or input record/guards")
    return expected_counts


def check_rgb_key_events(lib,oracle,negative=False):
    cases=oracle["rgb_key_events"]
    if len(cases)!=288 or oracle["payload_sha256"]!="9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4":
        raise ValueError("Expected complete original RGB key-event oracle")
    storage=(ctypes.c_uint8*49).in_dll(lib,"probe_hit_storage")
    lib.switch_events.argtypes=[ctypes.c_uint8,ctypes.c_uint8,ctypes.c_bool]
    lib.switch_events.restype=None
    io=(ctypes.c_uint32*10).in_dll(lib,"probe_group_io")
    hid=(ctypes.c_uint32*5).in_dll(lib,"probe_hid")
    state=ctypes.c_uint32.in_dll(lib,"original_rgb_group_state")
    colors=(ctypes.c_uint8*216).in_dll(lib,"ws2812_leds")
    before_unrelated=(list(io),list(hid),state.value,bytes(colors))
    mismatches=0
    for case in cases:
        if not (0<=case["row"]<4 and 0<=case["col"]<12 and case["initial_count"] in (0,7,8)):
            raise ValueError("Out-of-scope RGB event fixture input")
        before=bytes.fromhex(case["before_hex"]); expected=bytes.fromhex(case["after_hex"])
        if len(before)!=41 or len(expected)!=41:
            raise ValueError("Expected packed eight-hit fixture")
        storage[:]=b"\xA5"*4+before+b"\xA5"*4
        lib.switch_events(case["row"],case["col"],case["pressed"])
        if bytes(storage[:4])+bytes(storage[45:])!=b"\xA5"*8:
            raise AssertionError("Candidate RGB hit storage guard changed")
        if bytes(storage[4:45])!=expected:
            mismatches+=1
            if not negative:
                raise AssertionError(f"Candidate hit buffer differs from original: {case}")
    if before_unrelated!=(list(io),list(hid),state.value,bytes(colors)):
        raise AssertionError("RGB electrical events changed IO/group/pixel state")
    if negative and mismatches!=252:
        raise AssertionError(f"KEYRELEASES negative control expected252 differences, got{mismatches}")
    return mismatches if negative else len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, default=ROOT / "tests/fixtures/original-vial-emulation.json")
    parser.add_argument("--arm-object", type=Path)
    args = parser.parse_args()
    validate_reference(args.reference_dir)
    raw = args.uf2.read_bytes()
    evidence, _ = recover(raw)
    for relative, content in artifacts(raw).items():
        if (args.target / relative).read_text() != content:
            raise ValueError(f"Changed target seed: {relative}")
    oracle = json.loads(args.oracle.read_text())
    if oracle["payload_sha256"] != evidence["payload_sha256"]:
        raise ValueError("Oracle payload binding mismatch")
    clang = shutil.which("clang")
    if not clang:
        raise RuntimeError("Clang required; no installation attempted")
    with tempfile.TemporaryDirectory(prefix="fave40h-target-rgb-") as directory:
        temp = Path(directory)
        source = prepare_probe(temp, args.reference_dir, args.target)
        # Keep upstream warnings visible: deliberate channel initializer override
        # and unused RGBW `w` argument when compiling the original RGB profile.
        flags = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-error=initializer-overrides", "-Wno-error=unused-parameter",
                 "-I", str(temp), "-I", str(temp/"platform_headers"), "-I", str(args.reference_dir / "drivers/led")]
        library = temp / ("rgb.dylib" if sys.platform == "darwin" else "rgb.so")
        subprocess.run([clang, *flags, "-shared", "-fPIC", str(source), "-o", str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        count = check_native(lib, raw, oracle)
        group_count = check_group_lifecycle(lib, oracle)
        limit_count = check_rgb_limits(lib, oracle)
        filter_count, composed_count = check_indicators(lib, oracle)
        control_count=check_controls(lib,oracle)
        shift_count,bsdl_count=check_backspace_delete(lib,oracle)
        cadet_counts=check_cadet(lib,oracle)
        event_oracle=json.loads((ROOT/"tests/fixtures/original-rgb-events.json").read_text())
        event_count=check_rgb_key_events(lib,event_oracle)
        # Observe the same upstream overlapping memcpy source under optimization;
        # this is not a promise for a future target libc/compiler/link profile.
        optimized=temp/"rgb-optimized.dylib"
        subprocess.run([clang,*flags,"-O2","-shared","-fPIC",str(source),"-o",str(optimized)],check=True)
        check_rgb_key_events(ctypes.CDLL(str(optimized)),event_oracle)
        negative=temp/"rgb-keyreleases.dylib"
        subprocess.run([clang,*flags,"-DPROBE_KEYRELEASES","-shared","-fPIC",str(source),"-o",str(negative)],check=True)
        release_differences=check_rgb_key_events(ctypes.CDLL(str(negative)),event_oracle,negative=True)
        if args.arm_object:
            obj = temp / "rgb-arm.o"
            subprocess.run([clang, "--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-ffreestanding",
                            *flags, "-c", str(source), "-o", str(obj)], check=True)
            with args.arm_object.open("xb") as output:
                output.write(obj.read_bytes())
    print(json.dumps({"compiled_led_table_bytes": 264, "original_encoding_cases_matched": count,
        "original_rgb_group_cases_matched": group_count, "original_rgb_limits_cases_matched": limit_count,
        "original_rgb_control_cases_matched": control_count,
        "original_shift_edge_cases_matched": shift_count, "original_bsdl_cases_matched": bsdl_count,
        "original_cadet_dispatch_cases_matched": cadet_counts, "native_cadet_compositions_verified": 3,
        "original_rgb_key_event_cases_matched": event_count, "optimized_event_cases_matched": event_count,
        "keyreleases_negative_differences": release_differences,
        "full_feature_pipeline_executed": False,
        "original_filter_cases_matched": filter_count, "original_composed_chunks_matched": composed_count,
        "physical_eeprom_executed": False, "physical_hid_usb_executed": False,
        "captured_hardware_api_requests": 9, "physical_dma_pwm_executed": False,
        "cpu_clock_shim_hz_conditional": 48000000, "full_qmk_hal_build": False,
        "arm_rgb_probe_object": str(args.arm_object) if args.arm_object else None,
        "sentinel": "ORIGINAL_TARGET_RGB_PROBE_COMPLETE"}, indent=2))


if __name__ == "__main__":
    main()
