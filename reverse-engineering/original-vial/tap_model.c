// SPDX-License-Identifier: GPL-2.0-or-later
// Original 0x08014188 -> 0x08014148, with HID/scheduler calls represented as data.
#include "tap_model.h"
bool original_vial_tap_code_trace(uint8_t keycode, uint16_t normal_delay_ms,
    uint16_t caps_delay_ms, struct original_vial_tap_trace *trace) {
    if (trace == 0) return false;
    uint16_t delay = keycode == 0x39 ? caps_delay_ms : normal_delay_ms;
    uint32_t ticks = delay ? (uint32_t)(((uint64_t)delay * ORIGINAL_VIAL_TAP_TICK_HZ + 999) / 1000) : 1;
    *trace = (struct original_vial_tap_trace){
        .count = 3,
        .effects = {
            {ORIGINAL_VIAL_TAP_REGISTER_CODE, keycode},
            {ORIGINAL_VIAL_TAP_SLEEP_TICKS, ticks},
            {ORIGINAL_VIAL_TAP_UNREGISTER_CODE, keycode}
        }
    };
    return true;
}
