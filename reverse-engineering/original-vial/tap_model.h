// SPDX-License-Identifier: GPL-2.0-or-later
// Original tap wrapper call intents only, NOT USB reports or real sleeping.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_TAP_TICK_HZ 100000u
enum original_vial_tap_effect_kind {
    ORIGINAL_VIAL_TAP_REGISTER_CODE = 1,
    ORIGINAL_VIAL_TAP_SLEEP_TICKS = 2,
    ORIGINAL_VIAL_TAP_UNREGISTER_CODE = 3
};
struct original_vial_tap_effect { uint32_t kind, argument; };
struct original_vial_tap_trace {
    uint32_t count;
    struct original_vial_tap_effect effects[3];
};
// Delays are configured uint16 milliseconds; outputs are scheduler tick counts.
// Null trace returns false. Other arguments are typed/bounded like vendor calls.
bool original_vial_tap_code_trace(uint8_t keycode, uint16_t normal_delay_ms,
    uint16_t caps_delay_ms, struct original_vial_tap_trace *trace);
