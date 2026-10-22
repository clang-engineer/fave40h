// SPDX-License-Identifier: GPL-2.0-or-later
// ORIGINAL helper state/ordered call intents only. No QMK, HID, clock or EEPROM.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_cadet_state {
    uint8_t last_modifier;
    uint16_t pressed_at;
};
enum original_vial_cadet_effect_kind {
    ORIGINAL_VIAL_CADET_REGISTER_MODS = 1,
    ORIGINAL_VIAL_CADET_UNREGISTER_MODS = 2,
    ORIGINAL_VIAL_CADET_TAP_CODE = 3
};
struct original_vial_cadet_effect { uint8_t kind, argument; };
struct original_vial_cadet_trace {
    uint8_t count;
    struct original_vial_cadet_effect effects[4];
};
// Only the 14 vendor codes 0x7E01..0x7E0E. Shared state is NOT per-key.
// now/term are caller-provided uint16 milliseconds. No live clock is read.
// Unknown keycode or null state/trace returns false without modifying outputs.
bool original_vial_cadet_event(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace);
// Core stage ONLY: caller must already have passed earlier vendor/feature gates.
// true: built-in 0x7C18..0x7C1E consumed. false: continue after optional reset.
// Other press clears last_modifier; other release changes no state. Trace clears.
// Null state/trace returns false unchanged. NOT QMK's continuation return flag.
bool original_vial_cadet_core_stage(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace);
// Explicit primitive only. Caller decides which dispatcher paths interrupt.
// Non-null state required; timer is retained. Does not release modifiers.
void original_vial_cadet_reset(struct original_vial_cadet_state *state);
