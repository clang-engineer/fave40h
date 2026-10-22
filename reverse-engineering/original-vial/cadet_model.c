// SPDX-License-Identifier: GPL-2.0-or-later
// Original helper 0x0801D4C8 + isolated core stage 0x08016646; NOT full routing.
// Effects are call intents, NOT complete USB reports or tap-code delays.
#include "cadet_model.h"
#include "vendor_parameters.h"
static uint8_t mod_bit(uint8_t code) { return (uint8_t)(1u << (code & 7)); }
static bool is_modifier(uint8_t code) { return (uint8_t)(code + 0x20) < 8; }
static void emit(struct original_vial_cadet_trace *trace, uint8_t kind, uint8_t argument) {
    trace->effects[trace->count++] = (struct original_vial_cadet_effect){kind, argument};
}
static void perform_cadet(struct original_vial_cadet_state *state,
    struct original_vial_cadet_args args, bool pressed, uint16_t now,
    uint16_t tapping_term, struct original_vial_cadet_trace *trace) {
    *trace = (struct original_vial_cadet_trace){0};
    if (pressed) {
        state->last_modifier = args.hold_modifier;
        state->pressed_at = now;
        emit(trace, ORIGINAL_VIAL_CADET_REGISTER_MODS, mod_bit(args.hold_modifier));
    } else if (state->last_modifier == args.hold_modifier &&
               (uint16_t)(now - state->pressed_at) < tapping_term) {
        if (args.hold_modifier != args.tap_modifier) {
            emit(trace, ORIGINAL_VIAL_CADET_UNREGISTER_MODS, mod_bit(args.hold_modifier));
            if (is_modifier(args.tap_modifier))
                emit(trace, ORIGINAL_VIAL_CADET_REGISTER_MODS, mod_bit(args.tap_modifier));
        }
        emit(trace, ORIGINAL_VIAL_CADET_TAP_CODE, args.tap_keycode);
        if (is_modifier(args.tap_modifier))
            emit(trace, ORIGINAL_VIAL_CADET_UNREGISTER_MODS, mod_bit(args.tap_modifier));
    } else {
        emit(trace, ORIGINAL_VIAL_CADET_UNREGISTER_MODS, mod_bit(args.hold_modifier));
    }
    // Original release paths leave BOTH shared fields intact.
}
bool original_vial_cadet_event(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace) {
    struct original_vial_cadet_args args;
    if (state == 0 || trace == 0 || !original_vial_cadet_parameters(keycode, &args)) return false;
    perform_cadet(state, args, pressed, now, tapping_term, trace);
    return true;
}
static const struct original_vial_cadet_args builtin_parameters[7] = {
    { 0xE0, 0xE1, 0x26 }, // 0x7C18
    { 0xE4, 0xE5, 0x27 }, // 0x7C19
    { 0xE1, 0xE1, 0x26 }, // 0x7C1A
    { 0xE5, 0xE5, 0x27 }, // 0x7C1B
    { 0xE2, 0xE1, 0x26 }, // 0x7C1C
    { 0xE6, 0xE5, 0x27 }, // 0x7C1D
    { 0xE5, 0x01, 0x28 }, // 0x7C1E
};
bool original_vial_cadet_core_stage(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace) {
    if (state == 0 || trace == 0) return false;
    if (keycode >= 0x7C18 && keycode <= 0x7C1E) {
        perform_cadet(state, builtin_parameters[keycode - 0x7C18], pressed, now, tapping_term, trace);
        return true;
    }
    *trace = (struct original_vial_cadet_trace){0};
    if (pressed) original_vial_cadet_reset(state);
    return false;
}
void original_vial_cadet_reset(struct original_vial_cadet_state *state) {
    state->last_modifier = 0;
}
