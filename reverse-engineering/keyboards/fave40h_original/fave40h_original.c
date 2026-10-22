// SPDX-License-Identifier: GPL-2.0-or-later
// Original 264-byte LED table, through pinned QMK led_config_t.
#include "quantum.h"
led_config_t g_led_config = {
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
        { 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 255, 12 },
        { 23, 255, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 },
        { 41, 255, 40, 39, 38, 255, 255, 255, 37, 36, 35, 34 },
    },
    {
        { 13, 2 },
        { 31, 2 },
        { 49, 2 },
        { 67, 2 },
        { 85, 2 },
        { 103, 2 },
        { 121, 2 },
        { 139, 2 },
        { 157, 2 },
        { 175, 2 },
        { 193, 2 },
        { 211, 2 },
        { 211, 22 },
        { 175, 22 },
        { 157, 22 },
        { 139, 22 },
        { 121, 22 },
        { 103, 22 },
        { 85, 22 },
        { 67, 22 },
        { 49, 22 },
        { 31, 22 },
        { 13, 22 },
        { 13, 42 },
        { 49, 42 },
        { 67, 42 },
        { 85, 42 },
        { 103, 42 },
        { 121, 42 },
        { 139, 42 },
        { 157, 42 },
        { 175, 42 },
        { 193, 42 },
        { 211, 42 },
        { 211, 62 },
        { 193, 62 },
        { 175, 62 },
        { 157, 62 },
        { 85, 62 },
        { 67, 62 },
        { 49, 62 },
        { 13, 62 },
        { 0, 64 },
        { 0, 48 },
        { 0, 32 },
        { 0, 16 },
        { 0, 0 },
        { 18, 0 },
        { 36, 0 },
        { 54, 0 },
        { 72, 0 },
        { 90, 0 },
        { 108, 0 },
        { 134, 0 },
        { 152, 0 },
        { 170, 0 },
        { 188, 0 },
        { 206, 0 },
        { 224, 0 },
        { 224, 16 },
        { 224, 32 },
        { 224, 48 },
        { 224, 64 },
        { 206, 64 },
        { 188, 64 },
        { 152, 64 },
        { 108, 64 },
        { 90, 64 },
        { 72, 64 },
        { 54, 64 },
        { 36, 64 },
        { 18, 64 },
    },
    { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 }
};

// Original user EEPROM word at 0x13: low two bytes are RGB group enables.
// Keep all four loaded bytes verbatim; do not normalize nonzero enable bytes.
uint32_t original_rgb_group_state;
void eeconfig_init_user(void) {
    original_rgb_group_state = 0x00000101U;
    eeconfig_update_user(original_rgb_group_state);
}
void keyboard_post_init_user(void) {
    original_rgb_group_state = eeconfig_read_user();
}
// Last Shift edge, not the union of currently held Shift modifiers.
uint8_t original_last_shift_edge;
static const uint8_t original_cadet_args[14][3] = {
    {0xE1, 0xE1, 0x2F},
    {0xE5, 0xE5, 0x30},
    {0xE0, 0xE1, 0x2F},
    {0xE4, 0xE5, 0x30},
    {0xE2, 0xE1, 0x2F},
    {0xE6, 0xE5, 0x30},
    {0xE1, 0xE1, 0x36},
    {0xE5, 0xE5, 0x37},
    {0xE0, 0xE1, 0x36},
    {0xE4, 0xE5, 0x37},
    {0xE2, 0xE1, 0x36},
    {0xE6, 0xE5, 0x37},
    {0xE0, 0x01, 0x39},
    {0xE4, 0x01, 0x28},
};
// Destructive reset remains pending. Do not add an EEPROM save here.
bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    if (keycode == 0xE1 || keycode == 0xE5) original_last_shift_edge = record->event.pressed;
    if (keycode == 0x7E00) {
        // Deliberately reselect on release too, as in the original.
        uint8_t code = original_last_shift_edge ? 0x4C : 0x2A;
        if (record->event.pressed) register_code(code);
        else unregister_code(code);
        return false;
    }
    if (keycode >= 0x7E01 && keycode <= 0x7E0E) {
        const uint8_t *args = original_cadet_args[keycode - 0x7E01];
        perform_space_cadet(record, keycode, args[0], args[1], args[2]);
        return false;
    }
    if (keycode < 0x7E10 || keycode > 0x7E15) return true;
    if (record->event.pressed) {
        unsigned command = keycode - 0x7E10;
        unsigned shift = (command / 3) * 8;
        uint32_t value = (original_rgb_group_state >> shift) & 0xFFU;
        switch (command % 3) {
            case 0: value ^= 1U; break;
            case 1: value = 1U; break;
            case 2: value = 0U; break;
        }
        original_rgb_group_state = (original_rgb_group_state & ~(0xFFU << shift)) | (value << shift);
    }
    return false;
}
bool rgb_matrix_indicators_user(void) {
    if (host_keyboard_leds() & 0x02U) rgb_matrix_set_color(22, 255, 255, 255);
    return true;
}
// Framework-supplied valid LED interval only. Keep the original per-chunk pass:
// a final Caps white at LED22 is outside [60,72) and is deliberately not cleared.
bool rgb_matrix_indicators_advanced_user(uint8_t begin, uint8_t end) {
    for (uint8_t led = begin; led < end; ++led) {
        uint8_t flags = g_led_config.flags[led];
        if (((original_rgb_group_state & 0xFFU) == 0 && (flags & 4U)) ||
            (((original_rgb_group_state >> 8) & 0xFFU) == 0 && (flags & 2U)))
            rgb_matrix_set_color(led, 0, 0, 0);
    }
    return true;
}
