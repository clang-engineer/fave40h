// SPDX-License-Identifier: GPL-2.0-or-later
#include "vendor_parameters.h"
static const struct original_vial_cadet_args parameters[14] = {
    { 0xE1, 0xE1, 0x2F }, // 0x7E01
    { 0xE5, 0xE5, 0x30 }, // 0x7E02
    { 0xE0, 0xE1, 0x2F }, // 0x7E03
    { 0xE4, 0xE5, 0x30 }, // 0x7E04
    { 0xE2, 0xE1, 0x2F }, // 0x7E05
    { 0xE6, 0xE5, 0x30 }, // 0x7E06
    { 0xE1, 0xE1, 0x36 }, // 0x7E07
    { 0xE5, 0xE5, 0x37 }, // 0x7E08
    { 0xE0, 0xE1, 0x36 }, // 0x7E09
    { 0xE4, 0xE5, 0x37 }, // 0x7E0A
    { 0xE2, 0xE1, 0x36 }, // 0x7E0B
    { 0xE6, 0xE5, 0x37 }, // 0x7E0C
    { 0xE0, 0x01, 0x39 }, // 0x7E0D
    { 0xE4, 0x01, 0x28 }, // 0x7E0E
};
bool original_vial_cadet_parameters(unsigned keycode, struct original_vial_cadet_args *output) {
    if (keycode < 0x7E01 || keycode > 0x7E0E || output == 0) return false;
    *output = parameters[keycode - 0x7E01];
    return true;
}
// Deliberately retain original last-edge behavior, including overlapping shifts.
void original_vial_shift_edge(uint16_t keycode, bool pressed, uint8_t *last_shift_edge) {
    if (keycode == 0xE1 || keycode == 0xE5) *last_shift_edge = pressed;
}
// Original checks this again on release, not a saved key from the press.
uint16_t original_vial_bsdl_keycode(uint8_t last_shift_edge) {
    return last_shift_edge ? 0x4C : 0x2A;
}
bool original_vial_rgb_control(uint16_t keycode, bool pressed, uint8_t enabled[2]) {
    if (keycode < 0x7E10 || keycode > 0x7E15) return false;
    if (!pressed) return true;
    unsigned index = (keycode - 0x7E10) / 3;
    switch ((keycode - 0x7E10) % 3) {
        case 0: enabled[index] ^= 1; break;
        case 1: enabled[index] = 1; break;
        case 2: enabled[index] = 0; break;
    }
    return true;
}
