// SPDX-License-Identifier: GPL-2.0-or-later
// No MMIO, DMA, interrupts or EEPROM. NOT a flashable QMK implementation.
#include "rgb_model.h"
const uint8_t original_vial_led_matrix[4][12] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
    { 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 255, 12 },
    { 23, 255, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 },
    { 41, 255, 40, 39, 38, 255, 255, 255, 37, 36, 35, 34 }
};
const uint8_t original_vial_led_positions[72][2] = {
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
    { 18, 64 }
};
const uint8_t original_vial_led_flags[72] = {
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
};

// 0x08013924: initial black data and 224 reset slots held low.
void original_vial_pwm_init(uint32_t output[1952]) {
    for (unsigned i = 0; i < 1952; ++i) output[i] = i < 1728 ? 8 : 0;
}
// 0x08013320: GRB bytes, MSB first. The reset tail is never rewritten.
void original_vial_pwm_encode(const uint8_t grb[72][3], uint32_t output[1952]) {
    for (unsigned led = 0; led < 72; ++led)
        for (unsigned channel = 0; channel < 3; ++channel)
            for (unsigned bit = 0; bit < 8; ++bit)
                output[led * 24 + channel * 8 + bit] = (grb[led][channel] & (0x80u >> bit)) ? 21 : 8;
}
// Post-effect filtering from 0x080156F8..0x08015754, BEFORE flush.
// Caps Lock override LED 22 is set before this and can also be suppressed.
bool original_vial_rgb_filter(uint8_t grb[72][3], unsigned begin, unsigned end, const uint8_t enabled[2]) {
    if (begin > end || end > 72) return false;
    for (unsigned led = begin; led < end; ++led)
        if ((!enabled[0] && (original_vial_led_flags[led] & 4)) ||
            (!enabled[1] && (original_vial_led_flags[led] & 2)))
            for (unsigned channel = 0; channel < 3; ++channel) grb[led][channel] = 0;
    return true;
}
