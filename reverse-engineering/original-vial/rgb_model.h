// SPDX-License-Identifier: GPL-2.0-or-later
// ORIGINAL binary-backed data / RAM-only model. NOT a hardware driver.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_RGB_LEDS 72
#define ORIGINAL_VIAL_PWM_COLOR_WORDS 1728
#define ORIGINAL_VIAL_PWM_WORDS 1952
extern const uint8_t original_vial_led_matrix[4][12];
extern const uint8_t original_vial_led_positions[72][2];
extern const uint8_t original_vial_led_flags[72];
// All pointer arguments must reference complete, non-overlapping arrays.
void original_vial_pwm_init(uint32_t output[1952]);
void original_vial_pwm_encode(const uint8_t grb[72][3], uint32_t output[1952]);
// Valid chunk: 0 <= begin <= end <= 72. Invalid range leaves colors unchanged.
bool original_vial_rgb_filter(uint8_t grb[72][3], unsigned begin, unsigned end, const uint8_t enabled[2]);
