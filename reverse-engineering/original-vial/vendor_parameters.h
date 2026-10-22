// SPDX-License-Identifier: GPL-2.0-or-later
// Recovered vendor parameters / RAM controls, NOT complete timing/HID behavior.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_cadet_args { uint8_t hold_modifier, tap_modifier, tap_keycode; };
bool original_vial_cadet_parameters(unsigned keycode, struct original_vial_cadet_args *output);
// Partial vendor controls only; no QMK/HID/EEPROM calls or cadet state machine.
void original_vial_shift_edge(uint16_t keycode, bool pressed, uint8_t *last_shift_edge);
uint16_t original_vial_bsdl_keycode(uint8_t last_shift_edge);
// Returns whether recognized, NOT QMK's process_record continuation flag.
bool original_vial_rgb_control(uint16_t keycode, bool pressed, uint8_t enabled[2]);
