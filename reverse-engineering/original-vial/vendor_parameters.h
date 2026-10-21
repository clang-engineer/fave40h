// SPDX-License-Identifier: GPL-2.0-or-later
// Recovered vendor call arguments only, NOT the complete timing/USB behavior.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_cadet_args { uint8_t hold_modifier, tap_modifier, tap_keycode; };
bool original_vial_cadet_parameters(unsigned keycode, struct original_vial_cadet_args *output);
