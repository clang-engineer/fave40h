// SPDX-License-Identifier: GPL-2.0-or-later
// Reconstructed from manufacturer ORIGINAL Vial binary; names are new.
// FORENSIC MODEL ONLY. Not a complete QMK firmware and NOT safe to flash.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_LAYERS 4
#define ORIGINAL_VIAL_ROWS 4
#define ORIGINAL_VIAL_COLS 12
extern const uint16_t original_vial_factory_keymaps[4][4][12];
void original_vial_reset_keymaps(uint16_t output[4][4][12]);
bool original_vial_keycode_address(unsigned layer, unsigned row, unsigned col, uint16_t *address);
