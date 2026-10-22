// SPDX-License-Identifier: GPL-2.0-or-later
// RAM-only predicates for two isolated startup gates, NOT EEPROM or reset code.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_PREFIX_BYTES 0x29u
#define ORIGINAL_VIAL_CORE_MAGIC 0xfee3u
#define ORIGINAL_VIAL_VIA_MAGIC_ADDR 0x25u
#define ORIGINAL_VIAL_BUILD_ID_LOW24 0x29f44bu
#define ORIGINAL_VIAL_LAYOUT_OPTION_ADDR 0x28u
// Non-null buffers must contain at least PREFIX_BYTES bytes. Null is treated as
// invalid/zero defensively; original firmware always supplies storage.
bool original_vial_via_valid(const uint8_t *prefix);
bool original_vial_core_prefix_valid(const uint8_t *prefix);
uint8_t original_vial_layout_option(const uint8_t *prefix);
