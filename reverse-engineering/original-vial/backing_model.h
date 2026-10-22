// SPDX-License-Identifier: GPL-2.0-or-later
// Pure word codec and captured intents; NEVER a physical flash driver.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_backing_intent { uint32_t driver_offset, physical_word, size; };
uint32_t original_vial_backing_word(uint32_t word, uint8_t inversion_flag);
// Mirrors the original unchecked uint32 offset calculation; performs NO write.
bool original_vial_backing_program(uint32_t base, uint32_t offset, uint32_t logical_word,
    uint8_t inversion_flag, uint32_t driver_status, struct original_vial_backing_intent *intent);
// error is the byte observed at the FINAL check, not an initial/stale error.
// A controlled byte injection is NOT a verified physical bus-fault scenario.
bool original_vial_backing_read(uint32_t physical_word, uint8_t inversion_flag,
    uint8_t observed_error, uint32_t *logical_word);
