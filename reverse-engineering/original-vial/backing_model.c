// SPDX-License-Identifier: GPL-2.0-or-later
#include "backing_model.h"
uint32_t original_vial_backing_word(uint32_t word, uint8_t inversion_flag) {
    return inversion_flag ? ~word : word;
}
bool original_vial_backing_program(uint32_t base, uint32_t offset, uint32_t logical_word,
    uint8_t inversion_flag, uint32_t driver_status, struct original_vial_backing_intent *intent) {
    if (intent == 0) return false;
    *intent = (struct original_vial_backing_intent){base + offset,
        original_vial_backing_word(logical_word, inversion_flag), 4};
    return driver_status == 0;
}
bool original_vial_backing_read(uint32_t physical_word, uint8_t inversion_flag,
    uint8_t observed_error, uint32_t *logical_word) {
    if (logical_word == 0) return false;
    *logical_word = observed_error ? 0 : original_vial_backing_word(physical_word, inversion_flag);
    return observed_error == 0;
}
