// SPDX-License-Identifier: GPL-2.0-or-later
// Original one-entry slice 0x08018824..0x0801887e; no hardware/whole-loop calls.
#include "journal_model.h"
bool original_vial_journal_entry(uint8_t *cache, const uint8_t *entry,
    uint32_t position, bool second_read_ok, struct original_vial_journal_trace *trace) {
    if (trace == 0) return false;
    *trace = (struct original_vial_journal_trace){ .kind = ORIGINAL_VIAL_JOURNAL_BAD_ARGUMENT, .next_position = position };
    if (cache == 0 || entry == 0 || position < 0x1008u || position >= 0x2000u || (position & 3u)) return false;
    trace->read_words = 1;
    if ((entry[0] | entry[1] | entry[2] | entry[3]) == 0) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_EMPTY;
        return true;
    }
    trace->next_position += 4;
    if (entry[0] & 0xC0u) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_REJECTED;
        return true;
    }
    trace->address = ((uint32_t)(entry[0] & 7u) << 16) | ((uint32_t)entry[1] << 8) | entry[2];
    trace->length = (entry[0] >> 3) & 7u;
    if (trace->length > 5 || (trace->length > 1 && position + 8 > 0x2000u)) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_UNMODELED;
        return false;
    }
    if (trace->address + trace->length > 4096u) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_REJECTED;
        return true;
    }
    if (trace->length > 1) {
        trace->read_words = 2;
        if (!second_read_ok) {
            trace->kind = ORIGINAL_VIAL_JOURNAL_READ_FAILED;
            return true;
        }
        trace->next_position += 4;
    }
    for (unsigned i = 0; i < trace->length; ++i) cache[trace->address + i] = entry[3 + i];
    trace->kind = ORIGINAL_VIAL_JOURNAL_APPLIED;
    return true;
}
