// SPDX-License-Identifier: GPL-2.0-or-later
// One-entry final RAM/cursor model only, NOT a persistent journal replay driver.
#pragma once
#include <stdbool.h>
#include <stdint.h>
enum original_vial_journal_kind {
    ORIGINAL_VIAL_JOURNAL_EMPTY, ORIGINAL_VIAL_JOURNAL_APPLIED,
    ORIGINAL_VIAL_JOURNAL_REJECTED, ORIGINAL_VIAL_JOURNAL_READ_FAILED,
    ORIGINAL_VIAL_JOURNAL_UNMODELED, ORIGINAL_VIAL_JOURNAL_BAD_ARGUMENT
};
struct original_vial_journal_trace {
    uint32_t kind, address, next_position;
    uint8_t length, read_words;
};
// cache >=4096 bytes, entry >=8 translated bytes. First word is supplied/read.
// Position must be aligned and in [0x1008,0x2000). False means defensive argument
// failure or UNMODELED (normal-type lengths 6/7; second read past backing budget).
// Those exclusions are NOT claims that the original rejects such records.
// True means a modeled outcome, NOT necessarily an accepted record. Errors in
// the full firmware lead toward consolidation; never interpret them as skip.
bool original_vial_journal_entry(uint8_t *cache, const uint8_t *entry,
    uint32_t position, bool second_read_ok, struct original_vial_journal_trace *trace);
