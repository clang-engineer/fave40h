// SPDX-License-Identifier: GPL-2.0-or-later
// Consolidated-load final RAM state only; NOT flash, log replay or whole init.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_SNAPSHOT_BYTES 4104u
#define ORIGINAL_VIAL_CACHE_BYTES 4096u
#define ORIGINAL_VIAL_LOG_START 4104u
struct original_vial_snapshot_cache { uint8_t bytes[4096]; uint32_t write_address; };
// Diagnostic outcomes defined by this model, NOT recovered QMK enum values.
enum original_vial_snapshot_outcome {
    ORIGINAL_VIAL_SNAPSHOT_READ_FAILED = 0,
    ORIGINAL_VIAL_SNAPSHOT_MISMATCH = 1,
    ORIGINAL_VIAL_SNAPSHOT_MATCH = 2,
    ORIGINAL_VIAL_SNAPSHOT_BAD_ARGUMENT = 3
};
// Input is AFTER backing-store translation (e.g. physical inversion), with
// successful checksum reads assumed. A data-word read failure clears RAM.
// Match preserves the caller's cursor; mismatch/failure sets it to LOG_START.
enum original_vial_snapshot_outcome original_vial_snapshot_load(
    struct original_vial_snapshot_cache *cache, const uint8_t *translated_snapshot,
    bool data_reads_succeeded);
// Exactly CACHE_BYTES bytes, not an arbitrary-length hash API. Null returns 0
// defensively; original code always supplies valid RAM.
uint64_t original_vial_snapshot_fnv64(const uint8_t *bytes);
