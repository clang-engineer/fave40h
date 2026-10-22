// SPDX-License-Identifier: GPL-2.0-or-later
// Original consolidated-load slice 0x08018758..0x08018816, no hardware calls.
#include "snapshot_model.h"
uint64_t original_vial_snapshot_fnv64(const uint8_t *bytes) {
    if (bytes == 0) return 0;
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    for (unsigned i = 0; i < ORIGINAL_VIAL_CACHE_BYTES; ++i)
        hash = (hash ^ bytes[i]) * UINT64_C(0x100000001b3);
    return hash;
}
enum original_vial_snapshot_outcome original_vial_snapshot_load(
    struct original_vial_snapshot_cache *cache, const uint8_t *snapshot,
    bool data_reads_succeeded) {
    if (cache == 0 || snapshot == 0) return ORIGINAL_VIAL_SNAPSHOT_BAD_ARGUMENT;
    if (data_reads_succeeded) {
        uint64_t stored = 0;
        for (unsigned i = 0; i < 8; ++i)
            stored |= (uint64_t)snapshot[ORIGINAL_VIAL_CACHE_BYTES + i] << (i * 8);
        if (stored == original_vial_snapshot_fnv64(snapshot)) {
            for (unsigned i = 0; i < ORIGINAL_VIAL_CACHE_BYTES; ++i) cache->bytes[i] = snapshot[i];
            return ORIGINAL_VIAL_SNAPSHOT_MATCH;
        }
    }
    for (unsigned i = 0; i < ORIGINAL_VIAL_CACHE_BYTES; ++i) cache->bytes[i] = 0;
    cache->write_address = ORIGINAL_VIAL_LOG_START;
    return data_reads_succeeded ? ORIGINAL_VIAL_SNAPSHOT_MISMATCH : ORIGINAL_VIAL_SNAPSHOT_READ_FAILED;
}
