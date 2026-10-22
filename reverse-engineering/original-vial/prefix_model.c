// SPDX-License-Identifier: GPL-2.0-or-later
// Original 0x0801ae04/0x0801ae74 and isolated startup gate conditions only.
#include "prefix_model.h"
bool original_vial_via_valid(const uint8_t *p) {
    return p != 0 && p[ORIGINAL_VIAL_VIA_MAGIC_ADDR] == (ORIGINAL_VIAL_BUILD_ID_LOW24 & 255u)
        && p[ORIGINAL_VIAL_VIA_MAGIC_ADDR + 1] == ((ORIGINAL_VIAL_BUILD_ID_LOW24 >> 8) & 255u)
        && p[ORIGINAL_VIAL_VIA_MAGIC_ADDR + 2] == ((ORIGINAL_VIAL_BUILD_ID_LOW24 >> 16) & 255u);
}
bool original_vial_core_prefix_valid(const uint8_t *p) {
    return p != 0 && ((uint16_t)p[0] | ((uint16_t)p[1] << 8)) == ORIGINAL_VIAL_CORE_MAGIC
        && original_vial_via_valid(p);
}
uint8_t original_vial_layout_option(const uint8_t *p) {
    return p != 0 ? p[ORIGINAL_VIAL_LAYOUT_OPTION_ADDR] : 0;
}
