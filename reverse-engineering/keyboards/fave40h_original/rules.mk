# SPDX-License-Identifier: GPL-2.0-or-later
$(error ORIGINAL_TARGET_INCOMPLETE: RGB, vendor handlers and Vial security pending; no partial-image override)
EEPROM_DRIVER = wear_leveling
WEAR_LEVELING_DRIVER = embedded_flash
SPACE_CADET_ENABLE = yes
RGB_MATRIX_ENABLE = yes
RGB_MATRIX_DRIVER = ws2812
WS2812_DRIVER = pwm
