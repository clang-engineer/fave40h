# SPDX-License-Identifier: GPL-2.0-or-later
# STM32F411 is an evidence-based BUILD CANDIDATE, not a measured part number.
MCU = STM32F411
BOARD = GENERIC_STM32_F411XE
BOOTLOADER = custom
MCU_LDSCRIPT = fave40h_inspection
EEPROM_DRIVER = transient
LTO_ENABLE = yes
RGB_MATRIX_ENABLE = no
RGBLIGHT_ENABLE = no
BACKLIGHT_ENABLE = no
CONSOLE_ENABLE = no
COMMAND_ENABLE = no

ifeq ($(strip $(FAVE40H_EXPERIMENTAL_BUILD)),yes)
    OPT_DEFS += -DFAVE40H_EXPERIMENTAL_BUILD -DSTM32_HSECLK=16000000U
else
    $(error Inspection-only target: explicitly set FAVE40H_EXPERIMENTAL_BUILD=yes; DO NOT FLASH)
endif
