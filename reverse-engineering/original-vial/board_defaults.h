// SPDX-License-Identifier: GPL-2.0-or-later
// ORIGINAL Vial early-init data only. Does not configure hardware.
#pragma once
#include <stdint.h>
#define ORIGINAL_VIAL_APP_BASE 0x08010000u
#define ORIGINAL_VIAL_PLLCFGR 0x04413010u
#define ORIGINAL_VIAL_CFGR 0x38881000u
struct original_vial_gpio_defaults {
    uint32_t moder, otyper, ospeedr, pupdr, odr, afrl, afrh;
};
// Order A,B,C,D,E,H. Exact packed constants from 0x0801EA14.
static const struct original_vial_gpio_defaults original_vial_gpio[6] = {
    { 0x2A8004A0u, 0x00000000u, 0xFFFFFBAFu, 0x64155105u, 0x0000FFDFu, 0x00007700u, 0x000AA000u }, // GPIOA
    { 0x00000080u, 0x00000000u, 0xFFFFFFFFu, 0x55555555u, 0x0000FFFFu, 0x00000000u, 0x00000000u }, // GPIOB
    { 0x00000000u, 0x00000000u, 0xFFFFFFFFu, 0x01555555u, 0x0000FFFFu, 0x00000000u, 0x00000000u }, // GPIOC
    { 0x00000000u, 0x00000000u, 0xFFFFFFFFu, 0x55555555u, 0x0000FFFFu, 0x00000000u, 0x00000000u }, // GPIOD
    { 0x00000000u, 0x00000000u, 0xFFFFFFFFu, 0x55555555u, 0x0000FFFFu, 0x00000000u, 0x00000000u }, // GPIOE
    { 0x00000000u, 0x00000000u, 0xFFFFFFFFu, 0x55555550u, 0x0000FFFFu, 0x00000000u, 0x00000000u }, // GPIOH
};
