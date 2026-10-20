// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include_next <mcuconf.h>
// Stock PLLCFGR = 0x04413010. HSE=16 MHz is inferred from PLL + USB/timer clocks.
#undef STM32_PLLM_VALUE
#define STM32_PLLM_VALUE 16
#undef STM32_PLLN_VALUE
#define STM32_PLLN_VALUE 192
#undef STM32_PLLP_VALUE
#define STM32_PLLP_VALUE 4
#undef STM32_PLLQ_VALUE
#define STM32_PLLQ_VALUE 4
#undef STM32_ST_USE_TIMER
#define STM32_ST_USE_TIMER 5
// The generic F411 configuration supplies HSE source, AHB /1, APB1 /2, APB2 /1.
