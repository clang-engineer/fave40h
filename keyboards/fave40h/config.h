#pragma once

// Reconstructed from BOTH stock FAVE40H VIA and Vial instruction streams.
// Logical row/column order, not MCU package pin numbers.
// Evidence: docs/matrix-recovery.md. Not yet electrically validated.
#define MATRIX_ROWS 4
#define MATRIX_COLS 12
#define MATRIX_ROW_PINS { A5, A6, A3, A4 }
#define MATRIX_COL_PINS { B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8 }

// Firmware drives one column low, then reads four pulled-up row inputs.
#define DIODE_DIRECTION ROW2COL

// This header alone is NOT a firmware port. Do not assume MCU variant,
// oscillator, bootloader/linker geometry, or EEPROM layout from these pins.
