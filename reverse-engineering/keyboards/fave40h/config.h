// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#ifndef FAVE40H_EXPERIMENTAL_BUILD
#    error "Inspection build only: pass FAVE40H_EXPERIMENTAL_BUILD=yes. Do not flash."
#endif
#define MATRIX_ROWS 4
#define MATRIX_COLS 12
#define MATRIX_ROW_PINS { A5, A6, A3, A4 }
#define MATRIX_COL_PINS { B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8 }
#define DIODE_DIRECTION ROW2COL

// Deliberately RAM-only until hardware/recovery and storage migration are verified.
#define TRANSIENT_EEPROM_SIZE 4096
#define DEBOUNCE 5
