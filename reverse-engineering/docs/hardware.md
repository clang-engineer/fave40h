# Hardware research

From the supplied FAVE40H VIA definition: USB VID `0x5123`, PID `0xA02D`, name `Fave40H_LJTuring`, logical matrix 4 x 12, and layout option `1U Shift`. The embedded Vial definition has the same matrix, layout and custom-keycode descriptions.

## Recovered from both firmware instruction streams

Rows: A5, A6, A3, A4.

Columns: B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8.

The firmware selects columns low and reads active-low row inputs: QMK `ROW2COL`. Initialization and scan code agree on the ordered pin lists. This is static evidence, not a physical continuity test. See [matrix recovery](matrix-recovery.md) for addresses and reproducible checks.

Both stock images use UF2 family field `0x57755A57` and target address `0x08010000`. Exact MCU variant, clock setup, bootloader/recovery, linker/flash geometry, persistent-storage layout, and custom/RGB implementation still require work. The public source is not yet a complete firmware port; do not flash it.
