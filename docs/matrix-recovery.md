# Matrix recovery from both stock FAVE40H builds

Status: **pin configuration recovered by static firmware analysis; no device test and no new firmware build.**
This report supersedes the older statements that no matrix pin assignments had been found.

## Recovered QMK configuration

| Logical axis | GPIO order (zero-based matrix indexing) |
|---|---|
| Rows 0–3 | A5, A6, A3, A4 |
| Columns 0–11 | B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8 |
| Scan convention | Select one column low; read four active-low row inputs |
| QMK diode direction | ROW2COL |

`keyboards/fave40h/config.h` now contains these settings. The labels are GPIO names, not physical package pin numbers. Diode direction is inferred from the firmware's electrical scan convention, not from a multimeter or diode photograph.

## Why these are matrix pins, not arbitrary peripheral literals

Both files were extracted from the owner's manufacturer ZIP and decoded using Clang/LLD and LLVM objdump in Thumb/Cortex-M4 mode. Whole-file linear decoding alone was not treated as proof. The reset branch, startup calls, main's scan calls, table loads, loop bounds, and register operations were inspected together.

| Evidence | VIA address | Vial address |
|---|---|---|
| Reset branch | 0x080102FC -> 0x080101E0 | same |
| Startup's main call at 0x080102A8 | 0x08017FE0 | 0x080183A0 |
| One main-to-scan call | 0x080187F6 | 0x08018BE2 |
| Matrix scan entry | 0x0801A5E4 | 0x0801D65C |
| Column-table literal load | 0x0801A5F0 | 0x0801D66C |
| Column table, 12 32-bit entries | 0x0801AEE8 | 0x0801DD24 |
| Row-table literal load | 0x0801A63E | 0x0801D6B6 |
| Row table, 4 32-bit entries | 0x0801B3F0 | 0x0801E5DC |
| Selected-column reset write | 0x0801A61E | 0x0801D698 |
| Row input-register read | 0x0801A660 | 0x0801D6D8 |

The code splits each pin value into `port = value & ~0xF` and `pad = value & 0xF`. For example, `0x4002040C` becomes GPIOB pin 12. It configures the selected column as an output, writes the bit mask to the high half of BSRR (port + 0x1A), reads each row's IDR (port + 0x10), and sets the column bit in a 16-bit row word when the input is low. The loops cover twelve columns and four rows.

Separately, initialization iterates the same column table and loads the same four row pins in the same order. The input helper configures input mode with pull-up (`0x20` in this build's PAL mode encoding). The GPIO-mode helpers were also inspected, not identified solely by address similarity.

The two builds have different instruction/register allocation but yield identical ordered pin lists. This is stronger evidence than a single raw byte-pattern match. It remains static reconstruction, not proof that an independently rebuilt firmware works on the board.

## Embedded Vial definition

The Vial image contains an XZ-compressed JSON stream at **0x0801DFA8**, decoding to 2,767 bytes. Its matrix is 4 x 12, its layout label is `1U Shift`, and it has 22 custom-keycode descriptions. The `layouts` and `customKeycodes` objects exactly match the supplied VIA JSON. Names and descriptions do not recover the C implementations of the custom keycodes.

The tool can extract this definition to a new local file. The original firmware and full manufacturer definition are not published in this repository.

## Reproduce and tests

```sh
python3 tools/recover_matrix.py '/path/to/fave40h (2).zip'
python3 tools/recover_matrix.py '/path/to/fave40h (2).zip' --vial-json extracted-vial-definition.json
FAVE40H_STOCK_ZIP='/path/to/fave40h (2).zip' python3 -m unittest discover -s tests -v
```

The first command checks known SHA-256 identities, validates UF2 structure, decodes selected BL/LDR instructions at inspected boundaries, verifies instruction witnesses, extracts the pin tables, and cross-checks init versus scan. It is a **build-specific evidence checker, not an automatic decompiler**. Unknown or modified firmware is rejected. See `matrix-evidence.json` for exact hashes and generated results.

Local result: **15 tests passed**, including both original builds, embedded JSON extraction, header/evidence agreement, and malformed/modified-input rejection. Python syntax checks also passed. These are host-side analysis tests, not keyboard or QMK firmware tests.

For manual disassembly, use the ELF-wrapping procedure in `startup-disassembly.md`. Inspect VIA 0x0801A5E4–0x0801A69C and Vial 0x0801D65C–0x0801D71A, plus their literal pools shown above. Decoding an ELF wrapper does not produce a flashable firmware.

## What is still missing

An exact supported MCU/board target, clock configuration, linker/bootloader and flash geometry, persistent-storage allocation, a real default keymap, and the desired custom/RGB functionality. The existing six-layer macro is only a setting: no six-layer UF2 has been built or flashed. Do not infer a complete port from this matrix header.

At 4 x 12 with two-byte keycodes, raw keymap storage alone grows from 384 to 576 bytes for four versus six layers. The extra 192 bytes do not include Vial metadata, macros, tap dances, combos, or other settings; available storage has not been validated.

## Primary-source interpretation references

- [QMK matrix scanner](https://github.com/qmk/qmk_firmware/blob/master/quantum/matrix.c), inspected blob `ccedcc3f792d576401e677c7c77aea3330d1fd07`: ROW2COL selects columns and reads rows.
- [QMK ChibiOS GPIO interface](https://github.com/qmk/qmk_firmware/blob/master/platforms/chibios/gpio.h), inspected blob `a8d6554f296b6a47239feb6647fd9614d8e80e02`.
- [ST STM32F4 GPIO register layout](https://github.com/STMicroelectronics/cmsis-device-f4/blob/master/Include/stm32f411xe.h#L265-L277), inspected blob `03c36a1bfb2eefbe6789c267b9f34606a8c69bc9`: IDR +0x10 and BSRR +0x18. Using this header to interpret shared F4 registers does **not** identify the chip as an STM32F411.
