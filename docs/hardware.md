# Hardware research

Confirmed from supplied FAVE40H VIA definition:
- USB VID: `0x5123`; PID: `0xA02D`
- Logical matrix: 4 rows × 12 columns
- Keyboard name: `Fave40H_LJTuring`
- One layout option: `1U Shift`

Supplied FAVE40H VIA/Vial UF2 images target `0x08010000`; this does not establish the MCU model, bootloader, or pin assignments.

**Unknown:** exact MCU, row/column GPIO pins, diode direction, RGB pin mappings, bootloader recovery procedure, EEPROM/wear-leveling configuration, Vial UID and custom keycode implementations.

Do not flash reconstructed firmware before verifying these details.
