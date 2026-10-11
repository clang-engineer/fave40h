# Roadmap

1. Identify MCU and bootloader from physical board or reliable documentation.
2. Recover and verify matrix row/column GPIO mapping and diode direction.
3. Implement QMK `keyboard.json` / layout mapping based on supplied VIA definition.
4. Integrate original Vial JSON, custom keycodes and lighting controls.
5. Validate persistent storage allocation for 6 dynamic layers.
6. Compile; inspect UF2 target; confirm reliable rollback before device testing.

No reconstructed image is currently safe to flash.
