# STM32F4 family evidence

The manufacturer FAVE40H UF2 firmware carries family ID `0x57755A57` and targets application address `0x08010000`.

Microsoft UF2 family definitions identify `0x57755A57` as **STM32F4 family**, rather than STM32F1:
- https://github.com/microsoft/uf2/blob/master/utils/uf2families.json
- https://microsoft.github.io/uf2/

The public STM32 UF2 bootloader example also uses the same family ID and default app load address:
- https://github.com/mmoskal/uf2-stm32f/blob/master/hw_config.h

**Inference, not hardware proof:** FAVE40H likely uses an STM32F4-family MCU and a bootloader that reserves flash below `0x08010000`. The exact chip, flash geometry, and bootloader are not yet verified. Do not assume the example bootloader is installed.

## Next reverse-engineering steps

1. Extract a contiguous binary from each supplied UF2, preserving address and block order.
2. Disassemble as ARM Thumb at base `0x08010000`; identify vector handlers and startup.
3. Locate STM32F4 peripheral accesses, especially RCC (`0x40023800`) and GPIO (`0x40020000` onward). Presence of addresses is a clue, not proof of key matrix pin mapping.
4. Compare VIA and Vial common routines to identify matrix scan code.
5. Cross-check inferred GPIO pins with PCB traces before generating firmware.
6. Validate EEPROM/wear-leveling region and custom keycodes before expanding from four to six layers.

No safe-to-flash firmware has been built.
