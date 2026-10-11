# Six-layer inspection target — DO NOT FLASH

This is a new source implementation, not the manufacturer's recovered original source. The matrix pins come from both stock binaries. The six-layer example, project UID, and inspection build profile are new.

## What the profile deliberately does not do

- It uses the **transient EEPROM driver** (4096 bytes in RAM). Settings do not persist across reset/power loss. It does not use the stock flash storage sector.
- The bootloader type is `custom` with upstream weak no-op callbacks. This is NOT a recovered reboot/recovery implementation.
- RGB, backlight, and the manufacturer's custom keycodes/menus are not implemented or advertised.
- STM32F411 and 128 KiB RAM are a build candidate consistent with stock software, not a confirmed physical chip/density.
- A successful compile does not make this image suitable for flashing. No firmware artifacts are published by CI.

## Source

`keyboards/fave40h/keymaps/six_layers.h` contains six real matrix arrays: base, numbers, symbols, navigation, media, and F1–F12. On base, the split spaces use `LT()` for numbers/symbols; the right three bottom keys hold navigation/media/extra layers. Higher-layer bottom keys are transparent. The array occupies 576 bytes (6 × 4 × 12 × 2).

`info.json` describes 42 physical keys. The Vial definition reuses the physical geometry supplied by the owner but removes unimplemented vendor custom keycodes and LED menus. It is not a full vendor definition dump.

## Explicit compile-only opt-in

Overlay `keyboards/fave40h` into Vial-QMK at the commit in `tools/vial_revision.txt`, initialize its required submodules, then run:

```sh
make fave40h:default FAVE40H_EXPERIMENTAL_BUILD=yes
make fave40h:vial FAVE40H_EXPERIMENTAL_BUILD=yes
```

The custom linker limits application bytes to `[0x08010000, 0x08020000)`, avoiding the first 64 KiB. `tools/check_build.py` checks the linked ELF address range and the 576-byte keymap symbol. The opt-in gate is only a development guard, not a proof of safety.

The first local check passed 13 source tests including host C grammar checks with a stub. Those checks are **not QMK compilation**. Refer to the GitHub Actions run for the actual ARM/QMK build outcome; no success is assumed in this document.

Before a device build: identify silicon and reliable independent recovery, confirm clock/flash geometry and firmware size, implement and validate persistent-storage migration, then test key input/Vial/USB/optional lighting on hardware.
