# Six-layer inspection target — COMPILES, DO NOT FLASH

This is a new source implementation, not the manufacturer's original source. Matrix pins come from both stock binaries. The six-layer example, project UID, and inspection profile are new.

## Actual ARM build result

[GitHub Actions run 38119072326](https://github.com/clang-engineer/fave40h-qmk/actions/runs/38119072326), source commit `88776b7354bf16de4e74b19689b20fcef2cd9026`, completed successfully on 2026-10-11 with ARM GCC 13.2.1. Vial-QMK is pinned to `dd43959ae5c08d8a28d38a1acf7b04e86b14a344`.

| Target | ARM compilation/link | BIN size | ELF load end (exclusive) | Keymap symbol |
|---|---|---:|---|---:|
| `fave40h:default` | Passed | 22358 B | `0x08015758` | 576 B |
| `fave40h:vial` | Passed | 38400 B | `0x08019600` | 576 B |

Both ELF images start loading at `0x08010000` and have entry `0x080102FD`. The default ELF's load segments total 22360 bytes versus a 22358-byte BIN because of alignment; these are not interchangeable size metrics. Both passed the custom address-range and keymap-symbol checks. The initial build emitted a metadata filename warning and a non-fatal serial-LTO warning; the metadata file has since been renamed to `keyboard.json`.

The same run passed 25 host-side tests and skipped 3 that require the unpublished original ZIP (28 discovered). New platform tests were added afterward; consult the latest run for its count. There was no physical device, USB/Vial GUI, or persistent-storage test.

## What this profile deliberately does not do

- **Transient EEPROM only:** 4096 bytes of RAM. Settings are discarded on reset/power loss. The stock flash storage sector is not selected as a backend.
- **No bootloader implementation:** `custom` uses upstream weak no-op callbacks. This is not recovered reboot/recovery behavior.
- **No RGB/vendor extensions:** lighting and the manufacturer's custom keycodes/menus are not implemented or advertised.
- **No confirmed silicon identification:** STM32F411 with 128 KiB RAM is an evidence-based build candidate.
- **No firmware distribution or flashing:** CI publishes no firmware artifacts and does not connect to a keyboard.

## Source and layout

`keyboards/fave40h/keymaps/six_layers.h` contains six real matrix arrays: base, numbers, symbols, navigation, media, and F1–F12. Base split spaces use `LT()` for numbers/symbols; the three rightmost bottom keys hold navigation/media/extra layers. Higher-layer bottom keys are transparent. These are fresh example defaults, not a copy of the owner's existing keymap.

`keyboard.json` describes 42 physical keys. The Vial definition retains the supplied physical geometry and `1U Shift` option, but omits unimplemented vendor keycodes and LED menus. A new UID distinguishes this project from the manufacturer build.

## Explicit compile-only opt-in

Overlay `keyboards/fave40h` into a separate Vial-QMK checkout pinned by `tools/vial_revision.txt`. Install the toolchain/dependencies and required submodules as shown in `.github/workflows/inspection-build.yml`, then run inside that checkout:

```sh
make fave40h:default FAVE40H_EXPERIMENTAL_BUILD=yes
make fave40h:vial FAVE40H_EXPERIMENTAL_BUILD=yes
```

From this repository, inspect the resulting ELF files:

```sh
python3 tools/check_build.py /path/to/vial-qmk/.build/fave40h_default.elf
python3 tools/check_build.py /path/to/vial-qmk/.build/fave40h_vial.elf
```

The linker constrains all app bytes to `[0x08010000, 0x08020000)`. The explicit flag is only an accidental-build guard; neither it nor a green build proves safe flashing. Generated BIN/HEX files are also inspection-only even if upstream build messages call them load files for flashing.

Before a device test: establish independent recovery and hardware identity, validate board initialization and clock behavior, implement and validate storage migration, and then test keys/Vial/USB/optional lighting. See [platform recovery](platform-recovery.md) for the stock settings sector and why an application UF2 is not a full backup.
