# Supplied firmware evidence

The user supplied two original manufacturer firmware images named `FAve40h_VIA.uf2` and `FAve40H_VIAL.uf2`. These files are **not** redistributed here.

UF2 inspection previously yielded:

| Image | Blocks | Payload bytes | Target start | Family field |
|---|---:|---:|---|---|
| VIA | 187 | 47,872 | `0x08010000` | `0x57755A57` |
| Vial | 242 | 61,952 | `0x08010000` | `0x57755A57` |

These values are metadata, **not** a confirmed MCU part number or bootloader. The address must not be reused in a new image until the target is independently verified.

To inspect your local copy without flashing:

```bash
python3 tools/inspect_uf2.py path/to/FAve40H_VIAL.uf2
```

Reverse engineering tasks: identify target CPU instruction set, interrupt vector table, matrix scan GPIO registers, bootloader and flash map, and EEPROM emulation/wear-leveling behavior. No pin mapping is currently verified.
