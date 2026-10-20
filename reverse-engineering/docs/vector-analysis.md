# FAVE40H vector-table evidence

Read-only inspection of the user-provided manufacturer VIA and Vial UF2 files shows:

| Property | VIA | Vial |
|---|---|---|
| UF2 flags | `0x00002000` | `0x00002000` |
| Family ID | `0x57755A57` | `0x57755A57` |
| Image start | `0x08010000` | `0x08010000` |
| First word (candidate initial SP) | `0x20000400` | `0x20000400` |
| Second word (candidate reset handler) | `0x080102FD` | `0x080102FD` |

The odd reset handler address is consistent with a Thumb entry address; its aligned instruction address would be `0x080102FC`. These facts suggest an ARM Cortex-M-style vector table but **do not confirm the MCU part number or row/column pins**.

Reproduce locally using the manufacturer-supplied file:

```sh
python3 tools/inspect_vectors.py /path/to/FAve40H_VIAL.uf2
```

Next: identify target silicon using physical markings or trustworthy bootloader metadata; only then perform architecture-specific disassembly and trace matrix scan GPIO accesses. **No new firmware should be flashed yet.**
