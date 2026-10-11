# FAVE40H QMK / Vial reconstruction

Unofficial reverse-engineering project for the LJTuring FAVE40H hot-swap keyboard. **Goal:** replace the shipped four Vial layers with six editable layers and maintain a modifiable source tree.

> [!WARNING]
> This is an **incomplete, non-buildable scaffold**, not a working firmware port. Do not flash it. Keep the original manufacturer UF2 as a recovery reference.

## Evidence

- User-supplied FAVE40H VIA/Vial UF2 firmware files (not redistributed here).
- Vendor VIA definition identifies `Fave40H_LJTuring`, USB VID `0x5123`, PID `0xA02D`, logical matrix `4 × 12`, and `1U Shift` layout option.
- UF2 metadata indicates a target address of `0x08010000`; the MCU and bootloader have **not** been verified.

## Source layout

- `keyboards/fave40h/keymaps/vial/` — six-layer setting and Vial/QMK placeholders.
- `docs/hardware.md` — confirmed hardware information and open questions.
- `docs/roadmap.md` — work required before building or flashing.

## Outstanding blockers

Identify MCU/bootloader, GPIO row/column mapping, diode direction, LED connections, storage layout, Vial UID, and custom keycode behavior. The vendor JSON describes UI layout and keycode labels; it does not provide these hardware connections or implementations.

## Reference

- [Vial-QMK](https://github.com/vial-kb/vial-qmk)
- [QMK documentation](https://docs.qmk.fm/)

No original proprietary firmware binaries are included in this public repository.
