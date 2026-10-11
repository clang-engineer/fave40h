# Testing

## Verified locally against manufacturer ZIP

The original manufacturer ZIP provided by the keyboard owner was tested read-only. Checks passed for the 4×12 VIA matrix and for the 187-block VIA / 242-block Vial UF2 images, their UF2 headers, sequential addresses, and candidate ARM vectors.

Run the same validation locally:

```sh
python3 tools/test_firmware.py '/path/to/fave40h (2).zip'
```

The manufacturer's UF2 files are not included in this repository. Do not publish or flash any modified image on the basis of these checks alone.

## Not yet tested

- QMK compilation (keyboard definition and matrix pin mappings are incomplete)
- Six dynamic Vial layers and EEPROM capacity
- Bootloader and safe recovery process
- Physical key input, lighting, macros and custom keycodes

**Status: reconstruction scaffold, not working firmware.**
