# Stock clock, RAM and storage reconstruction

These are static observations of the owner's two original FAVE40H UF2 images, not measurements of a connected keyboard. `tools/recover_platform.py` rejects unknown SHA-256 identities, checks selected instruction boundaries/calls, decodes their operands, and inspects the referenced flash tables. It is a build-specific evidence checker, not an automatic decompiler.

## Clock and RAM

Both stock images write `0x04413010` to RCC PLLCFGR and `0x38881000` to CFGR, later selecting PLL. The PLL fields decode to HSE source, M=16, N=192, P=4, Q=4. Combined with the stock timer's 48,000,000 Hz constant and the USB clock requirement, this is consistent with **16 MHz HSE and 48 MHz system clock**. The oscillator has not been measured.

Both software heap-limit constants are `0x20020000`, corresponding to a 128 KiB RAM address window starting at `0x20000000`. This is a software configuration, not a capacity test. **STM32F411 is the inspection build candidate, not a verified package/part number.** Shared F4 code is not unique silicon identification.

| Inspected evidence | VIA address | Vial address |
|---|---|---|
| PLL literal load, followed by store to RCC +4 | `0x080153C8` | `0x0801B0EC` |
| CFGR literal load, followed by store to RCC +8 | `0x080153E4` | `0x0801B108` |
| Software heap-limit literal load | `0x08018176` | `0x08018536` |
| Timer-clock literal load | `0x080195A0` | `0x08013A00` |

## Persistent storage in the stock images

| Setting | VIA | Vial |
|---|---:|---:|
| Logical EEPROM-emulation buffer | 1024 B | 4096 B |
| Wear-leveling backing size | 2048 B | 8192 B |
| First flash sector index | 3 | 3 |
| Sector start | `0x0800C000` | `0x0800C000` |
| Whole erase sector size | 16384 B | 16384 B |
| Sector end, exclusive | `0x08010000` | `0x08010000` |

The code requests sector 3, calls the sector-offset helper, and reads the offset/size table. Its logical-buffer read loop ends at 1024/4096 bytes; the backing allocation loop checks 2048/8192 bytes. This is not inferred just from strings naming `wear_leveling`.

| Instruction/table | VIA | Vial |
|---|---|---|
| Backing-size CMP.W | `0x0801834A` | `0x0801870A` |
| MOVS R1, #3 before offset helper | `0x0801835C` | `0x0801871C` |
| Logical-buffer loop CMP.W | `0x080183B2` | `0x08018772` |
| Sector-offset helper | `0x08013B46` | `0x0801B49C` |
| Sector-size helper | `0x08013B60` | `0x0801B4B6` |
| Flash descriptor table | `0x0801AFE8` | `0x0801DE24` |

Each image includes four flash geometry descriptors: 128, 256, 384 and 512 KiB. **Their presence does not tell us which physical capacity the board has.** Sector 3 has the same offset and size in all four descriptors.

An important correction to the earlier rough memory model: the first 64 KiB is **not proven to be entirely bootloader code**. The stock settings sector lies within that region, immediately below the application's `0x08010000` start. Reflashing the supplied application UF2 alone is not a backup of the user's current settings or of the installed bootloader. Do not mass-erase or initialize this sector based on the evidence report.

## Implications for six layers

The raw 4x12 keymap grows from 384 to 576 bytes (+192). This does not prove compatibility with the vendor's complete settings layout. Metadata, macros, combos, tap dance, key overrides, and changes between QMK versions must also be accounted for. Migrating an existing four-layer EEPROM layout into a new six-layer implementation has not been implemented.

The new source therefore uses **4096-byte transient RAM storage** for compile/inspection work, with no persistent EEPROM backend selected. These writes disappear on reset/power loss. It is not the finished everyday-use firmware the project aims to produce.

## Reproduce

```sh
python3 tools/recover_platform.py '/path/to/fave40h (2).zip'
FAVE40H_STOCK_ZIP='/path/to/fave40h (2).zip' python3 -m unittest discover -s tests -p 'test_platform_recovery.py' -v
```

Local result on the original ZIP: all **9 platform tests passed**, including both stock images and modified-input rejection. The combined new source/platform suites passed **22 tests** locally. These counts do not include the older matrix-recovery suite. Generated values are in [platform-evidence.json](platform-evidence.json).

## Primary-source interpretation references

- [ChibiOS F4 clock initialization at the build-pinned revision](https://github.com/qmk/ChibiOS/blob/8bd61b804303f1614d574546c2dd735eeabb09f5/os/hal/ports/STM32/STM32F4xx/hal_lld.c): PLLCFGR composition and HSE/PLL startup sequence.
- [QMK EEPROM driver documentation](https://docs.qmk.fm/drivers/eeprom): transient storage is RAM-only; wear leveling is a separate persistent backend.
- [Vial porting documentation](https://get.vial.today/docs/porting-to-vial.html): a device definition and supported firmware build are required, not only a GUI layout file.

See [inspection-build.md](inspection-build.md) for the successfully compiled source and its restrictions.
