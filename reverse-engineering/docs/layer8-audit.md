# Manufacturer eight-layer firmware: fresh static audit

Date: 2026-10-21. **No device access, firmware modification, or flashing.**

This audit treats the older reconstruction as unverified background, not as its
source of truth. The target is the manufacturer's recent eight-layer firmware,
not our experimental six-layer source port. Instruction addresses were inspected
with Ghidra 12.1.4 using `ARM:LE:32:Cortex` and checked against original bytes.
The evidence checker is build-specific, not an automatic source recovery tool.

## Target and boundaries

| Field | Observed value |
|---|---|
| Input | `firmware/layer8/fave40h_f411_vial.uf2` |
| UF2 SHA-256 | `c64e08bfc3c5a74833408064425e7995178cf9e98d59ded807ddf3aaf5e10ee9` |
| Extracted payload SHA-256 | `eb3c2bc80ed7f4495f77781da6918b9b30738fcff6a3c59af9d583bc21e0809a` |
| UF2 / payload bytes | 120320 / 60160 (payload includes padding) |
| Mapped interval | `[0x08010000, 0x0801EB00)` |
| UF2 family field | `0x57755A57`; not independent MCU identification |
| Initial SP | `0x20000400` |
| Reset vector / instruction address | `0x080102FD` / `0x080102FC` (Thumb bit cleared) |
| Startup VTOR value / register literals | `0x08010000` / `0xE000ED08` |

The provided application UF2 does **not** contain the low-flash bootloader or
current settings sector. Reinstalling this UF2 is not a full-device backup.

## 1. Matrix: strong static evidence, not a continuity test

```c
#define MATRIX_ROW_PINS { A5, A6, A3, A4 }
#define MATRIX_COL_PINS { B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8 }
#define DIODE_DIRECTION ROW2COL
```

- Scan entry: `0x0801D108`. Column table: `0x0801DA00`; row table: `0x0801DA30`.
- `0x0801D114` loads the column table. The loop runs 12 columns.
- `0x0801D12A..0x0801D140` selects GPIO output mode and writes the column's
  bit to GPIO BSRR's high half (`GPIO + 0x1A`), driving that column low.
- `0x0801D178..0x0801D194` reads each row from GPIO IDR (`GPIO + 0x10`). A low
  input sets the pressed bit. The inner loop reads four rows.
- The selected column is subsequently released through `0x080142B2`, which
  configures input/pullup (mode constant `0x20` passed to the GPIO helper).
- Initialization `0x08018A2A..0x08018A56` uses the same column table and the
  same four ordered row pins. The checker requires init/scan agreement.

This independently agrees with the earlier notes, but does not establish the
physical MCU marking, electrical diode orientation by measurement, or RGB pins.
The diode-direction name is the QMK convention for this scan behavior.

## 2. Clock: register writes verified, oscillator inferred

RCC base `0x40023800` is loaded from `0x0801AB10`. HSE enable/ready polling
precedes PLL configuration. Actual stores are visible at:

| Instruction | Register | Value |
|---|---|---|
| `0x0801AA94..96` | RCC PLLCFGR (+4) | `0x04413010` |
| `0x0801AAB0..B2` | RCC CFGR (+8) | `0x38881000` |

PLLSRC=HSE, M=16, N=192, P=4, Q=4. This gives both SYSCLK and the PLLQ output
at three times HSE. **If the USB FS clock is correctly 48 MHz, HSE is 16 MHz
and SYSCLK is 48 MHz.** This is not a measurement of the crystal.
The file also contains a 48,000,000 constant at `0x08013824`.

The clock routine compares debug/CPU IDs with `0x20006411` and `0x410FC241` for
one flash-latency branch. These are code expectations, not observed chip values.
`f411` in the supplied filename is supporting context only. Physical MCU and
flash/RAM capacity remain unverified.

## 3. USB: recoverable configuration

The device-descriptor response selects `0x0801E42A` through the literal load at
`0x08019F02`; it is not merely an unreferenced byte-pattern match.
The configuration response selects `0x0801E3CF` (91 bytes).

- VID:PID: **`5123:A02D`**; USB device version `0x0002`.
- Manufacturer: `LJTuring`; product: `Fave40H`.
- String descriptors are recovered through the indexed table used by the
  descriptor handler, rather than guessed from arbitrary printable text.
- Initial GPIOA configuration selected by early init sets PA11 and PA12 to
  alternate-function mode, AF10, consistent with STM32 USB OTG FS.

| Interface | Descriptor class/subclass/protocol | Interrupt endpoints |
|---|---|---|
| 0 | HID / boot / keyboard | `0x81`, 8 bytes |
| 1 | HID / none / none | `0x82` IN + `0x02` OUT, 32 bytes |
| 2 | HID / none / none | `0x83` IN, 32 bytes |

All endpoint intervals are 1 ms at full speed. Interface 1 is consistent with
the raw-HID command transport; the complete HID report semantics and USB driver
initialization still need validation. No actual USB enumeration test was run.

The embedded XZ Vial definition at `0x0801DB94` decodes successfully: matrix
4x12, lighting `vialrgb`, 22 custom-keycode descriptions. Descriptions alone do
not prove the behavior or pin assignment of each vendor RGB/custom function.

## 4. Layers and settings

The layer-count response contains `MOVS r3,#8` at `0x0801958A`. The keycode
setter `0x0801386A` bounds layer <=7, row <=3, col <=11 and addresses keycodes
at `0x29 + layer*96 + row*24 + col*2`. Buffer handling also bounds offsets to
`0x300` (768 bytes). Thus eight layers are implemented in addressing code, not
merely listed in the user's JSON backup.

| Observation | Original Vial | Recent eight-layer Vial |
|---|---:|---:|
| Layer count | 4 | 8 |
| Keymap bytes | 384 | 768 |
| Keymap logical start | `0x29` | `0x29` |
| Logical EEPROM buffer | 4096 | 4096 |
| Wear-leveling backing budget | 8192 | 8192 |
| First flash sector | 3 | 3 |
| Macro logical start | `0x471` | `0x5F1` |
| Macro capacity | 2959 | 2575 |

Original UF2 SHA-256:
`d5e680fa2507534b63b316a3e67a5d7457af4bdfa65189f464d4e1b029692431`.
Original evidence: protocol case 0x11, `MOVS r3,#4` at `0x080198BA`, keycode
setter `0x08014548`, buffer bounds `0x180`, macro bounds `0xB8F` and base
`0x471`. The original and recent payload sizes are 61952 and 60160 bytes;
this must **not** be treated as a one-byte patch of otherwise identical code.

Recent storage witnesses: backing comparison `0x08018630`, sector-3 selection
`0x08018642`, and logical-copy limit `0x08018694`. Sector helper routines use
8-byte (offset,size) records. All four represented flash geometries describe
sector 3 at offset `0xC000`, length `0x4000`, base `0x08000000`:
**`[0x0800C000, 0x08010000)`**. Multiple geometry descriptors do not identify
actual physical flash capacity.

Added keymap bytes exactly equal the lost macro capacity (384 bytes). This
supports keeping the same overall logical settings budget. It does **not**
prove old/new settings compatibility or a safe migration policy.

## 5. Bootloader entry: request mechanism found, recovery not proven

At `0x08018ACE` the application writes **`0xF01669EF` to RAM `0x2000FFFC`**,
then calls `0x0801A9B8`. That routine executes barriers and writes SCB AIRCR
with `0x05FA0004`, preserving priority-group bits, to request a system reset.
The raw-HID command switch's bootloader command branches into this path after
its permission check and response/delay. A startup key path also reaches it.

This establishes what the **application requests**. The receiving bootloader
is outside this UF2, so its handling of the marker, USB recovery mode, physical
entry gesture, protection, and full backup/restore procedure are **not verified**.
Do not label the bootloader as a particular vendor implementation from the magic
value alone. Do not mass-erase or flash a reconstructed application yet.

## Reproduce without touching hardware

From the repository root:

```sh
python3 reverse-engineering/tools/audit_layer8.py \
  firmware/layer8/fave40h_f411_vial.uf2
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_layer8_audit.py -v
```

The checker rejects unknown firmware identities, validates instruction witnesses,
compares initialization/scan tables, parses referenced USB descriptors, and
decodes the embedded Vial definition. It writes only JSON to stdout. Tests
validate byte evidence and malformed-input rejection, not physical operation.

To reproduce the Ghidra instruction inspection on macOS/Homebrew:

```sh
work=$(mktemp -d /tmp/fave40h-layer8.XXXXXX)
python3 reverse-engineering/tools/extract_uf2_bin.py \
  firmware/layer8/fave40h_f411_vial.uf2 "$work/layer8.bin"
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  "$work" layer8-audit -import "$work/layer8.bin" \
  -loader BinaryLoader -loader-baseAddr 0x08010000 \
  -processor ARM:LE:32:Cortex -cspec default \
  -analysisTimeoutPerFile 120 -max-cpu 2 \
  -scriptPath "$PWD/reverse-engineering/tools" -postScript AuditLayer8.java
```

Use the strict checker first; the older extraction helper alone is not a full
UF2 admission validator. Ghidra's decompiler can merge unrelated functions or
misinterpret vector-table data: follow instruction addresses, references, and
register data flow, not inferred names or C pseudocode alone.

## Next gates before an experimental firmware build/flash

1. Confirm MCU package marking and oscillator on the PCB; establish independent,
   repeatable bootloader entry and recovery without relying on new firmware.
2. Review the existing experimental source against the fresh evidence. Recover
   the remaining board/RGB setup and complete USB initialization. Preserve the
   bootloader and define storage-layout/version migration deliberately.
3. Build and inspect address ranges first. Only after recovery is proven should
   an explicitly approved minimal USB/key-scan hardware test be considered.

No source-port correctness or ready-to-flash image is claimed by this audit.

## Interpretation references

- [Vial-QMK VIA command handling](https://github.com/vial-kb/vial-qmk/blob/vial/quantum/via.c)
- [ChibiOS GPIOv2 mode definitions](https://github.com/qmk/ChibiOS/blob/8bd61b804303f1614d574546c2dd735eeabb09f5/os/hal/ports/STM32/LLD/GPIOv2/hal_pal_lld.h)
- [ChibiOS STM32F4 clock initialization](https://github.com/qmk/ChibiOS/blob/8bd61b804303f1614d574546c2dd735eeabb09f5/os/hal/ports/STM32/STM32F4xx/hal_lld.c)
- [ST STM32F411 reference manual (RM0383)](https://www.st.com/resource/en/reference_manual/DM00119316-.pdf)

These explain conventions and register meanings; they do not identify the exact
manufacturer source revision or replace the local binary evidence.
