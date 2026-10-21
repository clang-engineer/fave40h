# Original FAve40H Vial source reconstruction

**Target: `firmware/origin/FAve40H_VIAL.uf2`, not the recent eight-layer build.**
The goal is to reconstruct the original firmware's implementation on top of the
appropriate public QMK/Vial code, without adding layers or substituting the old
six-layer experimental port. Exact manufacturer filenames, symbols, comments,
source revision and byte-identical compilation have not been recovered.

## Status: partial source/data recovery, NOT a firmware build

Recovered C code currently compiles and is exercised **on the host computer**.
This directory has no complete QMK board target, USB/EEPROM implementation,
flashable artifact, or proven hardware behavior. Nothing was flashed.

| Artifact | What is actually recovered |
|---|---|
| `factory_defaults.c/.h` | Original factory keymap values; keymap-only reset semantics; bounded dynamic-keymap EEPROM address calculation |
| `board_defaults.h` | Exact GPIO A/B/C/D/E/H register initialization data and PLL/CFGR constants; no MMIO writes |
| `vendor_parameters.c/.h` | Arguments for 14 custom space-cadet tap/hold keycodes, decoded from original Thumb instructions; NOT the timing state machine |
| `vial-definition.json` | Embedded manufacturer Vial definition decoded from the original image, including 22 custom-key descriptions |
| `evidence.json` | Exact input/payload hashes, source addresses, instruction witnesses, recovered data, and explicit uncertainty flags |

The seven generated files are deterministic outputs of
[`recover_original_vial.py`](../tools/recover_original_vial.py). Their C identifiers
and file organization are ours, not recovered manufacturer names. This is more
than dumping decompiler text, but much less than a finished replacement firmware.

## Key findings from the ORIGINAL image

- UF2 SHA-256:
  `d5e680fa2507534b63b316a3e67a5d7457af4bdfa65189f464d4e1b029692431`.
  Payload SHA-256:
  `9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4`.
- Dynamic keymaps have **four layers**, but the factory table at `0x0801E284`
  contains only **three layers (288 bytes)**. Reset code at `0x08015824`
  reads these for layers 0..2 and explicitly substitutes `KC_TRNS` for every
  layer-3 matrix cell. Bytes after the table are not a fourth factory keymap.
- Factory base has Caps Lock at matrix `[1][0]`, split spaces `LT(1, Space)`
  and `LT(2, Space)`. This is not the user's customized JSON backup.
- Rows: **A5, A6, A3, A4**. Columns: **B12, B13, B14, B15, A8, B6, B5,
  B4, B3, A15, B7, B8**. Init and active-low column-selection/row-read scan
  code independently agree on the ordered pin lists (`ROW2COL`).
- Early-init register writer `0x0801AA7E` establishes the packed GPIO field
  order. The six groups start at `0x0801EA14` and initialize A/B/C/D/E/H.
- PLLCFGR `0x04413010` and CFGR `0x38881000` are actually written by the
  original early init at `0x0801B034`. HSE=16 MHz and SYSCLK=48 MHz are
  inferred for a correct 48 MHz USB clock; they are not physical measurements.
- USB VID:PID **5123:A02D**, device version **0x0100**, manufacturer
  `LJTuring`, product `Fave40H`, serial `vial:f64c2b3c`.
  The serial suffix is **not** a verified Git revision. Do not guess a source
  revision from it; the exact upstream/manufacturer version remains unknown.
- Original logical settings buffer is 4096 bytes; backing budget is 8192.
  The recovered layout is shown below. Existing settings compatibility with a
  reconstructed build is not established.
- A boot-entry path writes `0xF01669EF` to RAM `0x2000FFFC` and requests an
  SCB system reset through `0x0801B010`. The supplied application begins at
  `0x08010000` and contains neither the receiving low-flash bootloader nor a
  backup of current device settings. Recovery behavior remains unproven.

### Original logical settings layout

These are **logical EEPROM offsets**, not absolute flash addresses.

| Region | Start | End exclusive | Record count/size |
|---|---:|---:|---|
| Dynamic keymap | `0x29` | `0x1A9` | 4 x 4 x 12 x 2 bytes |
| QMK settings | `0x1A9` | `0x1D1` | 40 bytes |
| Tap dance | `0x1D1` | `0x271` | 16 x 10 bytes |
| Combo | `0x271` | `0x311` | 16 x 10 bytes |
| Key override | `0x311` | `0x3B1` | 16 x 10 bytes |
| Alternate repeat | `0x3B1` | `0x471` | 32 x 6 bytes |
| Macro buffer | `0x471` | `0x1000` | 2959 bytes |

The initial `0x00..0x28` fields have not been completely decoded. This table is
not a migration implementation and must not be used to erase device flash.

### Custom key recovery boundary

The original dispatcher has custom codes `0x7E00..0x7E15`. Cases
`0x7E01..0x7E0E` pass explicit hold-modifier/tap-modifier/tap-key arguments to
shared helper `0x0801D4C8`. Those arguments are decoded and exported as C.
They cover modifier/braces, modifier/angle-brackets, Ctrl/Caps and Ctrl/Enter.
Upstream `perform_space_cadet` is a useful semantic match, not proof of the
exact original source revision or complete timing equivalence.

Backspace/Delete, settings clear/reboot, and switch/underglow RGB cases are
identified in the instruction stream but are **not yet exported as functional
handlers**. Their side effects and RGB driver's physical wiring need further
work. In particular the reboot function never returns: naively decompiling it
as returning makes settings-clear appear to fall through into an RGB toggle.
The Ghidra inspection script annotates the verified non-returning reset path
so that false control flow is not taken as source behavior.

The original factory keymap includes `0x7C00` (bootloader request). It is kept
as evidence in a data array, not advertised as safe to execute on a new port.

## Reproduce the recovered source/data

From the repository root:

```sh
python3 reverse-engineering/tools/recover_original_vial.py \
  firmware/origin/FAve40H_VIAL.uf2 --check reverse-engineering/original-vial
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_vial_recovery.py -v
```

For an independent NEW output directory, use `--export /path/to/new-directory`.
The tool refuses existing output directories, unknown images, the eight-layer
build, and the VIA build. It never writes to the firmware input.

Tests compile the portable C models with host `cc -std=c11 -Wall -Wextra
-Werror`, compare all 192 address calculations, the full 384-byte reset result,
and the 14 custom parameter sets. That is **not** ARM/QMK compilation or a
physical test. Generated-source consistency tests are not an independent proof
that all reverse-engineering interpretations are correct; instruction and
runtime cross-checks are still required.

### Reproduce original Ghidra inspection

After the Python checker accepts the original image:

```sh
work=$(mktemp -d /tmp/fave40h-original.XXXXXX)
python3 reverse-engineering/tools/extract_uf2_bin.py \
  firmware/origin/FAve40H_VIAL.uf2 "$work/original-vial.bin"
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  "$work" original-vial -import "$work/original-vial.bin" \
  -loader BinaryLoader -loader-baseAddr 0x08010000 \
  -processor ARM:LE:32:Cortex -cspec default \
  -analysisTimeoutPerFile 120 -max-cpu 2 \
  -scriptPath "$PWD/reverse-engineering/tools" \
  -postScript InspectOriginalVial.java > "$work/inspection.log" 2>&1
# Headless can exit zero despite a post-script exception: inspect both checks.
grep 'ORIGINAL_INSPECTION_COMPLETE' "$work/inspection.log"
! grep 'ERROR' "$work/inspection.log"
```

The script binds itself to the ORIGINAL payload hash, explicitly seeds known
instruction boundaries that raw-binary auto-analysis misses, annotates the
verified non-returning reset functions in the analysis database, and prints
instruction evidence and selected pseudocode. It does not alter executable
bytes. Decompiled names and prototypes are not original source names or ABIs.

## Remaining work toward the user's goal

1. **Recover vendor/RGB implementation**: physical LED data pin/driver, LED map,
   switch/underglow gating, Backspace/Delete behavior and full custom-key timing.
2. **Identify a compatible upstream base**: compare implementation and settings
   ABI against public QMK/Vial versions. The old inspection port's pinned commit
   is a candidate reference, not the recovered manufacturer revision.
3. **Assemble an original-four-layer QMK board target** preserving the recovered
   behavior, USB, memory map and settings layout; compile for ARM and inspect it.
4. **Validate hardware/recovery separately**: MCU marking, independent loader
   entry/backup, persistent-storage safety, then explicitly approved device tests.

Do not replace these gates with a successful host test or a decompiler result.
The eight-layer audit and the previous six-layer source remain separate work.

References for interpretation:
[QMK/Vial dynamic keymaps](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/dynamic_keymap.c),
[space-cadet implementation](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/process_keycode/process_space_cadet.c),
[keycode ranges](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/keycodes.h).
