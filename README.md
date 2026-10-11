# FAVE40H QMK / Vial reconstruction

Unofficial reconstruction for the LJTuring FAVE40H hot-swap keyboard. Goal: a maintainable source port with **six editable Vial layers** instead of four.

> **Not a working firmware port yet.** No reconstructed UF2 has been built or tested on a keyboard. Keep the original manufacturer firmware; do not flash an incomplete port.

## Current result

The matrix pin order and scan direction have now been recovered from **both** stock VIA and Vial binaries, using instruction-level inspection and cross-checking initialization against the scan loop:

```c
#define MATRIX_ROW_PINS { A5, A6, A3, A4 }
#define MATRIX_COL_PINS { B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8 }
#define DIODE_DIRECTION ROW2COL
```

This configuration is in `keyboards/fave40h/config.h`. It is based on static firmware evidence, not electrical measurements or a successful firmware build.

Read [matrix recovery](docs/matrix-recovery.md) for the code paths, addresses, limitations, and primary-source references; [generated evidence](docs/matrix-evidence.json) contains the exact firmware hashes. Older investigation notes are historical; see the updated [analysis correction](docs/analysis-correction.md).

## Reproduce

```sh
python3 tools/recover_matrix.py '/path/to/fave40h (2).zip'
FAVE40H_STOCK_ZIP='/path/to/fave40h (2).zip' python3 -m unittest discover -s tests -v
```

**15 host-side tests passed locally** with the owner's original ZIP. Without that ZIP, the three manufacturer-dependent tests are skipped. The tool can also extract the embedded Vial definition locally with `--vial-json output.json`.

## Remaining work

Verify the exact MCU/clock/bootloader/linker target and persistent-storage allocation, implement the default keymap and required custom/RGB functions, then compile and inspect the result before any device test. The six-layer setting exists, but the project is still not buildable as a complete QMK keyboard.

Manufacturer UF2/BIN images are not redistributed. The public tree contains reconstructed settings, analysis tools, tests, and documentation only.
