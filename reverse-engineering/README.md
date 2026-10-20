# FAVE40H QMK / Vial reconstruction

Unofficial source reconstruction for the LJTuring FAVE40H hot-swap keyboard. Goal: **six editable Vial layers** and a maintainable source port.

> **ARM compilation passed; hardware use is NOT validated.** This is a compile/inspection target, not ready-to-flash replacement firmware. Settings use RAM only, bootloader callbacks are unimplemented, and RGB/vendor extensions are absent. Keep the original firmware and do not flash this target.

## Current result

The `default` and `vial` targets both compiled and linked successfully in [GitHub Actions](https://github.com/clang-engineer/fave40h-qmk/actions/runs/38119072326). Their ELF address-range checks and 576-byte (6 x 4 x 12 x 2) keymap checks passed. The Vial BIN was 38400 bytes. This is actual QMK/ARM compilation, not just a Python or C syntax test.

The source now includes a 42-key layout, six complete example keymaps, a Vial definition, clock settings, a guarded build profile, and a custom linker map. Read [inspection build](docs/inspection-build.md) for the exact revision, results, commands, and restrictions.

## Reconstructed hardware evidence

From instruction-level inspection of **both** original VIA and Vial images:

```c
#define MATRIX_ROW_PINS { A5, A6, A3, A4 }
#define MATRIX_COL_PINS { B12, B13, B14, B15, A8, B6, B5, B4, B3, A15, B7, B8 }
#define DIODE_DIRECTION ROW2COL
```

[Matrix recovery](docs/matrix-recovery.md) explains the scan and initialization cross-checks. [Platform recovery](docs/platform-recovery.md) records the clock settings and stock flash-backed storage. STM32F411 and 16 MHz HSE are evidence-based build assumptions, not measured chip/oscillator identity.

In particular, stock Vial uses a 4096-byte logical settings buffer with 8192-byte backing inside flash sector 3 at `0x0800C000`. The new inspection source deliberately does not use that persistent backend. Raw keymap growth is only 192 bytes, but compatibility of the complete old/new settings formats still requires work.

## Reproduce

```sh
python3 tools/recover_matrix.py '/path/to/fave40h (2).zip'
python3 tools/recover_platform.py '/path/to/fave40h (2).zip'
FAVE40H_STOCK_ZIP='/path/to/fave40h (2).zip' python3 -m unittest discover -s tests -v
```

The original ZIP is not in this public repository; stock-dependent tests skip when it is absent. Compile commands and the automated ARM build are in [inspection-build.md](docs/inspection-build.md). **Compilation is not permission or a recommendation to flash.**

## Remaining work

Verify physical silicon and reliable recovery, reproduce board/USB initialization, implement persistent storage and migration without erasing bootloader/settings, then validate six-layer behavior on the actual keyboard. Vendor RGB/custom functions are a separate compatibility task. The source is a new implementation, not an exact recovery of the manufacturer's original code.

Older investigation notes are historical; follow the current reports above. Manufacturer UF2/BIN images and user-specific settings are not redistributed.





