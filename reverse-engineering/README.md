# FAVE40H QMK / Vial reconstruction

## Current goal: reconstruct the ORIGINAL Vial firmware

The target is **`firmware/origin/FAve40H_VIAL.uf2`**, not the manufacturer's newer eight-layer version. See [original-only recovered source/data and remaining work](original-vial/README.md). This is partial recovery, not a complete or flash-ready firmware.

Original-only recovery now includes the **PB10/TIM2 PWM-DMA RGB path**, 72-LED map (42 switch + 30 underglow), isolated vendor controls, shared vendor/built-in space-cadet state and reached-core interruption behavior, plus tap-delay selection/arithmetic, checked against 2,372 original-Thumb emulation cases with explicit clock/HID/scheduler, storage-read and initialization-entry boundaries. The earlier feature pipeline is not reconstructed as a whole. Host tests and freestanding ARM object compilation do **not** constitute a complete QMK firmware or hardware validation.

The original 40-byte QMK settings layout/prototype/reset shape matches the pinned reference profile in a [scoped ABI audit](original-vial/settings-abi-audit.json). Reproducing the original requires recorded build values, notably `TAP_CODE_DELAY=0` rather than that header's default 10; whole-EEPROM compatibility and exact source revision remain unproven.

A separate [serialized-record audit](original-vial/records-abi-audit.json) matches record sizes and logical intervals with counts **16/16/16/32**. The candidate's 4096-byte defaults use 32 for all four; leaving them unchanged would shift macro storage from `0x471` to `0x651`. Actual EEPROM persistence/migration and runtime record semantics remain unverified.

The [prefix audit](original-vial/prefix-abi-audit.json) derives the original `0x29` keymap base from the candidate's 37-byte core + 3-byte stamp + 1-byte layout profile. Original startup compares stamp `4B F4 29` (BUILD_ID low24 `0x29F44B`); changing it can enter initialization paths. Matching addresses alone does not justify retaining the stamp or reusing live settings. Initialization bodies and flash operations were not executed.

The original consolidated-cache load now has a RAM-only [snapshot model](original-vial/snapshot_model.h): 4096 bytes + little-endian FNV1a64 checkpoint, followed by the log at `0x1008`. A bad checksum clears cache RAM but proceeds to log playback; it does not by itself mean immediate flash erase. A separate [one-entry journal model](original-vial/journal_model.h) matches 111 header/copy/cursor/error cases. Complete replay, consolidation and physical flash/recovery remain unverified; lengths 6/7 and second reads beyond budget are explicitly unmodeled rather than normalized into a new rejection policy.

The [backing wrapper model](original-vial/backing_model.h) captures word complementation and driver intents without running a physical driver. Available ROM profiles agree on sector 3: configured backing uses `[0x0800C000,0x0800E000)`, but its erase sector extends to `0x08010000`. The remaining 8 KiB is not independently erasable; contents and physical capacity are unknown. RAM-only error checks do not prove bus-fault safety.

The separate [original-four-layer target seed](keyboards/fave40h_original/README.md) now carries original USB/matrix/layout metadata and the three compiled factory layers. A candidate introspection probe verifies all 192 four-layer reset cells, including the transparent fourth layer. Original GPIO/PLL/CFGR overrides now match a RAM-only initializer/clock-header probe. The target LED map matches all 264 original ROM bytes; the pinned PWM encoder matches 51 original frames under captured hardware APIs (no physical DMA/LED operation). Original IRQ50/TIM5 static witnesses resolve the TIM2 system-timer/PWM conflict. Thirteen bounded RGB group-word reset/load cases now bind target user hooks through actual candidate weak KB delegates and captured APIs; no physical EEPROM or complete reset/migration is executed. Original 15-LED chunk limits match the candidate helper for 256 inputs; target Caps/group-filter callbacks now match 25 original filters and 24 composed slices through extracted candidate indicator/RENDERING dispatch (controlled render/host/color inputs, not a complete animation engine). Six group-key commands match 48 original byte-control cases through the candidate module/KB prefix (controlled stage sentinels, not full core/HID execution; no invented EEPROM autosave). Shift-edge Backspace/Delete now matches 16 original cases with captured register/unregister intents (not real HID reports), retaining the original overlapping-Shift/release-reselection quirks. All 14 custom Space Cadet keys now reuse the unmodified candidate helper and shared built-in state; 324 original custom/standard/core-default/vendor-bypass cases match through selected KB/Space Cadet stages (controlled timer/term and modifier/tap APIs; intervening features omitted). A read-only RGB profile audit matches the 45-entry ROM catalog and reset fields against candidate source, finding mode15/speed128 versus candidate13/127; the initial proposal-only audit does not itself configure the target or identify hidden slot29's implementation. Press-only eight-slot RGB hit collection is now connected: 288 original Thumb cases (including original memcpy) match actual candidate switch-events/collector source at default optimization and-O2; KEYRELEASES is a failing negative control, not a target setting. Hidden mode29 now has an instruction-backed PixelFlow-shaped signature;1024 original interval cases match actual candidate nested interval/math source at-O0/-O2 (that interval-only probe does not execute colors). Another96 persistent mode29 calls match the entire candidate PixelFlow/RNG at a controlled HSV/RGB API boundary, including wait-before-init and wrap behavior. Actual scalar HSV conversion now matches9472 original cases and all256 CIE-table bytes; the older mode29 trace probe preserves diagnostic HSV, while a separate96-call comparison now executes441 actual original HSV conversions and matches candidate effect color bytes at RGB API boundaries. Factory mode15 also matches1260 actual dispatch/runner/Chevron/HSV cases at RGB API boundaries; the generator/target now bind the matching43 optional effects and factory mode15/speed128. Actual target config/post-config compilation reproduces all180 catalog bytes and reset prefix3d00ffff80ff with256 padding canaries; framebuffer/reactive/press support is derived, not forced. A separate288-sequence/1440-chunk mode15 RAM composition now matches persistent GRB bytes before/after Caps and group filtering at-O0/-O2, using actual original RAM setters and an explicit native effect-to-staging API join (the candidate RENDERING caller retains a completion-only stub, not full renderer execution). Remaining effect bodies and the full RGB runtime are still unverified. **The target build remains blocked** until RGB, vendor/reset and Vial security integration are complete; a keymap-only ARM object is not linked firmware. The historical six-layer target is not reused.

The [eight-layer audit](docs/layer8-audit.md) is separate comparison material only.

## Historical six-layer inspection port — not the current restoration target

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





