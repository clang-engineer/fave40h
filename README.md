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




---

FAve40H RGB LED 설정법
VIA , VIAL펌웨어 모두 아래 토글키를 사용하여 RGB LED설정을 변경해주어야 합니다.

VIA도 아래 토글키를 사용할 수 있습니다.

VIAL은 아래 캡스락 RGB LED설정(인덱스 기능 및 색상 설정)을 할 수 없습니다.


Fave40H rgb 토글키
FN2(우측 스페이스봐)+좌쉽 >>스위치 rgb온/온오프
FN2(우측 스페이스바)+좌컨 >>언더글로우 rgb온/오프
FN2(우측 스페이스바)+캡스락 >> 전체 rgb led 온/오프

RGB 모드 변경은 레이어 상에 RGB MODE+ - 를 지정하여 변경하시면 됩니다.


캡스락 RGB LED 설정
그리고 캡스락 RGB led 관련한 조정은,Web VIA에서 구성메뉴의 led controll 탭에 들어가시면 보실 수 있습니다. 

기능 설명은 제가 올린 캡쳐화면을 참고하여 설명드리겠습니다.

Switch - 꺼두면 캡스락 led를 따로 설정하지 않고 쓰겠다는 말이고 켜두면 개별 제어를 하겠다는 말입니다.

Index - 여기서 지정하는 키의 스위치 led가 캡스락을 눌렀을때 지정한 색상으로 변하게 됩니다. 예를 들어 ESC키를 설정하면 캡스락을 눌렀을 때 ESC의 led가 변경되게 됩니다. 

색상 - 말그대로 색상


감사합니다. 



