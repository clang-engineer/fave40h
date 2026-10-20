# Testing status

## Actual ARM compilation

Both `fave40h:default` and `fave40h:vial` passed compilation/linking and ELF address/keymap checks in [run 38119072326](https://github.com/clang-engineer/fave40h-qmk/actions/runs/38119072326). See [inspection-build.md](inspection-build.md) for metrics and limitations. The build uses RAM-only EEPROM emulation, not working persistent storage.

## Host-side tests

- Original matrix-recovery suite: 15 tests, with 3 requiring the unpublished stock ZIP.
- New source geometry and C-grammar suite: 13 tests; these are not QMK runtime tests.
- New clock/storage evidence suite: 9 tests, with 4 requiring the stock ZIP.

The combined new source/platform suites were executed locally with the owner's original ZIP: **22 passed, zero skipped**. The earlier matrix suite is not included in that local count. The first ARM build run discovered 28 tests and passed 25 with 3 skips; it predates the additional platform suite. With all current suites, CI discovers 37 tests, of which 7 require the stock ZIP; consult the completed run for actual outcomes.

```sh
python3 -m unittest discover -s tests -v
FAVE40H_STOCK_ZIP='/path/to/fave40h (2).zip' python3 -m unittest discover -s tests -v
```

## Not validated

Physical keys, USB enumeration, Vial GUI behavior, reboot/recovery, retained settings after power loss, and RGB/vendor custom functions have not been tested on a keyboard. Neither a green workflow nor a readable manufacturer UF2 proves these properties. Do not flash the inspection target.
