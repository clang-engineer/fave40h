# STM32F4 peripheral literal scan

Read-only analysis of the owner-supplied FAVE40H manufacturer ZIP. Each UF2 block has 256 payload bytes; image base is `0x08010000`.

| Register base | VIA firmware occurrences | Vial firmware occurrences |
|---|---|---|
| GPIOA `0x40020000` | `0x0801544C` | `0x0801B170` |
| GPIOB `0x40020400` | `0x0801961C` | `0x08013A7C` |
| RCC `0x40023800` | `0x08015444`, `0x080182A0`, `0x080186BC`, `0x08019624` | `0x08013A84`, `0x08018660`, `0x08018A84`, `0x0801B168` |

No exact 32-bit literal occurrences of GPIOC/GPIOD/GPIOE base addresses were found by this scan. This **does not exclude** their use; addresses can be computed dynamically or referenced through offsets.

## Reproduce

```sh
python3 tools/scan_gpio_literals.py '/path/to/fave40h (2).zip'
```

## Interpretation

These are raw little-endian byte-pattern matches, **not proven code references**. The next step is to disassemble Thumb instructions around literal-pool references and inspect register read/write behavior, then determine whether those routines implement key matrix scanning, RGB, or other peripherals. No GPIO pin assignment or safe-to-flash image has been established.
