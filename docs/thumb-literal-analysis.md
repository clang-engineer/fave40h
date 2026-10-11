# Thumb literal reference analysis

The owner-supplied FAVE40H manufacturer ZIP was inspected locally with `tools/trace_thumb_literals.py`.

The script decodes 16-bit Thumb `LDR Rt, [PC, #imm]` patterns and resolves PC-relative literal-pool references. It is **not full disassembly**; matches may be data or otherwise not reachable code.

| Base register | VIA instruction address | Vial instruction address |
|---|---|---|
| GPIOA `0x40020000` | `0x08015314` | `0x0801B038` |
| GPIOB `0x40020400` | `0x080194E6` | `0x08013946` |
| RCC `0x40023800` | multiple references | multiple references |

Run:
```sh
python3 tools/trace_thumb_literals.py '/path/to/fave40h (2).zip'
```

Next, inspect the surrounding Thumb instructions and data flow, including GPIO register offsets and RCC enables, to distinguish key scanning from LED, USB or other initialization. No verified matrix pins or buildable keyboard definition exist yet. Do not flash a reconstructed image.
