# Confirmed Thumb literal references: interpretation limits

A read-only scan of the supplied FAVE40H VIA and Vial UF2 firmware found PC-relative Thumb `LDR` references to STM32F4 peripheral bases. Example:

| Register | VIA instruction | Vial instruction |
|---|---|---|
| GPIOA `0x40020000` | `0x08015314` | `0x0801B038` |
| GPIOB `0x40020400` | `0x080194E6` | `0x08013946` |
| RCC `0x40023800` | `0x08015310` | `0x0801B034` |

The GPIOA/RCC references occur together in a similar instruction sequence in both firmware variants, suggesting a shared initialization routine. **This is not evidence that GPIOA is a matrix row or column port.** GPIOB references likewise need function-level classification.

A raw 16-bit Thumb LDR-pattern scan is not a complete disassembler: instruction boundaries, control-flow reachability, and Thumb-2 instructions need verification. Do not infer GPIO pins from these offsets.

Next concrete step: load the UF2 payload as a raw ARM Cortex-M Thumb image at `0x08010000` into Ghidra, identify the reset handler, and follow cross-references to the RCC/GPIO literal pools. Verify peripheral register offsets and bit masks for key scan versus LED/USB initialization. The key matrix GPIO map remains unknown.

No new firmware image has been built or flashed.
