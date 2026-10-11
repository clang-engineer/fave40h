# Analysis correction — resolved by actual startup disassembly

The previous version of this page incorrectly called the `0x484D` halfwords at VIA `0x08015314` and Vial `0x0801B038` likely string-data false positives. **That conclusion is retracted.** Printable-looking bytes are not sufficient to classify code as a string.

The reset vector branches to `0x080101E0`. The unconditional startup BL at `0x08010248` targets VIA `0x08015310` or Vial `0x0801B034`. In each function, the instruction four bytes after entry is a real Thumb LDR loading GPIOA's base from a literal pool. Subsequent instructions reset/enable GPIO clocks and call a port-initialization helper.

The GPIOB locations VIA `0x080194E6` and Vial `0x08013946` are also instructions in a peripheral-initialization routine. They still do not, by themselves, establish matrix pins. Do not equate a GPIO reference with a matrix connection.

Matrix pins were independently recovered from the scan loop's ordered row/column tables and register operations, then checked against the initialization code in both builds. See [matrix-recovery.md](matrix-recovery.md), the authoritative current result.

The early halfword-pattern scanner remains only a candidate finder; it is not a control-flow-aware disassembler. No new firmware has been flashed, and hardware operation of a reconstructed port remains unverified.
