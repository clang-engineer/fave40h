# Analysis correction

Earlier reports of GPIO cross-references are not verified. Checking the manufacturer firmware bytes at 0x08015314 and 0x0801B038 found the halfword 0x484D inside an ASCII-like data sequence. This value resembles a Thumb LDR instruction, but is likely a data false positive. The same concern applies to 0x080194E6 and 0x08013946.

Do not use these addresses as evidence of GPIO pin assignments. A control-flow-aware disassembly from the reset vector is required before identifying actual matrix scanning routines. No row or column GPIO mapping has been established; the project remains non-buildable and unsafe to flash.
