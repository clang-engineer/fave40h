# ARM Thumb disassembly — verified local experiment

The owner-provided FAVE40H VIA UF2 was extracted to a contiguous BIN at `0x08010000`, wrapped in an ELF section using Clang's ARM assembler and LLD, and disassembled with LLVM objdump. This is **actual instruction decoding**, unlike previous byte-pattern scanning. Reachability of later code is still unproven.

## Observed reset sequence (VIA image)

The vector table's reset entry is `0x080102FD` (Thumb bit set). Disassembly at `0x080102FC` yields:

```asm
080102fc: e770        b 0x080101e0
```

At `0x080101E0`, the decoded startup includes:

```asm
080101e0: b672         cpsid i
080101e2: 4837         ldr r0, [pc, #0xdc]
080101e4: f380 8808    msr msp, r0
080101e8: 4836         ldr r0, [pc, #0xd8]
080101ea: f380 8809    msr psp, r0
08010244: f004 fe86    bl 0x08014f54
08010248: f005 f862    bl 0x08015310
```

This sequence establishes a real starting point for control-flow tracing, and contains floating-point/system register initialization consistent with a Cortex-M4F-class target. It does not determine the exact MCU part.

## Reproduce (Clang, LLD, llvm-objdump)

```sh
python3 tools/extract_uf2_bin.py /path/to/FAve40h_VIA.uf2 via.bin
printf '.syntax unified\n.thumb\n.section .text.firmware,"ax",%%progbits\n.global firmware_start\nfirmware_start:\n.incbin "via.bin"\n' > firmware.s
printf 'SECTIONS { . = 0x08010000; .text : { *(.text.firmware) } }\n' > link.ld
clang -target armv7em-none-eabi -c firmware.s -o firmware.o
ld.lld -T link.ld firmware.o -o firmware.elf
llvm-objdump -d --start-address=0x080101e0 --stop-address=0x08010250 firmware.elf
```

Use this only in a local directory containing your manufacturer-provided image. **Do not flash the generated ELF.** The wrapper is for inspection, not a functional firmware build.

## Next

Trace the two startup calls and find actual GPIO register writes on reachable paths; separate GPIO initialization for key scanning from RGB and other peripherals. GPIO pin mapping and six-layer firmware remain unresolved.
