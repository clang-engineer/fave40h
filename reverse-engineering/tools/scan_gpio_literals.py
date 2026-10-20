#!/usr/bin/env python3
"""Read-only scan for STM32F4 peripheral address literals in UF2 images.

This is NOT disassembly and cannot prove which pins scan keys.
"""
import argparse
import struct
import zipfile
from pathlib import Path

BASE = 0x08010000
REGISTERS = {
    "GPIOA": 0x40020000,
    "GPIOB": 0x40020400,
    "GPIOC": 0x40020800,
    "GPIOD": 0x40020C00,
    "GPIOE": 0x40021000,
    "RCC": 0x40023800,
}

def scan(name, raw):
    if not raw or len(raw) % 512:
        raise ValueError("invalid UF2 length")
    blocks = {}
    for off in range(0, len(raw), 512):
        block = raw[off:off+512]
        m0, m1, flags, addr, size, idx, total, family = struct.unpack_from("<8I", block)
        end, = struct.unpack_from("<I", block, 508)
        if (m0, m1, end) != (0x0A324655, 0x9E5D5157, 0x0AB16F30) or size > 476:
            raise ValueError(f"bad UF2 block {off // 512}")
        blocks[addr] = block[32:32+size]
    base = min(blocks)
    end = max(addr+len(payload) for addr,payload in blocks.items())
    data = bytearray(b"\xff"*(end-base))
    for addr,payload in blocks.items():
        data[addr-base:addr-base+len(payload)] = payload
    print(f"{name}: base=0x{base:08X}, image bytes={len(data)}")
    for label,value in REGISTERS.items():
        needle = struct.pack("<I", value)
        hits = []
        cursor = 0
        while True:
            pos = data.find(needle, cursor)
            if pos < 0: break
            hits.append(f"0x{base+pos:08X}")
            cursor = pos+1
        print(f"  {label:5} {value:#010x}: {', '.join(hits) if hits else 'none'}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("firmware", help="Manufacturer .uf2 or ZIP containing .uf2 files")
    path = Path(p.parse_args().firmware)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.lower().endswith(".uf2"):
                    scan(name, z.read(name))
    else:
        scan(path.name, path.read_bytes())

if __name__ == "__main__":
    main()
