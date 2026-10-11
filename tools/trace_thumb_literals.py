#!/usr/bin/env python3
"""Read-only scan of Thumb-1 PC-relative LDR literal references.

Not a full disassembler: false positives are possible; Thumb-2 forms are omitted.
"""
import argparse, struct, zipfile
from pathlib import Path

REGS = {"GPIOA":0x40020000,"GPIOB":0x40020400,"GPIOC":0x40020800,"RCC":0x40023800}

def scan(raw, name):
    blocks = {}
    for off in range(0, len(raw), 512):
        b = raw[off:off+512]
        if len(b) != 512:
            raise ValueError("truncated UF2 block")
        a, size = struct.unpack_from("<II", b, 12)
        if size > 476:
            raise ValueError("invalid UF2 payload size")
        blocks[a] = b[32:32+size]
    base = min(blocks)
    end = max(a+len(v) for a,v in blocks.items())
    buf = bytearray(b"\xff"*(end-base))
    for a,v in blocks.items():
        buf[a-base:a-base+len(v)] = v
    print(name, "base", hex(base))
    for pos in range(0, len(buf)-1, 2):
        h = struct.unpack_from("<H",buf,pos)[0]
        if h & 0xf800 != 0x4800:
            continue
        addr = base+pos
        literal = ((addr+4)&~3)+((h&0xff)*4)
        if not(base <= literal <= end-4):
            continue
        value = struct.unpack_from("<I",buf,literal-base)[0]
        if value in REGS.values():
            label = next(k for k,v in REGS.items() if v == value)
            print(f"  {label}: instruction=0x{addr:08X}, literal=0x{literal:08X}, register=r{(h>>8)&7}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("firmware", help="manufacturer .uf2 or ZIP")
    path = Path(p.parse_args().firmware)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.lower().endswith(".uf2"):
                    scan(z.read(n), n)
    else:
        scan(path.read_bytes(),path.name)
