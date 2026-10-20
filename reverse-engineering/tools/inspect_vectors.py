#!/usr/bin/env python3
"""Read-only ARM vector-table inspection of UF2 firmware images."""
import argparse
import struct
from pathlib import Path

MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)

def inspect(path):
    raw = Path(path).read_bytes()
    if not raw or len(raw) % 512:
        raise ValueError("Invalid UF2 length")
    blocks = {}
    for off in range(0, len(raw), 512):
        b = raw[off:off+512]
        m0,m1,flags,addr,n,index,total,family = struct.unpack_from("<8I",b)
        end, = struct.unpack_from("<I",b,508)
        if (m0,m1,end) != MAGIC or n > 476:
            raise ValueError(f"Invalid UF2 block {off//512}")
        if addr in blocks:
            raise ValueError(f"Duplicate address {addr:#x}")
        blocks[addr] = b[32:32+n]
    start = min(blocks)
    if start not in blocks or len(blocks[start]) < 64:
        raise ValueError("Insufficient first block")
    data = blocks[start]
    print(f"Image: {path}\nVector base: 0x{start:08X}")
    for i in range(16):
        v, = struct.unpack_from("<I",data,i*4)
        name = ["initial_sp","reset","nmi","hardfault","memmanage","busfault","usagefault","reserved7","reserved8","reserved9","reserved10","svc","debugmon","reserved13","pendsv","systick"][i]
        print(f"{i:2} {name:12} 0x{v:08X}")
    print("Addresses are candidates; architecture and bootloader must be independently verified.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("uf2")
    inspect(parser.parse_args().uf2)
