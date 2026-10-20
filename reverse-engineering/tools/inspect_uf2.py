#!/usr/bin/env python3
"""Read-only UF2 metadata inspector; does not modify firmware."""
import argparse
import struct
from pathlib import Path

MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30

def inspect(path):
    data = Path(path).read_bytes()
    if len(data) % 512:
        raise ValueError("UF2 size is not a multiple of 512")
    blocks = []
    for i in range(0, len(data), 512):
        b = data[i:i+512]
        m0,m1,flags,address,size,index,total,family = struct.unpack_from("<8I", b)
        end, = struct.unpack_from("<I", b, 508)
        if (m0,m1,end) != (MAGIC0,MAGIC1,MAGIC_END):
            raise ValueError(f"Invalid UF2 magic at block {i//512}")
        if size > 476:
            raise ValueError(f"Invalid payload size at block {i//512}")
        blocks.append((flags,address,size,index,total,family))
    addresses = [b[1] for b in blocks]
    print(f"File: {path}")
    print(f"Blocks: {len(blocks)}")
    print(f"Payload bytes: {sum(b[2] for b in blocks)}")
    print(f"Target start: 0x{min(addresses):08X}")
    print(f"Target end (exclusive): 0x{max(b[1]+b[2] for b in blocks):08X}")
    print(f"Family ID field: 0x{blocks[0][5]:08X} (valid as family only when flags bit 0x2000 set)")
    print(f"Flags: 0x{blocks[0][0]:08X}")
    print("Note: UF2 metadata alone does not identify GPIO pins or verify safe flashing.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("uf2")
    inspect(p.parse_args().uf2)
