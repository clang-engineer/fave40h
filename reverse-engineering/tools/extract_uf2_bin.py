#!/usr/bin/env python3
"""Read-only UF2 to contiguous BIN extractor for local ARM analysis."""
import argparse, struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument("uf2")
p.add_argument("output")
args=p.parse_args()
raw=Path(args.uf2).read_bytes()
if not raw or len(raw)%512: raise ValueError("Invalid UF2 length")
chunks={}
for i in range(0,len(raw),512):
 b=raw[i:i+512]
 m0,m1,flags,addr,n,index,total,family=struct.unpack_from("<8I",b)
 end,=struct.unpack_from("<I",b,508)
 if (m0,m1,end)!=(0x0A324655,0x9E5D5157,0x0AB16F30) or n>476:
  raise ValueError(f"Bad block {i//512}")
 if addr in chunks: raise ValueError("Duplicate block address")
 chunks[addr]=b[32:32+n]
base=min(chunks)
end=max(addr+len(v) for addr,v in chunks.items())
out=bytearray(b"\xff"*(end-base))
for addr,payload in chunks.items():out[addr-base:addr-base+len(payload)]=payload
Path(args.output).write_bytes(out)
print(f"Extracted {len(out)} bytes at base 0x{base:08X}")
