#!/usr/bin/env python3
"""Read-only validation of manufacturer FAVE40H firmware files.

Usage:
  python3 tools/test_firmware.py "/path/to/fave40h (2).zip"
No firmware is modified or flashed.
"""
import argparse
import json
import struct
import zipfile

FILES = ("FAve40h_VIA.uf2", "FAve40H_VIAL.uf2")
MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)

def validate_uf2(data, filename):
    assert len(data) and len(data) % 512 == 0, "invalid UF2 size"
    count = len(data) // 512
    payload_bytes = 0
    for i in range(count):
        block = data[i * 512:(i + 1) * 512]
        m0, m1, flags, address, size, index, total, family = struct.unpack_from("<8I", block)
        end, = struct.unpack_from("<I", block, 508)
        assert (m0, m1, end) == MAGIC, f"bad magic in block {i}"
        assert size <= 476 and index == i and total == count, f"bad block metadata {i}"
        assert flags & 0x2000 and family == 0x57755A57, f"unexpected family {i}"
        assert address == 0x08010000 + i * 256, f"unexpected address {i}"
        assert size == 256, f"unexpected payload size {i}"
        payload_bytes += size
    sp, reset = struct.unpack_from("<2I", data, 32)
    assert (sp, reset) == (0x20000400, 0x080102FD), "unexpected vector candidates"
    print(f"PASS {filename}: {count} blocks, {payload_bytes} bytes, SP=0x{sp:08X}, reset=0x{reset:08X}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("zip", help="Manufacturer FAVE40H ZIP file")
    args = parser.parse_args()
    with zipfile.ZipFile(args.zip) as archive:
        via = json.loads(archive.read("FAve40H_via.json"))
        assert via["matrix"] == {"rows": 4, "cols": 12}
        print("PASS VIA logical matrix: 4x12")
        for name in FILES:
            validate_uf2(archive.read(name), name)
    print("PASS all checks (file structure only; NOT hardware validation)")

if __name__ == "__main__":
    main()
