#!/usr/bin/env python3
"""Check and recover matrix settings from two known stock FAVE40H UF2 builds.

Read-only; no USB/device access. This is a build-specific evidence checker,
not a general decompiler. GPIO roles come from manual control-flow and
register-use analysis, then are checked against instruction bytes here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

MAGIC = (0x0A324655, 0x9E5D5157, 0x0AB16F30)
BASE = 0x08010000
FAMILY = 0x57755A57
PROFILES = {
    "a545e1a6bafc4eedec9ffa676d9e7245254ef1a7a185c98986928c9c06ec9d22": {
        "name": "VIA", "size": 47872, "main": 0x08017FE0,
        "early_init": 0x08015310, "gpio_ldr": 0x08015314,
        "scan": 0x0801A5E4, "scan_call": 0x080187F6,
        "cols_ldr": 0x0801A5F0, "rows_ldr": 0x0801A63E,
        "cols_table": 0x0801AEE8, "rows_table": 0x0801B3F0,
        "init_cols_ldr": 0x0801878C,
        "init_row_ldrs": [0x080187A4, 0x080187AA, 0x080187B0, 0x080187B6],
        "witnesses": {
            0x0801A608: "21f00f0a01f00f01",  # split port / pad
            0x0801A61E: "aaf81a50",          # column BSRR high-half write
            0x0801A658: "22f00f0e02f00f02",  # split row port / pad
            0x0801A660: "def810e0",          # row GPIO IDR read
            0x0801A66E: "3343",              # set column bit in row word
            0x0801A674: "0429",              # four rows
            0x0801A696: "0c2c",              # twelve columns
        },
    },
    "d5e680fa2507534b63b316a3e67a5d7457af4bdfa65189f464d4e1b029692431": {
        "name": "Vial", "size": 61952, "main": 0x080183A0,
        "early_init": 0x0801B034, "gpio_ldr": 0x0801B038,
        "scan": 0x0801D65C, "scan_call": 0x08018BE2,
        "cols_ldr": 0x0801D66C, "rows_ldr": 0x0801D6B6,
        "cols_table": 0x0801DD24, "rows_table": 0x0801E5DC,
        "init_cols_ldr": 0x08018B66,
        "init_row_ldrs": [0x08018B7E, 0x08018B84, 0x08018B8A, 0x08018B90],
        "witnesses": {
            0x0801D682: "21f00f0001f00f01",
            0x0801D698: "4483",
            0x0801D6D0: "22f00f0e02f00f02",
            0x0801D6D8: "def810e0",
            0x0801D6E4: "4aea0303",
            0x0801D6BA: "4ff0040c",
            0x0801D66E: "0c25",
        },
    },
}


@dataclass(frozen=True)
class Image:
    base: int
    data: bytes
    family: int

    def read(self, address: int, size: int) -> bytes:
        offset = address - self.base
        if size < 0 or offset < 0 or offset + size > len(self.data):
            raise ValueError(f"Read outside image: {address:#x}, size={size}")
        return self.data[offset:offset + size]

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]


def parse_uf2(raw: bytes) -> Image:
    """Strict parser for ordinary, contiguous, family-tagged flash UF2 files."""
    if not raw or len(raw) % 512:
        raise ValueError("UF2 must contain complete 512-byte blocks")
    count = len(raw) // 512
    chunks, indices, families = {}, set(), set()
    for offset in range(0, len(raw), 512):
        b = raw[offset:offset + 512]
        m0, m1, flags, addr, size, index, total, family = struct.unpack_from("<8I", b)
        end, = struct.unpack_from("<I", b, 508)
        if (m0, m1, end) != MAGIC:
            raise ValueError("Invalid UF2 magic")
        if flags != 0x2000:
            raise ValueError("Unsupported UF2 flags (expected family-tagged flash blocks)")
        if not 0 < size <= 476 or addr + size > 0x100000000:
            raise ValueError("Invalid UF2 payload size/address")
        if total != count or index >= count or index in indices or addr in chunks:
            raise ValueError("Inconsistent/duplicate UF2 block metadata")
        indices.add(index)
        families.add(family)
        chunks[addr] = b[32:32 + size]
    if indices != set(range(count)) or len(families) != 1:
        raise ValueError("Missing indices or inconsistent family IDs")
    addresses = sorted(chunks)
    cursor = addresses[0]
    for address in addresses:
        if address != cursor:
            raise ValueError("UF2 address gap or overlap")
        cursor += len(chunks[address])
    return Image(addresses[0], b"".join(chunks[a] for a in addresses), families.pop())


def ldr_literal(image: Image, address: int) -> int:
    """Resolve the literal value of one Thumb T1 LDR, at a verified boundary."""
    opcode, = struct.unpack("<H", image.read(address, 2))
    if opcode & 0xF800 != 0x4800:
        raise ValueError(f"Not a Thumb T1 literal load at {address:#x}")
    literal = ((address + 4) & ~3) + 4 * (opcode & 255)
    return image.u32(literal)


def bl_target(image: Image, address: int) -> int:
    h1, h2 = struct.unpack("<2H", image.read(address, 4))
    if h1 & 0xF800 != 0xF000 or h2 & 0xD000 != 0xD000:
        raise ValueError(f"Not a Thumb BL at {address:#x}")
    s = (h1 >> 10) & 1
    i1 = 1 ^ ((h2 >> 13) & 1) ^ s
    i2 = 1 ^ ((h2 >> 11) & 1) ^ s
    imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 1023) << 12) | ((h2 & 2047) << 1)
    if s:
        imm -= 1 << 25
    return address + 4 + imm


def pin_name(value: int) -> str:
    port = value & ~15
    if port not in (0x40020000, 0x40020400):
        raise ValueError(f"Unexpected matrix GPIO encoding: {value:#x}")
    return ("A" if port == 0x40020000 else "B") + str(value & 15)


def recover(raw: bytes) -> dict:
    image = parse_uf2(raw)
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in PROFILES:
        raise ValueError("Unknown firmware SHA-256; refusing build-specific offsets")
    p = PROFILES[digest]
    if (image.base, image.family, len(image.data)) != (BASE, FAMILY, p["size"]):
        raise ValueError("Image metadata differs from the inspected build")
    if image.u32(BASE + 4) != 0x080102FD or image.read(0x080102FC, 2) != b"\x70\xe7":
        raise ValueError("Reset entry/branch differs")
    for source, target in [(0x08010248, p["early_init"]), (0x080102A8, p["main"]), (p["scan_call"], p["scan"])]:
        if bl_target(image, source) != target:
            raise ValueError(f"Call target differs at {source:#x}")
    if ldr_literal(image, p["gpio_ldr"]) != 0x40020000:
        raise ValueError("Early GPIOA reference differs")
    for address, expected in p["witnesses"].items():
        pattern = bytes.fromhex(expected)
        if image.read(address, len(pattern)) != pattern:
            raise ValueError(f"Matrix instruction witness differs at {address:#x}")
    cols_addr = ldr_literal(image, p["cols_ldr"])
    rows_addr = ldr_literal(image, p["rows_ldr"])
    if (cols_addr, rows_addr) != (p["cols_table"], p["rows_table"]):
        raise ValueError("Matrix table pointers differ")
    rows = list(struct.unpack("<4I", image.read(rows_addr, 16)))
    cols = list(struct.unpack("<12I", image.read(cols_addr, 48)))
    if ldr_literal(image, p["init_cols_ldr"]) != cols_addr:
        raise ValueError("Init and scan disagree about column table")
    if [ldr_literal(image, x) for x in p["init_row_ldrs"]] != rows:
        raise ValueError("Init and scan disagree about row order")
    if len(set(rows + cols)) != 16:
        raise ValueError("Matrix pins overlap")
    return {
        "firmware": p["name"], "uf2_sha256": digest,
        "payload_sha256": hashlib.sha256(image.data).hexdigest(),
        "image_base": hex(image.base), "payload_bytes": len(image.data),
        "scan_entry": hex(p["scan"]),
        "rows_table": hex(rows_addr), "cols_table": hex(cols_addr),
        "matrix_pins": {"rows": [pin_name(v) for v in rows], "cols": [pin_name(v) for v in cols]},
        "diode_direction": "ROW2COL",
        "pressed_state": "row input low while selected column is driven low",
        "evidence_level": "static firmware reconstruction; not electrically verified",
        "flash_ready": False,
    }


def load_images(path: Path) -> list[tuple[str, bytes]]:
    if path.suffix.lower() != ".zip":
        return [(path.name, path.read_bytes())]
    with zipfile.ZipFile(path) as archive:
        candidates = [i for i in archive.infolist() if i.filename.lower().endswith(".uf2")]
        if not candidates or any(i.file_size > 2**20 for i in candidates):
            raise ValueError("No UF2 files or unexpectedly large ZIP member")
        return [(i.filename, archive.read(i)) for i in candidates]


def extract_vial_definition(raw: bytes) -> dict:
    # The exact inspected Vial image contains an XZ stream at this address.
    result = recover(raw)
    if result["firmware"] != "Vial":
        raise ValueError("Embedded Vial definition requires the Vial build")
    image = parse_uf2(raw)
    offset = 0x0801DFA8 - image.base
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    decoded = decoder.decompress(image.data[offset:], max_length=2**20)
    if not decoder.eof:
        raise ValueError("Incomplete or oversized embedded definition")
    definition = json.loads(decoded)
    if definition.get("matrix") != {"rows": 4, "cols": 12}:
        raise ValueError("Unexpected embedded matrix dimensions")
    return definition


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path, help="Stock UF2 or manufacturer ZIP")
    parser.add_argument("--vial-json", type=Path, help="Extract embedded Vial definition to a NEW local file")
    args = parser.parse_args()
    try:
        images = load_images(args.firmware)
        results = [recover(raw) for _, raw in images]
        if len({json.dumps(r["matrix_pins"], sort_keys=True) for r in results}) != 1:
            raise ValueError("Firmware variants disagree about matrix pins")
        if args.vial_json:
            vial = next((raw for _, raw in images if hashlib.sha256(raw).hexdigest() in PROFILES and PROFILES[hashlib.sha256(raw).hexdigest()]["name"] == "Vial"), None)
            if vial is None:
                raise ValueError("No supported Vial firmware was supplied")
            definition = extract_vial_definition(vial)
            with args.vial_json.open("x", encoding="utf-8") as stream:
                json.dump(definition, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        print(json.dumps(results, indent=2))
    except (OSError, ValueError, zipfile.BadZipFile, lzma.LZMAError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
