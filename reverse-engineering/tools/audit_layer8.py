#!/usr/bin/env python3
"""Read-only evidence checker for ONE inspected manufacturer eight-layer UF2.

No USB access, flashing, firmware patching, or dependency on previous recovery
reports. Addresses and instruction witnesses were inspected in Ghidra 12.1.4.
This is not a general disassembler or a claim that hardware is safe to flash.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import lzma
from pathlib import Path
import struct

SHA256 = "c64e08bfc3c5a74833408064425e7995178cf9e98d59ded807ddf3aaf5e10ee9"
BASE = 0x08010000
FAMILY = 0x57755A57
MAX_UF2_BYTES = 1024 * 1024
# Exact instruction boundaries inspected in Ghidra; meaning is explained in
# docs/layer8-audit.md. Constants alone do not establish register usage.
WITNESSES = {
    "layer_count_reply": (0x0801958A, "0823"),
    "keycode_bounds": (0x0801386A, "072838b51d4616d8032914d80b2a12d8"),
    "keymap_buffer_bounds_and_base": (0x080195B6, "b5f5407f08d205f12900faf734f9"),
    "macro_capacity_and_base": (0x08013CBC, "40f60f2540f2f157"),
    "column_init_table": (0x08018A2A, "924d0c24"),
    "row_init_calls": (0x08018A42, "8d48fbf735fc8c48fbf732fc8c48fbf72ffc8b48fbf72cfc"),
    "column_table_load": (0x0801D114, "794f"),
    "column_drive_low": (0x0801D13C, "fef782f84583"),
    "row_table_load": (0x0801D15E, "684d"),
    "row_idr_read": (0x0801D178, "21f00f0e01f00f01def810e02efa01f1c9077cd43243"),
    "four_rows": (0x0801D192, "042b20f8022c"),
    "twelve_columns": (0x0801D1B4, "0c2cb6b2b1d1"),
    "input_pullup_mode": (0x080142C2, "202220f00f0006f0bcff"),
    "pll_write": (0x0801AA94, "224a5a60"),
    "cfgr_write": (0x0801AAB0, "1c4a9a60"),
    "boot_magic_store_and_reset_call": (0x08018ACE, "734b734a1a6001f070ff"),
    "system_reset": (0x0801A9B8, "bff34f8f0549064bca6802f4e0621343cb60bff34f8f00bf"),
    "usb_device_descriptor_reply": (0x08019F02, "084a1223d7e7"),
    "usb_configuration_reply": (0x08019EB4, "144a5b23"),
    "backing_budget": (0x08018630, "baf5005f"),
    "sector_selection": (0x08018642, "032102f0d6fb"),
    "sector_offset_lookup": (0x0801AE02, "53f8340010bd"),
    "sector_size_lookup": (0x0801AE1C, "03ebc403586810bd"),
    "logical_buffer_extent": (0x08018694, "b6f5805ff4d1"),
}


@dataclass(frozen=True)
class Image:
    base: int
    data: bytes
    family: int

    def read(self, address: int, size: int) -> bytes:
        offset = address - self.base
        if size < 0 or offset < 0 or offset + size > len(self.data):
            raise ValueError(f"Outside image: {address:#x}, size={size}")
        return self.data[offset:offset + size]

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]


def parse_uf2(raw: bytes) -> Image:
    if not raw or len(raw) % 512 or len(raw) > MAX_UF2_BYTES:
        raise ValueError("Expected nonempty, complete UF2 blocks, at most 1 MiB")
    chunks, indices, families = {}, set(), set()
    count = len(raw) // 512
    for offset in range(0, len(raw), 512):
        block = raw[offset:offset + 512]
        m0, m1, flags, address, size, index, total, family = struct.unpack_from("<8I", block)
        if (m0, m1, struct.unpack_from("<I", block, 508)[0]) != (0x0A324655, 0x9E5D5157, 0x0AB16F30):
            raise ValueError("Invalid UF2 magic")
        if flags != 0x2000 or not 0 < size <= 476 or address + size > 2**32:
            raise ValueError("Unsupported flags, payload size or address")
        if total != count or index >= count or index in indices or address in chunks:
            raise ValueError("Inconsistent or duplicate UF2 block metadata")
        indices.add(index)
        families.add(family)
        chunks[address] = block[32:32 + size]
    if len(families) != 1:
        raise ValueError("Inconsistent UF2 family")
    addresses = sorted(chunks)
    cursor = addresses[0]
    for address in addresses:
        if address != cursor:
            raise ValueError("UF2 gap or overlap")
        cursor += len(chunks[address])
    return Image(addresses[0], b"".join(chunks[a] for a in addresses), families.pop())


def literal(image: Image, address: int) -> int:
    opcode = struct.unpack("<H", image.read(address, 2))[0]
    if opcode & 0xF800 != 0x4800:
        raise ValueError(f"Expected Thumb T1 literal load at {address:#x}")
    return image.u32(((address + 4) & ~3) + (opcode & 255) * 4)


def pin(value: int) -> str:
    ports = {0x40020000: "A", 0x40020400: "B"}
    if value & ~15 not in ports:
        raise ValueError("Unexpected GPIO port")
    return ports[value & ~15] + str(value & 15)


def expect(actual, expected, label: str):
    if actual != expected:
        raise ValueError(f"Evidence mismatch: {label}: {actual!r} != {expected!r}")
    return actual


def check_evidence(image: Image) -> dict:
    """Verify the manually inspected build profile, never guess new offsets."""
    expect((image.base, image.family, len(image.data)), (BASE, FAMILY, 60160), "image metadata")
    for name, (address, hex_bytes) in WITNESSES.items():
        expect(image.read(address, len(bytes.fromhex(hex_bytes))), bytes.fromhex(hex_bytes), name)
    expect(image.u32(BASE), 0x20000400, "initial stack pointer")
    expect(image.u32(BASE + 4), 0x080102FD, "reset vector")
    expect(image.u32(0x080102C8), BASE, "VTOR value")
    expect(image.u32(0x080102CC), 0xE000ED08, "VTOR register")

    col_table = literal(image, 0x0801D114)
    row_table = literal(image, 0x0801D15E)
    expect(literal(image, 0x08018A2A), col_table, "column init and scan agreement")
    columns = list(struct.unpack("<12I", image.read(col_table, 48)))
    rows = list(struct.unpack("<4I", image.read(row_table, 16)))
    expect([literal(image, a) for a in (0x08018A42, 0x08018A48, 0x08018A4E, 0x08018A54)], rows, "row init and scan agreement")
    expect(len(set(rows + columns)), 16, "non-overlapping pins")

    pll = literal(image, 0x0801AA94)
    cfgr = literal(image, 0x0801AAB0)
    expect((pll, cfgr, image.u32(0x0801AB10)), (0x04413010, 0x38881000, 0x40023800), "RCC values")
    m, n, p, q = pll & 63, (pll >> 6) & 511, 2 * (((pll >> 16) & 3) + 1), (pll >> 24) & 15
    expect(bool(pll & (1 << 22)), True, "HSE selected")
    # This is an inference requiring a correctly clocked USB FS peripheral.
    inferred_hse = 48000000 * q * m // n

    device_address = literal(image, 0x08019F02)
    descriptor = image.read(device_address, 18)
    expect(descriptor[:2], b"\x12\x01", "USB device descriptor")
    vid, pid = struct.unpack_from("<HH", descriptor, 8)
    config_address = literal(image, 0x08019EB4)
    config_head = image.read(config_address, 9)
    expect(config_head[:2], b"\x09\x02", "USB configuration descriptor")
    total = struct.unpack_from("<H", config_head, 2)[0]
    config = image.read(config_address, total)
    interfaces, endpoints, cursor, interface = [], [], 0, None
    while cursor < len(config):
        size, kind = config[cursor:cursor + 2]
        if size < 2 or cursor + size > len(config):
            raise ValueError("Invalid USB configuration descriptor length")
        part = config[cursor:cursor + size]
        if kind == 4:
            expect(size, 9, "interface length")
            interface = part[2]
            interfaces.append({"number": interface, "class": part[5], "subclass": part[6], "protocol": part[7]})
        elif kind == 5:
            expect(size, 7, "endpoint length")
            endpoints.append({"interface": interface, "address": hex(part[2]), "attributes": part[3], "max_packet": struct.unpack_from("<H", part, 4)[0], "interval_ms_at_full_speed": part[6]})
        cursor += size
    strings_base = image.u32(0x08019F10)
    strings = {}
    for name, index in zip(("manufacturer", "product", "serial"), descriptor[14:17]):
        address = image.u32(strings_base + index * 4)
        length, kind = image.read(address, 2)
        if kind != 3 or length < 2 or length % 2:
            raise ValueError("Invalid USB string")
        strings[name] = image.read(address + 2, length - 2).decode("utf-16le")

    expect((image.u32(0x08018C9C), image.u32(0x08018CA0)), (0x2000FFFC, 0xF01669EF), "boot request RAM marker")
    expect((image.u32(0x0801A9D4), image.u32(0x0801A9D8)), (0xE000ED00, 0x05FA0004), "AIRCR reset request")
    sector_geometries = []
    for address in range(0x0801D620, 0x0801D690, 28):
        attributes, width, count, table, uniform, flash, total_flash = struct.unpack("<7I", image.read(address, 28))
        expect((attributes, width, uniform, flash), (3, 4, 0, 0x08000000), "flash descriptor")
        sectors = [struct.unpack("<II", image.read(table + i * 8, 8)) for i in range(count)]
        expect(sectors[3], (0xC000, 0x4000), "settings sector geometry")
        expect(sum(size for _, size in sectors), total_flash, "flash table total")
        sector_geometries.append(total_flash)
    gpio_a = image.u32(0x0801AB14)
    moder, _, _, _, _, afrl, afrh = struct.unpack("<7I", image.read(gpio_a, 28))
    usb_pins = {f"PA{pad}": {"mode": (moder >> (pad * 2)) & 3, "alternate_function": ((afrl if pad < 8 else afrh) >> ((pad % 8) * 4)) & 15} for pad in (11, 12)}
    expect(usb_pins, {"PA11": {"mode": 2, "alternate_function": 10}, "PA12": {"mode": 2, "alternate_function": 10}}, "initial USB pin mux")

    xz_address = BASE + image.data.index(b"\xfd7zXZ\x00")
    decoder = lzma.LZMADecompressor()
    decoded = decoder.decompress(image.data[xz_address - BASE:], max_length=1024 * 1024)
    if not decoder.eof:
        raise ValueError("Incomplete or oversized Vial definition")
    definition = json.loads(decoded)
    expect(definition["matrix"], {"rows": 4, "cols": 12}, "embedded Vial matrix")
    return {
        "image": {"base": hex(BASE), "bytes": len(image.data), "payload_sha256": hashlib.sha256(image.data).hexdigest(), "initial_sp": hex(image.u32(BASE)), "reset_thumb_address": hex(image.u32(BASE + 4))},
        "matrix": {"rows": [pin(v) for v in rows], "columns": [pin(v) for v in columns], "row_table": hex(row_table), "column_table": hex(col_table), "direction": "ROW2COL", "evidence": "selected column driven low; row IDR low sets pressed bit; init/scan tables agree", "physical_wiring_verified": False},
        "clocks": {"pllcfgr": hex(pll), "cfgr": hex(cfgr), "source": "HSE", "m": m, "n": n, "p": p, "q": q, "hse_hz_inferred_for_usb_48mhz": inferred_hse, "sysclk_hz_inferred": inferred_hse * n // m // p, "oscillator_measured": False},
        "usb": {"vid": hex(vid), "pid": hex(pid), **strings, "device_descriptor": hex(device_address), "configuration_descriptor": hex(config_address), "interfaces": interfaces, "endpoints": endpoints, "initial_pin_mux": usb_pins, "enumeration_tested": False},
        "vial": {"layers": 8, "keymap_bytes": 768, "logical_keymap_start": "0x29", "embedded_definition": hex(xz_address), "matrix": definition["matrix"], "lighting": definition.get("lighting"), "custom_keycode_count": len(definition.get("customKeycodes", []))},
        "storage": {"logical_bytes": 4096, "backing_budget_bytes": 8192, "first_sector": 3, "sector_start": "0x0800c000", "erase_sector_bytes": 16384, "represented_flash_capacities_not_physical_capacity": sector_geometries, "macro_start": "0x5f1", "macro_bytes": 2575, "migration_verified": False},
        "boot_request": {"ram_address": "0x2000fffc", "value": "0xf01669ef", "reset_function": "0x0801a9b8", "aircr": "0xe000ed0c", "bootloader_image_present": False, "recovery_verified": False},
        "mcu": {"candidate": "STM32F411", "filename_and_f4_register_map_are_not_silicon_identification": True, "physical_part_verified": False},
        "instruction_witnesses": {k: {"address": hex(a), "bytes": h} for k, (a, h) in WITNESSES.items()},
        "flash_ready": False,
    }


def audit(raw: bytes) -> dict:
    image = parse_uf2(raw)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SHA256:
        raise ValueError("Unknown firmware SHA-256; refusing fixed-offset evidence profile")
    return {"uf2_sha256": digest, **check_evidence(image)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    args = parser.parse_args()
    try:
        if args.uf2.stat().st_size > MAX_UF2_BYTES:
            raise ValueError("UF2 exceeds 1 MiB limit")
        print(json.dumps(audit(args.uf2.read_bytes()), indent=2, ensure_ascii=False))
    except (ValueError, OSError, struct.error, lzma.LZMAError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
