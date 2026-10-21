#!/usr/bin/env python3
"""Recover forensic source/data from the ORIGINAL four-layer Vial UF2 only.

Not a complete QMK port or a flashable firmware. No USB access. SHA-256 and
instruction witnesses bind every fixed offset to the inspected original build.
Only the generic, strict UF2/Thumb parsing primitives are reused from the old
investigation; no previous hardware conclusions or eight-layer profiles are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct

from recover_matrix import parse_uf2, ldr_literal, bl_target, pin_name

ORIGINAL_SHA256 = "d5e680fa2507534b63b316a3e67a5d7457af4bdfa65189f464d4e1b029692431"
PAYLOAD_SHA256 = "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4"
BASE = 0x08010000
WITNESSES = {
    "factory_keymap_source_and_layer3_transparent": (0x08015844, "032c18bf39f815300191eab208bf012358460135fef776fe0c2d0199f0d10136042e09f1180902d00025f1b2e8e70134042c"),
    "four_layer_reply": (0x080198BA, "0423"),
    "dynamic_keycode_bounds": (0x08014548, "032870b51e4616d8032914d80b2a12d8"),
    "matrix_drive_column": (0x0801D67E, "88f3118821f00f0001f00f0109fa01f421460122a4b2fef72af9448387f3"),
    "matrix_read_row_idr": (0x0801D6D0, "22f00f0e02f00f02def810e02efa02f2d2073dd44aea030321f8023c"),
    "matrix_column_init": (0x08018B66, "874d0c24"),
    "matrix_row_init": (0x08018B7E, "8248fbf72afb8148fbf727fb8148fbf724fb8048fbf721fb"),
    "matrix_input_pullup": (0x080141E8, "202220f00f0007f07dfb"),
    "pll_write": (0x0801B0EC, "224a5a60"),
    "cfgr_write": (0x0801B108, "1c4a9a60"),
    "system_reset_no_return": (0x0801B010, "bff34f8f0549064bca6802f4e0621343cb60bff34f8f00bffde7"),
    "gpio_register_write_order": (0x0801AA7E, "4b6843608b688360cb68c3600b6943614b6903628b6943620b6803607047"),
    "boot_marker_and_reset": (0x08018C0A, "684b684a1a6002f0fef9"),
    "tap_dance_reset_region": (0x08015898, "40f2d11440f2712520460a2203a90a3407f062feac42f7d1"),
    "combo_reset_region": (0x080158BA, "40f2113520460a2203a90a3407f053feac42f7d1"),
    "override_reset_region": (0x080158E6, "40f2b13520460a2203a90a3407f03dfeac42f7d1"),
    "alt_repeat_reset_region": (0x08015902, "40f271452046062203a9063407f02ffeac42f7d1"),
}


def require(actual, expected, label):
    if actual != expected:
        raise ValueError(f"Original evidence mismatch: {label}")
    return actual


def recover(raw: bytes) -> tuple[dict, dict]:
    if len(raw) > 1024 * 1024:
        raise ValueError("Input exceeds 1 MiB")
    image = parse_uf2(raw)
    require(hashlib.sha256(raw).hexdigest(), ORIGINAL_SHA256, "not original FAve40H_VIAL.uf2 (8-layer/VIA builds are not this target)")
    require((image.base, image.family, len(image.data)), (BASE, 0x57755A57, 61952), "UF2 metadata")
    require(hashlib.sha256(image.data).hexdigest(), PAYLOAD_SHA256, "payload identity")
    for name, (address, pattern) in WITNESSES.items():
        expected = bytes.fromhex(pattern)
        require(image.read(address, len(expected)), expected, name)
    require(bl_target(image, 0x08010248), 0x0801B034, "startup early_init")
    require(bl_target(image, 0x080102A8), 0x080183A0, "startup application entry")
    require(bl_target(image, 0x08018BE2), 0x0801D65C, "matrix scan caller")
    require(bl_target(image, 0x08013EE8), 0x0801B010, "reboot reset call")
    require((image.u32(BASE), image.u32(BASE + 4)), (0x20000400, 0x080102FD), "vectors")

    # Reset loop loads this table only for layers 0..2; layer 3 uses KC_TRNS.
    # 0x0801582A is Thumb-2 LDR.W r10,[PC,#0xF8] -> 0x08015924.
    require(image.read(0x0801582A, 4), bytes.fromhex("dff8f8a0"), "factory table pointer load")
    table = image.u32(0x08015924)
    values = struct.unpack("<144H", image.read(table, 288))
    keymaps = [[[values[layer * 48 + row * 12 + col] for col in range(12)] for row in range(4)] for layer in range(3)]
    keymaps.append([[1] * 12 for _ in range(4)])
    factory_bytes = b"".join(struct.pack("<12H", *row) for layer in keymaps for row in layer)

    cols_table = ldr_literal(image, 0x0801D66C)
    rows_table = ldr_literal(image, 0x0801D6B6)
    columns = list(struct.unpack("<12I", image.read(cols_table, 48)))
    rows = list(struct.unpack("<4I", image.read(rows_table, 16)))
    require(ldr_literal(image, 0x08018B66), cols_table, "column init/scan agreement")
    require([ldr_literal(image, a) for a in (0x08018B7E, 0x08018B84, 0x08018B8A, 0x08018B90)], rows, "row init/scan agreement")
    require(len(set(rows + columns)), 16, "unique pins")

    # Early init supplies six packed register groups to the port initializer.
    gpio_table = image.u32(0x0801B16C)
    gpio_defaults = {}
    for i, port in enumerate("ABCDEH"):
        gpio_defaults[port] = dict(zip(("MODER", "OTYPER", "OSPEEDR", "PUPDR", "ODR", "AFRL", "AFRH"), struct.unpack("<7I", image.read(gpio_table + i * 28, 28))))
    require((image.u32(0x0801B168), image.u32(0x0801B170)), (0x40023800, 0x40020000), "early RCC/GPIO bases")
    pll = ldr_literal(image, 0x0801B0EC)
    cfgr = ldr_literal(image, 0x0801B108)
    require((pll, cfgr), (0x04413010, 0x38881000), "clock values")

    descriptor_address = ldr_literal(image, 0x0801A272)
    descriptor = image.read(descriptor_address, 18)
    require(descriptor[:2], b"\x12\x01", "USB device descriptor")
    vid, pid, device_version = struct.unpack_from("<HHH", descriptor, 8)
    strings_table = image.u32(0x0801A280)
    strings = {}
    for name, index in zip(("manufacturer", "product", "serial"), descriptor[14:17]):
        address = image.u32(strings_table + index * 4)
        size, kind = image.read(address, 2)
        require(kind, 3, "USB string type")
        if size < 2 or size % 2:
            raise ValueError("Invalid USB string size")
        strings[name] = image.read(address + 2, size - 2).decode("utf-16le")

    # Referenced by the original get_keyboard_id handler (8-byte copy).
    require(image.u32(0x08019C1C), 0x0801DB0E, "UID response pointer")
    uid = image.read(image.u32(0x08019C1C), 8)

    # Bounded decoding of the two MOV argument forms actually inspected in
    # the 14 vendor space-cadet cases. No general disassembler is claimed.
    cadet = []
    entries = (0x08015EDC, 0x08015EF0, 0x08015EFE, 0x08015F0C, 0x08015F1A, 0x08015F28, 0x08015F36, 0x08015F44, 0x08015F52, 0x08015F60, 0x08015F6E, 0x08015FA8, 0x08015FB6, 0x08015FC4)
    for index, address in enumerate(entries, 1):
        tap_load, stack_store, arg0, arg1, h1, h2 = struct.unpack("<6H", image.read(address, 12))
        require(tap_load & 0xFF00, 0x2300, "cadet tap-key MOVS r3")
        require(stack_store, 0x9300, "cadet fifth argument STR r3,[sp]")
        if arg1 == 0x461A:  # MOV r2,r3 (same hold and tap modifiers)
            require(arg0 & 0xFF00, 0x2300, "cadet shared modifier MOVS r3")
            hold, tap_mod = arg0 & 255, arg0 & 255
        else:
            require((arg0 & 0xFF00, arg1 & 0xFF00), (0x2200, 0x2300), "cadet separate MOVS r2/r3")
            hold, tap_mod = arg0 & 255, arg1 & 255
        require((h1 & 0xFBF0, (h2 >> 8) & 15), (0xF240, 1), "cadet MOVW r1")
        keycode = ((h1 & 15) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 255)
        require(keycode, 0x7E00 + index, "cadet keycode order")
        cadet.append({"keycode": keycode, "hold_modifier": hold, "tap_modifier": tap_mod, "tap_keycode": tap_load & 255, "case_address": hex(address)})
    require(bl_target(image, 0x08015EEA), 0x0801D4C8, "shared space-cadet helper")
    xz_address = BASE + image.data.index(b"\xfd7zXZ\x00")
    require(xz_address, 0x0801DFA8, "embedded Vial definition location")
    decoder = lzma.LZMADecompressor()
    decoded = decoder.decompress(image.data[xz_address - BASE:], max_length=1024 * 1024)
    if not decoder.eof:
        raise ValueError("Incomplete or oversized definition")
    definition = json.loads(decoded)
    require(definition["matrix"], {"rows": 4, "cols": 12}, "definition matrix")
    require(len(definition["customKeycodes"]), 22, "custom-keycode descriptions")

    # Persistent storage numbers require the inspected instructions too.
    for address, pattern in {
        0x0801870A: "baf5005f",  # CMP.W r10,#0x2000
        0x0801871C: "0321",      # MOVS r1,#3
        0x08018772: "b8f5805f",  # CMP.W r8,#0x1000
    }.items():
        require(image.read(address, len(bytes.fromhex(pattern))), bytes.fromhex(pattern), f"storage {address:#x}")
    require((image.u32(0x08018DAC), image.u32(0x08018DB0)), (0x2000FFFC, 0xF01669EF), "boot request marker")
    require((image.u32(0x0801B02C), image.u32(0x0801B030)), (0xE000ED00, 0x05FA0004), "SCB reset request")
    result = {
        "target": "firmware/origin/FAve40H_VIAL.uf2",
        "uf2_sha256": ORIGINAL_SHA256,
        "payload_sha256": PAYLOAD_SHA256,
        "source_reconstruction_complete": False,
        "flash_ready": False,
        "application": {"base": hex(BASE), "payload_bytes": len(image.data), "reset_vector": "0x080102fd", "early_init": "0x0801b034", "main_candidate": "0x080183a0"},
        "factory_keymap": {"dynamic_layers": 4, "compiled_default_layers": 3, "table": hex(table), "compiled_table_bytes": 288, "fourth_layer": "KC_TRNS in ALL 48 matrix cells; generated by reset code, not read after the 3-layer table", "raw_keycodes": keymaps, "expanded_little_endian_sha256": hashlib.sha256(factory_bytes).hexdigest()},
        "matrix": {"rows": [pin_name(v) for v in rows], "columns": [pin_name(v) for v in columns], "rows_encoded": rows, "columns_encoded": columns, "row_table": hex(rows_table), "column_table": hex(cols_table), "diode_direction": "ROW2COL", "physical_wiring_verified": False},
        "board": {"gpio_table": hex(gpio_table), "gpio_register_defaults": gpio_defaults, "pllcfgr": hex(pll), "cfgr": hex(cfgr), "hse_hz_inferred_for_usb": 16000000, "sysclk_hz_inferred": 48000000, "silicon_identified": False},
        "usb": {"descriptor": hex(descriptor_address), "vid": hex(vid), "pid": hex(pid), "device_version_bcd": hex(device_version), **strings, "serial_is_not_a_verified_source_revision": True},
        "vial": {"uid_bytes": list(uid), "definition_address": hex(xz_address), "definition_sha256": hashlib.sha256(decoded).hexdigest(), "lighting": definition.get("lighting"), "custom_keycode_count": len(definition["customKeycodes"])},
        "vendor_space_cadet": {"helper": "0x0801d4c8", "parameters": cadet, "timing_state_machine_reconstructed": False},
        "storage": {"logical_bytes": 4096, "backing_bytes": 8192, "sector_index": 3, "keymap_start": 0x29, "keymap_end_exclusive": 0x1A9, "qmk_settings_end_exclusive": 0x1D1, "tap_dance": {"start": 0x1D1, "entries": 16, "stride": 10}, "combo": {"start": 0x271, "entries": 16, "stride": 10}, "key_override": {"start": 0x311, "entries": 16, "stride": 10}, "alt_repeat": {"start": 0x3B1, "entries": 32, "stride": 6}, "macro": {"start": 0x471, "bytes": 2959}, "layout_migration_verified": False},
        "boot_request": {"ram_address": "0x2000fffc", "magic": "0xf01669ef", "reset_routine": "0x0801b010", "bootloader_in_supplied_image": False, "recovery_verified": False},
        "witnesses": {name: {"address": hex(address), "bytes": pattern} for name, (address, pattern) in WITNESSES.items()},
    }
    return result, definition


def artifacts(result: dict, definition: dict) -> dict[str, str]:
    """Deterministic data/model source, NOT a complete board/firmware target."""
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Reconstructed from manufacturer ORIGINAL Vial binary; names are new.
// FORENSIC MODEL ONLY. Not a complete QMK firmware and NOT safe to flash.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_LAYERS 4
#define ORIGINAL_VIAL_ROWS 4
#define ORIGINAL_VIAL_COLS 12
extern const uint16_t original_vial_factory_keymaps[4][4][12];
void original_vial_reset_keymaps(uint16_t output[4][4][12]);
bool original_vial_keycode_address(unsigned layer, unsigned row, unsigned col, uint16_t *address);
'''
    arrays = []
    for index, layer in enumerate(result["factory_keymap"]["raw_keycodes"]):
        rows = ["        { " + ", ".join(f"0x{value:04X}" for value in row) + " }" for row in layer]
        arrays.append(f"    // Layer {index}" + (" (reset code fills KC_TRNS)" if index == 3 else " (compiled table)") + "\n    {\n" + ",\n".join(rows) + "\n    }")
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Binary-backed source reconstruction, NOT manufacturer file/symbol recovery.
// For inspection/host tests only: includes the factory boot/reset keycode.
#include "factory_defaults.h"
const uint16_t original_vial_factory_keymaps[4][4][12] = {
''' + ",\n".join(arrays) + '''
};

// Semantic reconstruction of 0x08015824's KEYMAP portion only.
// The original also resets tap dance/combos/etc.; this function does NOT.
void original_vial_reset_keymaps(uint16_t output[4][4][12]) {
    for (unsigned layer = 0; layer < 4; ++layer)
        for (unsigned row = 0; row < 4; ++row)
            for (unsigned col = 0; col < 12; ++col)
                output[layer][row][col] = original_vial_factory_keymaps[layer][row][col];
}

// Bounds/address arithmetic from 0x08014548; no EEPROM access performed.
bool original_vial_keycode_address(unsigned layer, unsigned row, unsigned col, uint16_t *address) {
    if (layer >= 4 || row >= 4 || col >= 12 || address == 0) return false;
    *address = (uint16_t)(0x29 + layer * 0x60 + row * 0x18 + col * 2);
    return true;
}
'''
    board = '''// SPDX-License-Identifier: GPL-2.0-or-later
// ORIGINAL Vial early-init data only. Does not configure hardware.
#pragma once
#include <stdint.h>
#define ORIGINAL_VIAL_APP_BASE 0x08010000u
#define ORIGINAL_VIAL_PLLCFGR 0x04413010u
#define ORIGINAL_VIAL_CFGR 0x38881000u
struct original_vial_gpio_defaults {
    uint32_t moder, otyper, ospeedr, pupdr, odr, afrl, afrh;
};
// Order A,B,C,D,E,H. Exact packed constants from 0x0801EA14.
static const struct original_vial_gpio_defaults original_vial_gpio[6] = {
'''
    for port, registers in result["board"]["gpio_register_defaults"].items():
        board += "    { " + ", ".join(f"0x{v:08X}u" for v in registers.values()) + f" }}, // GPIO{port}\n"
    board += "};\n"
    vendor_header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Recovered vendor call arguments only, NOT the complete timing/USB behavior.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_cadet_args { uint8_t hold_modifier, tap_modifier, tap_keycode; };
bool original_vial_cadet_parameters(unsigned keycode, struct original_vial_cadet_args *output);
'''
    vendor_source = '''// SPDX-License-Identifier: GPL-2.0-or-later
#include "vendor_parameters.h"
static const struct original_vial_cadet_args parameters[14] = {
'''
    for row in result["vendor_space_cadet"]["parameters"]:
        vendor_source += "    { " + ", ".join(f"0x{row[k]:02X}" for k in ("hold_modifier", "tap_modifier", "tap_keycode")) + f" }}, // 0x{row['keycode']:04X}\n"
    vendor_source += '''};
bool original_vial_cadet_parameters(unsigned keycode, struct original_vial_cadet_args *output) {
    if (keycode < 0x7E01 || keycode > 0x7E0E || output == 0) return false;
    *output = parameters[keycode - 0x7E01];
    return true;
}
'''
    dump = lambda value: json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    return {"factory_defaults.h": header, "factory_defaults.c": source, "board_defaults.h": board, "vendor_parameters.h": vendor_header, "vendor_parameters.c": vendor_source, "vial-definition.json": dump(definition), "evidence.json": dump(result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--export", type=Path, help="Write artifacts to a NEW directory; refuse overwrite")
    group.add_argument("--check", type=Path, help="Verify exported artifacts without modifying them")
    args = parser.parse_args()
    try:
        if args.uf2.stat().st_size > 1024 * 1024:
            raise ValueError("Input exceeds 1 MiB")
        result, definition = recover(args.uf2.read_bytes())
        files = artifacts(result, definition)
        if args.export:
            args.export.mkdir()  # Exclusive creation: do not overwrite existing work.
            for name, content in files.items():
                with (args.export / name).open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(content)
            print(f"Exported {len(files)} forensic source/data files to {args.export}; NOT flash-ready")
        elif args.check:
            for name, content in files.items():
                require((args.check / name).read_bytes(), content.encode("utf-8"), f"export {name}")
            print(f"Verified {len(files)} original-only artifacts; NOT flash-ready")
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    except (ValueError, OSError, struct.error, lzma.LZMAError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
