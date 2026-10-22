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
    "rgb_set_grb": (0x080132EC, "30b5044d00eb40002c182a546170a37030bd00bf"),
    "rgb_encode_pwm": (0x08013320, "f0b5174a174c102092f801c017789678214600234cfa03f515f0010f14bf152508250d6247fa03f515f0010f14bf1525082541f8045946fa03f515f0010f03f1010314bf15250825082b4d64e2d11830b0f5da6f02f1030204f16004d4d1f0bd"),
    "rgb_pin_and_buffer_init": (0x08013924, "38b5534c0023224608210133b3f5d86f42f8041bf9d14ff4607200214d48fef7bbf84d489a224ff4806107f0cdff"),
    "rgb_dma_start": (0x0801399E, "002282f31188394bd96901f13c003649086337484c6388624ff4f460c862886a40f001008862"),
    "rgb_timer_start": (0x08013A28, "01255060116255611061d16014b14ff4004151648521116002221a70002282f31188302181f31188d96841f00401d960db69da6382f3118838bd"),
    "pwm_object_tim2": (0x080184B6, "754b754e7649764d042200244ff001081a744ff0804283f80080dc605c601c76da61"),
    "vendor_backspace_delete": (0x08015EBA, "3a4b1b7835b11bb14c20fef760f8d1e62a20fae71bb14c20fef7eaf8cae62a20fae7"),
    "shift_edge_tracking": (0x08015AB6, "24f004039bb2e12b01d17c4b1d70"),
    "rgb_chunk_filter": (0x080156F8, "3b78c4b2c0f307252bb9dff8a0802646f3b2ab4208d37b781bb9244ee3b2ab4210d303b0bde8f08308eb060393f8c0305a0705d500231a4619463046fff7a0f90136e5e7331993f8c0309b0705d500231a4619462046fff793f90134dee7"),
    "clear_settings_then_reboot_no_return": (0x08015FD2, "002d3ff44baefef704fafdf776ff"),
    "cadet_term_lookup": (0x0801D4A0, "1fb5a0f5ae43ff2b09d801a9c0b2f8f757fa20b9bdf80c0005b05df804fb014b188bf9e7"),
    "cadet_helper_state_machine": (0x0801D4C8, "2de9f8431d469df82080254b8946144668b11a70fdf74aff224b04f0070418800120a040c0b2bde8f843f6f73fbd1e7896422ed11b4b1f88fdf738ffc71b4846fff7caffbfb2b84223d905f12004ae42e4b210d006f00700012606fa00f0c0b2f6f7b6fd072c06d805f0070006fa00f0c0b2f6f71bfd4046f6f722fe072c0dd805f007050120a840bde8f843c0b2f6f79fbd04f007040120a040f5e7bde8f883"),
    "cadet_reset_slice": (0x08017346, "944b0022a4f5e0451a70"),
    "cadet_core_dispatch": (0x08016646, "a4f5f843183b9af80500062b00f27386dfe803f0b2baa2aac2cad2"),
    "cadet_builtin_cases": (0x0801679E, "26230093e1231a4647f61a41fff79ebb27230093e5231a4647f61b41fff796bb26230093e022e12347f61841fff78ebb27230093e422e52347f61941fff786bb26230093e222e12347f61c41fff77ebb27230093e622e52347f61d41fff776bb28230093e522012347f61e41fff76ebb"),
    "cadet_core_default": (0x0801733C, "9af80510002900f0c780944b0022a4f5e0451a70"),
    "vendor_dispatch_table": (0x08015E96, "a4f5fc44013c142c0cd8dfe804f01c262d343b424950575e65828990979ea7adb4bdc4"),
    "tap_code_delay_wrapper": (0x08014188, "034b39280cbf198cd98bfff7d9bf"),
    "tap_code_delay_body": (0x08014148, "38b50c460546fff71bffa4b10b4940f2e730a4fb014120184ff47a724ff0000341f10001fdf7f4fe07f078f92846bde83840fff796bf0120f6e7"),
    "qmk_settings_ram_reset": (0x080144DC, "184baf2210b51a8041f288325a800a229a805a81da8128229a82c821142032229984d880da821983002205211e2098815a835020998308241c8118825c82da83188483f82210da84"),
    "qmk_settings_load_40_bytes": (0x08014218, "70b50b4d40f2a91440f2d1162046fff7e8ff0134b44205f8010bf7d1054d1a242b6903b19847013c05f11405f8d170bd"),
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
    "backing_program_wrapper": (0x0801280C, "0b4b37b51c680b4b01911b7804440bb1c9430191084b186803680422dd68214601aba847b0fa80f0400903b030bd"),
    "backing_read_wrapper": (0x08012848, "38b50f4b1d680f4b0544186803685b680c46984743690c485a590c4d0c492d780123037000230b7005b1d2430370087818b10b702360002038bd22600120fbe7"),
    "backing_startup_one": (0x080184C2, "4ff00108"),
    "backing_attribute_flag": (0x0801863C, "037803ea08031370"),
    "backing_sector_three": (0x0801871C, "032102f0bdfe0a4b1860"),
    "journal_entry_decode_copy": (0x08018824, "119b6bb313f0c00f04f104081493d9b241f0b5831d04c3f3074205f4e025154303f47f431d434fead10905ebd101b1f5805f01f2a48319f0060f00f0d98115a94046f9f7efff002801f0998308344a460df153017819f9f709f8"),
    "journal_one_word_cursor": (0x08018C14, "44462ce6"),
    "journal_reject_exit": (0x08019FA2, "44460020fef76ebc"),
    "snapshot_read_and_hash_init": (0x08018758, "be4f4ff0000807eb08014046faf770f8002801f0148408f10408b8f5805ff2d1b74cb84db5480021"),
    "snapshot_checksum_compare": (0x080187F0, "14a94ff48050faf727f820b115a941f20400faf721f8dde91423ab4208bfa24201d0fbf7f7fe"),
    "snapshot_ram_clear": (0x08014604, "08b5064b4ff4805218460021fdf754fa00f5805341f208021a6008bd"),
    "via_prefix_validity": (0x0801AE04, "08b52520f9f7f7f94b2801d0002008bd2620f9f7f0f9f428f8d12720f9f7ebf9a0f1290358425841f1e7"),
    "early_via_gate": (0x08018B5C, "02f052f908b902f064f9"),
    "core_prefix_gate": (0x08018BBC, "2046faf7f3ff4ff6e36398422bd0fbf70bfc"),
    "core_gate_via_branch": (0x08018C22, "02f0eff80028d1d1cee7"),
    "tap_dance_reset_region": (0x08015898, "40f2d11440f2712520460a2203a90a3407f062feac42f7d1"),
    "combo_reset_region": (0x080158BA, "40f2113520460a2203a90a3407f053feac42f7d1"),
    "override_reset_region": (0x080158E6, "40f2b13520460a2203a90a3407f03dfeac42f7d1"),
    "alt_repeat_reset_region": (0x08015902, "40f271452046062203a9063407f02ffeac42f7d1"),
}


def require(actual, expected, label):
    if actual != expected:
        raise ValueError(f"Original evidence mismatch: {label}")
    return actual


def recover_settings(image) -> dict:
    """Bounded decoding of original QS RAM writes and ARM32 prototype records."""
    ram = image.u32(0x08014540)
    require([image.u32(a) for a in (0x08014248, 0x08014470)], [ram, ram], "QS load/save/reset agreement")
    require(ram, 0x200011C8, "QS RAM base")
    table = image.u32(0x0801424C)
    require(table, 0x0801E3D4, "QS prototype table")
    protos = []
    for index in range(26):
        qsid, size, bit, ptr, get, set_, notify = struct.unpack("<HBBIIII", image.read(table + index * 20, 20))
        if ptr and not (ram <= ptr and ptr + size <= ram + 40):
            raise ValueError("QS prototype pointer outside settings RAM")
        protos.append({"qsid": qsid, "size": size, "bit": bit, "offset": ptr - ram if ptr else None, "get": hex(get), "set": hex(set_), "notify": hex(notify)})
    require([p["qsid"] for p in protos], [*range(1, 8), *range(9, 28)], "QS ids")
    # Only the inspected prefix, before the first EEPROM save call, is decoded.
    halfword = lambda address: struct.unpack("<H", image.read(address, 2))[0]
    registers = {}
    reset = [None] * 40
    pc = 0x080144DC
    while pc < 0x08014524:
        op = halfword(pc)
        width = 2
        store = None
        if op & 0xFF00 == 0x4B00:  # LDR r3 literal
            registers[3] = ldr_literal(image, pc)
        elif op == 0xB510:  # PUSH {r4,lr}; no modeled data write
            pass
        elif op & 0xF800 == 0x2000:  # MOVS low register, immediate
            registers[(op >> 8) & 7] = op & 255
        elif op & 0xFBF0 == 0xF240:  # MOVW (the observed 5000-ms timeout)
            second = halfword(pc + 2)
            registers[(second >> 8) & 15] = ((op & 15) << 12) | (((op >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 255)
            width = 4
        elif op & 0xF800 == 0x8000:  # STRH immediate
            require((op >> 3) & 7, 3, "QS STRH base register")
            store = ((op >> 6) & 31) * 2, op & 7, 2
        elif op == 0xF883:  # The inspected STRB.W [r3,#0x22]
            second = halfword(pc + 2)
            store = second & 0xFFF, (second >> 12) & 15, 1
            width = 4
        else:
            raise ValueError(f"Unsupported QS reset instruction at {pc:#x}")
        if store:
            offset, reg, count = store
            require(registers.get(3), ram, "QS store base")
            if reg not in registers or offset + count > 40:
                raise ValueError("Invalid QS reset store")
            for byte in range(count):
                reset[offset + byte] = (registers[reg] >> (byte * 8)) & 255
        pc += width
    require([i for i, value in enumerate(reset) if value is None], [35], "QS reset preserves unused byte")
    require(bl_target(image, 0x08014524), 0x08014448, "QS prefix stops before EEPROM save")
    return {"ram_base": hex(ram), "logical_start": 0x1A9, "logical_end_exclusive": 0x1D1,
        "bytes": 40, "prototype_table": hex(table), "prototype_stride": 20, "prototypes": protos,
        "reset_prefix": "0x080144dc..0x08014524", "reset_bytes": reset,
        "preserved_offsets": [35], "reset_eeprom_or_callbacks_executed": False,
        "manufacturer_symbols_recovered": False}


def recover_snapshot(image) -> dict:
    cache = image.u32(0x08018A54)
    require([image.u32(a) for a in (0x08014774, 0x08014620)], [cache, cache], "snapshot cache agreement")
    basis = image.u32(0x08018A58) | (image.u32(0x08018A5C) << 32)
    require(basis, image.u32(0x08014778) | (image.u32(0x0801477C) << 32), "snapshot FNV bases agree")
    require(basis, 0xCBF29CE484222325, "FNV1a64 basis")
    require(image.u32(0x08014780), cache + 4096, "snapshot write cursor follows cache")
    return {"cache_ram": hex(cache), "logical_bytes": 4096, "backing_transfer_bytes": 4,
        "checksum_start": 4096, "checksum_bytes": 8, "log_start": 4104,
        "fnv_basis": hex(basis), "fnv_prime": hex(0x100000001B3),
        "checksum_format": "little-endian FNV1a64 over 4096 translated logical bytes; NOT raw physical flash",
        "read_slice": "0x08018758..0x08018816; data failure exits through 0x08019f96, stop before 0x08018896",
        "match": "cache preserved, incoming write cursor unchanged; log playback follows outside model",
        "mismatch": "cache zeroed, write cursor=0x1008; still proceeds to log playback, not immediate flash erase",
        "data_read_failure": "cache zeroed, write cursor=0x1008; exits consolidated load before log playback",
        "checksum_read_failures_modeled": False, "log_playback_modeled": False,
        "physical_flash_translation_verified": False, "erase_write_or_migration_executed": False,
        "reference_url": "https://raw.githubusercontent.com/vial-kb/vial-qmk/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/wear_leveling/wear_leveling.c",
        "reference_sha256": "a5480ffe8cc544414f5ef63d47f86c27c7f21e623c57021514d7dc9113d6542b",
        "reference_scope": "candidate snapshot/FNV semantics only, not exact manufacturer revision or full backend compatibility"}


def recover_prefix(image) -> dict:
    """Observed prefix accesses and the two startup gates, never reset execution."""
    def immediate(pc, register, opcode=0x2000):
        word = struct.unpack("<H", image.read(pc, 2))[0]
        require(word & 0xFF00, opcode | (register << 8), "prefix immediate")
        return word & 255

    addresses = [immediate(pc, 0) for pc in (0x0801AE06, 0x0801AE14, 0x0801AE1E)]
    require(addresses, list(range(addresses[0], addresses[0] + 3)), "VIA stamp addresses")
    magic = [immediate(0x0801AE0C, 0, 0x2800), immediate(0x0801AE1A, 0, 0x2800), image.read(0x0801AE26, 1)[0]]
    layout = immediate(0x0801AE76, 0)
    require(layout, addresses[-1] + 1, "VIA layout address")
    fields = []
    for name, pc, reg, size in (("magic", 0x080143EE, 0, 2), ("debug", 0x080143F6, 0, 1),
        ("default_layer", 0x08014400, 0, 1), ("keymap", 0x08013BE8, 0, 2),
        ("keyboard", 0x08014420, 0, 4), ("user", 0x0801442E, 0, 4),
        ("rgb_matrix", 0x08013CDE, 1, 8)):
        fields.append({"reference_label": name, "offset": immediate(pc, reg), "size": size, "address_instruction": hex(pc)})
    # MOVW r3,#imm16 in the observed later gate.
    first, second = struct.unpack("<HH", image.read(0x08018BC2, 4))
    require((first & 0xFBF0, (second >> 8) & 15), (0xF240, 3), "core gate MOVW")
    core_magic = ((first & 15) << 12) | (((first >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 255)
    return {"bytes_before_keymap": layout + 1, "observed_core_accesses": fields,
        "core_magic_u16": core_magic, "via_magic_start": addresses[0], "via_magic_bytes": magic,
        "build_id_low24": int.from_bytes(bytes(magic), "little"), "build_id_high8_known": False,
        "layout_options_start": layout, "layout_options_bytes": 1,
        "early_gate": "0x08018b5c..0x08018b66: invalid VIA stamp calls 0x0801ae2e",
        "later_gate": "0x08018bbc..0x08018bce via 0x08018c22: invalid core magic OR invalid VIA stamp calls 0x080143e4",
        "gates_are_isolated_not_a_full_boot_simulation": True,
        "reset_or_flash_operations_executed": False, "full_prefix_field_semantics_proven": False}


def recover_dynamic_records(image) -> list[dict]:
    """Decode only the four observed stack-template initializers, not EEPROM code."""
    records = []
    start = None
    # Fixed slice boundaries are tied to the original hash and loop witnesses.
    for name, begin, end, loop, stride in (
        ("tap_dance", 0x08015880, 0x08015898, 0x0801589C, 10),
        ("combo", 0x080158B0, 0x080158BA, 0x080158BA, 10),
        ("key_override", 0x080158CE, 0x080158E6, 0x080158E6, 10),
        ("alt_repeat", 0x080158FA, 0x08015902, 0x08015902, 6),
    ):
        def half(pc):
            return struct.unpack("<H", image.read(pc, 2))[0]

        def movw(pc, expected_register):
            first, second = half(pc), half(pc + 2)
            require(first & 0xFBF0, 0xF240, "record MOVW opcode")
            require((second >> 8) & 15, expected_register, "record MOVW register")
            return ((first & 15) << 12) | (((first >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 255)

        if start is None:
            start = movw(0x08015898, 4)
        finish = movw(loop, 5)
        # These loop bodies add the stride to r4, then call the same backend.
        require(half(loop + 10), 0x3400 | stride, "record loop stride")
        require(bl_target(image, loop + 12), 0x0801D570, "record write boundary")
        frame = [None] * stride
        value, pc = None, begin
        while pc < end:
            op, width, store = half(pc), 2, None
            if op & 0xFF00 == 0x2300:  # MOVS r3,#imm8
                value = op & 255
            elif op & 0xFBF0 == 0xF240:  # MOVW r3,#imm16
                value, width = movw(pc, 3), 4
            elif op & 0xFF00 == 0x9300:  # STR r3,[sp,#imm*4]
                store = (op & 255) * 4, 4
            elif op in (0xF8AD, 0xF88D):  # STRH.W / STRB.W r3,[sp,#imm12]
                second, width = half(pc + 2), 4
                require(second >> 12, 3, "record store register")
                store = second & 0xFFF, 2 if op == 0xF8AD else 1
            else:
                raise ValueError(f"Unsupported record initializer at {pc:#x}")
            if store:
                offset, size = store[0] - 12, store[1]
                if value is None or offset < 0 or offset + size > stride:
                    raise ValueError("Record initializer store outside template")
                frame[offset:offset + size] = [(value >> (8 * i)) & 255 for i in range(size)]
            pc += width
        require(pc, end, "record initializer boundary")
        if None in frame or finish <= start or (finish - start) % stride:
            raise ValueError("Incomplete record initializer or invalid interval")
        records.append({"name": name, "start": start, "end_exclusive": finish,
            "entries": (finish - start) // stride, "stride": stride, "reset_bytes": frame,
            "initializer_range": [hex(begin), hex(end)]})
        start = finish
    return records


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

    # RGB is recovered from this image's code and pointers, not the old port.
    require((image.u32(0x08013300), image.u32(0x08013380)), (0x20005064, 0x20005064), "GRB buffer")
    require((image.u32(0x08013A74), image.u32(0x08013384)), (0x200031E0, 0x200031FC), "PWM buffer / bit-7 pointer")
    require(image.u32(0x08013A78), 0x200031E0 + 1728 * 4, "PWM reset tail")
    require(image.u32(0x08013A7C), 0x40020400, "GPIOB pin-mode call base")
    require((image.u32(0x08013A8C), image.u32(0x0801868C)), (0x200011A8, 0x200011A8), "PWM object init/use agreement")
    require((image.u32(0x08013A88), image.u32(0x08013A90)), (0x40026000, 0x06035540), "DMA1 and stream mode")
    require((image.u32(0x08013A98), image.u32(0x08013A9C)), (48000000, 24000000), "PWM timer input/tick clocks")
    require(image.u32(0x08013A94), 0x0801E6D8, "PWM config pointer")
    require(struct.unpack("<3I", image.read(0x0801E6D8, 12)), (24000000, 30, 0), "PWM config frequency/period/callback")
    led_table = image.u32(0x080157A4)
    require(led_table, 0x0801DEA0, "LED configuration pointer")
    led_matrix = [list(image.read(led_table + row * 12, 12)) for row in range(4)]
    led_positions = [list(image.read(led_table + 48 + i * 2, 2)) for i in range(72)]
    led_flags = list(image.read(led_table + 192, 72))
    require(led_flags, [4] * 42 + [2] * 30, "switch/underglow flags")
    require(sorted(v for row in led_matrix for v in row if v != 255), list(range(42)), "42 distinct matrix LEDs")
    require((image.u32(0x080157A0), image.u32(0x08016294), image.u32(0x08018DCC)), (0x20001EE4,) * 3, "RGB flags boot/handler/filter agreement")
    require((image.u32(0x08015CB4), image.u32(0x08015FA4)), (0x20001C40,) * 2, "shift edge state agreement")
    # These six cases only change RAM bytes; they do not write EEPROM.
    for address, pattern in {
        0x08015FE0: "002d3ff444aeab4a137883f0010313703de6",
        0x08015FF2: "002d3ff43baea64b012204e0",
        0x08015FFE: "002d3ff435aea34b00221a7030e6",
        0x0801600C: "002d3ff42eaea04a537883f00103537027e6",
        0x0801601E: "002d3ff425ae9b4b01225a7020e6",
        0x0801602C: "002d3ff41eae984b0022f7e7",
    }.items():
        require(image.read(address, len(bytes.fromhex(pattern))), bytes.fromhex(pattern), f"RGB vendor case {address:#x}")

    require(image.u32(0x08014184), 100000, "tap-delay software tick frequency")
    require(image.u32(0x08014198), 0x200011C8, "tap-delay settings base")
    for site, target in ((0x0801414E, 0x08013F88), (0x0801416C, 0x08011F58), (0x08014170, 0x0801B464)):
        require(bl_target(image, site), target, f"tap-delay call {site:#x}")

    # Referenced by the original get_keyboard_id handler (8-byte copy).
    require(image.u32(0x08019C1C), 0x0801DB0E, "UID response pointer")
    uid = image.read(image.u32(0x08019C1C), 8)

    # Bounded decoding of the two MOV argument forms actually inspected in
    # the 14 vendor + 7 built-in space-cadet cases. No general disassembler is claimed.
    cadet = []
    entries = (0x08015EDC, 0x08015EF0, 0x08015EFE, 0x08015F0C, 0x08015F1A, 0x08015F28, 0x08015F36, 0x08015F44, 0x08015F52, 0x08015F60, 0x08015F6E, 0x08015FA8, 0x08015FB6, 0x08015FC4)
    builtin_entries = tuple(0x0801665A + 2 * offset for offset in image.read(0x0801665A, 7))
    for expected_keycode, address in zip((*range(0x7E01, 0x7E0F), *range(0x7C18, 0x7C1F)), entries + builtin_entries):
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
        require(keycode, expected_keycode, "cadet keycode order")
        cadet.append({"keycode": keycode, "hold_modifier": hold, "tap_modifier": tap_mod, "tap_keycode": tap_load & 255, "case_address": hex(address)})
    cadet, builtin_cadet = cadet[:14], cadet[14:]
    require(bl_target(image, 0x08015EEA), 0x0801D4C8, "shared space-cadet helper")
    require((image.u32(0x0801D568), image.u32(0x08017598)), (0x20001CED,) * 2, "cadet helper/reset shared last modifier")
    require(image.u32(0x0801D56C), 0x200051BC, "cadet 16-bit press timestamp")
    require(image.u32(0x0801D4C4), 0x200011C8, "cadet global settings base")
    for site, target in ((0x0801D4DC, 0x0801B374), (0x0801D500, 0x0801B374), (0x0801D508, 0x0801D4A0), (0x0801D528, 0x08014098), (0x0801D53A, 0x08013F74), (0x0801D540, 0x08014188)):
        require(bl_target(image, site), target, f"cadet call {site:#x}")
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
        "rgb": {"driver": "WS2812-compatible PWM/DMA; exact LED part unverified", "data_pin": "B10", "pal_mode": "0x9a (AF1, push-pull, highest speed)", "timer": "TIM2", "timer_base": "0x40000000", "channel_one_based": 3, "tick_hz": 24000000, "period_ticks": 30, "zero_high_ticks": 8, "one_high_ticks": 21, "dma_controller": 1, "dma_stream": 1, "dma_channel": 3, "dma_cr": "0x06035540", "circular": True, "dma_word_bits": 32, "wire_order": "GRB, MSB first", "led_count": 72, "switch_led_count": 42, "underglow_led_count": 30, "color_words": 1728, "reset_words": 224, "transfer_words": 1952, "reset_low_us_inferred": 280, "buffer_address": "0x200031e0", "grb_address": "0x20005064", "configuration_table": hex(led_table), "matrix_to_led": led_matrix, "positions": led_positions, "flags": led_flags, "physical_output_verified": False, "filter_range": "half-open chunk; flag 4 is switch, flag 2 is underglow"},
        "vendor_controls": {"backspace_delete": {"keycode": "0x7e00", "selector": "0x20001c40 last E1/E5 edge, NOT aggregate modifiers", "unshifted": "0x2a", "shifted": "0x4c", "release_rechecks_current_selector": True}, "rgb_keys": {"switch_toggle": "0x7e10", "switch_on": "0x7e11", "switch_off": "0x7e12", "underglow_toggle": "0x7e13", "underglow_on": "0x7e14", "underglow_off": "0x7e15", "press_only": True, "ram_address": "0x20001ee4", "handler_writes_eeprom": False}, "clear_and_reboot": {"keycode": "0x7e0f", "press_only": True, "calls": ["0x080143e4", "0x08013ecc"], "modeled": False}},
        "vendor_space_cadet": {"helper": "0x0801d4c8", "parameters": cadet, "builtin_parameters": builtin_cadet, "core_stage_entry": "0x08016646", "core_default_press_exit": "0x08017350", "core_default_release_exit": "0x080174d4", "core_stage_modeled": True, "verified_vendor_bypass_codes": [0x7E00, *range(0x7E10, 0x7E16)], "pipeline_before_core_modeled": False, "helper_state_machine_reconstructed": True, "timing_state_machine_reconstructed": False, "dispatcher_interruption_routing_reconstructed": False, "last_modifier_ram": "0x20001ced", "pressed_at_u16_ram": "0x200051bc", "vendor_term_source": "uint16 settings[+0x18] at 0x200011e0; custom codes do not enter tap-dance lookup", "tap_condition": "last_modifier == hold_modifier && uint16(now - pressed_at) < tapping_term", "release_clears_state": False, "reset_primitive": "0x08017346..0x08017350 clears last modifier only", "hid_and_timer_boundaries_executed": False},

        "qmk_settings": recover_settings(image),
        "tap_code": {"wrapper": "0x08014188", "delay_body": "0x08014148", "settings_base": "0x200011c8", "normal_delay_u16_offset": "0x1e", "caps_delay_u16_offset": "0x20", "caps_keycode": "0x39", "software_tick_hz_constant": 100000, "zero_delay_sleep_ticks": 1, "nonzero_delay_sleep_ticks": "(uint64(delay_ms) * 100000 + 999) / 1000", "ordered_calls": ["0x08013f88 register_code", "0x0801b464 sleep_ticks", "0x080140aa unregister_code"], "hid_reports_and_scheduler_executed": False, "physical_tick_rate_verified": False},
        "backing_wrapper": recover_backing(image),
        "journal_entry": {"scope": "one supplied first word, cache update and next cursor only",
            "cache_ram": hex(image.u32(0x08018A54)), "entry_type_bits": "first byte bits 6..7; only type 0 accepted in 4-byte backing profile",
            "address": "((byte0 & 7) << 16) | (byte1 << 8) | byte2",
            "length": "(byte0 >> 3) & 7", "payload_start": 3,
            "modeled_lengths": [0, 1, 2, 3, 4, 5], "empty": "all-zero first word: no advance",
            "one_word": "length 0 or 1: consume 4 bytes; nonzero length-0 header is accepted as no-op",
            "two_words": "length 2..5: second word read, consume 8 bytes only if successful",
            "bounds": "address + length <= 4096; length 0 at address 4096 is accepted",
            "rejected_or_second_read_failed": "no cache copy; consumed first word advances cursor by 4; full loop later requests consolidation, NOT skip",
            "lengths_6_7_modeled": False, "lengths_6_7_note": "three-bit reader field permits these lengths; copy may read beyond eight-byte temporary. Model explicitly reports UNMODELED, not firmware rejection.",
            "second_word_beyond_backing_budget_modeled": False, "first_word_read_failure_modeled": False,
            "full_replay_or_consolidation_modeled": False, "physical_flash_executed": False,
            "reference_scope": "same candidate wear_leveling.c as snapshot; 4-byte backing profile only"},
        "snapshot": recover_snapshot(image),
        "eeprom_prefix": recover_prefix(image),
        "dynamic_records": recover_dynamic_records(image),
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
// Recovered vendor parameters / RAM controls, NOT complete timing/HID behavior.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_cadet_args { uint8_t hold_modifier, tap_modifier, tap_keycode; };
bool original_vial_cadet_parameters(unsigned keycode, struct original_vial_cadet_args *output);
// Partial vendor controls only; no QMK/HID/EEPROM calls or cadet state machine.
void original_vial_shift_edge(uint16_t keycode, bool pressed, uint8_t *last_shift_edge);
uint16_t original_vial_bsdl_keycode(uint8_t last_shift_edge);
// Returns whether recognized, NOT QMK's process_record continuation flag.
bool original_vial_rgb_control(uint16_t keycode, bool pressed, uint8_t enabled[2]);
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
// Deliberately retain original last-edge behavior, including overlapping shifts.
void original_vial_shift_edge(uint16_t keycode, bool pressed, uint8_t *last_shift_edge) {
    if (keycode == 0xE1 || keycode == 0xE5) *last_shift_edge = pressed;
}
// Original checks this again on release, not a saved key from the press.
uint16_t original_vial_bsdl_keycode(uint8_t last_shift_edge) {
    return last_shift_edge ? 0x4C : 0x2A;
}
bool original_vial_rgb_control(uint16_t keycode, bool pressed, uint8_t enabled[2]) {
    if (keycode < 0x7E10 || keycode > 0x7E15) return false;
    if (!pressed) return true;
    unsigned index = (keycode - 0x7E10) / 3;
    switch ((keycode - 0x7E10) % 3) {
        case 0: enabled[index] ^= 1; break;
        case 1: enabled[index] = 1; break;
        case 2: enabled[index] = 0; break;
    }
    return true;
}
'''
    dump = lambda value: json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    return {"factory_defaults.h": header, "factory_defaults.c": source, "board_defaults.h": board, "vendor_parameters.h": vendor_header, "vendor_parameters.c": vendor_source, "vial-definition.json": dump(definition), "evidence.json": dump(result), **rgb_artifacts(result["rgb"]), **cadet_artifacts(result["vendor_space_cadet"]["builtin_parameters"]), **tap_artifacts(), **prefix_artifacts(result["eeprom_prefix"]), **snapshot_artifacts(result["snapshot"]), **journal_artifacts(), **backing_artifacts()}


def rgb_artifacts(rgb: dict) -> dict[str, str]:
    """RAM-only semantic model. Original encode updates data, not reset tail."""
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// ORIGINAL binary-backed data / RAM-only model. NOT a hardware driver.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_RGB_LEDS 72
#define ORIGINAL_VIAL_PWM_COLOR_WORDS 1728
#define ORIGINAL_VIAL_PWM_WORDS 1952
extern const uint8_t original_vial_led_matrix[4][12];
extern const uint8_t original_vial_led_positions[72][2];
extern const uint8_t original_vial_led_flags[72];
// All pointer arguments must reference complete, non-overlapping arrays.
void original_vial_pwm_init(uint32_t output[1952]);
void original_vial_pwm_encode(const uint8_t grb[72][3], uint32_t output[1952]);
// Valid chunk: 0 <= begin <= end <= 72. Invalid range leaves colors unchanged.
bool original_vial_rgb_filter(uint8_t grb[72][3], unsigned begin, unsigned end, const uint8_t enabled[2]);
'''
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// No MMIO, DMA, interrupts or EEPROM. NOT a flashable QMK implementation.
#include "rgb_model.h"
'''
    for name, shape, values in (("matrix", "[4][12]", rgb["matrix_to_led"]), ("positions", "[72][2]", rgb["positions"])):
        source += f"const uint8_t original_vial_led_{name}{shape} = {{\n"
        source += ",\n".join("    { " + ", ".join(str(v) for v in row) + " }" for row in values) + "\n};\n"
    source += "const uint8_t original_vial_led_flags[72] = {\n    " + ", ".join(str(v) for v in rgb["flags"]) + "\n};\n"
    source += '''
// 0x08013924: initial black data and 224 reset slots held low.
void original_vial_pwm_init(uint32_t output[1952]) {
    for (unsigned i = 0; i < 1952; ++i) output[i] = i < 1728 ? 8 : 0;
}
// 0x08013320: GRB bytes, MSB first. The reset tail is never rewritten.
void original_vial_pwm_encode(const uint8_t grb[72][3], uint32_t output[1952]) {
    for (unsigned led = 0; led < 72; ++led)
        for (unsigned channel = 0; channel < 3; ++channel)
            for (unsigned bit = 0; bit < 8; ++bit)
                output[led * 24 + channel * 8 + bit] = (grb[led][channel] & (0x80u >> bit)) ? 21 : 8;
}
// Post-effect filtering from 0x080156F8..0x08015754, BEFORE flush.
// Caps Lock override LED 22 is set before this and can also be suppressed.
bool original_vial_rgb_filter(uint8_t grb[72][3], unsigned begin, unsigned end, const uint8_t enabled[2]) {
    if (begin > end || end > 72) return false;
    for (unsigned led = begin; led < end; ++led)
        if ((!enabled[0] && (original_vial_led_flags[led] & 4)) ||
            (!enabled[1] && (original_vial_led_flags[led] & 2)))
            for (unsigned channel = 0; channel < 3; ++channel) grb[led][channel] = 0;
    return true;
}
'''
    return {"rgb_model.h": header, "rgb_model.c": source}


def cadet_artifacts(builtin: list[dict]) -> dict[str, str]:
    """Vendor helper / reached-core-stage state and call intents, not HID reports."""
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// ORIGINAL helper state/ordered call intents only. No QMK, HID, clock or EEPROM.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_cadet_state {
    uint8_t last_modifier;
    uint16_t pressed_at;
};
enum original_vial_cadet_effect_kind {
    ORIGINAL_VIAL_CADET_REGISTER_MODS = 1,
    ORIGINAL_VIAL_CADET_UNREGISTER_MODS = 2,
    ORIGINAL_VIAL_CADET_TAP_CODE = 3
};
struct original_vial_cadet_effect { uint8_t kind, argument; };
struct original_vial_cadet_trace {
    uint8_t count;
    struct original_vial_cadet_effect effects[4];
};
// Only the 14 vendor codes 0x7E01..0x7E0E. Shared state is NOT per-key.
// now/term are caller-provided uint16 milliseconds. No live clock is read.
// Unknown keycode or null state/trace returns false without modifying outputs.
bool original_vial_cadet_event(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace);
// Core stage ONLY: caller must already have passed earlier vendor/feature gates.
// true: built-in 0x7C18..0x7C1E consumed. false: continue after optional reset.
// Other press clears last_modifier; other release changes no state. Trace clears.
// Null state/trace returns false unchanged. NOT QMK's continuation return flag.
bool original_vial_cadet_core_stage(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace);
// Explicit primitive only. Caller decides which dispatcher paths interrupt.
// Non-null state required; timer is retained. Does not release modifiers.
void original_vial_cadet_reset(struct original_vial_cadet_state *state);
'''
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original helper 0x0801D4C8 + isolated core stage 0x08016646; NOT full routing.
// Effects are call intents, NOT complete USB reports or tap-code delays.
#include "cadet_model.h"
#include "vendor_parameters.h"
static uint8_t mod_bit(uint8_t code) { return (uint8_t)(1u << (code & 7)); }
static bool is_modifier(uint8_t code) { return (uint8_t)(code + 0x20) < 8; }
static void emit(struct original_vial_cadet_trace *trace, uint8_t kind, uint8_t argument) {
    trace->effects[trace->count++] = (struct original_vial_cadet_effect){kind, argument};
}
static void perform_cadet(struct original_vial_cadet_state *state,
    struct original_vial_cadet_args args, bool pressed, uint16_t now,
    uint16_t tapping_term, struct original_vial_cadet_trace *trace) {
    *trace = (struct original_vial_cadet_trace){0};
    if (pressed) {
        state->last_modifier = args.hold_modifier;
        state->pressed_at = now;
        emit(trace, ORIGINAL_VIAL_CADET_REGISTER_MODS, mod_bit(args.hold_modifier));
    } else if (state->last_modifier == args.hold_modifier &&
               (uint16_t)(now - state->pressed_at) < tapping_term) {
        if (args.hold_modifier != args.tap_modifier) {
            emit(trace, ORIGINAL_VIAL_CADET_UNREGISTER_MODS, mod_bit(args.hold_modifier));
            if (is_modifier(args.tap_modifier))
                emit(trace, ORIGINAL_VIAL_CADET_REGISTER_MODS, mod_bit(args.tap_modifier));
        }
        emit(trace, ORIGINAL_VIAL_CADET_TAP_CODE, args.tap_keycode);
        if (is_modifier(args.tap_modifier))
            emit(trace, ORIGINAL_VIAL_CADET_UNREGISTER_MODS, mod_bit(args.tap_modifier));
    } else {
        emit(trace, ORIGINAL_VIAL_CADET_UNREGISTER_MODS, mod_bit(args.hold_modifier));
    }
    // Original release paths leave BOTH shared fields intact.
}
bool original_vial_cadet_event(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace) {
    struct original_vial_cadet_args args;
    if (state == 0 || trace == 0 || !original_vial_cadet_parameters(keycode, &args)) return false;
    perform_cadet(state, args, pressed, now, tapping_term, trace);
    return true;
}
static const struct original_vial_cadet_args builtin_parameters[7] = {
@BUILTIN_PARAMETERS@
};
bool original_vial_cadet_core_stage(struct original_vial_cadet_state *state,
    unsigned keycode, bool pressed, uint16_t now, uint16_t tapping_term,
    struct original_vial_cadet_trace *trace) {
    if (state == 0 || trace == 0) return false;
    if (keycode >= 0x7C18 && keycode <= 0x7C1E) {
        perform_cadet(state, builtin_parameters[keycode - 0x7C18], pressed, now, tapping_term, trace);
        return true;
    }
    *trace = (struct original_vial_cadet_trace){0};
    if (pressed) original_vial_cadet_reset(state);
    return false;
}
void original_vial_cadet_reset(struct original_vial_cadet_state *state) {
    state->last_modifier = 0;
}
'''
    rows = ["    { " + ", ".join(f"0x{row[k]:02X}" for k in ("hold_modifier", "tap_modifier", "tap_keycode")) + f" }}, // 0x{row['keycode']:04X}" for row in builtin]
    source = source.replace("@BUILTIN_PARAMETERS@", "\n".join(rows))
    return {"cadet_model.h": header, "cadet_model.c": source}


def recover_backing(image) -> dict:
    profiles = []
    for index in range(4):
        address = 0x0801DE24 + index * 28
        attributes, program_unit, count, table, uniform, base, capacity = struct.unpack("<7I", image.read(address, 28))
        if (attributes, program_unit, count, uniform, base) != (3, 4, index + 5, 0, 0x08000000):
            raise ValueError("Original backing descriptor changed")
        sectors = [dict(zip(("offset", "size"), struct.unpack("<2I", image.read(table + n * 8, 8)))) for n in range(count)]
        end = 0
        for sector in sectors:
            if sector["offset"] != end:
                raise ValueError("Original sector table is not contiguous")
            end += sector["size"]
        if end != capacity or sectors[3] != {"offset": 0xC000, "size": 0x4000}:
            raise ValueError("Original sector budget changed")
        profiles.append({"descriptor": hex(address), "attributes": attributes, "program_unit": program_unit,
            "flash_base": hex(base), "capacity": capacity, "sectors": sectors})
    if image.u32(0x0801283C) != image.u32(0x08012888) or image.u32(0x08012840) != image.u32(0x08012894) or image.u32(0x080186D8) != image.u32(0x08012840):
        raise ValueError("Original shared backing globals changed")
    return {"profiles": profiles, "physical_capacity_verified": False,
        "base_offset_ram": hex(image.u32(0x0801283C)), "inversion_flag_ram": hex(image.u32(0x08012840)),
        "driver_pointer_ram": hex(image.u32(0x08012844)), "read_active_ram": hex(image.u32(0x08012890)), "read_error_ram": hex(image.u32(0x08012898)),
        "startup_inversion": "descriptor attributes & 1; all four available profiles yield 1",
        "word_codec": "any nonzero inversion byte complements the 32-bit word in both directions",
        "program": "driver-relative offset = uint32(base + offset), size 4; driver status zero alone means success; wrapper has no bounds/alignment check",
        "read": "descriptor memory base + driver-relative offset; observed final error byte nonzero gives zero output and false; stale error is cleared before check",
        "read_guard_order": "physical word LDR at 0x08012860 precedes active=1 at 0x0801286A; do not infer physical fault safety from RAM probes",
        "first_sector": 3, "backing_budget": 8192,
        "configured_backing_range": ["0x800c000", "0x800e000"], "erase_sector_range": ["0x800c000", "0x8010000"],
        "same_sector_tail": "0x0800E000..0x08010000 lies outside configured backing but shares erase sector; contents unknown",
        "driver_program_erase_unlock_lock_executed": False, "bus_fault_handler_validated": False,
        "scope": "word transform and captured driver intents / RAM-backed read, not physical hardware or complete wear-leveling recovery"}


def backing_artifacts() -> dict[str, str]:
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Pure word codec and captured intents; NEVER a physical flash driver.
#pragma once
#include <stdbool.h>
#include <stdint.h>
struct original_vial_backing_intent { uint32_t driver_offset, physical_word, size; };
uint32_t original_vial_backing_word(uint32_t word, uint8_t inversion_flag);
// Mirrors the original unchecked uint32 offset calculation; performs NO write.
bool original_vial_backing_program(uint32_t base, uint32_t offset, uint32_t logical_word,
    uint8_t inversion_flag, uint32_t driver_status, struct original_vial_backing_intent *intent);
// error is the byte observed at the FINAL check, not an initial/stale error.
// A controlled byte injection is NOT a verified physical bus-fault scenario.
bool original_vial_backing_read(uint32_t physical_word, uint8_t inversion_flag,
    uint8_t observed_error, uint32_t *logical_word);
'''
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
#include "backing_model.h"
uint32_t original_vial_backing_word(uint32_t word, uint8_t inversion_flag) {
    return inversion_flag ? ~word : word;
}
bool original_vial_backing_program(uint32_t base, uint32_t offset, uint32_t logical_word,
    uint8_t inversion_flag, uint32_t driver_status, struct original_vial_backing_intent *intent) {
    if (intent == 0) return false;
    *intent = (struct original_vial_backing_intent){base + offset,
        original_vial_backing_word(logical_word, inversion_flag), 4};
    return driver_status == 0;
}
bool original_vial_backing_read(uint32_t physical_word, uint8_t inversion_flag,
    uint8_t observed_error, uint32_t *logical_word) {
    if (logical_word == 0) return false;
    *logical_word = observed_error ? 0 : original_vial_backing_word(physical_word, inversion_flag);
    return observed_error == 0;
}
'''
    return {"backing_model.h": header, "backing_model.c": source}


def journal_artifacts() -> dict[str, str]:
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// One-entry final RAM/cursor model only, NOT a persistent journal replay driver.
#pragma once
#include <stdbool.h>
#include <stdint.h>
enum original_vial_journal_kind {
    ORIGINAL_VIAL_JOURNAL_EMPTY, ORIGINAL_VIAL_JOURNAL_APPLIED,
    ORIGINAL_VIAL_JOURNAL_REJECTED, ORIGINAL_VIAL_JOURNAL_READ_FAILED,
    ORIGINAL_VIAL_JOURNAL_UNMODELED, ORIGINAL_VIAL_JOURNAL_BAD_ARGUMENT
};
struct original_vial_journal_trace {
    uint32_t kind, address, next_position;
    uint8_t length, read_words;
};
// cache >=4096 bytes, entry >=8 translated bytes. First word is supplied/read.
// Position must be aligned and in [0x1008,0x2000). False means defensive argument
// failure or UNMODELED (normal-type lengths 6/7; second read past backing budget).
// Those exclusions are NOT claims that the original rejects such records.
// True means a modeled outcome, NOT necessarily an accepted record. Errors in
// the full firmware lead toward consolidation; never interpret them as skip.
bool original_vial_journal_entry(uint8_t *cache, const uint8_t *entry,
    uint32_t position, bool second_read_ok, struct original_vial_journal_trace *trace);
'''
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original one-entry slice 0x08018824..0x0801887e; no hardware/whole-loop calls.
#include "journal_model.h"
bool original_vial_journal_entry(uint8_t *cache, const uint8_t *entry,
    uint32_t position, bool second_read_ok, struct original_vial_journal_trace *trace) {
    if (trace == 0) return false;
    *trace = (struct original_vial_journal_trace){ .kind = ORIGINAL_VIAL_JOURNAL_BAD_ARGUMENT, .next_position = position };
    if (cache == 0 || entry == 0 || position < 0x1008u || position >= 0x2000u || (position & 3u)) return false;
    trace->read_words = 1;
    if ((entry[0] | entry[1] | entry[2] | entry[3]) == 0) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_EMPTY;
        return true;
    }
    trace->next_position += 4;
    if (entry[0] & 0xC0u) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_REJECTED;
        return true;
    }
    trace->address = ((uint32_t)(entry[0] & 7u) << 16) | ((uint32_t)entry[1] << 8) | entry[2];
    trace->length = (entry[0] >> 3) & 7u;
    if (trace->length > 5 || (trace->length > 1 && position + 8 > 0x2000u)) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_UNMODELED;
        return false;
    }
    if (trace->address + trace->length > 4096u) {
        trace->kind = ORIGINAL_VIAL_JOURNAL_REJECTED;
        return true;
    }
    if (trace->length > 1) {
        trace->read_words = 2;
        if (!second_read_ok) {
            trace->kind = ORIGINAL_VIAL_JOURNAL_READ_FAILED;
            return true;
        }
        trace->next_position += 4;
    }
    for (unsigned i = 0; i < trace->length; ++i) cache[trace->address + i] = entry[3 + i];
    trace->kind = ORIGINAL_VIAL_JOURNAL_APPLIED;
    return true;
}
'''
    return {"journal_model.h": header, "journal_model.c": source}


def snapshot_artifacts(snapshot: dict) -> dict[str, str]:
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Consolidated-load final RAM state only; NOT flash, log replay or whole init.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_SNAPSHOT_BYTES 4104u
#define ORIGINAL_VIAL_CACHE_BYTES 4096u
#define ORIGINAL_VIAL_LOG_START 4104u
struct original_vial_snapshot_cache { uint8_t bytes[4096]; uint32_t write_address; };
// Diagnostic outcomes defined by this model, NOT recovered QMK enum values.
enum original_vial_snapshot_outcome {
    ORIGINAL_VIAL_SNAPSHOT_READ_FAILED = 0,
    ORIGINAL_VIAL_SNAPSHOT_MISMATCH = 1,
    ORIGINAL_VIAL_SNAPSHOT_MATCH = 2,
    ORIGINAL_VIAL_SNAPSHOT_BAD_ARGUMENT = 3
};
// Input is AFTER backing-store translation (e.g. physical inversion), with
// successful checksum reads assumed. A data-word read failure clears RAM.
// Match preserves the caller's cursor; mismatch/failure sets it to LOG_START.
enum original_vial_snapshot_outcome original_vial_snapshot_load(
    struct original_vial_snapshot_cache *cache, const uint8_t *translated_snapshot,
    bool data_reads_succeeded);
// Exactly CACHE_BYTES bytes, not an arbitrary-length hash API. Null returns 0
// defensively; original code always supplies valid RAM.
uint64_t original_vial_snapshot_fnv64(const uint8_t *bytes);
'''
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original consolidated-load slice 0x08018758..0x08018816, no hardware calls.
#include "snapshot_model.h"
uint64_t original_vial_snapshot_fnv64(const uint8_t *bytes) {
    if (bytes == 0) return 0;
    uint64_t hash = UINT64_C(@BASIS@);
    for (unsigned i = 0; i < ORIGINAL_VIAL_CACHE_BYTES; ++i)
        hash = (hash ^ bytes[i]) * UINT64_C(@PRIME@);
    return hash;
}
enum original_vial_snapshot_outcome original_vial_snapshot_load(
    struct original_vial_snapshot_cache *cache, const uint8_t *snapshot,
    bool data_reads_succeeded) {
    if (cache == 0 || snapshot == 0) return ORIGINAL_VIAL_SNAPSHOT_BAD_ARGUMENT;
    if (data_reads_succeeded) {
        uint64_t stored = 0;
        for (unsigned i = 0; i < 8; ++i)
            stored |= (uint64_t)snapshot[ORIGINAL_VIAL_CACHE_BYTES + i] << (i * 8);
        if (stored == original_vial_snapshot_fnv64(snapshot)) {
            for (unsigned i = 0; i < ORIGINAL_VIAL_CACHE_BYTES; ++i) cache->bytes[i] = snapshot[i];
            return ORIGINAL_VIAL_SNAPSHOT_MATCH;
        }
    }
    for (unsigned i = 0; i < ORIGINAL_VIAL_CACHE_BYTES; ++i) cache->bytes[i] = 0;
    cache->write_address = ORIGINAL_VIAL_LOG_START;
    return data_reads_succeeded ? ORIGINAL_VIAL_SNAPSHOT_MISMATCH : ORIGINAL_VIAL_SNAPSHOT_READ_FAILED;
}
'''.replace("@BASIS@", snapshot["fnv_basis"]).replace("@PRIME@", snapshot["fnv_prime"])
    return {"snapshot_model.h": header, "snapshot_model.c": source}


def prefix_artifacts(prefix: dict) -> dict[str, str]:
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// RAM-only predicates for two isolated startup gates, NOT EEPROM or reset code.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_PREFIX_BYTES @SIZE@u
#define ORIGINAL_VIAL_CORE_MAGIC @CORE@u
#define ORIGINAL_VIAL_VIA_MAGIC_ADDR @VIA@u
#define ORIGINAL_VIAL_BUILD_ID_LOW24 @BUILD@u
#define ORIGINAL_VIAL_LAYOUT_OPTION_ADDR @LAYOUT@u
// Non-null buffers must contain at least PREFIX_BYTES bytes. Null is treated as
// invalid/zero defensively; original firmware always supplies storage.
bool original_vial_via_valid(const uint8_t *prefix);
bool original_vial_core_prefix_valid(const uint8_t *prefix);
uint8_t original_vial_layout_option(const uint8_t *prefix);
'''
    for token, value in (("SIZE", prefix["bytes_before_keymap"]), ("CORE", prefix["core_magic_u16"]),
        ("VIA", prefix["via_magic_start"]), ("BUILD", prefix["build_id_low24"]), ("LAYOUT", prefix["layout_options_start"])):
        header = header.replace("@" + token + "@", hex(value))
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original 0x0801ae04/0x0801ae74 and isolated startup gate conditions only.
#include "prefix_model.h"
bool original_vial_via_valid(const uint8_t *p) {
    return p != 0 && p[ORIGINAL_VIAL_VIA_MAGIC_ADDR] == (ORIGINAL_VIAL_BUILD_ID_LOW24 & 255u)
        && p[ORIGINAL_VIAL_VIA_MAGIC_ADDR + 1] == ((ORIGINAL_VIAL_BUILD_ID_LOW24 >> 8) & 255u)
        && p[ORIGINAL_VIAL_VIA_MAGIC_ADDR + 2] == ((ORIGINAL_VIAL_BUILD_ID_LOW24 >> 16) & 255u);
}
bool original_vial_core_prefix_valid(const uint8_t *p) {
    return p != 0 && ((uint16_t)p[0] | ((uint16_t)p[1] << 8)) == ORIGINAL_VIAL_CORE_MAGIC
        && original_vial_via_valid(p);
}
uint8_t original_vial_layout_option(const uint8_t *p) {
    return p != 0 ? p[ORIGINAL_VIAL_LAYOUT_OPTION_ADDR] : 0;
}
'''
    return {"prefix_model.h": header, "prefix_model.c": source}


def tap_artifacts() -> dict[str, str]:
    header = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original tap wrapper call intents only, NOT USB reports or real sleeping.
#pragma once
#include <stdbool.h>
#include <stdint.h>
#define ORIGINAL_VIAL_TAP_TICK_HZ 100000u
enum original_vial_tap_effect_kind {
    ORIGINAL_VIAL_TAP_REGISTER_CODE = 1,
    ORIGINAL_VIAL_TAP_SLEEP_TICKS = 2,
    ORIGINAL_VIAL_TAP_UNREGISTER_CODE = 3
};
struct original_vial_tap_effect { uint32_t kind, argument; };
struct original_vial_tap_trace {
    uint32_t count;
    struct original_vial_tap_effect effects[3];
};
// Delays are configured uint16 milliseconds; outputs are scheduler tick counts.
// Null trace returns false. Other arguments are typed/bounded like vendor calls.
bool original_vial_tap_code_trace(uint8_t keycode, uint16_t normal_delay_ms,
    uint16_t caps_delay_ms, struct original_vial_tap_trace *trace);
'''
    source = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original 0x08014188 -> 0x08014148, with HID/scheduler calls represented as data.
#include "tap_model.h"
bool original_vial_tap_code_trace(uint8_t keycode, uint16_t normal_delay_ms,
    uint16_t caps_delay_ms, struct original_vial_tap_trace *trace) {
    if (trace == 0) return false;
    uint16_t delay = keycode == 0x39 ? caps_delay_ms : normal_delay_ms;
    uint32_t ticks = delay ? (uint32_t)(((uint64_t)delay * ORIGINAL_VIAL_TAP_TICK_HZ + 999) / 1000) : 1;
    *trace = (struct original_vial_tap_trace){
        .count = 3,
        .effects = {
            {ORIGINAL_VIAL_TAP_REGISTER_CODE, keycode},
            {ORIGINAL_VIAL_TAP_SLEEP_TICKS, ticks},
            {ORIGINAL_VIAL_TAP_UNREGISTER_CODE, keycode}
        }
    };
    return true;
}
'''
    return {"tap_model.h": header, "tap_model.c": source}


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
