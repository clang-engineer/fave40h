#!/usr/bin/env python3
"""Offline original-Vial record size/layout audit against one pinned reference.

Only serialized type sizes, reset-template interpretation and region arithmetic.
Not proof of runtime field semantics, source revision or whole EEPROM compatibility.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

from audit_original_settings import REVISION
from recover_original_vial import recover, require

SOURCES = {
    "vial.h": ("quantum/vial.h", "db5ea5a835ba98883302930d1035a9496e6bcbd73373f60fa793cee104c97284"),
    "nvm_dynamic_keymap.c": ("quantum/nvm/eeprom/nvm_dynamic_keymap.c", "9e68535aca78744eb8c67d8d4bf8bcabff8231c058cb07d36bc4871934d6796b"),
}
TYPES = {"tap_dance": "vial_tap_dance_entry_t", "combo": "vial_combo_entry_t",
    "key_override": "vial_key_override_entry_t", "alt_repeat": "vial_alt_repeat_key_entry_t"}
MACROS = {"tap_dance": "VIAL_TAP_DANCE", "combo": "VIAL_COMBO",
    "key_override": "VIAL_KEY_OVERRIDE", "alt_repeat": "VIAL_ALT_REPEAT_KEY"}


def parse_header(header: str) -> dict:
    """Narrow grammar for the pinned header's four uint8/uint16 structs."""
    structs = {}
    for body, name in re.findall(r"typedef\s+struct\s*\{([^}]+)\}\s*(vial_\w+_entry_t)\s*;", header):
        fields, offset, alignment = [], 0, 1
        for declaration in body.split(";"):
            if not declaration.strip():
                continue
            match = re.fullmatch(r"\s*(uint(8|16)_t)\s+(\w+)(?:\[(\d+)\])?\s*", declaration)
            if not match:
                raise ValueError("Unsupported record declaration")
            ctype, bits, field, count = match.groups()
            width, count = int(bits) // 8, int(count or 1)
            if not 1 <= count <= 4:
                raise ValueError("Unsupported record array size")
            offset = (offset + width - 1) // width * width
            fields.append({"name": field, "ctype": ctype, "count": count, "offset": offset, "size": width * count})
            offset += width * count
            alignment = max(alignment, width)
        size = (offset + alignment - 1) // alignment * alignment
        assertion = re.search(rf"_Static_assert\(sizeof\({name}\)\s*==\s*(\d+)", header)
        if not assertion:
            raise ValueError("Missing record sizeof assertion")
        require(size, int(assertion[1]), "reference record size")
        structs[name] = {"size": size, "fields": fields}
    require(set(structs), set(TYPES.values()), "reference record types")
    defaults = {}
    for name, macro in MACROS.items():
        match = re.search(rf"#\s*if\s+TOTAL_EEPROM_BYTE_COUNT\s*>\s*4000\s*#\s*define\s+{macro}_ENTRIES\s+(\d+)", header)
        if not match:
            raise ValueError("Unsupported reference count-selection grammar")
        defaults[name] = int(match[1])
    return {"types": structs, "default_counts_at_4096_bytes": defaults}


def reference_from_files(header: bytes, nvm: bytes) -> dict:
    for name, content in (("vial.h", header), ("nvm_dynamic_keymap.c", nvm)):
        require(hashlib.sha256(content).hexdigest(), SOURCES[name][1], f"reference source {name}")
    return {"revision": REVISION,
        "sources": {name: {"sha256": digest, "url": f"https://raw.githubusercontent.com/vial-kb/vial-qmk/{REVISION}/{path}"}
            for name, (path, digest) in SOURCES.items()},
        **parse_header(header.decode()), "nvm_macros": parse_nvm_macros(nvm.decode())}


def parse_nvm_macros(nvm: str) -> dict:
    definitions = {}
    for name, expression in re.findall(r"^\s*#\s*define\s+(\w+)\s+([^\n]+)", nvm, re.M):
        definitions.setdefault(name, expression.strip())
    return definitions


def evaluate_regions(definitions: dict, sizes: dict, profile: dict) -> dict:
    """Evaluate only +,-,* and named object macros for this enabled-feature profile.

    The first definition of each feature size is its enabled branch. This is NOT
    a general preprocessor. Exact source hashes gate the public audit entry point.
    EEPROM_ADDR is supplied explicitly; prefix origin is intentionally not audited.
    """
    values, visiting = dict(profile), set()

    def value(name):
        if name in values:
            return values[name]
        if name in visiting or name not in definitions:
            raise ValueError(f"Unsupported or cyclic reference macro: {name}")
        visiting.add(name)
        expression = re.sub(r"sizeof\((\w+)\)", lambda m: str(sizes[m[1]]), definitions[name])
        result = node(ast.parse(expression, mode="eval").body)
        visiting.remove(name)
        values[name] = result
        return result

    def node(item):
        if isinstance(item, ast.Constant) and type(item.value) is int:
            return item.value
        if isinstance(item, ast.Name):
            return value(item.id)
        if isinstance(item, ast.BinOp) and type(item.op) in (ast.Add, ast.Sub, ast.Mult):
            left, right = node(item.left), node(item.right)
            return left + right if isinstance(item.op, ast.Add) else left - right if isinstance(item.op, ast.Sub) else left * right
        raise ValueError("Unsupported reference macro expression")

    return {"qmk_settings_start": value("VIAL_QMK_SETTINGS_EEPROM_ADDR"),
        **{name: {"start": value(macro + "_EEPROM_ADDR"), "bytes": value(macro + "_SIZE")} for name, macro in MACROS.items()},
        "macro": {"start": value("DYNAMIC_KEYMAP_MACRO_EEPROM_ADDR"), "bytes": value("DYNAMIC_KEYMAP_MACRO_EEPROM_SIZE")}}


def compare(original: dict, reference: dict) -> dict:
    storage = original["storage"]
    profile = {"TOTAL_EEPROM_BYTE_COUNT": storage["logical_bytes"],
        "DYNAMIC_KEYMAP_EEPROM_ADDR": storage["keymap_start"],
        "DYNAMIC_KEYMAP_LAYER_COUNT": original["factory_keymap"]["dynamic_layers"],
        "MATRIX_ROWS": len(original["matrix"]["rows"]), "MATRIX_COLS": len(original["matrix"]["columns"]),
        "NUM_ENCODERS": 0,
        **{MACROS[r["name"]] + "_ENTRIES": r["entries"] for r in original["dynamic_records"]}}
    sizes = {name: spec["size"] for name, spec in reference["types"].items()}
    sizes["qmk_settings_t"] = original["qmk_settings"]["bytes"]
    regions = evaluate_regions(reference["nvm_macros"], sizes, profile)
    differences, records = [], []
    if regions["qmk_settings_start"] != original["qmk_settings"]["logical_start"]:
        differences.append("QS start differs")
    for record in original["dynamic_records"]:
        name = record["name"]
        spec = reference["types"][TYPES[name]]
        if spec["size"] != record["stride"]:
            differences.append(f"{name} stride differs")
        if regions[name] != {"start": record["start"], "bytes": record["end_exclusive"] - record["start"]}:
            differences.append(f"{name} interval differs")
        raw = bytes(record["reset_bytes"])
        fields = []
        for field in spec["fields"]:
            width = 1 if field["ctype"] == "uint8_t" else 2
            values = [int.from_bytes(raw[field["offset"] + i * width:field["offset"] + (i + 1) * width], "little") for i in range(field["count"])]
            fields.append({**field, "original_template_interpreted_as_reference": values if field["count"] > 1 else values[0]})
        default = reference["default_counts_at_4096_bytes"][name]
        records.append({**record, "reference_type": TYPES[name], "reference_fields": fields,
            "reference_default_entries_at_4096_bytes": default,
            "explicit_count_override_for_this_profile": record["entries"] != default})
    if regions["macro"] != storage["macro"]:
        differences.append("macro interval differs")
    return {"scope": "record sizes + enabled-feature logical-region arithmetic with explicit original base/counts; reference field interpretation only",
        "size_and_region_match": not differences, "differences": differences,
        "profile": profile, "records": records, "reference_regions": regions,
        "dynamic_record_byte_order": "little-endian ARM stack templates; keymap keycodes use a separate big-endian format",
        "prefix_default_origin_audited": False, "original_runtime_field_semantics_proven": False,
        "reference_reset_function_equivalence_proven": False, "whole_eeprom_compatibility_proven": False,
        "exact_manufacturer_revision_identified": False, "flash_ready": False}


def audit(raw: bytes, header: bytes, nvm: bytes) -> dict:
    original, _ = recover(raw)
    reference = reference_from_files(header, nvm)
    comparison = compare(original, reference)
    return {"original_uf2_sha256": original["uf2_sha256"], "original_payload_sha256": original["payload_sha256"],
        "reference": reference, "comparison": comparison}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--header", type=Path, required=True)
    parser.add_argument("--nvm-source", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--export", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    try:
        if args.uf2.stat().st_size > 1024 * 1024 or any(p.stat().st_size > 128 * 1024 for p in (args.header, args.nvm_source)):
            raise ValueError("Input size limit exceeded")
        result = audit(args.uf2.read_bytes(), args.header.read_bytes(), args.nvm_source.read_bytes())
        text = json.dumps(result, indent=2) + "\n"
        if args.export:
            with args.export.open("x", encoding="utf-8", newline="\n") as output:
                output.write(text)
        else:
            require(args.check.read_bytes(), text.encode(), "record ABI audit")
        print(f"Record size/region match={result['comparison']['size_and_region_match']}; NOT full EEPROM compatibility or flash-ready")
        if result["comparison"]["differences"]:
            parser.exit(1)
    except (ValueError, OSError, KeyError, SyntaxError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
