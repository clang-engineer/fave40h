#!/usr/bin/env python3
"""Offline, hash-bound comparison of original QS ABI with ONE reference revision.

Not firmware source-revision identification or whole-EEPROM compatibility proof.
No network/device access. Inputs must be the exact public reference files below.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

from recover_original_vial import recover, require

REVISION = "dd43959ae5c08d8a28d38a1acf7b04e86b14a344"
SOURCE_HASHES = {
    "qmk_settings.h": "d5846b5983b807c2bd44881d25e55671080018767193cea664ab3aa71d549c84",
    "qmk_settings.c": "beecfd2c0980dc2d3043884b68a5c358e255ca53c29b5866ca127b4fbf68fa8b",
}


def parse_reference(header: str, source: str) -> dict:
    """Narrow parser for this pinned source grammar, not a C preprocessor."""
    block = re.search(r"typedef\s+struct\s*\{([^}]+)\}\s*qmk_settings_t\s*;", header, re.S)
    if not block:
        raise ValueError("Missing qmk_settings_t")
    declarations = re.sub(r"/\*.*?\*/|//[^\n]*", "", block[1], flags=re.S)
    fields, offset = [], 0
    for declaration in declarations.split(";"):
        if not declaration.strip():
            continue
        field = re.fullmatch(r"\s*(uint(?:8|16)_t)\s+(\w+)\s*", declaration)
        if not field:
            raise ValueError("Unsupported QS field declaration")
        size = 1 if field[1] == "uint8_t" else 2
        offset = (offset + size - 1) // size * size
        fields.append({"name": field[2], "ctype": field[1], "offset": offset, "size": size})
        offset += size
    declared = re.search(r"_Static_assert\(sizeof\(qmk_settings_t\)\s*==\s*(\d+)", header)
    if not declared:
        raise ValueError("Missing QS sizeof assertion")
    require((offset + 1) // 2 * 2, int(declared[1]), "reference QS size")
    by_name = {field["name"]: field for field in fields}
    bits = {name: int(value) for name, value in re.findall(r"#define\s+(QS_\w+_bit)\s+(\d+)", header)}
    protos_block = re.search(r"protos\[\]\s+PROGMEM\s*=\s*\{(.*?)\};", source, re.S)
    if not protos_block:
        raise ValueError("Missing prototype table")
    protos = []
    for line in protos_block[1].splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"DECLARE_(STATIC_SETTING_NOTIFY|STATIC_SETTING|STATIC_BITSETTING|SETTING)\((\d+),\s*(\w+)(?:,\s*(\w+))?\)", line)
        if not match:
            raise ValueError(f"Unsupported prototype: {line}")
        form, qsid, field, extra = match.groups()
        if form == "SETTING":
            require((field, extra), ("magic_settings_get", "magic_settings_set"), "custom setting")
            row = {"qsid": int(qsid), "kind": "custom", "field": None, "offset": None, "size": 0, "bit": 0, "notify": None}
        else:
            layout = by_name[field]
            row = {"qsid": int(qsid), "kind": "bit" if form == "STATIC_BITSETTING" else "scalar", "field": field,
                "offset": layout["offset"], "size": layout["size"], "bit": bits[extra] if form == "STATIC_BITSETTING" else 0,
                "notify": extra if form == "STATIC_SETTING_NOTIFY" else None}
        protos.append(row)
    reset_block = re.search(r"void qmk_settings_reset\(void\)\s*\{(.*?)\n\}", source, re.S)
    if not reset_block:
        raise ValueError("Missing reset function")
    assignments = dict(re.findall(r"QS\.(\w+)\s*=\s*(\w+)\s*;", reset_block[1]))
    header_defaults = {name: int(value) for name, value in re.findall(r"#\s*define\s+(\w+)\s+(\d+)\b", header) if name in assignments.values()}
    return {"revision": REVISION, "source_hashes": SOURCE_HASHES,
        "source_urls": {name: f"https://raw.githubusercontent.com/vial-kb/vial-qmk/{REVISION}/quantum/{name}" for name in SOURCE_HASHES},
        "profile": "QMK_SETTINGS enabled; MOUSEKEY_ENABLE enabled; MK_3_SPEED disabled; ARM32 prototype pointers",
        "bytes": int(declared[1]), "fields": fields, "prototypes": protos,
        "reset_assignments": assignments, "header_macro_defaults": header_defaults}


def reference_from_files(header: bytes, source: bytes) -> dict:
    for name, content in (("qmk_settings.h", header), ("qmk_settings.c", source)):
        require(hashlib.sha256(content).hexdigest(), SOURCE_HASHES[name], f"reference source {name}")
    return parse_reference(header.decode("utf-8"), source.decode("utf-8"))


def compare(settings: dict, reference: dict) -> dict:
    require(reference["revision"], REVISION, "reference revision")
    require(reference["source_hashes"], SOURCE_HASHES, "reference hashes")
    differences = []
    if settings["bytes"] != reference["bytes"]:
        differences.append("QS byte count differs")
    original = {p["qsid"]: p for p in settings["prototypes"]}
    if set(original) != {p["qsid"] for p in reference["prototypes"]}:
        differences.append("Setting IDs differ")
    handlers, callbacks = {}, {}
    for proto in reference["prototypes"]:
        actual = original.get(proto["qsid"])
        if actual is None:
            continue
        for name in ("size", "bit", "offset"):
            if actual[name] != proto[name]:
                differences.append(f"QS id {proto['qsid']} {name} differs")
        pair = actual["get"], actual["set"]
        if handlers.setdefault(proto["kind"], pair) != pair:
            differences.append(f"Inconsistent {proto['kind']} handler group")
        notify = actual["notify"]
        if (proto["notify"] is None) != (notify == "0x0"):
            differences.append(f"QS id {proto['qsid']} notify presence differs")
        if proto["notify"] and callbacks.setdefault(proto["notify"], notify) != notify:
            differences.append(f"Inconsistent notify group {proto['notify']}")
    defaults, macros, preserved = [], {}, []
    for field in reference["fields"]:
        start, size = field["offset"], field["size"]
        raw = settings["reset_bytes"][start:start + size]
        assignment = reference["reset_assignments"].get(field["name"])
        if any(byte is None for byte in raw):
            preserved.extend(start + i for i, byte in enumerate(raw) if byte is None)
            if assignment is not None:
                differences.append(f"Reset assignment for preserved field {field['name']}")
            value = None
        else:
            value = int.from_bytes(bytes(raw), "little")
            if assignment is None:
                differences.append(f"Reference does not assign reset field {field['name']}")
            elif assignment.isdigit():
                if int(assignment) != value:
                    differences.append(f"Reset literal differs for {field['name']}")
            else:
                default = reference["header_macro_defaults"].get(assignment)
                entry = {"required_value_for_original": value, "reference_header_default": default,
                    "override_needed_with_this_header": default != value if default is not None else None}
                if macros.setdefault(assignment, entry) != entry:
                    differences.append(f"Conflicting required macro value for {assignment}")
        defaults.append({**field, "original_reset_value": value, "reference_assignment": assignment})
    return {"scope": "40-byte QS struct + prototype shape/grouping + RAM-reset assignments only",
        "structural_match": not differences, "differences": differences, "fields": defaults,
        "required_build_macros": dict(sorted(macros.items())), "preserved_offsets": preserved,
        "handler_groups": {name: {"get": pair[0], "set": pair[1]} for name, pair in handlers.items()},
        "notification_groups": callbacks, "callback_bodies_compared": False,
        "exact_manufacturer_revision_identified": False, "whole_eeprom_compatibility_proven": False,
        "flash_ready": False}


def audit(raw: bytes, header: bytes, source: bytes) -> dict:
    original, _ = recover(raw)
    reference = reference_from_files(header, source)
    return {"original_uf2_sha256": original["uf2_sha256"], "original_payload_sha256": original["payload_sha256"],
        "reference": reference, "comparison": compare(original["qmk_settings"], reference)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--header", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--export", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    try:
        if args.uf2.stat().st_size > 1024 * 1024 or any(p.stat().st_size > 128 * 1024 for p in (args.header, args.source)):
            raise ValueError("Input size limit exceeded")
        report = audit(args.uf2.read_bytes(), args.header.read_bytes(), args.source.read_bytes())
        text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.export:
            with args.export.open("x", encoding="utf-8", newline="\n") as output:
                output.write(text)
        else:
            require(args.check.read_bytes(), text.encode("utf-8"), "settings audit report")
        print(f"QS structural match={report['comparison']['structural_match']}; NOT whole-EEPROM compatibility or flash-ready")
        if not report["comparison"]["structural_match"]:
            parser.exit(1)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
