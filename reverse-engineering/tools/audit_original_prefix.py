#!/usr/bin/env python3
"""Offline, pinned-source audit of the original EEPROM prefix profile.

Only observed core access addresses, packed reference layout and VIA prefix
arithmetic. No EEPROM, reset, migration, flash operations or compiler execution.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

from audit_original_settings import REVISION
from audit_original_records import parse_nvm_macros
from recover_original_vial import recover, require

SOURCES = {
    "eeconfig.h": ("quantum/eeconfig.h", "d5060211da78683a1a722c507c3fe018de08f87ba8d7bda9b433cf9dce0590f5"),
    "via.h": ("quantum/via.h", "82cfa43bbc57818509735c3c567fe1ea7ea28284ad9aebf1cfda3fe34206e8a9"),
    "via.c": ("quantum/via.c", "f8d0220363b944b8826cefee178a825422e369e5cdf4f233a45a846a4eb40f63"),
    "nvm_eeprom_eeconfig_internal.h": ("quantum/nvm/eeprom/nvm_eeprom_eeconfig_internal.h", "d628b12f461f1b3889b4fa3f5578ecd10bfcbf6363a84d77a70bf1e4c3c3e746"),
    "nvm_eeprom_via_internal.h": ("quantum/nvm/eeprom/nvm_eeprom_via_internal.h", "0ac50614ec49a50f305e80ce7847d07db01515c2bacf7574c55b11b33fe97737"),
}


def parse_packed_core(source: str) -> dict:
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    match = re.search(r"typedef\s+struct\s+PACKED\s*\{.*?\}\s*eeprom_core_t\s*;", clean, re.S)
    if not match:
        raise ValueError("Missing packed EEPROM core")
    declaration = match[0]
    body = declaration[declaration.index("{") + 1:declaration.rindex("}")]
    fields, offset = [], 0

    def members(text):
        result = []
        for item in text.split(";"):
            if not item.strip():
                continue
            found = re.fullmatch(r"\s*uint(8|16|32|64)_t\s+(\w+)\s*", item)
            if not found:
                raise ValueError("Unsupported packed core field")
            result.append((found[2], int(found[1]) // 8))
        return result

    parts = re.split(r"(union\s*\{[^{}]+\}\s*;)", body)
    require(len(parts), 3, "one anonymous core union")
    for part in parts:
        union = part.strip().startswith("union")
        entries = members(part[part.index("{") + 1:part.rindex("}")] if union else part)
        if union:
            fields.extend({"name": name, "offset": offset, "size": size} for name, size in entries)
            offset += max(size for _, size in entries)
        else:
            for name, size in entries:
                fields.append({"name": name, "offset": offset, "size": size})
                offset += size
    return {"bytes": offset, "fields": fields, "packed_declaration": declaration}


def reference_from_files(files: dict[str, bytes]) -> dict:
    for name, (_, digest) in SOURCES.items():
        require(hashlib.sha256(files[name]).hexdigest(), digest, f"reference source {name}")
    texts = {name: raw.decode() for name, raw in files.items()}
    core = parse_packed_core(texts["nvm_eeprom_eeconfig_internal.h"])
    definitions = {**parse_nvm_macros(texts["nvm_eeprom_eeconfig_internal.h"]),
        **parse_nvm_macros(texts["nvm_eeprom_via_internal.h"])}
    formulas = {
        "EECONFIG_BASE_SIZE": "((uint8_t)sizeof(eeprom_core_t))",
        "EECONFIG_SIZE": "((EECONFIG_BASE_SIZE)+(EECONFIG_KB_DATA_SIZE)+(EECONFIG_USER_DATA_SIZE))",
        "VIA_EEPROM_MAGIC_ADDR": "(EECONFIG_SIZE)",
        "VIA_EEPROM_LAYOUT_OPTIONS_ADDR": "(VIA_EEPROM_MAGIC_ADDR+3)",
        "VIA_EEPROM_CUSTOM_CONFIG_ADDR": "(VIA_EEPROM_LAYOUT_OPTIONS_ADDR+VIA_EEPROM_LAYOUT_OPTIONS_SIZE)",
        "VIA_EEPROM_CONFIG_END": "(VIA_EEPROM_CUSTOM_CONFIG_ADDR+VIA_EEPROM_CUSTOM_CONFIG_SIZE)",
    }
    for name, expression in formulas.items():
        require(re.sub(r"\s+", "", definitions[name]), expression, f"reference prefix formula {name}")
    macros = {**parse_nvm_macros(texts["eeconfig.h"]), **parse_nvm_macros(texts["via.h"])}
    profile = {name: int(macros[name], 0) for name in ("EECONFIG_KB_DATA_SIZE", "EECONFIG_USER_DATA_SIZE",
        "VIA_EEPROM_LAYOUT_OPTIONS_SIZE", "VIA_EEPROM_LAYOUT_OPTIONS_DEFAULT", "VIA_EEPROM_CUSTOM_CONFIG_SIZE")}
    magic_block = re.search(r"bool via_eeprom_is_valid\(void\)\s*\{\s*#ifdef VIAL_ENABLE(.*?)#else", texts["via.c"], re.S)
    if not magic_block:
        raise ValueError("Missing Vial validity branch")
    require(re.sub(r"\s+", "", magic_block[1]),
        "uint8_tmagic0=BUILD_ID&0xFF;uint8_tmagic1=(BUILD_ID>>8)&0xFF;uint8_tmagic2=(BUILD_ID>>16)&0xFF;", "reference BUILD_ID byte selection")
    return {"revision": REVISION,
        "sources": {name: {"sha256": digest, "url": f"https://raw.githubusercontent.com/vial-kb/vial-qmk/{REVISION}/{path}"}
            for name, (path, digest) in SOURCES.items()},
        "core": core, "default_profile": profile, "prefix_formulas": formulas,
        "vial_stamp_source": "low 24 bits of BUILD_ID, least-significant byte first; not the non-Vial build-date branch"}


def compare(prefix: dict, reference: dict) -> dict:
    require(reference["revision"], REVISION, "reference revision")
    profile, core = reference["default_profile"], reference["core"]
    fields = {f["name"]: f for f in core["fields"]}
    differences = []
    for access in prefix["observed_core_accesses"]:
        field = fields[access["reference_label"]]
        if (access["offset"], access["size"]) != (field["offset"], field["size"]):
            differences.append(f"Core access differs: {access['reference_label']}")
    magic = core["bytes"] + profile["EECONFIG_KB_DATA_SIZE"] + profile["EECONFIG_USER_DATA_SIZE"]
    layout = magic + 3
    end = layout + profile["VIA_EEPROM_LAYOUT_OPTIONS_SIZE"] + profile["VIA_EEPROM_CUSTOM_CONFIG_SIZE"]
    if (magic, layout, end, profile["VIA_EEPROM_LAYOUT_OPTIONS_SIZE"]) != (prefix["via_magic_start"],
        prefix["layout_options_start"], prefix["bytes_before_keymap"], prefix["layout_options_bytes"]):
        differences.append("VIA prefix interval differs")
    observed = {f["reference_label"] for f in prefix["observed_core_accesses"]}
    return {"scope": "seven observed core field accesses + default reference prefix arithmetic + original gate predicates",
        "prefix_profile_match": not differences, "differences": differences,
        "reference_core_bytes": core["bytes"], "reference_via_magic_start": magic,
        "reference_layout_start": layout, "reference_keymap_start": end,
        "original": prefix,
        "reference_core_fields_not_verified_against_original": sorted(set(fields) - observed),
        "required_build_id_low24_for_original_stamp": prefix["build_id_low24"],
        "build_id_high8_known": False, "candidate_actual_generated_build_id_checked": False,
        "warning": "A different BUILD_ID low24 can trigger original-style factory reset at startup. Do not preserve this stamp merely to bypass reset without proving full storage compatibility.",
        "all_core_field_semantics_proven": False, "reset_bodies_compared_or_executed": False,
        "flash_backing_or_migration_proven": False, "exact_manufacturer_revision_identified": False,
        "whole_eeprom_compatibility_proven": False, "flash_ready": False}


def audit(raw: bytes, files: dict[str, bytes]) -> dict:
    original, _ = recover(raw)
    reference = reference_from_files(files)
    return {"original_uf2_sha256": original["uf2_sha256"], "original_payload_sha256": original["payload_sha256"],
        "reference": reference, "comparison": compare(original["eeprom_prefix"], reference)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--export", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    try:
        paths = {name: args.reference_dir / name for name in SOURCES}
        if args.uf2.stat().st_size > 1024 * 1024 or any(p.stat().st_size > 128 * 1024 for p in paths.values()):
            raise ValueError("Input size limit exceeded")
        result = audit(args.uf2.read_bytes(), {name: path.read_bytes() for name, path in paths.items()})
        text = json.dumps(result, indent=2) + "\n"
        if args.export:
            with args.export.open("x", encoding="utf-8", newline="\n") as output:
                output.write(text)
        else:
            require(args.check.read_bytes(), text.encode(), "prefix audit report")
        print(f"Prefix profile match={result['comparison']['prefix_profile_match']}; NOT whole EEPROM compatibility or flash-ready")
        if result["comparison"]["differences"]:
            parser.exit(1)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
