#!/usr/bin/env python3
"""Actual original HSV/CIE-table comparison against pinned candidate color code.

Sampled scalar conversion only, NOT full HSV exhaustion, rendering or hardware.
No target configuration, source checkout, index or device changes.
"""
import argparse
import ctypes
import itertools
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from audit_original_rgb_mode29 import PAYLOAD_SHA, ROOT, pinned_source
from prepare_original_target import REVISION, validate_reference
from recover_original_vial import parse_uf2, recover

CIE_LITERAL = 0x08014868
CIE_ADDRESS = 0x0801DB1A
HSV_ENTRY_WITNESS = bytes.fromhex("30b52949c0f3074310f47f4fc95c85b0c2b2c0f3072544d0")


def original_hsv_profile(raw):
    recover(raw)
    image = parse_uf2(raw)
    if image.read(0x080147C0, len(HSV_ENTRY_WITNESS)) != HSV_ENTRY_WITNESS:
        raise ValueError("Changed original HSV entry witness")
    if int.from_bytes(image.read(CIE_LITERAL, 4), "little") != CIE_ADDRESS:
        raise ValueError("Changed original HSV CIE literal")
    return image.read(CIE_ADDRESS, 256)


def color_program(reference, temp):
    hashes = {}
    read = lambda path: pinned_source(reference, path, hashes)
    for name in ("color.c", "color.h", "led_tables.c", "led_tables.h"):
        (temp / name).write_text(read("quantum/" + name))
    implementation = read("quantum/rgb_matrix/rgb_matrix.c")
    wrapper = re.search(r"__attribute__\(\(weak\)\) rgb_t rgb_matrix_hsv_to_rgb\(hsv_t hsv\) \{.*?^\}", implementation, re.S | re.M)
    if not wrapper:
        raise ValueError("Missing actual default RGB-matrix HSV wrapper")
    common = read("builddefs/common_features.mk")
    matrix_section = common[common.index("ifeq ($(strip $(RGB_MATRIX_ENABLE)), yes)"):common.index("ifeq ($(strip $(RGB_MATRIX_DRIVER)), aw20216s)")]
    if "CIE1931_CURVE := yes" not in matrix_section or "OPT_DEFS += -DUSE_CIE1931_CURVE" not in common:
        raise ValueError("Unmodeled candidate RGB-matrix CIE build profile")
    # Storage/attribute adapters only; color arithmetic, table and declarations
    # are the unmodified source files, not a hand-translated color algorithm.
    (temp / "util.h").write_text('#pragma once\n#define PACKED __attribute__((packed))\n')
    (temp / "progmem.h").write_text('#pragma once\n#include <stdint.h>\n#define PROGMEM\n#define pgm_read_byte(p) (*(const uint8_t *)(p))\n')
    source = temp / "hsv.c"
    source.write_text('''#include "color.h"
#include "led_tables.h"
#define API __attribute__((visibility("default")))
_Static_assert(sizeof(rgb_t)==3 && sizeof(hsv_t)==3,"source packed color types");
''' + wrapper[0] + '''
API uint32_t probe_hsv(uint32_t packed) {
    hsv_t hsv={(uint8_t)packed,(uint8_t)(packed>>8),(uint8_t)(packed>>16)};
#ifdef PROBE_NOCIE
    rgb_t rgb=hsv_to_rgb_nocie(hsv);
#else
    rgb_t rgb=rgb_matrix_hsv_to_rgb(hsv);
#endif
    return (uint32_t)rgb.r|((uint32_t)rgb.g<<8)|((uint32_t)rgb.b<<16);
}
API const uint8_t *probe_curve(void) {
#ifdef USE_CIE1931_CURVE
    return CIE1931_CURVE;
#else
    return 0;
#endif
}
''')
    return source, hashes


def validate_oracle(oracle):
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(oracle["grayscale"]) != 256 or len(oracle["hsv_grid"]) != 9216:
        raise ValueError("Incomplete original HSV oracle")
    levels = (0, 1, 127, 128, 254, 255)
    if {(row[0] & 255, (row[0] >> 8) & 255, (row[0] >> 16) & 255) for row in oracle["hsv_grid"]} != set(itertools.product(range(256), levels, levels)):
        raise ValueError("Changed original HSV grid")
    if [row[0] & 0xFFFFFF for row in oracle["grayscale"]] != [v << 16 for v in range(256)]:
        raise ValueError("Changed original grayscale inputs")
    for packed, rgb in oracle["grayscale"] + oracle["hsv_grid"]:
        if not (0 <= packed <= 0xFFFFFFFF and 0 <= rgb <= 0xFFFFFF):
            raise ValueError("Out-of-scope HSV packed value")


def audit(raw, reference):
    original_table = original_hsv_profile(raw)
    validate_reference(reference)
    oracle = json.loads((ROOT / "tests/fixtures/original-rgb-hsv.json").read_text())
    validate_oracle(oracle)
    if bytes.fromhex(oracle["cie_table_hex"]) != original_table:
        raise ValueError("Original HSV fixture table mismatch")
    cc = shutil.which("cc")
    if not cc:
        raise RuntimeError("Existing host compiler required; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-rgb-hsv-") as folder:
        temp = Path(folder)
        source, hashes = color_program(reference, temp)
        differences = {}
        for tag, opt, extra in (("cie", "-O0", ["-DUSE_CIE1931_CURVE"]),
                                ("optimized", "-O2", ["-DUSE_CIE1931_CURVE"]),
                                ("nocie_api", "-O0", ["-DUSE_CIE1931_CURVE", "-DPROBE_NOCIE"])):
            output = temp / (tag + ".so")
            subprocess.run([cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt,
                            "-fvisibility=hidden", "-shared", "-fPIC", *extra, "-I", str(temp),
                            str(source), str(temp / "color.c"), str(temp / "led_tables.c"), "-o", str(output)], check=True)
            lib = ctypes.CDLL(str(output))
            lib.probe_hsv.argtypes = [ctypes.c_uint32]; lib.probe_hsv.restype = ctypes.c_uint32
            lib.probe_curve.restype = ctypes.POINTER(ctypes.c_uint8)
            if bytes(lib.probe_curve()[:256]) != original_table:
                raise AssertionError("Candidate compiled CIE table differs from all256 original bytes")
            differences[tag] = sum(lib.probe_hsv(packed) != rgb for packed, rgb in oracle["grayscale"] + oracle["hsv_grid"])
        if differences["cie"] or differences["optimized"] or not differences["nocie_api"]:
            raise AssertionError(f"HSV differential failed: {differences}")
    return {"candidate_revision": REVISION, "source_sha256": hashes,
            "original_hsv_entry": "0x080147C0", "cie_table_address": f"0x{CIE_ADDRESS:08X}",
            "compiled_original_cie_bytes_matched": 256, "original_hsv_cases_matched": 9472,
            "optimized_hsv_cases_matched": 9472,
            "nocie_api_negative_differences": differences["nocie_api"],
            "actual_candidate_color_arithmetic_executed": True, "exhaustive_hsv_space_tested": False,
            "original_thumb_executed_by_this_command": False, "target_changes_applied": False,
            "scope": "actual scalar original147c0 fixture vs unmodified candidate color.c/led_tables.c/header/default matrix wrapper; CIE table all256 bytes; storage/attribute shims only. All hues x six saturation/value levels plus256 grays, not all16777216 HSV values or matrix pipeline/physical colors/source provenance",
            "sentinel": "ORIGINAL_RGB_HSV_AUDIT_COMPLETE"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir), indent=2))


if __name__ == "__main__":
    main()
