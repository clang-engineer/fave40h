#!/usr/bin/env python3
"""Compile exact candidate introspection + target factory keymap with API shims.

This is NOT a complete QMK, board, USB, peripheral or EEPROM build.
"""
import argparse
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from prepare_original_target import artifacts, validate_reference
from recover_original_vial import recover


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--arm-object", type=Path)
    args = parser.parse_args()
    validate_reference(args.reference_dir)
    raw = args.uf2.read_bytes()
    for relative, content in artifacts(raw).items():
        if (args.target / relative).read_text() != content:
            raise ValueError(f"Changed target seed: {relative}")
    evidence, _ = recover(raw)
    cc = shutil.which("cc")
    if not cc:
        raise RuntimeError("Host C compiler required; no installation attempted")
    with tempfile.TemporaryDirectory(prefix="fave40h-target-keymap-") as directory:
        temp = Path(directory)
        # Unmodified, SHA-checked upstream source; only headers are controlled shims.
        source = temp / "keymap_introspection.c"
        source.write_bytes((args.reference_dir / "quantum/keymap_introspection.c").read_bytes())
        (temp / "keyboard_shim.h").write_text(f'''#pragma once
#include <stdint.h>
#include "{args.target.resolve() / 'config.h'}"
#define MATRIX_ROWS 4
#define MATRIX_COLS 12
#define PROGMEM
#define KC_TRNS 1
#define pgm_read_word(pointer) (*(pointer))
#define DYNAMIC_KEYMAP_ENABLE
#define MAX_LAYER DYNAMIC_KEYMAP_LAYER_COUNT
''')
        (temp / "compiler_support.h").write_text('#define STATIC_ASSERT(condition, message) _Static_assert(condition, message)\n')
        for header in ("keymap_introspection.h", "util.h"):
            (temp / header).write_text("// Controlled empty API shim; feature-specific branches disabled.\n")
        defines = [f'-DKEYMAP_C="{args.target.resolve() / "keymaps/vial/keymap.c"}"', '-DQMK_KEYBOARD_H="keyboard_shim.h"', "-I", str(temp)]
        library = temp / ("keymap.dylib" if sys.platform == "darwin" else "keymap.so")
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", *defines, str(source), "-o", str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.keymap_layer_count_raw.restype = ctypes.c_uint8
        lib.keycode_at_keymap_location_raw.argtypes = [ctypes.c_uint8] * 3
        lib.keycode_at_keymap_location_raw.restype = ctypes.c_uint16
        if lib.keymap_layer_count_raw() != 3:
            raise AssertionError("Factory layer count changed")
        for layer in range(4):
            for row in range(4):
                for column in range(12):
                    if lib.keycode_at_keymap_location_raw(layer, row, column) != evidence["factory_keymap"]["raw_keycodes"][layer][row][column]:
                        raise AssertionError(f"Factory cell mismatch: {layer},{row},{column}")
        if args.arm_object:
            clang = shutil.which("clang")
            if not clang:
                raise RuntimeError("Clang required for ARM keymap-only probe; no installation attempted")
            obj = temp / "keymap-arm.o"
            subprocess.run([clang, "--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-ffreestanding", "-std=c11", "-Wall", "-Wextra", "-Werror", *defines, "-c", str(source), "-o", str(obj)], check=True)
            with args.arm_object.open("xb") as output:
                output.write(obj.read_bytes())
    print(json.dumps({"compiled_factory_layers": 3, "dynamic_layers": 4, "native_cells_checked": 192,
        "arm_keymap_only_object": str(args.arm_object) if args.arm_object else None,
        "full_qmk_firmware": False, "peripherals_or_eeprom_executed": False,
        "sentinel": "ORIGINAL_TARGET_KEYMAP_PROBE_COMPLETE"}, indent=2))


if __name__ == "__main__":
    main()
