"""Target seed tests: no ARM firmware link, EEPROM, USB or peripheral execution."""
import contextlib
import ctypes
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import prepare_original_target as target
from recover_original_vial import recover

TARGET = ROOT / "reverse-engineering/keyboards/fave40h_original"


class OriginalTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uf2 = ROOT / "firmware/origin/FAve40H_VIAL.uf2"
        if not cls.uf2.exists():
            raise unittest.SkipTest("Original Vial UF2 absent")
        cls.raw = cls.uf2.read_bytes()
        cls.evidence, cls.definition = recover(cls.raw)
        cls.files = target.artifacts(cls.raw)

    def test_eleven_seed_files_are_original_only_deterministic_and_blocked(self):
        self.assertEqual(len(self.files), 11)
        for relative, content in self.files.items():
            self.assertEqual((TARGET / relative).read_text(), content, relative)
        manifest = json.loads(self.files["target-evidence.json"])
        self.assertFalse(manifest["complete_firmware"])
        self.assertFalse(manifest["flash_ready"])
        self.assertTrue(manifest["build_blockers"])
        self.assertTrue(manifest["flash_blockers"])
        self.assertEqual(self.uf2.read_bytes(), self.raw)

    def test_identity_matrix_and_layout_match_observed_data(self):
        keyboard = json.loads(self.files["keyboard.json"])
        self.assertEqual(keyboard["manufacturer"], self.evidence["usb"]["manufacturer"])
        self.assertEqual(keyboard["keyboard_name"], self.evidence["usb"]["product"])
        self.assertEqual(keyboard["usb"], {"vid": "0x5123", "pid": "0xa02d", "device_version": "1.0.0"})
        self.assertEqual(keyboard["matrix_pins"], {"rows": self.evidence["matrix"]["rows"], "cols": self.evidence["matrix"]["columns"]})
        self.assertEqual(keyboard["diode_direction"], "ROW2COL")
        layout = keyboard["layouts"]["LAYOUT"]["layout"]
        self.assertEqual(len(layout), 42)
        self.assertEqual(len({tuple(key["matrix"]) for key in layout}), 42)
        for row in range(4):
            keys = [k for k in layout if k["y"] == row]
            self.assertEqual(max(k["x"] + k.get("w", 1) for k in keys), 12)

    def test_config_retains_profile_without_old_stamp_or_security_bypass(self):
        config = self.files["config.h"]
        expected = {"DYNAMIC_KEYMAP_LAYER_COUNT": 4, "WEAR_LEVELING_LOGICAL_SIZE": 4096,
            "WEAR_LEVELING_BACKING_SIZE": 8192, "WEAR_LEVELING_EFL_FIRST_SECTOR": 3,
            "VIAL_TAP_DANCE_ENTRIES": 16, "VIAL_COMBO_ENTRIES": 16, "VIAL_KEY_OVERRIDE_ENTRIES": 16,
            "VIAL_ALT_REPEAT_KEY_ENTRIES": 32, "TAP_CODE_DELAY": 0}
        for name, value in expected.items():
            self.assertRegex(config, rf"(?m)^#define {name} {value}$")
        self.assertNotRegex(config, r"(?m)^#\s*define\s+(?:BUILD_ID|VIAL_INSECURE|VIAL_UNLOCK_COMBO_\w+)\b")
        self.assertEqual([int(x, 16) for x in re.findall(r"0x[0-9A-F]{2}\b", config)], self.evidence["vial"]["uid_bytes"])

    def test_catalog_bindings_defaults_and_automatic_support_flags(self):
        config = self.files["config.h"]
        effects = re.findall(r"(?m)^#define ENABLE_RGB_MATRIX_(\w+)\s*$", config)
        self.assertEqual(len(effects), 43)
        self.assertEqual(set(effects), set(target.ORIGINAL_RGB_EFFECTS))
        self.assertEqual(len(set(target.ORIGINAL_RGB_EFFECTS)), 43)
        self.assertIn("PIXEL_FLOW", effects)
        self.assertIn("RAINBOW_MOVING_CHEVRON", effects)
        self.assertRegex(config, r"(?m)^#define RGB_MATRIX_DEFAULT_MODE RGB_MATRIX_RAINBOW_MOVING_CHEVRON$")
        self.assertRegex(config, r"(?m)^#define RGB_MATRIX_DEFAULT_SPD 128$")
        self.assertNotRegex(config, r"(?m)^#define RGB_MATRIX_(?:FRAMEBUFFER_EFFECTS|KEYREACTIVE_ENABLED|KEYRELEASES)\b")
        self.assertRegex(self.files["keymaps/vial/rules.mk"], r"(?m)^VIALRGB_ENABLE = yes$")

    def test_effect_manifest_distinguishes_bindings_from_complete_runtime(self):
        manifest = json.loads(self.files["target-evidence.json"])
        profile = manifest["rgb_effect_profile"]
        self.assertEqual(profile["enable_effects"], list(target.ORIGINAL_RGB_EFFECTS))
        self.assertEqual((profile["vial_table_entries"], profile["qmk_mode_limit"], profile["unmapped_qmk_mode"]), (45, 46, 29))
        self.assertEqual((profile["default_mode"], profile["default_speed"]), (15, 128))
        self.assertEqual(profile["default_initialized_prefix_hex"], "3d00ffff80ff")
        self.assertEqual(profile["padding_bytes_untouched"], [6, 7])
        self.assertEqual(profile["selected_effects_compared"], [15, 29])
        self.assertFalse(profile["all_effect_bodies_verified"])
        self.assertFalse(manifest["complete_firmware"])
        self.assertTrue(any("RGB runtime" in item for item in manifest["build_blockers"]))

    def test_full_vial_definition_keeps_alternative_layout_and_all_custom_keys(self):
        definition = json.loads(self.files["keymaps/vial/vial.json"])
        self.assertEqual(definition, self.definition)
        self.assertEqual(len(definition["customKeycodes"]), 22)
        self.assertIn("2,10\n\n\n0,1", definition["layouts"]["keymap"][2])
        self.assertEqual(definition["lighting"], "vialrgb")

    def test_native_compiled_target_has_only_three_exact_factory_layers(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler absent")
        with tempfile.TemporaryDirectory(prefix="fave40h-target-table-") as directory:
            temp = Path(directory)
            (temp / "shim.h").write_text("#include <stdint.h>\n#define PROGMEM\n#define MATRIX_ROWS 4\n#define MATRIX_COLS 12\n")
            (temp / "probe.c").write_text(f'#include "{TARGET / "keymaps/vial/keymap.c"}"\nunsigned factory_layers(void) {{ return sizeof(keymaps) / (4 * 12 * sizeof(uint16_t)); }}\n')
            libpath = temp / ("keymap.dylib" if sys.platform == "darwin" else "keymap.so")
            subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", '-DQMK_KEYBOARD_H="shim.h"', "-I", str(temp), str(temp / "probe.c"), "-o", str(libpath)], check=True, capture_output=True)
            lib = ctypes.CDLL(str(libpath))
            lib.factory_layers.restype = ctypes.c_uint
            self.assertEqual(lib.factory_layers(), 3)
            values = (ctypes.c_uint16 * 144).in_dll(lib, "keymaps")
            self.assertEqual(list(values), [key for layer in self.evidence["factory_keymap"]["raw_keycodes"][:3] for row in layer for key in row])

    def test_make_guard_cannot_be_overridden_by_partial_or_insecure_flags(self):
        make = shutil.which("make")
        if not make:
            self.skipTest("Make absent")
        result = subprocess.run([make, "-f", str(TARGET / "rules.mk"), "-n", "ALLOW_PARTIAL_BUILD=1", "VIAL_INSECURE=yes"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ORIGINAL_TARGET_INCOMPLETE", result.stderr)

    def test_changed_original_and_unknown_layout_geometry_are_rejected(self):
        raw = bytearray(self.raw)
        raw[40] ^= 1
        with self.assertRaisesRegex(ValueError, "not original"):
            target.artifacts(bytes(raw))
        with self.assertRaisesRegex(ValueError, "geometry"):
            target.default_layout({"layouts": {"keymap": [[{"r": 15}, "0,0"]]}})

    def test_wrong_reference_or_modified_reference_source_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(target.subprocess, "check_output", return_value="wrong\n"):
                with self.assertRaisesRegex(ValueError, "revision"):
                    target.validate_reference(path)
            first = path / next(iter(target.REFERENCE_HASHES))
            first.parent.mkdir(parents=True)
            first.write_text("changed")
            with patch.object(target.subprocess, "check_output", return_value=target.REVISION + "\n"):
                with self.assertRaisesRegex(ValueError, "Changed QMK reference"):
                    target.validate_reference(path)

    def test_export_refuses_existing_destination_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "target"
            argv = ["prepare_original_target.py", str(self.uf2), "--reference-dir", directory, "--export", str(destination)]
            with patch.object(sys, "argv", argv), patch.object(target, "validate_reference"), contextlib.redirect_stdout(io.StringIO()):
                target.main()
                marker = destination / "keyboard.json"
                marker.write_text("preserve existing data")
                with self.assertRaises(FileExistsError):
                    target.main()
                self.assertEqual(marker.read_text(), "preserve existing data")


if __name__ == "__main__":
    unittest.main()
