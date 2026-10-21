"""Original-only binary/source consistency tests; never touch USB/hardware."""
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "reverse-engineering/tools"
sys.path.insert(0, str(TOOLS))
import recover_original_vial as recovery

ARTIFACTS = ROOT / "reverse-engineering/original-vial"


class OriginalRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input = ROOT / "firmware/origin/FAve40H_VIAL.uf2"
        if not cls.input.exists():
            raise unittest.SkipTest("Manufacturer original Vial UF2 absent")
        cls.raw = cls.input.read_bytes()
        cls.result, cls.definition = recovery.recover(cls.raw)
        cls.image = recovery.parse_uf2(cls.raw)

    def test_strict_original_identity_and_read_only(self):
        self.assertEqual(hashlib.sha256(self.input.read_bytes()).hexdigest(), recovery.ORIGINAL_SHA256)
        self.assertFalse(self.result["flash_ready"])
        self.assertFalse(self.result["source_reconstruction_complete"])
        self.assertEqual(self.raw, self.input.read_bytes())

    def test_other_manufacturer_firmwares_rejected(self):
        for relative in ("firmware/layer8/fave40h_f411_vial.uf2", "firmware/origin/FAve40h_VIA.uf2"):
            path = ROOT / relative
            if path.exists():
                with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "not original"):
                    recovery.recover(path.read_bytes())

    def test_modified_payload_rejected(self):
        raw = bytearray(self.raw)
        raw[40] ^= 1
        with self.assertRaisesRegex(ValueError, "not original"):
            recovery.recover(bytes(raw))

    def test_three_compiled_layers_and_generated_fourth(self):
        keymaps = self.result["factory_keymap"]["raw_keycodes"]
        self.assertEqual(len(keymaps), 4)
        expected = list(struct.unpack("<144H", self.image.read(0x0801E284, 288)))
        self.assertEqual([v for layer in keymaps[:3] for row in layer for v in row], expected)
        self.assertEqual(keymaps[3], [[1] * 12 for _ in range(4)])
        # Do not accidentally interpret bytes AFTER the 3-layer table as layer 3.
        self.assertNotEqual(list(struct.unpack("<48H", self.image.read(0x0801E284 + 288, 96))), [1] * 48)

    def test_factory_defaults_not_user_backup(self):
        self.assertEqual(self.result["factory_keymap"]["raw_keycodes"][0][1][0], 0x39)  # Factory Caps Lock
        self.assertEqual(self.result["factory_keymap"]["raw_keycodes"][2][1][11], 0x7C00)  # Factory QK_BOOT
        self.assertEqual(self.result["factory_keymap"]["dynamic_layers"], 4)

    def test_gpio_and_clocks(self):
        self.assertEqual(self.result["matrix"]["rows"], ["A5", "A6", "A3", "A4"])
        self.assertEqual(self.result["matrix"]["columns"], ["B12", "B13", "B14", "B15", "A8", "B6", "B5", "B4", "B3", "A15", "B7", "B8"])
        self.assertEqual(self.result["board"]["gpio_table"], "0x801ea14")
        for index, port in enumerate("ABCDEH"):
            self.assertEqual(list(self.result["board"]["gpio_register_defaults"][port].values()), list(struct.unpack("<7I", self.image.read(0x0801EA14 + 28 * index, 28))))
        self.assertEqual(self.result["board"]["pllcfgr"], "0x4413010")
        self.assertFalse(self.result["board"]["silicon_identified"])

    def test_vial_definition_and_usb(self):
        self.assertEqual(self.definition["matrix"], {"rows": 4, "cols": 12})
        self.assertEqual(len(self.definition["customKeycodes"]), 22)
        self.assertEqual(self.result["usb"]["device_version_bcd"], "0x100")
        self.assertEqual(self.result["usb"]["serial"], "vial:f64c2b3c")
        self.assertEqual(self.result["vial"]["uid_bytes"], list(bytes.fromhex("bc780a5daf64ce92")))

    def test_vendor_argument_decoding_from_instruction_operands(self):
        rows = self.result["vendor_space_cadet"]["parameters"]
        expected = [(0xE1, 0xE1, 0x2F), (0xE5, 0xE5, 0x30), (0xE0, 0xE1, 0x2F), (0xE4, 0xE5, 0x30), (0xE2, 0xE1, 0x2F), (0xE6, 0xE5, 0x30), (0xE1, 0xE1, 0x36), (0xE5, 0xE5, 0x37), (0xE0, 0xE1, 0x36), (0xE4, 0xE5, 0x37), (0xE2, 0xE1, 0x36), (0xE6, 0xE5, 0x37), (0xE0, 1, 0x39), (0xE4, 1, 0x28)]
        self.assertEqual([(r["hold_modifier"], r["tap_modifier"], r["tap_keycode"]) for r in rows], expected)
        self.assertEqual([r["keycode"] for r in rows], list(range(0x7E01, 0x7E0F)))
        self.assertFalse(self.result["vendor_space_cadet"]["timing_state_machine_reconstructed"])

    def test_storage_intervals_do_not_overlap(self):
        storage = self.result["storage"]
        self.assertEqual(storage["keymap_start"] + 4 * 4 * 12 * 2, storage["keymap_end_exclusive"])
        end = storage["qmk_settings_end_exclusive"]
        for kind in ("tap_dance", "combo", "key_override", "alt_repeat"):
            group = storage[kind]
            self.assertEqual(group["start"], end)
            end = group["start"] + group["entries"] * group["stride"]
        self.assertEqual(end, storage["macro"]["start"])
        self.assertEqual(end + storage["macro"]["bytes"], storage["logical_bytes"])
        self.assertFalse(self.result["boot_request"]["recovery_verified"])

    def test_exported_artifacts_are_reproducible(self):
        for name, content in recovery.artifacts(self.result, self.definition).items():
            with self.subTest(name=name):
                self.assertEqual((ARTIFACTS / name).read_bytes(), content.encode("utf-8"))

    def test_cli_refuses_overwrite_and_checks_without_changes(self):
        with tempfile.TemporaryDirectory(prefix="fave40h-original-test-") as temp:
            command = [sys.executable, str(TOOLS / "recover_original_vial.py"), str(self.input)]
            output = Path(temp) / "recovered"
            subprocess.run(command + ["--export", str(output)], check=True, capture_output=True)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            self.assertNotEqual(subprocess.run(command + ["--export", str(output)], capture_output=True).returncode, 0)
            subprocess.run(command + ["--check", str(output)], check=True, capture_output=True)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})


class CompiledRecoveredModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("Host C compiler absent")
        cls.temp = tempfile.TemporaryDirectory(prefix="fave40h-original-c-")
        cls.addClassCleanup(cls.temp.cleanup)
        extension = ".dylib" if sys.platform == "darwin" else ".so"
        library = Path(cls.temp.name) / ("model" + extension)
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(ARTIFACTS / "factory_defaults.c"), str(ARTIFACTS / "vendor_parameters.c"), "-o", str(library)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.original_vial_keycode_address.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint16)]
        cls.lib.original_vial_keycode_address.restype = ctypes.c_bool
        cls.lib.original_vial_reset_keymaps.argtypes = [ctypes.c_void_p]
        cls.lib.original_vial_reset_keymaps.restype = None

    def test_all_192_keycode_addresses(self):
        for layer in range(4):
            for row in range(4):
                for col in range(12):
                    output = ctypes.c_uint16()
                    self.assertTrue(self.lib.original_vial_keycode_address(layer, row, col, ctypes.byref(output)))
                    self.assertEqual(output.value, 0x29 + layer * 96 + row * 24 + col * 2)

    def test_invalid_addresses_and_null(self):
        for coordinates in ((4, 0, 0), (0, 4, 0), (0, 0, 12), (0xFFFFFFFF, 0, 0)):
            out = ctypes.c_uint16(0xDEAD)
            self.assertFalse(self.lib.original_vial_keycode_address(*coordinates, ctypes.byref(out)))
            self.assertEqual(out.value, 0xDEAD)
        self.assertFalse(self.lib.original_vial_keycode_address(0, 0, 0, None))

    def test_reset_produces_exact_384_bytes(self):
        buffer = (ctypes.c_uint16 * 192)(*[0xDEAD] * 192)
        self.lib.original_vial_reset_keymaps(buffer)
        evidence = json.loads((ARTIFACTS / "evidence.json").read_text())
        actual = struct.pack("<192H", *buffer)
        self.assertEqual(hashlib.sha256(actual).hexdigest(), evidence["factory_keymap"]["expanded_little_endian_sha256"])

    def test_vendor_argument_query(self):
        class Args(ctypes.Structure):
            _fields_ = [("hold", ctypes.c_uint8), ("tap_mod", ctypes.c_uint8), ("tap_key", ctypes.c_uint8)]
        query = self.lib.original_vial_cadet_parameters
        query.argtypes = [ctypes.c_uint, ctypes.POINTER(Args)]
        query.restype = ctypes.c_bool
        rows = json.loads((ARTIFACTS / "evidence.json").read_text())["vendor_space_cadet"]["parameters"]
        for row in rows:
            output = Args()
            self.assertTrue(query(row["keycode"], ctypes.byref(output)))
            self.assertEqual((output.hold, output.tap_mod, output.tap_key), (row["hold_modifier"], row["tap_modifier"], row["tap_keycode"]))
        for keycode in (0x7E00, 0x7E0F, 0xFFFFFFFF):
            self.assertFalse(query(keycode, ctypes.byref(Args())))
        self.assertFalse(query(0x7E01, None))


if __name__ == "__main__":
    unittest.main()
