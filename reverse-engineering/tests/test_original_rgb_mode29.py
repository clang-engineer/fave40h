"""Static mode29 signature and pure arithmetic original-Thumb oracle boundaries."""
import itertools
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_mode29 import LITERALS, WITNESSES, inspect_mode29_image
from recover_original_vial import parse_uf2

ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-mode29-interval.json").read_text())


class OriginalMode29Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())

    def modified(self, address):
        original = self.image
        class Changed:
            def read(self, start, size):
                data = bytearray(original.read(start, size))
                if start <= address < start + size:
                    data[address - start] ^= 1
                return bytes(data)
        return Changed()

    def test_real_jump_and_private_state_signature(self):
        info = inspect_mode29_image(self.image)
        self.assertEqual(info["case_entry"], "0x08014F58")
        self.assertEqual(info["led_state_ram"], "0x20001B55")
        self.assertEqual(info["led_state_bytes"], 72 * 3)
        self.assertIn("before init", info["wait_gate"])
        self.assertIn("not manufacturer", info["scope"])

    def test_changed_jump_table_rejected(self):
        with self.assertRaisesRegex(ValueError, "jump-table"):
            inspect_mode29_image(self.modified(0x08014AE8 + 29 * 2))

    def test_each_instruction_guard_is_enforced(self):
        for address in WITNESSES:
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, "instruction witness"):
                    inspect_mode29_image(self.modified(address))

    def test_each_literal_is_enforced(self):
        for address in LITERALS:
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, "literal"):
                    inspect_mode29_image(self.modified(address))

    def test_all_speeds_and_uint32_times_are_original_oracle_inputs(self):
        cases = ORACLE["rgb_mode29_interval"]
        self.assertEqual(ORACLE["payload_sha256"], "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4")
        self.assertEqual(len(cases), 1024)
        self.assertEqual({(c["speed"], c["now"]) for c in cases},
                         set(itertools.product(range(256), (0, 1, 0xFFFFFF00, 0xFFFFFFFF))))
        for case in cases:
            denominator = min(case["speed"] + 16, 255) * 17 >> 8
            self.assertEqual(case["next_wait"], (case["now"] + 3000 // denominator) & 0xFFFFFFFF)
        self.assertIn("Only original150d8..150fa", ORACLE["boundary_policy"])
        self.assertIn("No renderer dispatch", ORACLE["boundary_policy"])

    def test_interval_extremes_saturation_and_wrap_preserved(self):
        values = {(c["speed"], c["now"]): c["next_wait"] for c in ORACLE["rgb_mode29_interval"]}
        self.assertEqual(values[0, 0], 3000)
        self.assertEqual(values[128, 0], 333)
        self.assertEqual(values[255, 0], 187)
        self.assertEqual(values[255, 0xFFFFFFFF], 186)
        self.assertEqual({values[speed, 0] for speed in range(239, 256)}, {187})


if __name__ == "__main__":
    unittest.main()
