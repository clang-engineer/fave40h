"""Actual original scalar HSV conversion: CIE data, coverage and boundary properties."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_hsv import original_hsv_profile, validate_oracle

ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-hsv.json").read_text())
TABLE = bytes.fromhex(ORACLE["cie_table_hex"])
ROWS = ORACLE["grayscale"] + ORACLE["hsv_grid"]


def rgb_bytes(packed):
    return (packed & 255, (packed >> 8) & 255, (packed >> 16) & 255)


class OriginalRGBHSVTests(unittest.TestCase):
    def test_complete_declared_sample_grid_and_scope(self):
        validate_oracle(ORACLE)
        self.assertEqual(len(ROWS), 9472)
        self.assertEqual(ORACLE["cie_table_address"], "0x0801DB1A")
        self.assertIn("No callback replacements", ORACLE["boundary_policy"])
        self.assertIn("not exhaustive16777216", ORACLE["boundary_policy"])

    def test_literal_and_full_rom_table_match_fixture(self):
        raw = (ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes()
        self.assertEqual(original_hsv_profile(raw), TABLE)
        self.assertEqual(len(TABLE), 256)
        self.assertEqual(TABLE[0], 0)
        self.assertEqual(TABLE[-1], 255)
        self.assertTrue(all(a <= b for a, b in zip(TABLE, TABLE[1:])))

    def test_grayscale_uses_every_cie_entry_and_ignores_padding(self):
        self.assertEqual({packed >> 24 for packed, _ in ORACLE["grayscale"]}, set(range(256)))
        for packed, result in ORACLE["grayscale"]:
            value = (packed >> 16) & 255
            self.assertEqual(rgb_bytes(result), (TABLE[value],) * 3)

    def test_zero_value_gray_saturation_and_max_channel(self):
        for packed, result in ROWS:
            _, saturation, value = rgb_bytes(packed)
            rgb = rgb_bytes(result)
            self.assertEqual(max(rgb), TABLE[value])
            if saturation == 0:
                self.assertEqual(rgb, (TABLE[value],) * 3)
            if value == 0:
                self.assertEqual(result, 0)

    def test_hue_region_seams_and_255_wrap(self):
        grid = {rgb_bytes(packed): rgb_bytes(result) for packed, result in ORACLE["hsv_grid"]}
        for hue, expected in ((0, (255, 0, 0)), (42, (255, 252, 0)),
                              (43, (252, 255, 0)), (85, (0, 255, 0)),
                              (128, (0, 252, 255)), (170, (0, 0, 255)),
                              (213, (255, 0, 252)), (255, (255, 0, 0))):
            self.assertEqual(grid[hue, 255, 255], expected)
        for saturation in (0, 1, 127, 128, 254, 255):
            for value in (0, 1, 127, 128, 254, 255):
                self.assertEqual(grid[0, saturation, value], grid[255, saturation, value])

    def test_nocie_api_is_a_meaningful_negative_control(self):
        # The nocie algorithm's maximum channel equals raw V; therefore these
        # captured CIE outputs must differ independently of hue/saturation.
        differences = sum(max(rgb_bytes(result)) != ((packed >> 16) & 255) for packed, result in ROWS)
        self.assertEqual(differences, 4861)
        changed = dict(ORACLE, hsv_grid=ORACLE["hsv_grid"][:-1])
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
