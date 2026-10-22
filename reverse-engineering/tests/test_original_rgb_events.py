"""Bounded original Thumb electrical-edge hit collector, not a full RGB engine."""
import itertools
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-events.json").read_text())
RGB = json.loads((ROOT / "reverse-engineering/original-vial/evidence.json").read_text())["rgb"]
TARGET = ROOT / "reverse-engineering/keyboards/fave40h_original"


class OriginalRGBEventTests(unittest.TestCase):
    def test_original_scope_and_complete_valid_input_grid(self):
        self.assertEqual(ORACLE["payload_sha256"], "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4")
        self.assertIn("Original Thumb memcpy", ORACLE["boundary_policy"])
        self.assertIn("stop before heatmap", ORACLE["boundary_policy"])
        cases = ORACLE["rgb_key_events"]
        self.assertEqual(len(cases), 288)
        actual = {(c["row"], c["col"], c["pressed"], c["initial_count"]) for c in cases}
        self.assertEqual(actual, set(itertools.product(range(4), range(12), (False, True), (0, 7, 8))))
        for case in cases:
            self.assertEqual(len(bytes.fromhex(case["before_hex"])), 41)
            self.assertEqual(len(bytes.fromhex(case["after_hex"])), 41)

    def test_all_release_edges_preserve_opaque_hit_bytes(self):
        cases = [c for c in ORACLE["rgb_key_events"] if not c["pressed"]]
        self.assertEqual(len(cases), 144)
        for case in cases:
            self.assertEqual(case["before_hex"], case["after_hex"])
            self.assertEqual(case["original_memcpy_calls"], 0)

    def test_mapped_presses_append_xy_index_zero_tick_and_fifo(self):
        changed = 0
        for case in ORACLE["rgb_key_events"]:
            led = RGB["matrix_to_led"][case["row"]][case["col"]]
            if not case["pressed"] or led == 255:
                continue
            changed += 1
            before = bytes.fromhex(case["before_hex"])
            expected = bytearray(before)
            count = case["initial_count"]
            if count == 8:
                for offset, width in ((1, 1), (9, 1), (17, 1), (25, 2)):
                    expected[offset:offset + 7 * width] = before[offset + width:offset + 8 * width]
                count = 7
            expected[1 + count], expected[9 + count] = RGB["positions"][led]
            expected[17 + count] = led
            expected[25 + count * 2:27 + count * 2] = b"\0\0"
            expected[0] = count + 1
            self.assertEqual(bytes.fromhex(case["after_hex"]), bytes(expected))
        self.assertEqual(changed, 126)

    def test_six_unmapped_matrix_cells_never_add_hits(self):
        cases = [c for c in ORACLE["rgb_key_events"] if RGB["matrix_to_led"][c["row"]][c["col"]] == 255]
        self.assertEqual(len(cases), 36)
        for case in cases:
            self.assertEqual(case["before_hex"], case["after_hex"])

    def test_full_mapped_press_runs_four_original_memcpy_calls(self):
        copied = 0
        for case in ORACLE["rgb_key_events"]:
            full = case["pressed"] and case["initial_count"] == 8 and RGB["matrix_to_led"][case["row"]][case["col"]] != 255
            self.assertEqual(case["original_memcpy_calls"], 4 if full else 0)
            copied += int(full)
        self.assertEqual(copied, 42)

    def test_target_binds_press_profile_with_catalog_but_keeps_runtime_blocked(self):
        config = (TARGET / "config.h").read_text()
        manifest = json.loads((TARGET / "target-evidence.json").read_text())
        self.assertIn("#define RGB_MATRIX_KEYPRESSES", config)
        self.assertNotIn("#define RGB_MATRIX_KEYRELEASES", config)
        self.assertIn("#define ENABLE_RGB_MATRIX_PIXEL_FLOW", config)
        self.assertIn("#define ENABLE_RGB_MATRIX_RAINBOW_MOVING_CHEVRON", config)
        self.assertFalse(manifest["rgb_effect_profile"]["all_effect_bodies_verified"])
        self.assertIn("#define LED_HITS_TO_REMEMBER 8", config)
        self.assertEqual(manifest["rgb_key_events"]["edge"], "press")
        self.assertEqual(manifest["rgb_key_events"]["packed_hit_bytes"], 41)
        self.assertIn("complete RGB runtime pipeline and remaining effects conformance", manifest["build_blockers"])
        self.assertIn("ORIGINAL_TARGET_INCOMPLETE", (TARGET / "rules.mk").read_text())


if __name__ == "__main__":
    unittest.main()
