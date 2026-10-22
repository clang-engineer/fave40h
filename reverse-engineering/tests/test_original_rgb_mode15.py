"""Actual factory mode15: phase, immutable geometry, HSV and RGB API boundaries."""
import itertools
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_mode15 import LEVELS, inspect_mode15
from recover_original_vial import parse_uf2

FIXTURES = Path(__file__).parent / "fixtures"
ORACLE = json.loads((FIXTURES / "original-rgb-mode15.json").read_text())
ROWS = ORACLE["rgb_mode15"]
SCALAR = json.loads((FIXTURES / "original-rgb-hsv.json").read_text())
IMAGE = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())
MAP = IMAGE.read(0x0801DEA0, 264)


class OriginalMode15Tests(unittest.TestCase):
    def test_complete_grid_scope_and_dispatch_witnesses(self):
        self.assertEqual(len(ROWS), 1260)
        self.assertEqual({tuple(r[k] for k in ("speed", "now", "hsv", "flags", "iter")) for r in ROWS},
                         set(itertools.product(*LEVELS)))
        inspect_mode15(IMAGE)
        self.assertIn("actual HSV147c0/CIE", ORACLE["boundary_policy"])
        self.assertIn("No target/catalog/default changes", ORACLE["boundary_policy"])

    def test_instruction_and_literal_mutations_rejected(self):
        for address in (0x08014D4E, 0x08012B48, 0x0801BE50, 0x08014D9C, 0x08012B98, 0x0801BED4, 0x08014AE8 + 30):
            class Changed:
                def read(self, start, size):
                    data = bytearray(IMAGE.read(start, size))
                    if start <= address < start + size:
                        data[address - start] ^= 1
                    return bytes(data)
            with self.assertRaises(ValueError):
                inspect_mode15(Changed())

    def test_exact_phase_and_meaningful_nonfixed_counterfactual(self):
        different = 0
        for row in ROWS:
            timer, speed = row["now"] & 65535, row["speed"]
            expected = ((timer * (speed // 4 + 2)) >> 8) & 255
            self.assertEqual(row["phase"], expected)
            different += expected != ((timer * (speed // 4 + 1)) >> 8) & 255
        self.assertEqual(different, 360)
        self.assertEqual(sum(r["hsv"] == 0x8080FF and bool(r["trace"]) for r in ROWS), 231)

    def test_original_geometry_math_and_flag_filtered_chunks(self):
        for row in ROWS:
            indices = [i for i in range(row["iter"] * 15, min(row["iter"] * 15 + 15, 72)) if MAP[192 + i] & row["flags"]]
            self.assertEqual(len(row["trace"]), 2 * len(indices))
            h, s, v = row["hsv"] & 255, (row["hsv"] >> 8) & 255, (row["hsv"] >> 16) & 255
            for index, i in enumerate(indices):
                hsv, rgb = row["trace"][index * 2:index * 2 + 2]
                x, y = MAP[48 + i * 2:50 + i * 2]
                self.assertEqual(hsv[:4], [2, (h + abs(y - 32) + x - row["phase"]) & 255, s, v])
                self.assertEqual(rgb, [1, i, *hsv[4:]])
            self.assertEqual(row["rendering"], row["iter"] < 4)
            self.assertEqual(bytes.fromhex(row["params_after_hex"]), bytes((row["iter"] + 1, row["flags"], int(row["init"]))))

    def test_all9072_hsv_outputs_match_separate_actual_scalar_fixture(self):
        scalar = {arg & 0xFFFFFF: result for arg, result in SCALAR["grayscale"] + SCALAR["hsv_grid"]}
        count = 0
        for row in ROWS:
            for event in row["trace"]:
                if event[0] == 2:
                    _, h, s, v, r, g, b = event
                    self.assertEqual(r | (g << 8) | (b << 16), scalar[h | (s << 8) | (v << 16)])
                    count += 1
        self.assertEqual(count, 9072)

    def test_timer_high16_bits_do_not_change_effect(self):
        lookup = {tuple(r[k] for k in ("speed", "now", "hsv", "flags", "iter")): r for r in ROWS}
        for row in ROWS:
            if row["now"] not in (65536, 0xFFFFFFFF):
                continue
            other = lookup[row["speed"], row["now"] & 65535, row["hsv"], row["flags"], row["iter"]]
            for key in ("phase", "trace", "rendering", "params_after_hex"):
                self.assertEqual(row[key], other[key])


if __name__ == "__main__":
    unittest.main()
