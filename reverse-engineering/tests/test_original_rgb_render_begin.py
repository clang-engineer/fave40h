"""Actual pre-dispatch init/enable/flags clear, no effects/caller/HAL execution."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_render_begin import grid, inspect_begin, validate_oracle
from recover_original_vial import parse_uf2

ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-render-begin.json").read_text())
ROWS = ORACLE["rgb_render_begin"]
IMAGE = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())


class OriginalRgbRenderBeginTests(unittest.TestCase):
    def test_complete_grid_and_inside_frame_boundary(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 1524)
        self.assertEqual(len(grid()), 1524)
        self.assertEqual(sum(r["grid"] == "init" for r in ROWS), 1200)
        for text in ("no call/API replacement", "caller effect selection is not executed", "Iter255", "active function frame"):
            self.assertIn(text, ORACLE["boundary_policy"])

    def test_instruction_branch_and_literal_mutations_rejected(self):
        inspect_begin(IMAGE)
        for address in (0x08014AA4, 0x08014AC4, 0x08014ADA, 0x08014B44, 0x08014D64, 0x08013304):
            class Changed:
                def read(self, start, size):
                    data = bytearray(IMAGE.read(start, size))
                    if start <= address < start + size:
                        data[address-start] ^= 1
                    return bytes(data)
            with self.assertRaises(ValueError):
                inspect_begin(Changed())

    def test_actual_init_compares_raw_enable_and_effect(self):
        for row in ROWS:
            init = row["effect"] != row["last_effect"] or row["enable"] != row["last_enable"]
            self.assertEqual(bytes.fromhex(row["params_after_hex"]), bytes((row["iter"], row["new_flags"], int(init))))
        self.assertEqual({r["enable"] for r in ROWS}, {0, 1, 2, 3})
        self.assertEqual({r["last_enable"] for r in ROWS}, {0, 1, 2, 3, 255})

    def test_only_flag_changes_clear_all216_bytes(self):
        ramp = hashlib.sha256(bytes((i*73+19) & 255 for i in range(216))).hexdigest()
        black = hashlib.sha256(bytes(216)).hexdigest()
        for row in ROWS:
            clear = row["old_flags"] != row["new_flags"]
            self.assertEqual(row["clear_calls"], int(clear))
            self.assertEqual(row["grb_sha256"], black if clear else ramp)
        self.assertEqual(sum(r["clear_calls"] for r in ROWS), 270)
        self.assertTrue(any(bytes.fromhex(r["params_after_hex"])[2] and not r["clear_calls"] for r in ROWS))
        self.assertTrue(any(not bytes.fromhex(r["params_after_hex"])[2] and r["clear_calls"] for r in ROWS))

    def test_counterfactual_counts_independently_match_native(self):
        ignored = booleanized = 0
        for row in ROWS:
            actual = bytes.fromhex(row["params_after_hex"])[2]
            ignored += bool(actual) != (row["effect"] != row["last_effect"])
            booleanized += bool(actual) != (row["effect"] != row["last_effect"] or bool(row["enable"]) != bool(row["last_enable"]))
        self.assertEqual(ignored, 300)
        self.assertEqual(booleanized, 216)
        self.assertEqual(sum(bool(r["clear_calls"]) for r in ROWS), 270)

    def test_iter255_only_preserved_and_arbitrary_flag_bytes_not_masked(self):
        self.assertEqual(sum(r["iter"] == 255 for r in ROWS), 508)
        for row in ROWS:
            if row["new_flags"] == 128:
                self.assertEqual(bytes.fromhex(row["params_after_hex"])[1], 128)
        self.assertTrue(any(r["old_flags"] == 0 and r["new_flags"] == 128 and r["clear_calls"] == 1 for r in ROWS))

    def test_incomplete_or_changed_input_grid_rejected(self):
        for mutate in (lambda o: o["rgb_render_begin"].pop(),
                       lambda o: o["rgb_render_begin"][0].update(enable=4),
                       lambda o: o["rgb_render_begin"][0].update(last_enable=254),
                       lambda o: o["rgb_render_begin"][0].update(iter=254)):
            changed = copy.deepcopy(ORACLE); mutate(changed)
            with self.assertRaises(ValueError):
                validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
