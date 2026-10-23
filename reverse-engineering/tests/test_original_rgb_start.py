"""Bounded STARTING copy/reset, not clock/aging/dispatch or full task."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_start import inspect_start, validate_oracle
from recover_original_vial import parse_uf2

ORACLE = json.loads((Path(__file__).parent/"fixtures/original-rgb-start.json").read_text())
ROWS = ORACLE["rgb_start"]
IMAGE = parse_uf2((ROOT/"firmware/origin/FAve40H_VIAL.uf2").read_bytes())


class OriginalRgbStartTests(unittest.TestCase):
    def test_complete_grid_and_active_frame_scope(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 432)
        for text in ("Supplied r5=timer-buffer snapshot", "SP=2000ffd8", "aging", "count255 is copy-only", "no render/sync/task/HAL", "Flags/init preserved"):
            self.assertIn(text, ORACLE["boundary_policy"])

    def test_instruction_and_literal_mutations_rejected(self):
        inspect_start(IMAGE)
        for address in (0x0801566E, 0x08015676, 0x080156AE, 0x080156B6, 0x080156BA, 0x080156BE, 0x080156C4, 0x08015780, 0x08015784, 0x08015790, 0x08015794, 0x08015798, 0x0801579C):
            class Changed:
                def read(self, start, length):
                    data = bytearray(IMAGE.read(start, length))
                    if start <= address < start+length:
                        data[address-start] ^= 1
                    return bytes(data)
            with self.assertRaises(ValueError):
                inspect_start(Changed())

    def test_iter_only_reset_flags_init_preserved_and_rendering_next(self):
        for row in ROWS:
            self.assertEqual(row["params_after_hex"], bytes((0, row["flags"], row["init"])).hex())
            self.assertEqual(row["task_state_after"], 1)
            self.assertEqual(row["memcpy_calls"], 1)

    def test_full_unsigned_timer_snapshot_not_stale_frame(self):
        self.assertEqual({r["timer_buffer"] for r in ROWS}, {0, 1, 15, 16, 65535, 0xFFFFFFFF})
        for row in ROWS:
            self.assertEqual(row["frame_timer_after"], row["timer_buffer"])
            self.assertNotEqual(row["frame_timer_after"], row["old_frame_timer"])

    def test_whole41_byte_copy_including_unused_slots_and_tick_tail(self):
        for row in ROWS:
            hits = bytes.fromhex(row["input_hits_hex"])
            old = bytes.fromhex(row["old_tracker_hex"])
            after = bytes.fromhex(row["tracker_after_hex"])
            self.assertEqual(len(after), 41)
            self.assertEqual(after, hits)
            self.assertEqual(old, bytes(b^255 for b in hits))
            self.assertNotEqual(after[25:41], old[25:41])
            self.assertEqual(after[0], (0, 1, 8, 255)[row["pattern"]])
        self.assertEqual(sum(bytes.fromhex(r["input_hits_hex"])[0] == 255 for r in ROWS), 108)
        # These108 raw count255 copies are NOT valid input for upstream aging.

    def test_counterfactual_counts_independent_of_native(self):
        self.assertEqual(sum(r["iter"] != 0 for r in ROWS), 288)
        self.assertEqual(sum(r["old_frame_timer"] != r["frame_timer_after"] for r in ROWS), 432)
        self.assertEqual(sum(r["old_tracker_hex"] != r["tracker_after_hex"] for r in ROWS), 432)

    def test_incomplete_or_changed_inputs_rejected(self):
        for mutate in (lambda o: o["rgb_start"].pop(),
                       lambda o: o["rgb_start"][0].update(iter=1),
                       lambda o: o["rgb_start"][0].update(timer_buffer=2),
                       lambda o: o["rgb_start"][0].update(input_hits_hex="00"),
                       lambda o: o["rgb_start"][0].update(old_tracker_hex="00"*41),
                       lambda o: o["rgb_start"][0].update(old_frame_timer=0)):
            changed = copy.deepcopy(ORACLE); mutate(changed)
            with self.assertRaises(ValueError):
                validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
