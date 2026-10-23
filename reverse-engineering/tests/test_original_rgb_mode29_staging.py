"""Mode29 persistent API/RAM composition, not full task/HAL integration."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_mode29_staging import inspect_all_staging, validate_oracle
from recover_original_vial import parse_uf2

FIXTURES = Path(__file__).parent / "fixtures"
ORACLE = json.loads((FIXTURES / "original-rgb-mode29-staging.json").read_text())
SEQUENCES = ORACLE["rgb_mode29_staging"]
IMAGE = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())
FLAGS = IMAGE.read(0x0801DF60, 72)


def replay(negative=0):
    differences = 0
    for seq in SEQUENCES:
        pixels = bytearray.fromhex(seq["initial_grb_hex"])
        for row in seq["steps"]:
            for event in row["trace"]:
                if event[0] == 0:
                    r, g, b = event[1:]
                    pixels[:] = bytes((r, g, b) if negative == 3 else (g, r, b)) * 72
                elif event[0] == 1:
                    _, index, r, g, b = event
                    pixels[index*3:index*3+3] = bytes((r, g, b) if negative == 3 else (g, r, b))
            before = pixels.hex()
            white = 0
            if negative != 1:
                if seq["caps"] == 2 and (not row["rendering"] or negative == 2):
                    pixels[66:69] = b"\xff" * 3
                    white = 1
                for i in range(row["iter"] * 15, min(row["iter"] * 15 + 15, 72)):
                    if (((seq["group_word"] & 255) == 0 and FLAGS[i] & 4) or
                            (((seq["group_word"] >> 8) & 255) == 0 and FLAGS[i] & 2)):
                        pixels[i*3:i*3+3] = b"\x00" * 3
            differences += (before != row["effect_grb_hex"] or pixels.hex() != row["post_grb_hex"] or white != row["caps_white_calls"])
    return differences


class OriginalMode29StagingTests(unittest.TestCase):
    def test_complete_grid_and_bounded_scope(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 72)
        self.assertEqual(sum(len(s["steps"]) for s in SEQUENCES), 1152)
        self.assertEqual(sum(r["original_hsv_calls"] for s in SEQUENCES for r in s["steps"]), 5292)
        for text in ("separately entered", "no RGB setter replacement", "indirectly observed", "flags-change-clear"):
            self.assertIn(text, ORACLE["boundary_policy"])

    def test_real_all_and_single_setter_instruction_mutations_rejected(self):
        inspect_all_staging(IMAGE)
        for address in (0x08012FC8, 0x08013304, 0x0801331A, 0x080132EC, 0x08013300):
            class Changed:
                def read(self, start, size):
                    data = bytearray(IMAGE.read(start, size))
                    if start <= address < start + size:
                        data[address-start] ^= 1
                    return bytes(data)
            with self.assertRaises(ValueError):
                inspect_all_staging(Changed())

    def test_all2304_before_after_snapshots_replay_with_persistent_buffers(self):
        self.assertEqual(replay(), 0)

    def test_independent_counterfactual_counts_match_native(self):
        self.assertEqual(replay(1), 684)
        self.assertEqual(replay(2), 456)
        self.assertEqual(replay(3), 1100)

    def test_wait_before_init_keeps_effect_cache_seed_and_staging(self):
        for seq in SEQUENCES:
            previous, waiting = seq["steps"][4:6]
            self.assertTrue(waiting["init"])
            self.assertFalse(waiting["rendering"])
            self.assertEqual(waiting["trace"], [])
            self.assertEqual(waiting["effect_grb_hex"], previous["post_grb_hex"])
            for key in ("seed_after", "next_wait", "led_state_rgb_hex"):
                self.assertEqual(waiting[key], previous[key])
            self.assertEqual(waiting["caps_white_calls"], int(seq["caps"] == 2))

    def test_caps_runs_on_completed_wait_even_before_final_chunk(self):
        for seq in SEQUENCES:
            if seq["caps"] != 2 or seq["group_word"] & 255:
                continue
            row = seq["steps"][5]  # iter0 wait completes, not iter4
            self.assertEqual(row["iter"], 0)
            self.assertEqual(bytes.fromhex(row["post_grb_hex"])[66:69], b"\xff" * 3)
            self.assertTrue(any(row["rendering"] for row in seq["steps"]))
            self.assertTrue(all(r["caps_white_calls"] == int(not r["rendering"]) for r in seq["steps"]))

    def test_incomplete_and_effect_state_mutations_rejected(self):
        for mutate in (lambda o: o["rgb_mode29_staging"].pop(),
                       lambda o: o["rgb_mode29_staging"][0].update(value=128),
                       lambda o: o["rgb_mode29_staging"][0].update(group_word=0),
                       lambda o: o["rgb_mode29_staging"][0]["steps"][0].update(seed_after=99),
                       lambda o: o["rgb_mode29_staging"][0]["steps"][0].update(caps_white_calls=1),
                       lambda o: o["rgb_mode29_staging"][0]["steps"][0].update(post_grb_hex="00")):
            changed = copy.deepcopy(ORACLE); mutate(changed)
            with self.assertRaises(ValueError):
                validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
