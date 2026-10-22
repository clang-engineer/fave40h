"""Stateful original mode29 cases at a deliberately controlled HSV/RGB boundary."""
import itertools
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-mode29-frames.json").read_text())
FLAGS = json.loads((ROOT / "reverse-engineering/original-vial/evidence.json").read_text())["rgb"]["flags"]


class OriginalMode29FrameTests(unittest.TestCase):
    def test_persistent_sequences_and_scope(self):
        sequences = ORACLE["rgb_mode29_frames"]
        self.assertEqual(len(sequences), 6)
        self.assertEqual({(s["speed"], s["initial_seed"]) for s in sequences},
                         set(itertools.product((0, 128, 255), (0, 65535))))
        self.assertIn("original RNG14900/14924", ORACLE["boundary_policy"])
        self.assertIn("HSV147c0 replaced", ORACLE["boundary_policy"])
        self.assertEqual(ORACLE["payload_sha256"], "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4")
        for sequence in sequences:
            self.assertEqual(len(sequence["steps"]), 16)
            for row in sequence["steps"]:
                self.assertEqual(len(bytes.fromhex(row["led_state_rgb_hex"])), 216)

    def test_wait_precedes_init_and_common_tail_still_advances_iter(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            rows = sequence["steps"]
            for row in rows:
                self.assertEqual(bytes.fromhex(row["params_after_hex"]),
                                 bytes((row["iter"] + 1, row["flags"], int(row["init"]))))
            self.assertTrue(rows[5]["init"])
            for index in (5, 6, 12):
                self.assertFalse(rows[index]["rendering"])
                self.assertEqual(rows[index]["trace"], [])
                for key in ("seed_after", "led_state_rgb_hex", "next_wait"):
                    self.assertEqual(rows[index][key], rows[index - 1][key])

    def test_original_rng_lcg_progression_including_range_calls(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            seed = sequence["initial_seed"]
            for row in sequence["steps"]:
                initialized = any(e[0] == 0 for e in row["trace"])
                colors = sum(e[0] == 2 for e in row["trace"])
                calls = (72 if initialized else 0) + (1 if row["original_memcpy_calls"] else 0) + 2 * colors
                for _ in range(calls):
                    seed = (seed * 2053 + 13849) & 65535
                self.assertEqual(seed, row["seed_after"])

    def test_final_shift_refill_and_deadline(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            rows = sequence["steps"]
            for index in (4, 11, 14):
                row = rows[index]
                before = bytes.fromhex(rows[index - 1]["led_state_rgb_hex"])
                after = bytes.fromhex(row["led_state_rgb_hex"])
                self.assertEqual(row["original_memcpy_calls"], 71)
                self.assertEqual(after[:-3], before[3:])
                colors = [e for e in row["trace"] if e[0] == 2]
                self.assertEqual(after[-3:], bytes(colors[-1][4:]) if colors else b"\0\0\0")
                speed = sequence["speed"]
                interval = 3000 // (min(speed + 16, 255) * 17 >> 8)
                self.assertEqual(row["next_wait"], (row["now"] + interval) & 0xFFFFFFFF)
            self.assertEqual(sum(r["original_memcpy_calls"] for r in rows), 71 * 3)

    def test_rendered_chunk_flags_and_stored_rgb_values(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            before = bytes(216)
            wait = 0
            for row in sequence["steps"]:
                after = bytes.fromhex(row["led_state_rgb_hex"])
                single = [e for e in row["trace"] if e[0] == 1]
                waiting = wait > row["now"]
                if waiting:
                    self.assertEqual(row["trace"], [])
                else:
                    if row["init"]:
                        self.assertEqual(row["trace"][0], [0, 0, 0, 0])
                        before = after  # No tested init call is the final chunk.
                    indices = [i for i in range(row["iter"] * 15, min(row["iter"] * 15 + 15, 72))
                               if FLAGS[i] & row["flags"]]
                    self.assertEqual(single, [[1, i, *before[i * 3:i * 3 + 3]] for i in indices])
                    self.assertEqual(row["rendering"], row["iter"] < 4)
                before, wait = after, row["next_wait"]

    def test_unsigned_wrap_gate_is_preserved_not_repaired(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            row = sequence["steps"][15]
            if sequence["speed"] == 255:
                self.assertEqual(row["trace"], [])
                self.assertFalse(row["rendering"])
            else:
                self.assertTrue(row["rendering"])
                self.assertEqual(len(row["trace"]), 15)


if __name__ == "__main__":
    unittest.main()
