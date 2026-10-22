"""Mode29 real HSV integration: actual Thumb colors, persistent state and boundaries."""
import itertools
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent
ROOT = HERE.parents[1]
ORACLE = json.loads((HERE / "fixtures/original-rgb-mode29-frames-real-hsv.json").read_text())
DIAGNOSTIC = json.loads((HERE / "fixtures/original-rgb-mode29-frames.json").read_text())
SCALAR = json.loads((HERE / "fixtures/original-rgb-hsv.json").read_text())
FLAGS = json.loads((ROOT / "reverse-engineering/original-vial/evidence.json").read_text())["rgb"]["flags"]
TABLE = bytes.fromhex(ORACLE["cie_table_hex"])


class OriginalMode29RealHSVTests(unittest.TestCase):
    def test_declared_scope_and_actual_hsv_call_counts(self):
        sequences = ORACLE["rgb_mode29_frames"]
        self.assertEqual(len(sequences), 6)
        self.assertEqual({(s["speed"], s["initial_seed"]) for s in sequences},
                         set(itertools.product((0, 128, 255), (0, 65535))))
        self.assertTrue(ORACLE["actual_hsv_conversion_executed"])
        self.assertEqual(ORACLE["payload_sha256"], DIAGNOSTIC["payload_sha256"])
        self.assertIn("no HSV argument/result/PC replacement", ORACLE["boundary_policy"])
        self.assertIn("Not full renderer", ORACLE["boundary_policy"])
        count = 0
        for sequence in sequences:
            self.assertEqual(len(sequence["steps"]), 16)
            for row in sequence["steps"]:
                colors = [e for e in row["trace"] if e[0] == 2]
                self.assertEqual(row["original_hsv_calls"], len(colors))
                count += len(colors)
        self.assertEqual(count, 441)

    def test_only_colors_change_against_preserved_diagnostic_cases(self):
        differing = 0
        for real, diagnostic in zip(ORACLE["rgb_mode29_frames"], DIAGNOSTIC["rgb_mode29_frames"]):
            for field in ("speed", "initial_seed", "value"):
                self.assertEqual(real[field], diagnostic[field])
            for row, old in zip(real["steps"], diagnostic["steps"]):
                for key in old.keys() - {"trace", "led_state_rgb_hex"}:
                    self.assertEqual(row[key], old[key])
                self.assertEqual(len(row["trace"]), len(old["trace"]))
                for event, previous in zip(row["trace"], old["trace"]):
                    # Operation kind, HSV inputs and LED indices stay identical.
                    size = {0: 1, 1: 2, 2: 4}[event[0]]
                    self.assertEqual(event[:size], previous[:size])
                differing += row["trace"] != old["trace"]
        self.assertGreater(differing, 0)

    def test_actual_cie_values_and_shared_scalar_samples(self):
        self.assertEqual(TABLE.hex(), SCALAR["cie_table_hex"])
        scalar = {arg & 0xFFFFFF: rgb for arg, rgb in SCALAR["grayscale"] + SCALAR["hsv_grid"]}
        covered = 0
        for sequence in ORACLE["rgb_mode29_frames"]:
            for row in sequence["steps"]:
                for event in row["trace"]:
                    if event[0] != 2:
                        continue
                    _, h, s, v, r, g, b = event
                    self.assertEqual(v, sequence["value"])
                    self.assertEqual(max(r, g, b), TABLE[v])
                    self.assertTrue(0 <= h <= 255 and 127 <= s < 255)
                    packed = h | (s << 8) | (v << 16)
                    if packed in scalar:
                        self.assertEqual(r | (g << 8) | (b << 16), scalar[packed])
                        covered += 1
        self.assertGreater(covered, 0)

    def test_original_cache_replay_with_actual_rng_and_hsv_results(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            seed, wait, state = sequence["initial_seed"], 0, [bytes(3)] * 72

            def random8():
                nonlocal seed
                seed = (seed * 2053 + 13849) & 65535
                return (seed + (seed >> 8)) & 255

            for row in sequence["steps"]:
                colors = iter(e for e in row["trace"] if e[0] == 2)

                def color():
                    if random8() & 2:
                        return bytes(3)
                    h, s = random8(), 127 + ((random8() * 128) >> 8)
                    event = next(colors)
                    self.assertEqual(event[1:4], [h, s, sequence["value"]])
                    return bytes(event[4:])

                if wait > row["now"]:
                    self.assertEqual(row["trace"], [])
                    self.assertFalse(row["rendering"])
                else:
                    if row["init"]:
                        self.assertEqual(row["trace"][0], [0, 0, 0, 0])
                        state = [color() for _ in range(72)]
                    indices = [i for i in range(row["iter"] * 15, min(row["iter"] * 15 + 15, 72)) if FLAGS[i] & row["flags"]]
                    self.assertEqual([e for e in row["trace"] if e[0] == 1], [[1, i, *state[i]] for i in indices])
                    self.assertEqual(row["rendering"], row["iter"] < 4)
                    if row["iter"] == 4:
                        state = state[1:] + [color()]
                        wait = (row["now"] + 3000 // (min(sequence["speed"] + 16, 255) * 17 >> 8)) & 0xFFFFFFFF
                self.assertEqual(list(colors), [])
                self.assertEqual(b"".join(state).hex(), row["led_state_rgb_hex"])
                self.assertEqual(seed, row["seed_after"])
                self.assertEqual(wait, row["next_wait"])

    def test_wait_before_init_and_wrapped_deadline_remain_original(self):
        for sequence in ORACLE["rgb_mode29_frames"]:
            rows = sequence["steps"]
            self.assertTrue(rows[5]["init"])
            self.assertFalse(rows[5]["rendering"])
            self.assertEqual(rows[5]["original_hsv_calls"], 0)
            self.assertEqual(rows[5]["led_state_rgb_hex"], rows[4]["led_state_rgb_hex"])
            self.assertEqual(rows[15]["rendering"], sequence["speed"] != 255)
            self.assertEqual(rows[15]["original_hsv_calls"], 0)

    def test_actual_partial_brightness_not_diagnostic_mapping(self):
        colors = [event for seq in ORACLE["rgb_mode29_frames"] if seq["value"] == 128
                  for row in seq["steps"] for event in row["trace"] if event[0] == 2]
        self.assertTrue(colors)
        self.assertEqual(TABLE[128], 48)
        sensitive_rows = sum(seq["value"] == 128 and any(
            event[0] == 2 or (event[0] == 1 and any(event[2:])) for event in row["trace"])
            for seq in ORACLE["rgb_mode29_frames"] for row in seq["steps"])
        self.assertEqual(sensitive_rows, 35)
        for _, h, s, v, r, g, b in colors:
            self.assertEqual(max(r, g, b), 48)
            self.assertNotEqual([r, g, b], [(h + v) & 255, s ^ v, h ^ s])


if __name__ == "__main__":
    unittest.main()
