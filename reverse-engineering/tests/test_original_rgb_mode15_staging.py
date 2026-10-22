"""Persistent RAM-only mode15 + post-effect composition; not whole renderer/HAL."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_mode15_staging import inspect_staging, validate_oracle
from recover_original_vial import parse_uf2

FIXTURES = Path(__file__).parent / "fixtures"
ORACLE = json.loads((FIXTURES / "original-rgb-mode15-staging.json").read_text())
SEQUENCES = ORACLE["rgb_mode15_staging"]
OLD = json.loads((FIXTURES / "original-rgb-mode15.json").read_text())["rgb_mode15"]
IMAGE = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())
FLAGS = IMAGE.read(0x0801DF60, 72)


def replay(negative=0):
    differences = 0
    for seq in SEQUENCES:
        pixels = bytearray.fromhex(seq["initial_grb_hex"])
        for row in seq["steps"]:
            for event in row["trace"]:
                if event[0] == 1:
                    _, i, r, g, b = event
                    pixels[i*3:i*3+3] = bytes((r, g, b) if negative == 3 else (g, r, b))
            before = pixels.hex()
            white = 0
            if negative != 1:
                if seq["caps"] == 2 and (row["iter"] == 4 or negative == 2):
                    pixels[66:69] = b"\xff\xff\xff"
                    white = 1
                for i in range(row["iter"] * 15, min(row["iter"] * 15 + 15, 72)):
                    if (((seq["group_word"] & 255) == 0 and FLAGS[i] & 4) or
                            (((seq["group_word"] >> 8) & 255) == 0 and FLAGS[i] & 2)):
                        pixels[i*3:i*3+3] = b"\x00\x00\x00"
            differences += (before != row["effect_grb_hex"] or pixels.hex() != row["post_grb_hex"] or white != row["caps_white_calls"])
    return differences


class OriginalMode15StagingTests(unittest.TestCase):
    def test_full_persistent_grid_and_explicit_boundaries(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 288)
        self.assertEqual(sum(len(seq["steps"]) for seq in SEQUENCES), 1440)
        for text in ("separately entered", "no RGB setter replacement", "flush/DMA/HAL/device"):
            self.assertIn(text, ORACLE["boundary_policy"])
        self.assertEqual(sum(len(row["trace"]) // 2 for seq in SEQUENCES for row in seq["steps"]), 10368)

    def test_actual_ram_setter_wrapper_and_literal_witnesses(self):
        inspect_staging(IMAGE)
        for address in (0x080132EC, 0x080132F6, 0x08013300, 0x08014A78):
            class Changed:
                def read(self, start, size):
                    data = bytearray(IMAGE.read(start, size))
                    if start <= address < start + size:
                        data[address - start] ^= 1
                    return bytes(data)
            with self.assertRaises(ValueError):
                inspect_staging(Changed())

    def test_effect_trace_is_identical_to_separate1260_case_fixture(self):
        old = {tuple(r[k] for k in ("speed", "now", "hsv", "flags", "iter")): r for r in OLD}
        for seq in SEQUENCES:
            for row in seq["steps"]:
                expected = old[tuple(row[k] for k in ("speed", "now", "hsv", "flags", "iter"))]
                self.assertEqual({key: row[key] for key in expected}, expected)

    def test_all2880_before_after_snapshots_replay_in_persistent_order(self):
        self.assertEqual(replay(), 0)

    def test_independent_counterfactuals_match_native_difference_counts(self):
        self.assertEqual(replay(1), 696)  # omitted post pass
        self.assertEqual(replay(2), 720)  # basic Caps on unfinished chunks
        self.assertEqual(replay(3), 888)  # RGB bytes misinterpreted as GRB

    def test_caps_final_white_survives_disabled_keylight_filter(self):
        for seq in SEQUENCES:
            if seq["caps"] != 2 or seq["group_word"] & 255:
                continue
            self.assertEqual([r["caps_white_calls"] for r in seq["steps"]], [0, 0, 0, 0, 1])
            self.assertEqual(bytes.fromhex(seq["steps"][-1]["post_grb_hex"])[66:69], b"\xff\xff\xff")
            # LED22 was cleared when chunk1 covered it, before final Caps writes.
            self.assertEqual(bytes.fromhex(seq["steps"][1]["post_grb_hex"])[66:69], b"\x00\x00\x00")

    def test_incomplete_or_changed_context_rejected(self):
        for mutate in (lambda o: o["rgb_mode15_staging"].pop(),
                       lambda o: o["rgb_mode15_staging"][0].update(speed=127),
                       lambda o: o["rgb_mode15_staging"][0]["steps"][0].update(rendering=False),
                       lambda o: o["rgb_mode15_staging"][0]["steps"][0].update(caps_white_calls=1),
                       lambda o: o["rgb_mode15_staging"][0].update(initial_grb_hex="00" * 216),
                       lambda o: o["rgb_mode15_staging"][0]["steps"][0].update(effect_grb_hex="00")):
            changed = copy.deepcopy(ORACLE)
            mutate(changed)
            with self.assertRaises(ValueError):
                validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
