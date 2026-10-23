"""Full RAM flush/driver dispatch/encoder, not hardware or caller scheduling."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_flush import inspect_flush, validate_oracle
from recover_original_vial import parse_uf2

ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-flush.json").read_text())
ROWS = ORACLE["rgb_flush"]
IMAGE = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())


def expected_pwm(grb):
    words = [21 if byte & (1 << bit) else 8 for byte in grb for bit in range(7, -1, -1)]
    return b"".join(word.to_bytes(4, "little") for word in words) + b"\xA5" * (224 * 4)


class OriginalRgbFlushTests(unittest.TestCase):
    def test_complete_grid_and_full_ram_function_scope(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 96)
        for text in ("full RAM flush-function", "No instruction/API replacement", "reset tail", "physical timer/DMA/HAL"):
            self.assertIn(text, ORACLE["boundary_policy"])

    def test_flush_branch_and_literal_mutations_rejected(self):
        inspect_flush(IMAGE)
        for address in (0x08012FCC, 0x08012FDE, 0x08012FE4, 0x08012FF8, 0x08013384):
            class Changed:
                def read(self, start, size):
                    data = bytearray(IMAGE.read(start, size))
                    if start <= address < start + size:
                        data[address-start] ^= 1
                    return bytes(data)
            with self.assertRaises(ValueError):
                inspect_flush(Changed())
        # Original encoder walks backward through the first byte's bits.
        self.assertEqual(int.from_bytes(IMAGE.read(0x08013384, 4), "little"), 0x200031E0 + 7*4)
        self.assertEqual(int.from_bytes(IMAGE.read(0x08013380, 4), "little"), 0x20005064)

    def test_trackers_are_committed_before_encoder_and_sync_only_after(self):
        for row in ROWS:
            self.assertEqual(row["encoder_calls"], 1)
            self.assertEqual([o["phase"] for o in row["observations"]], ["before", "after"])
            for event in row["observations"]:
                self.assertEqual(event["trackers_state"], [row["effect"], row["enable"], 2])
            self.assertEqual(row["final_trackers_state"], [row["effect"], row["enable"], 3])

    def test_all1952_words_match_independent_msb_first_grb_encoding(self):
        initial = hashlib.sha256(b"\xA5" * (1952 * 4)).hexdigest()
        for row in ROWS:
            pwm = expected_pwm(bytes.fromhex(row["input_grb_hex"]))
            self.assertEqual(len(pwm), 1952*4)
            digest = hashlib.sha256(pwm).hexdigest()
            self.assertEqual(row["observations"][0]["pwm_sha256"], initial)
            self.assertEqual(row["observations"][1]["pwm_sha256"], digest)
            self.assertEqual(row["final_pwm_sha256"], digest)

    def test_pulse_outputs_depend_on_pixels_not_effect_or_enable(self):
        for pattern in ("ramp", "black", "white"):
            hashes = {r["final_pwm_sha256"] for r in ROWS if r["pattern"] == pattern}
            self.assertEqual(len(hashes), 1)
        self.assertEqual(len({r["final_pwm_sha256"] for r in ROWS}), 3)

    def test_counterfactual_counts_independently_match_native(self):
        late = sum([r["old_effect"], r["old_enable"]] != [r["effect"], r["enable"]] for r in ROWS)
        self.assertEqual(late, 93)
        self.assertEqual(sum(any(o["trackers_state"][2] != 3 for o in r["observations"]) for r in ROWS), 96)
        self.assertEqual(sum(bool(r["encoder_calls"]) for r in ROWS), 96)

    def test_incomplete_or_changed_inputs_rejected(self):
        for mutate in (lambda o: o["rgb_flush"].pop(),
                       lambda o: o["rgb_flush"][0].update(enable=4),
                       lambda o: o["rgb_flush"][0].update(pattern="unknown"),
                       lambda o: o["rgb_flush"][0].update(input_grb_hex="00" * 216)):
            changed = copy.deepcopy(ORACLE); mutate(changed)
            with self.assertRaises(ValueError):
                validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
