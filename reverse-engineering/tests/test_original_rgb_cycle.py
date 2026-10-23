"""Selected real renderer/post/flush lifetimes; not task scheduling or hardware."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
from audit_original_rgb_cycle import validate_oracle
from recover_original_vial import parse_uf2

ORACLE = json.loads((Path(__file__).parent / "fixtures/original-rgb-cycle.json").read_text())
SEQUENCES = ORACLE["rgb_cycles"]
IMAGE = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())
LED_FLAGS = IMAGE.read(0x0801DF60, 72)


def apply_trace(pixels, trace):
    pixels = bytearray(pixels)
    for event in trace:
        if event[0] == 0:
            _, r, g, b = event
            pixels[:] = bytes((g, r, b)) * 72
        else:
            _, led, r, g, b = event
            if not 0 <= led < 72:
                raise ValueError("Invalid LED trace")
            pixels[led*3:led*3+3] = bytes((g, r, b))
    return pixels


def post(pixels, seq, row):
    pixels = bytearray(pixels)
    white = int(bool(row["effect"] and seq["caps"] & 2 and row["render_state"] == 2))
    if white:
        pixels[22*3:22*3+3] = b"\xff" * 3
    if row["effect"]:
        begin = row["iter_before"] * 15
        for i in range(begin, min(begin+15, 72)):
            if (not seq["group_word"] & 255 and LED_FLAGS[i] & 4) or (not (seq["group_word"] >> 8) & 255 and LED_FLAGS[i] & 2):
                pixels[i*3:i*3+3] = b"\0" * 3
    return pixels, white


def pwm_digest(pixels):
    words = b"".join((21 if byte & (1 << bit) else 8).to_bytes(4, "little") for byte in pixels for bit in range(7, -1, -1))
    return hashlib.sha256(words + b"\xa5" * (224*4)).hexdigest()


class OriginalRgbCycleTests(unittest.TestCase):
    def test_complete_scoped_cycles(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 16)
        self.assertEqual(sum(len(s["steps"]) for s in SEQUENCES), 416)
        for text in ("updated ONLY by actual flush", "ten supplied frame starts", "separately entered post slice", "not entire task/start/sync", "fail closed"):
            self.assertIn(text, ORACLE["boundary_policy"])

    def test_actual_init_lifetime_and_state_transitions(self):
        for seq in SEQUENCES:
            last = [255, 255]
            for row in seq["steps"]:
                init = [row["effect"], row["enable"]] != last
                self.assertEqual(row["params_after_hex"], bytes((row["chunk"]+1, row["flags"], init)).hex())
                self.assertEqual(row["iter_before"], row["chunk"])
                self.assertEqual(row["last_before_flush"], last)
                state = (2 if init else 3) if row["effect"] == 0 else (1 if row["frame"] in (2, 3, 4, 7) and row["chunk"] < 4 else 2)
                self.assertEqual(row["render_state"], state)
                self.assertEqual(row["did_flush"], state == 2)
                if row["did_flush"]:
                    last = [row["effect"], row["enable"]]
                self.assertEqual(row["final_trackers_state"], last + [1 if state == 1 else 3])
            for frame in (2, 4):
                # No synthetic iter0-only init: last trackers stay old until flush.
                self.assertEqual([r["params_after_hex"][-2:] for r in seq["steps"] if r["frame"] == frame], ["01"] * 5)

    def test_wait_before_init_enable_change_commits_without_cache_reinit(self):
        for seq in SEQUENCES:
            frame = {f: [r for r in seq["steps"] if r["frame"] == f] for f in range(10)}
            done = frame[4][-1]
            self.assertEqual(done["next_wait"], 1333)
            for f in (5, 6):
                row = frame[f][0]
                self.assertEqual(row["cache_rgb_hex"], done["cache_rgb_hex"])
                self.assertEqual(row["seed_after"], done["seed_after"])
                self.assertEqual(row["next_wait"], 1333)
                self.assertEqual(row["hsv_calls"], 0)
                self.assertEqual(row["render_trace"], [])
            self.assertEqual(frame[6][0]["params_after_hex"], "01ff01")
            self.assertEqual(frame[6][0]["final_trackers_state"], [29, 2, 3])
            self.assertTrue(all(r["params_after_hex"][-2:] == "00" for r in frame[7]))
            self.assertTrue(all(r["hsv_calls"] == 0 for r in frame[7][:-1]))
            self.assertEqual(frame[7][-1]["next_wait"], 5333)

    def test_pixelflow_init_repeats_rng_and_clear_each_first_frame_chunk(self):
        for seq in SEQUENCES:
            rows = [r for r in seq["steps"] if r["frame"] == 4]
            self.assertEqual(len({r["seed_after"] for r in rows}), 5)
            self.assertEqual(len({r["cache_rgb_hex"] for r in rows}), 5)
            for row in rows:
                self.assertIn([0, 0, 0, 0], row["render_trace"])
                self.assertGreater(row["hsv_calls"], 0)
            # Each later init clears previous chunks; previous supplied-init
            # effect fixtures must not be interpreted as this actual lifetime.
            last_effect = bytes.fromhex(rows[-1]["effect_grb_hex"])
            self.assertEqual(last_effect[:60*3], bytes(60*3))

    def test_persistent_grb_replay_post_and_full_pwm_match_independent_models(self):
        for seq in SEQUENCES:
            pixels = bytes.fromhex(seq["initial_grb_hex"])
            pwm = hashlib.sha256(b"\xa5" * (1952*4)).hexdigest()
            for row in seq["steps"]:
                pixels = apply_trace(pixels, row["render_trace"])
                self.assertEqual(pixels.hex(), row["effect_grb_hex"])
                pixels, white = post(pixels, seq, row)
                self.assertEqual(white, row["caps_white_calls"])
                self.assertEqual(pixels.hex(), row["post_grb_hex"])
                if row["did_flush"]:
                    pwm = pwm_digest(pixels)
                self.assertEqual(pwm, row["pwm_sha256"])

    def test_final_caps_survives_disabled_keylight_and_wait_completions(self):
        for seq in SEQUENCES:
            if seq["caps"] != 2 or seq["group_word"] & 255:
                continue
            for row in seq["steps"]:
                if row["effect"] and row["render_state"] == 2:
                    self.assertEqual(row["caps_white_calls"], 1)
                    self.assertEqual(bytes.fromhex(row["post_grb_hex"])[66:69], b"\xff" * 3)

    def test_negative_counts_match_independent_persistent_replay(self):
        skip_post = boolean_enable = 0
        for seq in SEQUENCES:
            pixels = bytes.fromhex(seq["initial_grb_hex"])
            pwm = hashlib.sha256(b"\xa5" * (1952*4)).hexdigest()
            for row in seq["steps"]:
                pixels = apply_trace(pixels, row["render_trace"])
                if row["did_flush"]:
                    pwm = pwm_digest(pixels)
                skip_post += bool(row["caps_white_calls"] or pixels.hex() != row["effect_grb_hex"] or pixels.hex() != row["post_grb_hex"] or pwm != row["pwm_sha256"])
                old_effect, old_enable = row["last_before_flush"]
                boolean_init = row["effect"] != old_effect or bool(row["enable"]) != bool(old_enable)
                boolean_enable += boolean_init != bool(bytes.fromhex(row["params_after_hex"])[2])
        self.assertEqual(skip_post, 279)
        self.assertEqual(boolean_enable, 16)

    def test_incomplete_or_changed_schedules_rejected(self):
        for mutate in (lambda o: o["rgb_cycles"].pop(),
                       lambda o: o["rgb_cycles"][0]["steps"].pop(),
                       lambda o: o["rgb_cycles"][0]["steps"][1].update(chunk=1),
                       lambda o: o["rgb_cycles"][0]["steps"][0].update(mode=29),
                       lambda o: o["rgb_cycles"][0].update(group_word=0),
                       lambda o: o["rgb_cycles"][0].update(value=1)):
            changed = copy.deepcopy(ORACLE); mutate(changed)
            with self.assertRaises(ValueError):
                validate_oracle(changed)


if __name__ == "__main__":
    unittest.main()
