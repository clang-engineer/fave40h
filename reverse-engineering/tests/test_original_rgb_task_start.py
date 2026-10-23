"""Actual whole STARTING invocation; unsupported render/flush/sync excluded."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"reverse-engineering/tools"))
from audit_original_rgb_task_start import inspect_task_start,validate_oracle
from audit_original_rgb_timers import age_model
from recover_original_vial import parse_uf2

ORACLE=json.loads((Path(__file__).parent/"fixtures/original-rgb-task-start.json").read_text())
ROWS=ORACLE["rgb_task_start"]
IMAGE=parse_uf2((ROOT/"firmware/origin/FAve40H_VIAL.uf2").read_bytes())


class OriginalRgbTaskStartTests(unittest.TestCase):
    def test_complete_grid_and_real_task_entry_return_scope(self):
        self.assertEqual(len(validate_oracle(ORACLE)),384)
        for text in ("genuine prologue", "epilogue and return", "no supplied r5/r6/SP/OV", "State0 only", "no effect bodies", "unsupported paths trapped", "BEFORE copied"):
            self.assertIn(text,ORACLE["boundary_policy"])

    def test_selection_suspend_return_instruction_mutations_rejected(self):
        inspect_task_start(IMAGE)
        for address in (0x08015658,0x0801565C,0x08015662,0x08015668,0x080156AA,0x0801571A,0x0801571C,0x08015788,0x0801578C):
            class Changed:
                def read(self,start,size):
                    data=bytearray(IMAGE.read(start,size))
                    if start<=address<start+size:data[address-start]^=1
                    return bytes(data)
            with self.assertRaises(ValueError):inspect_task_start(Changed())

    def test_actual_selection_honors_suspend_and_all_nonzero_enable_bytes(self):
        for r in ROWS:
            effect=r["mode"] if r["enable"] and not r["suspend"] else 0
            self.assertEqual(r["selected_effect"],effect)
        for enable in (2,3):
            self.assertEqual({r["selected_effect"] for r in ROWS if r["enable"]==enable and not r["suspend"]},{0,15,29,45})

    def test_two_reads_aging_then_start_copies_current_not_stale_data(self):
        for r in ROWS:
            self.assertEqual(r["clock_reads"],2)
            self.assertEqual(r["memcpy_calls"],1)
            self.assertEqual(r["timer_buffer_after"],r["second_clock"])
            self.assertEqual(r["frame_timer_after"],r["second_clock"])
            aged=age_model(bytes.fromhex(r["input_hits_hex"]),1).hex()
            self.assertEqual(r["aged_hits_hex"],aged)
            self.assertEqual(r["tracker_after_hex"],aged)
            if r["count"]==8:
                self.assertEqual(bytes.fromhex(aged)[0],6)
                self.assertNotEqual(aged,r["input_hits_hex"])

    def test_start_only_resets_iter_and_advances_to_rendering(self):
        for r in ROWS:
            self.assertEqual(r["params_after_hex"],"00a501")
            self.assertEqual(r["state_after"],1)

    def test_suspension_and_disable_do_not_skip_timer_or_frame_copy(self):
        for r in ROWS:
            if not r["suspend"] and r["enable"]:continue
            self.assertEqual(r["selected_effect"],0)
            self.assertEqual(r["clock_reads"],2)
            self.assertEqual(r["memcpy_calls"],1)
            self.assertEqual(r["tracker_after_hex"],r["aged_hits_hex"])

    def test_negative_counts_independently_match_native(self):
        self.assertEqual(sum(bool(r["suspend"] and r["enable"] and r["mode"]) for r in ROWS),108)
        self.assertEqual(sum(bool(not r["suspend"] and r["enable"] in (2,3) and r["mode"]) for r in ROWS),72)
        self.assertEqual(sum(r["input_hits_hex"]!=r["tracker_after_hex"] for r in ROWS),192)

    def test_incomplete_or_changed_inputs_rejected(self):
        for mutate in (lambda o:o["rgb_task_start"].pop(),lambda o:o["rgb_task_start"][0].update(mode=1),
                       lambda o:o["rgb_task_start"][0].update(enable=4),lambda o:o["rgb_task_start"][0].update(suspend=2),
                       lambda o:o["rgb_task_start"][0].update(input_hits_hex="00"*41),lambda o:o["rgb_task_start"][0].update(first_clock=9)):
            changed=copy.deepcopy(ORACLE);mutate(changed)
            with self.assertRaises(ValueError):validate_oracle(changed)


if __name__=="__main__":unittest.main()
