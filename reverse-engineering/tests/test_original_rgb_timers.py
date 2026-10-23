"""Clock getter boundary and original unsigned/non-compacting aging quirks."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/"reverse-engineering/tools"))
from audit_original_rgb_timers import inspect_timers, validate_oracle, age_model
from recover_original_vial import parse_uf2

ORACLE = json.loads((Path(__file__).parent/"fixtures/original-rgb-timers.json").read_text())
ROWS = ORACLE["rgb_timers"]
IMAGE = parse_uf2((ROOT/"firmware/origin/FAve40H_VIAL.uf2").read_bytes())


def ticks(data):
    return [int.from_bytes(data[25+2*i:27+2*i], "little") for i in range(8)]


class OriginalRgbTimersTests(unittest.TestCase):
    def test_complete_grid_and_scope(self):
        self.assertEqual(len(validate_oracle(ORACLE)), 432)
        for text in ("original prologue", "only clock getter", "two supplied uint32", "Stop before mode selection", "count255 NOT accepted", "not repaired"):
            self.assertIn(text, ORACLE["boundary_policy"])

    def test_instruction_and_pointer_mutations_rejected(self):
        inspect_timers(IMAGE)
        for address in (0x08015618,0x08015624,0x0801562E,0x08015636,0x08015656,0x0801567A,0x0801568E,0x08015694,0x080156A6,0x08015780,0x08015784):
            class Changed:
                def read(self, start, size):
                    data=bytearray(IMAGE.read(start,size))
                    if start<=address<start+size:data[address-start]^=1
                    return bytes(data)
            with self.assertRaises(ValueError):inspect_timers(Changed())

    def test_two_clock_reads_first_delta_second_buffer_and_wrap(self):
        for r in ROWS:
            self.assertEqual(r["clock_reads"],2)
            self.assertEqual((r["first_clock"]-r["old_timer"])&0xFFFFFFFF,r["delta"])
            self.assertEqual((r["second_clock"]-r["first_clock"])&0xFFFFFFFF,r["skew"])
            self.assertEqual(r["timer_buffer_after"],r["second_clock"])
        self.assertTrue(any(r["first_clock"]<r["old_timer"] for r in ROWS))

    def test_byte_output_matches_independent_tick_arithmetic(self):
        for r in ROWS:
            before=bytes.fromhex(r["input_hits_hex"]);after=bytes.fromhex(r["hits_after_hex"])
            old_ticks=ticks(before);new_ticks=ticks(after);removed=0
            threshold=(65535-r["delta"])%2**32
            self.assertEqual(after[1:25],before[1:25])
            for i,old_tick in enumerate(old_ticks):
                if i>=r["count"]:expected=old_tick
                elif old_tick>threshold:expected=old_tick;removed+=1
                else:expected=(old_tick+r["delta"])%65536
                self.assertEqual(new_ticks[i],expected)
            self.assertEqual(after[0],r["count"]-removed)

    def test_expiration_does_not_compact_or_stop_at_shrinking_count(self):
        r=next(r for r in ROWS if (r["old_timer"],r["delta"],r["skew"],r["count"],r["pattern"])==(0,1,0,4,2))
        data=bytes.fromhex(r["hits_after_hex"])
        self.assertEqual(data[0],3)
        self.assertEqual(ticks(data)[:4],[65535,1,65535,2])
        # Expired index0 remains; index3 still updates despite final count3.
        self.assertEqual(data[1:25],bytes.fromhex(r["input_hits_hex"])[1:25])

    def test_large_delta_underflow_retains_count_and_wraps_ticks(self):
        for r in ROWS:
            if r["delta"]<=65535:continue
            before=bytes.fromhex(r["input_hits_hex"]);after=bytes.fromhex(r["hits_after_hex"])
            self.assertEqual(after[0],before[0])
            for i in range(r["count"]):self.assertEqual(ticks(after)[i],(ticks(before)[i]+r["delta"])&65535)

    def test_counterfactual_counts_match_native(self):
        differences={name:0 for name in ("delta_from_second","saturate_age","zero_expired")}
        for r in ROWS:
            before=bytes.fromhex(r["input_hits_hex"])
            for name in differences:
                delta=(r["delta"]+r["skew"])&0xFFFFFFFF if name=="delta_from_second" else r["delta"]
                differences[name]+=age_model(before,delta,name=="saturate_age",name=="zero_expired").hex()!=r["hits_after_hex"]
        self.assertEqual(differences,{"delta_from_second":156,"saturate_age":108,"zero_expired":100})

    def test_incomplete_or_invalid_count_inputs_rejected(self):
        for mutate in (lambda o:o["rgb_timers"].pop(),lambda o:o["rgb_timers"][0].update(count=255),
                       lambda o:o["rgb_timers"][0].update(first_clock=1),lambda o:o["rgb_timers"][0].update(second_clock=1),
                       lambda o:o["rgb_timers"][0].update(input_hits_hex="00"*41)):
            changed=copy.deepcopy(ORACLE);mutate(changed)
            with self.assertRaises(ValueError):validate_oracle(changed)


if __name__=="__main__":unittest.main()
