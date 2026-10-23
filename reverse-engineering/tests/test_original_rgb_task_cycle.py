"""Genuine parent task: selected rendering and a separate reselected flush."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"reverse-engineering/tools"))
from audit_original_rgb_task_cycle import validate_oracle, inspect_task_cycle
from audit_original_rgb_timers import age_model
from recover_original_vial import parse_uf2
from test_original_rgb_cycle import apply_trace, post, pwm_digest

FIXTURES=Path(__file__).parent/"fixtures"
ORACLE=json.loads((FIXTURES/"original-rgb-task-cycle.json").read_text())
SEQUENCES=ORACLE["rgb_task_cycles"]
IMAGE=parse_uf2((ROOT/"firmware/origin/FAve40H_VIAL.uf2").read_bytes())
GEOMETRY=IMAGE.read(0x0801DEA0,264)
SCALAR=json.loads((FIXTURES/"original-rgb-hsv.json").read_text())
COLORS={a&0xFFFFFF:r for a,r in SCALAR["grayscale"]+SCALAR["hsv_grid"]}


class OriginalTaskCycleTests(unittest.TestCase):
    def test_complete_grid_and_honest_scope(self):
        self.assertEqual(validate_oracle(ORACLE),SEQUENCES)
        self.assertEqual(sum(len(s["steps"]) for s in SEQUENCES),320)
        self.assertIn("genuine original task calls",ORACLE["boundary_policy"])
        self.assertIn("NEVER executed",ORACLE["boundary_policy"])
        self.assertIn("No separate post/start entry",ORACLE["boundary_policy"])
        inspect_task_cycle(IMAGE)

    def test_rejects_grid_schedule_and_input_mutations(self):
        for change in (lambda o:o["rgb_task_cycles"].pop(),lambda o:o["rgb_task_cycles"][0]["steps"].pop(),
                       lambda o:o["rgb_task_cycles"][0]["steps"][6].update(mode=15),lambda o:o["rgb_task_cycles"][0].update(initial_hits_hex="00"*41)):
            altered=copy.deepcopy(ORACLE);change(altered)
            with self.assertRaises(ValueError):validate_oracle(altered)

    def test_instruction_and_literal_witness_mutations_rejected(self):
        for address in (0x08015618,0x080156C8,0x08015756,0x0801575E,0x0801578C,0x08012FCC,0x08013320):
            class Changed:
                def read(self,start,size):
                    b=bytearray(IMAGE.read(start,size))
                    if start<=address<start+size:b[address-start]^=1
                    return bytes(b)
            with self.assertRaises(ValueError):inspect_task_cycle(Changed())

    def test_actual_state_init_and_flush_tracker_lifetimes(self):
        for s in SEQUENCES:
            last=[255,255];init=0;previous=3
            for r in s["steps"]:
                before=r["state_before"];p=bytes.fromhex(r["params_after_hex"])
                self.assertEqual(before,0 if r["call"]==0 else previous)
                effect=0 if r["suspend"] or not r["enable"] else r["mode"]
                self.assertEqual(r["selected_effect"],effect)
                if before==1:init=int(effect!=last[0] or r["enable"]!=last[1])
                if before==2:last=[effect,r["enable"]]
                self.assertEqual(r["trackers_state"][:2],last)
                self.assertEqual(p[2],init)
                self.assertEqual(r["flush_calls"],int(before==2))
                self.assertEqual(r["clock_reads"],2)
                if before!=1:self.assertEqual((r["render_trace"],r["hsv_calls"],r["caps_white_calls"]),([],0,0))
                previous=r["trackers_state"][2]
            self.assertEqual(previous,3)

    def test_clocks_aging_and_copied_tracker_persist_across_all_calls(self):
        for s in SEQUENCES:
            hits=bytes.fromhex(s["initial_hits_hex"]);tracker=bytes(41);buffer=31;frame=0
            for r in s["steps"]:
                hits=age_model(hits,(r["first_clock"]-buffer)&0xFFFFFFFF);buffer=r["first_clock"]+1
                if r["state_before"]==0:frame=buffer;tracker=hits
                self.assertEqual(r["timer_buffer_after"],buffer)
                self.assertEqual(r["frame_timer_after"],frame)
                self.assertEqual(r["hits_after_hex"],hits.hex())
                self.assertEqual(r["hit_tracker_hex"],tracker.hex())

    def test_between_call_config_changes_and_wait_before_init(self):
        for s in SEQUENCES:
            frames=[[r for r in s["steps"] if r["frame"]==f] for f in range(7)]
            self.assertEqual(frames[0][-2]["selected_effect"],15)
            self.assertEqual(frames[0][-1]["selected_effect"],29)
            # First PixelFlow use is already "last29": zero BSS cache, no forced init.
            self.assertTrue(all(bytes.fromhex(r["params_after_hex"])[2]==0 for r in frames[1][1:-1]))
            self.assertEqual(frames[2][-1]["trackers_state"][:2],[0,2])
            self.assertTrue(all(bytes.fromhex(r["params_after_hex"])[2]==1 for r in frames[2][1:-1]))
            wait=frames[3][1]
            self.assertEqual((wait["hsv_calls"],wait["render_trace"],wait["trackers_state"][2]),(0,[],2))
            self.assertEqual(bytes.fromhex(wait["params_after_hex"])[2],1)
            self.assertEqual(wait["caps_white_calls"],int(bool(s["caps"]&2)))
            self.assertEqual(frames[3][-1]["trackers_state"][:2],[0,0])
            self.assertEqual(frames[4][-1]["trackers_state"][2],3) # warm None skips FLUSHING
            self.assertEqual(frames[5][-1]["trackers_state"][:2],[29,3])
            self.assertTrue(all(bytes.fromhex(r["params_after_hex"])[2]==0 for r in frames[6][1:-1]))

    def test_independent_render_post_and_persistent_pwm_byte_replay(self):
        for s in SEQUENCES:
            pixels=bytes((i*73+19)&255 for i in range(216));pwm=hashlib.sha256(bytes([0xA5])*(1952*4)).hexdigest()
            for r in s["steps"]:
                pixels=apply_trace(pixels,r["render_trace"]);whites=0
                if r["state_before"]==1:
                    pixels,whites=post(pixels,s,{"effect":r["selected_effect"],"render_state":r["trackers_state"][2],"iter_before":bytes.fromhex(r["params_after_hex"])[0]-1})
                if r["flush_calls"]:pwm=pwm_digest(pixels)
                self.assertEqual(r["caps_white_calls"],whites)
                self.assertEqual(r["grb_hex"],pixels.hex())
                self.assertEqual(r["pwm_sha256"],pwm)

    def test_independent_ignore_suspend_counterfactual_40(self):
        differences=0
        for s in SEQUENCES:
            last=[255,255];init=0
            for r in s["steps"]:
                effect=r["mode"] if r["enable"] else 0
                if r["state_before"]==1:init=int(effect!=last[0] or r["enable"]!=last[1])
                if r["state_before"]==2:last=[effect,r["enable"]]
                differences+=effect!=r["selected_effect"] or last!=r["trackers_state"][:2] or init!=bytes.fromhex(r["params_after_hex"])[2]
        self.assertEqual(differences,40)

    def test_independent_live_clock_counterfactual_272_including_carryover(self):
        # All non-STARTING calls have a wrong frame clock. Eight additional
        # STARTING calls inherit changed Chevron GRB/PWM (groups enabled only).
        # PixelFlow clock only changes wait deadlines here: both ready/wait
        # branches remain unchanged in these bounded sequences.
        clock_wrong=0;carry=[]
        for s in SEQUENCES:
            pixels=bytes((i*73+19)&255 for i in range(216));pwm=None
            for r in s["steps"]:
                trace=r["render_trace"]
                if r["state_before"]==1 and r["selected_effect"]==15:
                    phase=((((r["first_clock"]+1)&65535)*34)>>8)&255;trace=[]
                    for event in r["render_trace"]:
                        if event[0]==0:trace.append(event);continue
                        i=event[1];x,y=GEOMETRY[48+2*i:50+2*i];h=(abs(y-32)+x-phase)&255
                        rgb=COLORS[h|(255<<8)|(s["value"]<<16)];trace.append([1,i,rgb&255,(rgb>>8)&255,(rgb>>16)&255])
                pixels=apply_trace(pixels,trace)
                if r["state_before"]==1:pixels,_=post(pixels,s,{"effect":r["selected_effect"],"render_state":r["trackers_state"][2],"iter_before":bytes.fromhex(r["params_after_hex"])[0]-1})
                if r["flush_calls"]:pwm=pwm_digest(pixels)
                if r["state_before"]!=0:clock_wrong+=1
                elif pixels.hex()!=r["grb_hex"] or (pwm is not None and pwm!=r["pwm_sha256"]):carry.append((s["initial_seed"],s["caps"],s["group_word"],r["frame"]))
        self.assertEqual(clock_wrong,264)
        self.assertEqual(len(carry),8)
        self.assertEqual({(group,frame) for _,_,group,frame in carry},{(0xA5B60101,1),(0xA5B60101,6)})
        self.assertEqual(clock_wrong+len(carry),272)


if __name__=="__main__":unittest.main()
