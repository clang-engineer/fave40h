"""Original per-chunk RGB observations; no full engine or hardware execution."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
TARGET=ROOT/"reverse-engineering/keyboards/fave40h_original"
ORACLE=json.loads((Path(__file__).parent/"fixtures/original-vial-emulation.json").read_text())


class OriginalRGBChunkTests(unittest.TestCase):
    def test_all_uint8_limits_and_normal_five_spans(self):
        cases=ORACLE["rgb_limits"]
        self.assertEqual([c["iter"] for c in cases],list(range(256)))
        for case in cases:
            minimum=(case["iter"]*15)&255
            maximum=min(72,((case["iter"]+1)*15)&255)
            self.assertEqual(case["packed_limits"],minimum|(maximum<<8))
        self.assertEqual([(c["packed_limits"]&255,c["packed_limits"]>>8) for c in cases[:5]],[(0,15),(15,30),(30,45),(45,60),(60,72)])
        self.assertIn("only iter0..4",ORACLE["rgb_chunk_boundary_policy"])

    def test_original_caps_before_filter_final_chunk_quirk_is_not_silently_fixed(self):
        cases=ORACLE["rgb_composed_chunks"]
        self.assertEqual(len(cases),24)
        for case in cases:
            self.assertEqual(case["caps_white_calls"],int(case["iter"]==4 and bool(case["caps"])))
            if case["iter"]==1 and case["keylight"]==0:
                self.assertEqual(case["caps_led_after"],[0,0,0])
            if case["iter"]==4 and case["caps"]:
                self.assertEqual(case["caps_led_after"],[255,255,255])
        self.assertTrue(any(c["iter"]==4 and c["caps"] and not c["keylight"] and c["caps_led_after"]==[255,255,255] for c in cases))

    def test_target_pins_original_chunk_size_without_claiming_complete_indicators(self):
        self.assertIn("#define RGB_MATRIX_LED_PROCESS_LIMIT 15",(TARGET/"config.h").read_text())
        manifest=json.loads((TARGET/"target-evidence.json").read_text())
        self.assertEqual(manifest["rgb_chunks"]["normal_spans"],[[0,15],[15,30],[30,45],[45,60],[60,72]])
        self.assertIn("do not silently fix",manifest["rgb_chunks"]["caps_filter_quirk"])
        self.assertFalse(manifest["complete_firmware"])
        self.assertTrue(manifest["build_blockers"])


if __name__=="__main__":
    unittest.main()
