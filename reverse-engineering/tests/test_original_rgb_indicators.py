"""Real target user hooks with controlled host/color/input APIs, not full QMK."""
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
TARGET=ROOT/"reverse-engineering/keyboards/fave40h_original"
ORACLE=json.loads((Path(__file__).parent/"fixtures/original-vial-emulation.json").read_text())
EVIDENCE=json.loads((ROOT/"reverse-engineering/original-vial/evidence.json").read_text())


class Record(ctypes.Structure):
    # Controlled unit shim; pinned actual keyrecord types are checked by RGB CLI.
    _fields_=[("pressed",ctypes.c_bool)]


class OriginalRGBIndicatorTests(unittest.TestCase):
    def test_native_target_selected_user_hooks_match_original(self):
        cc=shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler absent")
        with tempfile.TemporaryDirectory(prefix="fave40h-indicators-") as directory:
            temp=Path(directory)
            # ABI/API shims for self-contained unit execution. The separate RGB
            # verifier uses pinned actual types and actual dispatcher bodies.
            (temp/"quantum.h").write_text('''#include <stdint.h>
#include <stdbool.h>
typedef struct { struct { bool pressed; } event; } keyrecord_t;
typedef struct { uint8_t x,y; } led_point_t;
typedef struct { uint8_t matrix_co[4][12]; led_point_t point[72]; uint8_t flags[72]; } led_config_t;
uint32_t eeconfig_read_user(void);
void eeconfig_update_user(uint32_t);
uint8_t host_keyboard_leds(void);
void register_code(uint8_t);
void unregister_code(uint8_t);
void perform_space_cadet(keyrecord_t *,uint16_t,uint8_t,uint8_t,uint8_t);
void rgb_matrix_set_color(int,uint8_t,uint8_t,uint8_t);
''')
            (temp/"probe.c").write_text(f'''#include "{TARGET/'fave40h_original.c'}"
uint8_t frame[216],caps;
uint32_t whites,bad_index,io_calls,hid[5],cadet_request[6];
void perform_space_cadet(keyrecord_t *record,uint16_t key,uint8_t hold,uint8_t mod,uint8_t tap) {{
    ++cadet_request[0]; cadet_request[1]=key; cadet_request[2]=record->event.pressed;
    cadet_request[3]=hold; cadet_request[4]=mod; cadet_request[5]=tap;
}}
void capture_code(uint32_t pressed,uint8_t code) {{
    if(hid[0]<2) {{ hid[1+hid[0]*2]=pressed; hid[2+hid[0]*2]=code; }}
    ++hid[0];
}}
void register_code(uint8_t code) {{ capture_code(1,code); }}
void unregister_code(uint8_t code) {{ capture_code(0,code); }}
uint32_t eeconfig_read_user(void) {{ ++io_calls; return 0; }}
void eeconfig_update_user(uint32_t value) {{ (void)value; ++io_calls; }}
uint8_t host_keyboard_leds(void) {{ return caps; }}
void rgb_matrix_set_color(int i,uint8_t r,uint8_t g,uint8_t b) {{
    if(i<0 || i>=72) {{ ++bad_index; return; }}
    if(i==22 && r==255 && g==255 && b==255) ++whites;
    frame[i*3]=g; frame[i*3+1]=r; frame[i*3+2]=b;
}}
''')
            library=temp/("indicators.dylib" if sys.platform=="darwin" else "indicators.so")
            subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Werror","-shared","-fPIC","-I",str(temp),str(temp/"probe.c"),"-o",str(library)],check=True,capture_output=True)
            lib=ctypes.CDLL(str(library))
            frame=(ctypes.c_uint8*216).in_dll(lib,"frame")
            state=ctypes.c_uint32.in_dll(lib,"original_rgb_group_state")
            caps=ctypes.c_uint8.in_dll(lib,"caps")
            whites=ctypes.c_uint32.in_dll(lib,"whites")
            lib.rgb_matrix_indicators_user.restype=ctypes.c_bool
            lib.rgb_matrix_indicators_advanced_user.argtypes=[ctypes.c_uint8,ctypes.c_uint8]
            lib.rgb_matrix_indicators_advanced_user.restype=ctypes.c_bool
            for composed,cases in ((False,ORACLE["filters"]),(True,ORACLE["rgb_composed_chunks"])):
                for case in cases:
                    ctypes.memmove(frame,bytes.fromhex(case["input_grb_hex"]),216)
                    keylight,underglow=(case["keylight"],case["underglow"]) if composed else case["enabled"]
                    before=0xA5B60000|keylight|(underglow<<8)
                    state.value=before
                    caps.value=case["caps"] if composed else 0
                    whites.value=0
                    if composed:
                        if case["iter"]==4:
                            self.assertTrue(lib.rgb_matrix_indicators_user())
                        begin=case["iter"]*15
                        end=min(begin+15,72)
                    else:
                        begin,end=case["begin"],case["end"]
                    self.assertTrue(lib.rgb_matrix_indicators_advanced_user(begin,end))
                    self.assertEqual(hashlib.sha256(bytes(frame)).hexdigest(),case["expected_grb_sha256"])
                    self.assertEqual(state.value,before)
                    self.assertEqual(whites.value,case["caps_white_calls"] if composed else 0)
            lib.process_record_user.argtypes=[ctypes.c_uint16,ctypes.POINTER(Record)]
            lib.process_record_user.restype=ctypes.c_bool
            for case in ORACLE["rgb_controls"]:
                state.value=0xA5B60000|case["before"][0]|(case["before"][1]<<8)
                record=Record(case["pressed"])
                before_frame=bytes(frame)
                self.assertFalse(lib.process_record_user(case["keycode"],ctypes.byref(record)))
                self.assertEqual(state.value,0xA5B60000|case["after"][0]|(case["after"][1]<<8))
                self.assertEqual(record.pressed,case["pressed"])
                self.assertEqual(bytes(frame),before_frame)
            for key in (0,4,0xE1,0x7DFF,0x7E16,0xFFFF):
                for pressed in (False,True):
                    state.value=0xA5B60280
                    self.assertTrue(lib.process_record_user(key,ctypes.byref(Record(pressed))))
                    self.assertEqual(state.value,0xA5B60280)
            # This unit captures only the user->upstream-helper arguments.
            # Actual unmodified helper/state/dispatch differential is in RGB CLI.
            request=(ctypes.c_uint32*6).in_dll(lib,"cadet_request")
            for row in EVIDENCE["vendor_space_cadet"]["parameters"]:
                for pressed in (False,True):
                    request[0]=0
                    self.assertFalse(lib.process_record_user(row["keycode"],ctypes.byref(Record(pressed))))
                    self.assertEqual(list(request),[1,row["keycode"],int(pressed),row["hold_modifier"],row["tap_modifier"],row["tap_keycode"]])
            selector=ctypes.c_uint8.in_dll(lib,"original_last_shift_edge")
            hid=(ctypes.c_uint32*5).in_dll(lib,"hid")
            for case in ORACLE["shift_edges"]:
                selector.value=case["before"]
                self.assertTrue(lib.process_record_user(case["keycode"],ctypes.byref(Record(case["pressed"]))))
                self.assertEqual(selector.value,case["after"])
            for case in ORACLE["backspace_delete"]:
                selector.value=case["selector"]
                for i in range(5): hid[i]=0
                self.assertFalse(lib.process_record_user(0x7E00,ctypes.byref(Record(case["pressed"]))))
                self.assertEqual(list(hid[:3]),[1,int(case["pressed"]),case["keycode"]])
                self.assertEqual(selector.value,case["selector"])
            selector.value=0
            for i in range(5): hid[i]=0
            for key,pressed in ((0xE1,True),(0x7E00,True),(0xE1,False),(0x7E00,False)):
                lib.process_record_user(key,ctypes.byref(Record(pressed)))
            self.assertEqual(list(hid),[2,1,0x4C,0,0x2A])
            selector.value=0
            for i in range(5): hid[i]=0
            for key,pressed in ((0xE1,True),(0xE5,True),(0xE1,False),(0x7E00,True)):
                lib.process_record_user(key,ctypes.byref(Record(pressed)))
            self.assertEqual(selector.value,0)
            self.assertEqual(list(hid[:3]),[1,1,0x2A])
            self.assertEqual(ctypes.c_uint32.in_dll(lib,"bad_index").value,0)
            self.assertEqual(ctypes.c_uint32.in_dll(lib,"io_calls").value,0)

    def test_manifest_distinguishes_connected_hooks_from_pending_effects(self):
        manifest=json.loads((TARGET/"target-evidence.json").read_text())
        self.assertEqual(manifest["rgb_indicators"]["target_hooks"],["rgb_matrix_indicators_user","rgb_matrix_indicators_advanced_user"])
        self.assertIn("whole effect engine",manifest["rgb_indicators"]["scope"])
        self.assertIn("complete RGB runtime pipeline and remaining effects conformance",manifest["build_blockers"])
        self.assertFalse(manifest["rgb_effect_profile"]["all_effect_bodies_verified"])
        self.assertEqual(manifest["rgb_controls"]["target_hook"],"process_record_user")
        self.assertEqual(len(manifest["rgb_controls"]["keycodes"]),6)
        self.assertEqual(manifest["space_cadet"]["shared_candidate_helper"],"perform_space_cadet")
        self.assertEqual(len(manifest["space_cadet"]["vendor_keycodes"]),14)
        self.assertIn("SPACE_CADET_ENABLE = yes",(TARGET/"rules.mk").read_text())
        self.assertIn("destructive vendor reset",manifest["build_blockers"])
        self.assertEqual(manifest["backspace_delete"]["keycode"],"0x7E00")
        self.assertIn("key reselected on release",manifest["backspace_delete"]["scope"])
        self.assertFalse(manifest["complete_firmware"])
        self.assertFalse(manifest["flash_ready"])


if __name__=="__main__":
    unittest.main()
