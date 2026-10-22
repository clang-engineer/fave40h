"""Bounded original reset/load oracle and real target hooks with RAM API shims."""
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "reverse-engineering/keyboards/fave40h_original"
ORACLE = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())


class OriginalRGBLifecycleTests(unittest.TestCase):
    def test_original_reset_load_scope_and_reserved_bytes(self):
        cases = ORACLE["rgb_group_lifecycle"]
        self.assertEqual(len(cases),13)
        for case in cases:
            if case["kind"] == "reset":
                self.assertEqual(case["state_after"],0x101)
                self.assertEqual([(e["offset"],e["word"]) for e in case["io"]],[(0xF,0),(0x13,0x101)])
                self.assertEqual(case["io"][0]["state_at_io"],case["initial_word"])
                self.assertEqual(case["io"][1]["state_at_io"],0x101)
            else:
                self.assertEqual(case["state_after"],case["stored_word"])
                self.assertEqual(len(case["io"]),1)
                self.assertEqual(case["io"][0]["kind"],"read")
                self.assertEqual(case["io"][0]["offset"],0x13)
                self.assertEqual(case["io"][0]["size"],4)
        self.assertTrue(any(c["stored_word"]==0xA5B6FF00 for c in cases))
        self.assertIn("partial/failing read",ORACLE["rgb_group_boundary_policy"])

    def test_native_target_user_hooks_match_original_user_word_effects(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler absent")
        with tempfile.TemporaryDirectory(prefix="fave40h-group-state-") as directory:
            temp=Path(directory)
            # Controlled type/API shim; actual pinned header and weak KB delegates
            # are additionally exercised by verify_original_target_rgb.py.
            (temp/"quantum.h").write_text('''#include <stdint.h>
#include <stdbool.h>
typedef struct { struct { bool pressed; } event; } keyrecord_t;
uint8_t host_keyboard_leds(void);
void register_code(uint8_t);
void unregister_code(uint8_t);
void perform_space_cadet(keyrecord_t *,uint16_t,uint8_t,uint8_t,uint8_t);
void rgb_matrix_set_color(int,uint8_t,uint8_t,uint8_t);
typedef struct { uint8_t x,y; } led_point_t;
typedef struct { uint8_t matrix_co[4][12]; led_point_t point[72]; uint8_t flags[72]; } led_config_t;
uint32_t eeconfig_read_user(void);
void eeconfig_update_user(uint32_t);
''')
            (temp/"probe.c").write_text(f'''#include "{TARGET / 'fave40h_original.c'}"
void perform_space_cadet(keyrecord_t *record,uint16_t key,uint8_t hold,uint8_t mod,uint8_t tap) {{
    (void)record; (void)key; (void)hold; (void)mod; (void)tap;
}}
void register_code(uint8_t code) {{ (void)code; }}
void unregister_code(uint8_t code) {{ (void)code; }}
uint8_t host_keyboard_leds(void) {{ return 0; }}
void rgb_matrix_set_color(int i,uint8_t r,uint8_t g,uint8_t b) {{ (void)i; (void)r; (void)g; (void)b; }}
uint32_t stored,reads,writes,state_at_io,word_at_io;
uint32_t eeconfig_read_user(void) {{ ++reads; state_at_io=original_rgb_group_state; word_at_io=stored; return stored; }}
void eeconfig_update_user(uint32_t value) {{ ++writes; state_at_io=original_rgb_group_state; word_at_io=value; stored=value; }}
''')
            library=temp/("state.dylib" if sys.platform=="darwin" else "state.so")
            subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Werror","-shared","-fPIC","-I",str(temp),str(temp/"probe.c"),"-o",str(library)],check=True,capture_output=True)
            lib=ctypes.CDLL(str(library))
            variables={name:ctypes.c_uint32.in_dll(lib,name) for name in ("original_rgb_group_state","stored","reads","writes","state_at_io","word_at_io")}
            self.assertEqual(variables["original_rgb_group_state"].value,0)
            for case in ORACLE["rgb_group_lifecycle"]:
                variables["original_rgb_group_state"].value=case["initial_word"]
                variables["stored"].value=case["stored_word"]
                variables["reads"].value=variables["writes"].value=0
                if case["kind"]=="reset":
                    lib.eeconfig_init_user()
                    self.assertEqual((variables["reads"].value,variables["writes"].value),(0,1))
                else:
                    lib.keyboard_post_init_user()
                    self.assertEqual((variables["reads"].value,variables["writes"].value),(1,0))
                event=case["io"][-1]
                self.assertEqual(variables["state_at_io"].value,event["state_at_io"])
                self.assertEqual(variables["word_at_io"].value,event["word"])
                self.assertEqual(variables["original_rgb_group_state"].value,case["state_after"])

    def test_target_uses_user_field_hooks_without_claiming_storage_completion(self):
        manifest=json.loads((TARGET/"target-evidence.json").read_text())
        lifecycle=manifest["rgb_group_lifecycle"]
        self.assertEqual(lifecycle["target_hooks"],["eeconfig_init_user","keyboard_post_init_user"])
        self.assertEqual(lifecycle["user_field_offset"],"0x13")
        self.assertEqual(lifecycle["reset_word"],"0x00000101")
        self.assertIn("six group keys connected",lifecycle["scope"])
        self.assertFalse(manifest["flash_ready"])
        self.assertTrue(manifest["build_blockers"])


if __name__=="__main__":
    unittest.main()
