"""Original-only binary/source consistency tests; never touch USB/hardware."""
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "reverse-engineering/tools"
sys.path.insert(0, str(TOOLS))
import recover_original_vial as recovery

ARTIFACTS = ROOT / "reverse-engineering/original-vial"


class CadetState(ctypes.Structure):
    _fields_ = [("last_modifier", ctypes.c_uint8), ("pressed_at", ctypes.c_uint16)]


class CadetEffect(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint8), ("argument", ctypes.c_uint8)]


class CadetTrace(ctypes.Structure):
    _fields_ = [("count", ctypes.c_uint8), ("effects", CadetEffect * 4)]


class TapEffect(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint32), ("argument", ctypes.c_uint32)]


class TapTrace(ctypes.Structure):
    _fields_ = [("count", ctypes.c_uint32), ("effects", TapEffect * 3)]


class OriginalRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input = ROOT / "firmware/origin/FAve40H_VIAL.uf2"
        if not cls.input.exists():
            raise unittest.SkipTest("Manufacturer original Vial UF2 absent")
        cls.raw = cls.input.read_bytes()
        cls.result, cls.definition = recovery.recover(cls.raw)
        cls.image = recovery.parse_uf2(cls.raw)

    def test_strict_original_identity_and_read_only(self):
        self.assertEqual(hashlib.sha256(self.input.read_bytes()).hexdigest(), recovery.ORIGINAL_SHA256)
        self.assertFalse(self.result["flash_ready"])
        self.assertFalse(self.result["source_reconstruction_complete"])
        self.assertEqual(self.raw, self.input.read_bytes())

    def test_other_manufacturer_firmwares_rejected(self):
        for relative in ("firmware/layer8/fave40h_f411_vial.uf2", "firmware/origin/FAve40h_VIA.uf2"):
            path = ROOT / relative
            if path.exists():
                with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "not original"):
                    recovery.recover(path.read_bytes())

    def test_modified_payload_rejected(self):
        raw = bytearray(self.raw)
        raw[40] ^= 1
        with self.assertRaisesRegex(ValueError, "not original"):
            recovery.recover(bytes(raw))

    def test_three_compiled_layers_and_generated_fourth(self):
        keymaps = self.result["factory_keymap"]["raw_keycodes"]
        self.assertEqual(len(keymaps), 4)
        expected = list(struct.unpack("<144H", self.image.read(0x0801E284, 288)))
        self.assertEqual([v for layer in keymaps[:3] for row in layer for v in row], expected)
        self.assertEqual(keymaps[3], [[1] * 12 for _ in range(4)])
        # Do not accidentally interpret bytes AFTER the 3-layer table as layer 3.
        self.assertNotEqual(list(struct.unpack("<48H", self.image.read(0x0801E284 + 288, 96))), [1] * 48)

    def test_factory_defaults_not_user_backup(self):
        self.assertEqual(self.result["factory_keymap"]["raw_keycodes"][0][1][0], 0x39)  # Factory Caps Lock
        self.assertEqual(self.result["factory_keymap"]["raw_keycodes"][2][1][11], 0x7C00)  # Factory QK_BOOT
        self.assertEqual(self.result["factory_keymap"]["dynamic_layers"], 4)

    def test_gpio_and_clocks(self):
        self.assertEqual(self.result["matrix"]["rows"], ["A5", "A6", "A3", "A4"])
        self.assertEqual(self.result["matrix"]["columns"], ["B12", "B13", "B14", "B15", "A8", "B6", "B5", "B4", "B3", "A15", "B7", "B8"])
        self.assertEqual(self.result["board"]["gpio_table"], "0x801ea14")
        for index, port in enumerate("ABCDEH"):
            self.assertEqual(list(self.result["board"]["gpio_register_defaults"][port].values()), list(struct.unpack("<7I", self.image.read(0x0801EA14 + 28 * index, 28))))
        self.assertEqual(self.result["board"]["pllcfgr"], "0x4413010")
        self.assertFalse(self.result["board"]["silicon_identified"])

    def test_rgb_driver_map_and_dma_from_original(self):
        rgb = self.result["rgb"]
        self.assertEqual((rgb["data_pin"], rgb["timer"], rgb["channel_one_based"]), ("B10", "TIM2", 3))
        self.assertEqual((rgb["dma_controller"], rgb["dma_stream"], rgb["dma_channel"]), (1, 1, 3))
        self.assertEqual(rgb["flags"], [4] * 42 + [2] * 30)
        self.assertEqual(rgb["matrix_to_led"][1], [22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 255, 12])
        self.assertEqual(sum(v == 255 for row in rgb["matrix_to_led"] for v in row), 6)
        self.assertEqual(rgb["color_words"] + rgb["reset_words"], rgb["transfer_words"])
        self.assertEqual(rgb["reset_words"] * rgb["period_ticks"] / rgb["tick_hz"] * 1000000, 280)
        self.assertFalse(rgb["physical_output_verified"])

    def test_vial_definition_and_usb(self):
        self.assertEqual(self.definition["matrix"], {"rows": 4, "cols": 12})
        self.assertEqual(len(self.definition["customKeycodes"]), 22)
        self.assertEqual(self.result["usb"]["device_version_bcd"], "0x100")
        self.assertEqual(self.result["usb"]["serial"], "vial:f64c2b3c")
        self.assertEqual(self.result["vial"]["uid_bytes"], list(bytes.fromhex("bc780a5daf64ce92")))

    def test_vendor_argument_decoding_from_instruction_operands(self):
        rows = self.result["vendor_space_cadet"]["parameters"]
        expected = [(0xE1, 0xE1, 0x2F), (0xE5, 0xE5, 0x30), (0xE0, 0xE1, 0x2F), (0xE4, 0xE5, 0x30), (0xE2, 0xE1, 0x2F), (0xE6, 0xE5, 0x30), (0xE1, 0xE1, 0x36), (0xE5, 0xE5, 0x37), (0xE0, 0xE1, 0x36), (0xE4, 0xE5, 0x37), (0xE2, 0xE1, 0x36), (0xE6, 0xE5, 0x37), (0xE0, 1, 0x39), (0xE4, 1, 0x28)]
        self.assertEqual([(r["hold_modifier"], r["tap_modifier"], r["tap_keycode"]) for r in rows], expected)
        self.assertEqual([r["keycode"] for r in rows], list(range(0x7E01, 0x7E0F)))
        cadet = self.result["vendor_space_cadet"]
        self.assertTrue(cadet["helper_state_machine_reconstructed"])
        self.assertFalse(cadet["timing_state_machine_reconstructed"])
        self.assertFalse(cadet["dispatcher_interruption_routing_reconstructed"])
        self.assertEqual((cadet["last_modifier_ram"], cadet["pressed_at_u16_ram"]), ("0x20001ced", "0x200051bc"))
        self.assertFalse(cadet["release_clears_state"])

    def test_builtin_cadet_parameters_and_core_stage_boundary(self):
        cadet = self.result["vendor_space_cadet"]
        rows = cadet["builtin_parameters"]
        self.assertEqual([row["keycode"] for row in rows], list(range(0x7C18, 0x7C1F)))
        self.assertEqual([(r["hold_modifier"], r["tap_modifier"], r["tap_keycode"]) for r in rows], [(0xE0,0xE1,0x26),(0xE4,0xE5,0x27),(0xE1,0xE1,0x26),(0xE5,0xE5,0x27),(0xE2,0xE1,0x26),(0xE6,0xE5,0x27),(0xE5,1,0x28)])
        self.assertEqual([int(row["case_address"], 16) for row in rows], [0x080167BE,0x080167CE,0x0801679E,0x080167AE,0x080167DE,0x080167EE,0x080167FE])
        self.assertTrue(cadet["core_stage_modeled"])
        self.assertFalse(cadet["pipeline_before_core_modeled"])
        self.assertFalse(cadet["dispatcher_interruption_routing_reconstructed"])

    def test_tap_delay_settings_and_boundary_evidence(self):
        tap = self.result["tap_code"]
        self.assertEqual(tap["settings_base"], "0x200011c8")
        self.assertEqual((tap["normal_delay_u16_offset"], tap["caps_delay_u16_offset"]), ("0x1e", "0x20"))
        self.assertEqual((tap["software_tick_hz_constant"], tap["zero_delay_sleep_ticks"]), (100000, 1))
        self.assertFalse(tap["hid_reports_and_scheduler_executed"])
        self.assertFalse(tap["physical_tick_rate_verified"])

    def test_storage_intervals_do_not_overlap(self):
        storage = self.result["storage"]
        self.assertEqual(storage["keymap_start"] + 4 * 4 * 12 * 2, storage["keymap_end_exclusive"])
        end = storage["qmk_settings_end_exclusive"]
        for kind in ("tap_dance", "combo", "key_override", "alt_repeat"):
            group = storage[kind]
            self.assertEqual(group["start"], end)
            end = group["start"] + group["entries"] * group["stride"]
        self.assertEqual(end, storage["macro"]["start"])
        self.assertEqual(end + storage["macro"]["bytes"], storage["logical_bytes"])
        self.assertFalse(self.result["boot_request"]["recovery_verified"])

    def test_exported_artifacts_are_reproducible(self):
        for name, content in recovery.artifacts(self.result, self.definition).items():
            with self.subTest(name=name):
                self.assertEqual((ARTIFACTS / name).read_bytes(), content.encode("utf-8"))

    def test_cli_refuses_overwrite_and_checks_without_changes(self):
        with tempfile.TemporaryDirectory(prefix="fave40h-original-test-") as temp:
            command = [sys.executable, str(TOOLS / "recover_original_vial.py"), str(self.input)]
            output = Path(temp) / "recovered"
            subprocess.run(command + ["--export", str(output)], check=True, capture_output=True)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            self.assertNotEqual(subprocess.run(command + ["--export", str(output)], capture_output=True).returncode, 0)
            subprocess.run(command + ["--check", str(output)], check=True, capture_output=True)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})


class CompiledRecoveredModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("Host C compiler absent")
        cls.temp = tempfile.TemporaryDirectory(prefix="fave40h-original-c-")
        cls.addClassCleanup(cls.temp.cleanup)
        extension = ".dylib" if sys.platform == "darwin" else ".so"
        library = Path(cls.temp.name) / ("model" + extension)
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(ARTIFACTS / "factory_defaults.c"), str(ARTIFACTS / "vendor_parameters.c"), str(ARTIFACTS / "rgb_model.c"), str(ARTIFACTS / "cadet_model.c"), str(ARTIFACTS / "tap_model.c"), "-o", str(library)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.original_vial_keycode_address.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint16)]
        cls.lib.original_vial_keycode_address.restype = ctypes.c_bool
        cls.lib.original_vial_reset_keymaps.argtypes = [ctypes.c_void_p]
        cls.lib.original_vial_reset_keymaps.restype = None
        cls.lib.original_vial_pwm_init.argtypes = [ctypes.c_void_p]
        cls.lib.original_vial_pwm_init.restype = None
        cls.lib.original_vial_pwm_encode.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cls.lib.original_vial_pwm_encode.restype = None
        cls.lib.original_vial_rgb_filter.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
        cls.lib.original_vial_rgb_filter.restype = ctypes.c_bool
        cls.lib.original_vial_rgb_control.argtypes = [ctypes.c_uint16, ctypes.c_bool, ctypes.c_void_p]
        cls.lib.original_vial_rgb_control.restype = ctypes.c_bool
        cls.lib.original_vial_shift_edge.argtypes = [ctypes.c_uint16, ctypes.c_bool, ctypes.c_void_p]
        cls.lib.original_vial_shift_edge.restype = None
        cls.lib.original_vial_bsdl_keycode.argtypes = [ctypes.c_uint8]
        cls.lib.original_vial_bsdl_keycode.restype = ctypes.c_uint16
        cls.lib.original_vial_cadet_event.argtypes = [ctypes.POINTER(CadetState), ctypes.c_uint, ctypes.c_bool, ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(CadetTrace)]
        cls.lib.original_vial_cadet_event.restype = ctypes.c_bool
        cls.lib.original_vial_cadet_core_stage.argtypes = cls.lib.original_vial_cadet_event.argtypes
        cls.lib.original_vial_cadet_core_stage.restype = ctypes.c_bool
        cls.lib.original_vial_cadet_reset.argtypes = [ctypes.POINTER(CadetState)]
        cls.lib.original_vial_cadet_reset.restype = None
        cls.lib.original_vial_tap_code_trace.argtypes = [ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(TapTrace)]
        cls.lib.original_vial_tap_code_trace.restype = ctypes.c_bool
        # Independent oracle: original Thumb instructions executed in Ghidra,
        # not values generated by recover_original_vial.py or this C model.
        cls.oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        if cls.oracle["payload_sha256"] != recovery.PAYLOAD_SHA256:
            raise AssertionError("Oracle is not bound to the original firmware")

    def test_pwm_initialization(self):
        output = (ctypes.c_uint32 * 1952)(*[0xDEADBEEF] * 1952)
        self.lib.original_vial_pwm_init(output)
        self.assertEqual(list(output), [8] * 1728 + [0] * 224)

    def test_pwm_matches_original_thumb_51_vectors(self):
        self.assertEqual(len(self.oracle["encodings"]), 51)
        for row in self.oracle["encodings"]:
            with self.subTest(name=row["name"]):
                source = (ctypes.c_uint8 * 216).from_buffer_copy(bytes.fromhex(row["input_grb_hex"]))
                before = bytes(source)
                output = (ctypes.c_uint32 * 1952)(*[0xA5A5A5A5] * 1952)
                self.lib.original_vial_pwm_encode(source, output)
                actual = struct.pack("<1952I", *output)
                self.assertEqual(hashlib.sha256(actual).hexdigest(), row["expected_pwm_sha256"])
                self.assertEqual(bytes(source), before)
                self.assertEqual(list(output)[1728:], [0xA5A5A5A5] * 224)

    def test_filter_matches_original_thumb_25_chunks(self):
        self.assertEqual(len(self.oracle["filters"]), 25)
        for row in self.oracle["filters"]:
            with self.subTest(begin=row["begin"], end=row["end"], enabled=row["enabled"]):
                colors = (ctypes.c_uint8 * 216).from_buffer_copy(bytes.fromhex(row["input_grb_hex"]))
                enabled = (ctypes.c_uint8 * 2)(*row["enabled"])
                self.assertTrue(self.lib.original_vial_rgb_filter(colors, row["begin"], row["end"], enabled))
                self.assertEqual(hashlib.sha256(bytes(colors)).hexdigest(), row["expected_grb_sha256"])

    def test_filter_invalid_ranges_leave_colors_unchanged(self):
        for begin, end in ((1, 0), (0, 73), (0xFFFFFFFF, 0), (0, 0xFFFFFFFF)):
            colors = (ctypes.c_uint8 * 216)(*[99] * 216)
            enabled = (ctypes.c_uint8 * 2)(0, 0)
            self.assertFalse(self.lib.original_vial_rgb_filter(colors, begin, end, enabled))
            self.assertEqual(bytes(colors), bytes([99] * 216))

    def test_led_tables_are_compiled_exactly(self):
        evidence = json.loads((ARTIFACTS / "evidence.json").read_text())["rgb"]
        for name, size, expected in (("matrix", 48, [v for row in evidence["matrix_to_led"] for v in row]), ("positions", 144, [v for xy in evidence["positions"] for v in xy]), ("flags", 72, evidence["flags"])):
            array = (ctypes.c_uint8 * size).in_dll(self.lib, "original_vial_led_" + name)
            self.assertEqual(list(array), expected)

    def test_rgb_controls_match_original_thumb_48_cases(self):
        self.assertEqual(len(self.oracle["rgb_controls"]), 48)
        for row in self.oracle["rgb_controls"]:
            with self.subTest(row=row):
                enabled = (ctypes.c_uint8 * 2)(*row["before"])
                self.assertTrue(self.lib.original_vial_rgb_control(row["keycode"], row["pressed"], enabled))
                self.assertEqual(list(enabled), row["after"])
        for keycode in (0, 0x7E00, 0x7E0F, 0x7E16, 0xFFFF):
            enabled = (ctypes.c_uint8 * 2)(19, 31)
            self.assertFalse(self.lib.original_vial_rgb_control(keycode, True, enabled))
            self.assertEqual(list(enabled), [19, 31])

    def test_shift_and_bsdl_match_original_thumb_16_cases(self):
        self.assertEqual((len(self.oracle["shift_edges"]), len(self.oracle["backspace_delete"])), (8, 8))
        for row in self.oracle["shift_edges"]:
            selector = ctypes.c_uint8(row["before"])
            self.lib.original_vial_shift_edge(row["keycode"], row["pressed"], ctypes.byref(selector))
            self.assertEqual(selector.value, row["after"])
        for row in self.oracle["backspace_delete"]:
            self.assertEqual(self.lib.original_vial_bsdl_keycode(row["selector"]), row["keycode"])
        # Preserve, do not silently fix, the original overlapping-shift quirk.
        selector = ctypes.c_uint8(0)
        for keycode, pressed in ((0xE1, True), (0xE5, True), (0xE1, False)):
            self.lib.original_vial_shift_edge(keycode, pressed, ctypes.byref(selector))
        self.assertEqual(selector.value, 0)
        self.assertEqual(self.lib.original_vial_bsdl_keycode(selector.value), 0x2A)

    def assert_cadet_vectors(self, rows, query, expected_keys):
        kinds = {"register_mods": 1, "unregister_mods": 2, "tap_code": 3}
        covered = set()
        for row in rows:
            with self.subTest(keycode=hex(row["keycode"]), name=row["name"]):
                state = CadetState(row["before_last_modifier"], row["before_pressed_at"])
                trace = CadetTrace()
                self.assertTrue(query(ctypes.byref(state), row["keycode"], row["pressed"], row["now"], row["tapping_term"], ctypes.byref(trace)))
                self.assertEqual((state.last_modifier, state.pressed_at), (row["after_last_modifier"], row["after_pressed_at"]))
                self.assertLessEqual(trace.count, 4)
                expected = [(kinds[effect["kind"]], effect["argument"]) for effect in row["effects"]]
                self.assertEqual([(effect.kind, effect.argument) for effect in trace.effects[:trace.count]], expected)
                self.assertEqual([(effect.kind, effect.argument) for effect in trace.effects[trace.count:]], [(0, 0)] * (4 - trace.count))
                covered.add(row["keycode"])
        self.assertEqual(covered, set(expected_keys))

    def test_cadet_matches_original_thumb_196_decisions_and_effect_traces(self):
        self.assertEqual(len(self.oracle["cadet"]), 196)
        self.assert_cadet_vectors(self.oracle["cadet"], self.lib.original_vial_cadet_event, range(0x7E01, 0x7E0F))

    def test_builtin_cadet_core_stage_matches_98_original_thumb_cases(self):
        self.assertEqual(len(self.oracle["builtin_cadet"]), 98)
        self.assert_cadet_vectors(self.oracle["builtin_cadet"], self.lib.original_vial_cadet_core_stage, range(0x7C18, 0x7C1F))

    def test_core_default_reached_stage_matches_16_original_thumb_cases(self):
        self.assertEqual(len(self.oracle["cadet_core_defaults"]), 16)
        for row in self.oracle["cadet_core_defaults"]:
            state = CadetState(row["before_last_modifier"], row["before_pressed_at"])
            trace = CadetTrace()
            ctypes.memset(ctypes.byref(trace), 0xA5, ctypes.sizeof(trace))
            self.assertFalse(self.lib.original_vial_cadet_core_stage(ctypes.byref(state), row["keycode"], row["pressed"], 1, 200, ctypes.byref(trace)))
            self.assertEqual((state.last_modifier, state.pressed_at), (row["after_last_modifier"], row["after_pressed_at"]))
            self.assertEqual(bytes(trace), bytes(ctypes.sizeof(trace)))

    def test_vendor_bypass_evidence_and_controls_14_original_thumb_cases(self):
        self.assertEqual(len(self.oracle["cadet_vendor_bypasses"]), 14)
        for row in self.oracle["cadet_vendor_bypasses"]:
            self.assertEqual((row["before_last_modifier"], row["before_pressed_at"]), (row["after_last_modifier"], row["after_pressed_at"]))
            flags = (ctypes.c_uint8 * 2)(1, 1)
            if row["keycode"] == 0x7E00:
                expected = [{"kind": "register_code" if row["pressed"] else "unregister_code", "argument": self.lib.original_vial_bsdl_keycode(1)}]
                self.assertEqual(row["effects"], expected)
            else:
                self.assertTrue(self.lib.original_vial_rgb_control(row["keycode"], row["pressed"], flags))
                self.assertEqual(row["effects"], [])
            self.assertEqual(list(flags), row["after_flags"])

    def test_core_null_inputs_preserve_state_and_trace(self):
        state, trace = CadetState(0xE1, 1234), CadetTrace()
        ctypes.memset(ctypes.byref(trace), 0xA5, ctypes.sizeof(trace))
        before_state, before_trace = bytes(state), bytes(trace)
        for keycode in (0x4, 0x7C18):
            self.assertFalse(self.lib.original_vial_cadet_core_stage(None, keycode, True, 0, 200, ctypes.byref(trace)))
            self.assertFalse(self.lib.original_vial_cadet_core_stage(ctypes.byref(state), keycode, True, 0, 200, None))
            self.assertEqual((bytes(state), bytes(trace)), (before_state, before_trace))

    def test_builtin_and_vendor_share_state_but_only_reached_core_press_interrupts(self):
        state, trace = CadetState(0, 0), CadetTrace()
        self.assertTrue(self.lib.original_vial_cadet_event(ctypes.byref(state), 0x7E01, True, 10, 200, ctypes.byref(trace)))
        self.assertTrue(self.lib.original_vial_cadet_core_stage(ctypes.byref(state), 0x7C1A, True, 20, 200, ctypes.byref(trace)))
        flags = (ctypes.c_uint8 * 2)(1, 1)
        self.assertTrue(self.lib.original_vial_rgb_control(0x7E10, True, flags))  # Earlier vendor bypass, not core stage.
        self.assertEqual((state.last_modifier, state.pressed_at), (0xE1, 20))
        self.assertTrue(self.lib.original_vial_cadet_event(ctypes.byref(state), 0x7E01, False, 21, 200, ctypes.byref(trace)))
        self.assertEqual([(e.kind, e.argument) for e in trace.effects[:trace.count]], [(3, 0x2F), (2, 2)])
        self.assertFalse(self.lib.original_vial_cadet_core_stage(ctypes.byref(state), 0x4, False, 22, 200, ctypes.byref(trace)))
        self.assertEqual(state.last_modifier, 0xE1)
        self.assertFalse(self.lib.original_vial_cadet_core_stage(ctypes.byref(state), 0x4, True, 23, 200, ctypes.byref(trace)))
        self.assertEqual((state.last_modifier, state.pressed_at), (0, 20))
        self.assertTrue(self.lib.original_vial_cadet_core_stage(ctypes.byref(state), 0x7C1A, False, 24, 200, ctypes.byref(trace)))
        self.assertEqual([(e.kind, e.argument) for e in trace.effects[:trace.count]], [(2, 2)])

    def test_cadet_reset_matches_original_thumb_4_states(self):
        self.assertEqual(len(self.oracle["cadet_resets"]), 4)
        for row in self.oracle["cadet_resets"]:
            state = CadetState(row["before_last_modifier"], row["before_pressed_at"])
            self.lib.original_vial_cadet_reset(ctypes.byref(state))
            self.assertEqual((state.last_modifier, state.pressed_at), (row["after_last_modifier"], row["after_pressed_at"]))

    def test_cadet_unknown_or_null_preserves_outputs(self):
        for keycode in (0, 0x7C18, 0x7E00, 0x7E0F, 0xFFFF, 0xFFFFFFFF):
            state = CadetState(0xE1, 1234)
            trace = CadetTrace()
            ctypes.memset(ctypes.byref(trace), 0xA5, ctypes.sizeof(trace))
            before_state, before_trace = bytes(state), bytes(trace)
            self.assertFalse(self.lib.original_vial_cadet_event(ctypes.byref(state), keycode, True, 7, 200, ctypes.byref(trace)))
            self.assertEqual((bytes(state), bytes(trace)), (before_state, before_trace))
        self.assertFalse(self.lib.original_vial_cadet_event(None, 0x7E01, True, 0, 200, ctypes.byref(trace)))
        self.assertEqual(bytes(trace), before_trace)
        self.assertFalse(self.lib.original_vial_cadet_event(ctypes.byref(state), 0x7E01, True, 0, 200, None))
        self.assertEqual(bytes(state), before_state)

    def test_cadet_shared_modifier_state_not_per_key_and_not_cleared_on_release(self):
        state = CadetState(0, 0)
        trace = CadetTrace()
        def event(key, pressed, now):
            self.assertTrue(self.lib.original_vial_cadet_event(ctypes.byref(state), key, pressed, now, 200, ctypes.byref(trace)))
            return [(effect.kind, effect.argument) for effect in trace.effects[:trace.count]]
        self.assertEqual(event(0x7E01, True, 10), [(1, 2)])
        self.assertEqual(event(0x7E07, True, 20), [(1, 2)])  # Same hold modifier, different tap key.
        self.assertEqual(event(0x7E01, False, 21), [(3, 0x2F), (2, 2)])
        self.assertEqual((state.last_modifier, state.pressed_at), (0xE1, 20))
        self.assertEqual(event(0x7E01, False, 22), [(3, 0x2F), (2, 2)])  # Bare helper has no release latch.
        self.lib.original_vial_cadet_reset(ctypes.byref(state))
        self.assertEqual(state.pressed_at, 20)
        self.assertEqual(event(0x7E01, False, 23), [(2, 2)])

    def tap_effects(self, keycode, normal, caps):
        trace = TapTrace()
        self.assertTrue(self.lib.original_vial_tap_code_trace(keycode, normal, caps, ctypes.byref(trace)))
        self.assertEqual(trace.count, 3)
        kinds = {1: "register_code", 2: "sleep_ticks", 3: "unregister_code"}
        return [{"kind": kinds[e.kind], "argument": e.argument} for e in trace.effects[:trace.count]]

    def test_tap_code_matches_272_original_thumb_traces(self):
        self.assertEqual(len(self.oracle["tap_code"]), 272)
        covered = set()
        for row in self.oracle["tap_code"]:
            with self.subTest(keycode=hex(row["keycode"]), normal=row["normal_delay_ms"], caps=row["caps_delay_ms"]):
                self.assertEqual(self.tap_effects(row["keycode"], row["normal_delay_ms"], row["caps_delay_ms"]), row["effects"])
                covered.add(row["keycode"])
        self.assertEqual(covered, set(range(256)))
        self.assertEqual(self.tap_effects(0x28, 0, 65535)[1]["argument"], 1)  # ONE tick, not 0 or 1 ms.
        self.assertEqual(self.tap_effects(0x39, 7, 1)[1]["argument"], 100)
        self.assertEqual(self.tap_effects(0x28, 65535, 0)[1]["argument"], 6553500)  # Needs 64-bit intermediate.

    def test_tap_code_null_trace_is_rejected(self):
        self.assertFalse(self.lib.original_vial_tap_code_trace(0x28, 7, 19, None))

    def test_composed_cadet_and_tap_match_21_original_expanded_traces(self):
        self.assertEqual(len(self.oracle["cadet_tap_expanded"]), 21)
        for row in self.oracle["cadet_tap_expanded"]:
            with self.subTest(keycode=hex(row["keycode"])):
                state = CadetState(row["before_last_modifier"], row["before_pressed_at"])
                trace = CadetTrace()
                query = self.lib.original_vial_cadet_core_stage if row["core_stage"] else self.lib.original_vial_cadet_event
                self.assertTrue(query(ctypes.byref(state), row["keycode"], False, row["now"], row["tapping_term"], ctypes.byref(trace)))
                expanded = []
                for effect in trace.effects[:trace.count]:
                    if effect.kind == 3:
                        expanded.extend(self.tap_effects(effect.argument, row["normal_delay_ms"], row["caps_delay_ms"]))
                    else:
                        expanded.append({"kind": "register_mods" if effect.kind == 1 else "unregister_mods", "argument": effect.argument})
                self.assertEqual(expanded, row["effects"])
                self.assertEqual((state.last_modifier, state.pressed_at), (row["after_last_modifier"], row["after_pressed_at"]))

    def test_all_192_keycode_addresses(self):
        for layer in range(4):
            for row in range(4):
                for col in range(12):
                    output = ctypes.c_uint16()
                    self.assertTrue(self.lib.original_vial_keycode_address(layer, row, col, ctypes.byref(output)))
                    self.assertEqual(output.value, 0x29 + layer * 96 + row * 24 + col * 2)

    def test_invalid_addresses_and_null(self):
        for coordinates in ((4, 0, 0), (0, 4, 0), (0, 0, 12), (0xFFFFFFFF, 0, 0)):
            out = ctypes.c_uint16(0xDEAD)
            self.assertFalse(self.lib.original_vial_keycode_address(*coordinates, ctypes.byref(out)))
            self.assertEqual(out.value, 0xDEAD)
        self.assertFalse(self.lib.original_vial_keycode_address(0, 0, 0, None))

    def test_reset_produces_exact_384_bytes(self):
        buffer = (ctypes.c_uint16 * 192)(*[0xDEAD] * 192)
        self.lib.original_vial_reset_keymaps(buffer)
        evidence = json.loads((ARTIFACTS / "evidence.json").read_text())
        actual = struct.pack("<192H", *buffer)
        self.assertEqual(hashlib.sha256(actual).hexdigest(), evidence["factory_keymap"]["expanded_little_endian_sha256"])

    def test_vendor_argument_query(self):
        class Args(ctypes.Structure):
            _fields_ = [("hold", ctypes.c_uint8), ("tap_mod", ctypes.c_uint8), ("tap_key", ctypes.c_uint8)]
        query = self.lib.original_vial_cadet_parameters
        query.argtypes = [ctypes.c_uint, ctypes.POINTER(Args)]
        query.restype = ctypes.c_bool
        rows = json.loads((ARTIFACTS / "evidence.json").read_text())["vendor_space_cadet"]["parameters"]
        for row in rows:
            output = Args()
            self.assertTrue(query(row["keycode"], ctypes.byref(output)))
            self.assertEqual((output.hold, output.tap_mod, output.tap_key), (row["hold_modifier"], row["tap_modifier"], row["tap_keycode"]))
        for keycode in (0x7E00, 0x7E0F, 0xFFFFFFFF):
            self.assertFalse(query(keycode, ctypes.byref(Args())))
        self.assertFalse(query(0x7E01, None))


if __name__ == "__main__":
    unittest.main()
