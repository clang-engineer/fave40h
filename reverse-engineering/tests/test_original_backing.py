"""Captured program intents and RAM-only reads, NOT a physical flash test."""
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "reverse-engineering/original-vial"
ORACLE = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())


class Intent(ctypes.Structure):
    _fields_ = [("driver_offset", ctypes.c_uint32), ("physical_word", ctypes.c_uint32), ("size", ctypes.c_uint32)]


class OriginalBackingEvidenceTests(unittest.TestCase):
    def test_geometry_helpers_and_software_ranges_do_not_identify_actual_capacity(self):
        evidence = json.loads((ARTIFACTS / "evidence.json").read_text())["backing_wrapper"]
        self.assertFalse(evidence["physical_capacity_verified"])
        self.assertFalse(evidence["bus_fault_handler_validated"])
        self.assertFalse(evidence["driver_program_erase_unlock_lock_executed"])
        self.assertIn("0x08012860 precedes active=1", evidence["read_guard_order"])
        profiles = evidence["profiles"]
        self.assertEqual([p["capacity"] for p in profiles], [131072, 262144, 393216, 524288])
        self.assertEqual(len(ORACLE["backing_geometry"]), 8)
        for profile in profiles:
            self.assertEqual((profile["attributes"], profile["program_unit"]), (3, 4))
            self.assertEqual(sum(s["size"] for s in profile["sectors"]), profile["capacity"])
            sector = profile["sectors"][3]
            self.assertEqual(sector, {"offset": 0xC000, "size": 16384})
            for row in ORACLE["backing_geometry"]:
                if row["descriptor"] == int(profile["descriptor"], 16):
                    self.assertEqual(row["sector"], 3)
                    self.assertEqual(row["value"], sector[row["kind"]])
        start, used_end = map(lambda x: int(x, 16), evidence["configured_backing_range"])
        erase_start, erase_end = map(lambda x: int(x, 16), evidence["erase_sector_range"])
        self.assertEqual((start, used_end, erase_start, erase_end), (0x0800C000, 0x0800E000, 0x0800C000, 0x08010000))
        self.assertEqual(used_end - start, evidence["backing_budget"])
        self.assertIn("contents unknown", evidence["same_sector_tail"])
        self.assertIn("NOT a physical fault", ORACLE["backing_boundary_policy"])


class OriginalBackingModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("Host C compiler absent")
        temp = tempfile.TemporaryDirectory(prefix="fave40h-backing-model-")
        cls.addClassCleanup(temp.cleanup)
        library = Path(temp.name) / ("backing.dylib" if sys.platform == "darwin" else "backing.so")
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(ARTIFACTS / "backing_model.c"), "-o", str(library)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.original_vial_backing_word.argtypes = [ctypes.c_uint32, ctypes.c_uint8]
        cls.lib.original_vial_backing_word.restype = ctypes.c_uint32
        cls.lib.original_vial_backing_program.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_uint8, ctypes.c_uint32, ctypes.POINTER(Intent)]
        cls.lib.original_vial_backing_program.restype = ctypes.c_bool
        cls.lib.original_vial_backing_read.argtypes = [ctypes.c_uint32, ctypes.c_uint8, ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint32)]
        cls.lib.original_vial_backing_read.restype = ctypes.c_bool
        if ORACLE["payload_sha256"] != "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4":
            raise AssertionError("Wrong original oracle")

    def test_195_program_intents_match_original_offset_word_and_return(self):
        self.assertEqual(len(ORACLE["backing_program"]), 195)
        for row in ORACLE["backing_program"]:
            with self.subTest(row=row):
                intent = Intent()
                success = self.lib.original_vial_backing_program(0xC000, row["offset"], row["logical_word"], row["inversion_flag"], row["driver_status"], ctypes.byref(intent))
                self.assertEqual(success, row["success"])
                self.assertEqual((intent.driver_offset, intent.physical_word, intent.size), (row["driver_offset"], row["physical_word"], 4))
                self.assertEqual(success, row["driver_status"] == 0)

    def test_144_reads_match_original_final_error_check(self):
        self.assertEqual(len(ORACLE["backing_read"]), 144)
        for row in ORACLE["backing_read"]:
            with self.subTest(row=row):
                word = ctypes.c_uint32(0xA5A5A5A5)
                success = self.lib.original_vial_backing_read(row["physical_word"], row["inversion_flag"], row["observed_error"], ctypes.byref(word))
                self.assertEqual((success, word.value), (row["success"], row["logical_word"]))

    def test_any_nonzero_flag_complements_and_roundtrips(self):
        for word in (0, 1, 0xFFFFFFFF, 0x80000000, 0x01234567):
            for flag in range(256):
                result = self.lib.original_vial_backing_word(word, flag)
                self.assertEqual(result, word ^ (0xFFFFFFFF if flag else 0))
                self.assertEqual(self.lib.original_vial_backing_word(result, flag), word)

    def test_intended_erased_word_normalization_not_hardware_validation(self):
        value = ctypes.c_uint32(0xA5A5A5A5)
        self.assertTrue(self.lib.original_vial_backing_read(0xFFFFFFFF, 1, 0, ctypes.byref(value)))
        self.assertEqual(value.value, 0)
        intent = Intent()
        self.assertTrue(self.lib.original_vial_backing_program(0xC000, 0, 0, 1, 0, ctypes.byref(intent)))
        self.assertEqual(intent.physical_word, 0xFFFFFFFF)

    def test_program_wrapper_itself_does_not_check_alignment_budget_or_wrap(self):
        rows = {r["offset"]: r for r in ORACLE["backing_program"]}
        for offset in (1, 8192, 0xFFFFFFFC):
            self.assertIn(offset, rows)
            self.assertEqual(rows[offset]["driver_offset"], (0xC000 + offset) & 0xFFFFFFFF)
        # These are captured requests with injected status zero, NOT valid device writes.

    def test_stale_error_cleared_and_observed_errors_zero_output(self):
        for row in ORACLE["backing_read"]:
            self.assertEqual((row["final_error"], row["final_active"]), (0, 0))
            self.assertEqual(row["success"], row["observed_error"] == 0)
            if row["observed_error"]:
                self.assertEqual(row["logical_word"], 0)
        self.assertTrue(any(r["stale_error"] == 255 and r["success"] for r in ORACLE["backing_read"]))

    def test_defensive_null_outputs_are_not_physical_driver_behavior(self):
        self.assertFalse(self.lib.original_vial_backing_program(0, 0, 0, 1, 0, None))
        self.assertFalse(self.lib.original_vial_backing_read(0, 1, 0, None))


if __name__ == "__main__":
    unittest.main()
