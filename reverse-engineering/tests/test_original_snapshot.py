"""Consolidated-load final RAM state; no physical flash, replay or migration."""
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "reverse-engineering/original-vial"
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import recover_original_vial as recovery


def data_pattern(name):
    seed, result = 0x12345678, bytearray()
    for i in range(4096):
        seed = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
        result.append(255 if name == "ff" else (i * 73 + 19) & 255 if name == "ramp" else seed >> 24 if name == "lcg" else 0)
    return bytes(result)


def fnv64(data):
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


class Cache(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_uint8 * 4096), ("write_address", ctypes.c_uint32)]


class Guarded(ctypes.Structure):
    _fields_ = [("before", ctypes.c_uint32), ("cache", Cache), ("after", ctypes.c_uint32)]


class OriginalSnapshotEvidenceTests(unittest.TestCase):
    def test_snapshot_scope_and_reference_are_explicit(self):
        evidence = json.loads((ARTIFACTS / "evidence.json").read_text())
        self.assertEqual(evidence["payload_sha256"], recovery.PAYLOAD_SHA256)
        snapshot = evidence["snapshot"]
        self.assertEqual((snapshot["cache_ram"], snapshot["logical_bytes"], snapshot["checksum_start"], snapshot["checksum_bytes"], snapshot["log_start"]),
            ("0x200021d8", 4096, 4096, 8, 4104))
        self.assertEqual(snapshot["fnv_basis"], "0xcbf29ce484222325")
        self.assertEqual(snapshot["fnv_prime"], "0x100000001b3")
        self.assertEqual(snapshot["reference_sha256"], "a5480ffe8cc544414f5ef63d47f86c27c7f21e623c57021514d7dc9113d6542b")
        for name in ("checksum_read_failures_modeled", "log_playback_modeled", "physical_flash_translation_verified", "erase_write_or_migration_executed"):
            self.assertFalse(snapshot[name])
        self.assertIn("still proceeds to log playback", snapshot["mismatch"])
        self.assertIn("not exact manufacturer revision", snapshot["reference_scope"])


class OriginalSnapshotModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("Host C compiler absent")
        temp = tempfile.TemporaryDirectory(prefix="fave40h-snapshot-model-")
        cls.addClassCleanup(temp.cleanup)
        library = Path(temp.name) / ("snapshot.dylib" if sys.platform == "darwin" else "snapshot.so")
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(ARTIFACTS / "snapshot_model.c"), "-o", str(library)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.original_vial_snapshot_fnv64.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
        cls.lib.original_vial_snapshot_fnv64.restype = ctypes.c_uint64
        cls.lib.original_vial_snapshot_load.argtypes = [ctypes.POINTER(Cache), ctypes.POINTER(ctypes.c_uint8), ctypes.c_bool]
        cls.lib.original_vial_snapshot_load.restype = ctypes.c_int
        cls.oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        if cls.oracle["payload_sha256"] != recovery.PAYLOAD_SHA256:
            raise AssertionError("Not the original instruction oracle")

    def test_sixteen_original_read_hash_compare_and_ram_clear_cases(self):
        rows = self.oracle["consolidated_snapshot"]
        self.assertEqual(len(rows), 16)
        for row in rows:
            with self.subTest(pattern=row["pattern"], mode=row["mode"], fail=row["fail_data_word"]):
                data = data_pattern(row["pattern"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), row["input_data_sha256"])
                snapshot = data + bytes.fromhex(row["checkpoint_le_hex"])
                buf = (ctypes.c_uint8 * 4104).from_buffer_copy(snapshot)
                guarded = Guarded()
                ctypes.memset(ctypes.addressof(guarded), 0xA5, ctypes.sizeof(guarded))
                guarded.cache.write_address = 0xDEADBEEF
                failed = row["fail_data_word"] >= 0
                outcome = self.lib.original_vial_snapshot_load(ctypes.byref(guarded.cache), buf, not failed)
                expected = 0 if failed else 2 if row["cache_clears"] == 0 else 1
                self.assertEqual(outcome, expected)
                self.assertEqual(row["data_read_failed"], failed)
                self.assertEqual(row["read_words"], row["fail_data_word"] + 1 if failed else 1026)
                self.assertEqual(hashlib.sha256(bytes(guarded.cache.bytes)).hexdigest(), row["cache_sha256"])
                self.assertEqual(guarded.cache.write_address, row["write_address"])
                self.assertEqual((guarded.before, guarded.after), (0xA5A5A5A5, 0xA5A5A5A5))
                self.assertEqual(bytes(buf), snapshot)
                if not failed:
                    original = int(row["computed_fnv64_hex"], 16)
                    self.assertEqual(original, fnv64(data))
                    self.assertEqual(original, self.lib.original_vial_snapshot_fnv64(buf))
                else:
                    self.assertIsNone(row.get("computed_fnv64_hex"))

    def test_match_preserves_cursor_and_both_checksum_halves_matter(self):
        rows = [r for r in self.oracle["consolidated_snapshot"] if r["fail_data_word"] < 0 and r["mode"] != "erased"]
        self.assertEqual(len(rows), 12)
        self.assertEqual({r["pattern"] for r in rows}, {"zero", "ff", "ramp", "lcg"})
        for row in rows:
            match = row["mode"] == "match"
            self.assertEqual(row["cache_clears"], 0 if match else 1)
            self.assertEqual(row["write_address"], 0xDEADBEEF if match else 4104)
            expected = data_pattern(row["pattern"]) if match else bytes(4096)
            self.assertEqual(row["cache_sha256"], hashlib.sha256(expected).hexdigest())

    def test_data_read_failure_at_first_middle_and_last_word(self):
        rows = [r for r in self.oracle["consolidated_snapshot"] if r["fail_data_word"] >= 0]
        self.assertEqual([r["fail_data_word"] for r in rows], [0, 512, 1023])
        for row in rows:
            self.assertEqual(row["cache_clears"], 1)
            self.assertEqual(row["cache_sha256"], hashlib.sha256(bytes(4096)).hexdigest())
            self.assertEqual(row["write_address"], 4104)

    def test_normalized_erased_snapshot_is_not_a_valid_zero_cache_checkpoint(self):
        row, = [r for r in self.oracle["consolidated_snapshot"] if r["mode"] == "erased"]
        self.assertEqual(row["checkpoint_le_hex"], "00" * 8)
        self.assertNotEqual(row["computed_fnv64_hex"], "00" * 8)
        self.assertEqual(row["cache_clears"], 1)

    def test_changed_data_invalidates_a_previously_valid_checksum(self):
        data = data_pattern("lcg")
        changed = bytearray(data + fnv64(data).to_bytes(8, "little"))
        changed[4095] ^= 1
        buf = (ctypes.c_uint8 * 4104).from_buffer_copy(changed)
        cache = Cache()
        cache.write_address = 0xDEADBEEF
        self.assertEqual(self.lib.original_vial_snapshot_load(ctypes.byref(cache), buf, True), 1)
        self.assertEqual(bytes(cache.bytes), bytes(4096))
        self.assertEqual(cache.write_address, 4104)

    def test_null_handling_is_defensive_not_original_semantics(self):
        cache = Cache()
        cache.write_address = 0xDEADBEEF
        before = bytes(cache)
        self.assertEqual(self.lib.original_vial_snapshot_load(ctypes.byref(cache), None, True), 3)
        self.assertEqual(bytes(cache), before)
        self.assertEqual(self.lib.original_vial_snapshot_load(None, None, False), 3)
        self.assertEqual(self.lib.original_vial_snapshot_fnv64(None), 0)

    def test_oracle_stops_before_replay_and_all_flash_operations(self):
        policy = self.oracle["snapshot_boundary_policy"]
        self.assertIn("No checksum-read failures, log playback", policy)
        self.assertIn("flash init/erase/program/lock", policy)
        self.assertIn("Budget 200000", policy)


if __name__ == "__main__":
    unittest.main()
