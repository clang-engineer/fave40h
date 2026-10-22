"""One translated journal entry only; no replay loop, cursor commit or flash."""
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

INITIAL = bytes((i * 73 + 19) & 255 for i in range(4096))
INITIAL_SHA = hashlib.sha256(INITIAL).hexdigest()


def entry(address, length, type_=0):
    return bytes([(type_ << 6) | (length << 3) | ((address >> 16) & 7),
        (address >> 8) & 255, address & 255, 0xD3, 0x29, 0x80, 0, 0xFF])


class Trace(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint32), ("address", ctypes.c_uint32),
        ("next_position", ctypes.c_uint32), ("length", ctypes.c_uint8), ("read_words", ctypes.c_uint8)]


class GuardedCache(ctypes.Structure):
    _fields_ = [("before", ctypes.c_uint32), ("bytes", ctypes.c_uint8 * 4096), ("after", ctypes.c_uint32)]


class OriginalJournalEvidenceTests(unittest.TestCase):
    def test_scope_and_unmodeled_domains_are_not_firmware_rejections(self):
        evidence = json.loads((ARTIFACTS / "evidence.json").read_text())
        journal = evidence["journal_entry"]
        self.assertEqual(journal["cache_ram"], evidence["snapshot"]["cache_ram"])
        self.assertEqual(journal["modeled_lengths"], list(range(6)))
        self.assertIn("NOT skip", journal["rejected_or_second_read_failed"])
        self.assertIn("not firmware rejection", journal["lengths_6_7_note"])
        for name in ("lengths_6_7_modeled", "second_word_beyond_backing_budget_modeled",
            "first_word_read_failure_modeled", "full_replay_or_consolidation_modeled", "physical_flash_executed"):
            self.assertFalse(journal[name])
        oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        self.assertIn("before 0x08018886 global cursor commit", oracle["journal_boundary_policy"])
        self.assertIn("whole-loop playback/consolidation and flash operations NOT executed", oracle["journal_boundary_policy"])


class OriginalJournalModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("Host C compiler absent")
        temp = tempfile.TemporaryDirectory(prefix="fave40h-journal-model-")
        cls.addClassCleanup(temp.cleanup)
        library = Path(temp.name) / ("journal.dylib" if sys.platform == "darwin" else "journal.so")
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(ARTIFACTS / "journal_model.c"), "-o", str(library)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.original_vial_journal_entry.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32, ctypes.c_bool, ctypes.POINTER(Trace)]
        cls.lib.original_vial_journal_entry.restype = ctypes.c_bool
        cls.oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        if cls.oracle["payload_sha256"] != recovery.PAYLOAD_SHA256:
            raise AssertionError("Wrong original instruction oracle")
        cls.rows = cls.oracle["journal_entry"]

    def run_entry(self, data, position=0x1008, second_ok=True):
        guarded, trace = GuardedCache(), Trace()
        ctypes.memset(ctypes.addressof(guarded), 0xA5, ctypes.sizeof(guarded))
        guarded.bytes[:] = INITIAL
        buf = (ctypes.c_uint8 * 8).from_buffer_copy(data)
        handled = self.lib.original_vial_journal_entry(guarded.bytes, buf, position, second_ok, ctypes.byref(trace))
        self.assertEqual((guarded.before, guarded.after), (0xA5A5A5A5, 0xA5A5A5A5))
        self.assertEqual(bytes(buf), data)
        return handled, trace, bytes(guarded.bytes)

    def test_all_111_original_entry_cases_match_c_ram_cursor_and_reads(self):
        self.assertEqual(len(self.rows), 111)
        for row in self.rows:
            with self.subTest(entry=row["entry_hex"], position=row["position"], second=row["second_read_ok"]):
                handled, trace, cache = self.run_entry(bytes.fromhex(row["entry_hex"]), row["position"], row["second_read_ok"])
                self.assertTrue(handled)
                self.assertEqual((trace.kind, trace.next_position, trace.read_words), (row["kind"], row["next_position"], row["read_words"]))
                self.assertEqual(hashlib.sha256(cache).hexdigest(), row["cache_sha256"])
                if "decoded_address" in row:
                    self.assertEqual((trace.address, trace.length), (row["decoded_address"], row["decoded_length"]))

    def test_empty_stops_but_nonzero_zero_length_entries_advance_as_noops(self):
        empty = [r for r in self.rows if r["kind"] == 0]
        self.assertEqual(len(empty), 2)
        for row in empty:
            self.assertEqual(row["next_position"], row["position"])
            self.assertEqual(row["cache_sha256"], INITIAL_SHA)
        noops = [r for r in self.rows if r["kind"] == 1 and r["decoded_length"] == 0]
        self.assertEqual(len(noops), 10)
        self.assertTrue(any(r["decoded_address"] == 4096 for r in noops))
        for row in noops:
            self.assertEqual(row["next_position"], row["position"] + 4)
            self.assertEqual(row["cache_sha256"], INITIAL_SHA)

    def test_nonzero_types_reject_before_decoding_or_second_read(self):
        rows = [r for r in self.rows if bytes.fromhex(r["entry_hex"])[0] & 0xC0]
        self.assertEqual(len(rows), 18)
        for row in rows:
            self.assertEqual((row["kind"], row["read_words"], row["next_position"]), (2, 1, row["position"] + 4))
            self.assertEqual(row["cache_sha256"], INITIAL_SHA)
            self.assertNotIn("decoded_address", row)

    def test_address_length_bounds_and_last_slot_cursor(self):
        for row in self.rows:
            if "decoded_address" not in row:
                continue
            address, length = row["decoded_address"], row["decoded_length"]
            data = bytes.fromhex(row["entry_hex"])
            self.assertEqual(address, ((data[0] & 7) << 16) | (data[1] << 8) | data[2])
            if address + length > 4096:
                self.assertEqual((row["kind"], row["read_words"]), (2, 1))
        end = [r for r in self.rows if r["kind"] == 1 and r["next_position"] == 8192]
        self.assertTrue(any(r["decoded_length"] == 1 and r["position"] == 8192 - 4 for r in end))
        self.assertTrue(any(r["decoded_length"] == 5 and r["position"] == 8192 - 8 for r in end))

    def test_second_word_failures_do_not_copy_or_consume_failed_word(self):
        rows = [r for r in self.rows if not r["second_read_ok"]]
        self.assertEqual(len(rows), 23)
        for row in rows:
            self.assertEqual((row["kind"], row["read_words"], row["next_position"]), (3, 2, row["position"] + 4))
            self.assertEqual(row["cache_sha256"], INITIAL_SHA)
        for length in (0, 1):
            handled, trace, _ = self.run_entry(entry(41, length), second_ok=False)
            self.assertTrue(handled)
            self.assertEqual((trace.kind, trace.read_words), (1, 1))

    def test_unmodeled_lengths_and_truncated_second_word_are_not_normalized(self):
        for data, position in ((entry(0, 6), 0x1008), (entry(0, 7), 0x1008), (entry(41, 2), 0x1FFC)):
            handled, trace, cache = self.run_entry(data, position)
            self.assertFalse(handled)
            self.assertEqual(trace.kind, 4)  # UNMODELED, not original rejection.
            self.assertEqual(cache, INITIAL)

    def test_defensive_bad_arguments_do_not_modify_cache(self):
        for position in (0, 0x1007, 0x1009, 8192, 0xFFFFFFFF):
            handled, trace, cache = self.run_entry(entry(0, 1), position)
            self.assertFalse(handled)
            self.assertEqual(trace.kind, 5)
            self.assertEqual(cache, INITIAL)
        trace = Trace()
        self.assertFalse(self.lib.original_vial_journal_entry(None, None, 0x1008, True, ctypes.byref(trace)))
        self.assertEqual(trace.kind, 5)
        self.assertFalse(self.lib.original_vial_journal_entry(None, None, 0x1008, True, None))


if __name__ == "__main__":
    unittest.main()
