"""Regression checks for byte evidence, not hardware correctness."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("layer8_audit", ROOT / "reverse-engineering/tools/audit_layer8.py")
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def block(address=0x08010000, index=0, total=1, payload=b"abcd", family=audit.FAMILY):
    result = bytearray(512)
    struct.pack_into("<8I", result, 0, 0x0A324655, 0x9E5D5157, 0x2000, address, len(payload), index, total, family)
    result[32:32 + len(payload)] = payload
    struct.pack_into("<I", result, 508, 0x0AB16F30)
    return bytes(result)


class Uf2ParserTests(unittest.TestCase):
    def test_contiguous_and_reordered_blocks(self):
        first = block(total=2)
        second = block(address=audit.BASE + 4, index=1, total=2, payload=b"efgh")
        self.assertEqual(audit.parse_uf2(second + first).data, b"abcdefgh")

    def test_incomplete_and_empty(self):
        for raw in (b"", b"x", block()[:-1]):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                audit.parse_uf2(raw)

    def test_bad_header_fields(self):
        for offset, value in ((0, 0), (4, 0), (8, 0), (16, 0), (16, 477), (20, 1), (24, 2), (508, 0)):
            raw = bytearray(block())
            struct.pack_into("<I", raw, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                audit.parse_uf2(raw)

    def test_duplicates_gap_overlap_and_family_mismatch(self):
        first = block(total=2)
        invalid = [
            first,
            block(address=audit.BASE + 4, index=0, total=2),
            block(address=audit.BASE + 8, index=1, total=2),
            block(address=audit.BASE + 2, index=1, total=2),
            block(address=audit.BASE + 4, index=1, total=2, family=123),
        ]
        for second in invalid:
            with self.subTest(second=second[:32].hex()), self.assertRaises(ValueError):
                audit.parse_uf2(first + second)

    def test_address_overflow(self):
        with self.assertRaises(ValueError):
            audit.parse_uf2(block(address=0xFFFFFFFE))

    def test_read_bounds_and_literal_validation(self):
        image = audit.Image(audit.BASE, b"abcd", audit.FAMILY)
        for address, size in ((audit.BASE - 1, 1), (audit.BASE + 4, 1), (audit.BASE, -1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                image.read(address, size)
        with self.assertRaises(ValueError):
            audit.literal(image, audit.BASE)

    def test_oversized_input(self):
        with self.assertRaises(ValueError):
            audit.parse_uf2(b"\0" * (audit.MAX_UF2_BYTES + 512))


class ManufacturerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "firmware/layer8/fave40h_f411_vial.uf2"
        if not cls.path.exists():
            raise unittest.SkipTest("Manufacturer UF2 not supplied")
        cls.raw = cls.path.read_bytes()
        cls.image = audit.parse_uf2(cls.raw)
        cls.result = audit.audit(cls.raw)

    def test_identity_and_no_source_mutation(self):
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), audit.SHA256)
        self.assertEqual(self.raw, self.path.read_bytes())
        self.assertFalse(self.result["flash_ready"])

    def test_matrix_and_init_scan_agreement(self):
        self.assertEqual(self.result["matrix"]["rows"], ["A5", "A6", "A3", "A4"])
        self.assertEqual(self.result["matrix"]["columns"], ["B12", "B13", "B14", "B15", "A8", "B6", "B5", "B4", "B3", "A15", "B7", "B8"])
        self.assertEqual(self.result["matrix"]["direction"], "ROW2COL")

    def test_clock_and_usb(self):
        self.assertEqual(self.result["clocks"]["hse_hz_inferred_for_usb_48mhz"], 16000000)
        self.assertEqual(self.result["clocks"]["sysclk_hz_inferred"], 48000000)
        self.assertEqual((self.result["usb"]["vid"], self.result["usb"]["pid"]), ("0x5123", "0xa02d"))
        self.assertEqual(self.result["usb"]["product"], "Fave40H")
        self.assertEqual([e["address"] for e in self.result["usb"]["endpoints"]], ["0x81", "0x82", "0x2", "0x83"])

    def test_definition_storage_and_recovery_limits(self):
        self.assertEqual(self.result["vial"]["layers"], 8)
        self.assertEqual(self.result["vial"]["matrix"], {"rows": 4, "cols": 12})
        self.assertEqual(self.result["storage"]["logical_bytes"], 4096)
        self.assertFalse(self.result["boot_request"]["recovery_verified"])
        self.assertFalse(self.result["boot_request"]["bootloader_image_present"])

    def test_unknown_image_rejected(self):
        modified = bytearray(self.raw)
        modified[32] ^= 1
        with self.assertRaisesRegex(ValueError, "Unknown firmware"):
            audit.audit(bytes(modified))

    def test_every_instruction_witness_detects_drift(self):
        for name, (address, _) in audit.WITNESSES.items():
            data = bytearray(self.image.data)
            data[address - self.image.base] ^= 1
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Evidence mismatch"):
                audit.check_evidence(audit.Image(self.image.base, bytes(data), self.image.family))

    def test_constant_pointer_and_pin_table_drift(self):
        for address in (0x0801AB20, 0x08018C9C, 0x0801DA30, 0x0801E327, 0x08019F24):
            data = bytearray(self.image.data)
            data[address - self.image.base] ^= 1
            with self.subTest(address=hex(address)), self.assertRaises(ValueError):
                audit.check_evidence(audit.Image(self.image.base, bytes(data), self.image.family))

    def test_existing_four_layer_image_is_not_assumed_compatible(self):
        original = ROOT / "firmware/origin/FAve40H_VIAL.uf2"
        if not original.exists():
            self.skipTest("Original four-layer UF2 not supplied")
        with self.assertRaisesRegex(ValueError, "Unknown firmware"):
            audit.audit(original.read_bytes())


if __name__ == "__main__":
    unittest.main()
