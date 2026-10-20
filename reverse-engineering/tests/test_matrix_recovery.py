"""Host tests only. Set FAVE40H_STOCK_ZIP to also test the private OEM files."""
import json
import os
from pathlib import Path
import re
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import recover_matrix as r


def block(index=0, total=1, address=r.BASE, payload=b"abcd"):
    out = bytearray(512)
    struct.pack_into("<8I", out, 0, *r.MAGIC[:2], 0x2000, address, len(payload), index, total, r.FAMILY)
    out[32:32 + len(payload)] = payload
    struct.pack_into("<I", out, 508, r.MAGIC[2])
    return bytes(out)


class ParserTests(unittest.TestCase):
    def test_single_block(self):
        im = r.parse_uf2(block())
        self.assertEqual(im.data, b"abcd")
        self.assertEqual(im.family, r.FAMILY)

    def test_reordered_blocks(self):
        a = block(0, 2, r.BASE, b"1234")
        b = block(1, 2, r.BASE + 4, b"5678")
        self.assertEqual(r.parse_uf2(b + a).data, b"12345678")

    def test_bad_length(self):
        for raw in (b"", b"x", block()[:-1]):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                r.parse_uf2(raw)

    def test_bad_magic(self):
        b = bytearray(block()); b[0] ^= 1
        with self.assertRaises(ValueError): r.parse_uf2(bytes(b))

    def test_nonflash_flag_rejected(self):
        b = bytearray(block()); struct.pack_into("<I", b, 8, 0x2001)
        with self.assertRaises(ValueError): r.parse_uf2(bytes(b))

    def test_duplicate_index_rejected(self):
        b = block(0, 2, r.BASE) + block(0, 2, r.BASE + 4)
        with self.assertRaises(ValueError): r.parse_uf2(b)

    def test_overlap_and_gap_rejected(self):
        for distance in (0, 2, 8):
            b = block(0, 2, r.BASE) + block(1, 2, r.BASE + distance)
            with self.subTest(distance=distance), self.assertRaises(ValueError):
                r.parse_uf2(b)

    def test_unknown_build_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown firmware"):
            r.recover(block())

    def test_out_of_bounds_read(self):
        im = r.parse_uf2(block())
        with self.assertRaises(ValueError): im.read(r.BASE - 1, 1)
        with self.assertRaises(ValueError): im.read(r.BASE, 5)

    def test_bl_forward_and_back(self):
        im = r.Image(0x08010244, bytes.fromhex("04f086fe"), r.FAMILY)
        self.assertEqual(r.bl_target(im, im.base), 0x08014F54)
        im = r.Image(0x0801A61A, bytes.fromhex("fdf76bfc"), r.FAMILY)
        self.assertEqual(r.bl_target(im, im.base), 0x08017EF4)

    def test_pin_decoding(self):
        self.assertEqual(r.pin_name(0x40020005), "A5")
        self.assertEqual(r.pin_name(0x4002040F), "B15")
        with self.assertRaises(ValueError): r.pin_name(0x20000400)

    def test_qmk_header_matches_recorded_evidence(self):
        evidence = json.loads((ROOT / "docs/matrix-evidence.json").read_text())
        header = (ROOT / "keyboards/fave40h/config.h").read_text()
        for result in evidence:
            for axis in ("rows", "cols"):
                macro = "MATRIX_ROW_PINS" if axis == "rows" else "MATRIX_COL_PINS"
                m = re.search(r"#define " + macro + r" \{([^}]+)\}", header)
                self.assertIsNotNone(m)
                self.assertEqual([v.strip() for v in m[1].split(",")], result["matrix_pins"][axis])
            self.assertEqual(len(set(result["matrix_pins"]["rows"] + result["matrix_pins"]["cols"])), 16)
            self.assertIn("#define DIODE_DIRECTION ROW2COL", header)
            self.assertFalse(result["flash_ready"])


@unittest.skipUnless(os.environ.get("FAVE40H_STOCK_ZIP"), "Private manufacturer ZIP not provided")
class StockFirmwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.images = r.load_images(Path(os.environ["FAVE40H_STOCK_ZIP"]))

    def test_both_builds_agree_with_recorded_evidence(self):
        actual = [r.recover(raw) for _, raw in self.images]
        expected = json.loads((ROOT / "docs/matrix-evidence.json").read_text())
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 2)
        self.assertEqual(actual[0]["matrix_pins"], actual[1]["matrix_pins"])

    def test_vial_embedded_definition(self):
        raw = next(raw for _, raw in self.images if r.recover(raw)["firmware"] == "Vial")
        j = r.extract_vial_definition(raw)
        self.assertEqual(j["matrix"], {"rows": 4, "cols": 12})
        self.assertEqual(j["layouts"]["labels"], ["1U Shift"])
        self.assertEqual(len(j["customKeycodes"]), 22)

    def test_modified_image_rejected(self):
        _, raw = self.images[0]
        b = bytearray(raw)
        b[100] ^= 1
        with self.assertRaisesRegex(ValueError, "Unknown firmware"):
            r.recover(bytes(b))


if __name__ == "__main__":
    unittest.main()
