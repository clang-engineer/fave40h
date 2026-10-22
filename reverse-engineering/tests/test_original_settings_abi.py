"""QS-only structural audit; no network, EEPROM, USB, scheduler or callbacks."""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import audit_original_settings as audit
import recover_original_vial as recovery

ARTIFACTS = ROOT / "reverse-engineering/original-vial"


class OriginalSettingsAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ARTIFACTS / "settings-abi-audit.json").read_text())
        cls.settings = json.loads((ARTIFACTS / "evidence.json").read_text())["qmk_settings"]
        cls.reference = cls.report["reference"]

    def test_audit_is_reproducible_but_not_whole_eeprom_proof(self):
        self.assertEqual(self.report["original_uf2_sha256"], recovery.ORIGINAL_SHA256)
        self.assertEqual(self.report["original_payload_sha256"], recovery.PAYLOAD_SHA256)
        self.assertEqual(self.reference["source_hashes"], audit.SOURCE_HASHES)
        self.assertEqual(self.report["comparison"], audit.compare(self.settings, self.reference))
        result = self.report["comparison"]
        self.assertTrue(result["structural_match"])
        for flag in ("callback_bodies_compared", "exact_manufacturer_revision_identified", "whole_eeprom_compatibility_proven", "flash_ready"):
            self.assertFalse(result[flag])

    def test_qsid_ids_sizes_bits_and_offsets(self):
        self.assertEqual(self.reference["bytes"], 40)
        self.assertEqual(len(self.reference["fields"]), 23)
        self.assertEqual([p["qsid"] for p in self.reference["prototypes"]], [*range(1, 8), *range(9, 28)])
        by_id = {p["qsid"]: p for p in self.reference["prototypes"]}
        self.assertEqual([(by_id[i]["offset"], by_id[i]["size"]) for i in (7, 18, 19, 25, 27)], [(24, 2), (30, 2), (32, 2), (36, 2), (38, 2)])
        self.assertEqual([(by_id[i]["offset"], by_id[i]["bit"]) for i in (22, 23, 24, 26)], [(29, 0), (29, 1), (29, 2), (29, 3)])
        self.assertEqual((by_id[21]["kind"], by_id[21]["offset"], by_id[21]["size"]), ("custom", None, 0))

    def test_reset_decoder_matches_four_original_thumb_canary_states(self):
        oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        self.assertEqual(len(oracle["settings_reset_prefix"]), 4)
        self.assertEqual(self.settings["preserved_offsets"], [35])
        for row in oracle["settings_reset_prefix"]:
            before = bytes.fromhex(row["before_hex"])
            expected = bytes(before[i] if value is None else value for i, value in enumerate(self.settings["reset_bytes"]))
            self.assertEqual(expected.hex(), row["after_hex"])
            self.assertEqual(expected[35], before[35])
        self.assertFalse(self.settings["reset_eeprom_or_callbacks_executed"])

    def test_all_23_reference_fields_agree_with_host_c_layout(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler absent")
        fields = self.reference["fields"]
        for field in fields:
            self.assertIn(field["ctype"], ("uint8_t", "uint16_t"))
            self.assertIsNotNone(re.fullmatch(r"[A-Za-z_]\w*", field["name"]))
        source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\ntypedef struct {\n"
        source += "\n".join(f"    {f['ctype']} {f['name']};" for f in fields)
        source += '\n} qs_t;\n_Static_assert(sizeof(qs_t) == 40, "size");\nint main(void) {\n'
        for field in fields:
            name = field["name"]
            source += f'    printf("%zu %zu\\n", offsetof(qs_t, {name}), sizeof(((qs_t *)0)->{name}));\n'
        source += "    return 0;\n}\n"
        with tempfile.TemporaryDirectory(prefix="fave40h-qs-layout-") as temp:
            path = Path(temp) / "layout.c"
            path.write_text(source)
            exe = Path(temp) / "layout"
            subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(exe)], check=True, capture_output=True)
            output = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
        self.assertEqual([tuple(map(int, line.split())) for line in output.splitlines()], [(f["offset"], f["size"]) for f in fields])

    def test_unknown_reference_sources_are_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "reference source qmk_settings.h"):
            audit.reference_from_files(b"unverified header", b"unverified source")

    def test_parser_rejects_missing_or_unsupported_struct_fields(self):
        for header in ("", "typedef struct { uint32_t wide; } qmk_settings_t;", "typedef struct { void *ptr; } qmk_settings_t;"):
            with self.subTest(header=header), self.assertRaises(ValueError):
                audit.parse_reference(header, "")

    def test_offset_bit_callback_literal_and_unused_mismatches_fail(self):
        for group, index, field, value in (("prototypes", 0, "offset", 25), ("prototypes", 20, "bit", 7), ("prototypes", 0, "notify", "0x123")):
            changed = copy.deepcopy(self.settings)
            changed[group][index][field] = value
            result = audit.compare(changed, self.reference)
            self.assertFalse(result["structural_match"])
            self.assertTrue(result["differences"])
        for offset in (26, 35):  # Literal zero field, and unassigned/preserved byte.
            changed = copy.deepcopy(self.settings)
            changed["reset_bytes"][offset] = 1
            self.assertFalse(audit.compare(changed, self.reference)["structural_match"])

    def test_required_macros_are_original_values_not_assumed_header_defaults(self):
        comparison = self.report["comparison"]
        macros = comparison["required_build_macros"]
        self.assertEqual(macros["TAP_CODE_DELAY"], {"required_value_for_original": 0, "reference_header_default": 10, "override_needed_with_this_header": True})
        self.assertEqual(macros["TAP_HOLD_CAPS_DELAY"], {"required_value_for_original": 80, "reference_header_default": 80, "override_needed_with_this_header": False})
        self.assertEqual(macros["TAPPING_TERM"]["required_value_for_original"], 200)
        self.assertIsNone(macros["TAPPING_TERM"]["reference_header_default"])  # Defined elsewhere, not checked here.
        self.assertEqual(comparison["preserved_offsets"], [35])


if __name__ == "__main__":
    unittest.main()
