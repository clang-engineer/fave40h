"""Serialized records only: no EEPROM persistence, USB or feature execution."""
import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import audit_original_records as audit
import recover_original_vial as recovery
from recover_matrix import Image

ARTIFACTS = ROOT / "reverse-engineering/original-vial"


def layout_source(reference):
    source = "#include <stdint.h>\n#include <stddef.h>\n"
    for name, spec in reference["types"].items():
        source += "typedef struct {\n"
        for field in spec["fields"]:
            suffix = f"[{field['count']}]" if field["count"] > 1 else ""
            source += f"{field['ctype']} {field['name']}{suffix};\n"
        source += f'}} {name};\n_Static_assert(sizeof({name})=={spec["size"]},"size");\n'
        for field in spec["fields"]:
            source += f'_Static_assert(offsetof({name},{field["name"]})=={field["offset"]},"offset");\n'
            source += f'_Static_assert(sizeof((({name}*)0)->{field["name"]})=={field["size"]},"field size");\n'
    return source


class OriginalRecordsAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((ARTIFACTS / "evidence.json").read_text())
        cls.report = json.loads((ARTIFACTS / "records-abi-audit.json").read_text())
        cls.reference = cls.report["reference"]

    def test_report_is_reproducible_with_explicit_limits(self):
        self.assertEqual(self.report["original_uf2_sha256"], recovery.ORIGINAL_SHA256)
        self.assertEqual(self.report["original_payload_sha256"], recovery.PAYLOAD_SHA256)
        self.assertEqual({name: value["sha256"] for name, value in self.reference["sources"].items()},
            {name: value[1] for name, value in audit.SOURCES.items()})
        self.assertEqual(self.report["comparison"], audit.compare(self.original, self.reference))
        result = self.report["comparison"]
        self.assertTrue(result["size_and_region_match"])
        for flag in ("prefix_default_origin_audited", "original_runtime_field_semantics_proven",
            "reference_reset_function_equivalence_proven", "whole_eeprom_compatibility_proven",
            "exact_manufacturer_revision_identified", "flash_ready"):
            self.assertFalse(result[flag])

    def test_original_templates_match_four_original_thumb_traces(self):
        oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        self.assertEqual(oracle["payload_sha256"], recovery.PAYLOAD_SHA256)
        cases = oracle["dynamic_record_reset"]
        self.assertEqual([r["name"] for r in cases], ["fill_0", "fill_255", "fill_165", "ramp"])
        expected = [{"address": record["start"] + i * record["stride"], "data_hex": bytes(record["reset_bytes"]).hex()}
            for record in self.original["dynamic_records"] for i in range(record["entries"])]
        self.assertEqual(len(expected), 80)
        for case in cases:
            self.assertEqual(case["writes"], expected)
        self.assertIn("never persisted", oracle["dynamic_record_boundary_policy"])

    def test_original_counts_must_not_follow_4096_byte_reference_defaults(self):
        records = self.report["comparison"]["records"]
        self.assertEqual([r["stride"] for r in records], [10, 10, 10, 6])
        self.assertEqual([r["entries"] for r in records], [16, 16, 16, 32])
        self.assertEqual([r["reference_default_entries_at_4096_bytes"] for r in records], [32] * 4)
        self.assertEqual([r["explicit_count_override_for_this_profile"] for r in records], [True, True, True, False])
        regions = self.report["comparison"]["reference_regions"]
        self.assertEqual([regions[r["name"]]["start"] for r in records], [0x1D1, 0x271, 0x311, 0x3B1])
        self.assertEqual(regions["macro"], {"start": 0x471, "bytes": 2959})
        defaults = dict(self.report["comparison"]["profile"])
        for name, macro in audit.MACROS.items():
            defaults[macro + "_ENTRIES"] = self.reference["default_counts_at_4096_bytes"][name]
        sizes = {name: spec["size"] for name, spec in self.reference["types"].items()}
        sizes["qmk_settings_t"] = 40
        self.assertEqual(audit.evaluate_regions(self.reference["nvm_macros"], sizes, defaults)["macro"], {"start": 0x651, "bytes": 2479})

    def test_reference_field_interpretation_of_original_defaults(self):
        records = self.report["comparison"]["records"]
        values = [{f["name"]: f["original_template_interpreted_as_reference"] for f in r["reference_fields"]} for r in records]
        self.assertEqual(values[0], {"on_tap": 0, "on_hold": 0, "on_double_tap": 0, "on_tap_hold": 0, "custom_tapping_term": 200})
        self.assertEqual(values[1], {"input": [0, 0, 0, 0], "output": 0})
        self.assertEqual(values[2], {"trigger": 0, "replacement": 0, "layers": 65535, "trigger_mods": 0,
            "negative_mod_mask": 0, "suppressed_mods": 0, "options": 7})
        self.assertEqual(values[3], {"keycode": 0, "alt_keycode": 0, "allowed_mods": 0, "options": 0})
        self.assertEqual(values[2]["options"] & 0x80, 0)  # Not the reference enabled bit.

    def test_all_fields_and_template_byte_order_agree_with_host_c(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler absent")
        source = layout_source(self.reference) + "#include <stdio.h>\nint main(void) {\n"
        initializers = ["{0,0,0,0,200}", "{{0,0,0,0},0}", "{0,0,65535,0,0,0,7}", "{0,0,0,0}"]
        for i, (record, initializer) in enumerate(zip(self.original["dynamic_records"], initializers)):
            name = audit.TYPES[record["name"]]
            source += f'{name} v{i}={initializer};\nfor(size_t j=0;j<sizeof(v{i});++j) printf("%02x",((unsigned char*)&v{i})[j]);\nputs("");\n'
        source += "return 0;\n}\n"
        with tempfile.TemporaryDirectory(prefix="fave40h-record-layout-") as temp:
            path, exe = Path(temp) / "layout.c", Path(temp) / "layout"
            path.write_text(source)
            subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(exe)], check=True, capture_output=True)
            output = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
        self.assertEqual(output.splitlines(), [bytes(r["reset_bytes"]).hex() for r in self.original["dynamic_records"]])

    def test_unknown_sources_and_unsupported_types_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "reference source vial.h"):
            audit.reference_from_files(b"unknown", b"unknown")
        for header in ("", "typedef struct { void *pointer; } vial_combo_entry_t;", "typedef struct { uint16_t input[999]; } vial_combo_entry_t;"):
            with self.subTest(header=header), self.assertRaises(ValueError):
                audit.parse_header(header)

    def test_region_evaluator_rejects_code_execution_and_cycles(self):
        sizes = {name: spec["size"] for name, spec in self.reference["types"].items()}
        sizes["qmk_settings_t"] = 40
        for value in ("__import__('os').system('not executed')", "VIAL_TAP_DANCE_EEPROM_ADDR"):
            macros = dict(self.reference["nvm_macros"])
            macros["VIAL_TAP_DANCE_EEPROM_ADDR"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit.evaluate_regions(macros, sizes, self.report["comparison"]["profile"])

    def test_count_stride_and_base_mismatches_are_reported(self):
        for kind in ("count", "stride", "base"):
            changed = copy.deepcopy(self.original)
            if kind == "base":
                changed["storage"]["keymap_start"] += 1
            else:
                changed["dynamic_records"][0]["entries" if kind == "count" else "stride"] += 1
            result = audit.compare(changed, self.reference)
            self.assertFalse(result["size_and_region_match"])
            self.assertTrue(result["differences"])

    def test_initializer_decoder_rejects_unknown_stores_and_loop_mutations(self):
        path = ROOT / "firmware/origin/FAve40H_VIAL.uf2"
        if not path.exists():
            self.skipTest("Manufacturer original Vial UF2 absent")
        image = recovery.parse_uf2(path.read_bytes())
        self.assertEqual(recovery.recover_dynamic_records(image), self.original["dynamic_records"])
        for address, halfword in ((0x08015880, 0xBF00), (0x08015884, 0x3024), (0x080158A6, 0x340B)):
            modified = bytearray(image.data)
            struct.pack_into("<H", modified, address - image.base, halfword)
            with self.subTest(address=address), self.assertRaises(ValueError):
                recovery.recover_dynamic_records(Image(image.base, bytes(modified), image.family))


if __name__ == "__main__":
    unittest.main()
