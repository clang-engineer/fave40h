"""Prefix observations and isolated startup conditions, never persistent storage."""
import copy
import ctypes
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import audit_original_prefix as audit
import recover_original_vial as recovery

ARTIFACTS = ROOT / "reverse-engineering/original-vial"


def layout_source(reference):
    # Exact reference packed declaration, for offsetof/sizeof ONLY (no instances).
    # ARM Clang diagnoses the intentionally unaligned anonymous union. Preserve
    # that diagnostic with -Wno-error=unaligned-access for this layout probe only;
    # never change packing or apply that exception to the recovered C models.
    core = reference["core"]
    source = '#include <stdint.h>\n#include <stddef.h>\n#define PACKED __attribute__((packed))\n'
    source += core["packed_declaration"] + f'\n_Static_assert(sizeof(eeprom_core_t)=={core["bytes"]},"size");\n'
    for field in core["fields"]:
        source += f'_Static_assert(offsetof(eeprom_core_t,{field["name"]})=={field["offset"]},"offset");\n'
        source += f'_Static_assert(sizeof(((eeprom_core_t*)0)->{field["name"]})=={field["size"]},"field size");\n'
    return source


class OriginalPrefixAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ARTIFACTS / "prefix-abi-audit.json").read_text())
        cls.reference = cls.report["reference"]
        cls.prefix = json.loads((ARTIFACTS / "evidence.json").read_text())["eeprom_prefix"]

    def test_pinned_report_is_reproducible_and_explicitly_partial(self):
        self.assertEqual(self.report["original_uf2_sha256"], recovery.ORIGINAL_SHA256)
        self.assertEqual(self.report["original_payload_sha256"], recovery.PAYLOAD_SHA256)
        self.assertEqual({name: entry["sha256"] for name, entry in self.reference["sources"].items()},
            {name: entry[1] for name, entry in audit.SOURCES.items()})
        self.assertEqual(self.report["comparison"], audit.compare(self.prefix, self.reference))
        result = self.report["comparison"]
        self.assertTrue(result["prefix_profile_match"])
        for name in ("candidate_actual_generated_build_id_checked", "all_core_field_semantics_proven",
            "reset_bodies_compared_or_executed", "flash_backing_or_migration_proven",
            "exact_manufacturer_revision_identified", "whole_eeprom_compatibility_proven", "flash_ready"):
            self.assertFalse(result[name])
        self.assertFalse(self.prefix["reset_or_flash_operations_executed"])

    def test_reference_prefix_default_profile_derives_original_base(self):
        comparison = self.report["comparison"]
        self.assertEqual((comparison["reference_core_bytes"], comparison["reference_via_magic_start"],
            comparison["reference_layout_start"], comparison["reference_keymap_start"]), (37, 37, 40, 41))
        self.assertEqual(len(self.prefix["observed_core_accesses"]), 7)
        self.assertEqual(len(self.reference["core"]["fields"]), 17)
        self.assertEqual(len(comparison["reference_core_fields_not_verified_against_original"]), 10)
        fields = {f["name"]: (f["offset"], f["size"]) for f in self.reference["core"]["fields"]}
        self.assertEqual(fields["keyboard"], (15, 4))
        self.assertEqual(fields["user"], (19, 4))
        self.assertEqual(fields["led_matrix"], (23, 4))
        self.assertEqual(fields["rgb_matrix"], (23, 8))
        self.assertEqual(fields["connection"], (36, 1))

    def test_build_id_low24_is_not_a_source_revision_or_safe_migration_override(self):
        self.assertEqual(self.prefix["via_magic_bytes"], [0x4B, 0xF4, 0x29])
        self.assertEqual(self.prefix["build_id_low24"], 0x29F44B)
        self.assertEqual(self.prefix["core_magic_u16"], 0xFEE3)
        self.assertFalse(self.prefix["build_id_high8_known"])
        self.assertTrue(self.prefix["gates_are_isolated_not_a_full_boot_simulation"])
        self.assertIn("not the non-Vial build-date", self.reference["vial_stamp_source"])
        self.assertIn("Do not preserve this stamp merely", self.report["comparison"]["warning"])

    def test_reference_packed_fields_agree_with_host_c(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler absent")
        self.assertEqual(audit.parse_packed_core(self.reference["core"]["packed_declaration"]), self.reference["core"])
        with tempfile.TemporaryDirectory(prefix="fave40h-prefix-layout-") as temp:
            source, obj = Path(temp) / "layout.c", Path(temp) / "layout.o"
            source.write_text(layout_source(self.reference))
            subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-c", str(source), "-o", str(obj)], check=True, capture_output=True)

    def test_unknown_sources_and_unsupported_packed_declarations_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "reference source eeconfig.h"):
            audit.reference_from_files({name: b"unverified" for name in audit.SOURCES})
        for source in ("", "typedef struct { uint8_t value; } eeprom_core_t;",
            "typedef struct PACKED { void *pointer; union { uint8_t a; uint64_t b; }; } eeprom_core_t;"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                audit.parse_packed_core(source)

    def test_access_and_extension_mismatches_are_reported(self):
        changed = copy.deepcopy(self.prefix)
        changed["observed_core_accesses"][0]["offset"] += 1
        self.assertFalse(audit.compare(changed, self.reference)["prefix_profile_match"])
        for name in ("EECONFIG_KB_DATA_SIZE", "EECONFIG_USER_DATA_SIZE", "VIA_EEPROM_LAYOUT_OPTIONS_SIZE", "VIA_EEPROM_CUSTOM_CONFIG_SIZE"):
            reference = copy.deepcopy(self.reference)
            reference["default_profile"][name] += 1
            with self.subTest(name=name):
                self.assertFalse(audit.compare(self.prefix, reference)["prefix_profile_match"])


class OriginalPrefixModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("Host C compiler absent")
        temp = tempfile.TemporaryDirectory(prefix="fave40h-prefix-model-")
        cls.addClassCleanup(temp.cleanup)
        obj = Path(temp.name) / ("prefix.dylib" if sys.platform == "darwin" else "prefix.so")
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(ARTIFACTS / "prefix_model.c"), "-o", str(obj)], check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(obj))
        for name in ("original_vial_via_valid", "original_vial_core_prefix_valid", "original_vial_layout_option"):
            fn = getattr(cls.lib, name)
            fn.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
            fn.restype = ctypes.c_uint8 if name.endswith("option") else ctypes.c_bool
        cls.oracle = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())
        if cls.oracle["payload_sha256"] != recovery.PAYLOAD_SHA256:
            raise AssertionError("Wrong original instruction oracle")

    @staticmethod
    def expected_stamp_reads(prefix):
        reads = []
        for i, expected in enumerate((0x4B, 0xF4, 0x29)):
            reads.append({"offset": 37 + i, "size": 1})
            if prefix[37 + i] != expected:
                break
        return reads

    def test_766_original_stamp_variations_and_short_circuit_reads(self):
        cases = self.oracle["prefix_validity"]
        self.assertEqual(len(cases), 766)
        self.assertEqual(len({r["stamp_hex"] for r in cases}), 766)
        for row in cases:
            prefix = bytearray([0xA5] * 41)
            prefix[37:40] = bytes.fromhex(row["stamp_hex"])
            buf = (ctypes.c_uint8 * 41).from_buffer_copy(prefix)
            self.assertEqual(self.lib.original_vial_via_valid(buf), row["valid"])
            self.assertEqual(row["valid"], row["stamp_hex"] == "4bf429")
            self.assertEqual(row["reads"], self.expected_stamp_reads(prefix))
            self.assertEqual(bytes(buf), bytes(prefix))

    def test_64_independent_startup_gates_and_layout_reads(self):
        cases = self.oracle["prefix_gates"]
        self.assertEqual(len(cases), 64)
        self.assertEqual(len({r["prefix_hex"] for r in cases}), 64)
        for row in cases:
            prefix = bytes.fromhex(row["prefix_hex"])
            buf = (ctypes.c_uint8 * 41).from_buffer_copy(prefix)
            self.assertEqual(row["early_reset_entries"], [] if self.lib.original_vial_via_valid(buf) else ["via_init"])
            self.assertEqual(row["later_reset_entries"], [] if self.lib.original_vial_core_prefix_valid(buf) else ["core_init"])
            self.assertEqual(row["early_reads"], self.expected_stamp_reads(prefix))
            late = [{"offset": 0, "size": 2}]
            if int.from_bytes(prefix[:2], "little") == 0xFEE3:
                late += self.expected_stamp_reads(prefix)
            self.assertEqual(row["later_reads"], late)
            self.assertEqual(row["layout_value"], self.lib.original_vial_layout_option(buf))
            self.assertEqual(row["layout_reads"], [{"offset": 40, "size": 1}])
            self.assertEqual(bytes(buf), prefix)
        self.assertIn("two independent startup slices", self.oracle["prefix_boundary_policy"])
        self.assertIn("BEFORE executing their bodies", self.oracle["prefix_boundary_policy"])

    def test_null_is_defensively_invalid_not_original_hardware_behavior(self):
        self.assertFalse(self.lib.original_vial_via_valid(None))
        self.assertFalse(self.lib.original_vial_core_prefix_valid(None))
        self.assertEqual(self.lib.original_vial_layout_option(None), 0)


if __name__ == "__main__":
    unittest.main()
