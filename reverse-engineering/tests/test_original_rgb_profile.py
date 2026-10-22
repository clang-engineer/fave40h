"""Static original-only defaults/catalog guards; actual SDK compile is a CLI probe."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import audit_original_rgb_profile as profile
from prepare_original_target import ORIGINAL_RGB_EFFECTS


class OriginalRGBProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "firmware/origin/FAve40H_VIAL.uf2"
        if not path.exists():
            raise unittest.SkipTest("Original Vial UF2 absent")
        cls.raw = path.read_bytes()
        cls.result = profile.original_profile(cls.raw)

    def test_six_default_fields_and_eight_byte_save_are_distinct(self):
        self.assertEqual(self.result["written_prefix_hex"], "3d00ffff80ff")
        self.assertEqual(self.result["written_byte_offsets"], list(range(6)))
        self.assertEqual(self.result["padding_byte_offsets_untouched"], [6, 7])
        self.assertEqual((self.result["save_logical_address"], self.result["save_length"]), ("0x17", 8))
        self.assertIn("no original Thumb execution", self.result["scope"])

    def test_catalog_has_all_stable_ids_but_one_unexposed_qmk_slot(self):
        rows = self.result["vialrgb_pairs"]
        self.assertEqual(len(rows), 45)
        self.assertEqual([vial for vial, _ in rows], list(range(45)))
        self.assertEqual(len(bytes.fromhex(self.result["vialrgb_table_hex"])), 180)
        self.assertEqual(dict(rows)[1], 45)  # Candidate direct-mode interpretation.
        self.assertEqual(dict(rows)[16], 15)  # Candidate Chevron interpretation.
        self.assertEqual({qmk for _, qmk in rows}, set(range(46)) - {29})

    def test_target_profile_validator_accepts_original_bytes_and_support_traits(self):
        actual = {"table_hex": self.result["vialrgb_table_hex"], "default_prefix_hex": "3d00ffff80ff",
                  "mode_limit": 46, "support_flags": 23, "dimensions": 0x480F08}
        profile.validate_target_profile(actual, self.result, ORIGINAL_RGB_EFFECTS, ORIGINAL_RGB_EFFECTS)

    def test_target_profile_validator_rejects_wrong_catalog_defaults_and_support(self):
        actual = {"table_hex": self.result["vialrgb_table_hex"], "default_prefix_hex": "3d00ffff80ff",
                  "mode_limit": 46, "support_flags": 23, "dimensions": 0x480F08}
        for field, wrong in (("table_hex", "00" * 180), ("default_prefix_hex", "3500ffff7fff"),
                             ("mode_limit", 45), ("support_flags", 31), ("support_flags", 22),
                             ("support_flags", 21), ("dimensions", 0x480E08), ("dimensions", 0x480F10)):
            with self.assertRaises(AssertionError):
                profile.validate_target_profile(dict(actual, **{field: wrong}), self.result, ORIGINAL_RGB_EFFECTS, ORIGINAL_RGB_EFFECTS)
        for enabled in (ORIGINAL_RGB_EFFECTS[:-1], ORIGINAL_RGB_EFFECTS + ("EXTRA",),
                        tuple("EXTRA" if name == "PIXEL_FLOW" else name for name in ORIGINAL_RGB_EFFECTS)):
            with self.assertRaisesRegex(AssertionError, "bindings"):
                profile.validate_target_profile(actual, self.result, enabled, ORIGINAL_RGB_EFFECTS)

    def test_target_probe_refuses_removed_conditional_guard_or_disabled_rgb(self):
        for rules in ("RGB_MATRIX_ENABLE = yes\n", "ifdef ALLOW\n$(error ORIGINAL_TARGET_INCOMPLETE: blocked)\nendif\nRGB_MATRIX_ENABLE = yes\n",
                      "$(error ORIGINAL_TARGET_INCOMPLETE: blocked)\nRGB_MATRIX_ENABLE = no\n"):
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder)
                (target / "keymaps/vial").mkdir(parents=True)
                (target / "config.h").write_text("")
                (target / "rules.mk").write_text(rules)
                (target / "keymaps/vial/rules.mk").write_text("VIALRGB_ENABLE = yes\n")
                with patch.object(profile, "validate_reference"), patch.object(profile.shutil, "which", return_value="/unused/cc"):
                    with self.assertRaisesRegex(ValueError, "unconditional guard"):
                        profile.audit_target(self.raw, target, target)

    def test_changed_original_rejected(self):
        changed = bytearray(self.raw)
        changed[40] ^= 1
        with self.assertRaises(ValueError):
            profile.original_profile(bytes(changed))

    def test_instruction_guard_is_live_after_identity_check(self):
        with patch.dict(profile.WITNESSES, {0x08013CF4: "00" * 44}):
            with self.assertRaisesRegex(ValueError, "RGB instruction witness"):
                profile.original_profile(self.raw)

    def test_changed_reference_header_rejected_before_hash_recording(self):
        with tempfile.TemporaryDirectory() as folder:
            reference = Path(folder)
            (reference / "header.h").write_bytes(b"changed\n")
            hashes = {}
            with patch.object(profile.subprocess, "check_output", return_value=b"pinned\n"):
                with self.assertRaisesRegex(ValueError, "Changed candidate profile source"):
                    profile.checked_source(reference, "header.h", hashes)
            self.assertEqual(hashes, {})

    def test_reference_source_identity_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            reference = Path(folder)
            text = b"pinned\n"
            (reference / "header.h").write_bytes(text)
            hashes = {}
            with patch.object(profile.subprocess, "check_output", return_value=text) as git:
                self.assertEqual(profile.checked_source(reference, "header.h", hashes), "pinned\n")
            self.assertEqual(hashes, {"header.h": hashlib.sha256(text).hexdigest()})
            self.assertIn(profile.REVISION + ":header.h", git.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
