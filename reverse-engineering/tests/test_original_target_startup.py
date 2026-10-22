"""GPIO/clock target overrides and bounded original writer oracle; no hardware."""
import copy
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import prepare_original_target as target
import verify_original_target_startup as startup

TARGET = ROOT / "reverse-engineering/keyboards/fave40h_original"
EVIDENCE = json.loads((ROOT / "reverse-engineering/original-vial/evidence.json").read_text())
ORACLE = json.loads((Path(__file__).parent / "fixtures/original-vial-emulation.json").read_text())


class OriginalTargetStartupTests(unittest.TestCase):
    def test_all_42_gpio_macros_replace_inherited_board_values(self):
        header = (TARGET / "board.h").read_text()
        values = dict(re.findall(r"#define (VAL_GPIO\w+) (0x[0-9A-F]+)U", header))
        expected = {f"VAL_GPIO{port}_{register}": value for port, registers in EVIDENCE["board"]["gpio_register_defaults"].items() for register, value in registers.items()}
        self.assertEqual({key: int(value,16) for key,value in values.items()}, expected)
        self.assertEqual(len(values), 42)
        for name in values:
            self.assertIn(f"#undef {name}\n#define {name}", header)
        self.assertIn("#include_next <board.h>", header)

    def test_hse_bypass_is_removed_and_frequency_stays_explicitly_inferred(self):
        header = (TARGET / "board.h").read_text()
        self.assertIn("#undef STM32_HSE_BYPASS", header)
        self.assertNotRegex(header, r"(?m)^#define STM32_HSE_BYPASS")
        self.assertIn("#define STM32_HSECLK 16000000U", header)
        manifest = json.loads((TARGET / "target-evidence.json").read_text())
        self.assertFalse(manifest["startup"]["physical_clock_measured"])
        self.assertFalse(manifest["startup"]["hse_bypass"])
        self.assertIn("NOT executed", manifest["startup"]["scope"])
        self.assertTrue(manifest["build_blockers"])

    def test_pll_dividers_and_clock_sources_match_original_profile(self):
        header = (TARGET / "mcuconf.h").read_text()
        for name, value in (("STM32_PLLM_VALUE",16), ("STM32_PLLN_VALUE",192), ("STM32_PLLP_VALUE",4), ("STM32_PLLQ_VALUE",4)):
            self.assertRegex(header, rf"(?m)^#define {name} {value}$")
        for name, value in (("STM32_PLLSRC", "STM32_PLLSRC_HSE"), ("STM32_SW", "STM32_SW_PLL"), ("STM32_PPRE1", "STM32_PPRE1_DIV2"), ("STM32_PPRE2", "STM32_PPRE2_DIV1")):
            self.assertIn(f"#undef {name}\n#define {name} {value}", header)
        self.assertIn("#include_next <mcuconf.h>", header)

    def test_six_original_thumb_writers_match_all_registers_and_untouched_holes(self):
        self.assertEqual(ORACLE["payload_sha256"], "9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4")
        rows = ORACLE["gpio_startup_writes"]
        self.assertEqual([row["port"] for row in rows], list("ABCDEH"))
        offsets = {"MODER":0, "OTYPER":1, "OSPEEDR":2, "PUPDR":3, "ODR":5, "AFRL":8, "AFRH":9}
        for row in rows:
            expected = [0xA5A5A5A5] * 10
            for register, value in EVIDENCE["board"]["gpio_register_defaults"][row["port"]].items():
                expected[offsets[register]] = value
            self.assertEqual(row["register_words"], expected)
        self.assertIn("No physical MMIO", ORACLE["gpio_startup_boundary_policy"])

    def test_unknown_cfgr_is_not_silently_projected_to_known_clock_macros(self):
        changed = copy.deepcopy(EVIDENCE)
        changed["board"]["cfgr"] = "0x0"
        with self.assertRaisesRegex(ValueError, "divider profile"):
            target.startup_artifacts(changed)

    def test_wrong_dependency_revision_stops_before_using_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(startup, "validate_reference"), patch.object(startup.subprocess, "check_output", side_effect=[startup.CHIBIOS+"\n", "wrong\n"]):
                with self.assertRaisesRegex(ValueError, "Wrong startup submodule"):
                    startup.validate_startup_reference(Path(directory))

    def test_modified_pinned_board_header_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            first = path / "lib/chibios" / next(iter(startup.HASHES))
            first.parent.mkdir(parents=True)
            first.write_text("modified")
            with patch.object(startup, "validate_reference"), patch.object(startup.subprocess, "check_output", side_effect=[startup.CHIBIOS+"\n", startup.CONTRIB+"\n"]):
                with self.assertRaisesRegex(ValueError, "Changed startup reference"):
                    startup.validate_startup_reference(path)


if __name__ == "__main__":
    unittest.main()
