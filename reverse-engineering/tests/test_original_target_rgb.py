"""Original RGB transport/map projection, not full lighting or physical tests."""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reverse-engineering/tools"))
import prepare_original_target as target
import verify_original_target_rgb as rgb_probe
from recover_original_vial import parse_uf2

TARGET = ROOT / "reverse-engineering/keyboards/fave40h_original"
EVIDENCE = json.loads((ROOT / "reverse-engineering/original-vial/evidence.json").read_text())


class OriginalTargetRGBTests(unittest.TestCase):
    def test_transport_uses_original_pin_timer_channel_stream_and_rgb_order(self):
        config = (TARGET / "config.h").read_text()
        expected = {"RGB_MATRIX_LED_COUNT":"72", "WS2812_DI_PIN":"B10", "WS2812_PWM_DRIVER":"PWMD2",
            "WS2812_PWM_CHANNEL":"3", "WS2812_PWM_PAL_MODE":"1",
            "WS2812_PWM_DMA_STREAM":"STM32_DMA1_STREAM1", "WS2812_PWM_DMA_CHANNEL":"3",
            "WS2812_BYTE_ORDER":"WS2812_BYTE_ORDER_GRB"}
        for name, value in expected.items():
            self.assertRegex(config, rf"(?m)^#define {name} {value}$")
        self.assertNotRegex(config, r"(?m)^#define WS2812_RGBW\b")

    def test_hal_pwm_and_vialrgb_are_enabled_but_make_guard_remains(self):
        self.assertIn("#include_next <halconf.h>", (TARGET / "halconf.h").read_text())
        self.assertIn("#undef HAL_USE_PWM\n#define HAL_USE_PWM TRUE", (TARGET / "halconf.h").read_text())
        rules = (TARGET / "rules.mk").read_text()
        for option in ("RGB_MATRIX_ENABLE = yes", "RGB_MATRIX_DRIVER = ws2812", "WS2812_DRIVER = pwm", "ORIGINAL_TARGET_INCOMPLETE"):
            self.assertIn(option, rules)
        self.assertIn("VIALRGB_ENABLE = yes", (TARGET / "keymaps/vial/rules.mk").read_text())

    def test_tim5_selection_is_original_vector_and_handler_backed_not_a_guess(self):
        image = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())
        self.assertEqual(int.from_bytes(image.read(0x08010000 + 4*(16+50),4),"little"), 0x0801B57D)
        self.assertEqual(image.read(0x0801B580,16).hex(), "2b4f3b69fa681340dab2d2439b073a61")
        self.assertEqual(int.from_bytes(image.read(0x0801B630,4),"little"), 0x40000C00)
        mcu = (TARGET / "mcuconf.h").read_text()
        self.assertIn("#undef STM32_ST_USE_TIMER\n#define STM32_ST_USE_TIMER 5", mcu)
        self.assertIn("#undef STM32_PWM_USE_TIM2\n#define STM32_PWM_USE_TIM2 TRUE", mcu)

    def test_entire_led_table_matches_original_264_rom_bytes(self):
        source = (TARGET / "fave40h_original.c").read_text()
        data = bytes(map(int, re.findall(r"\b\d+\b", source.split("= {",1)[1].split("};",1)[0])))
        image = parse_uf2((ROOT / "firmware/origin/FAve40H_VIAL.uf2").read_bytes())
        self.assertEqual(len(data),264)
        self.assertEqual(data,image.read(0x0801DEA0,264))
        self.assertEqual(data[-72:],bytes([4]*42+[2]*30))
        self.assertEqual(len([value for value in data[:48] if value != 255]),42)

    def test_actual_upstream_integer_formulas_reach_original_timing(self):
        config = (TARGET / "config.h").read_text()
        constants = {name:int(value) for name,value in re.findall(r"#define (WS2812_\w+) (\d+)\b",config)}
        tick = 24000000  # Conditional on inferred 16MHz HSE and prior clock-header probe.
        rgb = EVIDENCE["rgb"]
        self.assertEqual(tick // (1000000000 // constants["WS2812_TIMING"]),rgb["period_ticks"])
        self.assertEqual(tick // (1000000000 // constants["WS2812_T0H"]),rgb["zero_high_ticks"])
        self.assertEqual(tick // (1000000000 // constants["WS2812_T1H"]),rgb["one_high_ticks"])
        self.assertEqual(1000 * constants["WS2812_TRST_US"] // constants["WS2812_TIMING"],rgb["reset_words"])

    def test_unknown_transport_profile_is_rejected(self):
        changed = copy.deepcopy(EVIDENCE)
        changed["rgb"]["dma_cr"] = "0x0"
        with self.assertRaisesRegex(ValueError,"Unmodeled original RGB"):
            target.rgb_artifacts(changed)

    def test_transport_is_not_reported_as_complete_lighting_or_firmware(self):
        manifest = json.loads((TARGET / "target-evidence.json").read_text())
        self.assertFalse(manifest["complete_firmware"])
        self.assertFalse(manifest["flash_ready"])
        self.assertIn("complete RGB runtime pipeline and remaining effects conformance",manifest["build_blockers"])
        self.assertFalse(manifest["rgb_effect_profile"]["all_effect_bodies_verified"])
        self.assertIn("full RGB runtime and remaining effects unverified",manifest["rgb_transport"]["scope"])
        self.assertIn("no physical DMA/PWM",manifest["rgb_transport"]["scope"])

    def test_capture_shim_defines_true_so_absent_dmamux_does_not_become_enabled(self):
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("Host C preprocessor absent")
        condition = '\n#if (STM32_DMA_SUPPORTS_DMAMUX == TRUE) || (AT32_DMA_SUPPORTS_DMAMUX == TRUE)\n#error UNEXPECTED_DMAMUX_BRANCH\n#endif\n'
        for broken in (False,True):
            hardware = rgb_probe.HARDWARE
            if broken:
                hardware = hardware.replace("#define TRUE 1\n","")
            result = subprocess.run([cc,"-E","-x","c","-"],input="#include <stdint.h>\n"+hardware+condition,text=True,capture_output=True)
            if broken:
                self.assertNotEqual(result.returncode,0)
                self.assertIn("UNEXPECTED_DMAMUX_BRANCH",result.stderr)
            else:
                self.assertEqual(result.returncode,0,result.stderr)


if __name__ == "__main__":
    unittest.main()
