#!/usr/bin/env python3
"""Original-only QMK target seed. Intentionally blocked until runtime integration."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from recover_original_vial import recover

REVISION = "dd43959ae5c08d8a28d38a1acf7b04e86b14a344"
# Candidate names whose compiled Vial table matches all45 original entries.
# Names are bindings to the approved base, not manufacturer source provenance.
ORIGINAL_RGB_EFFECTS = (
    "ALPHAS_MODS", "BAND_PINWHEEL_SAT", "BAND_PINWHEEL_VAL", "BAND_SAT",
    "BAND_SPIRAL_SAT", "BAND_SPIRAL_VAL", "BAND_VAL", "BREATHING",
    "CYCLE_ALL", "CYCLE_LEFT_RIGHT", "CYCLE_OUT_IN", "CYCLE_OUT_IN_DUAL",
    "CYCLE_PINWHEEL", "CYCLE_SPIRAL", "CYCLE_UP_DOWN", "DIGITAL_RAIN",
    "DUAL_BEACON", "GRADIENT_LEFT_RIGHT", "GRADIENT_UP_DOWN", "HUE_BREATHING",
    "HUE_PENDULUM", "HUE_WAVE", "JELLYBEAN_RAINDROPS", "MULTISPLASH",
    "PIXEL_FLOW", "PIXEL_FRACTAL", "PIXEL_RAIN", "RAINBOW_BEACON",
    "RAINBOW_MOVING_CHEVRON", "RAINBOW_PINWHEELS", "RAINDROPS",
    "SOLID_MULTISPLASH", "SOLID_REACTIVE", "SOLID_REACTIVE_CROSS",
    "SOLID_REACTIVE_MULTICROSS", "SOLID_REACTIVE_MULTINEXUS",
    "SOLID_REACTIVE_MULTIWIDE", "SOLID_REACTIVE_NEXUS", "SOLID_REACTIVE_SIMPLE",
    "SOLID_REACTIVE_WIDE", "SOLID_SPLASH", "SPLASH", "TYPING_HEATMAP",
)
REFERENCE_HASHES = {
    "quantum/vialrgb_effects.inc": "4bcd1426ce215d69891181c3a55202580fd47cecd5ba60140e641d55413e9ff8",
    "quantum/rgb_matrix/animations/rgb_matrix_effects.inc": "879ff3e5ac88ee6432504032a04f9f5f09ba442b694890c35f918a7b7aa75132",
    "quantum/rgb_matrix/post_config.h": "b9a369b11f5e9ccc1b76986e072c61da2de40ed854837936c72f6f45a9f7d51d",
    "quantum/color.h": "d99ab54a015b653468e9059a8f44386a52c8d863858a3fa80b214ab5d3443240",
    "quantum/process_keycode/process_space_cadet.c": "2aedf14a19bb41ce8d4fc0f8729788c768ff1ed4cebe1cf2a9da976b251e3454",
    "quantum/process_keycode/process_space_cadet.h": "b3af491600d6526187cedffeadb307526e62bdeeb3704e16d2955c72a0b3d5c2",
    "quantum/action_tapping.h": "5391e6db8111db0590b0e4add05b45b90ff356993c161a0f5ee0458ffa16e7e8",
    "quantum/keycodes.h": "0a4cf54e4d2bd33fdbc12492fca88446545769abce7ab38bbd790c4aa019f523",
    "quantum/keycode.h": "3e9adb1a27e9c9b6731a2c457fc0252fdf58867d2c31c59c89eba02e1ff0afc3",
    "quantum/modifiers.h": "3bce36626836372e312b85f3d0f9f913f639e5c024dd4bda6b63f1ee1bd8ffb5",
    "platforms/timer.h": "af69c274f3ceff8abb3b733b0a104ee8c3dbe31092d3cce91bb66549e9c930a2",
    "quantum/quantum.c": "28cc489bccd93b6fb4cfc90cf8bf0d4b51ffe1928fb06bc309bf2449f5471b84",
    "quantum/action.h": "9dca61922243734df3dcca6bf746645a3e33d9abcb6d11abe6857dd9979f021b",
    "quantum/keyboard.h": "a8172bef9e6425327a584c7a5920d3416176bcaa6b03ce3e1106bf8e03cfe10a",
    "tmk_core/protocol/host.h": "48c1d9dd4174d8a26d348cbb7f56f8cfe835b2d464a1198326ec43996f2d0023",
    "quantum/rgb_matrix/rgb_matrix.c": "f1de3181f75adfe45435f5f479e22258d064ec3297cbebbeef301a911a11fd29",
    "quantum/rgb_matrix/rgb_matrix.h": "6bae63310a4a74f2119dbf98e22fb73ca5de14d13b9cea25e5b6841c043168ca",
    "quantum/eeconfig.c": "bd58a23aa7250d28314a6dc84286868dd403969b4cb865ffe80c6003675f8d4d",
    "quantum/eeconfig.h": "d5060211da78683a1a722c507c3fe018de08f87ba8d7bda9b433cf9dce0590f5",
    "quantum/keyboard.c": "b5a772541619667003090ba9ea686463457cbadfcc4f9148f17a3a12fbe32257",
    "quantum/keymap_introspection.c": "5142cdfa1fef83a137a222270aadcd91008f6fd5c2188b4d9b0d668c51aa3b98",
    "quantum/dynamic_keymap.c": "1a8fcded44060be269426234e2cf3412c82cf1bcf0de70568687924b9e6507d0",
    "builddefs/build_vial.mk": "bd228ea3422351321b604be57d1b471d56aa710faaf07684825263bc5e13725c",
    "platforms/chibios/boards/GENERIC_STM32_F411XE/configs/mcuconf.h": "6e68a8e6a3148cc6e494ac39576a8f18251e703508d15919f4ea585399a2d105",
    "platforms/chibios/boards/GENERIC_STM32_F411XE/board/board.mk": "bf955284e503ca33a99235fee3586fa351b7106dcd47789ed501c1348c47247e",
    "platforms/chibios/drivers/ws2812_pwm.c": "30ce49da04d3ac288243320f417b19609f50f31631b88ff25c5c247503c35c62",
    "drivers/led/ws2812.h": "1a15cc52d602fb5af78e3b278abece1008e12afc72bed1d3c1112754c28be3c0",
    "quantum/rgb_matrix/rgb_matrix_types.h": "59e08854c46e1161ae3b04af51730a6207321182120f26e274b218661614b6bc",
}


def validate_reference(directory):
    revision = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("Wrong experimental QMK revision")
    for relative, digest in REFERENCE_HASHES.items():
        if hashlib.sha256((directory / relative).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Changed QMK reference: {relative}")


def startup_artifacts(evidence):
    board = evidence["board"]
    pll = int(board["pllcfgr"], 16)
    if int(board["cfgr"], 16) != 0x38881000:
        raise ValueError("Unmodeled original clock divider profile")
    gpio = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Original six-bank register data through the pinned ChibiOS board initializer.
#pragma once
#include_next <board.h>
#undef BOARD_ST_NUCLEO64_F411RE
#undef BOARD_NAME
#define BOARD_NAME "Fave40H original reconstruction"
#define BOARD_FAVE40H_ORIGINAL
#undef STM32_HSECLK
#define STM32_HSECLK 16000000U
// Original clears HSEBYP before HSE enable; Nucleo bypass must not leak in.
#undef STM32_HSE_BYPASS
'''
    for port, registers in board["gpio_register_defaults"].items():
        for register, value in registers.items():
            macro = f"VAL_GPIO{port}_{register}"
            gpio += f"#undef {macro}\n#define {macro} 0x{value:08X}U\n"
    overrides = {"STM32_PLLM_VALUE": pll & 63, "STM32_PLLN_VALUE": (pll >> 6) & 511,
        "STM32_PLLP_VALUE": 2 * (((pll >> 16) & 3) + 1), "STM32_PLLQ_VALUE": (pll >> 24) & 15,
        "STM32_PLLSRC": "STM32_PLLSRC_HSE", "STM32_SW": "STM32_SW_PLL",
        "STM32_HPRE": "STM32_HPRE_DIV1", "STM32_PPRE1": "STM32_PPRE1_DIV2", "STM32_PPRE2": "STM32_PPRE2_DIV1",
        "STM32_RTCPRE_VALUE": 8, "STM32_MCO1SEL": "STM32_MCO1SEL_HSI", "STM32_MCO1PRE": "STM32_MCO1PRE_DIV1",
        "STM32_MCO2SEL": "STM32_MCO2SEL_SYSCLK", "STM32_MCO2PRE": "STM32_MCO2PRE_DIV5", "STM32_I2SSRC": "STM32_I2SSRC_CKIN",
        "STM32_HSI_ENABLED": "TRUE", "STM32_LSI_ENABLED": "TRUE", "STM32_HSE_ENABLED": "TRUE", "STM32_LSE_ENABLED": "FALSE",
        "STM32_CLOCK48_REQUIRED": "TRUE", "STM32_PWM_USE_TIM2": "TRUE", "STM32_ST_USE_TIMER": 5}
    mcu = '// SPDX-License-Identifier: GPL-2.0-or-later\n// Original PLL/CFGR profile; clock frequencies conditional on inferred 16MHz HSE.\n#pragma once\n#include_next <mcuconf.h>\n'
    for name, value in overrides.items():
        mcu += f"#undef {name}\n#define {name} {value}\n"
    return {"board.h": gpio, "mcuconf.h": mcu}


def rgb_artifacts(evidence):
    rgb = evidence["rgb"]
    parameters = evidence["vendor_space_cadet"]["parameters"]
    if [row["keycode"] for row in parameters] != list(range(0x7E01, 0x7E0F)):
        raise ValueError("Unmodeled original vendor Space Cadet codes")
    cadet_table = "static const uint8_t original_cadet_args[14][3] = {\n" + "".join(
        "    {" + ", ".join(f"0x{row[field]:02X}" for field in ("hold_modifier", "tap_modifier", "tap_keycode")) + "},\n"
        for row in parameters) + "};\n"
    if (rgb["led_count"], rgb["dma_cr"], rgb["transfer_words"], rgb["reset_words"]) != (72, "0x06035540", 1952, 224):
        raise ValueError("Unmodeled original RGB transport profile")
    table = "// SPDX-License-Identifier: GPL-2.0-or-later\n// Original 264-byte LED table, through pinned QMK led_config_t.\n#include \"quantum.h\"\nled_config_t g_led_config = {\n"
    for rows in (rgb["matrix_to_led"], rgb["positions"]):
        table += "    {\n"
        table += "".join("        { " + ", ".join(map(str, row)) + " },\n" for row in rows)
        table += "    },\n"
    table += "    { " + ", ".join(map(str, rgb["flags"])) + " }\n};\n"
    table += '''
// Original user EEPROM word at 0x13: low two bytes are RGB group enables.
// Keep all four loaded bytes verbatim; do not normalize nonzero enable bytes.
uint32_t original_rgb_group_state;
void eeconfig_init_user(void) {
    original_rgb_group_state = 0x00000101U;
    eeconfig_update_user(original_rgb_group_state);
}
void keyboard_post_init_user(void) {
    original_rgb_group_state = eeconfig_read_user();
}
// Last Shift edge, not the union of currently held Shift modifiers.
uint8_t original_last_shift_edge;
''' + cadet_table + '''// Destructive reset remains pending. Do not add an EEPROM save here.
bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    if (keycode == 0xE1 || keycode == 0xE5) original_last_shift_edge = record->event.pressed;
    if (keycode == 0x7E00) {
        // Deliberately reselect on release too, as in the original.
        uint8_t code = original_last_shift_edge ? 0x4C : 0x2A;
        if (record->event.pressed) register_code(code);
        else unregister_code(code);
        return false;
    }
    if (keycode >= 0x7E01 && keycode <= 0x7E0E) {
        const uint8_t *args = original_cadet_args[keycode - 0x7E01];
        perform_space_cadet(record, keycode, args[0], args[1], args[2]);
        return false;
    }
    if (keycode < 0x7E10 || keycode > 0x7E15) return true;
    if (record->event.pressed) {
        unsigned command = keycode - 0x7E10;
        unsigned shift = (command / 3) * 8;
        uint32_t value = (original_rgb_group_state >> shift) & 0xFFU;
        switch (command % 3) {
            case 0: value ^= 1U; break;
            case 1: value = 1U; break;
            case 2: value = 0U; break;
        }
        original_rgb_group_state = (original_rgb_group_state & ~(0xFFU << shift)) | (value << shift);
    }
    return false;
}
bool rgb_matrix_indicators_user(void) {
    if (host_keyboard_leds() & 0x02U) rgb_matrix_set_color(22, 255, 255, 255);
    return true;
}
// Framework-supplied valid LED interval only. Keep the original per-chunk pass:
// a final Caps white at LED22 is outside [60,72) and is deliberately not cleared.
bool rgb_matrix_indicators_advanced_user(uint8_t begin, uint8_t end) {
    for (uint8_t led = begin; led < end; ++led) {
        uint8_t flags = g_led_config.flags[led];
        if (((original_rgb_group_state & 0xFFU) == 0 && (flags & 4U)) ||
            (((original_rgb_group_state >> 8) & 0xFFU) == 0 && (flags & 2U)))
            rgb_matrix_set_color(led, 0, 0, 0);
    }
    return true;
}
'''
    return {"fave40h_original.c": table,
        "halconf.h": "// SPDX-License-Identifier: GPL-2.0-or-later\n#pragma once\n#include_next <halconf.h>\n#undef HAL_USE_PWM\n#define HAL_USE_PWM TRUE\n"}


def default_layout(definition):
    """Build-metadata projection of embedded option 0; full Vial JSON retained."""
    result, seen = [], set()
    for y, row in enumerate(definition["layouts"]["keymap"]):
        x, width = 0, 1
        for item in row:
            if isinstance(item, dict):
                if set(item) - {"c", "w", "x"}:
                    raise ValueError("Unmodeled original layout geometry")
                x += item.get("x", 0)
                width = item.get("w", 1)
                continue
            match = re.fullmatch(r"(\d+),(\d+)(?:\n\n\n0,([01]))?", item)
            if not match:
                raise ValueError("Unmodeled original layout label")
            r, c = int(match[1]), int(match[2])
            if match[3] != "1":
                if not (0 <= r < 4 and 0 <= c < 12) or (r, c) in seen:
                    raise ValueError("Invalid/duplicate original default layout cell")
                key = {"matrix": [r, c], "x": x, "y": y}
                if width != 1:
                    key["w"] = width
                result.append(key)
                seen.add((r, c))
            x += width
            width = 1
    return result


def artifacts(raw):
    evidence, definition = recover(raw)
    from recover_original_vial import parse_uf2
    image = parse_uf2(raw)
    if image.read(0x0801B0C4, 18).hex() != "196801f0f90119609a601a6842f480321a60":
        raise ValueError("Original non-bypass HSE initialization changed")
    for address, witness in ((0x08010108, "7db50108"), (0x0801B580, "2b4f3b69fa681340dab2d2439b073a61"), (0x0801B630, "000c0040")):
        if image.read(address, len(witness) // 2).hex() != witness:
            raise ValueError("Original TIM5 system-timer vector/handler witness changed")
    for address, witness in ((0x0801441E, "00210f20fff7fbfb074b40f2011119601320fff7f4fb"),
            (0x08018C84, "0023042214a91320149304f0c7fc4e4b149a1a60"),
            (0x08014444, "e41e0020"), (0x08018DCC, "e41e0020")):
        if image.read(address, len(witness) // 2).hex() != witness:
            raise ValueError("Original RGB group reset/load witness changed")
    if image.read(0x08014A7C, 40).hex() != "c0eb0010c3b203f10f02d2b2482a4ff0000063f30700134628bf482382b063f30f2002b070470000":
        raise ValueError("Original RGB chunk limits helper changed")
    usb, matrix = evidence["usb"], evidence["matrix"]
    layers = evidence["factory_keymap"]["raw_keycodes"][:3]
    layout = default_layout(definition)
    led_cells = {(r, c) for r, row in enumerate(evidence["rgb"]["matrix_to_led"]) for c, led in enumerate(row) if led != 255}
    if {tuple(k["matrix"]) for k in layout} != led_cells or len(layout) != 42:
        raise ValueError("Embedded default layout and original switch LED map differ")
    keyboard = {"keyboard_name": usb["product"], "manufacturer": usb["manufacturer"],
        "processor": "STM32F411", "board": "GENERIC_STM32_F411XE", "bootloader": "tinyuf2",
        "usb": {"vid": usb["vid"], "pid": usb["pid"], "device_version": "1.0.0"},
        "diode_direction": matrix["diode_direction"],
        "matrix_pins": {"rows": matrix["rows"], "cols": matrix["columns"]},
        "layouts": {"LAYOUT": {"layout": layout}}}
    uid = ", ".join(f"0x{b:02X}" for b in evidence["vial"]["uid_bytes"])
    config = f'''// SPDX-License-Identifier: GPL-2.0-or-later
// Generated original-only profile; startup/runtime integration is NOT complete.
#pragma once
#define DYNAMIC_KEYMAP_LAYER_COUNT 4
#define VIAL_KEYBOARD_UID {{ {uid} }}
#define WEAR_LEVELING_LOGICAL_SIZE 4096
#define WEAR_LEVELING_BACKING_SIZE 8192
#define WEAR_LEVELING_EFL_FIRST_SECTOR 3
#define VIAL_TAP_DANCE_ENTRIES 16
#define VIAL_COMBO_ENTRIES 16
#define VIAL_KEY_OVERRIDE_ENTRIES 16
#define VIAL_ALT_REPEAT_KEY_ENTRIES 32
#define TAP_CODE_DELAY 0
#define RGB_MATRIX_LED_COUNT 72
#define RGB_MATRIX_LED_PROCESS_LIMIT 15
// Original hit collector records presses, including consumed vendor keys.
#define RGB_MATRIX_KEYPRESSES
#define LED_HITS_TO_REMEMBER 8
// Original enum/catalog bindings; only selected effect bodies verified so far.
#define RGB_MATRIX_DEFAULT_MODE RGB_MATRIX_RAINBOW_MOVING_CHEVRON
#define RGB_MATRIX_DEFAULT_SPD 128
{''.join('#define ENABLE_RGB_MATRIX_' + name + chr(10) for name in ORIGINAL_RGB_EFFECTS)}#define WS2812_DI_PIN B10
#define WS2812_PWM_DRIVER PWMD2
#define WS2812_PWM_CHANNEL 3
#define WS2812_PWM_PAL_MODE 1
#define WS2812_PWM_DMA_STREAM STM32_DMA1_STREAM1
#define WS2812_PWM_DMA_CHANNEL 3
#define WS2812_TIMING 1250
#define WS2812_T0H 350
#define WS2812_T1H 900
#define WS2812_TRST_US 280
#define WS2812_BYTE_ORDER WS2812_BYTE_ORDER_GRB
// No old BUILD_ID pin, guessed unlock combo, or VIAL_INSECURE escape hatch.
'''
    rows = []
    for index, layer in enumerate(layers):
        rows.append(f"    [{index}] = {{")
        rows.extend("        { " + ", ".join(f"0x{k:04X}" for k in row) + " }," for row in layer)
        rows.append("    },")
    keymap = '''// SPDX-License-Identifier: GPL-2.0-or-later
// Three compiled factory layers, NOT four. Candidate raw introspection returns
// KC_TRNS for layer 3 during four-layer dynamic reset, matching original reset.
#include QMK_KEYBOARD_H
const uint16_t PROGMEM keymaps[3][MATRIX_ROWS][MATRIX_COLS] = {
''' + "\n".join(rows) + "\n};\n"
    manifest = {"status": "seed_only_build_blocked", "complete_firmware": False, "flash_ready": False,
        "experimental_qmk_revision": REVISION, "reference_hashes": REFERENCE_HASHES,
        "compiled_factory_layers": 3, "dynamic_layers": 4, "default_layout_keys": 42,
        "layout_scope": "embedded option 0 build metadata only; full Vial definition and its alternatives retained",
        "serial": usb["serial"], "serial_source": "pinned builddefs/build_vial.mk literal, NOT a verified manufacturer Git revision",
        "boot_profile": "candidate TinyUF2 application offset and request marker match; actual installed bootloader not identified",
        "processor_scope": "software-compatible candidate only, physical MCU/capacity unverified",
        "startup": {"gpio_banks": list(evidence["board"]["gpio_register_defaults"]), "hse_hz_inferred": 16000000,
            "hse_bypass": False, "pllcfgr": evidence["board"]["pllcfgr"], "cfgr": evidence["board"]["cfgr"],
            "scope": "target overrides for pinned board initializer; clock procedure/hardware NOT executed or fully validated",
            "hse_evidence_slice": "0x0801B0C4..0x0801B0D6", "physical_clock_measured": False},
        "system_timer": {"timer": "TIM5", "irq": 50, "handler": "0x0801B57C", "base_literal": "0x0801B630 -> 0x40000C00",
            "scope": "original IRQ50 vector and handler static inspection; no IRQ/kernel execution; avoids candidate default TIM2/PWM conflict"},
        "rgb_effect_profile": {"enable_effects": list(ORIGINAL_RGB_EFFECTS), "vial_table_entries": 45,
            "qmk_mode_limit": 46, "unmapped_qmk_mode": 29, "default_mode": 15,
            "default_mode_binding": "RGB_MATRIX_RAINBOW_MOVING_CHEVRON", "default_speed": 128,
            "default_initialized_prefix_hex": "3d00ffff80ff", "padding_bytes_untouched": [6, 7],
            "selected_effects_compared": [15, 29], "all_effect_bodies_verified": False,
            "scope": "catalog/default config bindings to approved candidate; target-config native table/default checks and selected15/29 effect comparisons, NOT full RGB runtime/renderer/indicator/flush, persistence or physical output"},
        "rgb_key_events": {"edge": "press", "hit_capacity": 8, "packed_hit_bytes": 41,
            "original_buffer_ram": "0x20001AC6", "scope": "electrical edge collector after action dispatch; guarded original Thumb incl memcpy and candidate switch-events/collector probes; no full scan/action/HID, aging, heatmap or renderer execution"},
        "rgb_chunks": {"process_limit": 15, "normal_spans": [[0,15],[15,30],[30,45],[45,60],[60,72]],
            "original_helper": "0x08014A7C..0x08014AA4", "scope": "all uint8 helper inputs verified; normal renderer uses iter0..4 only",
            "caps_filter_quirk": "active final chunk sets Caps LED22 white before filtering [60,72), so keylight-disabled state does not clear that white in this bounded slice; preserve, do not silently fix"},
        "rgb_group_lifecycle": {"user_field_offset": "0x13", "word_bytes": 4, "reset_word": "0x00000101",
            "original_state_ram": "0x20001EE4", "reset_slice": "0x0801441E..0x08014434",
            "load_slice": "0x08018C84..0x08018C98", "target_hooks": ["eeconfig_init_user", "keyboard_post_init_user"],
            "scope": "bounded reset/load and complete-read word preservation only; no physical EEPROM, complete reset, flush or migration validation; six group keys connected through user gate; complete persistence policy not established"},
        "rgb_transport": {"source": "unmodified pinned ws2812_pwm.c", "led_table_bytes": 264,
            "pwm_pin": "PB10", "timer": "TIM2", "channel": 3, "alternate_function": 1,
            "dma_stream": "DMA1 stream1", "dma_channel": 3, "dma_cr": evidence["rgb"]["dma_cr"],
            "tick_hz_conditional": 24000000, "period_ticks": 30, "zero_ticks": 8, "one_ticks": 21,
            "transfer_words": 1952, "reset_words": 224, "word_bits": 32,
            "scope": "transport, LED map, Caps/basic/group filter and catalog/default bindings connected; full RGB runtime and remaining effects unverified; no physical DMA/PWM execution"},
        "rgb_indicators": {"target_hooks": ["rgb_matrix_indicators_user", "rgb_matrix_indicators_advanced_user"],
            "scope": "candidate RENDERING case and weak indicator delegation checked with controlled render/host/color inputs; whole effect engine and physical LEDs untested"},
        "space_cadet": {"target_hook": "process_record_user", "shared_candidate_helper": "perform_space_cadet",
            "vendor_keycodes": [f"0x{code:04X}" for code in range(0x7E01,0x7E0F)],
            "scope": "14 original argument triples, single upstream shared last/timer state with built-ins; selected module/KB and Space Cadet route only; timer/tapping term and HID/tap boundaries controlled, intervening features and full pipeline unverified"},
        "backspace_delete": {"keycode": "0x7E00", "selector_ram_original": "0x20001C40",
            "scope": "last raw Shift press/release edge, not held-modifier union; key reselected on release; captured register/unregister intents only, not HID/USB or full pre/post-gate pipeline"},
        "rgb_controls": {"keycodes": ["0x7E10", "0x7E11", "0x7E12", "0x7E13", "0x7E14", "0x7E15"],
            "target_hook": "process_record_user", "scope": "consume press/release before downstream core stages, byte XOR/force1/force0; no added EEPROM save; full pre-gate/post-event pipeline and persistence unverified"},
        "build_blockers": ["complete RGB runtime pipeline and remaining effects conformance",
            "destructive vendor reset", "Vial unlock/security and feature pipeline integration"],
        "flash_blockers": ["complete storage/stamp/reset/migration compatibility", "physical MCU/clock/recovery verification", "explicit hardware-test permission"]}
    dump = lambda value: json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    return {"keyboard.json": dump(keyboard), "config.h": config,
        "rules.mk": "# SPDX-License-Identifier: GPL-2.0-or-later\n$(error ORIGINAL_TARGET_INCOMPLETE: RGB, vendor handlers and Vial security pending; no partial-image override)\nEEPROM_DRIVER = wear_leveling\nWEAR_LEVELING_DRIVER = embedded_flash\nSPACE_CADET_ENABLE = yes\nRGB_MATRIX_ENABLE = yes\nRGB_MATRIX_DRIVER = ws2812\nWS2812_DRIVER = pwm\n",
        "keymaps/vial/keymap.c": keymap,
        "keymaps/vial/rules.mk": "# SPDX-License-Identifier: GPL-2.0-or-later\nVIA_ENABLE = yes\nVIAL_ENABLE = yes\nQMK_SETTINGS = yes\nVIALRGB_ENABLE = yes\n",
        "keymaps/vial/vial.json": dump(definition), "target-evidence.json": dump(manifest), **startup_artifacts(evidence), **rgb_artifacts(evidence)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--export", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    validate_reference(args.reference_dir)
    files = artifacts(args.uf2.read_bytes())
    if args.export:
        args.export.mkdir(parents=True, exist_ok=False)
        for relative, content in files.items():
            path = args.export / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        print(f"Exported {len(files)} target seed files; BUILD BLOCKED, NOT firmware")
    else:
        for relative, content in files.items():
            if (args.check / relative).read_text() != content:
                raise ValueError(f"Changed target seed: {relative}")
        print(f"Verified {len(files)} target seed files; BUILD BLOCKED, NOT firmware")


if __name__ == "__main__":
    main()
