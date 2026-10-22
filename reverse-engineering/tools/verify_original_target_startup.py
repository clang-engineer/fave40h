#!/usr/bin/env python3
"""Actual pinned board.c on RAM GPIO + real clock-header constant probe.

RCC/clock callbacks are intercepted. No physical GPIO or clock procedure runs.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from prepare_original_target import artifacts, validate_reference
from recover_original_vial import PAYLOAD_SHA256, recover

CHIBIOS = "8bd61b804303f1614d574546c2dd735eeabb09f5"
CONTRIB = "3ac181e4ca5cafddaf8b472baa1d09c2b24c77b6"
BOARD = "os/hal/boards/ST_NUCLEO64_F411RE"
HAL = "os/hal/ports/STM32/STM32F4xx"
GPIO = "os/hal/ports/STM32/LLD/GPIOv2"
VENDOR = "os/common/ext/ST/STM32F4xx/stm32f411xe.h"
HASHES = {
    f"{BOARD}/board.h": "ac71dd6edc546d1422bc060012295ff1e55b9ba69e590d9dc5105415c930f450",
    f"{BOARD}/board.c": "673db32fe39b2539f29a16fc75c891f3241d0c25bce00fc1ba4473f7c2db0b63",
    f"{HAL}/hal_lld.h": "356f23ec42fec779bc30927ab2e15600e124bdc551b8925088700fd5d06a47ea",
    f"{HAL}/hal_lld.c": "dcb361a4a541d634ad76cb36d6df78adf0acacc9117f7aeed8eebdca57ff6a24",
    f"{HAL}/hal_lld_type1.h": "10b195e70c021843769df9be7140a6f23aa5e79164f04b1ee570e4504ecfeb47",
    f"{HAL}/stm32_registry.h": "d048572b2cb99f77f1574c09f8f01accf98df085e0543f046a58fbfa543fc224",
    f"{GPIO}/stm32_gpio.h": "f86ebec2b7b59430a35a214fc1398fe0987e39d7eb6c1ee1f8eaff37482967ff",
    VENDOR: "4b9a2c3270ddd130ccf39d4d70490088b942c15ecf85abcedd789153c9e1e99e",
}
FIELDS = ["MODER", "OTYPER", "OSPEEDR", "PUPDR", "IDR", "ODR", "BSRR.W", "LOCKR", "AFRL", "AFRH"]


def validate_startup_reference(directory):
    validate_reference(directory)
    for relative, revision in (("lib/chibios", CHIBIOS), ("lib/chibios-contrib", CONTRIB)):
        actual = subprocess.check_output(["git", "-C", str(directory / relative), "rev-parse", "HEAD"], text=True).strip()
        if actual != revision:
            raise ValueError(f"Wrong startup submodule: {relative}")
    chibios = directory / "lib/chibios"
    for relative, digest in HASHES.items():
        if hashlib.sha256((chibios / relative).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Changed startup reference: {relative}")
    return chibios


def prepare_probe(temp, target, reference, chibios):
    # Keep board.c, the GPIO type/registry and clock constants unmodified.
    (temp / "candidate_board.c").write_bytes((chibios / BOARD / "board.c").read_bytes())
    (temp / "hal_lld.h").write_bytes((chibios / HAL / "hal_lld.h").read_bytes())
    for helper in ("nvic.h", "cache.h", "mpu_v7m.h", "stm32_isr.h", "stm32_dma.h", "stm32_exti.h", "stm32_rcc.h", "stm32_tim.h"):
        (temp / helper).write_text("// Unused hardware helper suppressed for constant/RAM-only probe.\n")
    vendor = (chibios / VENDOR).read_text()
    bits = re.findall(r"^#define RCC_AHB1ENR_GPIO[ABCDEH]EN(?:_Pos|_Msk)?\s+[^\n]+", vendor, flags=re.M)
    if len(bits) != 18:
        raise ValueError("Unmodeled vendor GPIO clock-mask definitions")
    (temp / "gpio_bits.h").write_text("\n".join(bits) + "\n")
    bases = "\n".join(f"#define GPIO{port}_BASE ((uintptr_t)&probe_ports[{index}].regs)" for index, port in enumerate("ABCDEH"))
    (temp / "hal.h").write_text('''#pragma once
#include <stdint.h>
#include <stdbool.h>
#define TRUE 1
#define FALSE 0
// Only the CMSIS variant-selection alias is supplied; no real CMSIS MMIO base.
#define STM32F411xx
#include <board.h>
#include <mcuconf.h>
#include <stm32_registry.h>
#include "gpio_bits.h"
#include <stm32_gpio.h>
struct guarded_gpio { uint32_t before; stm32_gpio_t regs; uint32_t after; };
extern struct guarded_gpio probe_ports[6];
''' + bases + '''
#define HAL_USE_SDC FALSE
#define HAL_USE_MMC_SPI FALSE
void rccResetAHB1(uint32_t mask);
void rccEnableAHB1(uint32_t mask, bool low_power);
void stm32_clock_init(void);
''')
    driver = (chibios / HAL / "hal_lld.c").read_text()
    pll = next(e for e in re.findall(r"RCC->PLLCFGR\s*=\s*(.*?);", driver, re.S) if "STM32_PLLQ" in e)
    cfgr = next(e for e in re.findall(r"RCC->CFGR\s*=\s*(.*?);", driver, re.S) if "STM32_MCO2PRE" in e)
    initialize = "\n".join(f"probe_ports[p].regs.{field} = 0xA5A5A5A5u;" for field in FIELDS)
    snapshot = "\n".join(f"probe_clock_snapshot[p*10+{i}] = probe_ports[p].regs.{field};" for i, field in enumerate(FIELDS))
    (temp / "probe.c").write_text('''#include "hal.h"
#include "hal_lld.h"
#ifdef STM32_HSE_BYPASS
#error Original startup does not use HSE bypass
#endif
#include "candidate_board.c"
_Static_assert(sizeof(stm32_gpio_t) == 40, "GPIO type layout");
_Static_assert(sizeof(struct guarded_gpio) == 48, "GPIO guards layout");
struct guarded_gpio probe_ports[6];
uint32_t probe_events[9], probe_event_count, probe_clock_snapshot[60];
static void event(uint32_t kind, uint32_t mask, uint32_t argument) {
    if (probe_event_count < 3) {
        probe_events[probe_event_count*3] = kind;
        probe_events[probe_event_count*3+1] = mask;
        probe_events[probe_event_count*3+2] = argument;
    }
    ++probe_event_count;
}
void rccResetAHB1(uint32_t mask) { event(1, mask, 0); }
void rccEnableAHB1(uint32_t mask, bool low_power) { event(2, mask, low_power); }
void stm32_clock_init(void) {
    event(3, 0, 0);
    for (unsigned p = 0; p < 6; ++p) {
''' + snapshot + '''
    }
}
void probe_run(void) {
    probe_event_count = 0;
    for (unsigned p = 0; p < 6; ++p) {
        probe_ports[p].before = probe_ports[p].after = 0xA5A5A5A5u;
''' + initialize + '''
    }
    __early_init();
}
const uint32_t probe_clock_words[] = {
''' + pll + ",\n" + cfgr + ''',
STM32_SYSCLK, STM32_PLL48CLK, STM32_PCLK1, STM32_PCLK2, STM32_HCLK, STM32_GPIO_EN_MASK
};
''')
    return ["-I", str(temp), "-I", str(target.resolve()), "-I", str(chibios / BOARD), "-I", str(reference / "platforms/chibios/boards/GENERIC_STM32_F411XE/configs"), "-I", str(chibios / HAL), "-I", str(chibios / GPIO)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, default=Path(__file__).resolve().parents[1] / "tests/fixtures/original-vial-emulation.json")
    parser.add_argument("--arm-object", type=Path)
    args = parser.parse_args()
    chibios = validate_startup_reference(args.reference_dir)
    raw = args.uf2.read_bytes()
    for relative, content in artifacts(raw).items():
        if (args.target / relative).read_text() != content:
            raise ValueError(f"Changed target: {relative}")
    evidence, _ = recover(raw)
    oracle = json.loads(args.oracle.read_text())
    if oracle["payload_sha256"] != PAYLOAD_SHA256 or len(oracle["gpio_startup_writes"]) != 6:
        raise ValueError("Wrong original GPIO oracle")
    cc = shutil.which("cc")
    if not cc:
        raise RuntimeError("Host C compiler required; no installation attempted")
    with tempfile.TemporaryDirectory(prefix="fave40h-startup-probe-") as directory:
        temp = Path(directory)
        includes = prepare_probe(temp, args.target, args.reference_dir, chibios)
        library = temp / ("startup.dylib" if sys.platform == "darwin" else "startup.so")
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
        subprocess.run([cc, *flags, "-shared", "-fPIC", *includes, str(temp / "probe.c"), "-o", str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.probe_run()
        events = list((ctypes.c_uint32 * 9).in_dll(lib, "probe_events"))
        if ctypes.c_uint32.in_dll(lib, "probe_event_count").value != 3 or events != [1,159,0,2,159,1,3,0,0]:
            raise AssertionError("RCC reset/enable/clock-call boundary changed")
        ports = list((ctypes.c_uint32 * 72).in_dll(lib, "probe_ports"))
        snapshot = list((ctypes.c_uint32 * 60).in_dll(lib, "probe_clock_snapshot"))
        for i, row in enumerate(oracle["gpio_startup_writes"]):
            if row["port"] != "ABCDEH"[i] or ports[i*12] != 0xA5A5A5A5 or ports[i*12+11] != 0xA5A5A5A5:
                raise AssertionError("GPIO port/guards changed")
            if ports[i*12+1:i*12+11] != row["register_words"] or snapshot[i*10:i*10+10] != row["register_words"]:
                raise AssertionError("GPIO original-Thumb / pre-clock RAM state mismatch")
        clocks = list((ctypes.c_uint32 * 8).in_dll(lib, "probe_clock_words"))
        expected = [int(evidence["board"]["pllcfgr"],16), int(evidence["board"]["cfgr"],16), 48000000,48000000,24000000,48000000,48000000,159]
        if clocks != expected:
            raise AssertionError(f"Original clock profile mismatch: {clocks}")
        if args.arm_object:
            clang = shutil.which("clang")
            if not clang:
                raise RuntimeError("Clang required; no installation attempted")
            obj = temp / "startup.o"
            subprocess.run([clang, "--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-ffreestanding", *flags, *includes, "-c", str(temp / "probe.c"), "-o", str(obj)], check=True)
            with args.arm_object.open("xb") as output:
                output.write(obj.read_bytes())
    print(json.dumps({"gpio_banks": 6, "gpio_written_registers": 42, "gpio_words_checked": 60,
        "clock_register_words": clocks[:2], "system_clock_hz_conditional_on_16mhz_hse": clocks[2],
        "physical_clock_measured": False, "clock_procedure_executed": False,
        "full_firmware": False, "arm_startup_probe_object": str(args.arm_object) if args.arm_object else None,
        "sentinel": "ORIGINAL_TARGET_STARTUP_PROBE_COMPLETE"}, indent=2))


if __name__ == "__main__":
    main()
