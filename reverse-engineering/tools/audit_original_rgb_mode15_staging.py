#!/usr/bin/env python3
"""Mode15 -> Caps/group-filter -> GRB at explicit RAM/API composition boundaries.

Not a whole renderer caller, Make/QMK/HAL build, flush/DMA or device test.
"""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit_original_rgb_mode15 import program as effect_program
from audit_original_rgb_profile import audit_target
from audit_original_rgb_mode29 import ROOT, PAYLOAD_SHA
from prepare_original_target import REVISION, REFERENCE_HASHES, artifacts, validate_reference
from recover_original_vial import recover, parse_uf2
from verify_original_target_rgb import prepare_probe

GROUPS = ((0, 0), (0, 1), (1, 0), (1, 1), (2, 255), (255, 2))


def inspect_staging(image):
    for address, expected in ((0x080132EC, "30b5044d00eb40002c182a546170a37030bd00bf"),
                              (0x08013300, "64500020"), (0x08014A78, "fef738bc")):
        if image.read(address, len(expected) // 2).hex() != expected:
            raise ValueError("Changed original RGB RAM setter/literal/wrapper")


def stage_program(temp, reference, target):
    source = prepare_probe(temp, reference, target)
    source.write_text(source.read_text() + '''
#define STAGE_API __attribute__((visibility("default")))
STAGE_API void stage_seed(const uint8_t *grb,uint32_t group,uint8_t caps) {
    for(int i=0;i<72;i++) ws2812_set_color(i,grb[i*3+1],grb[i*3],grb[i*3+2]);
    original_rgb_group_state=group; probe_caps=caps;
}
STAGE_API void stage_rgb(int i,uint8_t r,uint8_t g,uint8_t b) { rgb_matrix_set_color(i,r,g,b); }
STAGE_API void stage_post(uint8_t iter,bool complete,uint8_t negative) {
    probe_white_calls=0;
    if(negative==1) return; // Deliberate missing-post-pass counterfactual.
    if(negative==2 && !complete) rgb_matrix_indicators(); // Deliberate early basic Caps.
    probe_render_chunk(iter,complete);
}
STAGE_API const uint8_t *stage_grb(void) { return (const uint8_t *)ws2812_leds; }
STAGE_API uint32_t stage_white(void) { return probe_white_calls; }
STAGE_API uint32_t stage_group(void) { return original_rgb_group_state; }
STAGE_API uint32_t stage_unexpected_io(void) {
    uint32_t result=probe_cadet_reads;
    for(unsigned i=0;i<25;i++) result|=probe_requests[i];
    for(unsigned i=0;i<10;i++) result|=probe_group_io[i];
    for(unsigned i=0;i<5;i++) result|=probe_hid[i];
    for(unsigned i=0;i<9;i++) result|=probe_cadet_trace[i];
    return result;
}
''')
    return source


def configure(effect, stage, led_map):
    effect.probe_map.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
    effect.probe_map((ctypes.c_uint8 * 264).from_buffer_copy(led_map))
    effect.probe_step.argtypes = [ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_bool]
    effect.probe_step.restype = ctypes.c_bool
    effect.probe_trace.restype = ctypes.POINTER(ctypes.c_uint32)
    effect.probe_length.restype = ctypes.c_uint32
    stage.stage_seed.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32, ctypes.c_uint8]
    stage.stage_seed.restype = None
    stage.stage_rgb.argtypes = [ctypes.c_int, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8]
    stage.stage_rgb.restype = None
    stage.stage_post.argtypes = [ctypes.c_uint8, ctypes.c_bool, ctypes.c_uint8]
    stage.stage_post.restype = None
    stage.stage_grb.restype = ctypes.POINTER(ctypes.c_uint8)
    stage.stage_white.restype = stage.stage_group.restype = stage.stage_unexpected_io.restype = ctypes.c_uint32


def compare(effect, stage, sequences, negative=0):
    differences = 0
    for seq in sequences:
        initial = bytes.fromhex(seq["initial_grb_hex"])
        stage.stage_seed((ctypes.c_uint8 * 216).from_buffer_copy(initial), seq["group_word"], seq["caps"])
        for row in seq["steps"]:
            rendering = effect.probe_step(seq["speed"], seq["now"], seq["hsv"], seq["flags"], row["iter"], row["init"])
            data, length = effect.probe_trace(), effect.probe_length()
            if length > 2048 or length % 12:
                raise AssertionError("Unmodeled composed effect trace length")
            trace = []
            for start in range(0, length, 12):
                if data[start] != 2 or data[start+7] != 1:
                    raise AssertionError("Unmodeled composed HSV/RGB pair")
                hsv, rgb = list(data[start:start+7]), list(data[start+7:start+12])
                trace.extend([hsv, rgb])
                _, index, r, g, b = rgb
                if not (0 <= index < 72 and all(0 <= channel <= 255 for channel in (r, g, b))):
                    raise AssertionError("Effect output escaped bounded RGB staging API")
                stage.stage_rgb(index, g if negative == 3 else r, r if negative == 3 else g, b)
            after_effect = bytes(stage.stage_grb()[:216])
            # API-boundary join: effect already ran independently; actual SDK
            # RENDERING/weak delegates/target hooks consume its completion value.
            stage.stage_post(row["iter"], not rendering, negative if negative in (1, 2) else 0)
            after_post = bytes(stage.stage_grb()[:216])
            if stage.stage_group() != seq["group_word"] or stage.stage_unexpected_io():
                raise AssertionError("Composition changed group bytes or requested EEPROM/HID/timer/DMA IO")
            mismatch = (trace != row["trace"] or rendering != row["rendering"] or
                        after_effect.hex() != row["effect_grb_hex"] or after_post.hex() != row["post_grb_hex"] or
                        stage.stage_white() != row["caps_white_calls"])
            differences += mismatch
    return differences


def validate_oracle(oracle):
    sequences = oracle["rgb_mode15_staging"]
    expected = set(itertools.product((0xFFFF00, 0x8080FF), (0, 256, 0xFFFFFFFF), (255, 4, 2, 0), (0, 2), GROUPS))
    actual = {(s["hsv"], s["now"], s["flags"], s["caps"], (s["group_word"] & 255, (s["group_word"] >> 8) & 255)) for s in sequences}
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(sequences) != 288 or actual != expected:
        raise ValueError("Incomplete mode15 staging oracle")
    for seq in sequences:
        if (seq["speed"] != 128 or seq["group_word"] >> 16 != 0xA5B6 or len(seq["steps"]) != 5 or
                bytes.fromhex(seq["initial_grb_hex"]) != bytes((i * 73 + 19) & 255 for i in range(216))):
            raise ValueError("Out-of-scope staging config/state")
        for i, row in enumerate(seq["steps"]):
            if row["iter"] != i or row["init"] != (i == 0) or any(row[k] != seq[k] for k in ("speed", "now", "hsv", "flags")):
                raise ValueError("Out-of-scope staging step")
            if (row["rendering"] != (i < 4) or row["caps_white_calls"] != int(i == 4 and seq["caps"] == 2) or
                    bytes.fromhex(row["params_after_hex"]) != bytes((i + 1, seq["flags"], int(i == 0)))):
                raise ValueError("Changed completion/indicator context")
            if len(bytes.fromhex(row["effect_grb_hex"])) != 216 or len(bytes.fromhex(row["post_grb_hex"])) != 216:
                raise ValueError("Incomplete GRB snapshot")
    return sequences


def audit(raw, reference, target):
    recover(raw); inspect_staging(parse_uf2(raw)); validate_reference(reference)
    target_inputs = {name: (target / name).read_bytes() for name in artifacts(raw)}
    for name, content in artifacts(raw).items():
        if target_inputs[name].decode() != content:
            raise ValueError("Changed generated target: " + name)
    profile = audit_target(raw, reference, target)
    oracle = json.loads((ROOT / "tests/fixtures/original-rgb-mode15-staging.json").read_text())
    sequences = validate_oracle(oracle)
    gcc = next((shutil.which(n) for n in ("gcc-16", "gcc-15", "gcc-14", "gcc-13") if shutil.which(n)), None)
    clang = shutil.which("clang")
    if not gcc or not clang:
        raise RuntimeError("Existing GNU and Clang host compilers required; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-mode15-staging-") as directory:
        temp = Path(directory)
        fx, st = temp / "effect", temp / "stage"
        fx.mkdir(); st.mkdir()
        effect_source, hashes = effect_program(reference, fx)
        stage_source = stage_program(st, reference, target)
        differences = {}
        for tag, opt in (("base", "-O0"), ("optimized", "-O2")):
            effect_lib, stage_lib = fx / (tag + ".so"), st / (tag + ".so")
            subprocess.run([gcc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt, "-fvisibility=hidden", "-shared", "-fPIC",
                            "-DUSE_CIE1931_CURVE", "-DFASTLED_SCALE8_FIXED=1", "-DFASTLED_BLEND_FIXED=1", "-DRGB_MATRIX_LED_PROCESS_LIMIT=15",
                            "-I", str(fx), str(effect_source), str(fx / "color.c"), str(fx / "led_tables.c"), "-o", str(effect_lib)], check=True)
            # The established PWM probe's two source-specific diagnostic classes
            # stay visible/nonfatal, not new blanket suppression or source patches.
            subprocess.run([clang, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-error=initializer-overrides",
                            "-Wno-error=unused-parameter", opt, "-fvisibility=hidden", "-shared", "-fPIC",
                            "-I", str(st), "-I", str(st / "platform_headers"), "-I", str(reference / "drivers/led"),
                            str(stage_source), "-o", str(stage_lib)], check=True)
            effect, stage = ctypes.CDLL(str(effect_lib)), ctypes.CDLL(str(stage_lib))
            configure(effect, stage, parse_uf2(raw).read(0x0801DEA0, 264))
            differences[tag] = compare(effect, stage, sequences)
            if tag == "base":
                for label, negative in (("missing_post", 1), ("early_basic", 2), ("swapped_red_green", 3)):
                    differences[label] = compare(effect, stage, sequences, negative)
        if differences != {"base": 0, "optimized": 0, "missing_post": 696, "early_basic": 720, "swapped_red_green": 888}:
            raise AssertionError(f"Mode15 staging differential failed: {differences}")
    if any((target / name).read_bytes() != content for name, content in target_inputs.items()):
        raise ValueError("Target inputs changed during composition audit")
    return {"candidate_revision": REVISION, "effect_source_sha256": hashes, "stage_reference_sha256": REFERENCE_HASHES,
            "target_profile": profile["target_profile"], "profile_source_sha256": profile["source_sha256"],
            "target_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in target_inputs.items()},
            "probe_builder_sha256": {name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest() for name in
                                     ("audit_original_rgb_mode15.py", "verify_original_target_rgb.py", "audit_original_rgb_mode15_staging.py", "EmulateOriginalVial.java")},
            "persistent_sequences_matched": 288, "chunks_matched": 1440, "optimized_chunks_matched": 1440,
            "negative_differences": differences, "actual_original_rgb_setter_in_fixture": True,
            "actual_original_hsv_calls_in_fixture": sum(len(row["trace"]) // 2 for seq in sequences for row in seq["steps"]),
            "before_after_grb_snapshots_per_profile": 2880,
            "original_thumb_executed_by_this_command": False,
            "native_io_requests": 0, "target_changes_applied": False, "whole_renderer_caller_executed": False,
            "scope": "explicit API composition: independent actual Chevron/runner/HSV records feed actual SDK WS2812 staging API through established nonsplit color adapter; actual SDK RENDERING case uses completion-only render stub then weak delegates/target Caps/filter. Original executes selected effect+RAM setter, separately entered post-effect slice with supplied register context. Persistent216-byte before/after snapshots, not complete renderer/start/sync/flags-change-clear/scan/flush/DMA/clock/HAL/physical output or source provenance",
            "sentinel": "ORIGINAL_RGB_MODE15_STAGING_AUDIT_COMPLETE"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir, args.target), indent=2))
