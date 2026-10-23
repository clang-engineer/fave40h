#!/usr/bin/env python3
"""Persistent mode29 -> Caps/group filter -> GRB at controlled RAM/API joins.

No complete renderer caller, flags-change clear, task/flush/DMA/HAL or device test.
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

from audit_original_rgb_mode15_staging import GROUPS, inspect_staging, stage_program
from audit_original_rgb_mode29_frames import frame_program
from audit_original_rgb_hsv import original_hsv_profile
from audit_original_rgb_mode29 import PAYLOAD_SHA, ROOT, inspect_mode29_image
from audit_original_rgb_profile import audit_target
from prepare_original_target import REVISION, REFERENCE_HASHES, artifacts, validate_reference
from recover_original_vial import parse_uf2, recover


def inspect_all_staging(image):
    inspect_staging(image)
    for address, expected in ((0x08012FC8, "00f09cb9"),
                              (0x08013304, "70b5134605460e4600242046324629460134fff7e9ff482cf7d170bd")):
        if image.read(address, len(expected) // 2).hex() != expected:
            raise ValueError("Changed original all-LED RAM setter/thunk")


def validate_oracle(oracle):
    sequences = oracle["rgb_mode29_staging"]
    expected = set(itertools.product((0, 128, 255), (0, 65535), (0, 2), GROUPS))
    actual = {(s["speed"], s["initial_seed"], s["caps"], (s["group_word"] & 255, (s["group_word"] >> 8) & 255)) for s in sequences}
    if oracle["payload_sha256"] != PAYLOAD_SHA or len(sequences) != 72 or actual != expected:
        raise ValueError("Incomplete mode29 staging grid")
    old = json.loads((ROOT / "tests/fixtures/original-rgb-mode29-frames-real-hsv.json").read_text())["rgb_mode29_frames"]
    old = {(s["speed"], s["initial_seed"]): s for s in old}
    for seq in sequences:
        previous = old[seq["speed"], seq["initial_seed"]]
        if (seq["value"] != previous["value"] or seq["group_word"] >> 16 != 0xA5B6 or len(seq["steps"]) != 16 or
                bytes.fromhex(seq["initial_grb_hex"]) != bytes((i * 73 + 19) & 255 for i in range(216))):
            raise ValueError("Changed mode29 staging sequence context")
        for row, prior in zip(seq["steps"], previous["steps"]):
            if any(row[k] != v for k, v in prior.items()):
                raise ValueError("Changed independent original effect/cache/wait trace")
            if (row["caps_white_calls"] != int(not row["rendering"] and seq["caps"] == 2) or
                    any(len(bytes.fromhex(row[k])) != 216 for k in ("effect_grb_hex", "post_grb_hex"))):
                raise ValueError("Changed mode29 post-effect snapshot/completion context")
    return sequences


def configure_effect(lib, seq, curve):
    lib.probe_init.argtypes = [ctypes.c_uint16, ctypes.c_uint8, ctypes.c_uint8]
    lib.probe_init.restype = None
    lib.probe_step.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_bool, ctypes.c_uint32]
    lib.probe_step.restype = ctypes.c_bool
    lib.probe_seed.restype = ctypes.c_uint16
    lib.probe_trace.restype = ctypes.POINTER(ctypes.c_uint32)
    lib.probe_trace_len.restype = lib.probe_overflow.restype = ctypes.c_uint32
    lib.probe_cie_curve.restype = ctypes.POINTER(ctypes.c_uint8)
    if bytes(lib.probe_cie_curve()[:256]) != curve:
        raise AssertionError("Native CIE table differs from original")
    lib.probe_init(seq["initial_seed"], seq["speed"], seq["value"])


def configure_stage(stage):
    stage.stage_seed.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32, ctypes.c_uint8]
    stage.stage_seed.restype = None
    stage.stage_rgb.argtypes = [ctypes.c_int, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8]
    stage.stage_rgb.restype = None
    stage.stage_all.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8]
    stage.stage_all.restype = None
    stage.stage_post.argtypes = [ctypes.c_uint8, ctypes.c_bool, ctypes.c_uint8]
    stage.stage_post.restype = None
    stage.stage_grb.restype = ctypes.POINTER(ctypes.c_uint8)
    stage.stage_white.restype = stage.stage_group.restype = stage.stage_unexpected_io.restype = ctypes.c_uint32


def compare_sequence(effect, stage, seq, negative):
    initial = bytes.fromhex(seq["initial_grb_hex"])
    stage.stage_seed((ctypes.c_uint8 * 216).from_buffer_copy(initial), seq["group_word"], seq["caps"])
    differences = 0
    for row in seq["steps"]:
        rendering = effect.probe_step(row["iter"], row["flags"], row["init"], row["now"])
        length, data = effect.probe_trace_len(), effect.probe_trace()
        if effect.probe_overflow() or length > 2048:
            raise AssertionError("Effect trace escaped owned buffer")
        trace, offset = [], 0
        while offset < length:
            kind = data[offset]
            if kind not in (0, 1, 2) or offset + (4, 5, 7)[kind] > length:
                raise AssertionError("Malformed effect record")
            size = (4, 5, 7)[kind]
            event = list(data[offset:offset + size]); trace.append(event); offset += size
            if kind == 2:
                continue
            rgb = event[1:] if kind == 0 else event[2:]
            if any(not 0 <= c <= 255 for c in rgb) or (kind == 1 and not 0 <= event[1] < 72):
                raise AssertionError("Effect output escaped bounded staging API")
            r, g, b = rgb
            channels = (g, r, b) if negative == 3 else (r, g, b)
            if kind == 0:
                stage.stage_all(*channels)
            else:
                stage.stage_rgb(event[1], *channels)
        before = bytes(stage.stage_grb()[:216])
        stage.stage_post(row["iter"], not rendering, negative if negative in (1, 2) else 0)
        after = bytes(stage.stage_grb()[:216])
        if stage.stage_group() != seq["group_word"] or stage.stage_unexpected_io():
            raise AssertionError("Post pass changed group or requested EEPROM/HID/timer/DMA IO")
        differences += (trace != row["trace"] or rendering != row["rendering"] or effect.probe_seed() != row["seed_after"] or
                        before.hex() != row["effect_grb_hex"] or after.hex() != row["post_grb_hex"] or
                        stage.stage_white() != row["caps_white_calls"])
    return differences


def audit(raw, reference, target):
    recover(raw); validate_reference(reference)
    image = parse_uf2(raw); inspect_mode29_image(image); inspect_all_staging(image)
    expected_target = artifacts(raw)
    target_inputs = {name: (target / name).read_bytes() for name in expected_target}
    if any(content.decode() != expected_target[name] for name, content in target_inputs.items()):
        raise ValueError("Changed generated target")
    profile = audit_target(raw, reference, target)
    oracle = json.loads((ROOT / "tests/fixtures/original-rgb-mode29-staging.json").read_text())
    sequences = validate_oracle(oracle)
    curve = original_hsv_profile(raw)
    gcc = next((shutil.which(n) for n in ("gcc-16", "gcc-15", "gcc-14", "gcc-13") if shutil.which(n)), None)
    clang = shutil.which("clang")
    if not gcc or not clang:
        raise RuntimeError("Existing GNU/Clang host compilers required; nothing installed")
    with tempfile.TemporaryDirectory(prefix="fave40h-mode29-staging-") as directory:
        temp = Path(directory); fx, st = temp / "effect", temp / "stage"; fx.mkdir(); st.mkdir()
        effect_source, hashes = frame_program(reference, fx, list(image.read(0x0801DF60, 72)), True)
        stage_source = stage_program(st, reference, target)
        stage_source.write_text(stage_source.read_text() + '\nSTAGE_API void stage_all(uint8_t r,uint8_t g,uint8_t b) { ws2812_set_color_all(r,g,b); }\n')
        differences = {}
        for tag, opt in (("base", "-O0"), ("optimized", "-O2")):
            stage_lib = st / (tag + ".so")
            subprocess.run([clang, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-error=initializer-overrides",
                            "-Wno-error=unused-parameter", opt, "-fvisibility=hidden", "-shared", "-fPIC",
                            "-I", str(st), "-I", str(st / "platform_headers"), "-I", str(reference / "drivers/led"),
                            str(stage_source), "-o", str(stage_lib)], check=True)
            stage = ctypes.CDLL(str(stage_lib)); configure_stage(stage)
            profiles = [(tag, 0)] + ([("missing_post", 1), ("early_basic", 2), ("swapped_red_green", 3)] if tag == "base" else [])
            for label, negative in profiles:
                count = 0
                for index, seq in enumerate(sequences):
                    # Fresh separately compiled hidden library per sequence AND
                    # counterfactual; function-local cache/wait cannot leak.
                    output = fx / f"{label}-{index}.so"
                    subprocess.run([gcc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", opt, "-fvisibility=hidden", "-shared", "-fPIC",
                                    "-DUSE_CIE1931_CURVE", "-DFASTLED_SCALE8_FIXED=1", "-DFASTLED_BLEND_FIXED=1", "-DRGB_MATRIX_LED_PROCESS_LIMIT=15",
                                    "-I", str(fx), str(effect_source), str(fx / "color.c"), str(fx / "led_tables.c"), "-o", str(output)], check=True)
                    effect = ctypes.CDLL(str(output)); configure_effect(effect, seq, curve)
                    count += compare_sequence(effect, stage, seq, negative)
                differences[label] = count
        if differences != {"base": 0, "optimized": 0, "missing_post": 684, "early_basic": 456, "swapped_red_green": 1100}:
            raise AssertionError(f"Mode29 staging differential failed: {differences}")
    if any((target / name).read_bytes() != content for name, content in target_inputs.items()):
        raise ValueError("Target changed during verification")
    return {"candidate_revision": REVISION, "effect_source_sha256": hashes, "stage_reference_sha256": REFERENCE_HASHES,
            "profile_source_sha256": profile["source_sha256"],
            "target_profile": profile["target_profile"],
            "target_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in target_inputs.items()},
            "probe_builder_sha256": {name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest() for name in
                                     ("audit_original_rgb_mode29_staging.py", "audit_original_rgb_mode29_frames.py", "audit_original_rgb_mode15_staging.py", "verify_original_target_rgb.py", "EmulateOriginalVial.java")},
            "persistent_sequences_matched": 72, "calls_matched": 1152, "optimized_calls_matched": 1152,
            "before_after_grb_snapshots_per_profile": 2304, "negative_differences": differences,
            "actual_original_hsv_calls_in_fixture": sum(row["original_hsv_calls"] for seq in sequences for row in seq["steps"]),
            "compiled_cie_bytes_matched": 256, "native_io_requests": 0,
            "native_private_cache_bytes_directly_compared": False, "native_private_wait_directly_compared": False,
            "original_thumb_executed_by_this_command": False, "target_changes_applied": False,
            "scope": "actual original selected mode29 effect/single/all RAM stores then separately entered post-effect slice; independently compiled native PixelFlow/HSV records joined to SDK staging and actual delegates/target hooks using completion-only renderer stub. Private native cache/wait observed indirectly. Not complete renderer caller/start/sync/flags-change-clear/scan/clock/task/flush/DMA/HAL/device or provenance",
            "sentinel": "ORIGINAL_RGB_MODE29_STAGING_AUDIT_COMPLETE"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("uf2", type=Path)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.uf2.read_bytes(), args.reference_dir, args.target), indent=2))
