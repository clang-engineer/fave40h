# Original-four-layer target — seed only, build blocked

This is the separate target selected for `firmware/origin/FAve40H_VIAL.uf2`.
It does **not** reuse the historical `../fave40h` six-layer port. It is not yet a
complete QMK target, linked firmware or flashable artifact.

## Assembled in this increment

- USB VID/PID `5123:A02D`, device BCD `0100`, observed manufacturer/product;
  matrix rows/columns and ROW2COL direction from the original binary.
- QMK layout metadata projected from option 0 of the embedded definition:
  42 keys, also checked against the original switch-LED matrix positions.
  This projection does not set EEPROM layout options. `keymaps/vial/vial.json`
  retains the **entire original definition**, both layout alternatives and all
  22 custom descriptions.
- Exactly **three compiled factory layers**, including all 48 matrix cells per
  layer, and **four dynamic layers**. No invented fourth compiled layer.
- Original UID, explicit 4096/8192-byte storage and first-sector-3 profile,
  16/16/16/32 dynamic record counts, and `TAP_CODE_DELAY=0`.

The pinned experimental Vial-QMK base is
`dd43959ae5c08d8a28d38a1acf7b04e86b14a344`. Its `builddefs/build_vial.mk`
**hardcodes** the same serial literal `vial:f64c2b3c`; the suffix is not evidence
of the manufacturer's Git revision. Critical reference file hashes are recorded
in `target-evidence.json` and checked before export/probing.

The candidate TinyUF2 profile places the application at `0x08010000` and its
request word at `0x2000FFFC`, matching the original's `0xF01669EF` request.
This does **not** identify the installed low-flash bootloader, physical MCU,
oscillator or capacity, nor prove real recovery works.

## Startup overrides and bounded validation

`board.h` wraps the pinned ChibiOS board header, replacing all **42 register
constants for GPIO A/B/C/D/E/H**, removing the inherited Nucleo HSE-bypass
setting and specifying inferred HSE 16 MHz. The original clears HSEBYP before
enabling HSE (`0x0801B0C4..0x0801B0D6`); bypass is not an arbitrary board choice.
`mcuconf.h` supplies original PLL M/N/P/Q = **16/192/4/4** and CFGR selections.
The default-board VDD limit constant remains a software assumption, not a
measurement of this PCB's supply.

`verify_original_target_startup.py` requires the exact ChibiOS and Contrib
revisions recorded in the reconstruction README and hashes eight critical
ChibiOS files. It executes the **unmodified upstream board initializer** with
GPIO bases redirected to guarded RAM, using the actual GPIOv2 type and MCU
registry. All 60 GPIO words (42 written + 18 untouched) match six new bounded
original-Thumb writer cases. A snapshot at the intercepted clock call verifies
GPIO is initialized first. RCC reset/enable calls are intercepted and their
`0x9F` masks recorded; no physical RCC operation is performed.

The real HAL clock headers and register-assignment expressions compute
`PLLCFGR=0x04413010` and pre-switch `CFGR=0x38881000`. With inferred HSE 16 MHz,
SYSCLK/USB are 48 MHz, APB1 is 24 MHz and APB2 is 48 MHz. The clock procedure,
ready-bit waits, flash/PWR handling and physical frequencies are **not executed
or fully validated** by this probe. Hardware-helper headers are suppressed;
this is not a full HAL or firmware build. A strict Cortex-M4 probe object checks
these header/initializer interfaces, not actual peripheral behavior.

## RGB transport and LED table

The target enables the pinned **unmodified `ws2812_pwm.c`** via
`RGB_MATRIX_DRIVER = ws2812` / `WS2812_DRIVER = pwm`, with VialRGB enabled.
`halconf.h` enables PWM; `mcuconf.h` enables TIM2 PWM and selects **TIM5 for the
system timer**, avoiding the candidate generic board's conflicting TIM2 default.
Original IRQ50 vector `0x08010108 -> 0x0801B57D`, the handler at `0x0801B57C`
and its `0x0801B630 -> 0x40000C00` literal support TIM5. This is static inspection,
not execution of the interrupt handler or scheduler.

Explicit transport settings select **PB10/AF1, TIM2 CH3, DMA1 stream1/channel3**,
GRB, 1250ns period, 350/900ns requested high times and 280us reset. With the
conditional 48MHz CPU clock, the actual upstream integer expressions yield
24MHz ticks, period30, high8/21, 1728 color + 224 reset = **1952 32-bit words**,
and circular DMA CR `0x06035540`.

`fave40h_original.c` supplies `g_led_config`: all **264 bytes** match the original
ROM table at `0x0801DEA0`, including matrix holes, 72 positions and 42 keylight /
30 underglow flags. The verifier compiles this target source with the exact two
packed LED type declarations extracted from the hash-checked reference.

`verify_original_target_rgb.py` compiles and executes the whole unmodified PWM
source against **controlled hardware-API shims**, with ordinary RAM timer/stream
objects. It verifies nine captured initialization requests, initial black/reset
buffer, color staging and all **51 existing original-Thumb encoder cases**,
including unchanged reset tail and the upstream unused extra buffer word.
GPIO mode and DMA register bits in this harness are explicit shims, not executed
ChibiOS helpers or validation of their ABI. CPU_CLOCK is a conditional 48MHz
shim, independently checked by the preceding startup/clock-header probe.

Native and Cortex-M4 probe compilation retain upstream warnings for the
intentional range-initializer override and unused upstream arguments (RGBW `w`
in RGB mode, weak advanced-module range parameters and weak LED-map arguments);
only those warning categories are nonfatal. No RGBW mode, driver-source patch,
physical GPIO/PWM/DMA/IRQ execution or full RGB animation engine is involved.
**RGB effect compatibility remains pending.** Group-key dispatch, Caps and
per-chunk filtering hooks are connected and checked as described below.

## Rendering chunks and Caps/filter composition

`RGB_MATRIX_LED_PROCESS_LIMIT` is explicitly pinned to **15**, matching the
original helper at `0x08014A7C`. Its normal spans are `[0,15)`, `[15,30)`,
`[30,45)`, `[45,60)`, `[60,72)`. The candidate's existing default also yields15;
this does not justify replacing chunk filtering with an assumed whole-frame pass.
All **256 uint8 inputs** match the unmodified candidate `rgb_matrix_get_limits()`
body/type extracted from the pinned source. Inputs beyond normal iter0..4 are
helper observations, not valid renderer spans or a new input-rejection policy.

Another **24 original-Thumb cases** execute the bounded active-effect Caps/filter
slice with controlled host LED reads and RGB setters, using original limits and
filter instructions. They cover iter0/1/4, both Caps states and both group bytes.
At final iter4/FLUSHING, LED22 is made white **before** filtering `[60,72)`;
therefore that white remains even with keylights disabled. At iter1, keylight
filtering covers LED22 and clears it. This observed composition must not be
silently changed into an all-LED post-filter. It is not a whole animation engine,
scheduler, HID or physical LED test.

The target now defines `rgb_matrix_indicators_user()` (Caps white LED22) and
`rgb_matrix_indicators_advanced_user()` (bytewise group enables and table flags).
The RGB verifier compiles the target callbacks with actual pinned effect/LED
parameter types, indicator functions, weak module/KB delegates and the exact
`RENDERING` case extracted from `rgb_matrix_task()`. Renderer completion and host
LED input are controlled; the nonsplit color boundary maps to the actual
candidate WS2812 staging API. It matches **all 25 existing original filter cases
and all 24 composed chunks**, including the final white-LED behavior. Rendering
does not alter the group word or request EEPROM IO. This is dispatcher/callback
composition verification, not execution of the animation engine or full QMK.

## RGB group-word lifecycle

The target's `eeconfig_init_user()` sets the RAM group word to **0x00000101**
then requests a user-word update. `keyboard_post_init_user()` loads the complete
user word verbatim, including non-boolean enable bytes and the upper two bytes.
The original user field is at logical **0x13**; reset writes keyboard word zero
at 0x0F first, then user word 0x101. The two low bytes control the two LED groups.

Thirteen bounded original-Thumb cases cover reset `0x0801441E..0x08014434`
(stopping before flush) and load `0x08018C84..0x08018C98` (a controlled complete
four-byte read into the original zeroed temporary). RAM and temporary guards are
checked. EEPROM callbacks are captured, not executed. Partial/failing reads,
whole reset, flush, migration and on-toggle persistence are outside this check.

The RGB verifier additionally copies the **actual pinned eeconfig.h**, and the
unmodified weak `eeconfig_init_kb()` / `keyboard_post_init_kb()` delegation bodies,
then calls them with the target's strong user hooks and captured RAM-only APIs.
It matches the original ordered keyboard/user write intents and raw word loads.
Using the user hook is significant: the candidate's default weak user initializer
would otherwise overwrite this field with zero. This checks these delegation
bodies, not the complete firmware initialization pipeline or NVM backend.

Lifecycle, indicator/filter and six group-key hooks are connected. RGB effect
compatibility, destructive reset and complete event handling remain pending.

## Six RGB group commands

The target `process_record_user()` consumes **0x7E10..0x7E15**, on both press and
release (`false` in QMK's continuation convention). Press performs byte XOR1,
force1 or force0 on group0/group1. Release does not change state. The other
byte and upper two bytes are preserved, including non-boolean values such as
255 toggling to254. Keys outside the implemented vendor branches return `true`
for later handlers (including the standard Space Cadet stage).

The RGB verifier uses exact candidate key position/event/tap/record declarations
under a controlled COMBO-enabled profile, the actual weak `process_record_kb()`
delegate and the exact `process_record_modules(...) && process_record_kb(...)`
prefix from `quantum.c`. Its module and later-stage sentinels are **shims**, not
execution of the complete feature chain or HID. The standard Space Cadet stage
now executes for surviving events; intervening feature stages are omitted. All **48 existing
original control cases** match; handled keys do not reach the later sentinel,
unrelated keys pass, and a blocked module prevents the user hook. Record bytes
and guards are unchanged. No original keyrecord byte-layout equivalence is
claimed by this selected-candidate API test.

The callback changes RAM only: no added EEPROM save and no immediate pixel
writes. This matches the observed bounded vendor cases, not proof of complete
original on-toggle persistence or all pre-/post-gate pipeline behavior.
Destructive reset, complete event handling and storage/migration safety remain pending.

## Shift-edge Backspace/Delete command

`process_record_user()` now tracks raw **0xE1/0xE5 press and release edges** in
one byte, while passing those Shift events onward. Command **0x7E00** consumes
both edges and requests `register_code` / `unregister_code` of Backspace0x2A
when the byte is zero, Delete0x4C otherwise. It checks the current byte again on
release, not a remembered press key. This deliberately preserves original quirks:
releasing either of two overlapping Shifts clears the selector even if the other
is still held; changing Shift during a held command can request Delete press
followed by Backspace release. Do not silently replace this with a modifier union
or a matched press/release latch.

All **eight original Shift-edge cases and eight Backspace/Delete cases** match
through the candidate weak KB/user gate with captured HID API intents, plus two
native compositions of those observed rules. Shift events reach the later-stage
sentinel; the command does not. Group word, EEPROM trace and record guards remain
unchanged. The exact register/unregister declarations come from pinned action.h,
but their bodies, USB reports and OS key behavior are **not executed or validated**.
These are not additional original-Thumb whole-pipeline cases.

## Shared Space Cadet custom keys

The target consumes **0x7E01..0x7E0E** by passing the recovered hold-modifier,
tap-modifier and tap-key triples to the candidate's `perform_space_cadet()`.
`SPACE_CADET_ENABLE = yes` is explicit (also the candidate default). No second
state machine is introduced: custom keys and the seven standard **0x7C18..0x7C1E**
keys use the same upstream private `sc_last` / `sc_timer`. Custom bracket/comma
arguments do **not** change the standard 9/0/Enter defaults.

The RGB/input verifier compiles **unmodified pinned process_space_cadet.c/.h**,
keycode/modifier headers, action_tapping.h and timer.h. It uses selected COMBO and
Vial tapping-term flags, with controlled timer/term values and captured modifier /
tap-code API intents. The actual weak KB/user prefix is followed by the actual
`process_space_cadet(keycode, record)` call from quantum.c. **Intervening feature
processors are omitted**; this is not the complete `process_record_quantum()`.
The verifier accesses private state only by same-translation-unit probe helpers;
production source does not expose or duplicate that state.

**196 custom +98 standard +16 core-default +14 vendor-bypass original cases**
match state, timer reads, intent order and selected-gate routing. This preserves
the strict `< tapping_term` threshold, 16-bit wrap, last-key shared state, no
release-time clear and normal pressed-key interruption. Consumed RGB/BSDL keys
do not incorrectly run the standard default reset. Three additional native
compositions cover custom↔standard shared state and normal-key interruption;
they are not new original-Thumb whole-pipeline cases. Record/guard, group-byte,
EEPROM and pixel invariants also hold. Unit tests separately capture the exact
14 user→helper argument triples; they do not substitute for this SDK probe.

No real timer, tap_code body/sleep, modifier-report implementation, USB or OS
behavior is executed here. Complete feature/security routing remains unfinished.
The verifier stages timer.h in a separate `-I` directory so its include-next
probe has the intended search semantics; upstream bytes and strict warnings are
preserved (no new warning suppression).

## RGB defaults/catalog audit — initial proposal

`audit_original_rgb_profile.py` adds a **read-only compatibility audit**. Original
reset instructions at `0x08013CF4` write six bytes `3d00ffff80ff` to
`0x20001CE0`: in the candidate's packed layout, enable1, mode15, HSV0/255/255,
speed128, flags255. The save wrapper at `0x08013CD8` requests **eight bytes at
logical0x17**; bytes6/7 are not initialized by the modeled reset stores. Do not
invent canonical zero padding or mistake this for complete reset/flush execution.

The original supported-list reader at `0x08019772` loads the table at
`0x0801E5EC`, reads halfwords at stride4 and stops at **45 entries**. Its table
contains Vial IDs0..44 (including OFF and direct), mapping to candidate QMK slots
0..45 except29. A proposed candidate enum profile matches **all180 ROM bytes**,
using stable Vial-mapped effects rather than blindly enabling the newer base's
extra animations. Candidate `PIXEL_FLOW` fills the unadvertised slot29; removing
it is a negative control that changes the catalog. **This does not establish the
original hidden mode's name or implementation.** Reactive press/release trigger
policy is also not established by enum-only framebuffer/keyreactive guard flags.

With that proposed catalog, unmodified candidate reset defaults produce
`3500ffff7fff` (mode13, speed127). Explicit candidate Chevron-mode15 and speed128
overrides produce the original six bytes. All256 prefill cases with distinct
padding canaries preserve bytes6/7 and capture one forced eight-byte save. The compiler uses actual
candidate enum/animation declaration headers, Vial mapping table, HSV/config
layout and reset body, checked against **52 immutable git source objects**.
Animation bodies are not compiled/executed; the optional ARM output is an
unlinked declaration/reset probe, not firmware or original Thumb execution.

**This proposal-only audit does not edit target configuration.** The later target
binding step below now applies the catalog/default profile while keeping full
runtime, reset/flush/storage and hardware blockers. The
separate hit-collector check below now establishes the press edge.
Run the audit against the pinned public reference (no installation required):

```sh
python3 reverse-engineering/tools/audit_original_rgb_profile.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk
# Optional --arm-object /new/path/profile-probe.o uses existing Clang.
```

## Electrical RGB hit collection — press edge connected

The target now explicitly defines **RGB_MATRIX_KEYPRESSES** and
**LED_HITS_TO_REMEMBER=8**. The original post-action slice at `0x08018EFA` uses
the changed matrix edge's pressed mask: releases skip LED mapping, while mapped
presses append LED X/Y/index with tick0. Its packed buffer at **0x20001AC6** is
41 bytes (eight slots); a full buffer shifts the four arrays then appends. Six
unmapped matrix cells do not append. This collection is separate from whether
a vendor key was consumed by the keycode handler.

`EmulateOriginalVial.java --rgb-events OUTPUT.json [--check]` generates the
separate `tests/fixtures/original-rgb-events.json`: **288 original Thumb cases**
(4×12 valid cells, press/release, initial count0/7/8), with buffer guards and
opaque byte patterns. The original memcpy body runs too, including all four
shift calls for each full mapped press; it is **not** an API replacement.
Execution stops at `0x080192CA` before heatmap processing, with a supplied valid
cell pointer and edge mask. Matrix scan, preceding action/HID, aging, IRQ,
heatmap and renderer are not executed. The existing2372-case fixture is unchanged.

The RGB verifier compiles actual candidate `switch_events()`, weak/default
LED-mapping and `rgb_matrix_handle_key_event()` bodies, plus exact last_hit_t and
flag declarations. It uses the target's press/capacity config and a controlled
nonsplit master role. All288 byte snapshots match at default optimization and
**-O2**. A KEYRELEASES override is a negative control: **252 mapped-edge cases
differ**. The remaining36 hole cases stay unchanged. Pixel/group/EEPROM/HID
traces and hit guards remain unchanged. Candidate keyboard.c is statically
checked to call switch_events after action_exec, matching the original call
before this slice; the complete caller/action pipeline is not executed here.

Upstream uses overlapping `memcpy` for shifts; the source is preserved. These
observed native outputs do not prove all future compiler/libc/link combinations.
The ARM result is unlinked, not physical validation. No complete effect catalog,
factory-default override or hidden-mode29 implementation is enabled by this step.

## Hidden mode29 — structural signature and interval verified

The original renderer15618 calls effect dispatcher14AA4. Its TBH table at
**0x08014AE8**, entry29, targets **0x08014F58**. Instruction/literal guards
establish a **PixelFlow-shaped** state machine: private216-byte RGB state at
**0x20001B55**,72 entries; unsigned wait gate before initialization; init clears
output and fills entries with black or HSV conversion using byte-RNG bit1;
flag-filtered chunks render stored RGB; the final chunk shifts71 three-byte
entries toward index0, refills index71 and advances the wait timer20002180.
This identifies structure, not the manufacturer's source name/revision or full
behavioral equivalence to the selected candidate.

`audit_original_rgb_mode29.py` compares the exact candidate PixelFlow nested
`interval()` function and actual pinned lib8tion math headers against a separate
**1024-case original Thumb oracle** (all256 speeds × four uint32 timer values).
Only original **0x080150D8..0x080150FA** arithmetic/store instructions execute in
that oracle, with supplied pointers, speed/current-time and guarded wait RAM.
The interval is `3000 / ((min(speed+16,255)*17)>>8)`; adding current time wraps
uint32. Increments at speed0/128/255 are3000/333/187 **timer units**, not a
physical-clock measurement. Existing2372+288 fixtures remain unchanged.

Actual candidate math matches all1024 cases at-O0 and-O2. Turning off
**FASTLED_SCALE8_FIXED** is a negative control with544 differing cases. Its
normal value1 comes from pinned common_features.mk, not a new target override.
Seven source files are byte-checked against immutable local git objects, even
when omitted from the sparse reference checkout. Existing **gcc-16** compiles
the unmodified GNU nested function; nothing is installed or downloaded. The
speed field is a controlled value shim, not complete config ABI validation.

```sh
python3 reverse-engineering/tools/audit_original_rgb_mode29.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk
# Ghidra script mode: EmulateOriginalVial.java --rgb-mode29-interval OUTPUT.json [--check]
```

The later frame probe below now executes RNG and the complete PixelFlow body
at controlled HSV/RGB boundaries. The later scalar HSV audit below tests the
actual conversion separately; complete scheduler/clock integration remains unverified. No complete effect catalog/default override
is applied here; the unconditional firmware build guard remains.

## Mode29 persistent calls — matched at the HSV/RGB API boundary

`audit_original_rgb_mode29_frames.py` compiles the **entire unmodified candidate
PixelFlow header**, actual RNG/math, limits/check-finished helpers and source
packed types with the existing GNU compiler. It compares six persistent
16-call sequences (**96 original calls**) at-O0/-O2: speeds0/128/255,
seeds0/65535, values255/128, all five chunks, flags255/4/2/0, re-init during
waiting, subsequent complete frames and uint32 wrap. The original selected
14AA4 dispatcher/mode29/common tail, RNG14900/14924, limits and memcpy execute;
**HSV147C0 is replaced** by the same diagnostic mapping on both sides,
`RGB=(uint8(h+v),s^v,h^s)`. RGB APIs12FC8/14A78 are captured and returned from,
not actual color staging/driver calls.

Ordered HSV-probe/RGB API traces, return value and RNG seed match for all96
calls at both optimization levels. A14-LED chunk negative control differs in
**90/96 calls**. Eleven immutable source files are checked. Separate hidden
native libraries provide fresh private state per sequence, without modifying
SDK function locals or relying on dynamic symbol interposition.

Original private216-byte cache, wait/global guards and untouched inputs are
checked. Original final chunks execute **71 actual three-byte memcpy calls**
each and refill the last entry. Native private cache/wait bytes are **not read
directly**: later rendered traces and gating observe their effects. The native
probe calls PixelFlow directly; the complete candidate dispatcher is not run.
Caller-supplied flags/iter/init/time isolate these effect boundaries.

The original **wait-before-init** behavior survives: requesting init while
waiting causes no clear/RNG/color operations. The unsigned wait comparison
also retains its wrap quirk: when a deadline wraps below a still-large current
time, the following call can render immediately. Neither behavior is repaired.

```sh
python3 reverse-engineering/tools/audit_original_rgb_mode29_frames.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk
# Ghidra: EmulateOriginalVial.java --rgb-mode29-frames OUTPUT.json [--check]
```

This is **algorithm/state conformance at a controlled color boundary**, not
actual HSV/color equivalence, the complete frame/indicator/flush pipeline,
physical animation or manufacturer source provenance. This diagnostic probe does
not configure the target; current catalog/default bindings are documented below
and the build guard remains unconditional.

## Actual scalar HSV/CIE conversion — sampled match

The original converter **0x080147C0..0x08014868** directly indexes a256-byte
CIE table at **0x0801DB1A**, loaded via literal14868. The compiled candidate
**CIE1931_CURVE matches all256 ROM bytes**. Actual original Thumb execution,
without an HSV replacement, matches unmodified candidate color.c, led_tables.c,
headers and the default rgb_matrix_hsv_to_rgb wrapper in **9472 cases**:
256 grayscale values with varied unused argument padding, plus all256 hues ×
saturation/value levels0/1/127/128/254/255. Guarded synthetic stack, saved
registers, packed RGB result and declared case coverage are checked.

`audit_original_rgb_hsv.py` runs the actual C arithmetic at-O0/-O2 and validates
six source files against immutable git objects. Only packed-attribute and
RAM-backed program-memory reads are adapted for the host. RGB-matrix enable
sets CIE1931_CURVE=yes in the pinned common_features.mk and that flag enables
USE_CIE1931_CURVE; no new target override is added. Calling the actual
**hsv_to_rgb_nocie** API is a negative control with **4861 differing cases**.
All active probe profiles keep-Wall/-Wextra/-Werror without warning exceptions.

```sh
python3 reverse-engineering/tools/audit_original_rgb_hsv.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk
# Ghidra: EmulateOriginalVial.java --rgb-hsv OUTPUT.json [--check]
```

This verifies the entire LUT and a declared scalar sample, **not all16777216
HSV triples**, physical colors or the complete renderer. The older96-call
mode29 fixture still deliberately uses diagnostic HSV; the separate real-HSV
integration below now tests actual conversion in persistent calls. This scalar audit does not configure catalog/default bindings. Current target
bindings are documented below; the unconditional build guard remains.

## Mode29 persistent calls with actual HSV — RGB API boundary match

`EmulateOriginalVial.java --rgb-mode29-frames-real-hsv OUTPUT.json [--check]`
adds a separate fixture, preserving the earlier diagnostic one. The same six
16-call sequences now execute **441 actual original HSV conversions** within
**96 mode29 calls**. HSV entry/return observation reads arguments/results and
checks saved registers/SP without changing arguments, return values or PC.
Original RNG, CIE LUT reads, limits,71 three-byte shifts on each final chunk,
wait-before-init and unsigned deadline wrap still execute. Only RGB output APIs
are captured and returned from; physical staging remains untouched.

```sh
python3 reverse-engineering/tools/audit_original_rgb_mode29_frames.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk \
  --real-hsv
```

The actual complete PixelFlow header, actual color.c/table/headers, default HSV
wrapper and RNG/math/limits run under existing GNU16. **14 source files** are
verified against immutable git objects. The default wrapper is renamed only by
preprocessing so an outer observation wrapper can log actual HSV results;
color arithmetic, LUT and PixelFlow are not rewritten. Only program-memory
byte reads and packed attributes use host adapters. Compiled LUT bytes match
all256 original bytes. Ordered HSV/RGB API records, return and RNG seed match
**96/96 at-O0 and-O2**. Chunk14 differs90/96; the actual nocie API differs
**35/96**, exactly the V128 calls containing a conversion or nonblack output.
All profiles retain-Wall/-Wextra/-Werror and hidden per-sequence native libraries.

Tests replay all216 original cache bytes using actual LCG decisions and observed
HSV results, check emitted flag-filtered slices, and compare noncolor state
against the preserved diagnostic fixture. Native private cache/wait remain
**indirectly observed**, not directly byte-read. This is actual selected effect
color-byte conformance at RGB setter boundaries, **not** full renderer,
indicator/group/flush, scheduler/clock/HAL/device or physical-color validation.
This comparison does not configure catalog/default bindings; current target
bindings are documented below. The target build guard remains unconditional.

## Factory mode15 — sampled Chevron/runner/color match

Original table entry15 dispatches at **0x08014D4E**, selecting callback
**0x08012B48** via literal14D9C and index runner **0x0801BE34**. The callback
adds `abs(int8(y-32)) + x - phase` to the HSV hue modulo256, preserving S/V.
Runner phase is `((uint16(timer) * (speed/4 + 2)) >> 8) & 255`, matching the
actual fixed-scale SDK expression, not a manually adjusted effect speed.

`EmulateOriginalVial.java --rgb-mode15 OUTPUT.json [--check]` executes the
selected dispatch, actual runner/callback/HSV/CIE/limits and common tail in
**1260 cases**: speeds0/128/255 × seven clocks0/1/255/256/65535/65536/FFFFFFFF ×
three HSV vectors(factory0/255/255,255/128/128,128/0/0) × flags255/4/2/0 ×
five chunks. There are **9072 actual HSV calls**, whose inputs/results all also
occur in the separate scalar fixture. RGB setter14A78 alone is captured and
returned from; input, RNG/global bytes, mode29 cache/wait and physical staging
are guarded. Initialization at chunk0 is supplied, not a complete boot/reset.

```sh
python3 reverse-engineering/tools/audit_original_rgb_mode15.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk
```

The complete unmodified candidate Chevron and index-runner headers, actual
color/LUT/math helpers and default center declaration run under existing GNU16;
**15 immutable source files** are checked. The full264 original ROM map bytes
are controlled input interpreted through actual packed source declarations
(point offset48, flags192), not a linked board/driver execution. Phase, ordered
HSV/RGB records and return match **1260/1260 at-O0/-O2**. Nonfixed scale differs
**360/1260**, nocie API **231/1260**; all256 compiled CIE bytes match ROM.
Tests additionally verify dispatch/instruction/literal mutations, all72 geometry
points and filtered chunks, HSV scalar agreement and low16 timer behavior.

This establishes sampled factory-mode Chevron behavior at RGB API boundaries,
not manufacturer source provenance, all possible inputs/45 effects, the full
renderer/indicator/group/flush or physical colors. The following step connects
catalog/default bindings without removing the unconditional build guard.

## Actual target catalog/default bindings — connected, build still blocked

The generator and target config now bind **43 optional effects**, including
unexposed PixelFlow29, plus the SDK's solid/direct declarations. The resulting
**45-entry Vial table matches all180 ROM bytes**, with QMK IDs0..45 excluding29
and effect limit46. This binds approved candidate names, not manufacturer source
names. Factory mode is explicitly Chevron15 and speed128; the other reset fields
remain the SDK defaults that match the original. No persistence policy or padding
normalization is added.

```sh
python3 reverse-engineering/tools/audit_original_rgb_profile.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk \
  --target reverse-engineering/keyboards/fave40h_original
# Optional --arm-object /new/path/target-profile.o: unlinked declaration/reset only.
```

Unlike the earlier proposal, this probe includes **actual target config.h**, the
actual pinned post_config.h and reactive-type guard, and the keymap's declared
VialRGB flag. It does **not inject a hand-selected effect list or force corrected
defaults** into the positive case. Actual SDK enum/animation declarations,
Vial table, packed types and reset body match prefix **3d00ffff80ff** for all256
canaries, preserving both padding bytes and one captured forced8-byte save.
Omitting PixelFlow changes the table; dropping target default overrides produces
**3500ffff7fff**, not the original prefix.

Framebuffer/reactive/press/Vial support bits resolve to23, with release disabled;
LED count72/chunk15/hit capacity8 are checked from actual preprocessed settings.
Framebuffer and reactive support are derived from upstream post-config/types,
not forced in the target. **53 SDK files** are validated against immutable Git
objects and target input hashes are recorded. Generator reference pins now also
cover the catalog declarations, post-config and color types(28 pinned files).
The optional ARM object is only a Cortex-M4 relocatable declaration/reset probe.

Only modes15 and29 have the selected real-color comparisons described above;
**remaining effect bodies and the full RGB runtime pipeline remain unverified**.
Enabling enum bindings in this blocked experimental source is not hardware
activation, a complete Make-resolved/QMK/HAL build, linked firmware or physical
validation. The unchanged unconditional guard still rejects normal builds and
partial/insecure override attempts. No commit, installation or flash is implied.

## Mode15 rendering + Caps/group filtering + GRB — bounded RAM composition

A separate `--rgb-mode15-staging` original fixture now contains **288 persistent
five-chunk sequences /1440 chunks**: factory speed128, two HSV vectors, three
clocks, four effect-flag masks, Caps off/on and six raw group-byte pairs including
nonboolean enables. Original mode15 dispatch/runner/actual HSV and the real
`0x08014A78`/`0x080132EC` RAM color setter run without replacement. Its output then
enters the separately bounded `0x080156CE..0x0801571A` Caps/filter slice with a
supplied active-effect/state-register context. Only the host LED getter is
controlled. Group/staging/private-state guards are checked; all10368 HSV calls
retain the previous independent mode15 fixture's traces.

```sh
python3 reverse-engineering/tools/audit_original_rgb_mode15_staging.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk \
  --target reverse-engineering/keyboards/fave40h_original
```

The candidate joins independently executed Chevron/runner/HSV API records to the
actual SDK WS2812 staging API through the existing **nonsplit color adapter**.
The extracted SDK RENDERING case still has a **completion-only renderer stub**;
it consumes the actual effect's return, then runs actual weak indicator delegates
and target Caps/filter hooks. Hidden symbol visibility keeps each native library's
private state isolated. This is explicit API-boundary composition, **not one
linked full renderer call**. Both-O0/-O2 match2880 before/after216-byte snapshots
per profile and all1440 ordered effect traces/returns, preserving persistent
buffer contents and raw group words. No EEPROM/HID/timer/DMA API is requested.

Independent counterfactuals differ in696 chunks when omitting the post pass,
720 when calling basic Caps before completion, and888 when swapping red/green.
The final-chunk Caps white at LED22 survives disabled keylight because the last
filter covers only[60,72); earlier chunk1 correctly clears that LED.
The audit also rechecks the actual target catalog/default profile and guard.

This does **not** execute the intervening original renderer caller, startup,
flags-change clearing, complete task scheduling/sync, flush/PWM encoding/DMA,
HAL/physical output. Mode29 composition is covered separately below. Existing
target files and the build blocker are unchanged; remaining runtime work is required.

## Mode29 wait/cache + Caps/filter + GRB — bounded RAM composition

`EmulateOriginalVial.java --rgb-mode29-staging OUTPUT.json [--check]` adds
**72 persistent sixteen-call sequences /1152 calls**: the previous six actual-HSV
mode29 sequences, each with Caps off/on and six raw group-byte pairs. All original
effect/HSV/RNG/memcpy/cache/wait observations remain identical to the separate
96-call fixture. The single-color RAM setter is real, as is the all-color thunk
`0x08012FC8` -> loop `0x08013304..0x08013320` -> setter `0x080132EC`.
No RGB setter is replaced. A separately entered post-effect Caps/filter slice
uses the controlled active-effect/state context; only the host getter is replaced.
Private original cache/wait/global bytes stay unchanged by that post pass, with
RAM and group/staging guards checked.

```sh
python3 reverse-engineering/tools/audit_original_rgb_mode29_staging.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk \
  --target reverse-engineering/keyboards/fave40h_original
```

Native comparison uses the entire unmodified PixelFlow/HSV/CIE/RNG/limits source
and a **fresh independently compiled hidden library for every sequence and
counterfactual**. Private native cache/wait remain **indirectly observed**, not
byte-read. Its RGB/all-color records join actual SDK WS2812 staging APIs; the
existing completion-only renderer stub feeds actual SDK RENDERING delegates and
target callbacks, not a single full renderer call. Both-O0/-O2 match1152 ordered
trace/return/seed observations and **2304 before/after216-byte GRB snapshots per
profile**; actual original HSV calls total5292, and all256 compiled CIE bytes match.
Composition requests no EEPROM/HID/timer/DMA APIs and preserves raw group words.
The actual target catalog/default/guard profile is also rechecked.

Counterfactuals differ684 calls without the post pass,456 with premature basic
Caps, and1100 with swapped red/green. Importantly, a **wait-before-init completion
at iter0** still invokes basic Caps, although it does not render/change the effect
cache or RNG seed: gating Caps only on iter4 would lose original behavior.
The advanced group pass still filters the current chunk; Caps LED22 survives
outside[0,15) even with keylight disabled.

This is controlled RAM/API-boundary composition. It omits the intervening original
renderer caller, automatic flags-change clearing, complete start/sync/task/clock,
scan/feature routing, flush/encoder/DMA/HAL and physical LEDs. It does not establish
manufacturer source provenance or all45 effects. No target generated code or build
guard is changed by these comparisons.

## Common renderer entry — init/enable/flags branches, before dispatch

The earlier selected-effect probes already entered the original common renderer,
but held last-enable equal to enable and supplied matching effect flags. A new
`--rgb-render-begin OUTPUT.json [--check]` fixture isolates **1524 independent
pre-dispatch cases** at `0x08014AA4..0x08014ADE`, including the init branch at
`0x08014B44..0x08014B48` and **actual all/single RAM color setters**. No API is
replaced. It stops inside the active call frame before effect dispatch; stack,
configuration, unrelated globals and GRB staging have guards.

```sh
python3 reverse-engineering/tools/audit_original_rgb_render_begin.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk \
  --target reverse-engineering/keyboards/fave40h_original
```

The1200-case init grid crosses effect0/15/29/45, five raw last-effect values,
enable0..3 and last-enable0..3/255. The324-case flags grid crosses six byte values
0/1/2/4/128/255 under unchanged, changed-effect and changed-enable contexts.
Iter0/4/255 is preserved; **255 only probes byte preservation**, not a valid
render chunk. Config.mode stays15; the caller's effect selection is not executed.
Raw enable2/3 and sentinel255 are comparison inputs, not invented user controls
or a claim about manufacturer boot-time last-state values.

Actual unmodified SDK init/flags statements, packed config/params types and
last-tracker declarations match all1524 cases at-O0/-O2. A nonsplit all-color
adapter reaches the actual SDK WS2812 staging API. Init is true when effect **or
raw enable** differs from its last tracker. Only an unequal flags byte clears
all216 staging bytes, exactly once; init alone does **not** clear in this prefix
(individual effects can clear on init). Params.iter
and raw flags are retained. Group state stays unchanged; no EEPROM/HID/timer/DMA
API is requested. The actual target catalog/default/build-guard profile is also
rechecked; generated target files are unchanged.

Ignoring enable changes differs300 cases, booleanizing enable differs216, and
omitting the flags clear differs270; independent unit calculations agree.
This still does not join these branches to a whole renderer/flush/task lifecycle.
In particular, the candidate SDK updates last-effect/enable in `rgb_task_flush`,
not in this prefix: caller sequencing and multi-chunk init lifetime remain work,
along with effect/indicator/flush integration, storage/security and hardware.

## Flush — actual last-tracker/driver/encoder/state chain in RAM

A separate `--rgb-flush OUTPUT.json [--check]` fixture executes the **entire
original flush function `0x08012FCC..0x08012FEA`** and actual encoder
`0x08013320..0x08013380`, with no instruction/API replacement. Its96 cases cross
four effect arguments, enable0..3, two old-tracker pairs and ramp/black/white GRB
inputs. Config.mode remains15; this does not execute caller mode selection.

```sh
python3 reverse-engineering/tools/audit_original_rgb_flush.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir /path/to/pinned/vial-qmk \
  --target reverse-engineering/keyboards/fave40h_original
```

The native path executes unmodified **SDK `rgb_task_flush` →
`rgb_matrix_update_pwm_buffers` → actual WS2812 driver vtable → actual
`ws2812_flush` encoder**. The encoder's public name is redirected only for an
entry/exit observation wrapper; its body/arithmetic is unchanged. Both-O0/-O2
match96 cases. Last-effect/enable already contain new raw values at encoder entry
and exit; task state stays FLUSHING2 during encoding and becomes SYNCING3 only
after it. This confirms that last trackers commit in flush, not the render prefix.
Moving tracker writes after encoding differs93 cases; premature SYNCING or
omitting encoding differs96 each. Independent unit calculations agree.

All1952 PWM words match an independent GRB/MSB-first model:1728 pulse words8/21
and224 untouched reset-tail canary words. Initial PWM is deliberatelyA5, not
hardware-initialized zeros; this checks which bytes flush leaves alone. Original
leading/extra-word/GRB/config/globals/stack guards and saved registers are checked;
native extra-word guard and unchanged config/params/GRB/group state are checked.
The literal at `0x08013384` points to PWM base+28 (first G byte's last bit), not
the buffer base: the original LSB-first loop writes backward to achieve MSB-first
wire order. Pulse-word matching does not establish physical timer frequency.

There are **no timer/DMA/EEPROM/HID API requests** in this RAM flush comparison.
Driver init and physical circular-DMA operation are not invoked. Actual target
profile/guard checks still run; no target generated source/config is changed.
This does not validate concurrent DMA reads, whole task/start/sync scheduling,
effect-to-flush caller routing, storage/security or physical output. The following
selected-mode probe connects actual multi-chunk init lifetime rather than supplied
completion/last-state values.

## Selected actual render → post → flush cycles (RAM only)

`--rgb-cycle OUTPUT.json [--check]` now executes **16 persistent sequences /
416 original renderer calls**, including **4,800 actual HSV calls and128 flushes**.
Ten supplied frame starts per sequence cover disabled mode0, Chevron15, PixelFlow29,
a flags change, PixelFlow wait completions, raw enable1→2 during wait, a later
ready frame, and return to disabled output. Speed128 is fixed; two seed/value
profiles, Caps0/2 and four group-enable pairs vary. It is not an exhaustive
mode/clock/config grid or complete task execution.

```sh
python3 reverse-engineering/tools/audit_original_rgb_cycle.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original
```

Unlike the older independent effect-to-staging probes, this native harness removes
its completion-only renderer and controlled-chunk helper. **Actual SDK
`rgb_task_render`, None/Chevron/PixelFlow bodies, HSV/CIE/math/RNG, RENDERING case,
weak indicator delegates, target Caps/group callbacks, actual SDK color wrappers,
driver vtable, flush and PWM encoder execute in the same library.** Observer-only
wrappers capture RGB API records and intermediate state; positive renderer/effect
bodies and arithmetic remain unmodified. Other catalog effects and the factory
LED-test entry trap if called. Unrelated Space Cadet entry points also trap in
this RGB-only harness rather than pulling its timer declarations into the GNU
translation unit; existing separate cadet tests are unchanged. No SDK source is
patched and no new warning suppression is added.

Each persistent sequence/counterfactual gets a fresh hidden library so function-local
PixelFlow cache/wait cannot leak across cases. At-O0 and-O2, all416 calls match RGB
API records, HSV call counts, RNG seed, init/flags/iter bytes, render state,
last trackers before/after flush, before/after216-byte GRB buffers, Caps call count,
and all1952 PWM words by digest. Native private cache/wait bytes are **not directly
read**; original snapshots and later actual calls observe their consequences.
Original cache/wait/config/global/stack/staging/PWM guards are checked; native
config/group/extra PWM-word guard and zero EEPROM/HID/timer/DMA requests hold.
The synthetic original call frame is initialized, including unused HSV padding;
accepted runs contain no uninitialized-state warnings.

This establishes two previously supplied-lifetime quirks rather than repairing them:

- Last-effect/enable change **only in flush**, so initial mode15/29 init remains
  true across all five chunks. PixelFlow clears all output and refills its cache
  with fresh RNG on **each** initial chunk; its final effect output only retains
  the final chunk before Caps/filtering. Do not impose iter0-only initialization.
- On enable1→2 while PixelFlow is waiting, init is true but wait returns before
  initialization. Flush still commits enable2. When time later reaches5000,
  init is false: the old cache is used, not silently reinitialized. Basic Caps
  also runs on iter0 wait completions; LED22 can survive disabled keylight.

Independent Python RGB/post/PWM replays match all416 calls. Omitting post differs
**279 calls**; booleanizing raw enable differs**16**. Full task mode selection,
STARTING/SYNCING transitions, frame-timer copying, scheduler/scan/feature routing,
remaining43 effects, storage/security and physical DMA/LED behavior are still
unverified. The following bounded STARTING probe checks frame-copy/reset control
before expanding to whole-task scheduling. The unconditional build guard stays.

## Bounded STARTING frame copy/reset (RAM only)

`--rgb-start OUTPUT.json [--check]` executes **432 original STARTING slices**:
`0x080156AE..0x080156C6`, stopped before the parent epilogue at`0x0801571A`,
including the **actual original41-byte memcpy**. Six unsigned timer snapshots
(0/1/15/16/65535/FFFFFFFF), three iter bytes, three flags, both init values and
four tracker byte patterns vary. Static switch/literal witnesses fix state0's
TBB branch, buffer pointers and copy size. The active parent frame is supplied:
`r5` equals the already-read timer-buffer snapshot,`r6` points to task state,
SP=`0x2000FFD8`, and OV=0 matches the preceding state0 CMP3. The parent prologue,
two clock reads, reactive-hit aging, mode selection and dispatch are **not executed**.

```sh
python3 reverse-engineering/tools/audit_original_rgb_start.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original
```

At-O0/-O2 all432 match **unmodified SDK `rgb_task_start`**, actual packed
`effect_params_t`/`last_hit_t` and the **actual target-derived reactive guard**.
Only iter becomes0; flags/init remain unchanged. The full32-bit frame timer takes
the snapshot, all41 tracker bytes copy even when count=0, and state becomes
RENDERING1. Unused slots/tick tail are copied, not normalized or truncated to count.
Original stack/callee-saved registers, source/destination/timer/global guards,
source bytes, group and GRB are checked; native object guards/source/input-clock
checks also hold. This standalone native function links no hardware APIs and
needs no warning exceptions. The input/output patterns deliberately differ so
skipping copy cannot pass. **108 count255 cases are raw copy-only tests, not valid
inputs for aging, collector or a live reactive renderer.**

Independent unit calculations agree with negative controls: missing iter reset
**288**, stale frame timer**432**, missing tracker copy**432**. This does not yet
replace the supplied frame starts in the preceding416-call cycle fixture or
establish actual timer reads/aging, complete STARTING dispatch, SYNCING/save
behavior, whole task/scan/feature routing, remaining effects, DMA or physical
output. The following timer/aging probe resolves that preceding boundary before
joining this actual start branch to the selected-cycle harness. Target
source/config and the build guard are unchanged.

## Actual clock/aging prefix (getter-only model)

`--rgb-timers OUTPUT.json [--check]` executes **432 original prefixes** from
`0x08015618` through the actual prologue/clock reads/aging loop, stopped at
`0x08015658` before mode selection. Only clock getter`0x0801B374` is replaced:
it returns two supplied unsigned32-bit snapshots. No hardware clock is read.
Counts0/1/4/8, three tick patterns, two old-clock positions, nine elapsed deltas
(including65535/65536/65537/FFFFFFFF) and same/different read snapshots vary.
Count255 is excluded; XY/index bytes are opaque here, never used for LED lookup.

```sh
python3 reverse-engineering/tools/audit_original_rgb_timers.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original
```

At-O0/-O2 all432 match **actual SDK `rgb_task_timers`**, actual nonsplit
sync-timer macros and `timer_elapsed32`/`TIMER_DIFF_32`, using only a two-value
`timer_read32` model. No elapsed arithmetic/aging loop is rewritten in the positive
candidate. The existing target-derived reactive guard and packed tracker types
remain in use. Original instruction/literal witnesses, stack/buffer/timer/global
guards, untouched frame timer/last tracker/params/state/group/GRB, and native
object guards/untouched state checks hold. Native compilation remains strict
with no warning exceptions. These are opaque timer units, not physical-frequency
or scheduler validation.

The following original behaviors are now explicit and must not be repaired:

- **First read determines delta; second read updates `rgb_timer_buffer`.** They
  need not be equal; unsigned subtraction correctly covers a32-bit clock wrap.
  `g_rgb_timer` does not change until STARTING copies the snapshot.
- The loop uses its **initial count**, decrements stored count on expiration,
  and does **not compact or clear expired entries**. Later original slots still
  update even when the stored count has shrunk below their indices. XY/index and
  inactive tick slots remain byte-identical.
- When delta exceeds65535, unsigned`UINT16_MAX - delta` underflows: sampled large
  deltas retain the count and add delta modulo65536 to tick bytes. Do not replace
  this with saturation, clearing or automatic expiration.

Independent byte-level replay agrees. Using the second read for delta differs
**156 cases**, expiring all ages above65535 differs**108**, and zeroing expired
ticks differs**100**. These are counterfactuals, not fixes applied to the target.
This prefix is still separate from the416-call selected render/post/flush probe.
The next section joins clock/aging to actual mode selection and STARTING;
full render/flush caller routing, SYNCING/save/scheduling, all effects,
storage/security and physical hardware remain unverified.

## Genuine task entry → selection → STARTING → return

`--rgb-task-start OUTPUT.json [--check]` now executes **384 complete original task
invocations** at`0x08015618`, including actual prologue, two modeled clock reads,
aging, mode/suspend selection, state0 dispatch, frame copy and genuine epilogue
`0x0801571A..0x0801571C` through return. **No r5/r6/SP/OV context is supplied and
STARTING is no longer separately entered in this probe.** Only the clock getter
is controlled. Every case begins at STARTING0; render/flush/SYNCING are excluded.

```sh
python3 reverse-engineering/tools/audit_original_rgb_task_start.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original
```

Modes0/15/29/45, raw enable0..3, supplied suspend0/1, normal/wrapping old clock,
count0/8 and iter0/4/255 vary. Mode45 is **selection-only**, not effect equivalence.
Suspend is an input flag, not execution of the suspend setter or a USB event.
At-O0/-O2 actual SDK `rgb_matrix_task`, timers/elapsed32 and STARTING match384/384
in one library. The only task-body addition observes selected effect before the
switch; a start wrapper only counts the call and checks prior clock reads.
Native timeout comes from the actual header/target and must be0. Unverified
render/flush/sync/indicator entry points **trap**, never simulate completion.

Effect selection is0 when suspended or disabled, otherwise the raw configured
mode: enable2/3 remain enabled, not enable1-only. Even suspended/disabled calls
age the source and copy the frame. The input ages **before** all41 bytes copy
into the tracker; count8's mixed ticks become count6 without compaction and that
aged byte array, not the stale input, is copied. Both timer buffer and frame timer
take the second clock value. Flags/init remainA5/1; only iter resets and state
becomes RENDERING1. Original config/suspend/source-destination/timer/global/stack
and callee-saved-register checks, group/GRB preservation and native object/config
checks hold. Native compilation has no warning exceptions; physical clock/HAL,
EEPROM and linked firmware are not executed.

Independent checks agree with counterfactuals: ignoring suspend**108**, accepting
only enable1**72**, and copying the pre-aged tracker**192** differ. This connects
the formerly separate timer/start boundaries for **STARTING calls only**. It does
not yet connect the416-call effect/post/flush fixture to actual task dispatch.
The next probe joins selected RENDERING and the **separate following FLUSHING
invocation** while recomputing effect from then-current config/suspend. These
older fixtures retain their own narrower boundaries.

## Genuine task STARTING → RENDERING/post → following-call FLUSHING

`--rgb-task-cycle OUTPUT.json [--check]` executes **8 persistent sequences /
320 whole original task invocations** at`0x08015618`. The real prologue, two clock
calls, aging, effect selection and state0/1/2 dispatch execute; the original post
runs in its actual caller context and FLUSHING restores the caller's stack then
tailcalls`0x08012FCC` at`0x0801575E`. No separate post/start entry or synthetic
active-frame r4/r5/r6/SP/OV context is supplied (ordinary initial ABI/SP remains
established). Only clock and host-LED getters are modeled. Actual RAM memcpy,
None/Chevron/PixelFlow/HSV/CIE/RNG, RGB setters and PWM encoder execute unchanged.

```sh
python3 reverse-engineering/tools/audit_original_rgb_task_cycle.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original
```

Native comparison executes actual SDK `rgb_matrix_task`, timers/elapsed32,
STARTING, selected renderer, weak delegates/target indicators, color wrappers,
flush/driver-vtable and encoder in one TU. At-O0/-O2 it matches **320/320 calls,
2404 actual HSV calls and48 flushes**: selected effects, render-only API traces,
Caps counts, params/init/state/last trackers/RNG, both timers, both41-byte hit
objects, all216 GRB bytes and1952-word PWM digests. Original stack/RAM guards,
callee-saved registers, raw config/group preservation and native object/config
canaries hold; no hardware/storage IO is requested. Fresh hidden native libraries
isolate each sequence and counterfactual (32 libraries total). Native private
PixelFlow cache/wait bytes remain **indirectly observed**, not directly compared.

The8 sequences pair seed0/value255 or seed65535/value128 with Caps0/2 and raw
group low bytes0/0 or1/1 (upper wordA5B6). Each has seven supplied frame starts:

| Render/config input | Separate next flush | Evidence retained |
|---|---|---|
| mode15,enable1 | mode29,enable1 | Last29 commits despite drawing15; first subsequent PixelFlow is init=false with zero BSS cache |
| mode29,enable1 | unchanged | Five chunks, frame timer frozen; no forced iter0-only initialization |
| mode29,enable2 | suspend=true | All initial chunks init=true; flush commits effect0/raw enable2 |
| mode29,enable2 while waiting | mode15,enable0 | Wait exits before init; basic Caps still runs; next flush commits0/0 |
| disabled mode15 (None) | **none** | Warm None directly enters SYNCING without encoding |
| mode15,enable1; flags255→4 mid-frame | mode29,enable3 | Actual flags clear/filter; next effect/enable commits independently |
| mode29,enable3 | unchanged | Last29/3 means init=false, prior cache lifetime retained |

Every task call ages the buffered hits; only STARTING copies the second clock
and full41-byte tracker into the active frame. Render and later flush clocks do
not replace the frame snapshot. STARTING does not clear prior GRB/PWM. Independent
byte replay reproduces aging/clock/state/flush trackers, post-filter output and
persistent PWM. **Ignoring suspend differs40 calls; using live buffer time for
all task states differs272**. The latter comprises264 wrong-clock non-STARTING
calls plus8 subsequent STARTING calls inheriting changed Chevron GRB/PWM. This
carryover is independently reconstructed from ROM geometry and separate scalar
HSV fixtures, not an assumed immediate clear at a new frame.

**Limits:** seven frame boundaries per sequence manually set state0 only after
state3. The original SYNCING branch`0x08015762+`, EEPROM/save/elapsed flush gate,
suspend setter/USB events, scheduler/scan/feature routing and physical timer/DMA/
LEDs do not execute. Native unsupported43 effects, cadet APIs and SYNCING trap.
Post **setter ordering** need not equal the original's two loops: only render
traces and final post RAM are compared. The preserved A5 PWM reset-tail values
are test canaries, not proof of physical reset initialization. No full firmware
build/link, new ARM object, tool installation, commit, or flash is performed.
The unconditional build guard and generated target sources/config stay unchanged.

Next safe boundary: inspect SYNCING/save/time-gate paths before choosing any
bounded RAM-only continuation; do not assume EEPROM writes are authorized or
connect unverified persistence/destructive reset. Remaining43 effects, Vial
security/storage and physical validation still block flash readiness.

## Intentionally unavailable

`rules.mk` unconditionally stops with `ORIGINAL_TARGET_INCOMPLETE`; there is no
partial-build override. RGB effects, destructive reset
and Vial unlock/security/feature integration are still missing. Startup overrides
are present but remain subject to full-build and hardware verification.
The embedded lighting/custom descriptions are not implementations of those
features. Do not remove the guard merely to obtain an image. No guessed unlock
combo, insecure fallback, or old BUILD_ID pin is supplied.

Full EEPROM compatibility, build-stamp/reset/migration safety and physical
hardware validation remain separate flash-readiness requirements. Neither a
successful keymap probe nor future compilation authorizes flashing.

## Reproduce

With an exact checkout of the selected revision:

```sh
QMK_REFERENCE=/path/to/pinned/vial-qmk
python3 reverse-engineering/tools/prepare_original_target.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --check reverse-engineering/keyboards/fave40h_original

work=$(mktemp -d)
python3 reverse-engineering/tools/verify_original_target_keymap.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original \
  --arm-object "$work/keymap-arm.o"
```

The probe compiles **unmodified hash-checked candidate keymap introspection**
with controlled API headers and this target's actual keymap/config. It checks
all 192 factory reset cells: 144 stored cells and 48 layer-3 `KC_TRNS` results.
It also compiles that keymap-only probe as a strict Cortex-M4 object with Clang.
The startup-specific check additionally requires initialized pinned submodules:

```sh
python3 reverse-engineering/tools/verify_original_target_startup.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original \
  --arm-object "$work/startup-probe.o"
```

RGB transport/map check (no physical driver calls):

```sh
python3 reverse-engineering/tools/verify_original_target_rgb.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$QMK_REFERENCE" \
  --target reverse-engineering/keyboards/fave40h_original \
  --arm-object "$work/rgb-probe.o"
```

These are host execution and **controlled-probe object compilation**, not a
full QMK/ChibiOS firmware build; no USB, peripherals, EEPROM or flash execute.
A full upstream JSON-schema validation has not been run (its Python dependency
is not installed); current tests check the assembled field/data contracts.

`--export` requires a new destination and refuses overwrite. Existing generated
files should be changed through `prepare_original_target.py`; the README is
maintained separately. No QMK/GNU Arm toolchain has been installed by this step.
