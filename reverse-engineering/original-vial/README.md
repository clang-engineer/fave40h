# Original FAve40H Vial source reconstruction

**Target: `firmware/origin/FAve40H_VIAL.uf2`, not the recent eight-layer build.**
The goal is to reconstruct the original firmware's implementation on top of the
appropriate public QMK/Vial code, without adding layers or substituting the old
six-layer experimental port. Exact manufacturer filenames, symbols, comments,
source revision and byte-identical compilation have not been recovered.

## Selected experimental build base

The approved next stage uses public Vial-QMK
`dd43959ae5c08d8a28d38a1acf7b04e86b14a344` as the **experimental build base for a
separate original-four-layer target**. This is not identification of the
manufacturer's exact revision or proof of whole-firmware behavior. Its gitlinks
pin ChibiOS to `8bd61b804303f1614d574546c2dd735eeabb09f5` and ChibiOS-Contrib to
`3ac181e4ca5cafddaf8b472baa1d09c2b24c77b6`. The historical six-layer target is
not the source of truth and is not repurposed. Toolchain installation, flashing
and migration have not been authorized by this build-base selection.

A separate [target seed](../keyboards/fave40h_original/README.md) now contains
original identity/matrix/layout metadata and three compiled factory layers for
four-layer dynamic reset. Its make rules deliberately block incomplete builds;
RGB effects, destructive reset and Vial security/complete event integration
are still pending. Target Caps/basic and per-chunk group-filter hooks now match
25 original filter cases and 24 composed chunks through extracted candidate
indicator delegates/RENDERING dispatch with controlled render/host/color inputs;
this is not a complete animation engine or firmware pipeline. The six RGB group
keys now match all 48 original byte-control cases via the selected candidate's
module/KB prefix and weak user delegation; later-stage sentinels verify consumed
versus passthrough behavior, not full core/HID execution. No EEPROM autosave
policy was added or inferred from these bounded cases. The target also connects
the last-Shift-edge Backspace/Delete command: eight original Shift-edge and eight
mapping cases match captured register/unregister intents, preserving overlapping
Shifts and release-time reselection. All 14 custom Space Cadet keys now call the
unmodified candidate helper sharing private state with the seven standard keys:
196 custom +98 standard +16 reached-core defaults +14 vendor bypasses match
through selected KB/Space Cadet dispatch with timer/term and modifier/tap API
shims. Intervening features, real HID reports and complete event handling remain
unvalidated; no new original-Thumb cases are claimed for these source probes.
A separate read-only RGB profile audit now matches the 45-entry supported table
and six reset-field bytes against actual candidate declarations/reset source.
It finds original mode15/speed128 versus candidate profile defaults13/127;
explicit proposed overrides match, without changing the target configuration.
Eight-byte save versus six initialized fields preserves two padding bytes. The
unadvertised internal slot29 is not proof of the original Pixel Flow animation.
See the target README for the 52-source-file native/ARM audit and its boundaries.
A separate **288-case original Thumb electrical-edge oracle** now verifies the
41-byte/eight-slot hit collector, including execution of the original memcpy
body. Presses append, releases and six unmapped cells do not; the candidate's
actual switch-events/collector bodies match at default optimization and-O2.
KEYRELEASES gives252 negative differences. The target now pins KEYPRESSES and
eight hits; that collector-only probe does not validate complete effects. The
later target binding below connects the catalog while keeping runtime blockers.
A later mode29 audit pins its TBH target14F58 and PixelFlow-shaped72×RGB
state/shift/RNG-HSV boundary structure. A separate1024-case original Thumb
arithmetic oracle matches the actual candidate nested interval + pinned math
headers at-O0/-O2 (nonfixed-scale negative544 differences). This is not full
animation execution or proof of the manufacturer's source revision. See the
target README for `audit_original_rgb_mode29.py` and exact boundaries.
The next bounded probe executes96 persistent original mode29 calls, actual
RNG/limits/memcpy and the entire unmodified candidate PixelFlow body at a
**controlled HSV/RGB API boundary**. Ordered API traces/return/seed match at
-O0/-O2; wrong chunk limit differs90/96. Native private cache/wait are observed
indirectly, not directly byte-compared; that probe does not execute actual HSV
or physical animation. A later separate scalar HSV audit now matches9472
actual original conversions and all256 CIE LUT bytes against pinned candidate
color.c/table/default-wrapper source at-O0/-O2; nocie API negative differs4861.
It does not exhaust all HSV triples. A separate real-HSV mode29 fixture now
executes441 original HSV conversions inside96 persistent effect calls and
matches the candidate at-O0/-O2; the diagnostic fixture remains unchanged.
All256 compiled CIE bytes match, chunk14 differs90/96 and nocie differs35/96.
Native private state is still observed indirectly; full renderer/indicator/flush
and physical colors remain unverified. See `audit_original_rgb_hsv.py`,
`audit_original_rgb_mode29_frames.py --real-hsv` and the target README for boundaries.

Factory mode15 now has a separate1260-case actual dispatch/runner/math/HSV
fixture: the pinned candidate Chevron/runner/color code matches all cases at
-O0/-O2, including9072 original HSV calls. Nonfixed scale differs360 and nocie
API differs231; see `audit_original_rgb_mode15.py`. This is a finite API-boundary
comparison with controlled original geometry/config/time, not the full renderer
or physical output. The generator/target now connect43 optional effect bindings
and explicit factory mode15/speed128. `audit_original_rgb_profile.py --target ...`
compiles actual target config/post-config, deriving framebuffer/reactive/press
support and matching all180 catalog bytes plus reset prefix3d00ffff80ff across256
padding canaries. Dropping PixelFlow/default overrides fails the comparison.
Only selected15/29 bodies have real-color probes. A separate mode15 RAM composition
now adds288 persistent five-chunk sequences(1440 chunks/10368 actual HSV calls):
original actual color stores followed by a separately entered Caps/group-filter
slice match2880 before/after GRB snapshots against candidate effect records joined
to SDK staging and actual target hooks, at-O0/-O2. The native RENDERING caller
retains a completion-only effect stub: this is not a full linked renderer call.
Missing post-pass, early Caps and red/green-swap controls differ696/720/888 chunks;
final-chunk Caps white survives the disabled keylight filter as in the original.
See `audit_original_rgb_mode15_staging.py` and the target README. Remaining effects,
mode29 composition, full RGB runtime and storage/physical safety remain blockers.
This adds288 edge,1024 interval and96 effect-call executions alongside the unchanged2372-case fixture;
heatmap, aging, preceding action/HID and full scan/render routing remain untested. The target now has the original 264-byte LED map and PWM
transport settings; the unmodified candidate PWM encoder matches all 51 existing
original encoder cases with controlled hardware-API shims. Original IRQ50/TIM5
static witnesses resolve its system-timer conflict with TIM2 PWM. No physical
lighting, IRQ or DMA is executed. Bounded group-word lifecycle cases now bind
target user initialization/post-init hooks: reset word 0x101 and complete raw
four-byte load from logical 0x13, preserving upper bytes/non-boolean enables.
Actual weak KB delegation bodies plus captured APIs match the original ordered
intents; full reset, partial-read faults, persistence and migration are unproved.
Startup headers provide original GPIO/PLL/CFGR settings. A separate RAM-only
initializer/clock-header probe matches 42 GPIO values and original register
constants; full clock execution and physical behavior remain unvalidated.
A hash-checked candidate introspection probe verifies all 192 reset cells on the
host and compiles as a shim-based ARM keymap object, not full QMK firmware.

## Status: partial source/data recovery, NOT a firmware build

Recovered C code is exercised **on the host computer** and separately compiles
to freestanding Cortex-M4 ARM object files with Clang. Selected RAM-only behavior
is also compared against **2,372 original-Thumb execution cases** in Ghidra,
with explicit clock/HID, storage-read and reset-entry boundary hooks.
This directory still has no complete QMK board target, USB/EEPROM implementation,
linked firmware, flashable artifact, or proven hardware behavior. Nothing was flashed.

| Artifact | What is actually recovered |
|---|---|
| `factory_defaults.c/.h` | Original factory keymap values; keymap-only reset semantics; bounded dynamic-keymap EEPROM address calculation |
| `board_defaults.h` | Exact GPIO A/B/C/D/E/H register initialization data and PLL/CFGR constants; no MMIO writes |
| `vendor_parameters.c/.h` | Arguments for 14 space-cadet keys, last-shift-edge tracking, Backspace/Delete selection and six press-only RGB controls; NOT full HID handlers or cadet timing |
| `rgb_model.c/.h` | Exact 72-LED matrix/positions/flags; RAM-only PWM initialization/encoding and switch/underglow filtering; NOT a hardware driver |
| `cadet_model.c/.h` | Shared helper state, uint16 elapsed/term decisions, call intents for 14 vendor + 7 built-in keys, explicit reset and isolated reached-core stage; NOT HID reports or the full pre-core pipeline |
| `tap_model.c/.h` | Caps/normal delay selection, uint64 delay-to-tick arithmetic and register/sleep/unregister intents; NOT real USB reports, sleeping or scheduling |
| `prefix_model.c/.h` | VIA stamp/core-magic predicates for two isolated startup gates and one-byte layout read; NOT EEPROM, initialization, flash or full boot |
| `snapshot_model.c/.h` | Consolidated-cache FNV1a64/checkpoint comparison and final RAM/cursor state; NOT physical flash, journal replay or complete recovery |
| `journal_model.c/.h` | One translated entry: header/address/length, bounded payload copy, next cursor and error classification; NOT the replay loop, cursor commit or consolidation |
| `backing_model.c/.h` | Word complement, captured four-byte program request/status and final read-error result; NOT a physical driver or verified bus-fault handling |
| `vial-definition.json` | Embedded manufacturer Vial definition decoded from the original image, including 22 custom-key descriptions |
| `evidence.json` | Exact input/payload hashes, source addresses, instruction witnesses, recovered data, and explicit uncertainty flags |

The twenty-one core generated files are deterministic outputs of
[`recover_original_vial.py`](../tools/recover_original_vial.py). The separate
`prefix-abi-audit.json`, `settings-abi-audit.json` and `records-abi-audit.json` are produced by the
hash-bound reference comparison tools below, not by pretending that an upstream
revision was recovered. Their C identifiers
and file organization are ours, not recovered manufacturer names. This is more
than dumping decompiler text, but much less than a finished replacement firmware.

## Key findings from the ORIGINAL image

- UF2 SHA-256:
  `d5e680fa2507534b63b316a3e67a5d7457af4bdfa65189f464d4e1b029692431`.
  Payload SHA-256:
  `9df2375a5dfc7d155c3320ea5df3f2cff6920686928ae6ff5c186de5bee453e4`.
- Dynamic keymaps have **four layers**, but the factory table at `0x0801E284`
  contains only **three layers (288 bytes)**. Reset code at `0x08015824`
  reads these for layers 0..2 and explicitly substitutes `KC_TRNS` for every
  layer-3 matrix cell. Bytes after the table are not a fourth factory keymap.
- Factory base has Caps Lock at matrix `[1][0]`, split spaces `LT(1, Space)`
  and `LT(2, Space)`. This is not the user's customized JSON backup.
- Rows: **A5, A6, A3, A4**. Columns: **B12, B13, B14, B15, A8, B6, B5,
  B4, B3, A15, B7, B8**. Init and active-low column-selection/row-read scan
  code independently agree on the ordered pin lists (`ROW2COL`).
- Early-init register writer `0x0801AA7E` establishes the packed GPIO field
  order. The six groups start at `0x0801EA14` and initialize A/B/C/D/E/H.
- PLLCFGR `0x04413010` and CFGR `0x38881000` are actually written by the
  original early init at `0x0801B034`. HSE=16 MHz and SYSCLK=48 MHz are
  inferred for a correct 48 MHz USB clock; they are not physical measurements.
- USB VID:PID **5123:A02D**, device version **0x0100**, manufacturer
  `LJTuring`, product `Fave40H`, serial `vial:f64c2b3c`.
  The serial suffix is **not** a verified Git revision. Do not guess a source
  revision from it; the exact upstream/manufacturer version remains unknown.
  The selected candidate's `builddefs/build_vial.mk` hardcodes that same serial
  literal; it is not a dynamically recovered manufacturer revision.
- Original logical settings buffer is 4096 bytes; backing budget is 8192.
  The recovered layout is shown below. Existing settings compatibility with a
  reconstructed build is not established.
- A boot-entry path writes `0xF01669EF` to RAM `0x2000FFFC` and requests an
  SCB system reset through `0x0801B010`. The supplied application begins at
  `0x08010000` and contains neither the receiving low-flash bootloader nor a
  backup of current device settings. Recovery behavior remains unproven.

### Original RGB driver and LED map

These findings come from the **original** image, independently of the old port.

| Item | Original evidence |
|---|---|
| Driver family | WS2812-compatible PWM/DMA encoding; exact LED part unverified |
| Data pin | **PB10**, AF1, push-pull; pin-mode call at `0x08013946..0x0801394E` |
| Timer | **TIM2 channel 3**, CCR3 at `0x4000003C`; object initialized at `0x080184B6..0x080184D6` |
| PWM | 24 MHz tick, period 30 ticks; high duty 8 for zero, 21 for one; GRB, MSB first |
| DMA | DMA1 stream 1, channel 3; circular, 32-bit memory/peripheral words; CR `0x06035540` |
| Frame | 1728 color words + 224 zero reset words = 1952 transfers; inferred 800 kbit/s and 280 µs reset low |
| LED configuration | `0x0801DEA0`: 48 matrix entries + 72 XY pairs + 72 flags |
| Groups | Indices **0..41** switch LEDs (`flags=4`); **42..71** underglow (`flags=2`) |
| Caps Lock | RGB task overrides index **22** to white before group filtering; full effect/task scheduling is not exported |

The exported matrix includes six `255`/no-LED cells, not 48 switch LEDs. Pin PB10
is selected by the driver during runtime, separately from early GPIO defaults.
The LED coordinates and group flags are recovered data, not physical continuity
or oscilloscope verification.

`original_vial_pwm_init()` models initialization of the 1952-word RAM buffer.
`original_vial_pwm_encode()` models `0x08013320`: it rewrites only the 1728 color
words and **preserves** the reset tail. Group filtering models the half-open
chunk loop at `0x080156F8`; disabled groups become black before encoding.
This is not a DMA synchronization, interrupt, electrical-output or effects engine
implementation. The original circular buffer can be updated while DMA reads it;
the model neither tests that timing nor introduces a different buffering scheme.

### Original logical settings layout

These are **logical EEPROM offsets**, not absolute flash addresses.

| Region | Start | End exclusive | Record count/size |
|---|---:|---:|---|
| Dynamic keymap | `0x29` | `0x1A9` | 4 x 4 x 12 x 2 bytes |
| QMK settings | `0x1A9` | `0x1D1` | 40 bytes |
| Tap dance | `0x1D1` | `0x271` | 16 x 10 bytes |
| Combo | `0x271` | `0x311` | 16 x 10 bytes |
| Key override | `0x311` | `0x3B1` | 16 x 10 bytes |
| Alternate repeat | `0x3B1` | `0x471` | 32 x 6 bytes |
| Macro buffer | `0x471` | `0x1000` | 2959 bytes |

The initial `0x00..0x28` fields have not been completely decoded. This table is
not a migration implementation and must not be used to erase device flash.

### Consolidated snapshot load (translated bytes, no flash or log replay)

The original cache is at `0x200021D8`; its write cursor follows at `0x200031D8`.
The bounded original load slice `0x08018758..0x08018816` reads 1024 four-byte
words and computes **FNV1a64** over all 4096 cache bytes. Its basis is
`0xCBF29CE484222325`, prime `0x100000001B3`. It compares the low/high checksum
words read at backing offsets `0x1000` and `0x1004`, in little-endian order.
The log begins at `0x1008`, leaving 4088 bytes in the observed 8192-byte budget.
These are **translated backing-store offsets, not physical flash addresses**.

`snapshot_model.c/.h` reconstructs only the final cache/cursor outcome of that
load. Callers supply 4104 translated bytes; diagnostic outcome values are ours,
not recovered QMK status-enum values.

| Observed condition | Cache and write cursor at the bounded exit |
|---|---|
| Checksum matches | Loaded cache retained; incoming cursor unchanged (normally initialized earlier to `0x1008`) |
| Checksum mismatches | Cache becomes zero; cursor becomes `0x1008`; original flow **continues to journal playback** |
| A data-word read fails | Cache becomes zero; cursor becomes `0x1008`; exits before playback; inspection stops before the caller's second clear |

**A checksum mismatch alone is not an immediate flash erase or a reason to reject
an entire EEPROM image. The log may still reconstruct data.** This model is not
a dump-recovery tool, since log replay is not implemented. In particular, a
normalized all-zero snapshot has checksum zero but FNV1a64 of 4096 zero bytes is
nonzero; it takes the mismatch path without executing flash operations here.
The UF2 contains application/default data, not a recovered live settings image.

Sixteen original-instruction cases use synthetic zero, `0xFF`, byte-ramp and LCG
cache patterns: twelve valid/low-bit-corrupt/high-bit-corrupt checkpoints, three
first/middle/last data-read failures, and one normalized erased snapshot. Original
Thumb performs the full add/carry FNV computation, comparison and RAM clear.
Backing reads return controlled translated words; `memset` is confined to cache
RAM. Cache/cursor canaries, input immutability and final SHA-256 values are checked.
The existing 50000-instruction budget remains unchanged for prior routines; only
this fixed 4096-byte slice uses a bounded 200000-instruction budget.

```sh
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_snapshot.py -v
```

The pinned candidate's [wear-leveling source](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/wear_leveling/wear_leveling.c)
provides the matching snapshot/FNV structure (raw source SHA-256
`a5480ffe8cc544414f5ef63d47f86c27c7f21e623c57021514d7dc9113d6542b`).
This does not identify the original source revision or prove the complete driver.
Checksum-read failure behavior, full log replay/consolidation, physical bit inversion,
flash driver errors/locking/erase/program, power-loss recovery and migration are
**not validated or implemented** by the snapshot model. No such operations execute.
The following subsection models one bounded journal entry separately.

### One journal entry (not the replay loop or recovery driver)

`journal_model.c/.h` matches the original entry slice beginning at `0x08018824`.
Its first four-byte word is supplied; only a possible second read is controlled
by the oracle. All bytes are after backing-store translation.

- Only type zero (`byte0 & 0xC0 == 0`) is accepted in this four-byte backing
  profile. Address is `((byte0 & 7) << 16) | (byte1 << 8) | byte2`; the three-bit
  length is `(byte0 >> 3) & 7`; payload starts at byte 3.
- An all-zero first word stops without advancing. A **nonzero length-zero**
  header is instead accepted as a no-op and advances four bytes. The original
  bound is `address + length <= 4096`, so length zero at address 4096 is accepted.
- Lengths 0/1 consume four bytes; lengths 2..5 read a second word and consume
  eight bytes only on success. Invalid type/address or second-read failure
  copies no cache bytes and leaves the next cursor four bytes after the header.
- The full original error path later requests consolidation; **errors are not
  records to silently skip**. That path can reach erase/program operations and
  is not executed by the entry oracle. A next cursor of `0x2000` similarly does
  not establish that full-log recovery/consolidation works.

The 111 original-Thumb cases cover lengths 0..5, small/large/boundary addresses,
all three invalid types, second-read failures, empty slots and last-slot cursors.
`memcpy` is hooked to bounded cache RAM. Execution stops before another entry,
before global cursor commit at `0x08018886`, and before consolidation callbacks.
C diagnostic values/defensive argument checks are ours, not recovered QMK enums.

**Lengths 6/7 are explicitly UNMODELED, not reinterpreted as firmware rejection.**
The original reader has a three-bit field without a five-byte limit at that
point; copying 6/7 bytes can consume unproven stack bytes beyond the eight-byte
temporary. The normal reference writer emits at most five payload bytes. The
model also declines a second word beyond the configured 8192-byte budget; this
is a modeling boundary, not a claimed original bounds check. First-word read
failure, complete/partial replay, malformed-record recovery and physical storage
remain unverified. Do not use this model as a persistent-storage driver.

```sh
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_journal.py -v
```

### Backing word transform and sector geometry (no physical driver execution)

`backing_model.c/.h` models the original wrappers at `0x0801280C` (program) and
`0x08012848` (read). Startup stores `descriptor.attributes & 1` in RAM
`0x200017A8`. All four available immutable ROM descriptors have attributes 3,
so their normal flag is 1. Both wrappers complement the whole uint32 word for
**any nonzero flag byte**. Thus the intended transform maps physical `FFFFFFFF`
to logical zero; this is not a measurement of live flash or a recovered dump.

Program requests use four bytes, driver-relative offset `uint32(base + offset)`
and the transformed word. Only driver status zero returns true. The wrapper
itself checks neither alignment nor the 8192-byte budget; captured out-of-range,
unaligned and wrapping requests are **not successful physical write tests**.
Read probes redirect descriptor memory to synthetic RAM. An observed final
nonzero error byte produces output zero/false and clears the error byte; a stale
initial error is cleared before that check. Final-byte injection does not verify
bus faults: notably the word load at `0x08012860` **precedes** active-guard enable
at `0x0801286A`. Fault ordering/recovery safety must not be inferred from these
RAM-only probes, and the reconstructed order has not been silently changed.

ROM descriptors at `0x0801DE24 + 28*n` provide 128/256/384/512 KiB profiles,
all with four-byte program units. These are available software profiles, **not
identification of physical capacity**. Original sector helpers independently
return sector 3 offset `0xC000`, size `0x4000` for each profile:

| Software region | Range |
|---|---|
| Configured 8192-byte backing | `[0x0800C000, 0x0800E000)` |
| Entire sector containing it | `[0x0800C000, 0x08010000)` (16384 bytes) |
| Same-sector tail, outside backing budget | `[0x0800E000, 0x08010000)`; contents unknown, not independently erasable |

The application's UF2 starts at `0x08010000`; it cannot establish contents of
these lower-flash regions or bootloader/recovery compatibility. Never assume
the same-sector tail is safe for unrelated data.

The additional **347 original-Thumb cases** comprise 195 captured program
requests, 144 RAM-backed reads and eight ROM sector-helper probes. Driver
objects/vtables are synthetic; program callbacks stop before their first
instruction and descriptor callbacks return controlled objects. No actual
flash initialization, unlock/lock, erase, program, fault handler, full replay,
power-loss recovery or migration executes. Physical hardware remains untested.

```sh
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_backing.py -v
```

### EEPROM prefix and startup validity gates (no initialization execution)

[`prefix-abi-audit.json`](prefix-abi-audit.json) checks five hash-pinned files
from the same candidate revision. Its packed `eeprom_core_t` is **37 bytes**;
default zero keyboard/user extension sizes, three VIA magic bytes, one layout
byte and zero custom-config bytes derive keymap start **`0x29`** without forcing
that base. Seven observed original accesses agree with reference offsets/sizes:

| Reference label (not recovered manufacturer symbol) | Offset | Bytes |
|---|---:|---:|
| Core magic | `0x00` | 2 |
| Debug | `0x02` | 1 |
| Default layer | `0x03` | 1 |
| Keymap config | `0x04` | 2 |
| Keyboard config | `0x0F` | 4 |
| User config | `0x13` | 4 |
| RGB matrix config | `0x17` | 8 |

The reference has ten other core fields whose original semantics are **not**
proved here, including an overlapping LED/RGB union and tail fields. Host C and
ARM static assertions check all 17 reference field offsets/sizes. ARM Clang warns
about the intentionally unaligned anonymous union in this **offsetof-only dummy
type**; only that layout probe uses `-Wno-error=unaligned-access`, retaining the
warning. The nine recovered C models themselves compile with strict `-Werror`.
No instance of that reference packed type is dereferenced by the probe.

Original `0x0801AE04` accepts exactly **`4B F4 29` at `[0x25,0x28)`**, with
short-circuit byte reads. Reference Vial uses **BUILD_ID low 24 bits**, not its
non-Vial build-date branch. Thus the observed low 24 bits are **`0x29F44B`**;
the high byte and the candidate's actual generated BUILD_ID are unknown here.
This is not a Git revision, serial number, UID or general schema fingerprint.
Layout options occupy one byte at `0x28`.

Two separately observed startup slices matter:

- `0x08018B5C..0x08018B66`: invalid VIA stamp calls VIA initialization
  `0x0801AE2E`, regardless of core magic.
- `0x08018BBC..0x08018BCE` (branch at `0x08018C22`): core magic other than
  `0xFEE3`, **or** invalid VIA stamp, calls core initialization `0x080143E4`.

**A changed build stamp can enter factory-initialization paths at boot even if
addresses match. Do not merely pin the old stamp to bypass initialization before
full storage compatibility is proved.** No build-stamp policy or migration is
implemented by this increment.

The oracle covers 766 distinct stamp inputs (valid plus every single-byte
replacement), and 64 core/stamp/unrelated-byte combinations for the two gates
and layout read. Byte/word reads return controlled input. Initialization entries
are intercepted **before their first instruction**. These are independent slices:
the later slice does not simulate effects of initialization from the earlier one.
No boot, EEPROM backend, flash erase/write or initialization body is executed.

```sh
reference=$(mktemp -d /tmp/fave40h-reference-prefix.XXXXXX)
revision=dd43959ae5c08d8a28d38a1acf7b04e86b14a344
for path in quantum/eeconfig.h quantum/via.h quantum/via.c \
  quantum/nvm/eeprom/nvm_eeprom_eeconfig_internal.h \
  quantum/nvm/eeprom/nvm_eeprom_via_internal.h; do
  curl -fsSL "https://raw.githubusercontent.com/vial-kb/vial-qmk/$revision/$path" \
    -o "$reference/${path##*/}"
done
python3 reverse-engineering/tools/audit_original_prefix.py \
  firmware/origin/FAve40H_VIAL.uf2 --reference-dir "$reference" \
  --check reverse-engineering/original-vial/prefix-abi-audit.json
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_prefix_abi.py -v
```

The tool is offline, refuses unknown source hashes and existing export files.
This is a compatible **reference prefix profile**, not proof of every original
core field, exact manufacturer build configuration, flash backing, reset-body
equivalence, migration, live EEPROM contents or safe reuse of settings.

### Reference QMK settings ABI audit (scoped, not a source-version identification)

[`settings-abi-audit.json`](settings-abi-audit.json) compares the original
**40-byte QS region only** with public Vial-QMK revision
`dd43959ae5c08d8a28d38a1acf7b04e86b14a344`. That revision is a candidate reference,
not the identified manufacturer revision.

The original prototype table at `0x0801E3D4` has 26 ARM32 records of 20 bytes.
Its setting IDs, field offsets/sizes, bit positions, getter/setter grouping and
notification grouping match the reference profile: QMK settings enabled, normal
mouse keys enabled, `MK_3_SPEED` disabled. The reference's 23 uint8/uint16 fields
occupy 40 bytes; all offsets are also checked with host C `offsetof`/`sizeof`.

Examples: tapping term is offset 24, tap delay 30, Caps Lock tap delay 32,
quick-tap term 36 and flow-tap term 38. Setting 21 is a custom magic/config
accessor, **not a field in those 40 bytes**. The four tapping bits share byte 29.
Field names come from the reference header, not recovered manufacturer symbols.

The original reset prefix `0x080144DC..0x08014524` is bounded-decoded and checked
against four original-instruction executions with distinct initial RAM canaries.
It writes 39 bytes and deliberately **preserves byte 35** (`unused` in the
reference), just as the reference reset does not assign that field. Emulation
stops **before** EEPROM save, keyboard clear and callbacks.

| Build setting inferred from original reset | Original value | Reference-header default checked here |
|---|---:|---:|
| `TAP_CODE_DELAY` | **0** | **10: must override for this reference** |
| `TAP_HOLD_CAPS_DELAY` | 80 | 80 |
| `TAPPING_TERM` / quick-tap term | 200 | Defined elsewhere; not established by this header audit |
| `ONESHOT_TIMEOUT` | 5000 | 5000 |
| `ONESHOT_TAP_TOGGLE` | 5 | 5 |

The report lists the other required macro values (mouse keys, combo and auto
shift) without assuming unchecked defaults from other headers. Structural match
means the typed region/prototype/reset assignment shape matches **with the
reported build values**. It does not mean a default build already matches.
Callback bodies, the complete initial EEPROM fields, dynamic-record ABIs, flash
backing/migration and live device settings are not validated by this audit.

To reproduce without installing or checking out QMK:

```sh
reference=$(mktemp -d /tmp/fave40h-reference-settings.XXXXXX)
revision=dd43959ae5c08d8a28d38a1acf7b04e86b14a344
for name in qmk_settings.h qmk_settings.c; do
  curl -fsSL "https://raw.githubusercontent.com/vial-kb/vial-qmk/$revision/quantum/$name" \
    -o "$reference/$name"
done
python3 reverse-engineering/tools/audit_original_settings.py \
  firmware/origin/FAve40H_VIAL.uf2 \
  --header "$reference/qmk_settings.h" --source "$reference/qmk_settings.c" \
  --check reverse-engineering/original-vial/settings-abi-audit.json
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_settings_abi.py -v
```

The auditor itself is offline and verifies exact SHA-256 hashes of both reference
files and the original firmware. `--export /new/report.json` refuses overwrite.
Unit tests use the stored source fingerprint/facts without network access; a
source re-fetch is needed for the complete independent report reproduction.

### Serialized dynamic records and logical-region audit

[`records-abi-audit.json`](records-abi-audit.json) compares the four record types
in the same pinned candidate's `vial.h` and evaluates its EEPROM region macros
from `quantum/nvm/eeprom/nvm_dynamic_keymap.c`. Both source hashes are checked.
This is **size/region compatibility under an explicit profile**, not proof of
all original runtime field meanings or persistence compatibility.

| Record | Original entries × bytes | Reference default at 4096 bytes | Original reset template interpreted using reference fields |
|---|---:|---:|---|
| Tap dance | 16 × 10 | **32** | Four zero keycodes, custom tapping term 200 |
| Combo | 16 × 10 | **32** | Four zero inputs, zero output |
| Key override | 16 × 10 | **32** | Zero trigger/replacement/modifiers, layers `0xFFFF`, options `0x07` (reference enabled bit `0x80` remains clear) |
| Alt repeat | 32 × 6 | 32 | All zero |

For this 4096-byte reference profile, explicitly set
`VIAL_TAP_DANCE_ENTRIES=16`, `VIAL_COMBO_ENTRIES=16` and
`VIAL_KEY_OVERRIDE_ENTRIES=16`. Otherwise the reference's automatic counts move
the macro start from the original **`0x471` to `0x651`** and reduce macro capacity
from 2959 to 2479 bytes. This does not prove which manufacturer macros produced
the original counts.

The audit uses four layers, 4×12 cells, zero encoder storage, 40 QS bytes and the
**explicit original keymap base `0x29`**. It does not yet independently derive the
candidate's default VIA/eeconfig prefix; the separate prefix audit above now
checks a matching default profile. With the recovered counts, the evaluated
candidate intervals exactly match `[0x1D1,0x271)`, `[0x271,0x311)`,
`[0x311,0x3B1)`, `[0x3B1,0x471)` and the remaining macro region.

`recover_original_vial.py` now bounded-decodes the four original stack-template
initializers and loop bounds/strides. Four independent Thumb executions of
`0x08015880..0x08015916` record **80 write intents each**, from different stack
canaries, and agree byte-for-byte with that decoder. Only stack assignments and
loops execute: `0x0801D570` is intercepted before persistence. Earlier keymap/QS
reset and unlock operations, later relock and the EEPROM backend are not run.
Host C checks all reference field offsets/sizes and template bytes; freestanding
ARM C static assertions also check the layouts. Records are little-endian ARM
byte templates, unlike the separate big-endian dynamic-keymap keycodes.

```sh
reference=$(mktemp -d /tmp/fave40h-reference-records.XXXXXX)
revision=dd43959ae5c08d8a28d38a1acf7b04e86b14a344
curl -fsSL "https://raw.githubusercontent.com/vial-kb/vial-qmk/$revision/quantum/vial.h" \
  -o "$reference/vial.h"
curl -fsSL "https://raw.githubusercontent.com/vial-kb/vial-qmk/$revision/quantum/nvm/eeprom/nvm_dynamic_keymap.c" \
  -o "$reference/nvm_dynamic_keymap.c"
python3 reverse-engineering/tools/audit_original_records.py \
  firmware/origin/FAve40H_VIAL.uf2 --header "$reference/vial.h" \
  --nvm-source "$reference/nvm_dynamic_keymap.c" \
  --check reverse-engineering/original-vial/records-abi-audit.json
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_records_abi.py -v
```

Stored reference facts support offline unit tests; independent report reproduction
requires the exact public files. Macro evaluation allows only integer arithmetic
and named object macros for this hash-bound, enabled-feature profile, not arbitrary
C or Python execution. Flash backing, migration, live settings, record dispatch
semantics and whole-reset equivalence remain unverified.

### Custom key recovery boundary

The original dispatcher has custom codes `0x7E00..0x7E15`. Cases
`0x7E01..0x7E0E` pass explicit hold-modifier/tap-modifier/tap-key arguments to
shared helper `0x0801D4C8`. Those arguments are decoded and exported as C.
They cover modifier/braces, modifier/angle-brackets, Ctrl/Caps and Ctrl/Enter.
`cadet_model.c/.h` now also reconstructs the **helper's** shared state and
ordered call intents:

- Press replaces one shared `last_modifier` byte at `0x20001CED` and uint16
  timestamp at `0x200051BC`, then registers the hold modifier. There is no
  separate state for each custom key.
- Release taps only when `last_modifier == hold_modifier` and
  `uint16(now - pressed_at) < tapping_term`. Equality is **hold**, not tap;
  subtraction wraps at 65536 ms. For these vendor codes, the original term
  getter reads the configured uint16 at settings `+0x18` (`0x200011E0`), not
  the tap-dance-specific path. The model does not invent a fixed term value.
- A quick release with a different tap modifier unregisters the hold modifier,
  conditionally registers the tap modifier, taps the key, then conditionally
  unregisters the tap modifier—in that order. `KC_TRNS` (`1`) is not treated
  as a modifier for Ctrl/Caps and Ctrl/Enter.
- Release leaves **both shared state fields unchanged**. A later press with the
  same hold modifier can replace the timestamp even if its tap key differs.
  The model preserves these helper semantics rather than adding per-key/latch state.
- The reset primitive at `0x08017346..0x08017350` clears only `last_modifier`,
  not the timestamp, and does not itself unregister a modifier. It is exported
  as an **explicit** operation, not automatically applied to every other key.

The emulator executes the original vendor argument-setup cases and helper,
including its real term getter. Clock return values are supplied at
`0x0801B374`; calls to modifier register/unregister and `tap_code` at
`0x08013F74`/`0x08014098`/`0x08014188` are recorded and returned from without
executing HID or delay internals. Those cases match the cadet helper's ordered
**intents**, not complete reports or electrical timing. Separate expanded cases
now continue through the actual tap wrapper and delay arithmetic described below.

#### Built-in keys and the interruption boundary

The seven built-in keys are decoded from the original TBB table at `0x0801665A`
and their Thumb argument-setup cases. They call the **same helper and shared
state** as the 14 vendor keys:

| Keycode | Hold modifier | Tap modifier | Tap key |
|---|---|---|---|
| `0x7C18` | Left Ctrl | Left Shift | `9` (`0x26`) |
| `0x7C19` | Right Ctrl | Right Shift | `0` (`0x27`) |
| `0x7C1A` | Left Shift | Left Shift | `9` |
| `0x7C1B` | Right Shift | Right Shift | `0` |
| `0x7C1C` | Left Alt | Left Shift | `9` |
| `0x7C1D` | Right Alt | Right Shift | `0` |
| `0x7C1E` | Right Shift | None (`KC_TRNS`) | Enter (`0x28`) |

`original_vial_cadet_core_stage()` models code beginning at `0x08016646`
**only if that stage is actually reached**. A built-in key consumes the stage
and runs the helper; another key's press clears `last_modifier`, whereas its
release does not. Neither default path changes the saved timestamp. Tests stop
press defaults at `0x08017350` immediately after the reset, and release defaults
at `0x080174D4` before later handlers. Those later handlers are not implemented
by the model. The function's boolean means built-in consumed vs stage continued,
not the original firmware's full `process_record` return value.

The earlier vendor switch at `0x08015E96` is materially different: original
execution confirms that **Backspace/Delete and all six RGB controls return at
`0x08015C6E` without visiting the core stage/reset**, on both press and release.
Do not route these events into `original_vial_cadet_core_stage()` afterward.
The destructive `0x7E0F` erase/reboot path is excluded from these execution tests.

The model does not decide whether every arbitrary event reaches the core stage:
prior feature hooks, tapping/override processing and other early exits are not
reconstructed as a whole. HID/report side effects and real sleeping/scheduling
remain outside it; tap-delay selection/arithmetic is now modeled separately.
Upstream `perform_space_cadet` is a semantic reference, not proof of the exact
source revision or full integration equivalence.

### Tap-code delay and ordered boundary calls

The original wrapper at `0x08014188` selects a uint16 millisecond delay from
settings `0x200011C8`: **Caps Lock (`0x39`) uses `+0x20`**, all other 8-bit tap
keycodes use `+0x1E`. The body at `0x08014148` always calls, in order:

1. Register code (`0x08013F88`).
2. Sleep (`0x0801B464`) with **1 scheduler tick if delay is zero**, otherwise
   `(uint64(delay_ms) * 100000 + 999) / 1000` ticks.
3. Unregister code (`0x080140AA`).

Zero is **not** a skipped wait or an assumed 1 ms wait. The binary's 100000 Hz
software conversion makes one tick nominally 10 µs; actual tick rate and wall-clock
waiting have not been measured. Nonzero integer millisecond settings convert to
100 ticks per millisecond. Values around 42949/42950 and 65535 ms exercise the
64-bit intermediate; do not replace the multiplication with overflowing uint32
arithmetic.

`tap_model.c/.h` returns this three-call trace as data. The independent emulator
executes the actual wrapper, multiplication and 64-bit division, intercepting only
register/unregister and sleep entry points. An all-256-key sweep and delay edges
check selection/order/conversion. Another 21 cases execute the vendor/built-in
cadet setup, helper **and tap wrapper together**, then compare them with the
composition of the two C models. HID report generation, the scheduler, real
waiting, and electrical timing are still **not executed or reconstructed** here.

The following **partial, RAM-only** behaviors are now exported and checked
against original instruction execution; they are not a complete `process_record`
implementation:

- `0x7E00`: press registers Backspace (`0x2A`) or Delete (`0x4C`); release
  unregisters the key selected by the **current** shift-edge byte. That byte is
  overwritten on each ordinary left/right Shift event, not computed from the
  aggregate modifier mask. Releasing either Shift clears it even if the other
  remains held. Changing it between custom-key press/release can select a
  different key on release. These original quirks are preserved, not fixed.
- `0x7E10..0x7E12`: switch RGB toggle/on/off; `0x7E13..0x7E15`: underglow
  toggle/on/off. Press only, release does nothing. Toggle uses bytewise XOR 1,
  not logical negation. These cases write two RAM bytes at `0x20001EE4`; they
  do not themselves write EEPROM. Startup loads that word from EEPROM `0x13`.
- `0x7E0F`: verified press path calls settings initialization `0x080143E4`,
  then non-returning reboot `0x08013ECC`. Its destructive side effects and
  reset are **not executed or implemented** by the model or emulator tests.

The reboot function never returns: naively decompiling it as returning makes
settings-clear appear to fall through into an RGB toggle. The Ghidra inspection
script annotates that verified fact so false control flow is not taken as source.

The original factory keymap includes `0x7C00` (bootloader request). It is kept
as evidence in a data array, not advertised as safe to execute on a new port.

## Reproduce the recovered source/data

From the repository root:

```sh
python3 reverse-engineering/tools/recover_original_vial.py \
  firmware/origin/FAve40H_VIAL.uf2 --check reverse-engineering/original-vial
python3 -m unittest discover -s reverse-engineering/tests \
  -p test_original_vial_recovery.py -v
```

For an independent NEW output directory, use `--export /path/to/new-directory`.
The tool refuses existing output directories, unknown images, the eight-layer
build, and the VIA build. It never writes to the firmware input.

Tests compile the portable C models with host `cc -std=c11 -Wall -Wextra
-Werror` and compare all 192 addresses, the full 384-byte reset, 14 cadet
parameter sets, LED data and initialization. The independent fixture
[`original-vial-emulation.json`](../tests/fixtures/original-vial-emulation.json)
is produced by executing original Thumb instructions, not the recovered C:
51 PWM encoding vectors (including walking bits at both ends), 48 RGB-control
cases, 8 shift-edge cases, 8 Backspace/Delete selections, 25 group-filter
chunks, **196 vendor cadet decision/ordered-intent cases**, 4 cadet reset cases,
**98 built-in cadet cases**, 16 reached-core default press/release cases, and
14 earlier vendor-bypass cases, **272 tap-code cases**, and **21 expanded
cadet-through-tap traces**, plus **4 QS RAM-reset prefixes** and **4 dynamic-record
reset slices (80 captured write intents each)**, **766 prefix-validity inputs**
and **64 independent prefix gate/layout cases**, plus **16 consolidated snapshot
load/hash/clear cases**, **111 one-entry journal cases** and **347 backing
word/intent/geometry cases**, **six RAM-redirected GPIO writer cases** and
**13 bounded RGB group-word reset/load cases** (captured EEPROM calls only),
**256 RGB limits helper inputs** and **24 bounded Caps/filter composed chunks**.
The original normal RGB spans are 15/15/15/15/12 LEDs. Final-chunk Caps white
LED22 survives filtering [60,72) even with keylights disabled; this observed
ordering is preserved as a golden reference, not silently corrected. Composed
cases use controlled host LED reads/setters, not full effects or physical LEDs.
The cadet cases cover all 14 vendor keys, press/state overwrite, equal/below/
above term, interruption/mismatching modifiers, uint16 wrap, and terms 0, 1
and 65535; the same scenarios also exercise all seven built-in keys through
actual table dispatch. Core-default tests include native-range neighbors and
release paths; bypass tests enforce that the core/reset/destructive boundaries
are not entered. Host-compiled C must match these scoped outputs. PWM tests deliberately
seed a nonzero reset-tail canary to verify that encoding leaves it untouched.

Freestanding ARM compilation was also checked separately:

```sh
out=$(mktemp -d /tmp/fave40h-original-arm.XXXXXX)
for name in factory_defaults vendor_parameters rgb_model cadet_model tap_model; do
  clang --target=arm-none-eabi -mcpu=cortex-m4 -mthumb -ffreestanding \
    -std=c11 -Wall -Wextra -Werror -c \
    "reverse-engineering/original-vial/$name.c" -o "$out/$name.o"
done
file "$out/"*.o
```

These are ARM **relocatable objects**, not linked QMK firmware. Neither host tests,
ARM compilation nor selected instruction emulation proves full firmware correctness,
persistent-storage compatibility, electrical behavior or flash safety.

### Reproduce original Ghidra inspection

After the Python checker accepts the original image:

```sh
work=$(mktemp -d /tmp/fave40h-original.XXXXXX)
python3 reverse-engineering/tools/extract_uf2_bin.py \
  firmware/origin/FAve40H_VIAL.uf2 "$work/original-vial.bin"
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  "$work" original-vial -import "$work/original-vial.bin" \
  -loader BinaryLoader -loader-baseAddr 0x08010000 \
  -processor ARM:LE:32:Cortex -cspec default \
  -analysisTimeoutPerFile 120 -max-cpu 2 \
  -scriptPath "$PWD/reverse-engineering/tools" \
  -postScript InspectOriginalVial.java > "$work/inspection.log" 2>&1
# Headless can exit zero despite a post-script exception: inspect both checks.
grep 'ORIGINAL_INSPECTION_COMPLETE' "$work/inspection.log"
! grep 'ERROR' "$work/inspection.log"
```

The script binds itself to the ORIGINAL payload hash, explicitly seeds known
instruction boundaries that raw-binary auto-analysis misses, annotates the
verified non-returning reset functions in the analysis database, and prints
instruction evidence and selected pseudocode. It does not alter executable
bytes. Decompiled names and prototypes are not original source names or ABIs.

### Reproduce original-instruction execution

Using the project created above (Ghidra 12.1.4 was used):

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  "$work" original-vial -process original-vial.bin -noanalysis -readOnly \
  -scriptPath "$PWD/reverse-engineering/tools" \
  -postScript EmulateOriginalVial.java \
  "$PWD/reverse-engineering/tests/fixtures/original-vial-emulation.json" --check \
  > "$work/emulation.log" 2>&1
grep 'ORIGINAL_EMULATION_COMPLETE' "$work/emulation.log"
! grep 'ERROR' "$work/emulation.log"
```

Without `--check`, the script writes a **new** fixture and refuses overwrite.
It checks the original payload hash, uses a bounded instruction budget, and
stops dispatcher slices before epilogues. Cadet cases execute the vendor setup
and complete helper control flow, substituting a controlled clock return and
recording/returning from HID intent boundaries. Other slices stop before HID calls.
Tap-code cases and expanded cadet-through-tap cases execute the actual delay
selection/arithmetic, recording and returning from the HID/sleep boundaries.
Prefix cases stub storage reads and intercept initialization entries before
executing their bodies; they do not execute boot or initialization. QS reset
cases execute RAM assignments only and stop before the first EEPROM save. They do not reset persistent settings. The script does **not** emulate boot,
USB reports, real waiting or the scheduler,
physical EEPROM/flash, the complete journal replay loop, peripheral registers, real clock/DMA
timing, or the full pipeline that
determines whether an event reaches the core stage.

## Remaining work toward the user's goal

1. **Finish runtime integration**: reconstruct the earlier feature/tapping/override
   gates that determine core-stage reachability; integrate real HID/report/scheduler
   semantics, clear/reset side effects, and RGB effects/task/PWM/DMA initialization.
   Tap-code delay arithmetic and ordered call boundaries are recovered separately.
   Shared vendor/built-in cadet state and reached-core interruption behavior now
   bind to the actual candidate helper through selected KB/Space Cadet stages;
   intervening feature gates, physical output and complete firmware remain unverified.
2. **Complete upstream compatibility comparison**: the QS region/prototype/reset
   shape matches the pinned candidate with recorded build macros; serialized
   record sizes/regions match with explicit 16/16/16/32 counts.
   The default prefix profile and seven original accesses also match, with a
   build-stamp-triggered initialization risk explicitly recorded. Next compare
   complete journal replay and physical backing, reset/migration behavior and
   remaining runtime field semantics. Snapshot hash/load/clear, bounded single-entry
   decoding, backing word transform/intents and software sector geometry are
   recovered in isolation, not complete EEPROM recovery or physical validation.
   The candidate is still not the recovered manufacturer revision.
3. **Assemble an original-four-layer QMK board target** preserving the recovered
   behavior, USB, memory map and settings layout; compile for ARM and inspect it.
4. **Validate hardware/recovery separately**: MCU marking, independent loader
   entry/backup, persistent-storage safety, then explicitly approved device tests.

Do not replace these gates with a successful host test or a decompiler result.
The eight-layer audit and the previous six-layer source remain separate work.

References for interpretation:
[QMK/Vial dynamic keymaps](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/dynamic_keymap.c),
[space-cadet implementation](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/process_keycode/process_space_cadet.c),
[keycode ranges](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/quantum/keycodes.h),
[PWM WS2812 reference](https://github.com/vial-kb/vial-qmk/blob/dd43959ae5c08d8a28d38a1acf7b04e86b14a344/platforms/chibios/drivers/ws2812_pwm.c).
The reference's driver structure is useful, but its current byte-buffer details
are not substituted for the original's recovered 32-bit DMA words; this is not
proof that the original was built from that revision.
