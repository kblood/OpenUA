# Pool of Radiance GEO-load capture aid

**Status: capture aid, not a capture. `playable: false`. `mappings: []`. No DOSBox-X run was made by this aid.**

**Correction (2026-11-18): the routine at `GAME.OVR:0x2F6FF` is not the GEO loader.** START stub 6
(`0x3E0C`, proc `0x0E08`) enters it, and it builds `WALLDEF<d>.dax`: the WALLDEF wrapper. The aid no
longer targets it. Its owner targets are now the **GEO fill at `GAME.OVR:0x2F9BE`** (group-relative
`0x10C7`), which reads the GEO literal at `0x2F994`.

**Entry status: UNESTABLISHED.** The pinned bytes give one candidate entry, START stub 7 (`0x3E11`,
`CD 3F C7 10 27`), whose proc word lands on the fill. Its fifth byte (`0x27`) is undecided and the RAM
dumps record `0x00` there. The entry is established only by an observed stop at the fill in a run, and
then only for that run.

Tool: `tools/por_geo_capture_aid.py` (`plan`, `check`), schema version 2. Tests:
`tests/test_por_geo_capture_aid.py` (84 synthetic tests, plus one retail anchor that runs only when
`OPENUA_POR_INSTALL` is set; 85 pass with it).

Companions: [por-area-evidence.md](por-area-evidence.md) (the layout probe that first located `0x2F6FF`,
now identified as the WALLDEF wrapper), [por-geo-buffer-fill-probe.md](por-geo-buffer-fill-probe.md) (the
fill's body), [por-ecl-21-stub7-dump-probe.md](por-ecl-21-stub7-dump-probe.md) (stub 7 against the RAM
dumps), [por-stub-tail-byte.md](por-stub-tail-byte.md) (the undecided tail byte), and
`tools/por_runtime_capture_plan.py` (the emulator pin and the DOSBox-X binary check, reused here).

## The question

Which TOC block of a `GEO<n>.DAX` archive does a GEO load read, and what routine performs that load?
The candidate GEO reader is the GEO fill at `0x2F9BE`. The owner entry, post-frame and exit below are
the **fill's**, and the one argument is its byte `[bp+6]`. That byte is recorded as a byte. Its meaning
is unresolved, and this aid does not assume one, and it does not turn a block into an area.

## What is verified and what is not

| Item | Status | Evidence |
| --- | --- | --- |
| GEO fill prologue `55 89 E5` at `0x2F9BE` | static, retail | `static_checks`, pinned GAME.OVR |
| `0x2F9C1` is an instruction boundary: `81 EC 10 01` (`sub sp,0x110`, a 272-byte frame) | static, decoded | `por_loadpieces_handler.linear` |
| `mov al,[bp+6]` = `8A 46 06` at `0x2FA09` (the one byte argument; also at `0x2FAE9`) | static, retail bytes | `static_checks` (`arg_bp6_read`) |
| Single exit: a linear walk from `0x2F9BE` (stop at return) reaches `0x2FAFA` as its only return; `retf 2` = `CA 02 00` | static, decoded (124 instructions) | `static_checks` (`fill_exit_is_single`, `retf_2`) |
| No `[bp+8]` read in the fill (no `46 08`, `7E 08`, `76 08` in the body) | static, retail bytes | byte scan of `0x2F9BE..0x2FAFD` |
| Group 29 covers `0x2F9BE` (seek `0x2E8F7`, size `0x120B`) | **candidate**, GoldBox runtime map, one snapshot | `GoldBox/docs/engine/research/pool-runtime-overlay-map.md` |
| START owner header `0x3DD7`: fileofs `0x2E8F7`, codesz `0x120B`, nstubs `8` | static, retail bytes | `geo_entry_candidate` |
| START stub 7 at `0x3E11`: `CD 3F C7 10 27`, proc `0x10C7` (`0x2E8F7 + 0x10C7 = 0x2F9BE`) | **static candidate**; tail `0x27` undecided | `geo_entry_candidate` |
| Stub 7 tail `0x27` (siblings 0..6 hold `0x00`) | **undecided**: not shown to be corrupt, not shown to be a field | [por-stub-tail-byte.md](por-stub-tail-byte.md) |
| RAM dumps at stub 7 | tail `00`, not `27`; the 16-byte window does not match | [por-ecl-21-stub7-dump-probe.md](por-ecl-21-stub7-dump-probe.md) |
| **GEO fill entry (a runtime stop at `0x2F9BE`)** | **UNESTABLISHED**, unobserved | none in the repo |
| Destination segment (`23A5`, snapshot 7; `33E7`, the 2026-11-17 run) | **route- and run-specific**; neither is a rule | GoldBox map; [por-geo-run-capture-2026-11-17.md](por-geo-run-capture-2026-11-17.md) |
| DOSBox-X binary present, pin matches | static (file read, not run) | SHA-256 `3f548183…4d509` |
| Debugger command forms `BP`, `BPINT`, `BPLIST`, `BPDEL`, `D`, `RUN` | grounded by GoldBox scripts and binary strings | see below |
| Register command `R` and the stack form `D SS:<value>` | **not grounded**; check with HELP | none |
| Any runtime hit of the fill, its caller, or a GEO seek | **none** | — |

### Corrections to the earlier notes

1. **Group.** `por-area-evidence.md` says the owner's overlay group is "uncovered" by the OpenUA
   START.EXE stub scan. The GoldBox runtime overlay map places `0x2F9BE` (and the GEO literal `0x2F994`)
   inside descriptor 29, seek `0x2E8F7`, size `0x120B`. The aid uses the GoldBox group as a
   **candidate**, and START stub 7 is the only static byte evidence that names the fill.
2. **Argument width.** The area note writes `cmp [bp+6],1` for the WALLDEF wrapper. For the fill the
   byte is read by `mov al,[bp+6]`. The aid records the argument word and its low byte, and does not
   interpret them.
3. **Identity.** Earlier notes, and version 1 of this aid, called `0x2F6FF` the GEO-load routine. It is
   the WALLDEF wrapper: START stub 6 enters it, and it builds `WALLDEF<d>.dax`. Version 1 observations
   are refused (see the schema section), because they were recorded against the wrong routine.

## Address translation

For a group loaded from file offset `seek` into `load_seg:buffer_off`, the file byte at `seek` sits at
`buffer_off` in that segment. So:

```
CS:IP = load_seg : buffer_off + (file_off - seek)        # file_off must be in [seek, seek + size)
```

- `file_to_cs_ip` refuses an offset outside the group, a segment or offset word out of range, and a
  result that would pass `0xFFFF` (the load would not hold the byte).
- `cs_ip_to_file` is the inverse for an observed stop. It refuses a segment other than the observed
  load segment, an IP below the buffer, and an IP past the group.
- The retail translations with `load_seg = 23A5`, `buffer_off = 0`: fill entry `23A5:10C7`, post-frame
  `23A5:10CA`, argument read `23A5:1112`, retf `23A5:1203`. With the 2026-11-17 placement (`33E7`) the
  entry is `33E7:10C7`. These are CANDIDATES until the load segment is observed.
- The WALLDEF wrapper translates to `23A5:0E08` (file `0x2F6FF`). It is refused as an owner stop
  (`test_walldef_wrapper_stop_is_refused_as_the_geo_fill`) and is never emitted as a breakpoint.

The `(file_off - seek)` model assumes the buffer holds the group's first byte at `buffer_off`. The
observation carries `dest` (the read's destination) and a dump of its first bytes, and `check` compares
the dump with the retail file. A match confirms the model for that run. A mismatch is a refusal.

## Subcommands

### `plan`

```sh
python tools/por_geo_capture_aid.py plan --install "PATH/TO/POOLRAD" \
    [--load-seg 23A5 --buffer-off 0000] [--dosbox PATH/TO/dosbox-x.exe] \
    [--debugger-helper PATH/TO/DosboxDebuggerInput.exe] \
    -o data/work/por-geo-capture-aid
```

Writes four files (deterministic: sorted keys, no timestamps, no absolute paths):

| File | Content |
| --- | --- |
| `por_geo_capture_aid.json` | schema `openua.por-geo-capture-aid`, targets, install checks, the static entry candidate (`geo_entry_static`), TOC table, emulator and helper inspection |
| `por_geo_capture_checklist.md` | the evidence required, stop rules, the observation procedure |
| `por_geo_capture_dosbox_commands.txt` | the debugger command template (never executed) |
| `por_geo_capture_observation.template.json` | the blank observation to fill from a run |

Without `--load-seg`, the breakpoint lines are **blocked comments**. The tool emits no CS:IP at all.
With `--load-seg`, the three fill breakpoints are emitted and each is labelled `[UNVERIFIED]`.

With `--install`, the plan refuses a pin mismatch (exit 2) and a failed static check (exit 2). It lists
the absolute seek offset of every TOC block of GEO1..8.DAX (29 blocks on the retail install).

`--dosbox` (or `POR_DOSBOX_X_EXE`) is read as bytes: presence, SHA-256, pin match, and the presence
of `BPINT`, `BPLIST`, `BPDEL` and `Breakpoint` in the binary. It is never executed.

### `check`

```sh
python tools/por_geo_capture_aid.py check --observation OBS.json \
    [--install "PATH/TO/POOLRAD"] -o data/work/por-geo-capture-aid/check
```

Checks one observation JSON and writes `por_geo_capture_check.json` and a short report. Exit codes:

| Exit | Meaning |
| --- | --- |
| 0 | every item is present and consistent (dump matched, fill stop matched, GEO seek is a TOC block start) |
| 1 | consistent so far, with blockers (for example no install, no fill stop, no GEO seek) |
| 2 | named refusal: a bad field, a translation refused, a contradiction, a pin mismatch, a version-1 observation, or unsafe output |

## Observation schema (`openua.por-geo-capture-observation`, version 2)

All hex values are strings: `"0x2E8F7"` or `"2E8F7"`. Words are 16-bit, segments are 4 hex digits.
Version 1 (which targeted the WALLDEF wrapper) is refused with a message naming the change.

| Field | Required | Meaning |
| --- | --- | --- |
| `schema`, `schema_version` | yes | must match exactly (`2`) |
| `route` | yes | a non-empty description of the save and the key path |
| `emulator_sha256` | no | recorded, not compared |
| `retail_pins_before`, `retail_pins_after` | no | if given, must match the pins |
| `load.file` | yes | `GAME.OVR` |
| `load.seek_abs` | yes | the observed absolute seek; must equal `0x2E8F7` (group 29) |
| `load.read_count` | yes | the observed count; must be at least `0x120B` |
| `load.dest` | yes | the read's destination `SEG:OFF` (the load segment) |
| `load.dest_dump_hex` | for a confirmed load | at least 4 bytes from `D dest`; compared with GAME.OVR (needs `--install`) |
| `owner_stop.at` | for the fill stop | `owner_entry`, `post_frame` or `retf` (all three are the GEO fill's) |
| `owner_stop.cs`, `owner_stop.ip` | with `at` | must equal the translated fill CS:IP for that target |
| `owner_stop.code_hex` | with `at` | must start with the target's expected bytes |
| `owner_stop.bp`, `return_cs`, `return_ip`, `arg_bp6_word` | at `post_frame` | frame and the one argument word; the return CS:IP gives the caller |
| `dax.open_name` | for a GEO bind | `GEO<n>.DAX` |
| `dax.open_handle`, `dax.seek_handle` | for a GEO bind | must be equal |
| `dax.seek_al` | no | default `0x0`; only absolute seeks (`0`) bind |
| `dax.seek_abs` | for a GEO bind | the absolute seek; must be the exact start of a TOC block |
| `dax.read_count` | no | recorded; compared with `comp_size`, a mismatch is recorded, not refused |

The return CS:IP at `post_frame` is classified: if its segment is the observed load segment, the caller
is in group 29 and its file offset is given. Otherwise the caller is reported as outside the group, and
its segment is not interpreted.

### Claims (`check` output)

| Claim | True when |
| --- | --- |
| `load_segment_confirmed` | the observed dump matches GAME.OVR |
| `owner_stop_observed` | a stop at the GEO fill was observed and its bytes and frame check out |
| `geo_fill_entry` | `observed-in-this-run` if the fill stop is present, otherwise `unestablished` (the static stub-7 candidate never sets it) |
| `geo_seek_observed` | a GEO open and seek were observed |
| `toc_seek_is_block_start` | the observed absolute seek is the exact start of a TOC block (a fact about the seek only) |
| `toc_block_bound` | `toc_seek_is_block_start` AND `owner_stop_observed`, in the same run. Never from the WALLDEF wrapper |

## The evidence needed (one run, repeated once)

Steps 2 to 4 are written for the GEO fill. A stop at the fill is what establishes its entry, for that
run only. Until a stop at `0x2F9BE` (translated) is observed, `toc_block_bound` stays `false`.

1. **Overlay read.** A `BPINT 21 3F` stop on `GAME.OVR` with seek `0x2E8F7`, count `>= 0x120B`, and a
   destination `SEG:OFF`. Dump at least 4 bytes at the destination and confirm they equal the retail
   bytes at `0x2E8F7`. This confirms the load segment.
2. **Fill stop.** A stop at the translated `owner_entry` (or `owner_post_frame`) with its code bytes.
   At `post_frame`: BP, the return CS:IP, and the one argument word (`[bp+6]`).
3. **GEO open.** A `BPINT 21 3D` stop whose name is `GEO<n>.DAX`, with the handle.
4. **GEO seek.** A `BPINT 21 42` stop on that handle, AL=0, with the absolute offset in CX:DX. The offset
   must equal a TOC block start. The `plan` output lists those offsets.
5. **Repeat.** A second run with the same save and keys agrees on every value.

Only after 1 to 4 agree does `check` report `toc_block_bound: true`. Even then the result is a
**seek-to-block binding for one run**. It is not an area mapping. The aid does not check the ORDER of the
stops within a run: the fill stop and the seek are checked as observed values, and step 5 is the
repeat that makes the pairing credible.

## Debugger command grounding

| Form | Evidence |
| --- | --- |
| `BP seg:off`, `BPDEL *`, `BPINT 21 42`, `BPINT 21 3D`, `D seg:off`, `RUN` | used by GoldBox debugger scripts (PoR and CoK) |
| `BPLIST` | used by GoldBox PoR trace scripts |
| `BPINT 21 3F` | appears in two GoldBox CoK files only (`cok-m4-fidelity-plan.md`, `cok-m4-combat-breakpoint-route.ps1`); no PoR script uses it, so it is unverified for PoR |
| register command `R`, stack form `D SS:<value>` | **no GoldBox evidence**; check with the debugger's HELP first |

The DOSBox-X binary contains the strings `BPINT`, `BPLIST`, `BPDEL` and `Breakpoint` (a static
check). The GoldBox `DosboxDebuggerInput.exe` helper is present (presence and hash are reported);
it was not run, and this aid never injects input.

## Stop rules

- If `D CS:IP` at any stop does not show the expected bytes, the segment is wrong. Stop. Do not reuse
  breakpoints from another run.
- Use a temporary copy of the retail folder. Hash `GAME.OVR` and `START.EXE` before and after.
- Do not write to the install. Do not type input into an unverified debugger form.
- Do not interpret `[bp+6]`. Record it as a byte.

## PoR and CoK boundary

- Every PoR number in the tool comes from `GAME.OVR`, `START.EXE`, the PoR DAX containers, or the
  PoR runtime notes in GoldBox (`pool-runtime-overlay-map.md`).
- The CoK GoldBox material is used **only** as evidence that a debugger form exists (`BPINT 21 3F`).
  No CoK address, descriptor, route or save is used. The CoK `BPINT 16` pacing workflow is not used.
- Group 29's destination segment `23A5` is a PoR route observation. It is not a CoK value.

## Limitations

- **No runtime evidence exists in the repo.** `performed: false`. The tool cannot produce a capture;
  it only prepares one and checks one a person records.
- **The fill's entry is unestablished.** Stub 7 is the only static byte evidence that names it, its tail
  byte is undecided, and the RAM dump disagrees on the tail. Nothing here decides the tail.
- The group is a **candidate** from one snapshot. The destination is route-specific. The OpenUA
  static stub scan does not confirm group 29.
- The `(file_off - seek)` model assumes the read places the group's first byte at `dest`. `check`
  tests this only with a dump.
- A single read covering the group is assumed (`read_count >= 0x120B`). A load in pieces is refused.
- The return address is read from the stack at `post_frame`. A caller that is not in group 29 is
  reported, not identified. The fill's CALLER is not identified by this aid.
- `[bp+6]` is recorded as a byte with unknown meaning. Nothing here links it to a block.
- Nothing binds a block to an area, a start area or a start entry. `mappings` is always empty.
- The register and stack debugger forms are not grounded (see above). The checklist says so.
- The stop order within a run is not checked (see the evidence section).

## Reproduce

```sh
python -m pytest tests/test_por_geo_capture_aid.py -q
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_geo_capture_aid.py -q   # + retail anchor
python tools/por_geo_capture_aid.py plan --install "PATH/TO/POOLRAD" \
    --dosbox "PATH/TO/dosbox-x.exe" -o data/work/por-geo-capture-aid/retail
```

Last run (2026-11-18, after the retarget): `tests/test_por_geo_capture_aid.py` 84 passed and 1 skipped
without the retail anchor; 85 passed with `OPENUA_POR_INSTALL` set to the pinned install. The neighbouring
suites (`test_por_runtime_capture_plan.py`, `test_por_area_evidence.py`, `test_por_farcall_resolve.py`,
`test_por_overlay_group_map.py`) pass (103 passed, 7 skipped), as do `test_por_geo_callee_identity_probe.py`
and `test_por_stub_tail_probe.py` (56 passed, 1 skipped).
