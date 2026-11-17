# Pool of Radiance: caller stack frames at the loader call sites (observe-only)

**Status: stack-accounting-consistent-at-all-walked-sites. `playable: false`. `geo_output: not_established`. `plane2_binding: not claimed`.**

Tool: `tools/por_geo_loader_caller_frame_probe.py`. Tests: `tests/test_por_geo_loader_caller_frame_probe.py`
(23 tests: 20 synthetic with falsifiers, 3 retail-gated; all 23 pass on this run, none skipped). Read-only: it reads
the pinned `GAME.OVR` and `START.EXE` and the two pinned memory dumps, and writes only under
`data/work/por-geo-loader-caller-frame-probe/`. It refuses unpinned inputs and outputs outside `data/work` or inside
the install.

Supplements [por-geo-loader-target-probe.md](por-geo-loader-target-probe.md). That probe counted the ten pushed
bytes against the body's `retf 0x12` and called the pair a prototype conflict without modelling the caller's frame.
This probe models it. Execution is unproven; the identity of `0x0802:0x0716` with START `0x876D` is still the loader
probe's conditional identity, and this probe does not re-establish it.

## Question and answer

> At each of the ten static call sites, what is the caller's stack frame, and does the callee's `retf 0x12` fit it?

**Answer: the conflict as the loader-target probe stated it does not hold where the caller can be walked.** The
ten pushed bytes are not the whole argument block. At six sites the walk finds exactly 8 more bytes that the caller
pushed earlier and did not pop: two far pointers. At the fill site (`0x2FA17`) those two pointers are the destinations
of two `0x0AF8:0x0B0B` copy calls, which pop only their source and leave the destination on the stack. The loader's
`retf 0x12` pops those 8 bytes too, and the caller's SP lands exactly on its allocation floor. At the other five walked
sites the leftover has the same 8-byte shape (two far pointers from `lea` and `ss` pushes); the walk does not tie each
pointer to its copy call there. The four remaining sites stay unknown, for the reasons in the table below.

## Corrections to the brief's premise

- The fill's frame is not 8 bytes. It is `sub sp,0x110` (bytes `81 ec 10 01` at GAME.OVR `0x2F9C1`), so the
  allocation is 272 bytes. The `[bp-8]` in the brief is the copy cursor `mov word [bp-8],2` at `0x2FA57`, after
  the loader call, and is not one of the words the loader's bp+16/bp+20 reads.
- The fill makes no store to its own frame words before the loader call. `[bp-2]` (status) and `[bp-6]` (output
  pointer) are uninitialized until the loader writes them through the pointers passed to it. The only frame
  references before the call are `lea`s (`[bp-10]`, `[bp-267]`, `[bp-272]`).
- The conflict claim, "every caller pushes 10 bytes and the body pops 18, so the identity conflicts", assumed no
  leftover. The walked sites all have 8 leftover bytes, so that claim is withdrawn for them (see below).

## The fill site 0x2FA17: exact stack equations

Symbols: `B` = the fill's BP (GAME.OVR procedure `0x2F9BE`), `A` = allocation = 0x110 = 272, `L` = leftover bytes
at the shape start = 8, `S0` = SP before the ten shape bytes.

| Quantity | Equation | Value |
| --- | --- | --- |
| Allocation floor | `B - A` | `B - 0x110` |
| SP before shape | `S0 = B - A - L` | `B - 280` |
| Output far pointer (`bp+6` offset, `bp+8` segment) | pushed last in the shape | `S0-10`, `S0-8` |
| Status far pointer (`bp+10`, `bp+12`) | `lea [bp-2]` | `S0-6`, `S0-4` |
| Id word (`bp+14`) | `mov al,[bp+6]; push ax` | `S0-2` |
| Callee's `bp` after `push bp; mov bp,sp` | `S0 - 16` | `B - 296` |
| Callee `bp+16` (far pointer P16) | `= S0` | `B-280`: offset `B-272` (`lea [bp-272]`), segment SS |
| Callee `bp+20` (far pointer P20) | `= S0 + 4` | `B-276`: offset `B-267` (`lea [bp-267]`), segment SS |
| SP after `retf 0x12` | `S0 + 8` | `B-272` = the allocation floor |

The two pointers are the leftovers of two `0x0AF8:0x0B0B` calls at `0x2F9EA` and `0x2FA04`. Each pushes a
destination far pointer and a source far pointer, and `retf 4` pops only the source. The destination stays:

- at `0x2F9EA`, source `cs:0x109D` = Pascal `03 'GEO'`, destination `SS:B-267`;
- at `0x2FA04`, source `cs:0x10A1` = Pascal `04 '.dax'`, destination `SS:B-272`.

So the callee's first two reads are P20 = `SS:B-267` (`GEO`) and P16 = `SS:B-272` (`.dax`). Both are then copied with
`0x0AF8:0x0B25`, a Pascal copy clamped to the count word 0x14.

The mapping of each callee read to a caller address and value:

| Callee read | Caller address | Caller word | Value (static) | Initialized by |
| --- | --- | --- | --- | --- |
| `bp+16`, offset | `B-280` | `lea [bp-272]` push | `B-272` | the push at `0x2F9FE` |
| `bp+18`, segment | `B-278` | `ss` push | SS | the push at `0x2F9FD` |
| `bp+20`, offset | `B-276` | `lea [bp-267]` push | `B-267` | the push at `0x2F9E4` |
| `bp+22`, segment | `B-274` | `ss` push | SS | the push at `0x2F9E3` |
| buffer at `B-272` | `B-272..B-269` | `04 '.dax'` | `.dax` | `0x0AF8:0x0B0B` at `0x2FA04` (literal `cs:0x10A1`) |
| buffer at `B-267` | `B-267..B-264` | `03 'GEO'` | `GEO` | `0x0AF8:0x0B0B` at `0x2F9EA` (literal `cs:0x109D`) |

The values are symbolic: the offsets are `B`-relative and the segment is the stack segment, which no dump gives.

**Plausibility.** The static bytes allow the reads to be supplied through the caller frame: the caller pushes the
two pointers and fills their buffers before the call. The chain depends on `0x0AF8:0x0B0B` returning with `retf 4`.
That byte fact is in the file and places uniquely in both dumps (below). The Pascal reading of the copy is inferred
from opcodes (`lodsb`, `stosb`, `rep movsb` with CX taken from the length byte) and corroborated only by the literal
bytes, which decode to plausible names. No run shows the copy or the pointer values.

## Ten call sites

Alloc = the `sub sp` before the walk. L = leftover bytes at the shape start (pushed by the caller, not yet popped).
Balance = `8 - L` bytes above the allocation floor after the loader's `retf 0x12`.

| Image | Site | Proc | Walk | Alloc | L | Balance | P16 / P20 (offset provenance, segment SS) |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| GAME.OVR | `0x0279E` | `0x026F6` | unknown | - | - | unknown: callee `002B:002A` at `0x2700` | - |
| GAME.OVR | `0x078A6` | `0x07814` | unknown | - | - | unknown: callee `03C5:002F` at `0x7832` | - |
| GAME.OVR | `0x1EF0D` | `0x1EEAA` | walked | 282 | 8 | balanced | `lea [bp-281]` / `lea [bp-276]` |
| GAME.OVR | `0x1F0A8` | `0x1EEAA` | unknown | - | - | unknown: callee `0709:0BF5` at `0x1EF2A` (after the first loader call) | - |
| GAME.OVR | `0x1F190` | `0x1EEAA` | unknown | - | - | unknown: same callee `0709:0BF5` | - |
| GAME.OVR | `0x2E246` | `0x2E170` | walked | 296 | 8 | balanced | `lea [bp-296]` / `lea [bp-291]` |
| GAME.OVR | `0x2F767` | `0x2F6FF` | walked | 280 | 8 | balanced | `lea [bp-280]` / `lea [bp-275]` |
| GAME.OVR | **`0x2FA17`** | `0x2F9BE` | walked | **272** | **8** | **balanced** | `lea [bp-272]` / `lea [bp-267]` |
| START.EXE | `0x047E0` | `0x0478A` | walked | 288 | 8 | balanced | `lea [bp-287]` / `lea [bp-256]` |
| START.EXE | `0x07276` | `0x07245` | walked | 18 | 8 | balanced | `lea [bp-17]` / `lea [bp-12]` |

Each balanced row means `retf 0x12` consumes exactly the 8 leftover bytes, so SP ends on the allocation floor. Each
row's `target_bp16_caller_bp_rel` is `-(alloc + 8)`, and its `target_bp20_caller_bp_rel` is four more.

The walk is a linear symbolic stack model over each procedure's bytes. It tracks pushes with register provenance,
`sub sp`/`add sp`, pops, far calls (callee pops `retf K`), and near calls. Near calls matter at two walked sites
(`0x2E246` and `0x047E0`): each pushes `es; di; cs` and calls a `retf 4` routine, which consumes the pushed CS and
the 4 bytes. The branches on those paths rejoin with equal depth (checked). Any unknown callee fails the site closed.

### Why the four sites are not walked

- `0x0279E` and `0x078A6`: the far call that precedes the shape goes to a segment with no established base
  (`0x002B`, `0x03C5`). The walk stops there. Nothing about these two sites is claimed.
- `0x1F0A8` and `0x1F190`: they follow the loader call at `0x1EF0D` in the same procedure. Their walk depends on the
  loader's pop count, which is the conditional identity, and then reaches a far call to `0x0709:0x0BF5` with no base.

## Copy-routine bases (memory-present, unknown instant)

The `0x0AF8` callees use file = `0xAC76 + offset`. The copy-helper probe's positive control set this base. This
probe checks it: each of the five callees below places **uniquely** in START at the expected file offset, in both
pinned dumps (masked match with the segment-literal rule, load `0x1866`).

| Callee | File | Placement in both dumps |
| --- | --- | --- |
| `0x0AF8:0x0B0B` | `0xB781` | unique, agrees |
| `0x0AF8:0x0B98` | `0xB80E` | unique, agrees |
| `0x0AF8:0x1366` | `0xBFDC` | unique, agrees |
| `0x0AF8:0x0B25` | `0xB79B` | unique, agrees |
| `0x0AF8:0x0C10` | `0xB886` | unique, agrees |

Their `retf` counts, read from the bytes: `0x0B0B` retf 4, `0x0B98` retf 4, `0x1366` retf 12, `0x0B25` retf 10,
`0x0C10` retf 8. The loader's body at START `0x876D` reads `les [bp+20]` (`0x8774`) and `les [bp+16]` (`0x8787`)
before its first branch (`0x87D1`), and its only return is `retf 0x12` at `0x899E`.

## Name literals (title evidence)

The literals the walked sites pass to the copy helpers decode as length-prefixed names. They match the install's
file names (the install is the pinned Pool of Radiance install, which also has `POOL` in `START.EXE`):

| Site | Literals (length, text) |
| --- | --- |
| `0x1EF0D` | 3 `MON`, 3 `CHA`, 4 `.dax` |
| `0x2E246` | 3 `PIC`, 5 `FINAL`, 4 `.dax` |
| `0x2F767` | 7 `WALLDEF`, 4 `.dax` |
| `0x2FA17` | 3 `GEO`, 4 `.dax` |

The procedure at `0x1EEAA` also passes the error literal `Unable to load monster` (length 22, at `0x1EF25`). That
call appears only in the partial logs of `0x1F0A8` and `0x1F190`, which are not walked, so it is listed here, not
claimed as a walked site's call.

The install has `MON1CHA.DAX`, `PIC1.DAX`, `FINAL5.DAX`, `GEO1.DAX` and `WALLDEF1.DAX`. The decoded stems appear in
those file names, but the numeric part (`1`, `5`) is not in any literal, so how the install name is built from the
pieces is not established. START sites are not decoded: the code base of their procedures is not established.

## Evidence labels

- **File-byte.** The ten call sites; each prologue, `sub sp` and `add sp` the walk uses; each callee's `retf` count;
  the fill's pushes, `lea`s and copy calls; the near callees' `retf 4`; the literals and their Pascal reading.
- **Memory-dump, unknown instant.** The five `0x0AF8` callees placing uniquely at their expected offsets.
- **Derived.** Every stack equation above; the balance `8 - L`; the callee reads' caller addresses.
- **Not established.** Everything in the list below.

## Not established

- That the loader `0x0802:0x0716` runs, or that any of the ten callers runs, at any instant.
- That the body at START `0x876D` is the loader. This probe takes its `retf 0x12` only under the loader-target
  probe's conditional identity.
- That `0x0AF8:0x0B0B` and `0x0AF8:0x0B25` copy as inferred from opcodes. The literals corroborate the Pascal
  reading; no run shows the copy.
- What the loader writes through its output pointer, or whether that pointer names a GEO block.
- The meaning of the id word, the status `0x402`, or the name strings beyond their bytes.
- The callees of `0x002B:0x002A` (site `0x279E`), `0x03C5:0x002F` (site `0x78A6`) and `0x0709:0x0BF5` (after
  `0x1EF0D`). No base is established for any of them.
- The live stack. The dumps carry no SS or SP and are of unknown instant, so the SS-relative pointer values are
  symbolic.
- Plane 2 binding, any consumer of a buffer, or any area or descriptor mapping.

## Next discriminating observations

The probe lists these as `next_discriminating_observations` in its JSON.

1. A live capture at the fill call (GAME.OVR `0x2FA17`), before the loader shape: the words at `SS:(BP-280)`
   to `SS:(BP-273)` should be two far pointers, offset then segment. The offset at `BP-280` should be `BP-272`
   (holding `04 '.dax'`), and the one at `BP-276` should be `BP-267` (holding `03 'GEO'`).
2. The same capture at the callee's first instruction (before its `push bp`, `SP = S0-14` with `S0 = BP-280`): the
   far pointer at `bp+16` is at `SP+14` and the one at `bp+20` is at `SP+18`.
3. The SP after the callee's `retf 0x12` should equal `BP-272`. An SP of `BP-264` would show an 8-byte over-pop;
   `BP-280` an 8-byte leftover.
4. A live capture of the callees at `0x002B:0x002A` (site `0x279E`), `0x03C5:0x002F` (site `0x78A6`) and
   `0x0709:0x0BF5` (after `0x1EF0D`), to close the three sites this probe cannot model.

These need a live run. The probe does not run one.

## Commands and results

```sh
python tools/por_geo_loader_caller_frame_probe.py
python -m pytest tests/test_por_geo_loader_caller_frame_probe.py -q
python -m pytest tests/test_por_geo_loader_target_probe.py -q   # unchanged loader probe, run for regression
```

- Probe: `wrote data/work/por-geo-loader-caller-frame-probe (walked=6/10 balanced=[0x1EF0D, 0x2E246, 0x2F767,
  0x2FA17, 0x047E0, 0x07276] not_balanced=[] status=stack-accounting-consistent-at-all-walked-sites)`, exit 0.
- Tests: `23 passed` for the new file (none skipped). The loader-target probe's tests: `24 passed`.

## Pins and inputs

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

| Dump (`ram-000000-100000.bin`, base 0) | SHA-256 (prefix) |
| --- | --- |
| `data/work/por-live-memory-pid34644` | `f8191750ea6c672e` |
| `data/work/por-wheel-live-capture` | `3788787cd795f1f5` |

Install: `data/work/por-geo-run/POOLRAD` (or `OPENUA_POR_INSTALL`). Both pins matched.

## Files and side effects

- New, tracked (to be committed by the parent): `tools/por_geo_loader_caller_frame_probe.py`,
  `tests/test_por_geo_loader_caller_frame_probe.py`, `docs/por-geo-loader-caller-frame-probe.md`.
- New, ignored output: `data/work/por-geo-loader-caller-frame-probe/por_geo_loader_caller_frame_probe.json` and
  `por_geo_loader_caller_frame_probe_report.md`.
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, and the existing helpers it imports
  (`por_farcall_resolve`, `por_overlay_group_map`, `por_geo_callee_identity_probe`, `por_loadpieces_handler`,
  and `por_geo_loader_target_probe` for its masked matcher).
- No edits to existing source, tests or docs. The loader-target probe and its doc are unchanged and still say
  "prototype conflict"; the parent should treat that wording as superseded for the six walked sites (its
  "Blocker" section). No emulator, GameLink, DOSBox, codewheel, retail-file write, or GoldBox access. No CoK rule or
  address is used for PoR.

## Not claimed

- No loader identity, no output-pointer identity, no GEO block, no plane-2 consumer, no transform, no
  descriptor-to-event mapping, no area mapping, and no execution at any instant.
- No segment-base model beyond the `0xAC76` base for segment `0x0AF8` (verified above) and the load `0x1866`.
