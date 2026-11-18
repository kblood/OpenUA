# Pool of Radiance: proc-entry anomalies in the VROOMM stub groups

**Status: STATIC-PROBE-ONLY. `playable: false`. No consistent origin is proved. Five well-formed stub slots
have no prologue at `fileofs + proc`, and no tested relation explains them all.**

Tool: [`tools/por_proc_entry_anomalies.py`](../tools/por_proc_entry_anomalies.py). Tests:
[`tests/test_por_proc_entry_anomalies.py`](../tests/test_por_proc_entry_anomalies.py) (26 tests: 17 synthetic with
falsifiers, 9 retail-gated; all 26 pass, none skipped). Output (git-ignored):
`data/work/por-proc-entry-anomalies/`. Companion to [por-door-entry-route-census.md](por-door-entry-route-census.md),
whose *Next discriminator* asked for this entry-model check. It does not edit that census or
`tools/por_farcall_resolve.py`.

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both are checked before use (the probe refuses a mismatch). Read-only on the install. The MZ image base is `0x200`.

## Question and answer

The scan reports three group procs that do not land on a prologue: `0x9807` proc[1] `0x087A`, `0x0ABC0` proc[1]
`0x080F`, and `0x3211F` proc[1] `0x804`. The full sweep finds two more of the same kind: `0x9AC` proc[1] `0x8FD`
and `0xE5D3` proc[1] `0x82D`.

**No consistent bias or origin explains them.** They are not malformed or partial groups. They are five
well-formed stub-1 slots in accepted two-stub groups, and the defect is confined to the proc word. The group
header, the chain of group extents, and stub 0 all verify. Which of the two remaining readings is true (stale
or unused word, or a word written against an origin not recovered here) is not settled by these bytes.

## What the bytes establish

- **Record layout.** A group header is `CD 3F 00 00`, `fileofs` (4), `codesz` (2), `fixupsz` (2), `jmpcnt` (2),
  then 8 more bytes. Stub slots start at `header+0x16` (or `+0x17` for the `+0x17` family), and each slot is 5 bytes:
  `CD 3F <proc word> <byte>`. For the four two-stub `+0x16` records `0x39E`, `0x4F1`, `0x516`, `0x561`, the next
  header is exactly `+0x25` on, so the stub run and trailer sit inside a fixed record. (The `0x3F2C` record is
  not followed by a header at `+0x25`, so its record bounds are not confirmed.)
- **The groups tile the overlay.** The 34 groups (24 accepted, 10 partial) satisfy `fileofs + codesz + fixupsz =
  next fileofs` for every neighbour. There are **0 chain breaks**, and the last group ends exactly at EOF `0x32519`.
- **Stub 0 is an exit thunk.** In **34 of 34** groups, stub 0's proc equals `codesz - 5`, and the five bytes there
  are `55 89 E5 5D CB` (push bp; mov bp,sp; pop bp; retf).
- **The `fileofs + proc` model holds almost everywhere.** Well-formed slots with a prologue at `fileofs + proc`:
  **389 of 394**. The five misses are the anomalies below.
- **Malformed slots also land on prologues.** The 10 malformed slots (all in partial groups) differ from a
  well-formed slot only in the trailing byte, which is nonzero (values seen: `0x48`, `0x13`, `0x40`, `0x18`,
  `0x72`, `0x27`, `0x22`, `0x63`). Their `fileofs + proc` targets are **10 of 10 prologues**. So their "malformed" label rests on
  the trailing byte alone. This is a finding about the scan's rule, not a promotion of those groups.

## The five anomalous slots (exact)

All five are stub index 1, in accepted groups with the record layout above. `prologue deltas` are the prologues
found within +/-0x40 of the target. `expected by chance` is the window width times the group body's prologue
density, so small-window hits are common and weak.

| group | hdr | proc | target `fo+proc` | codesz | proc < codesz | 9A raw / decoded | prologue deltas | expected by chance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0x9AC` | `0x39E` | `0x8FD` | `0x12A9` | `0x35E` | no | 0 / 0 | none | 0.30 |
| `0x9807` | `0x4F1` | `0x87A` | `0xA081` | `0x127F` | yes | 2 / **2** | +6 | 0.38 |
| `0xABC0` | `0x516` | `0x80F` | `0xB3CF` | `0x1927` | yes | 0 / 0 | -29 | 0.30 |
| `0xE5D3` | `0x561` | `0x82D` | `0xEE00` | `0x61A` | no | 0 / 0 | -38, +30 | 0.17 |
| `0x3211F` | `0x3F2C` | `0x804` | `0x32923` | `0xFC` | no | 0 / 0 | none | 1.02 |

Per row:

- **`0x9807` proc `0x87A`.** `0xA081..0xA086` is the ASCII text `attle:`, which is data inside the overlay body. The
  prologue `55 89 E5` is at `0xA087`, six bytes later, and it is the function the route census already walks as
  candidate root `0x0A087` (108 instructions, ends `retf 4`). This row is **reached**: two raw `9A 5C 00 2B 00`
  (`CALL FAR 002B:005C`) sit at `0x101D` and `0x1746`. Each is a decoded `call_far` in a complete walk
  (from prologues `0x0FD8` and `0x16DA`, the repo's own walker). Under the **M0** model (`0x200 + 0x2B*16 + 0x5C`)
  they name `0x50C`, this slot. Under M1 they name nothing. The census did not tag `0x50C`, because its targets were
  the writer, clearer, and stub 1 at `0x0089C`. A reached slot that names text, six bytes before a real function,
  is the strongest of the five. It is still **one record**: stub 0 and every other slot show no `+6` origin.
- **`0xABC0` proc `0x80F`.** Target `0xB3CF` lies inside the far-call operand area named by the census (`0xB3CD`).
  The only nearby prologue is at `-29`. No references.
- **`0x3211F` proc `0x804`.** The proc is larger than the group's `codesz` (`0xFC`), and the target is past EOF.
  The record is consistent with the chain and ends exactly at EOF. No references.
- **`0x9AC` proc `0x8FD` and `0xE5D3` proc `0x82D`.** The proc exceeds `codesz`. The targets land inside the
  *next* group's body (`0x12A9` is `+0x563` into `0xD46`; `0xEE00` is `+0x1A5` into the partial group `0xEC5B`).
  No references.

## Alternatives tested

| hypothesis | test | result |
| --- | --- | --- |
| One shared origin explains all five | `fo`, predecessor `fo`, next `fo`, header, stub start, `fo-0x200`, image base, `fo+8`, `fo+0x16` | **None fixes all five.** Predecessor `fo` fixes one (`0x3211F`, a chance hit: 1.02 expected). |
| A constant bias explains the nearby prologues | the window deltas | `+6` (`0x9807`) and `-29` (`0xABC0`) differ. `-38`/`+30` (`0xE5D3`) is ambiguous. No common value. |
| Group header or extent is malformed | chain, stub 0, header fields | Verified clean (0 chain breaks, 34/34 stub 0). |
| The record is a partial group | slot class | All five are well-formed, in accepted groups. |
| The word is a stale or unused entry | 9A references | Four of five have no decoded or raw reference. But 316 of the 355 prologue-valid non-stub-0 slots have no raw `9A` either (39 do), so "unreferenced" is the common case and does not separate the anomalies. |
| The five words are independent offsets | value distribution | All five are stub-1 words in `0x804`..`0x8FD`, and none recurs as another slot's proc. The cluster is unexplained. |

## What is not established

- **Which origin** the five proc words were written against. None of the eight tested relations fixes all five.
- **That `0x9807` slot is ever executed.** Two decoded call sites reach it under the **M0** model, which is a
  zero-skew assumption that the census also did not promote. Only a CS:IP capture would show a run.
- **The meaning of the trailing byte** (zero on all accepted slots, nonzero on the ten malformed ones) or of the
  record fields between the header and the stubs.
- **Whether the copy-protected loader rewrites any proc word at run time.** The static bytes cannot show it.

## Limits

- Stdlib-only static analysis with the existing walker and resolver scan. No emulator and no live capture.
- The `9A` count uses decoded `call_far` only when a *complete* walk from a prologue in the same group body
  decodes the site. A raw `9A` that no such walk reaches is not counted, so the decoded counts are a lower bound.
- The first draft of the raw `9A` parse read the segment and offset words in the wrong order. It was corrected
  before any result above was recorded. The corrected parse was cross-checked against the handler's 11 far calls
  (11 of 11 match).
- Read-only on the pinned install. No retail file written. No DOSBox, Hatari, GameLink, or codewheel run. GoldBox
  material was not used.

## Commands

```sh
sha256sum data/work/por-geo-run/POOLRAD/GAME.OVR data/work/por-geo-run/POOLRAD/START.EXE   # before and after
tools/.venv/Scripts/python.exe -I tools/por_proc_entry_anomalies.py \
    --install data/work/por-geo-run/POOLRAD -o data/work/por-proc-entry-anomalies          # exit 0
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_proc_entry_anomalies.py -q -p no:cacheprovider  # 26 passed
```

## Next discriminator

1. **Decode the trailing byte.** Show what the `+4` byte means in accepted and malformed slots. Until then, the
   scan's "malformed" rule is an unexplained classification, and its ten slots may be real entries.
2. **Test the `0x9807` slot under the census's candidate root.** A word of `0x880` would reach `0xA087`. That is a
   hypothesis to check against the two decoded call sites, not a fix.
3. **Only a live capture** (CS:IP on `int 3Fh` at `0x50C`, or the loader's overlay table) can say whether the
   `0x9807` slot is run and where it lands. That is blocked by the copy-protected path, per
   [por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md).

## Handoff

Static slice, 2026-11-18. Changed or created files, not committed or pushed:

- `tools/por_proc_entry_anomalies.py` (new): probe. Reports the per-slot survey, the chain and thunk checks, the
  eight-origin test, and the decoded `9A` reachability.
- `tests/test_por_proc_entry_anomalies.py` (new): 17 synthetic falsifier tests and 9 retail-gated pins. 26 pass.
- `docs/por-proc-entry-anomalies.md` (new): this document.

Outputs (git-ignored): `data/work/por-proc-entry-anomalies/` (JSON and report). Scratch scripts used during the
investigation are in `data/work/por-proc-entry-model/` (git-ignored, not part of the deliverable).
Not edited: `tools/por_farcall_resolve.py`, `tools/por_door_entry_route_census.py`,
`docs/por-door-entry-route-census.md`, and every other file.
