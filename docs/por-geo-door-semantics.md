# Pool of Radiance GEO door semantics: evidence and gaps

**Status: CENSUS + STATIC TRACES + ONE PoR DOS RUNTIME ROUTE. No general flag-to-runtime rule is proven.**
This note audits the converter's edge mapping for door flags (plane 3). One
PoR-specific original-game runtime trace now supports interaction-gated
crossing for a flag-2 edge; it does not establish a general byte-to-runtime
mapping. The tool added with this note,
`tools/por_geo_door_census.py`, only counts retail door values. It does not decide
what a value does in play.

## Question

`tools/por_map.py` `map_edge(slot, door)` currently does this:

| Gen1 edge | OpenUA byte | Rule name |
| --- | --- | --- |
| slot 0 (any door) | `0x00` | `open` |
| slot S, door 0 | `0xE0 \| S` | `solid` (passability 14) |
| slot S, door 1 | `0x10 \| S` | `auto-door` (passability 1, secret door) |
| slot S, door 2 | `0xF0 \| S` | `locked` (passability 15, "Blocked") |
| slot S, door 3 | `0xF0 \| S` | `door3-unresolved` (same provisional byte) |

Door flags 2 and 3 still produce the same byte, but diagnostics now keep them
distinct: flag 2 has one native PoR locked-door observation, while flag 3
remains an other-title hypothesis. Flag 1 is still mapped to "passable secret
door" without a PoR check.

## PoR original-game runtime observation (flag 2)

The read-only GoldBox reference contains a reproducible DOSBox-X trace of the
Pool of Radiance DOS executable in
`docs/engine/research/gen1-dosbox-runtime-trace.md`, sections dated 2026-07-22.
It records a party facing west at `(14,10)` in `GEO2.DAX` block 20. The edge
has wall slot 10 and observed plane-3/door flag 2. The native game displays
`LOCKED. BASH PICK EXIT`. A Pick attempt fails in one recorded attempt and
leaves the party in place; a subsequent Bash succeeds, moves the party to
`(13,10)`, and persists the opened edge. The trace then reaches descriptor 3
and native COMBAT. The GoldBox files were used read-only; this is PoR DOS
runtime evidence, not a CoK rule.

This supports the concrete observation that this flag-2 route is not an
unconditional open edge and that a successful interaction permits crossing.
It does not prove that every GEO byte with value 2 feeds this edge reader: the
separate static probe still has not bound its plane-3 buffer to the selected
GEO block. It also does not say anything about flag 3.

## Pins

Retail files were opened read-only from `G:\Games\Pool of Radiance\POOLRAD`.
Each `GEO<n>.DAX` was sha256-pinned before and after the census. The census
refuses to write a report if any file changed. Pins are recorded in
`data/work/por-door-semantics/probe/por_geo_door_census.json` (git-ignored).

| file | sha256 |
| --- | --- |
| GEO1.DAX | `e6bcc8c5ea4b101497353ec75386b96ad6368447a6669f4f82ca7dac3c1e204a` |
| GEO2.DAX | `2035246014efdb26de3114f4737d52a935ad8834f79b4a8e4880da2922b6d595` |
| GEO3.DAX | `ce4b4ecb74b03ca18bda5d00e9050ec4e18284ef89edf816480800070ed0c6ee` |
| GEO4.DAX | `167017243737cfacb996433632d3c70a55ce506d794a44e31c02d34e9e3c55d5` |
| GEO5.DAX | `24c5b6f1bbf18b6f9a34600d99043e002848b9d2165189e4000c000a01f5c527` |
| GEO6.DAX | `8bf4bbf5b1845c9d3181a7d47382d75f5337e27e1263690abb8820f9b722ecdb` |
| GEO7.DAX | `5f30b6e76ca42b563253fc9b4cee5be7db6ccbe0eb38eefe37866197e5be2127` |
| GEO8.DAX | `050cd0316ebf339f6b36233156eb99129c8eaa689df89e05fbfa13d72e89c045` |

`START.EXE` (size 65,231, sha256 `d825df2b…6b07bd`) was pinned and not read
by this slice.

## Evidence class 1: PoR retail bytes (census, measured)

All 29 blocks of 1026 bytes decoded with `tools/por_map.py`'s decoder. There
were 0 decode errors and 0 skipped blocks. Edge count is 29 × 256 × 4 = 29,696.

Door values over every edge:

| door | all edges | slot 0 (no wall) | slot nonzero (wall) |
| --- | --- | --- | --- |
| 0 | 26,590 | 16,810 | 9,780 |
| 1 | 2,962 | 86 | 2,876 |
| 2 | 130 | 2 | 128 |
| 3 | 14 | 0 | 14 |

Shared interior edges (E of one cell against W of its east neighbour, and S
against N of its south neighbour), keyed by the sorted pair of door values:

- Both sides have a wall slot: 5,408 pairs, door values agree on **5,308**.
  Disagreeing pairs are `0-1` 44, `0-2` 2, `1-2` 42, `1-3` 12. The rest are
  agreeing pairs (`0-0` 3,935; `1-1` 1,330; `2-2` 42; `3-3` 1).
- At least one side slot 0: 8,512 pairs, door values agree on **8,485**.

What this shows:

- Door value 1 is the common non-zero flag: 2,876 wall edges. Two-sided
  `1-1` pairs (1,330) are far more common than one-sided `0-1` pairs (44).
  That is consistent with flag 1 being an edge property, not noise.
- Door values 2 and 3 are rare (128 and 14 wall edges). Only 2 flag-2 edges
  sit on slot-0 edges, so the "open whatever the door" rule is almost never
  tested.
- Door values agree across a shared wall in about 98% of wall pairs. The
  disagreements are one-sided, so per-cell mapping can give one side a
  passable byte and the other side a blocked byte.

What this does **not** show: it counts stored values. It does not show that a
value passes or blocks the party, nor which value means "locked".

## Evidence class 2: PoR executable (static decode, cited from repo docs)

`docs/por-geo-buffer-fill-probe.md` records a static decode of `GAME.OVR` (not
a runtime capture). It reports four routines that touch the plane-3 field:

- `GAME.OVR:0x166CB` (8 sites) reads and writes `+0x300` (plane 3) with masks
  `0x3F`, `0xCF`, `0xF3`, `0xFC`. Those clear one 2-bit field each: W, S, E,
  N. It has no gate.
- `GAME.OVR:0x167D4` (8 sites) reads and writes `+0x300`, then ORs
  `0x40`, `0x10`, `0x04`, `0x01`. That sets a field to `01`. It is gated on
  `0 <= X,Y <= 15`.
- `GAME.OVR:0x2EC47` (4 sites) reads plane 3 at `+0x300`, gated on Y.

The same doc says the fill routine `0x2F9BE` is where the buffer is built, and
it records no field accessor inside that fill. A follow-up static caller probe
([`por-door-caller-probe.md`](por-door-caller-probe.md)) adds these bounded
findings:

- The setter `0x167D4` and clearer `0x166CB` are in the same well-formed group.
  Decoded in-group calls to both are found in the closure of stub 1, whose
  START target is `0x089C` / proc `0x0D6D` / GAME.OVR file `0x17438`.
- No direct far-call literal to that stub is found under either reported
  address model. The event that enters this group, and therefore what makes
  the setter or clearer run, remains unidentified.
- The reader `0x2EC47` returns a 2-bit plane-3 field. Four candidate far-call
  sites are decoder-verified and fixup-listed. Their following instructions
  compare the result with 0, 1 or 3.

The probe's address model is conditional: one dump-backed anchor supports the
`+0x7E` model at one reader site, while the writer/clearer group is absent from
both pinned dumps. These findings alone do not establish an event, a movement
check, or a door rule.

A second static probe ([`por-door-indirect-probe.md`](por-door-indirect-probe.md))
searched decoded instruction starts for indirect entries into the writer/clearer
stub. It found 0 `FF /2` near calls and 5 `FF /3` far calls across the walked
PoR image. None resolves to the target under the two unpromoted address models;
the five operands need DS or DI values that the probe does not establish. The
GAME.OVR walk covers 94.6% of group-body bytes, and 8,654 bytes outside groups
are not walked, so this is not proof that no caller exists. The trigger remains
unknown.

A follow-up branch probe ([`por-door-reader-branch-probe.md`](por-door-reader-branch-probe.md))
decoded the arms after the four reader calls. At `0x17469` in the stub-1 root
`0x17438`, reader result `R == 1` reaches `0x16E06`, which updates the party's
position bytes; `R == 0` does not. Results 2 or 3 reach that step only if an
unresolved callee returns nonzero. The other three reader sites classify,
inspect a neighbour, or clamp an edge and do not move the party.

This narrows the static evidence but does **not** prove a GEO door mapping.
The reader target is still an M1 address-model candidate, its return value 1
is also the reader's default, and the buffer read at `+0x300` has not been
joined to a loaded GEO block's plane 3. Therefore the branch establishes
`R == 1 -> decoded position update` in this conditional static path, not
`GEO door flag 1 -> passable`. Which events set or clear plane-3 fields also
remains unknown.

## Evidence class 3: OpenUA source-level movement behavior (not runtime-tested here)

`tools/dsn.py` (wall byte comment) and `src/engine/boot.c` define the high
nibble (passability). The menu-less `play_can_pass` used for strafe/backstep
refuses menu-coded nibbles; the forward-play path calls
`play_forward_allowed` → `jt955_dungeon_decide`, which runs the Blocked menu:

| high nibble | forward PLAY source path |
| --- | --- |
| 0 | open, pass |
| 1 | secret door, pass (the engine announces "A secret door!") |
| 6..13 | pass iff game-record byte `63 + code` is nonzero (event-togglable) |
| 14 | solid, blocked |
| 2, 15 | forward move runs the Blocked menu (force, pick when available, key when available, leave); a successful action permits this step |
| 3 | announces a secret door, then runs the same Blocked-menu variant |
| 4 | forward move runs the second Blocked-menu variant; action 1 refuses |
| 5 | announces a secret door, then runs the second menu variant |
| default | refuse |

The low nibble is the wall texture group; it plays no part in passability.
OpenUA's current forward movement therefore has an interaction path for the
converter's `0xF0 | slot` edge. It does not yet persist a successfully opened
edge as the PoR DOS trace does; the current Bash path only reports success to
the movement gate. The other movement keys use the menu-less gate and refuse
these menu-coded edges.

## Evidence class 4: other-title hypothesis (NOT PoR evidence)

`C:\Modding\GoldBox` (read-only reference) has a copy of `find_geo_path.py`
under `build/cok-recomp/` with a Gen1 door rule: flag 1 passes automatically, flag 2 opens a bash/pick/knock prompt,
and flag 3 is bash/knock only. It cites `docs/engine/research/decompile-ovr015-movement.md`,
which is a Curse of the Azure Bonds (COAB) / Krynn decompile. That rule is
**hypothesis only**. It is not PoR evidence. The converter's current mapping
was derived from it. The COAB note also says that picking or bashing writes an
"unlocked" bit into the same cell field, which is consistent with `0x167D4`
but is a different title and is not used to decide anything here.

## Mapping branches: what each would need to be exact

| branch | current byte | PoR evidence now | OpenUA behaviour now | verdict |
| --- | --- | --- | --- | --- |
| slot 0 -> open | `0x00` | 88 slot-0 doors exist; their effect is unknown | open | not proven either way |
| door 0 wall -> solid | `0xE0\|S` | 9,780 wall edges; 100 one-sided disagreements | solid | not proven |
| door 1 -> secret door | `0x10\|S` | PoR writes field `01`; conditional static branch with reader result `R == 1` updates position, but reader identity and GEO-plane source are unestablished; 2,876 wall edges | passes, prints "A secret door!" | **not proven**: no established link from GEO flag 1 to `R == 1`, nor PoR evidence for the secret-door message |
| door 2 -> interaction-gated | `0xF0\|S` | 128 wall edges; one PoR DOS route at GEO2 block 20 shows LOCKED/BASH/PICK and successful Bash crossing | forward movement offers the Blocked menu and permits a successful force/Bash action | supported for one original-game route; general flag binding and persistent-open parity remain unproven |
| door 3 -> unresolved | `0xF0\|S` | 14 wall edges; no PoR runtime observation | same OpenUA Blocked menu as door 2 | unresolved; Bash/Knock-only comes from CoK research, not PoR |

The converter preserves the existing byte mapping for now. It distinguishes
flag 2 and flag 3 in normalized rule counts and evidence labels, although both
currently encode as passability 15. A future flag-3 mapping change needs
PoR-specific evidence; the CoK distinction must not be promoted.

## Decision

`tools/por_map.py` now reports a separate flag-2 `locked` label and flag-3
`door3-unresolved` label while preserving the emitted bytes. The overall
`por_door_rule_proven` flag remains false because this one runtime route does
not bind all GEO flag-2 fields to the runtime reader or establish the other
flags. Tests assert both the unchanged wall byte and the distinct evidence
labels. Census, caller and branch tests remain in
`tests/test_por_geo_door_census.py`, `tests/test_por_door_caller_probe.py`, and
`tests/test_por_door_reader_branch_probe.py`.

## Limits

- Census counts stored bytes. It says nothing about passability.
- Shared-edge agreement measures consistency only.
- The reader identity and GEO-to-buffer source link are not established. The
  GoldBox PoR DOS runtime observation is independent of that static link and
  establishes only its recorded route. OpenUA has not yet been runtime-tested
  against that route. The current interactive capture path is blocked by copy
  protection (`docs/por-wall-runtime-capture-attempt.md`).
- The `slot S` texture group is still unverified against WALLDEF.
- CoK/COAB semantics are hypothesis only. The GoldBox repository's PoR DOS
  runtime trace is cited as PoR-specific evidence and was read-only.

## Next discriminating observation

The direct and bounded indirect-call censuses are complete; their results are
in [`por-door-caller-probe.md`](por-door-caller-probe.md) and
[`por-door-indirect-probe.md`](por-door-indirect-probe.md). The startup DS lead
at START function `0x0A9FC` has since been checked at runtime (see
[`por-int3f-live-dispatch.md`](por-int3f-live-dispatch.md)): after relocation,
`DS=0x14A0`, `DS:0x43F0` contains `E5 02 C6 12`, and the far call reaches
`12C6:02E5`, whose first byte is `retf`. This is a startup no-op, not a door
trigger. The overlay operands at `DS:0x6B84` still need their own DS trace, and
the indirect probe did not resolve them. Even a resolved pointer to stub 1
would identify only a trigger path; it would not establish the writer's
gameplay event. The reader branch effects are now decoded statically, but
their input is not yet tied to a specific loaded GEO cell.

The next discriminator is to run the OpenUA-converted GEO2 block-20 flag-2
route and compare the menu, Bash success, persistence and reverse crossing with
the original trace. Separately, establish the reader's live target and trace
its buffer back to the loaded GEO block, so its 2-bit return can be paired
with the raw door flag. The writer's caller/event remains a separate open
edge. The current direct retail capture route is blocked at copy protection (see
[`por-wall-runtime-capture-attempt.md`](por-wall-runtime-capture-attempt.md)).
Until those observations close the byte-to-reader link and OpenUA parity, the
general mapping branches stay provisional.
