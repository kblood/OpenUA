# Pool of Radiance GEO door semantics: evidence and gaps

**Status: CENSUS-ONLY. No door rule is proven. `tools/por_map.py` is unchanged.**
This note audits the converter's edge mapping for door flags (plane 3) and asks
whether any branch can be made exact enough to change emitted OpenUA behaviour.
It cannot, on the evidence available. The tool added with this note,
`tools/por_geo_door_census.py`, only counts retail door values. It does not decide
what a value does in play.

## Question

`tools/por_map.py` `map_edge(slot, door)` currently does this:

| Gen1 edge | OpenUA byte | Rule name |
| --- | --- | --- |
| slot 0 (any door) | `0x00` | `open` |
| slot S, door 0 | `0xE0 \| S` | `solid` (passability 14) |
| slot S, door 1 | `0x10 \| S` | `auto-door` (passability 1, secret door) |
| slot S, door 2 or 3 | `0xF0 \| S` | `locked` (passability 15, "Blocked") |

Two things are collapsed or assumed here: flags 2 and 3 share one byte, and
flag 1 is mapped to "passable secret door" without a PoR check. The question is
whether PoR's own bytes, or OpenUA's runtime semantics, prove any of these.

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
it records no field accessor inside that fill. That is all it establishes.

Two readings follow from the bytes, and neither is proven. First, PoR code
**writes** the value `01` into a door field, so `01` is a state the game
produces and not only a stored value. Second, the same code clears fields, so
fields change at runtime. Which event sets or clears a field is not
established. The consumer that turns a plane-3 value into "may the party cross
this edge" is not identified. The doc names `0x2EC47` as a reader, but it does
not say that the reader is the movement check.

## Evidence class 3: OpenUA runtime semantics (repo code, measured in-tree)

`tools/dsn.py` (wall byte comment) and `src/engine/boot.c` `play_can_pass`
define the high nibble (passability):

| high nibble | engine behaviour in `play_can_pass` |
| --- | --- |
| 0 | open, pass |
| 1 | secret door, pass (the engine announces "A secret door!") |
| 6..13 | pass iff game-record byte `63 + code` is nonzero (event-togglable) |
| 14 | solid, blocked |
| 2, 3, 4, 5, 15 | the force/knock/pick menus, deferred: **refuse passage** |
| default | refuse |

The low nibble is the wall texture group; it plays no part in passability.
Nibbles 2 to 5 and 15 are all deferred menus, so today every one refuses
passage.

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
| door 1 -> secret door | `0x10\|S` | written by PoR code as `01`; 2,876 wall edges; 1 = two-sided, common | passes, prints "A secret door!" | **not proven**: no PoR check that flag 1 passes the party |
| door 2 or 3 -> blocked | `0xF0\|S` | 130 and 14 wall edges | refuses (menu deferred) | **not proven**; 2 vs 3 cannot be separated, and both refuse today, so a split changes bytes but not play |

Splitting flags 2 and 3 into nibbles 2 and 3 would change the emitted map
bytes and nothing else, because both refuse in `play_can_pass` today. It would
only matter once the menus are lifted, and the evidence for which menu each
value opens does not exist yet.

## Decision

No change to `tools/por_map.py`. No falsification test is added for a mapping
branch, because no branch was changed. The tests added with this note cover
the census tool only (`tests/test_por_geo_door_census.py`).

## Limits

- Census counts stored bytes. It says nothing about passability.
- Shared-edge agreement measures consistency only.
- The executable evidence is a static decode. No routine was shown to be the
  movement check, and no runtime capture was made. The runtime path is blocked
  by copy protection (`docs/por-wall-runtime-capture-attempt.md`).
- The `slot S` texture group is still unverified against WALLDEF.
- Other titles (GoldBox, CoK, COAB) are hypothesis only.

## Next discriminating observation

Static, no DOSBox needed: find every caller of `GAME.OVR:0x167D4` (the
set-to-`01` writer) and of `0x166CB` (the clearer), and name the event each
belongs to.

- If `0x167D4` is reached from a bash/pick/knock success path, then `01` means
  "opened/unlocked" in PoR, which would support the flag-1 passage rule and
  show that the 2/3 locked cases use another path. That is supporting
  evidence only, not proof.
- If it is reached from a secret-door discovery routine, the converter's
  "secret door" reading gains real support, and the message text is a
  candidate for PoR's own string.
- If it has no caller, or is reached only from an unrelated routine, the door
  mapping stays unresolved and that is a result too.

Then identify the consumer of the `0x2EC47` plane-3 read. If it gates the
forward move, its result for a flag-1 edge decides the passage question
directly.
