# Pool of Radiance: GEO plane-2 observer (observe-only)

**Status: observe-only. `emitted: []`, `mappings: []`. No rule established.**

Tool: `tools/por_geo_plane2_observe.py`. Tests: `tests/test_por_geo_plane2_observe.py`
(14 tests: 13 synthetic, 1 retail gated on `OPENUA_POR_INSTALL`).

## Question and answer

> Can the nonzero Gen1 GEO plane-2 per-cell descriptor bytes be translated into
> OpenUA cell events or zones for Pool of Radiance?

**No, not yet.** PoR-specific evidence does not establish a consumer of plane 2, so no
translation rule is implemented. `tools/por_map.py` still zeroes plane 2 in
`build_openua_geo`. This slice adds a diagnostic that records what the bytes look like and
which readings are still open. It assigns no meaning and writes no cell events, zones or
flags.

Anchors refer to block ids, which can repeat in a DAX. The observer preserves all matching
TOC indices and reports `ambiguous-block-id` instead of selecting one if an anchor id is
duplicated; a synthetic test covers that refusal to bind silently.

This agrees with `docs/por-geo-descriptor-probe.md`: "consumer not established". That
probe traced a far call to the writer of DGROUP `0x6AB1`, and the callee is unidentified.
The observer does not re-run that trace.

## Why no rule was implemented

- The only path from the GEO bytes to game state runs through a far call at seg `0x03D5`,
  off `0x0034`, whose target the overlay fixup table patches at load time. Its code is not
  decoded, so nothing shows that the returned byte is the cell's plane-2 byte.
- Plane 2 is dense and varied. Several blocks have 256 of 256 cells nonzero. Distinct raw
  values run from 6 to 37 per block. Bit 7 is set on most nonzero cells in some blocks and
  on few in others. Nothing in the bytes alone picks an event key from a zone flag.
- Establishing a rule needs one of: a decoded consumer that reads plane 2 at
  `514 + y*16 + x`, or a runtime capture pairing the stored value with the cell's plane-2
  byte. Neither exists, and the runtime capture needs an emulator run that was out of scope.

## Commands and results

```sh
python tools/por_geo_plane2_observe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-geo-plane2-observe
# por_geo_plane2_observe: wrote C:\Modding\OpenUA\data\work\por-geo-plane2-observe (observe-only, emitted=0)
# exit 0

OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_geo_plane2_observe.py -q
# 14 passed

python -m pytest tests/test_por_geo_plane2_observe.py -q -rs
# 12 passed, 1 skipped (retail gate not set)
```

The observer's JSON has `blocks` = 29 and no `error` entries, across GEO1 through GEO8.

## Retail byte evidence

### Install pins (read-only; SHA-256 before and after the run, all unchanged)

| File | Bytes | SHA-256 (first 12) |
| --- | --- | --- |
| GEO1.DAX | — | `e6bcc8c5ea4b` |
| GEO2.DAX | — | `2035246014ef` |
| GEO3.DAX | — | `ce4b4ecb74b0` |
| GEO4.DAX | — | `167017243737` |
| GEO5.DAX | — | `24c5b6f1bbf1` |
| GEO6.DAX | — | `8bf4bbf5b184` |
| GEO7.DAX | — | `5f30b6e76ca4` |
| GEO8.DAX | — | `050cd0316ebf` |
| GAME.OVR | 206,105 | `872964a32cef` |
| START.EXE | 65,231 | `d825df2b1746` |

The GAME.OVR and START.EXE hashes match `docs/por-geo-descriptor-probe.md`. Before and after
hashes of all ten files are identical.

### Anchors (cross-checks, not evidence of a rule)

| GEO | Block (TOC idx) | Cell (x,y) | Documented | Observed | Tier | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | 20 (2) | (1,5) | 0x8E | 0x8E | retail-recorded (`docs/por-converter.md`) | agrees |
| 8 | 29 (3) | (7,8) | 0x02 (2 & 0x7F) | 0x02 | retail-recorded | agrees |
| 8 | 29 (3) | (7,7) | 0x01 (1 & 0x7F) | 0x01 | retail-recorded | agrees |
| 1 | 18 (0) | (14,8) | 0x86 | 0x86 | goldbox-por-cross-check | agrees |
| 2 | 20 (2) | (13,10) | 0x83 | 0x83 | goldbox-por-cross-check | agrees |

These are Pool-specific GoldBox reference observations, not CoK/DoK rules. They are
cross-checks only and do not prove the native DOS dataflow or justify an OpenUA mapping.

### Coverage

29 blocks across GEO1 to GEO8 (every block in the eight TOCs decodes to 1026 bytes with
size field 1024). Per-block counts are in `por_geo_plane2_observe.md` under
`data/work/por-geo-plane2-observe/`. Some examples:

| GEO | Block | Nonzero | Bit 7 | Distinct raw | Nonzero on all-open cells |
| --- | --- | --- | --- | --- | --- |
| 1 | 18 | 179 | 120 | 13 | 6 |
| 7 | 23 | 256 | 256 | 28 | 46 |
| 8 | 13 | 256 | 256 | 29 | 16 |
| 8 | 16 | 40 | 0 | 17 | 1 |

## Hypotheses (unresolved by this byte census)

| Id | Reading | Falsifier | Settles with |
| --- | --- | --- | --- |
| H1 | raw plane-2 byte is the cell's event/dispatch key | a consumer reading `514 + y*16 + x` that returns a different value, or a capture where `0x6AB1` differs from plane 2 at the party cell | the decoded callee at `0x03D5:0x0034`, or a runtime capture |
| H2 | `plane2 & 0x7F` is the event/dispatch key | as H1, plus a consumer that uses bit 7 | as H1 |
| H3 | bit 7 is a separate flag, low bits an identifier | a consumer ignoring bit 7, or bit 7 changing without low bits | a consumer decode or paired captures |
| H4 | nonzero plane 2 marks cells with a zone or backdrop | nonzero value on an all-open cell with no zone, or a zone on a zero byte | a zone-table decode or per-cell runtime zone state |
| H5 | plane 2 is independent of the wall planes | a repeatable cell-wise relation between plane-2 values and wall-edge tuples | cell-wise cross-tabulation; correlation alone would not establish semantics |

### Pool-specific external cross-check for H2

The read-only GoldBox reference page `docs/engine/research/pool-natural-encounter-route.md`
describes a Pool route using `GEO1.DAX#18` cell `(14,8)`, whose raw descriptor is `0x86`, and
the PoR ECL1#18 instruction `AND [C04F], #7F -> [6E79]`, followed by an `ON_GOTO` selector.
That is consistent with `0x86 & 0x7F == 6` serving as a selector in that PoR-specific route.
The local retail input independently contains that instruction sequence: `ECL1.DAX` SHA-256
`b1d08075869ef58ae4f08b53d2059b4ea60f0259c35fb6fda44e1c0737c3a4b9`, TOC index 0 / block id
18, decoded block SHA-256
`011a00d3f4e52e457dc7e4e60fa4ef95c4a0ed29cdfdcc37a2efd12cd3873ac6`. In the decoded block,
`0x1B9` (`0x2F`) has the three operands `0xC04F`, `0x7F`, `0x6E79`; `0x1C2` (`0x25`) is
`ON_GOTO` using `0x6E79`. This confirms that the cited code and values are in PoR's own ECL
bytes, while the GoldBox page supplies the separate route interpretation. The reference page
also says its native DOS staging does not execute this route. Thus this supports H2 as a
Pool-specific cross-check, not as a proven native DOS or OpenUA rule: the retail-code
producer link from the GEO plane byte to DOS `DGROUP 0x6AB1` remains unidentified, and this
observer makes no mapping from it. The GoldBox browser runtime result is evidence for that
separate implementation, not an OpenUA run.

## Title boundary

- Source: the PoR install only (`G:\Games\Pool of Radiance\POOLRAD`), read through
  `tools/por_map.py` (untracked; imported read-only, not modified).
- No CoK or DoK rules are used. `C:\Modding\GoldBox` was read as a read-only reference for
  the Pool-specific cross-check above and was not modified.
- The cross-check is explicitly scoped to Pool of Radiance, but it remains separate from
  the primary retail-code evidence and cannot establish an OpenUA descriptor mapping.

## Install immutability

The install was opened only with `open(..., "rb")` / `Path.read_bytes()`. SHA-256 of
GEO1–8.DAX, GAME.OVR and START.EXE was taken before and after the retail run, and all ten
are unchanged. The output folder is outside the install; `validate_output_dir` refuses one
inside it (tested).

## Generated artifacts

`data/work/por-geo-plane2-observe/por_geo_plane2_observe.json` and
`por_geo_plane2_observe.md`. Both are under `data/`, which `.gitignore` covers
(`git check-ignore` confirms `/data/*`). Nothing was written under a tracked path.

## Limits

- Counts describe bytes only. They say nothing about reachability in play.
- No runtime capture, no DOSBox, no GameLink, no codewheel, no emulator.
- The retail test checks the census, the five anchors and install immutability. It does not
  prove any mapping.
- `tools/por_map.py` was not changed. `build_openua_geo` still zeroes plane 2, which is the
  correct behaviour until a rule exists.
- If an anchor's block id appears more than once in its archive, its status is
  `ambiguous-block-id`; every matching TOC index and observed byte is listed, and no match
  is selected.

## Files touched

- New: `tools/por_geo_plane2_observe.py`, `tests/test_por_geo_plane2_observe.py`,
  `docs/por-geo-plane2-observe.md`.
- Generated (ignored): `data/work/por-geo-plane2-observe/`.
- Not modified: `tools/por_map.py`, the pipeline files, any existing doc, any dirty file,
  `C:\Modding\GoldBox`.
- Not committed, not pushed.

## Handoff

To establish a rule, the next step is one of the settling observations above. The cheapest
is a decode of the far-call callee at `0x03D5:0x0034`, which needs its runtime segment (a
capture). Until one of those exists, `build_openua_geo` must keep plane 2 at zero. A
future rule goes in a new standalone module with its own falsification tests, and its
evidence goes in this doc.
