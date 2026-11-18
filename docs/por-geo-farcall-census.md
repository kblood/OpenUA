# PoR far-call census toward START stub 6 (WALLDEF wrapper)

**Status: bounded static diagnostic. `playable: false`. No executed GEO load, block,
area, or campaign mapping is established.** The probe checks decoded calls in
parsed `GAME.OVR` overlay bodies against START stub 6 in `START.EXE`. Candidates are
arithmetic possibilities only.

## Reassessment (2026-11-18): the GEO conclusion is withdrawn

This census was first written as a GEO-loader census, and its `geo` file name and
identifiers are historical. Its anchor is **stub 6** (`START.EXE:0x3E0C`, group `0x3DD7`
index 6, proc `0x0E08`). Stub 6 enters the **WALLDEF wrapper** at `GAME.OVR:0x2F6FF`,
which builds `WALLDEF<d>.dax`. It is not the GEO loader. See
[`por-ecl-stub6-key-arg-probe.md`](por-ecl-stub6-key-arg-probe.md).

Consequences for this document:

- **No GEO result is claimed.** The 181 candidates, the "0 near calls" count, and the
  verdict are results about stub 6 and the WALLDEF wrapper. None of them is evidence about
  the GEO load.
- **The GEO fill is not tested.** The GEO stem literal at `GAME.OVR:0x2F994` is read by
  `mov di,0x109D` at `0x2F9E5`, inside the fill procedure at `0x2F9BE`. A census aimed at
  that fill needs its own anchor and is not run here.
- **The method is unchanged.** The paragraph-residue filter, the stub-seeded walks, and the
  fixup checks were applied to stub 6 as stated. Their output is still a valid stub-6 result,
  and this section keeps the earlier method visible rather than rewriting it.
- **Stub 7 is separate.** Its partial prefix match (`0x1A27`) is not part of this census's
  anchor, and this census does not use it.

## Retail result (2026-11-18)

The read-only run used the pinned local GOG `POOLRAD` binaries. The input
hashes matched the repository pins and were unchanged after analysis:

| file | bytes | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

| measure | result |
| --- | ---: |
| parsed groups (24 well-formed, 10 partial) | 34 |
| decoded instruction starts | 71,417 |
| clean / incomplete stub-seeded group walks | 32 / 2 |
| decoded far-call sites (3,615 strong, 378 weak-only) | 3,993 |
| distinct literal `seg:off` pairs | 326 |
| near calls directly to the WALLDEF wrapper body (`0x2F6FF`) | 0 |
| far-call candidates | 181 (166 strong, 15 weak-only) |

The verdict is `candidate-given-di-not-established`. Every candidate depends
on a fixup delta or literal-address interpretation; no candidate is evidence
that the routine ran. A separate dump probe later mapped four `03D5:003E` calls
in the shared 0x19BA handler to the exact five-byte stub-6 entry in both captures, but
those sites do not pass this census's paragraph-residue filter and execution
remains unknown; see [`por-ecl-21-stub6-dump-probe.md`](por-ecl-21-stub6-dump-probe.md).
The output is in ignored
`data/work/por-geo-farcall-census-20261118/`.

## What is checked

- `GAME.OVR` is parsed into overlay groups. The bounded decoder follows each
  well-formed stub's procedure entry, fall-through, conditional branches,
  jumps, and near calls that remain inside that group's code body.
- A second, explicitly weaker pass tries Borland prologue byte patterns not
  reached by a valid stub. These sites are labeled weak and never presented as
  verified entries.
- Each decoded far call is tested against its own group's fixup table. The
  table is checked as sorted, in-range body offsets. A listed segment word is
  considered under the loader's paragraph-delta shape; an offset word listed
  for fixup is left undecided. Unlisted words are checked as literal operands.
- A control set checks the eleven decoded far calls in the `0x21` handler
  against the separate residue calculation. The stub-6 bytes, descriptor
  group, stub index, proc offset, and the WALLDEF wrapper's owner are structural
  preconditions.

The stub-6 candidate is at `START.EXE:0x3E0C`, stub 6 of descriptor
`0x3DD7`, and names `GAME.OVR:0x2F6FF` (the WALLDEF wrapper). The census found no decoded near call
to that body. This only covers decoded instructions inside parsed overlay
bodies; it does not cover all image bytes, indirect targets, or runtime paths.

## Evidence limits

- The census asks only about stub 6. It says nothing about the GEO fill at `0x2F9BE` or
  any GEO-loader caller.
- “Strong” means a decoded path from a structurally parsed stub, not runtime
  reachability. “Weak” means a prologue-pattern seed only.
- The 181 paragraph-model candidates do not identify a unique loader caller.
  The separate stub-6 memory match covers only four sites in two snapshots and
  does not establish execution. Neither result is an area or DAX selector mapping.
- The paragraph-aligned resident-image arithmetic is a model. Its inputs are
  reported, not promoted to a loader fact.
- Two strong walks are incomplete; partial groups are included as partial.
- The probe makes no use of CoK or other-title call-site semantics. No emulator
  or runtime capture was performed.

## Reproduction

```powershell
tools/.venv/Scripts/python.exe -I tools/por_geo_farcall_census.py `
  --install "G:\Games\Pool of Radiance\POOLRAD" `
  -o data/work/por-geo-farcall-census-20261118

$env:OPENUA_POR_INSTALL = "G:\Games\Pool of Radiance\POOLRAD"
tools/.venv/Scripts/python.exe -I -m pytest `
  tests/test_por_geo_farcall_census.py -q -p no:cacheprovider
```

The tool refuses unpinned inputs and outputs outside `data/work/` or inside
the install. Passing self-checks validates the census structure; it does not
turn candidates into runtime evidence.
