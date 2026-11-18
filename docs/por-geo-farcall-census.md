# PoR far-call census for the GEO loader

**Status: bounded static diagnostic. `playable: false`. No GEO target, block,
area, or campaign mapping is established.** The probe checks decoded calls in
parsed `GAME.OVR` overlay bodies against the resident GEO VROOMM stub in
`START.EXE`. Candidates are arithmetic possibilities only.

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
| near calls directly to the GEO body | 0 |
| far-call candidates | 181 (166 strong, 15 weak-only) |

The verdict is `candidate-given-di-not-established`. Every candidate depends
on a fixup delta or literal-address interpretation; no candidate is evidence
that the routine ran. The output is in ignored
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
  against the separate residue calculation. The GEO stub bytes, descriptor
  group, stub index, proc offset, and GEO body owner are structural
  preconditions.

The GEO stub candidate is at `START.EXE:0x3E0C`, stub 6 of descriptor
`0x3DD7`, and names `GAME.OVR:0x2F6FF`. The census found no decoded near call
to that body. This only covers decoded instructions inside parsed overlay
bodies; it does not cover all image bytes, indirect targets, or runtime paths.

## Evidence limits

- “Strong” means a decoded path from a structurally parsed stub, not runtime
  reachability. “Weak” means a prologue-pattern seed only.
- The 181 candidates do not identify a unique loader caller, because fixup
  deltas and live far-call targets are not observed. They are not an area or
  DAX selector mapping.
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
