# Conditional ECL candidate-flow LOAD_PIECES census

**Status: supplementary diagnostic only. `playable: false`.** This census
compares where the ordinary linear ECL walk finds opcode `0x37` with where the
candidate control-flow walk finds it. It does not select one list as correct,
bind a wall archive, or make a runtime reachability claim.

## Usage

```sh
python tools/por_ecl_cfg_loadpieces_census.py --install "D:/PoR" \
  --framing spec-menus -o data/work/por-ecl-cfg-loadpieces-census/retail
```

The input is ECL1.DAX through ECL8.DAX. Each archive is parsed and hashed before
and after the read. The output records block and archive hashes, TOC ids, both
sets of `0x37` offsets, and the raw operands at each offset. It does not write
to the install. Candidate records also name the first predecessor (header root,
linear fallthrough or literal edge) and retain decoded candidate edges for
review. A missing or malformed archive is reported as a diagnostic.

The CFG side inherits the conditional base `0x98FE`, selected framing, and
control-flow assumptions from [`por-ecl-cfg-probe.md`](por-ecl-cfg-probe.md).
In particular, it treats opcode `0x00`/`0x13` as terminal, follows literal
`GOTO`/`GOSUB` edges, and keeps lexical continuation for conditional points and
multiway transfers. These are candidate paths, not PoR-validated runtime paths.

## Pinned-install result

Read-only run on the local pinned GOG install, `spec-menus` framing:

| Measure | Result |
|---|---:|
| ECL archives present | 8/8 |
| Blocks parsed and decoded | 29/29 |
| Linear `0x37` sites | 25 |
| Candidate-flow `0x37` sites | 19 |
| Candidate-only sites | 4 |
| Linear-only sites | 10 |
| Conditional uncertainty points | 598 |
| Candidate parser stops | 6 |
| Archive/container/block diagnostics | 0 |

The candidate-only offsets are:

| Archive / block | TOC index | Offset |
|---|---:|---:|
| ECL1 #24 | 1 | `0x1DB8` |
| ECL6 #25 | 2 | `0x15FE` |
| ECL7 #26 | 3 | `0x1855` |
| ECL8 #27 | 2 | `0x1394` |

The ECL1 #24 site illustrates the model difference. Its linear walk stops at
`0x00AA` on byte `0xFF`. Under the conditional vbase, header slot 4 seeds
candidate offset `0x0160`; candidate fallthrough then reaches `SAVE` at
`0x1DA5`, `COMPARE` at `0x1DAB`, `IF_GE` at `0x1DB1`, `SAVE` at `0x1DB2`, and
`LOAD_PIECES` at `0x1DB8`. The three operands are literal-code values 1, 3 and
5. The walk crosses the unresolved `IF_GE` point by lexical fallthrough, so
this chain is only a lead for a PoR handler trace, not evidence that the load
executes.

### WALLDEF inventory cross-check for the ECL1 #24 operands

A read-only run of the existing [PoR wall inventory](por-converter.md) on the
same local install found block IDs 1, 3, and 5 together in three archives:
WALLDEF1.DAX, WALLDEF3.DAX, and WALLDEF4.DAX. Each matching block decodes to
780 bytes and is counted as one record by the inventory's stated 780-byte
layout convention. That size convention is a structural census assumption,
not a PoR runtime record-semantics finding. The per-archive matches were:

| Archive | IDs present from `{1, 3, 5}` | SHA-256 |
|---|---|---|
| WALLDEF1.DAX | 1, 3, 5 | `7a6102b9a38b2400f38d3c3d66460ab889ab7b35bc684c9ac282b80de028ec5a` |
| WALLDEF2.DAX | 1 | `bfbd4106d6207ea22d0e5862074ddef582ae24772656b9e47251f1b00933995d` |
| WALLDEF3.DAX | 1, 3, 5 | `86a8b136b0254398c03c31fdf13ebe2d23cf571d473a4f38718578f1479f661e` |
| WALLDEF4.DAX | 1, 3, 5 | `e1729459c867048b25553beea4681808c958a5501291b9bf931def3463fe70ed` |
| WALLDEF5.DAX | 1 | `26d2dbab7054fc22fb4ce44019b6e5cb0d981a05d082a4a22b085dbafd0b4802` |
| WALLDEF6.DAX | 1 | `d1b1ebc727dca3e65d86d4ccbf7f461dca59b64cce173d51bd46f024e5121010` |
| WALLDEF7.DAX | 1, 3 | `cbb055cf16e516cdfc58cae66fdff21ceaa2f33adbe17321fb57c47f589238aa` |
| WALLDEF8.DAX | 1, 3 | `1fc950ad158ef1542f13efc1d7ace02e61ba8e49b8042850098386648285bca2` |

This is a structural compatibility check only. The ECL1 block's three values
are candidate-flow operands, not established PoR block arguments. The repeated
ID sets do not identify which WALLDEF archive is used, and no ECL-to-area or
ECL-to-WALLDEF archive binding follows from matching the archive number. The
existing wall census uses a layout convention borrowed from another title; it
does not bind any of these ECL values to a runtime load. In particular, the
`IF_GE` branch and candidate CFG fallthrough at `0x1DB1` remain unresolved.

For provenance, the ECL1.DAX container hash in the candidate census is
`b1d08075869ef58ae4f08b53d2059b4ea60f0259c35fb6fda44e1c0737c3a4b9`, and the
decoded ECL1 #24 block hash is
`bc8cce7550b4c284237499b19fa22b7a9c931fd021e0e73e7eee46abf51ede85`. The
inventory output was written under the ignored path
`data/work/por-ecl-loadpieces-operands-walldef-check/`.

The ten linear-only sites occur in ECL2 #9 (`0x07C2`), ECL2 #15 (`0x02A9`),
ECL4 #21 (`0x030E`), ECL5 #3 (`0x031E`), ECL5 #4 (`0x0BA1`), ECL5 #6
(`0x036F`), ECL8 #16 (`0x031D`, `0x046E`), and ECL8 #29 (`0x0364`, `0x0695`).
The lists differ in both directions; this is evidence that the two analysis
models have different coverage, not that either one is the game’s executed
path. Raw operand rows are retained in the JSON for later review.

## Limits and next use

- `0x98FE` remains conditional; menu framing and the opcode table remain
  unvalidated for every block.
- The CFG walk does not model the semantics of conditional opcodes `0x16..0x1B`.
  Its lexical fallthrough is an over-approximation. GOTO/GOSUB terminal and
  return behavior are assumptions from the current decoder model.
- A candidate `0x37` does not establish that the instruction executes, what
  its operands mean in PoR, which archive is opened, or which GEO area owns the
  result. No WALLDEF or 8X8D mapping is emitted.
- The census is useful for prioritizing the next PoR-native handler traces. It
  must not feed an art conversion rule until operand semantics and archive-to-
  area binding have independent evidence.

Tests: `tests/test_por_ecl_cfg_loadpieces_census.py` checks candidate-only and
linear-only sites, raw operand retention, set comparison, and deduplication.
