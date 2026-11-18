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
to the install. A missing or malformed archive is reported as a diagnostic.

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
