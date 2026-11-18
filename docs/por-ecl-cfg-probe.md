# PoR ECL candidate control-flow probe

**Status: candidate decode diagnostic only. `playable: false`. Runtime reachability is not established.**

`tools/por_ecl_cfg_probe.py` starts from the five ECL header pointers and follows
the decoder's literal `GOTO`, `GOSUB`, `ON_GOTO` and `ON_GOSUB` targets. This can
inspect code after an unsupported byte in linear order when a decoded transfer
points around it. It reuses `tools/por_ecl.py` for container parsing, RLE,
header validation and operand framing. It does not change the normal decoder or
the converter pipeline.

## Usage

```sh
python tools/por_ecl_cfg_probe.py --install "D:/PoR" --ecl 2 --index 2 \
  --framing spec-menus -o data/work/por-ecl-cfg/ecl2-20
```

The PoR-derived base `0x98FE` is used conditionally, exactly as in the decoder's
opt-in mode. The output contains candidate instruction offsets and edges, stops,
header roots that do not resolve into the block, and the linear decoder's first
stop. It is deterministic, omits the source path and block bytes, and marks
`playable: false` and `runtime_reachability_established: false`.

## Walk model

- Header pointers are converted with `(vaddr - 0x98FE) & 0xFFFF` and seeded only
  when they land in the body. This base is conditional, not promoted.
- Each instruction is decoded with the existing `por_ecl.walk_block` operand
  rules. A `GOTO` follows its literal target and suppresses fallthrough. A
  `GOSUB` follows its literal target and its fallthrough. Multiway transfers
  follow literal targets and retain fallthrough as a deliberate over-approximation.
- `EXIT` and `RETURN` stop a candidate path. Opcodes `0x16..0x1B` are recorded as
  `conditional-branch-semantics-open`; the probe retains lexical fallthrough as
  a candidate continuation but invents no branch target.
- Unsupported or truncated instructions stop only that candidate path. A target
  inside a previously decoded instruction is reported and not decoded again.
- The work limit defaults to 12,000 instruction starts. Reaching it is reported.

These are control-flow hypotheses drawn from the decoder table, not semantics
recovered from PoR's executing program. In particular, this probe does not
prove the base, menu framing, branch behavior, script entry execution, or that
bytes after an unknown opcode are data. A candidate edge is not a runtime edge.

## Verification

Synthetic tests cover a jump around an unsupported byte, out-of-block targets,
GOSUB target plus fallthrough, conditional uncertainty, invalid header roots,
and non-playable/conditional labeling. The retail run on ECL2 block 20 is a
diagnostic comparison against the existing linear walk only. Neither result is
used to emit events or OpenUA module data.
