# Pool of Radiance: decode of the GAME.OVR routine at 0x2EEF4

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`.**
**Answer: not-established.** The routine at `0x2EEF4` does not, by its own bytes, establish a
WALLDEF record selection, a record stride or index, a DAX file or read path, or a wall slot ->
art lookup. It has no inline DOS or INT call, no reference to the WALLDEF literal, and no
far call. Its only outward edges are 39 near calls into the group body, and the bytes do not say
what those callees do.

`tools/por_wall_owner_probe.py` decodes the ret-stopped walk from `0x2EEF4` read-only against the
pinned `GAME.OVR`. `tests/test_por_wall_owner_probe.py` checks the offset and control-flow claims on
synthetic fixtures with mutations, and checks the retail anchor when `OPENUA_POR_INSTALL` is set.

Related: [por-wall-render-probe.md](por-wall-render-probe.md) (the layout owner, from the static walk),
[por-wall-group29-target-probe.md](por-wall-group29-target-probe.md) (group 29 and stub 5, a partial
scanner row).

---

## Usage

```sh
python tools/por_wall_owner_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-owner-probe/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_wall_owner_probe.py -q
```

Output: `data/work/por-wall-owner-probe/retail/por_wall_owner_probe.json` (schema
`openua.por-wall-owner-probe` v1). Refuses an unpinned `GAME.OVR` unless `--allow-unpinned`.

## Pinned source

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |

Matched on the retail run. Read-only; no retail file or GoldBox file was written.

## What the bytes establish

Walk from `0x2EEF4`, stopped at the first return:

- **827 instructions**; return is `retf 6` at `0x2F6A8` (bytes `CA 06 00`), so the routine ends at
  `0x2F6AB`, the WALLDEF length byte. Adjacency is confirmed. Diagnostics: none.
- Flow counts: `seq` 725, `call` 39, `jcc` 37, `jmp` 25, `retf` 1. No indirect call or jump. No far call.
- **Inline interrupts: 0.** A DOS file function (open, read, seek) is not called inline. Any file
  access must happen inside a callee, or not at all.
- **Literal references: 0.** No immediate, direct operand, branch target or far offset in the routine
  equals `0x2F6AB` (file-offset model). The routine's raw bytes contain no `AB F6` word.
- **Group-relative literal: 0.** No operand equals `0x0DB4` (`0x2F6AB - 0x2E8F7`). This is a hypothesis
  model only; see the boundary below.

### The 39 near calls

Near-call displacements are relative, so their targets are file offsets whatever the group base is.
All six targets lie before the routine, inside the group body:

| Target (file) | Calls | Group-relative (hypothesis) | Note |
| --- | ---: | ---: | --- |
| `0x2E8F7` | 1 | `0x0000` | the group's first byte |
| `0x2EA6B` | 1 | `0x0174` | |
| `0x2EB08` | 18 | `0x0211` | |
| `0x2EC16` | 2 | `0x031F` | |
| `0x2ED72` | 16 | `0x047B` | **the stub 2 proc** in [the group 29 probe](por-wall-group29-target-probe.md) |
| `0x2EEEA` | 1 | `0x05F3` | the wrapper the group 29 probe places before the owner (`retf` at `0x2EEF3`) |

None of the six lands inside the routine. The call to `0x2ED72` is a decoded edge into a group-29
proc. The probe does not follow it, so what that callee does is not established.

### Data operands

- 305 BP-relative operands (arguments and locals) and 21 distinct DS-direct addresses, in the range
  `0x0CAA..0x6AAC`. These are A5/DGROUP-style data references. Nothing identifies them as WALLDEF or
  DAX state.
- 83 immediate operands. None equals the literal offset or the group-relative literal offset.

## What the bytes do not establish

- What any of the six callees does. Whether one of them reaches a WALLDEF or DAX read is open.
- Whether `0x2EEF4` is called from anywhere. No caller is shown (see the render probe and the
  group-29 probe).
- Any record index, stride or slot. The 780 and 156 immediates are not in this routine, and no
  constant here is tied to WALLDEF.
- Any 8X8D tile, set or bank.

## Evidence boundary

- The routine's near-call targets and the ret boundary are decoded from the pinned bytes.
- "Group-relative" labels use the buffer-zero placement from one runtime quote (`33E7:0000`). That is
  a hypothesis, not a retail fact, and no group-relative conclusion above depends on it.
- The stub-2 match is an address equality taken from the group-29 doc. It does not show that stub 2 is
  reached through the INT 3Fh route, nor what its proc does.

## Unresolved edges

| Edge | Status |
| --- | --- |
| `0x2EEF4` callers | none shown (no caller probe was added here) |
| callee `0x2ED72` (16 calls; stub 2 proc) | decoded call; callee not decoded |
| callee `0x2EB08` (18 calls) | decoded call; callee not decoded |
| callees `0x2E8F7`, `0x2EA6B`, `0x2EC16`, `0x2EEEA` | decoded calls; callees not decoded |
| DS data `0x0CAA..0x6AAC` | identity not established |
| WALLDEF literal `0x2F6AB` | no reference from this routine |

## Next evidence needed

1. A callee walk: decode the six callee procs with the same tool and look for an inline INT 21h
   (AH=3Dh/3Fh/42h) or a far call to a WALLDEF/8X8D path.
2. A decoded caller of `0x2EEF4`, or a runtime stop on entry during a dungeon load.

## Tests

`tests/test_por_wall_owner_probe.py` (13 tests, all passing with the retail install set).

- Synthetic: the owner ends at the literal; near-call target and outside-routine claim; off-by-one call
  displacement changes the target; argument push visible before INT; no literal reference in a clean
  fixture; a pushed literal offset is a reference; a moved return is flagged; flow counts; refusals.
- Retail (gated on `OPENUA_POR_INSTALL`): pin match; 827 instructions; `retf 6` at `0x2F6A8`; 39 near
  calls; 0 far calls; no diagnostics; 0 literal references; source unchanged across the run.
