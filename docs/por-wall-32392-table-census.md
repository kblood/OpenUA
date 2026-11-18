# Pool of Radiance: bounded census of DS table-region accesses for GAME.OVR 0x32392

**Status: STATIC-CENSUS-ONLY. `playable: false`. `mappings: []`. `events_emitted: 0`.**

Companion to [por-wall-32392-trace-probe.md](por-wall-32392-trace-probe.md). That probe walks the
closure of `0x32392` and reports its own table accesses. This census asks the wider question: which
decoded instructions in the pinned `GAME.OVR` and `START.EXE` reference the same DS addresses, and which
of them write. It also shows where the byte evidence stops.

`tools/por_wall_32392_table_census.py` is read-only and stdlib-only. It reuses the existing decoders:
`por_loadpieces_handler.decode`, `por_wall_callee_probe.explore` and `por_farcall_resolve.scan_all` (the
VROOMM group partition), plus `por_convert.validate_output_dir`. Nothing under `tools/` or `tests/` is
modified. `tests/test_por_wall_32392_table_census.py` has 46 synthetic tests (mutated bytes that must change
the result) and one retail pin test gated on `OPENUA_POR_INSTALL`.

## Usage

```sh
python tools/por_wall_32392_table_census.py --install "PATH/TO/POOLRAD" -o data/work/por-wall-32392-table-census/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_wall_32392_table_census.py -q
```

Output: `data/work/por-wall-32392-table-census/retail/por_wall_32392_table_census.json` (schema
`openua.por-wall-32392-table-census` v1; sorted keys, no timestamps, no paths). Two runs are
byte-identical. The retail run exits `1` on diagnostics (see below). The tool writes nothing to the install.

## Pinned sources

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both are matched against the pins in `por_farcall_resolve.PINNED`. An unpinned input is refused (exit 2).

## Regions

Half-open DS-relative ranges, taken from the trace probe's stated extents (not re-derived here):

| Id | Range | Use |
| --- | --- | --- |
| W | `[0x2722, 0x272C)` | word table, five words (class index * 2) |
| F | `[0x5E3A, 0x5E4E)` | far-pointer table, five far pointers (class index * 4) |
| S | `[0x4A20, 0x4A24)` | secondary far pointer |
| Q | `[0x5E4E, 0x5E52)` | output far pointer |

## Method and what it can see

- **Units.** GAME.OVR: 34 VROOMM groups (24 well-formed, 10 partial) from `scan_all`. Each unit's roots are
  its well-formed stub targets. START.EXE: the MZ entry point, plus a continuation (see below). Each root is
  decoded by recursive descent, and near calls are followed only inside the unit's own span. An instruction
  that ends beyond the span is dropped and counted as a leaf. Far (9A) and indirect calls are recorded, not followed.
- **Operands.** Each memory operand is classified as direct, indexed (`[di|si|bx|...+disp]`, not BP-based), or stack.
  The opcode gives the role: read, write, rmw, address (LEA), far (4-byte pointer load), or indirect call target.
- **Matches.** A DS direct operand matches when its byte range overlaps a region. A DS indexed operand matches
  when its displacement lies in a region; this is necessary only, since the base register is not evaluated. ES
  prefixed operands match as `es-*` candidates and are never counted as DS.
- **Writers.** A procedure with a write or rmw match is a writer. A near-call BFS from its unit's roots reports
  the path, or that none exists within the walk.
- **Surface a displacement match cannot see.** Register-only writes (`mov [di],ax`), string stores, and procedures
  that hold an immediate equal to a region address, which is the usual way to load a base register.
- **Pointer hand-off.** Procedures that touch a region and then call out, listed with their far-call literals.
  A callee may receive a region pointer. It is not followed.

## What the bytes establish

### 1. Placement of `0x32392` in the descriptor scan

Under `scan_all` the owner is the **well-formed** stub at START `0x42E3`, index 2 of the group header at
`0x42C2` (fileofs `0x32235`, codesz `0x2B2`, stub start `0x42D9`). The stub's procedure offset is `0x15D`
(`0x32392 - 0x32235`). This is START-side descriptor evidence, not a runtime fact. It agrees with the trace
probe's stub `0x42E3` but does not measure the far call that reaches it.

### 2. The owner's own accesses (11 in the owner; 49 across the whole census)

| Site | Instruction | Role | Region |
| --- | --- | --- | --- |
| `0x32444` | `mov ax,[di+0x2722]` | read | W (indexed) |
| `0x3242E`, `0x32432` | `mov ax,[di+0x5E3A]`, `or ax,[di+0x5E3C]` | read | F (indexed) |
| `0x3246E`, `0x32472` | `push [di+0x5E3C]`, `push [di+0x5E3A]` | read | F (indexed) |
| `0x32490` | `les di,[di+0x5E3A]` | far | F (indexed) |
| `0x32476`, `0x3247A` | `push [0x4A22]`, `push [0x4A20]` | read | S (direct) |
| `0x324AF` | `les di,[0x5E4E]` | far | Q (direct) |
| `0x324CF`, `0x324D3` | `push [0x5E50]`, `push [0x5E4E]` | read | Q (direct) |

This agrees with the trace probe: the table is read, the pointers are loaded, and the owner writes none of W, F, S or Q
through a displacement. The owner makes **8** far calls, matching the trace probe.

### 3. No disp-carrying writer exists in the walked code

- **Writer procedures: 0.** No write or rmw operand in any walked GAME.OVR or START.EXE procedure carries a
  displacement or direct address that lands in W, F, S or Q.
- **All 49 region accesses are reads or far loads.** The 36 `S` matches are pushes, and the others are W/F/Q loads.
- **Answer: `no-disp-carrying-writes-in-walked-code`.** This is a statement about the bytes walked. It is not a
  statement that no writer exists anywhere in the program. See the write surface below.

### 4. The write surface (not classified by region)

| Channel | Records | Where |
| --- | ---: | --- |
| Register-only writes (`mov [di],ax` and kin) | 154 | GAME.OVR |
| String store (`rep movsb` in the START copy, `stos`) | 1 | START.EXE |
| Procedures with a region-address immediate and a register-only write | 0 | — |

The immediate channel is narrow: one immediate equal to a region address appears in the walk, `add di,0x5E3A` at
`0x322ED` (proc `0x32270`, the owner group's other stub, which reads F). That proc has no register-only write, so the
channel yields no candidate writer here. The register-only writes cannot be bound to a region without
evaluating the base register, which this census does not do.

### 5. Pointer hand-off to far callees

Eleven GAME.OVR procedures touch a region and then make far calls (about 3,584 far sites are walked overall). Two are
interesting:

- `0x32270` (owner group, stub index 1) passes `DS:DI` into an F element to far callee `0x0464:0x0111`. The callee
  is not followed, so any write it makes through that pointer is invisible here.
- `0x32392` (the owner) makes 8 far calls. The trace probe records that its far calls `0x0464:0x08D4` and `0x0AF8:1685`
  take region-derived values (the element pointer and the far copy destination) as arguments. This census only counts them.

These are the main false-negative channel for writes. The census lists them, but the bytes do not show what the callees do.

## Unwalked and outside-span bytes

| Scope | Code bytes | Walked | Unwalked | Notes |
| --- | ---: | ---: | ---: | --- |
| GAME.OVR, 34 group units | 197,451 | 168,795 (85.5%) | 28,656 (14.5%) | 429 fixup words lie in the unwalked bytes |
| START.EXE, MZ entry | 64,719 span | 38 | 64,681 | the entry stops at the trampoline `retf` |
| START.EXE, copied continuation | 154 copied | 95 | 59 | bounded to the copied `CX = 0x9A` bytes |

- **Stub procedures outside their group's span: 3.** Group `0x039E` root `4777` (codesz ends at `3338`), group
  `0x0561` root `60928`, group `0x3F2C` root `207139`. These roots are recorded and not walked, so the groups they
  belong to are either mis-partitioned or contain a stub whose procedure is elsewhere. Not resolved here.
- **Near calls that leave their unit: 0.** Every near call in the walked code stays inside its unit.
- **Far calls: 3,584 walked, all with a fixup-listed seg word.** A fixup-listed seg word is loader-patched, so
  the literal `seg:off` in the file names no fixed target. No far edge is followed or resolved here.

## Decode gaps and diagnostics

Exit `1` is reported because two diagnostics fired:

| Diagnostic | Where | Effect |
| --- | --- | --- |
| `decode-incomplete` | group `0x04F1` at `0xA085` (`0x65`, a 386 prefix) | the walk reached non-8086 bytes, probably data |
| `decode-incomplete` | group `0x0516` at `0xB3D5` (`FE /2`, undefined in 8086) | probably data |
| `decode-incomplete` | partial group `0x08CD` at `0x1AFEE` (`insn-budget`, 1200) | the procedure budget was hit |
| `byte-conflicts-between-procedures` | group `0x04F1`, 4 bytes | two procedures decode different instruction boundaries over the same bytes |

Those gaps sit in groups other than the owner's, and the owner's group decodes cleanly.

START's own `DS` is `CS` after `push cs; pop ds`, and the census does not show it equal to the overlay's DGROUP. START
matches therefore carry that caveat. The START walk found no region access at all.

## Limits and false-positive risks

| Risk | Direction | Mitigation in the output |
| --- | --- | --- |
| Indexed matches ignore the base register: `[di+0x5E3A]` matches F whatever `di` holds. | false positive | every indexed match is labelled `indexed-disp-in-region` |
| Register-only writes and string stores cannot be bound to a region. | false negative (writers) | counted and listed as the write surface |
| Pointers passed to far or near callees are not followed. | false negative (writers) | pointer hand-off list |
| Far calls are not resolved (every seg word is fixup-listed). | false negative (call paths) | recorded with the fixup flag |
| Unwalked bytes (14.5% of GAME.OVR code, and nearly all of START). | false negative (everything) | coverage per unit |
| Data decoded as code in groups with decode gaps. | false positive | decode-incomplete and byte-conflict diagnostics |
| DS assumed equal to DGROUP in overlay code; START's DS is its image segment. | false positive | DS reassign sites listed; START caveat |
| The stub-root path check covers only near-call closure inside a unit. | false negative (reachability) | the root's own callers are not known |

## Limits and unresolved edges

| Edge or question | Status |
| --- | --- |
| Whether `0x32392` runs, or what reaches it at runtime | not established (static bytes only) |
| Which far call reaches the owner's stub, and under which delta | not re-measured here |
| The contents of W, F, S, Q and what the far pointers name | runtime data; not in the install's bytes |
| Table binding to WALLDEF / 8X8D data | **not established** |
| Which record a class index selects | not established |
| Writers through register bases or pointer hand-off | not established (write surface and hand-off list only) |
| START resident code outside the entry and copied continuation | unwalked; reachable only through far calls the census cannot resolve |

## Tests

`tests/test_por_wall_32392_table_census.py`: 46 synthetic tests and one retail pin test, all passing with
`OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD"` on 2026-11-18. The synthetic tests cover the access
roles (each with a mutation that flips the role), region boundaries (start, end, and straddling), ES versus DS
versus CS prefixes, BP-based operands, the bounded walk (leaves and roots outside the span), the write surface,
the immediate channel, the pointer hand-off, the START trampoline, refusals, and determinism. The retail test asserts
the owner's accesses, the zero-writer answer, the write-surface count, the 11 region procedures, the START copy length
`0x9A` and continuation `0x38`, the two diagnostics, and that the install is unchanged.
