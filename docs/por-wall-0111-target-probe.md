# Pool of Radiance: identity and bounded body of the far target 0x0464:0x0111 (called from GAME.OVR 0x32270)

**Status: STATIC-PROBE-ONLY. `playable: false`.** Answer: **the callee is located uniquely at START.EXE `0x478A` in both RAM dumps, conditional on the caller group's own measured delta (`0x1866`) applying to the callee's segment word.** The body is decoded inside a bounded walk. Its ES:DI-origin facts are linear-order facts, not control flow. Nothing here establishes that the callee runs, what its arguments are at run time, or that its writes reach the F table.

Companion to [por-wall-32392-table-census.md](por-wall-32392-table-census.md) (section 5 found the call and left the callee unfollowed) and [por-wall-far-target-probe.md](por-wall-far-target-probe.md) (resolved the other `0x0464` targets under a sibling-consensus delta). This probe does not use the consensus delta; it uses the caller's own measured delta.

`tools/por_wall_0111_target_probe.py` is read-only and stdlib-only. It reuses `por_overlay_group_map`, `por_wall_far_target_probe` (`descriptor_table`, `masked_hits`), `por_wall_32392_table_census` (`walk_procs`, `operand`, `region_matches`) and `por_wall_callee_probe` (`explore`). Nothing under `tools/` or `tests/` that already exists was modified. `tests/test_por_wall_0111_target_probe.py` has 20 synthetic tests (mutated bytes that must change the result) and one retail pin test gated on `OPENUA_POR_INSTALL`.

## Usage

```sh
python tools/por_wall_0111_target_probe.py --install "PATH/TO/POOLRAD" \
    --dump data/work/por-live-memory-pid34644/ram-000000-100000.bin \
    --dump data/work/por-wheel-live-capture/ram-000000-100000.bin \
    -o data/work/por-wall-0111-target-probe/retail
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_wall_0111_target_probe.py -q
```

Output: `data/work/por-wall-0111-target-probe/retail/por_wall_0111_target_probe.json` (schema `openua.por-wall-0111-target-probe` v1; sorted keys; no timestamps, no absolute paths). Two runs are byte-identical. Exit `0` = located uniquely in every dump; exit `1` = not identified (diagnostic); exit `2` = named refusal (unpinned input, bad install, output outside `data/work`). The retail run exits `0`. The tool writes nothing to the install.

## Pinned and measured inputs

| Input | Bytes | Note |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | SHA-256 `872964a3…7928614`, pin matched |
| `START.EXE` | 65,231 | SHA-256 `d825df2b…60b6a07bd`, pin matched |
| `data/work/por-live-memory-pid34644/ram-000000-100000.bin` | 1,048,576 | base 0, RAM dump |
| `data/work/por-wheel-live-capture/ram-000000-100000.bin` | 1,048,576 | base 0, RAM dump (a separate capture, not a repeat) |

## What the bytes establish

### 1. The call sites

`9A 11 01 64 04` (call far `0464:0111`) occurs **19 times in GAME.OVR and 0 times in START.EXE**. The focus site is GAME.OVR `0x322F3`, inside procedure `0x32270`, which decodes cleanly and contains the site. Its segment word (`0x322F6`, body offset `0xC1`) is **fixup-listed** in VROOMM group `0x42C2` (file `0x32235`, codesz `0x2B2`), and its raw word is `0x0464`.

The caller's argument setup, decoded (`0x322E2`–`0x322F2`): `shl`, `shl`, `add di,0x5E3A`, `push ds`, `push di`. So the callee receives `DS:DI`, where `DI = 0x5E3A + 4 × index`: the address of an F-table element, under the census's DS assumption (the caller's DS is the overlay's DGROUP).

### 2. The caller's measured delta

Group `0x42C2` maps uniquely in **both** dumps (base `0x327D0`). In each dump the live segment word at the focus site is `0x1CCA`, so the site's delta is `0x1CCA − 0x0464 = 0x1866`. **Every one of the group's 25 fixup words gives `0x1866` in each dump**, so the group's delta is uniform and measured. This is the only delta the probe uses. The sibling-consensus value (`0x1866`, from the earlier probe) agrees, but the probe does not rely on it.

Applying that delta once, the callee's segment is `(0x0464 + 0x1866) & 0xFFFF = 0x1CCA`, and its live window is at linear `0x1CDB1` (`0x1CCA × 16 + 0x111`) in both dumps.

### 3. Identity: START.EXE `0x478A`, unique

The 32 live bytes at `0x1CDB1` are `55 89 e5 81 ec 20 01 c4 …`. No exact 32-byte match exists in the pinned files. **One masked match exists in each dump, in START.EXE at `0x478A`**. The masked rule is the one used for far calls elsewhere: the windows are equal except one 16-bit word after a `9A`, which differs by exactly the delta. Here that word is `0x235E` live versus `0x0AF8` in the file (`0x0AF8 + 0x1866 = 0x235E`), so the callee's own far call `call 0x0AF8:0x0B25` (`START 0x47A0`) is the differing word.

Consistency check, arithmetic only: START offset minus segment offset is `0x4679` for `0x0464:0x0111` (`0x478A − 0x111`) and for every already-resolved `0x0464` target (`00FF → 0x4778`, `08D4 → 0x4F4D`, `1951 → 0x5FCA`, `1B52 → 0x61CB`, `2632 → 0x6CAB`). The six agree. This shows the offsets are mutually consistent under one arithmetic relation; it does not prove a segment model, and the tool does not use it to decide the match.

**Conditional scope of the identity.** The result holds if (a) the caller group's measured delta applies to the `0x0464` segment word, and (b) the `0x0AF8` word in the callee's own call is relocated by the same delta (the live `0x235E` is the only evidence for that word). Neither is proved independently of the dumps. The two dumps are two captures and agree.

### 4. The body (bounded walk, explicit span `0x4000..0x8000`)

The walk decodes 989 instructions in six procedures: `0x478A` (the target), `0x491E` (near-called from `0x48FF`), `0x6B07` (near-called from `0x4898`), `0x6C0E` (near-called from `0x47B7`), and two helpers `0x4679` and `0x46F4` reached from `0x491E`. No near call leaves the span. No instruction is incomplete.

**Passed-record writes (straight-line ES:DI origin, `les di,[bp+6]` → `es: mov`).** The callee's `[bp+6]` far pointer is the F element; the body never writes through it directly. It hands the pointer to two helpers, which do:

| Site | Procedure | Instruction | Reading |
| --- | --- | --- | --- |
| `0x6B41`, `0x6B44` | `0x6B07` | `es mov [di],ax`; `es mov [di+2],dx` | stores `DX:AX` into the first dword of the passed element |
| `0x6C9E`, `0x6CA1` | `0x6C0E` | `es mov [di],ax`; `es mov [di+2],ax` (`AX=0` from `xor ax,ax` at `0x6C9C`) | clears the first dword |

`0x6B07`'s value comes from `call 0x0AF8:0x023F` (`0x6B39`), whose return is taken as `DX:AX`. `0x6C0E`'s clear sits behind branches (`0x6C1E`/`0x6C20`, `0x6C4D`) that the walk does not evaluate: it runs when the element's first dword is non-zero. The helpers' call sites are reached from the body with the passed pointer (`push es; push di; push cs; call near`, `0x47B4`–`0x47B7` and `0x4895`–`0x4898`).

**Passed-record reads.** The body reads the element's first dword (`es mov [di]`, `es or [di+2]` at `0x47A8`–`0x47AB`, the zero test), loads a far pointer from it (`es les [di]`, `0x489E`), and pushes its words (`0x48F7`, `0x48FB`). The helpers read the same dword (`0x6C17`, `0x6C1A`, `0x6B4B`, and others).

**Other-origin ES accesses (not attributed to the passed record).** 23 ES writes and 47 ES reads in `0x491E` and the body go through ES:DI loaded from other pointers (`les [bp-286]`, `les [di+19]`). They are recorded, not assigned to the passed record.

**No INT 21h, no DOS file function, no WALLDEF/8X8D/DAX token in the walked bytes.** One `DAX` token lies at START `0x4787`, three bytes before the entry, outside every walked instruction byte.

**No DS-relative table access.** The walk has no DS operand that overlaps W, F, S or Q, and no immediate equal to a region address. Four DS direct operands exist, all at `DS:0x4A1E`: written once (`0x4942`, in `0x491E`) and tested by `0x6B07` and `0x6C0E` (`0x6B18`, `0x6B9B`, `0x6C4F`). That address sits just below S (`0x4A20..0x4A24`) and does not overlap it. Its meaning is not established.

**Far calls not followed** (the walk's edge, 25 sites): `0x0AF8:0x0B25`, `0x0AF8:0x0B0B`, `0x0802:0x0716`, `0x0AF8:0x1685` (× 9, copies), `0x0AF8:0x0A3F` (× 2), `0x0AF8:0x0254` (× 4), `0x0AF8:0x023F` (× 3), `0x0AF8:0x16A8` (× 3), `0x0899:0x0104`. Module `0x0AF8` is the module the earlier probes identified for copy and fill helpers; `0x023F`, `0x0254`, `0x0802:0x0716` and `0x0899:0x0104` are not identified.

## Answers to the four questions

| Question | Answer under the stated conditions | Evidence type |
| --- | --- | --- |
| Can pinned bytes plus the dumps locate the callee? | **Yes**: START `0x478A`, unique in each dump, under the caller's measured delta `0x1866` | masked one-word window, two dumps |
| Does the callee write the passed record? | **Yes, in two helpers** (`0x6B07` stores `DX:AX`; `0x6C0E` clears), reached from the body with the passed pointer | straight-line origin, branches not evaluated |
| Does it access DOS, DAX, WALLDEF or 8X8D? | **No** INT 21h and **no** token in walked bytes; `0x0802:0x0716` is not followed | bounded walk |
| Does it help locate W/F/S/Q initialisation? | **Candidate only.** If the caller's `DS:DI` is an F element (census DS assumption), `0x6B07` is a store of a far pointer into the F slot and `0x6C0E` a clear. W, S, Q: no evidence in the walk | conditional on the DS assumption; reading of the store is a hypothesis |

## What this does not establish

- That the caller's delta is the callee segment's true delta for every call of `0x0464`. The sibling and caller measurements agree; that is not proof.
- That `0x0464:0x0111` runs, at any real instant, or with which arguments.
- That the passed pointer is an F element at run time (the caller's `DS` and table index are not measured in either dump).
- That `0x0AF8:0x023F` allocates, or that `0x6B07` is an allocator-store. These are readings of the stored value and the call's shape, not identified routines.
- That the `0x6C0E` clear, or the `0x6B07` store, is reached on a real path. The walk ignores branch conditions.
- The meaning of the record fields beyond offset 0 and 2, and whether any write reaches W, F, S or Q through a DS displacement (none is in the walk).

## Limits

| Edge | Status |
| --- | --- |
| Caller group `0x42C2` delta | measured uniform in both dumps (25 fixups), not in the owner group |
| Callee `0x0AF8` word relocation | live `0x235E` only; same delta assumed |
| Walk span `0x4000..0x8000` | an explicit bound chosen for this probe; no near call leaves it |
| Origin tracking | linear order per procedure; reset at calls, branch targets and possible DI/ES clobbers |
| DS as DGROUP | assumed by the census; the caller pushes its DS, so the callee's ES equals it |
| Branches | not evaluated; the writes are reachable in straight-line order from the entry |
| `DS:0x4A1E` flag | written and read; meaning not established |

## Next discriminator

1. **Identify `0x0AF8:0x023F` and `0x0AF8:0x0254`** from the module bytes (the return convention and the size argument). If `0x023F` returns a block pointer in `DX:AX` and `0x0254` releases one, `0x6B07`/`0x6C0E` are an allocate/free pair for the F slot. That would be a stronger reading of the F writes, still not a runtime fact.
2. **A RAM dump whose instant is inside `0x32270`** (or with the F table visible at `DS:0x5E3A..0x5E4E`). The two existing dumps do not show the overlay's DS (no measured DGROUP base), so the F slot's contents cannot be read from them. A dump taken with the DGROUP base known, before and after the `0x0464:0x0111` call, would show whether the first dword of an F slot changes. That is the observation that would promote the F-write claim, and it needs new capture, not analysis.
3. **Measure the overlay DGROUP base in a dump** (for example through a DS-relative constant the body reads, such as `DS:0x4A1E` or the F table), so the DS assumption becomes a measurement.

## Tests

`tests/test_por_wall_0111_target_probe.py`: 20 synthetic tests and 1 retail test (gated). Synthetic: call-site search and its falsifiers; the caller's measured-delta rule (five falsifiers: group not uniform, dumps disagree, not fixup-listed, raw word wrong, one dump not unique); window resolution (masked unique, one-byte falsifier, delta off by one, exact mode, ambiguous repeat, out-of-dump); the ES:DI origin rule (les of another pointer, far call, `mov di,imm`, `mov ax,imm` non-clobbering); the touch table; the body (passed writes found, falsified by replacing the les, falsified by a far call between les and write, INT 21h detection, a token inside walked bytes counted and one outside not). Retail: pins matched, 19 call sites, focus group `0x42C2` body `0xBE` fixup-listed, caller delta `0x1866`, resolution `START 0x478A`, the four passed-record writes at `0x6B41`, `0x6B44`, `0x6C9E`, `0x6CA1`, no INT 21h, no body token, no DS region match, no region immediate, complete walk.

Results (2026-11-18): `python -m pytest tests/test_por_wall_0111_target_probe.py -q` → **20 passed, 1 skipped** without the pin; with `OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD"` → **21 passed**.
