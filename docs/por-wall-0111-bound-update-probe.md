# PoR wall 0111: bound-update probe (module routines 0x0AF8:0x0432, 0x03D3, 0x0491)

Status: **STATIC-PROBE-ONLY**. `playable: false`. `executed: not_established`.

This note answers one question from the module-target handoff: do the two calls in module routine
0x03D3 update the free-list bounds, as the earlier hypothesis said? It decodes the three routines from
pinned PoR bytes and reports what the bytes show. It does not show that any of them runs, with which
arguments, or against which list state.

Tool: `tools/por_wall_0111_bound_update_probe.py`. Test: `tests/test_por_wall_0111_bound_update_probe.py`.
Output (git-ignored): `data/work/por-wall-0111-bound-update-probe/por_wall_0111_bound_update_probe.json`.

## Inputs and anchors

- Module segment `0x0AF8` (file base `0xAC76`, so module offset = file offset - `0xAC76`). Live segment
  `0x235E` = `0x0AF8` + load `0x1866`.
- Pins: `START.EXE` sha256 `d825df2b…`, 65,231 bytes; `GAME.OVR` sha256 `872964a3…`, 206,105 bytes.
  Both match the pinned values.
- Two RAM dumps (`por-live-memory-pid34644`, `por-wheel-live-capture`, sha prefixes `f8191750…`,
  `3788787c…`). Both anchor the module uniquely at linear `0x235E0`.

## What was decoded

All three routines decode through the probe's own 16-bit ModRM decoder. The repo decoder's `text()`
drops the register for memory forms, so it was used only as a cross-check on length, flow and target.
Every instruction in each span agrees with that cross-check (0 failures).

| Routine | Span | Instructions | Returns | Direct callers (module offset) |
|---|---|---|---|---|
| 0x03D3 (release) | 0x03D3..0x0431 | 42 | 0x042F, 0x0431 | wrapper call at 0x025F (in START) |
| 0x0432 (link) | 0x0432..0x0490 | 45 | 0x0467, 0x0488, 0x0490 | 0x03D3 at 0x0426 and 0x042B |
| 0x0491 (size) | 0x0491..0x04A1 | 8 | 0x04A1 | 0x03D3 at 0x03F9; 0x030F (near candidate) |

Each span was checked against an expected listing of its exact bytes, and that listing matched in full
(42, 45 and 8 rows). External edges: none. Callers were searched as near `E8` candidates and as far
`9A`/`EA` operands in START and GAME.OVR; no far references were found.

### Register inputs (upward-exposed reads, backward liveness)

- 0x03D3: `ax, bx, cx, ds`.
- 0x0432: `bx, cx, di, ds, es`. The first read is `mov ax,di` at 0x0432.
- 0x0491: `ax`.

### Stores

- 0x03D3 writes only ES-relative memory: `mov es:[di+4],ax` at 0x0400 and `mov es:[di+6],dx` at 0x0404.
- 0x0432 writes two direct DS slots, both on the reachable path:
  - `mov ds:[0x4404],di` at 0x045F (high bound offset),
  - `mov ds:[0x4406],es` at 0x0463 (high bound segment).
- 0x0432 also writes ES-relative memory: `movsw` at 0x046F and 0x0470, `stosw` at 0x0483 and 0x0485,
  `mov es:[di],ax` at 0x0489, `mov es:[di+2],dx` at 0x048C.
- The head slot DS:0x440C is not written by any direct store. It is reached only through ES:DI
  (`mov di,0x440c` at 0x0408 and `les di,es:[di]` at 0x0413).

## The bounds answer (byte level)

**Partly supported, and narrower than the hypothesis.**

- The two calls in 0x03D3 do reach the bound stores, but only through 0x0432, and only the high bound is
  written: DS:0x4404:0x4406, at 0x045F and 0x0463.
- The write is conditional. The first call stores the high bound only on the path where the block's end
  equals its successor and that successor equals the high bound (the compares at 0x0453 and 0x0459,
  falling through the `jnz` at 0x0457 and 0x045D).
- The second call can store the high bound again only after the first has already set it to the block
  (the chain noted in the handoff).
- The low bound DS:0x4400:0x4402 is never written by any reachable byte.

This is a byte-level statement only. Whether a store takes place at run time depends on values the
bytes compare, and those values were not measured.

### Sanity checks on the reading

- Flag pairs: `add cl,0xf0`/`adc bx,0x0` (0x0442/0x0445), `add al,0xf0`/`adc dx,0x0` (0x047C/0x047E), and
  `add ax,0x7`/`rcr dx,1` (0x0491/0x0496, with `mov dx,ax` between them, which does not touch flags).
  All matched.
- Head chain: the walk from `mov di,0x440c` (0x0408) through the first `les` and the link call matched
  the expected listing.

## The size helper (0x0491)

Reading (matches the decoded sequence exactly): AX := S+7 with CF = carry out; DX := ((CF<<15) |
((S+7)&0xFFFF)>>1)>>3; AX := (S+7)&8. The returned pair is DX:AX, so 16·DX + AX = roundup8(S) and AX is
0 or 8. The tests check this identity for all 65,535 non-zero words. The caller at 0x03D3 stores the
pair into the block's +4..+7 dword, not the raw size.

## Normalisation (0x0442 in 0x0432; 0x047C in the merge path)

`add lo,0xf0 ; adc hi,0 ; and lo,0x0f` gives `(hi + [lo >= 16], lo & 0xF)`. It is exact when the low sum
is below 32 and differs from the paragraph/offset split at 32. The tests check both sides.

## Zero-size exit (0x03D3)

`or ax,ax` followed by `jz 0x0431`. On the zero path CF is clear, because `or` clears it and the `stc`
at 0x0430 is skipped. The landing is a bare `ret`.

## Corrections to the module-target note

- **Zero size is not refused.** The `jz` lands on a bare `ret` with CF clear: a no-op success under the
  carry convention. The note's "refused" is wrong on these bytes.
- **String moves exist.** Non-rep `movsw`, `lodsw` and `stosw` are on the merge path 0x0468..0x0487,
  reached from 0x0432 through the `jnz` at 0x0457 and 0x045D. The note's "no string move in 0x3D3/0x432"
  is wrong. There is no `rep` prefix, so this is not a bulk copy.

The note's claims that 0x0432 stores DS:0x4404 and DS:0x4406, and that 0x0254 is the release helper, are
consistent with the bytes. 0x0254 itself was not re-decoded here.

## Falsifiers

The test file mutates the fixture bytes and checks that the claims fail:

- branch flips (0x044D, 0x03D5), a call retarget to a non-entry (refused, fail closed), and a call
  retarget to the size helper (breaks the link-caller check);
- an external branch from 0x03D3 into the merge path (0x0421, `ja 0x0468`);
- a store moved behind an always-taken branch (0x0457 `jnz` to `jmp`), which removes the stores at
  0x045F/0x0463 and the ret at 0x0467 from the reachable set;
- a `movsw` replaced by `nop`, a high-bound store retargeted to the low bound, and a high-bound store
  turned into a load;
- the head-slot load (0x0408), the size-helper shift (0x0498), the flag-pair adjacency (0x0494), and the
  opcode outside the subset (0x0F, refused).

The synthetic fixture places the wrapper's call (`e8 71 01` at 0x025F) so the release-caller path is
exercised.

## Open edges (not established by this probe)

1. Whether any of these routines runs, and with which arguments. The caller's DS, the block size and the
   list state were not measured.
2. The values of DS:0x4400..0x4407 and DS:0x440C..0x440F at any instant. No value is read from any dump
   here.
3. That the free list is ordered, initialised or sentinel-terminated as the reading suggests. The
   reading comes from compare and store shapes only.
4. What the allocator does at run time. The search that feeds 0x0254 (0x0308 and its successors) was not
   decoded, so whether the top bound is ever raised is not shown.
5. The order and data conditions of the two calls in 0x03D3. The bytes fix the order (forward with the
   successor first, then backward with the predecessor) and the compare shapes. Which branch each call
   takes depends on values not measured here.
6. When the insertion point is the head, the predecessor is DS:0x440C itself. The bytes do not say
   whether DS:0x4410..0x4413 then holds a sane size.
7. Whether a free node can be adjacent to the top bound when a release absorbs a block into it. The bytes
   use the same compare in that case; no invariant is decoded.
8. Indirect callers (far pointers in data, jump tables). Only direct byte candidates were searched.
9. Node offsets other than 0 and 8, and size low-words other than 0 and 8, for nodes that did not come
   from 0x03D3. The normalisation is exact only under those ranges.
10. The wrapper's error codes. Its carry convention is taken from the module-target note; the error join
    at module 0x00E2 was not decoded.

## Usage

```sh
python -m pytest tests/test_por_wall_0111_bound_update_probe.py -q
OPENUA_POR_INSTALL=data/work/por-geo-run/POOLRAD python -m pytest tests/test_por_wall_0111_bound_update_probe.py -q
python tools/por_wall_0111_bound_update_probe.py
```

The CLI refuses output outside `data/work`, output inside the install, and an unpinned install (exit 2).
It exits 1 if a self-check fails.

## Results

- Focused tests, no install: 32 passed, 1 skipped (the gated retail test).
- Focused tests with `OPENUA_POR_INSTALL` set: 33 passed.
- Pinned CLI: exit 0, `self_checks_passed: true`, all 20 self-checks true, high bound written at
  0x045F and 0x0463, low bound not written. A second run produced a byte-identical JSON (`cmp`).

No existing file was edited. No retail file was edited. Nothing was committed or pushed. GoldBox was not
touched.
