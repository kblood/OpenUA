# Pool of Radiance: argument-push shape of the strong residue-compatible far calls

**Status: STATIC-PROBE-ONLY. `playable: false`, `established: false`, `mappings: []`. Shape comparison only.**

## Handoff

- **Verdict: `imm-id-shape-only`.** Of the **166** strong residue-compatible far-call sites (census: 181 candidates,
  166 strong), **9** are preceded by the known two-far-pointer push shape of the loader (START `0x876D`). In all nine the id word is
  pushed as `mov al,imm8; push ax`. **None (0)** uses the documented id form `mov al,[bp+d8]; push ax`.
- **The id form does not separate them from the loader.** The loader's own ten static call sites use both forms:
  nine documented, and START `0x7276` with `mov al,imm8`. So the nine are a shape match in the loader-caller sense,
  not a documented-form match. This is shape only: not a call to the loader, not runtime reachability, not target
  identity, not a GEO archive or block mapping, not a binding.
- **Counts (strong sites, `analysed_strong_sites` = 166):** no fall-through predecessor 0; entered by a branch 0;
  mismatched with the census 0; shape classes `loader-shape-imm-id` 9, `one-pointer` 2, `no-pointer-pair` 155. The nine
  have no branch join inside their window. All nine call the same `seg:off` `0085:005C`, which is not the loader's
  `0802:0716`.
- **Premise correction.** The brief describes the loader shape as "five far-pointer arguments". The existing
  caller-frame doc describes ten pushed bytes: one id word plus two far pointers (five words). The loader's full
  18-byte argument block is four far pointers plus one word, because two more far pointers are leftovers that the
  caller did not pop. This tool compares against the ten-byte pushed shape, as the existing probe does.
- **Tests:** `tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_argpush_shape.py -q`
  → **21 passed, 3 skipped** (no retail input). With `OPENUA_POR_INSTALL` set to the pinned POOLRAD folder →
  **24 passed**. Regression: the census and caller-frame test files → 53 passed.
- **Retail CLI:** `python -I tools/por_geo_stub_farcall_argpush_shape.py --install data/work/por-geo-run/POOLRAD -o data/work/por-geo-stub-farcall-argpush-shape/retail`
  → `shape_status=imm-id-shape-only strong_candidates=166 documented=0 imm=9 self_checks=pass`, exit 0, 14 of 14 self-checks pass.
- **Files (new, uncommitted):** `tools/por_geo_stub_farcall_argpush_shape.py`,
  `tests/test_por_geo_stub_farcall_argpush_shape.py`, `docs/por-geo-stub-farcall-argpush-shape.md`. Output (git-ignored):
  `data/work/por-geo-stub-farcall-argpush-shape/retail/por_geo_stub_farcall_argpush_shape.{json,md}`. The census,
  caller-frame and loader modules and their docs are unchanged (`git status` clean for them).
- **Next discriminator.** (1) Walk the caller frame at each of the nine sites with the caller-frame probe's own
  stack model, and check whether the callee's `retf` leftover balances as it does at the walked loader sites. (2) For
  `0085:005C`, the DI constraint from the census (`di_constraint_mod64k`) bounds which bodies it can reach; check their
  `retf` counts. Both need the same unknown DI and paragraph assumptions the census carries. A live capture at one
  nine-site call would settle it directly.

## Question

> Among the 166 strong residue-compatible far-call sites, does the instruction sequence immediately before the `9A`
> call resemble the loader's known caller shape? (The loader is the generic DAX loader at START `0x876D`.)

Only the strong sites were analysed. The 15 weak-only residue candidates are out of scope and are not in any table.

## Known shape (from the existing probes)

The loader call is `9A 16 07 02 08` (`0x0802:0x0716`). The caller pushes ten bytes before it, in this order:

1. an id word: `mov al,[bp+d8]; push ax` (the documented form, read from the caller's own argument), or
   `mov al,imm8; push ax` (the form the loader probe's `SHAPE_RE` also accepts);
2. a far pointer: `lea di,[bp+d]; push ss; push di`;
3. a second far pointer, the same three instructions.

The same shape is what `tools/por_geo_loader_caller_frame_probe.py` matches with its byte regex `SHAPE_RE`. The control
below checks that this tool's instruction scan agrees with that byte regex at all ten loader sites.

## Method

1. **Candidates.** `por_geo_stub_farcall_census.analyse` supplies the candidate sites. Each has one owner row, and
   a strong candidate's owner row is strong (166 of 181).
2. **Strong re-walk.** The owner group is re-walked with the census's own pass 1 (`por_geo_stub_farcall_census._walk`
   seeded from the group's well-formed stub procs). The re-walk's far-call set is compared, per group, with the
   census's strong far-call set. Any mismatch fails the run.
3. **Fall-through chain.** The instruction covering byte `at-1` must end at `at`. The chain walks back through decoded
   instruction ends, nearest first, up to 16 instructions. No inference is made across a gap.
4. **Shape scan.** Instruction-aligned, nearest first: three instructions `push di`, `push ss`, `lea di,[bp+d]` form one
   far pointer; two of them, then `push ax` and `mov al,...`, form the shape. The scan reports the pointer-pair count,
   the id form, and the lea displacements.
5. **Joins and entries.** A branch target strictly inside the consumed window (after its first byte, before the call)
   is a join. A branch whose target is the call is an entry. Only strong-pass control flow is used.
6. **Control.** The ten static loader call sites (`lcf.call_sites`, GAME.OVR x8, START.EXE x2) are scanned on their
   linear chain from `lcf.find_proc`. The scan must agree with the loader probe's byte regex at every site.

## Results

| Item | Value |
| --- | ---: |
| Census candidate sites (181) | 181 |
| Strong candidate sites | 166 |
| Analysed (strong, mismatches 0) | 166 |
| Fall-through predecessor missing (ambiguous) | 0 |
| Entered by a branch (call is a branch target) | 0 |
| `loader-shape-documented-id` (`mov al,[bp+d8]`) | **0** |
| `loader-shape-imm-id` (`mov al,imm8`) | **9** |
| Loader shape with a branch join in its window | 0 (all nine are clean) |
| `one-pointer` | 2 |
| `no-pointer-pair` | 155 |

Owner coverage of the 166 strong sites: 165 `strong-walk-clean`, 1 `strong-walk-incomplete` (`0xA888` in group `0x9807`,
class `no-pointer-pair`). Owner status: 115 well-formed, 51 partial.

### The nine loader-shape sites

All nine call `0085:005C`. Each window is `mov al,imm8; push ax; lea; push ss; push di; lea; push ss; push di`.

| at | owner group | owner status | id imm | lea `[bp+d]` (nearest first) | window start |
| --- | --- | --- | ---: | --- | --- |
| `0x14C4E` | `0x127FB` | well-formed | 1 | -6, -5 | `0x14C41` |
| `0x17D07` | `0x17831` | well-formed | 1 | -3, -2 | `0x17CFA` |
| `0x18168` | `0x17831` | well-formed | 0 | -2, -7 | `0x1815B` |
| `0x1820A` | `0x17831` | well-formed | 2 | -2, -7 | `0x181FD` |
| `0x182A0` | `0x17831` | well-formed | 0 | -2, -7 | `0x18293` |
| `0x183B9` | `0x17831` | well-formed | 0 | -2, -8 | `0x183AC` |
| `0x18422` | `0x17831` | well-formed | 3 | -2, -8 | `0x18415` |
| `0x1861E` | `0x17831` | well-formed | 0 | -2, -8 | `0x18611` |
| `0x1C900` | `0x1997F` | partial | 4 | -28, -27 | `0x1C8F3` |

Seven of the nine share group `0x17831`. Each owner coverage is `strong-walk-clean`.

### Control: the ten static loader call sites

| image | at | proc | class | id form | pointer pairs | byte regex hit |
| --- | --- | --- | --- | --- | ---: | --- |
| GAME.OVR | `0x279E` | `0x26F6` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x78A6` | `0x7814` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x1EF0D` | `0x1EEAA` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x1F0A8` | `0x1EEAA` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x1F190` | `0x1EEAA` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x2E246` | `0x2E170` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x2F767` | `0x2F6FF` | documented id | `mov-al-bp` | 2 | yes |
| GAME.OVR | `0x2FA17` | `0x2F9BE` | documented id | `mov-al-bp` | 2 | yes |
| START.EXE | `0x47E0` | `0x478A` | documented id | `mov-al-bp` | 2 | yes |
| START.EXE | `0x7276` | `0x7245` | **imm8 id** | `mov-al-imm` | 2 | yes |

The second column is the enclosing procedure (consistent with the `0x2FA17` site inside the GEO fill at `0x2F9BE`). The `0x2F767` site is inside the WALLDEF wrapper (`0x2F6FF`), not the GEO fill.

The scan agrees with the byte regex at all ten sites. The imm8 id at START `0x7276` is the reason the imm8 form cannot
be treated as "not the loader shape".

## What is established

- **Bytes.** The nine windows and their decoded instruction boundaries (decoder raw bytes checked against the input at
  every instruction). The absence of the documented id form among the 166 strong sites.
- **Decode.** The strong re-walk reproduces the census's strong far-call set in every owner group used (mirror check).
- **Control.** The scan reproduces the loader probe's byte regex at all ten loader sites, and the two id forms both
  occur there.

## What is not established

- That any of the nine sites runs, that its callee `0085:005C` is reached, or that any call is executed at any instant.
- That `0085:005C` is the loader, stub 6, or any body in the census. Its segment base is not established
  (the census's residue rule assumes an unknown DI).
- The callee's `retf` count, the caller's stack balance after the call, and the contents of any pointer.
- Any GEO archive, block, area, or plane-2 mapping. Nothing here is a binding.
- That the imm8 id form and the documented form differ in meaning. The control shows both forms at loader sites.

## Limits

- The chain and joins use only the census's strong decode. Weak (prologue-seeded) decode is not evidence of a path.
- Indirect branches are not followed. A branch from an undecoded or indirect source is invisible to the join check.
- The scan is instruction-aligned and strict. It admits only `lea di,[bp+d]` and `push ss; push di`. Other pointer
  pushes (for example `push cs; push di`) are not counted, by design.
- The inherited census limits apply: the DI delta and the MZ paragraph model are assumed.

## Pins, hashes and side effects

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Install: `data/work/por-geo-run/POOLRAD` (both pins matched; hashed before and after the run, unchanged).

| Output | SHA-256 |
| --- | --- |
| `por_geo_stub_farcall_argpush_shape.json` | `8d73a51a173181ac5bcab228a1a73e97923b947bf12625a7e7f8174a0f8d9d96` |
| `por_geo_stub_farcall_argpush_shape.md` | `8fbaa45fc1b72897da8be8dad4a9ff465fc1184bbf25fca291ae584de9fbf6bd` |
| `tools/por_geo_stub_farcall_argpush_shape.py` (as run) | `2efc209bdb0d0981136e67830003888a355fb1f05551546b19926b3bc25d370b` |

- No retail write. The probe writes only under `data/work/`. The census, caller-frame and loader modules, their tests
  and their docs were imported read-only and are unchanged.
- No GoldBox source, no emulator, DOSBox, Hatari, GameLink or codewheel. No CoK rule or address is used.
- Nothing is committed or pushed.

## Commands and results

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_argpush_shape.py -q
#   21 passed, 3 skipped
OPENUA_POR_INSTALL="C:/Modding/OpenUA/data/work/por-geo-run/POOLRAD" \
    tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_argpush_shape.py -q
#   24 passed
OPENUA_POR_INSTALL="C:/Modding/OpenUA/data/work/por-geo-run/POOLRAD" \
    tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_census.py tests/test_por_geo_loader_caller_frame_probe.py -q
#   53 passed (regression)
python -I tools/por_geo_stub_farcall_argpush_shape.py --install data/work/por-geo-run/POOLRAD \
    -o data/work/por-geo-stub-farcall-argpush-shape/retail
#   shape_status=imm-id-shape-only strong_candidates=166 documented=0 imm=9 self_checks=pass   (exit 0)
```

The retail test imports the probe and calls `probe()` without writing, so it writes nothing. The 3 skipped tests
without retail input are the retail anchors.

## Next evidence that would settle it

1. The caller-frame probe's stack model (`Walk`) at each of the nine sites, to see whether the 8-byte leftover balances
   as it does at the walked loader sites. The walk is not run here.
2. The DI constraint the census records for `0085:005C` (`di_constraint_mod64k`), used to enumerate the bodies it could
   reach under the residue, and their `retf` counts.
3. A live capture at one of the nine calls: the SP and the ten pushed words before `9A`, and the callee's `retf` on return.
