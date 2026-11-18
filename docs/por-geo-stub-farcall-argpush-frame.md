# Pool of Radiance: caller frames at the nine argument-push-shape sites (0085:005C)

**Status: frame-requirement-only. `playable: false`, `established: false`, `mappings: []`. Shape-frame comparison, not a loader, runtime, or GEO binding.**

Tool: `tools/por_geo_stub_farcall_argpush_frame.py`. Tests: `tests/test_por_geo_stub_farcall_argpush_frame.py`
(24: 17 synthetic with falsifiers, 7 retail anchors). Output (git-ignored):
`data/work/por-geo-stub-farcall-argpush-frame/por_geo_stub_farcall_argpush_frame.{json,md}`.

## Handoff

- **The nine sites do not show the loader's frame.** All nine call `0085:005C`. The loader's target is `0802:0716`.
  The four single-callee sites (`0x14C4E`, `0x17D07`, `0x18168`, `0x183B9`) each carry a **2-byte leftover** (one
  pushed word). The loader's walked sites carry **8**. Their frame balances only if the callee pops **12 bytes
  (`0x0C`)**. The loader's `retf 0x12` would leave them **6 bytes over-popped into locals**. The loader's `0x12` was
  never applied to any of the nine sites.
- **Requirement, not evidence.** `0085:005C` has no established segment base, so its pop is unknown. The sweep reports
  which pops would balance each frame. It reads no callee body.
- **Joint over the six decided sites** (`0x14C4E`, `0x17D07`, `0x18168`, `0x1820A`, `0x183B9`, `0x18422`): 7 joint
  hypotheses. `K_a` (`0085:005C`) = `0x0C` in all seven. `K_c` (`03C5:0039`) = `0x0A` in all seven. `K_g`
  (`00BA:16EC`) is `0x00`..`0x0C`, bounded here by feasibility (larger pops over-pop the pushed words), not by the grid.
- **Undecided, not refuted:** `0x182A0` (its window has backward branches `0x18263->0x1824E` and `0x18282->0x181B8`;
  every hypothesis fails closed, so none is walkable), `0x1861E` (4 auxiliary unknown callees, above the sweep limit of
  2), and `0x1C900` (9 auxiliary unknown callees and a loop at `0x1C602`).
- **A model gap in the existing caller-frame walk.** `por_geo_loader_caller_frame_probe.Walk` does not count
  `push r/m16` (`FF /6`, for example `push [0x5D94]`), and it silently ignores `pop r/m16` (`8F`). At `0x1820A` the
  uncounted memory pushes make the existing walk fail at the near call `0x181A4` ("consumes below the pushed words
  (6 bytes, 2 pushed)"), and at other hypotheses report a join-depth mismatch at `0x181AD`. Both are the same cause,
  not a fact about the bytes. This tool subclasses `Walk` (`FrameWalk`) to count `FF /6` as a word push, and fails
  closed on `pop r/m16`, `push imm`, `pushf`, `pusha`, `enter`, and `leave`. **The existing module is not changed; the
  parent should decide whether to fix it.** The six walked loader sites contain no `FF /6` or `8F` (scan), so their
  caller-frame conclusions are unaffected. The four loader call sites the probe does not walk were not scanned.

## Premise and identity check

| Check | Result |
| --- | --- |
| Exact nine-site census set (fresh `analyse`) | verified: 9 sites, owners, id immediates, lea displacements; 181 / 166 / 166 / 9 / 0 / 0 |
| Each `at` is a `9A` far call | yes (9 of 9) |
| Each call target | `0085:005C` (9 of 9); not `0802:0716` |
| Walked procedure in its census owner group | yes (9 of 9) |
| Loader's `0x12` applied to these sites | no; the loader resolver is replaced by "unknown" inside these walks |
| Segment base for `0085` | not established; the census DI stays unknown |

## Method

1. The site set is verified before any analysis: a fresh `por_geo_stub_farcall_argpush_shape.analyse` must reproduce
   exactly the nine expected sites and the census counts, or the run refuses.
2. Each site's enclosing prologue is found with the caller-frame probe's `find_proc`. The walk runs with its `Walk`
   model, subclassed as `FrameWalk` for `FF /6`.
3. Every `9A` in the linear window is listed (`static_far_callees_in_window`). Each unknown callee becomes a symbolic
   pop `K` shared by every site that calls it: `K_a` = `0085:005C` (the site's own call), `K_c` = `03C5:0039`,
   `K_g` = `00BA:16EC`. Sweep: `K_a` in `0x00..0x40`, others in `0x00..0x20`, word-aligned. A site with more than two
   auxiliary unknowns is not swept.
4. With callee pop `K` at a site's own call, the caller's SP sits `K - 10 - L` bytes above its allocation floor,
   `L` being the leftover at the shape start. The frame balances iff `K = 10 + L`.
5. A site is **decided** if at least one hypothesis walks. The joint is the set of `(K_a, K_c, K_g)` under which every
   decided site balances. Undecided sites are listed and never counted as refuted.

## Results

| Site | Owner | Target | Parameters | Alloc | Leftover L | Balancing hypotheses | Walk failures |
| --- | --- | --- | --- | ---: | --- | ---: | --- |
| `0x14C4E` | `0x127FB` | `0085:005C` | K_a | 26 | 2 | 1 of 33 | none |
| `0x17D07` | `0x17831` | `0085:005C` | K_a | 30 | 2 | 1 of 33 | none |
| `0x18168` | `0x17831` | `0085:005C` | K_a | 34 | 2 | 1 of 33 | none |
| `0x1820A` | `0x17831` | `0085:005C` | K_a, K_c, K_g | 34 | 2..14 | 7 of 70 | over-pop 8515, join 952 |
| `0x182A0` | `0x17831` | `0085:005C` | K_a, K_c, K_g | - | - | 0 of 0 (undecided) | over-pop 8515, join 1015, loop 7 |
| `0x183B9` | `0x17831` | `0085:005C` | K_a | 48 | 2 | 1 of 33 | none |
| `0x18422` | `0x17831` | `0085:005C` | K_a, K_c | 48 | 2..14 | 1 of 7 | over-pop 498, join 56 |
| `0x1861E` | `0x17831` | `0085:005C` | not swept | - | - | not claimed | 4 auxiliary unknowns |
| `0x1C900` | `0x1997F` | `0085:005C` | not swept | - | - | not claimed | 9 auxiliary unknowns; loop `0x1C602` |

Joint over the six decided sites: 7 tuples, all with `K_a = 0x0C`, `K_c = 0x0A`, `K_g` in `0x00..0x0C`.

**Control (the loader's own walked sites, the same walk):** `GAME.OVR 0x2F767` and `START.EXE 0x07276` each have
leftover 8 and balance at `0x12` (`balanced_with_loader_K: true`). `FrameWalk` reproduces the existing `Walk`'s
leftover at both (no `FF /6` there). The existing caller-frame probe's six walked sites are unchanged.

## Tests and commands

```sh
tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_argpush_frame.py -q
#   24 passed (17 synthetic; 7 retail anchors run against data/work/por-geo-run/POOLRAD) in ~67 s
OPENUA_POR_INSTALL="C:/Modding/OpenUA/data/work/por-geo-run/POOLRAD" \
    tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_argpush_frame.py -q
#   24 passed
OPENUA_POR_INSTALL="C:/Modding/OpenUA/data/work/por-geo-run/POOLRAD" \
    tools/.venv/Scripts/python.exe -m pytest tests/test_por_geo_stub_farcall_argpush_shape.py tests/test_por_geo_loader_caller_frame_probe.py -q
#   47 passed (regression; unchanged modules)
tools/.venv/Scripts/python.exe -I tools/por_geo_stub_farcall_argpush_frame.py \
    --install data/work/por-geo-run/POOLRAD -o data/work/por-geo-stub-farcall-argpush-frame
#   frame_status=joint-consistent-on-decided-sites-requirement-only; 3 site(s) undecided joint_K_a=['0x0C'] joint_tuples=7 sites=9 self_checks=pass
```

Synthetic falsifiers: a 2-byte leftover balances only at 12, and the loader's 18 over-pops by 6; an 8-byte leftover
balances only at 18 (positive control); two sites sharing a callee have no common balancing pop (`K = 10 + (12 - K)`
has no word-aligned solution); a call to `0802:0716` in a window fails closed and is never given 12 or 18; the memory
push is counted by `FrameWalk` but not by `Walk`; `push imm16` fails closed; the joint is empty when two decided
sites disagree; an undecided site is listed, not refuted; unpinned bytes, a missing or altered site, and outputs
outside `data/work` or inside the install are refused.

## Pins, hashes and side effects

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Install `data/work/por-geo-run/POOLRAD`: both pins matched; hashed before and after the run, unchanged (self-check).

| Output | SHA-256 |
| --- | --- |
| `por_geo_stub_farcall_argpush_frame.json` | `d08bda9b3ee9b01811bcf445cb573a5e72b4b9ce71ca05f75bb40d1fcbaad401` |
| `por_geo_stub_farcall_argpush_frame.md` | `559a35a34128a56c0a71501918039551fe56f4ac6da6e34ea9224062bff68dbf` |
| `tools/por_geo_stub_farcall_argpush_frame.py` (as run) | `600bae64328bcaec8da04cc5594dfbc76221b337fe29243eb1ba6711259877d8` |

- No retail write. The probe writes only under `data/work/por-geo-stub-farcall-argpush-frame/`. Its refusals cover an
  unpinned or missing install, an output outside `data/work`, and an output inside the install.
- The existing modules (`por_geo_loader_caller_frame_probe`, `por_geo_stub_farcall_argpush_shape`,
  `por_geo_stub_farcall_census`) were imported read-only and are unchanged.
- No GoldBox source, emulator, DOSBox, Hatari, GameLink, or codewheel was touched. No CoK rule or address is used.
- Nothing is committed or pushed.

## Limits

- Walks use the caller-frame probe's model: linear fall-through; a forward join must agree in depth; pops are limited
  to pushed words, so an over-pop into locals is infeasible; a backward branch inside a window fails closed.
- Sweeps are finite grids. A balance found in the grid is a requirement on an unknown pop, not a value of it. A grid
  miss is not a refutation. The `K_g` range is bounded by feasibility, not by the grid.
- Each `seg:off` is taken as one body, which its single operand implies. Nothing establishes the body or its segment
  base. The census DI and paragraph-model assumptions are inherited and unchanged.
- The leftover model is symbolic. The dumps and the census carry no SS or SP, so no live stack value is claimed.

## Not established

- That any of the nine sites runs, or that any call at them executes.
- That `0085:005C` is the loader, stub 6, or any census body. The shape matches are not a GEO result. Its segment base is not established.
- The pops of `0085:005C`, `03C5:0039`, and `00BA:16EC`. They are swept as requirements only.
- The pops of the unswept callees (`0709:0D68`, `0085:0057`, `0096:003E`, `00BA:1693`, `03F1:0137`, `00BA:1816`, `0709:0626`,
  `00BA:1037`, `00AC:0025`) and anything about the three undecided sites.
- That any shape id word, pushed pointer, or leftover word holds a GEO, block, or area value.
- Any GEO archive, block, plane 2, or descriptor binding.

## Next evidence that would settle it

1. Model the loops at `0x182A0` (`0x18263->0x1824E`, `0x18282->0x181B8`) and `0x1C900` (`0x1C602->0x1C3BB` and others),
   and the unswept windows, so `0x182A0`, `0x1861E` and `0x1C900` become decided.
2. Establish a segment base for `0085`, `03C5` and `00BA` (a DI or paragraph fact). That turns each requirement into a
   read of the callee's own `retf` count from its bytes. Until then `K_a = 0x0C` is a requirement, and a loader
   identity would need `0x12`, which the decided frames exclude.
3. A live capture at `GAME.OVR 0x14C4E` before its `9A`: one leftover word below the ten shape bytes. Then the callee's
   `retf` count from the stack difference.
4. The parent decides whether to fix `FF /6` in `por_geo_loader_caller_frame_probe.Walk`. That changes no current
   result (no loader window contains one), but any future walk through a memory push is wrong without it.
