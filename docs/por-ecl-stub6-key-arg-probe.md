# PoR stub-6 route: argument chain into GAME.OVR `0x2F6FF` (static, observe-only)

**Status: `playable: false`. `execution_established: false`. The archive selector and the requested id are not established by this route.**

Tool: [`tools/por_ecl_stub6_key_arg_probe.py`](../tools/por_ecl_stub6_key_arg_probe.py). Tests:
[`tests/test_por_ecl_stub6_key_arg_probe.py`](../tests/test_por_ecl_stub6_key_arg_probe.py) (13 tests:
retail falsifiers and synthetic checks; 13 passed with the pinned install). Output is written only under ignored
`data/work/por-ecl-stub6-key-arg-probe/`. Read-only; it refuses unpinned inputs and outputs outside `data/work`.

Follows [por-ecl-21-stub6-dump-probe.md](por-ecl-21-stub6-dump-probe.md) (the four `03D5:003E` sites and their
match to START stub 6), [por-ecl-21-dispatch-probe.md](por-ecl-21-dispatch-probe.md) and
[por-geo-selector-format-probe.md](por-geo-selector-format-probe.md).

## Two corrections to the labels this route inherited

The stub-6 route was carried in earlier notes as "the ECL `0x21` route to the GEO loader". The pinned bytes
contradict both halves of that label.

1. **The four stub-6 sites are on the non-`0x21` side of the shared handler.** The handler at `0x19BA` is entered
   from the dispatcher's `0x21` and `0x37` cases (`0x3D9A`–`0x3DA3`; the only `E8` to `0x19BA` is at `0x3DA3`). Inside
   the handler, `cmp byte [0x6F7F],0x21` at `0x19F1` and `jnz 0x1A66` at `0x19F6` split the two. The `0x21` side
   (`0x19F8`–`0x1A63`) ends in `jmp 0x1B05` and contains **no** stub-6 site; it calls stub 7 at `0x1A27`. The four
   stub-6 sites (`0x1A77`, `0x1A9E`, `0x1AAA`, `0x1AD6`) are on the `0x1A66` side. A byte scan of GAME.OVR finds no jump into `0x3DA2`
   other than the `0x21` `jz` at `0x3D9C`; the `0x37` path falls through at `0x3DA0`. **The stub-6 route is the `0x37` case**. The existing docs' "0x21/0x37 handler" wording is
   right; the "ECL 0x21 stub-6" name is not.

2. **`GAME.OVR:0x2F6FF` builds `WALLDEF<d>.dax`, not `GEO<d>.dax`.** Its copy sources are the Pascal pieces at
   `CS:0x0DB4` and `CS:0x0DBC` (group base `0x2E8F7`): file `0x2F6AB` is `07 "WALLDEF"` and file `0x2F6B3` is `04 ".dax"`.
   The wrapper copies the stem (`mov di,0x0DB4` at `0x2F735`), appends the formatter's digit, and copies the suffix
   (`mov di,0x0DBC` at `0x2F74F`). The GEO stem (`03 "GEO"`) is at file `0x2F994`, and it belongs to the separate
   fill at `0x2F9BE`, which is not a stub-6 target. The existing
   [por-walldef-table-link-probe.md](por-walldef-table-link-probe.md) already reads `0x2F6FF` as a WALLDEF entry; the
   "GEO-loader candidate" label in the stub-6 notes is stale. The stub-6 route therefore reaches a **WALLDEF** wrapper,
   and any GEO evidence from it is absent.

## The chain (file bytes, GAME.OVR unless marked)

| Step | Site | Bytes | Effect |
|---|---|---|---|
| Dispatch | `0x3D9A`, `0x3D9E`, `0x3DA3` | `3C 21 74 04` / `3C 37 75 07` / `E8` | `0x21` jumps to `0x3DA2`; `0x37` falls to `0x3DA2`; both `call 0x19BA` |
| Key split | `0x19F1`, `0x19F6` | `80 3E 7F 6F 21` / `75 6E` | `[0x6F7F] != 0x21` goes to `0x1A66` (stub-6 side) |
| Path A | `0x1A6B`–`0x1A77` | `cmp [bp-3],0x7F; jnz`; `mov al,0; push ax; mov al,1; push ax; call` | id `0x00`, gate `0x01` |
| Path B | `0x1A83`–`0x1A9E` | `es cmp [di+462],0; jz`; `es cmp [di+464],0; jz`; `mov al,[bp-3]; push; mov al,1; push; call` | id `[bp-3]`, gate `0x01` |
| Path C | `0x1AA3`–`0x1AAA` | `mov al,[bp-1]; push; mov al,3; push; call` | id `[bp-1]`, gate `0x03` (after B, same guard) |
| Path D | `0x1AB1`–`0x1AD6` | loop `k=1..3`, skip if element `0xFF`; `mov al,[bp+di-4]; push; mov al,[bp-4]; push; call` | id `array[k]`, gate `k` |
| Array | `0x19D6`–`0x19E8` | `mov al,[bp-4]; push ax; call 0x002B:0x0025; mov dl,al; mov [bp+di-4],dl` | `[bp-3]`, `[bp-2]`, `[bp-1]` = AL returned for `k=1..3` |
| Wrapper gate | `0x2F706`–`0x2F712` | `cmp [bp+6],1; jb`; `cmp [bp+6],3; jbe`; else `jmp 0x2F98E` | the second pushed byte must be `1..3` |
| Selector read | `0x2F715` | `mov al,[0x5376]` (`A0 76 53`) | the only DS-direct access to `0x5376` in the wrapper |
| Formatter | `0x2F72A` | `call 0x0AF8:0x1366` with value `[0x5376]`, min `0`, width `1` | the digit, as in the fill |
| Name | `0x2F72F`–`0x2F754` | `WALLDEF` copy, `0x0B98` append of the digit, `.dax` copy | `P20 = WALLDEF<d>`, `P16 = .dax` |
| Requested id | `0x2F759`–`0x2F75C` | `mov al,[bp+8]; push ax` | the first pushed byte of the stub call |
| Loader call | `0x2F767` | `call 0x0802:0x0716` (START `0x876D`, conditional) | the loader compares `cmp al,[bp+14]` at START `0x88DE` |
| Return | `0x2F991` | `retf 4` | the four bytes the stub pushed |

Each stub-6 site pushes two words, so `[bp+8]` is the id and `[bp+6]` the gate in the wrapper. The stub's
own `CD 3F 08 0E 00` entry points to proc `0x0E08` of group `0x2E8F7`, that is `0x2F6FF` (the earlier probe).

## What the route establishes, and what it does not

| Question | Answer | Basis |
|---|---|---|
| Which dispatcher case reaches the stub-6 sites? | **`0x37`** (the non-`0x21` side) | bytes at `0x3D9A`–`0x3DA3`, `0x19F1`–`0x19F6`; `E8` callers of `0x19BA`: one |
| Does the route name a GEO file? | **No.** It names `WALLDEF<d>.dax` | literals at file `0x2F6AB`, `0x2F6B3`; copies at `0x2F735`, `0x2F74F` |
| Archive selector | the digit `d` is the formatter's output for **`DS:[0x5376]`**, the same global the GEO fill reads. The route does not write it (`0` DS-direct stores in the handler and wrapper). Its value is **not established**: DS is not resolved and no writer is shown on this path. | selector access census; `0x2F715` |
| Requested block id | `[bp+8]` reaches the loader's `[bp+14]` compare. Its values are `0x00` (A), `[bp-3]` (B), `[bp-1]` (C), `array[k]` (D). The values are **not established**: `array[k]` is the AL returned by `0x002B:0x0025(k)`, and that target is not identified | arg patterns; array store `0x19E8` |
| Gate (second argument) | `[bp+6]` must be `1..3`; it selects a 780-byte slot (`0x30C`) in the buffer behind the far pointer at `DS:[0x6A58]` (`les [0x6a58]`), not an archive | `0x2F706`; slot arithmetic `0x2F7E0`–`0x2F7F8` |
| Did a call execute? | **Not shown.** No trace or capture in the inputs | |

### The `0x002B:0x0025` edge (the narrowest missing edge for the id)

Applying the `+0x1866` live-segment constant that places the `0x03D5` stubs (`0x03D5 → 0x1C3B`) to segment `0x002B`
gives linear `0x18935`. Both dumps hold `EA 36 01 CC 40` there, a far `jmp`, not a `CD 3F` stub. So the constant
does not place this segment as a stub, and the target is **not identified**. Its identity, and so the return AL for
`k = 1..3`, is the edge the id values depend on.

## Memory-byte presence (unknown capture instants; not execution)

| Window | `pid34644` | `wheel-live-capture` |
|---|---|---|
| Handler prologue `55 89 E5 83 EC 0C` at linear `0x468B4` (group `0x3C3`, base `0x45C40`) | present | present |
| Handler key window `80 3E 7F 6F 21 75 6E` at `0x468EB` | present | present |
| Wrapper prologue, gate, and selector load (`0x2F6FF`–`0x2F718`, no segment words) | **absent** | **absent** |
| START loader prologue at linear `0x20D96` (displacement `0x18629`) | present | present |

The wrapper body is not resident in either dump, although its stub entry (`CD 3F 08 0E 00`, linear `0x1C3EE`) is. So
at these snapshots the proc the stub names is not in memory. This is consistent with a group that was not loaded
at capture; it does not prove that the route never runs.

## Limits

- The dumps have unknown capture instants. Neither shows a stub-6 call, a `0x37` dispatch, or the handler's key
  value. The handler's presence and the loader's presence are memory-byte checks only.
- The loader body `0x876D` is a generic DAX loader: it takes the name pieces as arguments, so the WALLDEF/GEO label
  comes from the caller's literals, not from the loader.
- No file is shown to open. The name `WALLDEF<d>.dax` is what the wrapper's bytes build, if it runs.
- DS is not resolved, so `DS:[0x5376]` and `DS:[0x6A58]` have no memory value here.
- Pointer stores through `DS:[0x49D2]` and `DS:[0x49D6]` in the handler (`es mov` at `0x1A1E` and `0x1A32`) are not
  resolved and could in principle reach the selector; nothing in the bytes says they do.
- Nothing here is a GoldBox or CoK fact. No GoldBox map or opcode name was used.

## Next discriminating observations

1. **One live stop at the wrapper's loader call (`0x2F767`).** Record `AL` (the requested id), `[bp+6]` (the gate),
   `DS:[0x5376]`, and the name the DOS open receives. This fixes the selector, the id, and the file name in one
   observation, and it decides WALLDEF versus GEO by the name itself.
2. **Live stop at the handler's `cmp [0x6F7F],0x21` (`0x19F1`).** Expect `[0x6F7F] = 0x37` on the stub-6 route. Then
   record `AL` returned by each `0x002B:0x0025` call (`k = 1..3`) to fill in the id values.
3. **Identify the far target `0x002B:0x0025`.** Decode its code from a live capture, or find its segment mapping. The
   `+0x1866` constant does not fit this segment, so the mapping must come from the capture.

## Reproduction

```sh
python -I tools/por_ecl_stub6_key_arg_probe.py --install data/work/por-geo-run/POOLRAD
python -m pytest tests/test_por_ecl_stub6_key_arg_probe.py -q
```

- Probe: `status=ok checks=27 failed=0`, exit 0.
- `tests/test_por_ecl_stub6_key_arg_probe.py`: **13 passed** with the pinned install.

## Pins and inputs

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Dumps: `data/work/por-live-memory-pid34644/ram-000000-100000.bin` (SHA-256 prefix `f8191750ea6c672e`) and
`data/work/por-wheel-live-capture/ram-000000-100000.bin` (prefix `3788787cd795f1f5`), base 0.

## Files and side effects

- New, committed with this doc: `tools/por_ecl_stub6_key_arg_probe.py`, `tests/test_por_ecl_stub6_key_arg_probe.py`,
  `docs/por-ecl-stub6-key-arg-probe.md`.
- New, ignored output: `data/work/por-ecl-stub6-key-arg-probe/por_ecl_stub6_key_arg_probe.json`, and scratch under
  `data/work/por-ecl-21-stub6-arg-scratch/` (ignored; safe to delete).
- Read only: `GAME.OVR`, `START.EXE`, the two dumps, and the helpers `por_loadpieces_handler` (decoder),
  `por_overlay_group_map` (pins, install lookup), and `por_convert` (output-directory check).
- No edits to existing docs, source, or tests. The stale "GEO" labels in
  [por-ecl-21-stub6-dump-probe.md](por-ecl-21-stub6-dump-probe.md) and
  [por-ecl-21-dispatch-probe.md](por-ecl-21-dispatch-probe.md) are not changed here; they should be corrected in a
  separate commit that owns those files.
