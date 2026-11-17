# Pool of Radiance: who calls the plane-3 door routines (static, observe-only)

**Status: STATIC-PROBE-ONLY. `playable: false`. No door rule is proven.**
Tool: [`tools/por_door_caller_probe.py`](../tools/por_door_caller_probe.py). Tests:
[`tests/test_por_door_caller_probe.py`](../tests/test_por_door_caller_probe.py) (16 tests: 9 synthetic
with falsifiers, 7 retail-gated; all 16 pass). Output (git-ignored):
`data/work/por-door-caller-probe/por_door_caller_probe.json` and `..._report.md`.

This is the step the open edge in [por-geo-door-semantics.md](por-geo-door-semantics.md) asked for: find
the callers of the plane-3 writer `GAME.OVR:0x167D4`, the clearer `0x166CB`, and the reader `0x2EC47`, then
say what the consumer does with the reader's value. It answers the first two in part, and the consumer
only as far as its branch bytes go.

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched on the run. Unpinned input is refused (no override). Read-only. The dumps are read only
for the live-operand check, and they are named in the report.

## Method

1. **Owner groups** from `tools/por_farcall_resolve.py` `scan_all` (VROOMM descriptor headers and
   stub runs). `0x166CB` and `0x167D4` are in the well-formed group at file `0x166CB` (codesz `0x10AC`,
   header `0x881`); `0x167D4` is group-relative `+0x109`. `0x2EC47` is group-relative `+0x350` in the
   **partial** group at file `0x2E8F7` (header `0x3DD7`), whose stub 3 is at START `0x3DFD` (well-formed).
2. **Decoder-verified near calls.** Calls are found by `lh.walk` (`tools/por_loadpieces_handler.py`), a
   recursive-descent walk that gives instruction boundaries. A call is counted only if its site is a
   decoded instruction start. Tier **A**: the caller is in the call closure of a well-formed stub of the
   owner group, following in-group near calls. Tier **B**: a Borland-prologue function that no stub
   reaches. Tier **C** (byte-pattern `E8`/`E9` that is not a decoded start) is reported and never counted.
3. **Far calls (`9A`).** A far call into a group goes through its stub in START.EXE. Two address models
   are reported. Neither is promoted:
   - **M0** (resolver zero-skew): image `= 0x200 + seg*16 + off`. The resolver doc says this fits 2 of 11
     handler calls only.
   - **M1** (dump-anchored): file `= seg*16 + off + 0x7E`. The `0x7E` comes from one anchor: caller literal
     `03D5:0034` reaches stub 4 at START `0x3E02` in one RAM dump
     ([por-geo-callee-identity-probe.md](por-geo-callee-identity-probe.md)). Under M1 the stub stride gives
     literal `03D5:(slot - 0x3DCE)`: stub 3 (`0x3DFD`) is `03D5:002F`.
   A far site is a candidate only if its bytes decode as `call_far` in a walk **and** its segment word is in
   the containing group's fixup table (group-relative words; the loader patches these).
4. **Live-operand check (observation only).** For each dump, the owner group is placed uniquely by
   `tools/por_overlay_group_map.py` `map_group` and the 5 live bytes at each literal site are read. The
   calibration sites `03D5:0034` are checked first; then the stride site.

## Answer, with exact evidence

### Writer `0x167D4` (sets a field to `01`) and clearer `0x166CB`

Both are in group `0x166CB`. The group's stubs name procs `0x10A7`, `0x0D6D`, `0x0989` (stub 0, 1, 2).
Stub 1 (START `0x0089C`, proc `0x0D6D` = file `0x17438`) is the only stub whose closure reaches the
routines.

| callee | decoded in-group callers (tier A) | caller function | root stub |
| --- | --- | --- | --- |
| `0x166CB` clearer | `0x17558`, `0x17697` (`call 0x166cb`) | `0x17438` (stub 1 entry itself) | stub 1 |
| `0x167D4` writer | `0x16B5C`, `0x16B9A` | `0x1695F` | stub 1 (closure) |
| `0x167D4` writer | `0x16C28`, `0x16C66` | `0x16BAA` | stub 1 (closure) |

Each call is `push cs; call near` (a near `E8` whose callee returns `retf 6`; both routines end in `retf 6`
per [por-geo-buffer-fill-probe.md](por-geo-buffer-fill-probe.md)). The probe treats the
`push cs` as part of the call frame. Tier B is empty; byte-only hits are zero.

**No far literal reaches stub 1.** Under M0 there are no `9A` in `GAME.OVR` or `START.EXE` that land on
`0x0089C`. Under M1 there is no `9A` with any segment whose `seg*16+off` equals `0x0089C - 0x7E = 0x081E`
(count 0). So the **trigger** for group `0x166CB` is not
identified: a call from another overlay would need a literal this probe does not find.

### Reader `0x2EC47` (plane-3 field read) and its consumer

The reader's decoded listing (`lh.walk`, 120 instructions, complete) takes three words from the caller
(`[bp+6]` direction byte, `[bp+8]` X, `[bp+10]` Y) and returns with `retf 6`.

- Direction byte `cmp` to `0/2/4/6`, selecting `and 0x03 / 0x0C / 0x30 / 0xC0` on `es:[di+0x300]`
  (plane 3 at `+0x300`), then `shr` by `cl = 2/4/6` (direction 0 has no shift). That is a 2-bit field per direction, and the
  writer/clearer masks are the same set.
- Return path bytes: result slot `[bp-2]` starts at `1` (`c6 46 fe 01` at `0x2EC9A`). Helper `0x2EC16`
  returning zero with global `[0x84DC]` in `{0, 0x0A}` returns `0` (`0x2EC6B`). Helper `0x2ED72` returning
  zero (`or al,al; ja` fails at `0x2ECB0`) leaves `1`. An unlisted direction leaves `1` (`0x2ED3F`).
  These are byte facts. What the values mean in play is not decoded here.
- In-group callers of `0x2EC47`: **none** (byte-pattern `E8` to `0x2EC47`: zero). Its callers are cross-group
  far calls, and four `9A 2F 00 D5 03` sites are the only ones that reach its stub under M1.

| site | caller fn | group | live-check seg | the instruction after the call (consumer) |
| --- | --- | --- | --- | --- |
| `0x0C726` | `0x0C6FC` | `0x0C5D1` (dump-resident) | `1C3B` | `or al,al; jnz 0x0C735` (field ≠ 0) |
| `0x1699F` | `0x1695F` | `0x166CB` (absent in both dumps) | not checked | `cmp al,3; jz 0x169AB` (field == 3) |
| `0x16D8B` | `0x16D58` | `0x166CB` (absent) | not checked | `or al,al; jz 0x16E02` (field == 0) |
| `0x17469` | `0x17438` | `0x166CB` (absent) | not checked | `cmp al,1; jnz 0x17479; mov [bp-1],1` (field == 1) |

So the consumers test the returned 2-bit value (`0`, `1`, `3`) on `AL`. Their branch arms are decoded to
the extent shown above. What each arm does is not decoded.

## Far-call model and the dump check

- **Decoder-verified.** All four `9A 2F 00 D5 03` sites decode as `call_far 0x03d5:0x002f`, are
  fixup-listed in their owner group, and sit in tier-A closures (see the JSON for the context bytes).
- **Dump-observed (one dump's instant, both pinned dumps agree).**
  - Calibration: `03D5:0034` sites `0x03A4C`, `0x03F08`, `0x08F1A` (in groups `0x0D46`, `0x074D3`) read live
    segment `1C3B`, which matches the callee-identity doc's `03D5 + 0x1866`.
  - Stride: `0x0C726` (group `0x0C5D1`, unique in both dumps) reads live `1C3B:002F`, opcode `9A`.
  - Stub 3: START `0x3DFD` holds `cd 3f 50 03 00`. That 5-byte pattern is unique in START.EXE and in each
    dump, and the dump holds it at linear `0x1C3DF = 1C3B*16 + 0x2F`.
  - So for **one** site, the dump bytes support M1 (`1C3B:002F` names the stub-3 bytes). This is not a
    proof that the call ran.
- **Not dump-observed.** Group `0x166CB` (and `0x2DB87`) is **absent** from both dumps: no run of its stable
  bytes (longest anchor 727 bytes in `0x166CB`) occurs there. So three of the four stride sites, the
  writer, and the clearer are not seen live. This is consistent with the overlay not being resident at
  either dump instant. It is not evidence that the group is never loaded.

## What is not established

1. **Runtime.** Every caller above is a static decode. Nothing shows a call ran or what the values were.
2. **The trigger for group `0x166CB`.** Stub 1 has no `9A` literal under M0 or M1. Something else enters it
   (an indirect or table call, or a path the stub run does not model). Not identified.
3. **Consumer meaning.** The arms after each reader call are decoded to their compare bytes only.
4. **M1 beyond one site.** The `+0x7E` delta rests on one anchor. The stride site `0x0C726` supports it,
   but the other three stride sites are unchecked live.
5. **Writer/clearer arguments.** The arguments pushed before `call 0x167D4` / `0x166CB` lie outside the
   three-instruction window in the report. Not decoded.

## Next discriminating observation

Static (no emulator), the next step is a census of **indirect far calls** (`FF /3`, `call far m16:16`) and
indirect near calls (`FF /2`) in the tier-A and tier-B functions of `GAME.OVR` and `START.EXE`, resolving
any table or variable that could hold `0x0089C` or the stub-1 target (`0x17438`). If one resolves to stub 1
of group `0x166CB`, the trigger is found and the four writer/clearer callers become reachable by a named
path. If none does, the stub-1 entry has no static caller under this model, and the open edge stays open.

Live: a dump taken while group `0x166CB` is resident (any capture whose linear map places `0x166CB`
uniquely) would check the three unchecked stride sites and the writer/clearer callers. The runtime path
is blocked by copy protection (see [por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md)),
so this is not available now.

## Limits

- Stdlib-only static analysis plus the existing decoder. No emulator, no live register capture.
- The dumps have an unknown instant and are non-atomic. They are used for byte identity, not as a call trace.
- GoldBox and CoK/COAB material was not used. Nothing here is PoR semantics beyond the bytes listed.
- `por_map.py`, `tests/test_por_map.py`, `docs/por-converter.md`, `tools/README.md`, the loader-trace files,
  and `por-geo-door-semantics.md` are not edited by this slice.
