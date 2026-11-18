# Pool of Radiance: decoded transfers into the door routines and stub 1 (static, observe-only)

**Status: STATIC-PROBE-ONLY. `playable: false`. `trigger_established: false`. No door rule is proven.**
Tool: [`tools/por_door_entry_route_census.py`](../tools/por_door_entry_route_census.py). Tests:
[`tests/test_por_door_entry_route_census.py`](../tests/test_por_door_entry_route_census.py) (11 tests: 9 synthetic
with falsifiers, 2 retail-gated; all 11 pass, none skipped). Output (git-ignored):
`data/work/por-door-entry-route-census/por_door_entry_route_census.json` and `..._report.md`.

This follows [por-door-caller-probe.md](por-door-caller-probe.md) and
[por-door-indirect-probe.md](por-door-indirect-probe.md). Those counted near `E8`, literal `9A`, and `FF /2` / `FF /3`.
This census counts the remaining decoded transfer kinds: near `E9` and `EB` jumps, far `EA` jumps, and non-prologue
entries into group `0x166CB`. It covers every decoded instruction start in all 34 group bodies and in the START.EXE
walk set (the indirect probe's MZ-entry closure plus its prologue sweep, reused read-only).

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both are checked on load (`dc.load_pinned`, no override) and re-hashed after the run (`dip.recheck_pins`). Both
hashes were identical before and after the run. Read-only on the install; output is refused inside the install.

## Targets

- Writer `GAME.OVR:0x167D4`, clearer `0x166CB`, stub 1 START `0x0089C` and its proc `0x17438`, reader `0x2EC47`.
- Far targets are mapped under both models the earlier probes used, neither promoted:
  M0 `file = 0x200 + seg*16 + off`; M1 `file = seg*16 + off + 0x7E`.

## Result, with exact counts

Decoded instruction starts: GAME.OVR **71,701**, START.EXE **13,846**. Groups checked: **34**.

| transfer into the target | decoded count | where |
| --- | ---: | --- |
| `E8` call to writer `0x167D4` | **4** | `0x16B5C`, `0x16B9A`, `0x16C28`, `0x16C66` |
| `E8` call to clearer `0x166CB` | **2** | `0x17558`, `0x17697` |
| `E9` / `EB` jump to writer, clearer, or stub 1 | **0** | |
| `EA` far jump to stub 1 (M0 or M1) | **0** | |
| `9A` far call to stub 1 (M0 or M1) | **0** | |
| `E8` call to stub 1 proc `0x17438` | **0** | |
| decoded `CALL` into group 0x166CB body that does not begin on a Borland prologue | **0** | |

The six `E8` callers are exactly the set the caller probe already reported. The census's "new decoded near routes
beyond the prior caller sites" is therefore **0**.

Other rows (for orientation, not routes): 78 decoded `JMP`s and 15 decoded `CALL`s land at addresses inside the
group 0x166CB body, not on a named entry. Most of these are ordinary intra-function jumps. The census does not
assign them to functions, so they are not counted as entries.

Raw (undecoded) byte patterns that land inside the group 0x166CB body: **14**. These are 10 near (7 `E8` and 3 `E9`
in GAME.OVR) and 4 far `EA` bytes in START.EXE whose M0 or M1 target falls in the body. None lands on the writer,
clearer, stub 1, or proc `0x17438`. Raw hits are never counted.

## The one M1 near-word hit (checked, not a stub literal)

The indirect probe reported the word `0x081E` (M1's stub-1 value) once in GAME.OVR. It is at file `0x4E2F`, in
group `0x4577`. The decoded instructions are:

```
0x4E2E  bf 1e 08        mov di,0x081E
0x4E31  0e              push cs
0x4E32  57              push di
0x4E33  9a 0b 0b f8 0a  call far 0x0AF8:0x0B0B
```

So `0x081E` is an offset pushed as the offset half of a far pointer `CS:0x081E` and passed as an argument to
`0AF8:0B0B`. It is not a `9A` literal to a stub. Its value matches the M1 number only by coincidence unless the
pointer is shown to name stub 1, and nothing here shows that.

## What this does and does not establish

- **Established (static, decoded starts only):** no decoded near `E9`/`EB`, far `EA`, or far `9A` in the walked
  bytes transfers to stub 1 under M0 or M1, and no decoded transfer of any kind reaches the proc `0x17438`
  other than the already-known sites. Every decoded `CALL` into the body starts on a prologue.
- **Not established:** that any caller runs. Nothing here is a runtime trace. No door semantics are assigned to
  the writer, clearer, or reader.
- **Coverage limit:** the census sees only decoded starts. Bytes the walks do not reach, and walks that stop at an
  unsupported opcode, are not seen. Those stops are the three group walks (`unsupported-opcode-0x65`,
  `unsupported-fe-reg-2`, `target-out-of-range`) and one START walk (`unsupported-opcode-0x0f`), per the indirect
  probe. Also not walked: about 8,654 group-external bytes, and START bytes outside the walk set. START coverage
  was not measured by this census.
- **Reader group:** the reader `0x2EC47` is in group `0x2E8F7`, outside the group 0x166CB body. Its callers are
  the caller probe's cross-group `9A` sites, and this census does not re-scan them.
- **Models:** M0 and M1 are reported, not promoted. M1 rests on one anchor. The far counts here are zero under both.

## Commands

```sh
sha256sum data/work/por-geo-run/POOLRAD/GAME.OVR data/work/por-geo-run/POOLRAD/START.EXE   # before and after
tools/.venv/Scripts/python.exe -I tools/por_door_entry_route_census.py \
    --install data/work/por-geo-run/POOLRAD -o data/work/por-door-entry-route-census        # exit 0
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_door_entry_route_census.py -q -p no:cacheprovider  # 11 passed
```

## Next discriminator

The static transfer kinds are now exhausted for the walked bytes. Two gaps remain, and each is narrower than
"find the trigger":

1. **Decode past the unsupported-opcode stops.** The four walks named under *Coverage limit* stop at an opcode
   the 8086 decoder does not model. A transfer hidden after one of those stops would be the only static route
   left to stub 1 or the writer. Extending the decoder for those specific opcodes, then re-running this census,
   would close or confirm that gap.
2. **Data-driven dispatch.** If the trigger is a table word that the loader or the INT 3Fh handler reads at run
   time, no transfer instruction names stub 1 at all. That needs a runtime memory word, which the copy-protected
   path blocks ([por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md)).

## Limits

- Stdlib-only static analysis with the existing decoder and walk helpers. No emulator and no live capture.
- Read-only on the pinned install. No retail file written, no DOSBox, Hatari, GameLink or codewheel run.
- GoldBox, CoK and COAB material was not used. Nothing here is PoR semantics beyond the bytes listed.
- No existing file was edited. `tools/por_map.py`, `docs/por-geo-door-semantics.md`, and the `por_door_*` tools and
  tests were imported or read, not changed.

## Handoff

New files for review and staging (nothing committed or pushed):

- `tools/por_door_entry_route_census.py`
- `tests/test_por_door_entry_route_census.py`
- `docs/por-door-entry-route-census.md`
