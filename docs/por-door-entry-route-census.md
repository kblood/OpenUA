# Pool of Radiance: decoded transfers into the door routines and stub 1 (static, observe-only)

**Status: STATIC-PROBE-ONLY. `playable: false`. `trigger_established: false`. No door rule is proven.**
Tool: [`tools/por_door_entry_route_census.py`](../tools/por_door_entry_route_census.py). Tests:
[`tests/test_por_door_entry_route_census.py`](../tests/test_por_door_entry_route_census.py) (19 tests: 15 synthetic
with falsifiers, 4 retail-gated; all 19 pass, none skipped). Output (git-ignored):
`data/work/por-door-entry-route-census/` (the earlier run, before the candidate root) and
`data/work/por-door-entry-route-census-0a087/` (this run, with `candidate_roots`).

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
    --install data/work/por-geo-run/POOLRAD -o data/work/por-door-entry-route-census-0a087  # exit 0
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_door_entry_route_census.py -q -p no:cacheprovider  # 19 passed
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_loadpieces_handler.py -q -p no:cacheprovider  # 36 passed with OPENUA_POR_INSTALL set
```

## Decode stops (2026-11-18): classified, decoder not extended

The four stops named under *Coverage limit* were traced to their walk entries. None is a code start, so none
is a missing opcode, and the decoder was not extended. The decoder's behaviour is unchanged. The evidence:

| # | stop (image, file offset) | code | walk entry and kind | bytes at the stop | why the walk is not code |
| --- | --- | --- | --- | --- | --- |
| 1 | GAME.OVR `0x0A085` | `unsupported-opcode-0x65` | `0x0A081`, reached: group `0x09807` proc[1] = `0x087A` | `65` is the `e` of ASCII text `attle:` at `0x0A081..0x0A086` | the proc offset is 6 bytes early; the next prologue `55 89 E5` is at `0x0A087` |
| 2 | GAME.OVR `0x0B3D5` | `unsupported-fe-reg-2` | `0x0B3CF`, reached: group `0x0ABC0` proc[1] = `0x080F` | `FE 16` is inside `8D BE FB FE` (`lea di,[bp-0x105]`) | the entry lands inside the `9A` call far operand at `0x0B3CD` (`9A 0B 0B F8 0A`) |
| 3 | GAME.OVR `0x32923` | `target-out-of-range` | `0x32923`, reached: group `0x3211F` proc[1] = `0x804` | no bytes: the file is `0x32519` long | group `0x3211F` has `codesz` `0xFC`; the proc is 0x708 bytes past its own code and 0x40A past EOF |
| 4 | START.EXE `0x003D2` | `unsupported-opcode-0x0f` | `0x002F6`, prologue sweep, a real function (`push bp; mov bp,sp`) | `0F 00 B2` in the VROOMM `CD 3F` stub run | the function ends in `call far 0x0AF8:0x00E9` at `0x0034C` with no `ret` after it; the walker treats calls as returning and falls into the stub bytes |

Stop 4's sweep is a fall-through artefact. Stops 1 to 3 are proc-table entries that do not name code. In every
case, the stop byte is data, an operand, or a table byte. Support for `65`, `FE /2` or `0F` would decode data.

**Per-opcode reading (not PoR facts).** `FE` defines only `/0` (INC) and `/1` (DEC), so `FE /2` is refused on
every x86 reading. `0x65` is undefined in the decoder's 8086/80186 table; on the 80386 it is the GS prefix. The
8086 reading of `0x64`–`0x67` was not checked against a reference here, so no alias is assumed. `0x0F` is
POP CS on the 8086 and the two-byte escape on the 80186 and later. The decoder refuses it; the choice of CPU
does not change stop 4, because the byte sits in stub data. The tests pin the refusals and keep `FE /0` and
`FE /1` decoding.

**Correction (this slice): the census already walks `0x0A087`.** An earlier note said the walk set missed
this function. That was wrong. Group `0x09807` has codesz `0x127F`, and its tier-B prologue sweep walks every
Borland prologue in the body that no stub closure reaches. `0x0A087` (`55 89 E5`) is one of them, and that
walk is complete at 108 instructions. Its instructions are already in the baseline decoded set, and no
transfer from it lands on a tagged target under either model. So the "no route" result covers this function
as a walked entry. Proc[1] of groups `0xABC0` and `0x3211F` have no prologue within ±8 bytes, so their true
entries are unknown. The group proc model (`group.fileofs + proc`, trusted as *well-formed* by the stub scan)
is the open question, not the decoder.

## Supplementary candidate root `0x0A087` (candidate-only)

Reported under `candidate_roots` in the JSON and in a separate report section. Evidence label
`supplementary-candidate-root`; label `candidate-only`. **It is a candidate entry. It is not shown to be
reachable or run, and it is not baseline.** It adds no count to the baseline.

- **Identity.** GAME.OVR `0x0A087`, group `0x09807` `+0x0880`, prologue `55 89 E5`. Proc[1] `0x087A` is 6
  bytes before it; `0x0A081..0x0A086` is ASCII `attle:`.
- **Walk.** Complete, 108 instructions, span `0x0A087..0x0A1BB`, no incomplete stops, no overlap conflicts.
  It ends in `retf 4` at `0x0A1B8`. The walk is the same `lh.walk` the baseline uses.
- **Call sites.** One near `call` `0x0A11E -> 0x0A806`, a prologue in the same group and outside the
  `0x166CB` body, so untagged. One near `jmp` `0x0A118 -> 0x0A0B2` inside the function. Ten far calls at
  `0x0A093, 0x0A09C, 0x0A0C3, 0x0A0CE, 0x0A12F, 0x0A134, 0x0A139, 0x0A15E, 0x0A197, 0x0A1A5`. Each is
  reported under both models (M0 and M1), so 20 far rows. Every far target under either model is outside the
  tagged set (the nine distinct M0 targets run `0x0AE5`..`0xBC8B`; the M1 targets run `0x077D`..`0xBB09`).
- **Counts (distinct instruction starts).** New beyond baseline: **0**. Route rows: **0**. In-baseline
  route rows: **0**. Transfer candidate rows: 22 (2 near, 20 far across both models).
- **Double counting.** A far call tagged under both models is one instruction with two rows, and the new count
  is taken over instruction starts, so it is never counted twice. The baseline rows are unchanged, and the
  candidate rows carry an `in_baseline` flag.
- **Falsifiers (synthetic).** A changed prologue refuses the walk. A far call into the body (M0 clearer) is
  tagged under M0 only. A far call to stub 1 is tagged under M1 only. An absent route has no route rows.
- **Retail pins (test).** The GAME.OVR size and SHA-256 above, the prologue, the 108-instruction complete walk,
  the call sites above, and `new_instruction_count == 0`.

## Next discriminator

The static transfer kinds are exhausted for the walked entries. The decode-stop gap is a proc-model gap, not a
decoder gap. The next static step is:

1. **Entry model for group procs.** Find why group proc offsets are off: one is 6 bytes early, and two do not
   name a prologue. Then walk the corrected entries. This is a probe change, not a decoder change, and it is not
   part of this slice.
2. **Data-driven dispatch.** If the trigger is a table word that the loader or the INT 3Fh handler reads at run
   time, no transfer instruction names stub 1 at all. That needs a runtime memory word, which the copy-protected
   path blocks ([por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md)).

## Limits

- Stdlib-only static analysis with the existing decoder and walk helpers. No emulator and no live capture.
- Read-only on the pinned install. No retail file written, no DOSBox, Hatari, GameLink or codewheel run.
- GoldBox, CoK and COAB material was not used. Nothing here is PoR semantics beyond the bytes listed.
- No tool was edited in the decode-stop slice. `tools/por_loadpieces_handler.py` (decoder) and
  `tools/por_door_entry_route_census.py` are unchanged. `tools/por_map.py`, `docs/por-geo-door-semantics.md`, and
  the `por_door_*` tools were imported or read, not changed.
- The route census is the **walked-entry** result only: the group closures and prologue sweeps, not all of
  GAME.OVR. The function at `0x0A087` is a walked entry (the group `0x09807` sweep), so it is inside the baseline
  counts. It is a *candidate* entry, not established code (see *Supplementary candidate root*). "No route" is a
  claim about the walked entries, not the whole of GAME.OVR.

## Handoff

Candidate-root slice (2026-11-18), static only. Changed files, not committed or pushed:

- `tools/por_door_entry_route_census.py`: `candidate_root` and `candidate_transfer_rows`, a `candidate_roots`
  key, and a report section. The baseline walk, counts and rows are unchanged.
- `tests/test_por_door_entry_route_census.py`: 6 synthetic tests (inclusion, labelling, no double count, both
  models, changed-prologue falsifier, absent route) and 1 retail-gated pin test for `0x0A087`. 19 tests pass.
- `docs/por-door-entry-route-census.md`: the correction to the "misses the function" note, and the candidate
  section.

Census run on the pinned install, to `data/work/por-door-entry-route-census-0a087`: exit 0, pins unchanged
before and after. The baseline JSON matches the pre-change run (`decoded_transfers` 99, `raw_hits` 14, the
verdicts, decoded starts 71,701 and 13,846). The candidate reports 108 instructions, complete, 0 new, 0 route.

Decode-stop slice (2026-11-18), static only. Changed files, not committed or pushed:

- `tests/test_por_loadpieces_handler.py`: 3 synthetic tests added (stop-byte refusals with falsifiers, linear
  decode from ASCII text, the call-far fall-through mechanism with a `ret` falsifier).
- `tests/test_por_door_entry_route_census.py`: 1 retail-gated test added (the four stops, their address
  relations, and the pinned bytes). Two imports added.
- `docs/por-door-entry-route-census.md`: *Decode stops* section, test counts, and *Next discriminator*.

Census re-run on the pinned install: exit 0, pins unchanged before and after, GAME.OVR 71,701 and START 13,846
decoded starts, 0 new decoded near routes beyond prior, 0 stub-1 transfers. Output in `data/work/`, git-ignored.

Earlier files, still new for review:

- `tools/por_door_entry_route_census.py`
- `tests/test_por_door_entry_route_census.py`
- `docs/por-door-entry-route-census.md`
