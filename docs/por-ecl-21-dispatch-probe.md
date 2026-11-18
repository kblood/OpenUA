# Pool of Radiance: ECL opcode 0x21 dispatch probe (static)

**Status: STATIC-PROBE-ONLY. `playable: false`.** `tools/por_ecl_21_dispatch_probe.py` reads the pinned
retail `GAME.OVR` and `START.EXE` read-only and traces the `0x21` arm of the dispatcher to its handler
and that handler's far calls. Question: does the `0x21` path reach the GEO loader body at `GAME.OVR:0x2F6FF`,
or supply equivalent archive/block arguments?

**Answer: conditionally mapped in RAM, execution not established.** The direct edge into the GEO body is absent.
Under the zero-skew model no far call lands on the GEO stub, and the paragraph-residue probe rejects that
model for every site. A later RAM-dump check finds that four `03D5:003E` calls instead target the exact five-byte
START stub 6 in both captures; that stub's procedure word points to the GEO-loader candidate at `0x2F6FF`.
This is a memory-byte target chain, not evidence any call ran. Nine of the eleven calls were model-dependent
in the original file-only zero-skew analysis; follow-up dump checks now match four to stub 6, and the separate
`0x1A27` check has only a partial match to stub 7. The other target identities, call arguments, and execution
remain open. This probe does not analyze the call-frame arguments; a later
stub-7 cross-check finds the pushed byte is the first local populated from a three-call `002B:0025`
loop, and that its one-word shape fits the candidate fill, conditional on target identity. The helper's
return semantics remain open.

The opcode name, the CoK LOAD_FILES semantics and every GoldBox opcode map were not read or used. The
"operand parser" label on group `0x74D3` in `docs/por-farcall-resolution.md` cites a GoldBox map and is not
used here as PoR fact.

---

## Pinned inputs

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched their pins on the retail run. Both were hashed again after the run and are unchanged. The
probe refuses a file that does not match its pin.

## Usage

```sh
python3 tools/por_ecl_21_dispatch_probe.py --install "PATH/TO/POOLRAD" \
    -o data/work/por-ecl-21-dispatch-probe
```

Outputs: `por_ecl_21_dispatch_probe.json` (schema `openua.por-ecl-21-dispatch-probe` v1) and
`por_ecl_21_dispatch_probe.md`. Exit `0` every self-check passes, `1` a self-check fails, `2` a named refusal
(missing or unpinned input, output inside the install, output outside `data/work/`).

---

## Result

### 1. The `0x21` arm (decoded; direct `E8` edge)

| Item | Value | Evidence |
| --- | --- | --- |
| Compare | `cmp al,0x21` at `0x3D9A` (`3C 21`) | decoded |
| Branch | `je 0x3DA2` at `0x3D9C` into a group block | decoded |
| Block | `push cs` at `0x3DA2`; `call near 0x19BA` at `0x3DA3` (`E8`) | decoded; raw `E8` target recomputed and equal |
| Group members | `[0x21]` only | decoded |
| Handler | `0x19BA` | decoded |

The arm is present. The dispatch edge `0x3DA3` is a **direct near `E8`** edge, and its target is the
recomputed raw target. The probe cross-checks the same arm through `por_ecl_handler_cursor_probe.dispatch_edge`,
which recomputes the branch targets from raw bytes. Both agree.

The control opcode `0x37` (case 55) also calls `0x19BA`, through its own `jne` block at `0x3D9E`. So the
two cases share one handler.

### 2. The stream loop at `0x3EB7` (decoded walk)

The loop's key store is `mov [0x6F7F],al` at `0x3EE7`, immediately before `push cs; call near 0x3C73` at
`0x3EEB` (`E8`, a direct edge). The loop does not advance the cursor (`loop_advances_cursor: false`).
A raw byte scan finds nine `E8` sites that target `0x3EB7`. These are **byte-pattern** only: the probe did not
decode them as reachable code, and it traces no root. Reachability of `0x3EB7`, and so of the `0x21` arm,
from a PoR root is **not established**.

### 3. The handler `0x19BA` (decoded walk; 129 instructions; complete)

- Near calls: **0**. Indirect calls: **0**. Returns: one `retf` at `0x1B34`.
- Far calls (`9A seg:off`): **11**. Each is decoded. The walk covers every reachable path.

### 4. The far calls: what each lands on

Zero-skew image address is `hdr + seg*16 + off` with `hdr = 512`, the convention of `docs/por-farcall-resolution.md`.

| Call | `seg:off` | Zero-skew image | Result | Model |
| --- | --- | ---: | --- | --- |
| `0x19C3` | `2B:2A` | 1242 | VROOMM stub, group `0x74D3` index 21, target `0x92C3` | zero-skew stub |
| `0x19DA` | `2B:25` | 1237 | VROOMM stub, group `0x74D3` index 20, target `0x9196` | zero-skew stub |
| `0x1A27` | `3D5:43` | 16275 | not a stub | model-dependent |
| `0x1A53` | `AF8:B0B` | 48267 | not a stub | model-dependent |
| `0x1A5E` | `3E9:25` | 16565 | not a stub | model-dependent |
| `0x1A77` | `3D5:3E` | 16270 | not a stub | model-dependent |
| `0x1A9E` | `3D5:3E` | 16270 | not a stub | model-dependent |
| `0x1AAA` | `3D5:3E` | 16270 | not a stub | model-dependent |
| `0x1AD6` | `3D5:3E` | 16270 | not a stub | model-dependent |
| `0x1B1A` | `BA:27D9` | 13689 | not a stub | model-dependent |
| `0x1B27` | `BA:767` | 5383 | not a stub | model-dependent |

Every far call's seg word is in the overlay's fixup table (`seg_word_in_fixup_table: true`). So for the nine
"not a stub" calls the literal `seg` is not the load-time segment. Under zero-skew they land on ordinary
code bytes (`bytes_at_image_f`), which the probe records and does not interpret. Their load-time targets are
not in the file, so they are reported as **model-dependent**, not as "not GEO".

The two stub calls are the only far calls whose literal target is a VROOMM stub under the zero-skew model. The
probe matches them to group `0x74D3` (well-formed, 25 of 25 prologues). Neither is the GEO stub. The four
`03D5:003E` sites are separate from those zero-skew hits and are checked against live target bytes below.

### 5. The GEO body `0x2F6FF`

- The bytes at `GAME.OVR:0x2F6FF` are `55 89 E5 81 EC 18 01`, a Borland prologue.
- It is the target of **stub index 6** of group header `0x3DD7` (file `0x2E8F7`). That group is **partial**:
  seven of its eight stubs are valid, and all seven targets have a prologue. Group `0x2E8F7 + 0xE08 = 0x2F6FF`
  (`proc_off 3592`).
- Stub runs live in **`START.EXE`**, not `GAME.OVR`. The stub at `START.EXE` offset `15884` reads
  `CD 3F 08 0E 00`. Its zero-skew image address is `15884`.
- **No far call of `0x19BA` has zero-skew image address `15884`.** The eleven far-call images are
  `1242, 1237, 16275, 48267, 16565, 16270, 16270, 16270, 16270, 13689, 5383`. None equals `15884`.

So under the zero-skew model the `0x21` path has **no direct edge** to the GEO body. The result is deterministic
(`test_retail_analysis_is_deterministic`).

### Later RAM cross-check of the four `03D5:003E` sites

The follow-up [stub-6 dump probe](por-ecl-21-stub6-dump-probe.md) maps the handler group uniquely at
`0x45C40` in both pinned dumps. At `0x1A77`, `0x1A9E`, `0x1AAA`, and `0x1AD6`, the live call bytes
are `9A 3E 00 3B 1C`, targeting `1C3B:003E` / linear `0x1C3EE`. The first five target bytes are
`CD 3F 08 0E 00`, an exact match to START stub 6 at `0x3E0C`. Stub 6's proc word `0x0E08` maps
through owner group `0x2E8F7` to file `0x2F6FF`, the GEO-loader candidate.

This supersedes the earlier statement that all nine non-zero-skew calls were wholly model-dependent:
four have a memory-byte target match in these dumps. The target is a stub, not a direct call into
the body. The group is partial, the snapshot instant is unknown, and no call or INT 3Fh dispatch
is observed. Archive/block arguments and runtime GEO loading remain unestablished.

### Later RAM cross-check of the `0x1A27` target (partial)

The follow-up [stub-7 dump probe](por-ecl-21-stub7-dump-probe.md) found the live bytes for the `0x1A27`
operand `03D5:0043` in two pinned RAM dumps. In both, the live target is `1C3B:0043` (linear `0x1C3F3`),
and its first four bytes `CD 3F C7 10` match START stub 7 at `0x3E11`. The fifth byte differs (`00` in
RAM, `27` in START), and the 16-byte windows differ. The probe therefore labels this `prefix4-match-trailer-differs`,
not a full stub identity.

This is memory-byte evidence at unknown capture instants. It does not show that `0x1A27` executed, that
the ECL `0x21` arm was reached, or that the call enters the GEO fill at `0x2F9BE`. The earlier
`geo_call_status=not-established` remains the verdict. The stack-shape match to the fill remains conditional.

### 6. Arguments

The probe does not establish archive or block arguments. The decoder's operand text is incomplete for some ModRM
forms (for example `mov r5`, `sub r4, 0xc`), and nearest-by-address instructions cross jumps. The output keeps
these only as `nearest_decoded_before`, for inspection. No conclusion is drawn from them.

---

## Verdict

| Question | Answer | Basis |
| --- | --- | --- |
| Does the `0x21` arm reach a handler? | **Yes**: `0x3DA3` `E8` to `0x19BA` | decoded, direct |
| Does the handler make near or indirect calls? | **No** | decoded walk, complete |
| Does a far call of `0x19BA` target the GEO loader candidate? | **Four calls conditionally target START stub 6 in both dumps**, whose proc word points to `0x2F6FF`. The zero-skew and paragraph-aligned models do not resolve them; execution, INT 3Fh dispatch, and successful loading are not shown. The separate `0x1A27` call has only a partial prefix match to stub 7. | exact five-byte target match, stub proc word and owner offsets; no execution trace |
| Do the handler's bytes supply GEO archive/block arguments? | **Not established** | `[bp-3]` is the first AL result of a 1..3 call loop through `002B:0025`; the candidate fill's `[bp+6]` byte argument and `retf 2` are stack-compatible, but helper semantics, target identity, value and meaning remain open |
| Is the `0x21` path reachable from a PoR root? | **Not established** | nine `E8` callers of `0x3EB7`, byte-pattern only |

`geo_call_status` is `not-established`. The probe never returns `established`.

## Falsifiers and controls

`tests/test_por_ecl_21_dispatch_probe.py`, 19 tests. Thirteen need `OPENUA_POR_INSTALL` and skip without it.
Mutations work on in-memory copies. The install is never written.

| Control | Mutation | Required change |
| --- | --- | --- |
| Moved compare | `0x3D9B` set to `0xEE` | arm absent; status `arm-absent` |
| Moved dispatch call | rel16 at `0x3DA4` plus one | handler no longer `0x19BA`; self-check `arm_handler_is_expected` fails |
| Positive control | far call at `0x19C3` set to `9A 0C 00 C0 03` (image `15884`) | status `candidate-edge`; edge at `0x19C3` to group `0x3DD7` stub 6 |
| Negative control | GEO stub proc word in `START.EXE` plus one | no GEO candidate; status `not-established` |
| Combined | both changes | status `not-established` |

The positive and negative controls together show the verdict follows the bytes in both directions. The stub
lookup is done in `START.EXE`, so a control that edits only `GAME.OVR` cannot remove the candidate. That mistake
was made during test development and is what the tests now check.

Refusals (no retail needed): missing input, unpinned input, output inside the install, output outside
`data/work/`.

## Results

- Tests, retail pinned: **19 passed** (`OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD"`).
- Tests, no retail env: **6 passed, 13 skipped**.
- CLI, retail: `geo_call_status=not-established self_checks=pass`, exit `0`.
  Output JSON SHA-256 `e07c6adba2e371c15f4a29098f197fc3a474438a6a2b1207d26e0fabf51ed62e` (15,552 bytes, under `data/work/por-ecl-21-dispatch-probe/`).
- CLI refusals: output outside `data/work/` exit `2`; output inside the install exit `2`.
- Self-checks (16): all pass, including `inputs_unchanged`, `loop_raw_callers_expected` (9), and
  `handler_far_calls_at_stub_group_0x74D3` (2).

## Runtime reachability limits

- The nine model-dependent far calls cannot be resolved from the file alone. Their seg words are fixup-listed,
  so the load-time segment is not in `GAME.OVR` or `START.EXE`.
- The nine `E8` callers of `0x3EB7` are byte-pattern. No PoR root reaches the loop, so no run-time key value
  (including `0x21`) is shown to occur in any stream.
- Group `0x2E8F7` is partial. Its use as a GEO target rests on one valid stub and a prologue, not on a
  well-formed group.
- Only `GAME.OVR` and `START.EXE` were scanned. No other overlay and no runtime capture were used.
- No emulator, DOSBox, GameLink, codewheel or GoldBox input was used. No retail file was written.

## Discriminating next step

Decode the overlay fixup record for each of the remaining model-dependent seg-word sites. They lie in the handler's
group: descriptor header at `START.EXE` offset `963` (`0x3C3`), code at `GAME.OVR` offset `0x0D46`, `fixupsz 804`. Each record says whether the seg word is a resident or stub-segment
reference with a known base, or another overlay reference.

- If a record ties a seg word to a known base, recompute that call's target under that base. This could further
  explain the four dump-mapped stub-6 targets and decide whether any remaining site lands on a stub.
- If no record gives a base, the remaining static targets stay model-dependent. The next evidence would then be
  a runtime far-call trace at the handler sites `0x1A27`–`0x1B27` on a stream that carries key `0x21`. That is
  outside this slice.

---

## Files

- `tools/por_ecl_21_dispatch_probe.py`: the probe (reads `por_loadpieces_handler`, `por_farcall_resolve` and
  `por_ecl_handler_cursor_probe` read-only; edits none of them).
- `tools/por_ecl_21_stub6_dump_probe.py`: the follow-up check of the four live `03D5:003E` targets (see
  [`por-ecl-21-stub6-dump-probe.md`](por-ecl-21-stub6-dump-probe.md)).
- `tests/test_por_ecl_21_dispatch_probe.py`: 19 tests (synthetic refusals, retail expectations, mutation and
  falsification controls).
- `docs/por-ecl-21-dispatch-probe.md`: this document.

No existing file was changed. Nothing is staged, committed or pushed.
