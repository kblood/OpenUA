# Pool of Radiance: what the branch arms after the plane-3 reader call do (static, observe-only)

**Status: STATIC-PROBE-ONLY. `playable: false`. No door or movement rule is proven.**
Tool: [`tools/por_door_reader_branch_probe.py`](../tools/por_door_reader_branch_probe.py). Tests:
[`tests/test_por_door_reader_branch_probe.py`](../tests/test_por_door_reader_branch_probe.py) (29 tests:
19 synthetic with falsifiers, 10 retail-gated; all 29 pass with the pinned install present).
Output (git-ignored): `data/work/por-door-reader-branch-probe/por_door_reader_branch_probe.json` and
`..._report.md`.

This follows [por-door-caller-probe.md](por-door-caller-probe.md). That probe found four far-call sites
`9A 2F 00 D5 03` (literal `03D5:002F`) into the reader `GAME.OVR:0x2EC47`, and decoded only the compare
that follows each call. This probe follows each arm after the call and asks which arms write the bytes
the reader was given, and which only classify.

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched on the run. Unpinned input is refused (no override). Read-only.

## Answer

**The reader is on a forward-movement path at exactly one site, and only conditionally there.** That site is
`0x17469`, inside `0x17438` (the stub-1 root of group `0x166CB`). The reader's value `R` decides whether the
routine `0x16E06` runs. `0x16E06` adds a per-direction table delta to the party bytes `DS:6AAD` and
`DS:6AAE`, wraps them into 0..15, and then calls two far routines with the new position. The other three
sites do not move the party:

| site | caller | what the reader result does (decoded) | party-byte stores | verdict |
| --- | --- | --- | --- | --- |
| `0x0C726` | `0x0C6FC` | `R != 0` makes a second far check `03D5:002A` with the caller's own args; the caller returns 1, 0 or 3 | none | classifier; second check unresolved |
| `0x1699F` | `0x1695F` | `R==3` reads a far pointer local and a neighbour cell, then calls far `00B0:0048`; calls the writer `0x167D4` (plane-3 field) | none (DS `6DDE` stores, plane-3 stores) | neighbour/door look, not movement |
| `0x16D8B` | `0x16D58` | `R != 0` computes a trial step; stores only the edge constants `0x0F` / `0x00`, and only out of range | constant edge clamp only, no in-range store | edge check; never moves in range |
| `0x17469` | `0x17438` | `R == 1` reaches `call 0x16E06` exactly; `R == 0` does not; `R == 2/3` reach it only via a callee's return | computed stores to `DS:6AAD`/`6AAE` in `0x16E06` | forward step, gated by `R` |

What this means for "passability". At `0x17469` the reader is a gate on the step, not a pure classifier.
Whether `R==1` means "may pass" in play is **not** shown. Two byte facts keep that open. First, `R==1` is also
the reader's default return (see the reader section), so an `R==1` step does not prove the field read 1.
Second, `0x16E06` does no check of the destination cell before moving: it wraps and then calls checks
(`03D5:002A`, `03D5:0034`) whose results are only stored (`DS:6AB0`, `DS:6AB1`). So in the decoded bytes the
only gate on the step is `R` and the static guards below.

## Evidence levels

- **E1, byte-exact.** The arm follows from decoded instruction edges and constant flags (the caller's
  own compare on a constant AL). No unknown input decides it.
- **E2, decoded, conditional.** Reachable, but a branch depends on memory or a callee return the probe does
  not know. Reachability over the decoded edges, not a proof that the arm runs.
- **E3, static guard.** A branch where only one arm can still reach the site (CFG reachability over decoded
  edges, flags ignored).
- **E4, identity assumption.** The reader identity `03D5:002F` to `0x2EC47` is the caller probe's M1 candidate.
  Here it is supported only by byte consistency: the reader ends in `retf 6`, and each caller pushes three words.
  Nothing below is decided by the far-call image model.
- **U, unresolved.** Named in the open-edge list.

## Site checks (E1)

Each site's five bytes are `9A 2F 00 D5 03`, and its segment word `0x03D5` is listed in its owner group's
fixup table (group-relative). The four callers come from the owner closure index of the caller probe:

| site | owner group | site rel | caller |
| --- | --- | --- | --- |
| `0x0C726` | `0x0C5D1` | `0x0155` | `0x0C6FC` |
| `0x1699F` | `0x166CB` | `0x02D4` | `0x1695F` |
| `0x16D8B` | `0x166CB` | `0x06C0` | `0x16D58` |
| `0x17469` | `0x166CB` | `0x0D9E` | `0x17438` |

At each site the call is preceded by three `push ax` words, each loaded by a byte move from the argument
source (reader frame: `[bp+6]` = top push = direction, `[bp+8]` second, `[bp+10]` third). The reader's
`retf 6` pops exactly these three words. The reader's index is `[bp+8]*16 + [bp+10]`
(its `shl`, then `add di,ax`, then `add di,dx`), so the reader's "row" is its `[bp+8]` and its "column" is `[bp+10]`.

Argument provenance at each site (E1):

- `0x0C726`: `BP:+8`, `BP:+10`, `BP:+12` (the caller's own args; no party byte).
- `0x1699F`, `0x16D8B`, `0x17469`: `DS:6AAF` (direction), `DS:6AAE`, `DS:6AAD`.

## The reader's return set (E1)

The reader `0x2EC47` has 120 decoded instructions and one return, `retf 6` at `0x2ED6F`. Run with unknown
arguments, its returned AL is bounded `0..3`. The sources are:

- `0x2EC6B`: `[bp-1] = 0` (helper `0x2EC16` returns zero and global `[0x84DC]` is 0 or 0x0A).
- `0x2EC9A`: `[bp-2] = 1` (the default, which every zero-helper path and every unlisted direction keeps).
- Field paths: `and` with `0x03 / 0x0C / 0x30 / 0xC0` on `es:[di+0x300]`, then `shr` by 0/2/4/6. Each gives 0..3.

So the reader's values are `{0, 1, 2, 3}`. **`R = 1` is both the field value 1 and the default.** The
reader has no DS writes. The caller runs force `R` in `{0,1,2,3}` only at the target site. Other reader sites
(the one inside `0x1695F`) reached through a callee get an unbounded unknown AL (no bound applied).

## Per-site arms (E1 unless marked)

### `0x0C726` (caller `0x0C6FC`): classifier with a second check

- Guards (E3): `0x0C706`, `0x0C70C`, `0x0C712`, `0x0C718`. The site runs only when the caller's `[bp+10]` and
  `[bp+12]` are in 0..15 (signed compares). Otherwise the caller takes a separate arm at `0x0C756`.
- `R == 0`: `mov [bp-1],1`, returns 1 (exact).
- `R != 0`: `call 03D5:002A` (`0x0C741`) with the caller's `(dir, X, Y)`. Its result sets `[bp-1]` to 0 or 3.
  The body of `03D5:002A` is not decoded (U). No party bytes are written on any arm (E1).

### `0x1699F` (caller `0x1695F`): neighbour look, not movement

- Guards (E3): `0x1697C` `jnz` and `0x16985` `jz` (on caller locals `[bp-3]`, `[bp-6]`).
- The reader runs with the party bytes. `cmp al,3; jz 0x169AB` (`0x169A4`) sends `R == 3` to `0x169AB`, which
  reads `es:[bp-10]+16` and `+22` (a far pointer local) and calls `00B0:0048` with constants. Other arms call the writer `0x167D4` (plane-3 field write, via
  `0x16B5C` and `0x16B9A`) and read the direction table `DS:[di+0x2736]` / `[di+0x273F]` (E2: `di` is the
  direction byte, which the tool records as `ub 0xFF`).
- Party bytes: none stored on any arm (E1). Other DS stores: `DS:6DDE`. Plane-3 stores are through `es`
  (counted as unknown-pointer stores). This site is a neighbour and door look, not a step.

### `0x16D8B` (caller `0x16D58`): edge check, never a step in range

- No guards (E3). At `0x16D7A` it clears `es:[ptr49D6+0x5AA]` before the reader call (common to all arms).
- `R == 0`: `jz 0x16E02` returns with AL 0 (E1).
- `R != 0`: adds the table deltas to the locals `[bp-2]` and `[bp-4]`, then compares them **as words** with
  `0x0F` and `0`. It stores `0x0F` (above 15) or `0` (below 0) to `DS:6AAD` or `DS:6AAE`, and sets
  `es:[...+0x5AA] = 1`. The **in-range** value is never stored back (E1: no non-constant party store on any run;
  the census finds only the four constant stores in this function). Clamp, not wrap.
- No callees, no calls (E1).

### `0x17469` (caller `0x17438`): the forward step (E1 for `R=1`; E2 for `R=2/3`)

- Guards (E3): `0x17448` `jz` after `cmp al,1` on `AL = DS:[0x49FA]`, so the reader runs only when `DS:49FA == 1`.
  `0x17458` `jb` after `es cmp [di+1426],0xFF`, so the reader runs only when that ES byte is below `0xFF`.
- Result local: `0x1743F` sets `[bp-1] = 0` on entry.
- `R == 1` (E1): `0x1746E cmp al,1; 0x17470 jnz` not taken; `0x17472 mov [bp-1],1`; `0x17476 jmp 0x176F2`;
  `0x176F2 cmp [bp-1],0` is exact (not zero); `0x176F9 call 0x16E06`.
- `R == 0` (E1): `jnz` taken to `0x17479`; `cmp al,2` fails; `jmp 0x175B8`; `cmp al,3` fails; `jmp 0x176F2`.
  `[bp-1]` is still the entry 0, so `jz 0x176FE` is taken and `0x16E06` is **not** called. This arm then reaches
  `0x17764`/`0x17769`, which store constants `0xFF` to `DS:6B00` and `DS:6B05` (E1; meaning U).
- `R == 2 / 3` (E2): the arms call `0x1695F` (`0x17595`, `0x176D4`) and `0x16D13` (`0x175AF`, `0x176EC`),
  `0x16901`, `0x16CB9`, `0x16BAA`, `0x166CB`, and far `0x0AF8:*`. The results reach `[bp-1]` at `0x176D7` and
  `0x176EF` before `0x176F2`. So `call 0x16E06` happens only if a callee's AL is nonzero. `0x1695F` returns AL
  in `{0,1}` (explorer bound from the `0x1699F` analysis, E2). The probe treats callee returns as unknown, so this
  arm is reachable, not exact.

### `0x16E06` (the step, E1 in its bytes)

Reached only through `0x176F9` in this group (decoded). In order:

1. `push [0x2628]; call 08AE:00DC` (`0x16E09`, `0x16E0D`). Its result is not tested in the bytes. Its effect is unknown (U).
2. Direction byte `DS:6AAF` is zero-extended into `DI`. Then `DS:[DI+0x2736]` is added to `DS:6AAD` (`0x16E1D`),
   and `DS:[DI+0x273F]` to `DS:6AAE` (`0x16E2C`). The table is DS data outside `GAME.OVR` (U).
3. Wrap (E1): `cmp [6AAD],0; jge` (signed byte), then `mov [6AAD],0x0F` if negative. `cmp [6AAD],0x0F; jle`, then
   `mov [6AAD],0x00` if above 15. The same for `6AAE`. **Wrap, not clamp**: `0x16E06` maps -1 to 15 and 16 to 0.
4. `push DS:6AAD, DS:6AAE, DS:6AAF; call 03D5:002A` (`0x16E6C`), then `mov [6AB0], al` (`0x16E71`).
5. `call 0AF8:16A8` (`0x16E80`), then `push DS:6AAD, DS:6AAE; call 03D5:0034` (`0x16E8D`), then `mov [6AB1], al`
   (`0x16E92`).

So `0x16E06` is a move followed by two checks at the new cell. Their results are stored and not otherwise
used here. The literal `03D5:0034` is the caller probe's calibration literal (E4 for its stub).

### The direction writers (census, not a step)

The party direction byte `DS:6AAF` is also written by the routine containing `0x17054`: a register
store at `0x1719A`, `0x171D8`, `0x1721D`, and constant stores `0`, `2`, `4`, `6` at `0x17397`, `0x173A2`,
`0x173AD`, `0x173B8`. Those are direction stores, not steps (E1 for the bytes; their meaning U).

## Writer census for the party bytes (E1, bounded)

Static DS-direct writes to `0x6AAD`, `0x6AAE`, `0x6AAF`, in the decoded closure and prologue-sweep walks of the two
owner groups `0x0C5D1` and `0x166CB` only (4,942 instructions checked; not exhaustive over the overlay):

- `0x16E06`: 6 (`add [6AAD]`, `add [6AAE]` from the table; four constant wrap stores).
- `0x16D58`: 4 (constant clamp stores).
- `0x17054`: 7 (direction stores).

No hit in `0x0C5D1`, `0x1695F`, `0x17438` itself.

## Caveats the parent should keep

1. **Reader identity (E4).** Every arm above is about the bytes at `03D5:002F`. If that literal does not reach
   `0x2EC47`, the reader analysis is about an unknown callee. Only byte consistency supports the identity.
2. **Reachability, not execution.** No dump, trace or run shows any arm executing or which `R` was returned.
3. **`R` semantics.** `R=1` is both a field value and the default. The bytes do not say what `R` means in play.
4. **Wrap vs. clamp.** Two different edge rules exist in the decoded code (`0x16E06` wraps; `0x16D58` clamps).
   Which one the game relies on is not decided here.

## Open edges (unresolved)

- The bodies of the far routines `03D5:002A`, `03D5:0034`, `08AE:00DC`, `0AF8:16A8`, `0AF8:0B25/0B0B/0B98/0C10`,
  `00B0:0048`, `0464:2595`, `03D0:002F`, `03C5:002A`, `00BA:290B`. Not decoded.
- The in-group callees (`0x16901`, `0x16D13`, `0x16CB9`, `0x16BAA`, `0x16EE3`, `0x1695F`, `0x167D4`) were run by
  the tool with unknown arguments and unknown returns. Their arms are in the JSON, not read by hand.
- The result of `08AE:00DC` at `0x16E0D` (not tested in the bytes): it could be a gate for the step.
- The direction table values at `DS:2736+dir` and `DS:273F+dir` (DS data outside `GAME.OVR`).
- What sets `DS:49FA` (the guard at `0x17443`) and the ES byte at `+0x592` (guard at `0x17458`).
- What reads the flag `es:[ptr49D6+0x5AA]` that `0x16D58` sets.
- The trigger for `0x17438` (stub-1 root) and callers of `0x16D58` and `0x16E06` outside the closure walked here.
- Runtime. No live capture; the copy-protected runtime path is unavailable (see
  [por-wall-runtime-capture-attempt.md](por-wall-runtime-capture-attempt.md)).

## Commands and results

All on this checkout, Windows, Python 3.13 with the repo venv (`tools/.venv`, the interpreter `make test` uses).
The default `python` lacks pytest, so tests run with `tools/.venv/Scripts/python.exe`.

```sh
# 1. Probe run, read-only on the pinned install, output under data/work
tools/.venv/Scripts/python.exe -I tools/por_door_reader_branch_probe.py \
    --install data/work/por-geo-run/POOLRAD -o data/work/por-door-reader-branch-probe
#   -> "wrote data\work\por-door-reader-branch-probe", exit 0 (about 0.4 s)

# 2. Focused tests (synthetic + retail-gated; the install is present so none skipped)
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_door_reader_branch_probe.py -q -p no:cacheprovider
#   -> 29 passed

# 3. Neighbouring door-probe tests (regression check; those files were not edited)
tools/.venv/Scripts/python.exe -I -m pytest tests/test_por_door_caller_probe.py tests/test_por_door_indirect_probe.py -q -p no:cacheprovider
#   -> 41 passed
```

Read-only inline checks used during the work (not saved): decoding the reader listing, the four caller
listings, `0x175B8`, `0x176C4`–`0x17770`, `0x16E06` and its tail, and the `0x17438` prologue. All used the existing
`lh.walk`/`lh.decode` and `dcp.load_pinned`, and wrote nothing.

## Side effects and scope

- New files only: `tools/por_door_reader_branch_probe.py`, `tests/test_por_door_reader_branch_probe.py`,
  `docs/por-door-reader-branch-probe.md`. Outputs are under `data/work/por-door-reader-branch-probe/` (git-ignored).
- No existing file was edited. `tools/por_door_caller_probe.py`, `tools/por_door_indirect_probe.py`,
  `tools/por_geo_door_census.py` were imported (for pinned load and the closure index) and not changed.
- Read-only on `data/work/por-geo-run/POOLRAD/GAME.OVR` and `START.EXE` (hash-pinned). No write to any retail file.
- No DOSBox, Hatari, GameLink, codewheel, or other retail tooling was run.
- `__pycache__` directories were created by the imports; they are git-ignored.
- Nothing committed or pushed. The parent reviews the three exact paths above.
- GoldBox, CoK and COAB material was not used. Nothing here is PoR semantics beyond the bytes listed.
