# Pool of Radiance: DS of the INT 3Fh dispatcher's `callf [0x43F0]` (static, observe-only)

**Status: STATIC-PROBE-ONLY. `playable: false`. The trigger is NOT established.**
Tool: [`tools/por_door_ds_entry_probe.py`](../tools/por_door_ds_entry_probe.py). Tests:
[`tests/test_por_door_ds_entry_probe.py`](../tests/test_por_door_ds_entry_probe.py) (27 tests: 23 synthetic, most
with a falsifier; 2 refusal; 2 retail-gated anchor and read-only/determinism checks; all 27 pass with the retail gate
open). Output (git-ignored): `data/work/por-door-ds-entry-probe/por_door_ds_entry_probe.json` and `..._report.md`.

This follows [por-door-indirect-probe.md](por-door-indirect-probe.md), which left the START handler's
`callf [0x43F0]` (file `0x0AA40`) with DS unresolved, and [por-door-caller-probe.md](por-door-caller-probe.md).
The question: does any byte-level caller or entry path establish AX, and hence DS, for that call, and can the far
pointer it reads reach the door writer/clearer stub at START `0x0089C`?

**Answer, in one paragraph.** No caller is needed. The dispatcher sets AX and DS itself (`mov ax,0x0C7C; mov ds,ax`),
on every path, and no decoded or raw edge enters that span from outside. The only static value written to
`DS:[0x43F0]` is offset `0x02E5`, and that offset cannot address `0x0089C` under any of the three shifts examined
(named M0 and M1, and the shift quoted from the live capture). The route is **not shown** to reach the stub. It
stays open for a shift with residue 7 (mod 16), which none of those three gives; for two open callee edges; and for
27 block copies whose destinations are unresolved.

## Pins

| file | size | sha256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched on every run. The probe reads them through `por_door_caller_probe.load_pinned` (unpinned input is a named
refusal, no override) and re-hashes both after the run (`pins_rechecked.unchanged`). No dump, emulator, GoldBox,
install write, or codewheel was touched.

## Method

1. **Decoded chain.** `por_loadpieces_handler.walk` from `0x0A9FC`. The decoder's `Insn` gives opcode, ModRM,
   immediate, DS-direct displacement and flow. Facts below are class D unless labelled R, M or X.
2. **Image census.** Closure from the MZ entry (`0F72:0012`, file `0xF932`) plus a Borland prologue sweep: 173 walks,
   172 complete, 34,699 of 64,719 image bytes covered (53.6%, the same figure as the indirect probe).
3. **Bypass edges.** Decoded jumps, calls and far literals from outside the dispatcher body into the AX/DS-load span,
   and decoded or raw callers of the dispatcher entry.
4. **Callee closure** of the two calls between the DS load and the `callf` (near call to `0x0AA4E`). Each function is
   decoded on a miss, audited for DS writes (bracket-checked), far calls and indirect calls.
5. **DS:`[43F0]` and `[43F2]` references.** Decoded DS-direct operands and moffs forms, plus raw byte patterns (`disp16`
   with ModRM `mod 00, rm 110`, or moffs `A0`–`A3`), in START and GAME.OVR.
6. **Shifts and residues.** A seg:off pointer addresses file `seg*16 + off + k` (uniform `k`). For each pointer/target
   pair the report gives the required `k` mod 16 (`required_skew`). Three shifts are checked, and none is promoted:
   **M0** `k = 0x200` (residue 0, paragraph-loaded image), **M1** `k = 0x7E` (residue 14, dump-anchored in the caller
   probe), and **X** the runtime shift quoted from the live capture (`linear − file = 0x0854A`, `k ≡ 6`).
7. **MZ.** Header fields and the relocation table (`nreloc`), to see whether the `mov ax` immediate is loader-patched.

## Findings

### The dispatcher sets AX and DS itself (class D)

- `0x0A9FC`–`0x0AA4D` is a complete 42-instruction walk. It is INT 3Fh-shaped: it saves registers, reads the interrupt
  return `CS:IP` (`les bx,[bp+2]`), pushes the word there (`push es:[bx]`), and ends with `iret` at `0x0AA4D`. It is
  **not** shown to be an installed handler (see the residue section).
- `0x0AA07` `B8 7C 0C` `mov ax,0x0C7C` (immediate decoded, ok).
- `0x0AA0A` `8E D8` `mov ds,ax` (ok).
- `0x0AA40` `FF 1E F0 43` `callf [0x43F0]` (ok).
- **No branch** precedes the DS load (`branch_before_ds_load: []`). Every path from `0x0A9FC` reaches `0x0AA07` and
  `0x0AA0A`. So AX is overwritten on every path, and **no caller establishes AX**.
- **No decoded or raw edge enters `0x0AA08`–`0x0AA40`** from outside the dispatcher body, and **no decoded or raw caller
  reaches `0x0A9FC`**. The dispatcher's only possible entry is the INT 3Fh vector (below).
- The two calls between the DS load and the `callf` (`0x0AA19`, `0x0AA2A`) both go to `0x0AA4E`. The direct path has no
  DS write, so DS is `0x0C7C` on that path.

### MZ: the immediate is not loader-patched (MZ fields are class D)

- `e_crlc` (nreloc) = **0**. No fixup covers the `mov ax` immediate (`mz_relocation_covers_mov_ax_immediate: false`).
- So the static literal is `0x0C7C`. The live doc quotes `DS = 0x14A0` (X, from
  [por-int3f-live-dispatch.md](por-int3f-live-dispatch.md)), that is `0x0C7C + 0x0824`. The MZ table does not explain it.
  Either something in START patches it at run time, or the quoted capture is of a different image. Not decoded.

### The only static writer of `DS:[0x43F0]` is routine A (class D)

Direct-address references in START: 5 decoded, 5 raw, 0 uncovered.

| file | instruction | class |
| --- | --- | --- |
| `0x0A7D5` | `mov ax,[0x43F0]` (moffs) | read |
| `0x0A7D8` | `or ax,[0x43F2]` | read |
| `0x0A7DE` | `mov word [0x43F0],0x2E5` (`C7 06 F0 43 E5 02`) | **write** |
| `0x0A7E4` | `mov [0x43F2],cs` | write (segment = routine A's CS, not established) |
| `0x0AA40` | `callf [0x43F0]` | read (the dispatcher's call) |

- The store is guarded: it runs only when `[43F0]` and `[43F2]` are zero (`0x0A7D5`–`0x0A7DC`).
- **DS at the store is routine A's entry DS.** Routine A pushes DS at `0x0A762` and restores it at `0x0A782`. The temporary
  `push ss; pop ds` at `0x0A773`–`0x0A774` sits inside that bracket. So the store writes the caller's `DS:[43F0]`. The
  check is address-order, not a path proof, but every decoded path to `0x0A7DE` is inside that one bracket.
- **Who calls routine A is not established.** No decoded or raw far literal or near call reaches `0x0A728` under M0, M1,
  or X (`routine_a.decoded_callers` and the raw scans are empty).
- GAME.OVR contains **no** `F0 43` or `F2 43` byte pair at all. So no overlay instruction can address `DS:[43F0]` with a
  disp16 or moffs operand. Base-indexed forms are not excluded.
- START has four `F0 43` pairs. Three are the decoded operands above (`0x0A7D5`, `0x0A7DE`, `0x0AA40`). The fourth is data
  at `0x0FC99`, preceded by `0x43`, not a ModRM disp16 form.

### The pointer value, and the three shifts (class D with M and X models)

- The routine A pointer is `CS_A : 0x02E5`. Its residue is **5** (mod 16).
- Door stub 1 (`0x0089C`, `CD 3F 6D 0D 00`) has residue **12**.
- For a uniform shift the pointer reaches the stub only if `k ≡ 7 (mod 16)` (`required_skew`).

| shift | k mod 16 | pointer `0x2E5` reaches stub 1 | source |
| --- | ---: | :---: | --- |
| M0, paragraph-loaded image | 0 | no | zero-skew convention |
| M1, dump-anchored | 14 | no | por-door-caller-probe.md |
| X, quoted live shift `0x0854A` | 6 | no | por-int3f-runtime-capture.md (not re-derived) |
| required | 7 | yes | not one of the three |

So **the only static pointer value cannot address the stub under any of the three shifts examined.** The argument needs a
uniform shift; a per-segment base would break it, and the bytes do not fix one.

### Callee closure: two open edges (class D)

The closure of `0x0AA4E` has 10 functions. Nine have no open edge: seven have no DS write, far call or indirect call, and
`0x0ABB4` and `0x0ABFC` each contain a DS write bracketed by `push ds` / `pop ds` (`bracketed`, so they restore DS). The
tenth, `0x0AA4E`, contains two open edges:

| at | kind | text | note |
| --- | --- | --- | --- |
| `0x0A71C` (in fn `0x0A716`, reached by `jmp 0x0A716` at `0x0AAFC`) | far call | `call 0x0AF8:0x00E2` | target not resolved; its M0 file target is `0x0B262` |
| `0x0AAC0` | indirect callf | `callf [0x8504]` | `[0x8504]` = CS:0x268, stored by routine A at `0x0A7CB` |

`[0x8504]`'s offset `0x268` has residue 8, the same as routine A's entry `0x0A728`. Under M0 it equals routine A's entry if
routine A's CS is `0x0A2C` (R). CS is not established, so this is a candidate, not a finding. If it holds, the dispatcher's
own call chain re-enters routine A with DS `0x0C7C`, and routine A would store `CS_A:0x2E5` to the word that the
`callf [0x43F0]` reads. The pointer still has residue 5, so the stub is still not reached.

### INT 3Fh installs and the dispatcher (R, residue arithmetic)

Two literal installs (`mov dx,imm16; mov ax,253Fh; int 21h`):

| install site | DX | skew needed to put the dispatcher at file `0x0A9FC` |
| --- | ---: | ---: |
| `0x0A7EE` (routine A) | `0x02E6` | 6 |
| `0x0ACF0` (routine B) | `0x00D7` | 5 |

Under M0 (0) and M1 (14), **no literal install reaches the dispatcher.** Under the quoted live shift (6), install A's DX
lands exactly on `0x0A9FC`, so under X the dispatcher is the live INT 3Fh handler. Routine B's install is in another
function: the walk from `0x0A9FC` ends at `0x0AA4D` and does not contain `0x0ACF0`.

## The live-capture shift (X): a finding for the parent

The runtime-capture doc places the live INT 3Fh handler `12C6:02E6` on file `0xA9FC`, and routine B's handler `131C:00D7` on
file `0xAD4D`. Both give the same runtime-minus-file shift, `0x0854A`, which is **not a multiple of 16**. A paragraph-loaded
image (M0) cannot produce that. So either the live START code does not sit at a paragraph-affine copy of the file (the entry
block copy with `rep movsb` is one candidate, not verified), or the byte-window placement is wrong. The static probe cannot
decide which. The consequence is the same either way: under X the pointer still misses the stub, so this does not change the
verdict. It does change the premise. The dispatcher is the live INT 3Fh handler only under X.

## Corrections to earlier docs (for the parent to decide; not edited here)

1. [por-int3f-handler.md](por-int3f-handler.md) (runtime update) and [por-int3f-runtime-capture.md](por-int3f-runtime-capture.md)
   label `12C6:02E6` as "routine A, file `0xA9FC`". That holds only under the quoted shift X (`k ≡ 6`). Under M0 or M1 it is
   impossible (`0x2E6` has residue 6; `0xA9FC` has residue 12). The label should name its shift.
2. The handler doc's "install routine B, enclosing prologue `0xa9fc`" is the nearest preceding prologue, not a containing
   function (the walk from `0xA9FC` ends at `0xAA4D`).

## Test and run results

```text
OPENUA_POR_INSTALL="C:/Modding/OpenUA/data/work/por-geo-run/POOLRAD" \
  /c/Python313/python -m pytest tests/test_por_door_ds_entry_probe.py -q -p no:cacheprovider
  -> 27 passed
/c/Python313/python -m pytest tests/test_por_door_ds_entry_probe.py -q -p no:cacheprovider   (no env var)
  -> 27 passed
/c/Python313/python -I tools/por_door_ds_entry_probe.py --install data/work/por-geo-run/POOLRAD \
  -o data/work/por-door-ds-entry-probe
  -> exit 0; trigger_established=False; required uniform skew 7 (mod 16)
```

The retail anchors pin: `mov ax` at `0x0AA07` (`0x0C7C`), `mov ds` at `0x0AA0A`, `callf` at `0x0AA40`; dispatcher 42
instructions and complete; no bypass edges; routine A's store at `0x0A7DE` (`0x02E5`) with bracketed DS; two closure open
edges (`0x0A71C`, `0x0AAC0`); two bracketed callees (`0x0ABB4`, `0x0ABFC`); five DS-direct START refs; zero `F0 43` / `F2 43`
pairs in GAME.OVR; `nreloc = 0`; 34,699 covered bytes; skew 7; the quoted shift (`0x0854A`, `k ≡ 6`) placing install A on the
dispatcher and missing the stub; `trigger_established: false`; and the two install DX values. The read-only test checks both
pins before and after the run and requires identical JSON on two runs.

A bug found and fixed during this session: the first run reported every closure callee as `none`, because the DS check read
only the image census, which does not walk `0x0AA4E` or `0x0ABB4`. The check now decodes on a miss. A falsifier test passes an
empty instruction map to lock that in.

## Side effects

- New files only: `tools/por_door_ds_entry_probe.py`, `tests/test_por_door_ds_entry_probe.py`, `docs/por-door-ds-entry-probe.md`,
  and outputs under `data/work/por-door-ds-entry-probe/` (git-ignored). `__pycache__` (git-ignored) may appear from the imports.
- No existing file was edited.
- No commit, no push, no emulator, no GoldBox, no codewheel, and no writes to the install folder. Both pinned files re-hashed
  unchanged after every run.

## Next evidence that would settle it

1. **Routine A's caller.** Find the far or near call that enters `0x0A728`, and its DS. A caller with `DS = 0x0C7C` would put the
   store on the dispatcher's word. Static decode found none under M0, M1, or X.
2. **The live shift.** Explain `0x0854A` (not a multiple of 16). Check whether START copies its code block at run time (the entry's
   `rep movsb`), and whether the byte-window placement is unique for the whole START image.
3. **The two open edges.** Decode the far target `0x0AF8:0x00E2`, and the target of `callf [0x8504]`, and check whether either
   writes `DS:[0x43F0]`.
4. **Block copies.** 27 decoded string moves or stores exist in START. Resolve their destinations, particularly the `rep movsw`
   at `0x0ABDD` (ES:DI).

## Limits

- Static bytes only. Every runtime value above is quoted (X) from another doc, not re-derived.
- The residue results assume one uniform shift for all START code. A block copy or a per-segment base would break them.
- DS:`[43F0]` writers are found by direct-address decode and raw pattern. Base-indexed and block-copy writes are counted (27 sites)
  but not resolved. The callee-closure edges are not resolved.
- Coverage is 53.6% of the START image. An unwalked call or store would be missed.
- GAME.OVR is raw-scanned only; overlay DS is not known, so its hits would be unlabelled (there are none).
- No PoR or GoldBox semantics beyond these bytes. Nothing here says what the far target does.
