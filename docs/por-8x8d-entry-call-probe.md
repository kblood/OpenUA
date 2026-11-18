# Pool of Radiance: entry-call census with jump and indirect edges (static, observe-only)

**Status: `static-probe-only`. `playable: false`. `mappings: []`. `binding_established: false`.**
**Verdict: the census now counts direct jumps and indirect transfers as well as E8 calls. It finds no
established caller of START `0x7245`, the GAME.OVR `0x32270` stub at START `0x42DE`, or GAME.OVR
`0x32270`. The DOS open helper has three cross-body E8 callers, and its chain tops out at the
prologue-entered routine `0x0A728`. Every indirect table edge is unlinked.**

Tool: [`tools/por_8x8d_entry_call_probe.py`](../tools/por_8x8d_entry_call_probe.py). Tests:
[`tests/test_por_8x8d_entry_call_probe.py`](../tests/test_por_8x8d_entry_call_probe.py) (27 tests: 21 synthetic
falsifiers and refusal/determinism checks, 6 retail anchors; without `OPENUA_POR_INSTALL` the 6 anchors skip).
Retail output is under ignored `data/work/por-8x8d-entry-call-probe/retail/`.

Related: [por-8x8d-dos-sites-probe](por-8x8d-dos-sites-probe.md) (its D9 lists indirect and jump callers as not
counted; this probe counts them), [por-8x8d-archive-chain-probe](por-8x8d-archive-chain-probe.md) (E8 and 9A
census of the stub and `0x32270`), [por-farcall-resolution](por-farcall-resolution.md) (the stub groups).

---

## Question

The earlier probes counted decode-verified E8 near calls, and 9A far calls under an unvalidated image model.
They did not count direct `jmp`/`jcc`, and they did not count indirect `FF /2`–`/5` transfers through a
table or register. This slice asks whether those omitted edges give START `0x7245`, the VROOMM stub at START
`0x42DE`, GAME.OVR `0x32270`, or the DOS open/read chain a caller that the earlier census missed.

PoR DOS bytes only. GoldBox and CoK sources are not used. No Amiga or other-title method is applied here.

---

## Pinned inputs

| File | Bytes | SHA-256 | Pin |
| --- | ---: | --- | --- |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` | match |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` | match |

Both are read from the user-supplied GOG install (`G:/Games/Pool of Radiance/POOLRAD`) read-only and re-hashed
after the run (`source_unchanged_during_run: true`). Without `--allow-unpinned` a mismatch is refused (exit 2).

## Usage

```sh
python tools/por_8x8d_entry_call_probe.py --install "PATH/TO/POOLRAD" \
    -o data/work/por-8x8d-entry-call-probe/retail
# exit 0 (pins match); re-run into another folder is byte-identical
python -m pytest tests/test_por_8x8d_entry_call_probe.py -q
#   27 passed with OPENUA_POR_INSTALL set; 21 passed, 6 skipped without it
```

Exit codes: `0` pins match and the scan completed; `1` output written with `retail_evidence: false` (only with
`--allow-unpinned`); `2` named refusal (missing files, output outside `data/` or inside the install, a pin
mismatch without the flag, or a source that changed during the run).

---

## Method

Decoder: the shared `tools/por_loadpieces_handler.decode` (no edits to it). All addresses are file offsets; direct
branch targets are relative, so they need no image model.

**Tiers.** A *body* is the set of instruction starts reached from an entry by fall-through and direct `jmp`/`jcc`
edges. Calls fall through without being entered. `ret`, unconditional jumps and indirect transfers end a path.
A direct jump is followed only when its target lies in `[entry, entry + 0x400)`; a farther jump is a tail jump
into another routine. The tier of a source is:

- **A**: in the body of an E8-verified entry (an E8 target);
- **B**: in a body entered only from a prologue (`push bp; mov bp,sp`), not from an E8 target;
- **C**: in neither.

**Caller rule.** A direct edge counts as a caller only when its source is tier A and no E8 body contains both the
source and the target. A branch inside one routine is reported as same-body and does not count. Tiers B and C are
reported and not counted.

**Indirect transfers.** Every decoded `FF /2`, `/3`, `/4`, `/5`, in both images, with its addressing form and the
displacement the bytes give (`direct` = mod 00 rm 110; `base-disp` = a `[base+disp]` form; `register`;
`base-no-disp`). None is linked to a table yet (see U1).

**Table-word hits.** Every byte position in the image holding the 16-bit word `target - base`, for bases `0` and
`0x200` (the two near-offset bases the earlier probes used). A base whose value is 0 is skipped and recorded,
because every zero word would match. A hit is a *candidate* table slot; the expected chance rate per value is
`image length / 65536`, recorded for comparison.

**Far model.** 9A literals with `0x200 + seg*16 + off == target`, reported separately as model-conditional.

---

## Results

### Targets (counts by the rules above)

| id | target | E8 tier A | E8 all | direct jumps A / B / C | far-model A / total | word hits base 0 / base 0x200 | chance per value |
| --- | --- | ---: | ---: | --- | --- | --- | ---: |
| L | START `0x07245` | 0 | 0 | 0 / 0 / 0 | 0 / 0 | 3 / 0 | 0.9953 |
| STUB | START `0x042DE` | 0 | 0 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 0.9953 |
| OPEN | START `0x0A89E` | 3 | 3 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 0.9953 |
| OVR_OPEN | START `0x0A728` | 0 | 0 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 0.9953 |
| PATH | START `0x0A86A` | 0 | 0 | 2 / 0 / 0 | 0 / 0 | 0 / 0 | 0.9953 |
| READ_A | START `0x0A97E` | 0 | 0 | 0 / 0 / 0 | 0 / 0 | 0 / 2 | 0.9953 |
| READ_B | START `0x0B306` | 0 | 1 | 0 / 0 / 0 | 0 / 0 | 0 / 1 | 0.9953 |
| READ_C | START `0x0B360` | 0 | 0 | 0 / 0 / 0 | 0 / 0 | 0 / 0 | 0.9953 |
| R | GAME.OVR `0x32270` | 0 | 0 | 0 / 0 / 0 | 0 / 0 | 0 / 12 | 3.1449 |

The "direct jumps A" entries for PATH are both same-body (see below). They are not callers.

### Direct A-tier edges (the only counted callers)

| source | kind | target | class |
| --- | --- | --- | --- |
| START `0x0A806` | E8 | OPEN `0x0A89E` | cross-body caller (body of `0x0A7FF`) |
| START `0x0A841` | E8 | OPEN `0x0A89E` | cross-body caller (body of `0x0A80B`) |
| START `0x0A895` | E8 | OPEN `0x0A89E` | cross-body caller (body of `0x0A846`) |
| START `0x0A85B` | jcc `74` | PATH `0x0A86A` | same-body branch, not a caller |
| START `0x0A89A` | jcc `72` | PATH `0x0A86A` | same-body branch, not a caller |

**Chain shape.** `0x0A728` (overlay-open, `retf 4`) is not an E8 target, and no decoded E8, direct jump, 9A or
table word reaches it. Its body makes three E8 calls: `0x0A73D` to `0x0A7FF`, `0x0A742` to `0x0A80B`, and
`0x0A747` to `0x0A846`. Each of those three routines calls OPEN. Those three call sites are tier B (inside
`0x0A728`'s prologue-entered body), so the counted A-tier callers of OPEN are called only from a routine whose own
caller is not decode-verified. The chain's top is `0x0A728`. The earlier probes' statement that `0x0A86A` has no
E8 caller is still true of `0x0A86A` itself; the routine that contains it is `0x0A846`, which is E8-entered.

### Indirect transfers (FF /2–/5)

| image | kind | total | tier A | tier B | tier C | with direct disp |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| START.EXE | call_far | 57 | 8 | 1 | 48 | 4 |
| START.EXE | call_near | 120 | 4 | 0 | 116 | 62 |
| START.EXE | jmp_far | 44 | 2 | 0 | 42 | 1 |
| START.EXE | jmp_near | 113 | 11 | 0 | 102 | 16 |
| GAME.OVR | call_far | 85 | 2 | 3 | 80 | 4 |
| GAME.OVR | call_near | 280 | 0 | 0 | 280 | 150 |
| GAME.OVR | jmp_far | 83 | 0 | 0 | 83 | 0 |
| GAME.OVR | jmp_near | 75 | 0 | 0 | 75 | 31 |

Tier-A indirect sites: 25 in START and 2 in GAME.OVR. None is linked to a table, so none is a caller of anything
here. The full list is in the report (`por_8x8d_entry_call_probe_report.md`, "Tier-A indirect sites").

### Word hits (candidates only, all unlinked)

- **R `0x32270`, base `0x200` (value `0x3070`): 12 hits, every one tier C** (not in any walked body): at GAME.OVR
  `0x04F3E`, `0x14BF4`, `0x190C7`, `0x19EC8`, `0x1B855`, `0x1B879`, `0x1BA18`, `0x2106E`, `0x21AC0`, `0x21F2C`,
  `0x24A3A`, `0x2C73B`. That is about 3.8 times the chance rate. It is not a caller, and nothing yet ties any of
  them to an indirect site.
- **L `0x07245`, base 0: 3 hits** at START `0x00EA6`, `0x01AD3`, `0x0FCCE`, all tier C. About 3 times the chance rate
  of one per value, on three hits. Not significant alone.
- READ_A `0x0A97E` (2 hits at base `0x200`) and READ_B `0x0B306` (1 hit): tier C, unlinked.
- STUB `0x042DE` and OVR_OPEN `0x0A728`: no word hits under either base.

---

## Corrections to earlier notes (this probe's tiers and the earlier doc)

- `por-8x8d-dos-sites-probe` grades the routine `0x0A86A` as tier B, and so its E8 to OPEN at `0x0A895` is not
  counted as a caller there. Under the body rule here, `0x0A895` is tier A: it lies in `0x0A846`'s body, and
  `0x0A846` is E8-entered (from `0x0A747`). This probe's first pass, with a linear sweep, gave 2 tier-A callers of
  OPEN. Following the jcc edges gives 3, the same three call sites as the earlier census's E8 list.
- `0x0A86A` is not a separate routine entry. Its two jcc edges (`0x0A85B`, `0x0A89A`) are inside `0x0A846`. The
  earlier doc's "tier B path copy routine" is the body of `0x0A846` seen from its inner label.

---

## Evidence boundaries

- Established by bytes, under the decode-only rules above: the E8 callers of OPEN and their tiers; the
  same-body status of the PATH jcc edges; the three E8 callers of `0x0A728`'s chain; the counts in the tables.
- **Not** established: a caller of START `0x7245`, the stub at `0x42DE`, GAME.OVR `0x32270`, or `0x0A728` (no
  decoded edge reaches any of them; word hits are unlinked); any link between a table slot and an indirect site;
  any far (9A) caller beyond the model; any call through a `0F 8x` near Jcc (the shared decoder rejects 0F).
- The body rule (span 0x400, calls not entered, tail jumps outside the span) is a **heuristic**. The tests
  falsify each side of it on synthetic code. A real routine with a far internal jump would be counted as a
  caller, and that would be a false positive, not a result.
- Nothing here is a runtime fact. No emulator, DOSBox, GameLink, codewheel, or retail write was used.
- GoldBox and CoK material is not used as evidence. No Amiga or other-title method is applied.

## Unresolved edges (from the JSON)

- **U1** the DS (or CS) base of each indirect displacement. Without it, no table slot links to an indirect site.
- **U2** indirect table slots holding a target offset: candidates only, with the chance rate recorded.
- **U3** 9A callers of the stub and of `0x32270`: the image model `0x200 + seg*16 + off` is not validated.
- **U4** near Jcc encoded as `0F 8x`: not counted by the shared decoder.
- **U5** callers above depth 1: this probe takes one census level and does not walk upward.

## Next discriminator

Fix the DS base, then test the tier-A indirect sites against it. The START.EXE startup code holds the data
segment literal (a `mov ax, imm16` followed by `mov ds, ax`); locate it and derive the DS base that the MZ load
image implies. Then, for each of the 25 tier-A START indirect sites with a direct or `[base+disp]` form, read the
word at `DSbase + displacement` (or its table range) and ask whether it equals an E8-verified body start, and
in particular `0x0A89E`, `0x0A728`, `0x0A97E`, `0x0B306` or `0x0B360`. A link is established only if that word
is the value the indirect site reads and the site's own tier is A. If no site links, the census stays
bounded and the next step is a runtime observation, which this slice does not do.

---

## Commands and results

```sh
python tools/por_8x8d_entry_call_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-8x8d-entry-call-probe/retail           # exit 0; retail_evidence true
python tools/por_8x8d_entry_call_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-8x8d-entry-call-probe/retail-b         # cmp: JSON and report byte-identical
python -m pytest tests/test_por_8x8d_entry_call_probe.py -q  # 27 passed (with OPENUA_POR_INSTALL)
python -m pytest tests/test_por_8x8d_archive_chain_probe.py tests/test_por_8x8d_dos_sites_probe.py -q
#   34 passed, 10 skipped (no regression in the neighbouring probes)
```
