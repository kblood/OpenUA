# Pool of Radiance: START.EXE DOS open/read sites, entry walk and caller census (observe-only)

**Status: `static-probe-only`. `playable: false`. `mappings: []`. `binding_established: false`.**
**Verdict: bounded. The open and the four reads are located by decode. Their use for an 8X8D archive is not established.**

Tool: [`tools/por_8x8d_dos_sites_probe.py`](../tools/por_8x8d_dos_sites_probe.py). Tests:
[`tests/test_por_8x8d_dos_sites_probe.py`](../tests/test_por_8x8d_dos_sites_probe.py) (20 tests: 16 synthetic
falsifiers and determinism/refusal checks, 4 retail-gated anchors; without `OPENUA_POR_INSTALL` the 4 anchors skip).
Output is under ignored `data/work/por-8x8d-dos-sites-probe/retail/`.

Related: [por-8x8d-archive-chain-probe](por-8x8d-archive-chain-probe.md) (the 8X8D read-path trace this builds on;
its "not contained" result for `0x0A8B6` is refined here), [por-8x8d-loader-probe](por-8x8d-loader-probe.md),
[por-8x8d-blocks](por-8x8d-blocks.md) (the block 201 rule).

---

## Question

The START.EXE INT 21h sites are one AH=3Dh open at file offset `0x0A8B6` and AH=3Fh reads at `0x0A9B5`, `0x0A9D6`,
`0x0B333`, `0x0B374`. The earlier trace found none contained by a prologue-entered routine. This probe allows
entries without a prologue, walks them, and takes an upward caller census. It asks which routines the bytes
connect to these sites, and whether any code on that chain builds or names an 8X8D archive.

Evidence labels used below:

- **decoded**: an instruction decodes and lies on a ret-stopped linear walk from the entry shown.
- **e8-verified**: the entry is the target of a decode-verified E8 near call (relative, so no image model is used),
  and an anchored linear sweep from an earlier prologue or byte-ret start lands on it as an instruction start.
- **byte-ret**: the byte before the entry is a ret (C3/CB) or ret imm16 (C2/CA) that decodes to the entry. Not
  decode-synced. Weakest entry basis.
- **model**: depends on the far-call image model `file = 0x200 + seg*16 + off`, which is not validated.
- **consistency**: a CS base places pointers on Pascal piece length bytes. Not proof.
- **hypothesis**: an interpretation the bytes do not establish.

---

## Pinned inputs

| File | Bytes | SHA-256 | Pin |
| --- | ---: | --- | --- |
| `START.EXE` | 65,231 | `d825df2b…60b6a07bd` | match, unchanged after run |
| `GAME.OVR` | 206,105 | `872964a3…7928614` | match, unchanged after run |

`START.EXE` has `e_crlc = 0` (no relocations) and image base `0x200`. The INT 21h inventory is the shared one from
`por_8x8d_archive_chain_probe` (predecessor rule, 58 sites in START, 0 in GAME.OVR).

---

## Established (decoded, model-free unless marked)

### The open: `0x0A8B6` is inside a non-prologue helper at `0x0A89E`

- **decoded.** `0x0A89E` is a ret-stopped routine of 14 instructions (`ret` at `0x0A8B8`). It begins
  `lds si,[bp+6]`, copies a Pascal string with `lodsb; mov cl,al; xor ch,ch; rep movsb`, writes a NUL with
  `xor al,al; stosb`, sets `lea dx,[bp-0x82]; push ss; pop ds`, loads `mov al,[bp-2]`, and then
  `mov ah,3Dh; int 21h`. It has no prologue. The destination is ES:DI, which the caller sets.
- **e8-verified.** Three decode-verified E8 calls target `0x0A89E`: from `0x0A806` (inside `0x0A7FF`), `0x0A841`
  (inside `0x0A80B`) and `0x0A895` (inside `0x0A86A`). The earlier probe's prologue-only search could not see it.
- This is the **only** decoded INT 21h AH=3Dh in START. GAME.OVR has none. So every open that the byte scan
  decodes goes through this helper, except any of the five AH-unresolved sites in the table below.

### The three callers of the open helper

- **`0x0A7FF` (E8 from `0x0A73D`, inside `0x0A728`).** `push ds; lea di,[bp-0x82]; push ss; pop es; call 0x0A89E;
  pop ds; ret`. Sets ES:DI to the frame buffer, then calls the helper.
- **`0x0A80B` (E8 from `0x0A742`, inside `0x0A728`).** Contains `mov ah,30h; int 21h` (decoded) before the
  helper call at `0x0A841`, and a `\`-handling test (`cmp 0x5C; jnz`). Its helper call is the path-building form.
- **`0x0A86A` (no decode-verified E8 callers; tier B).** A copy loop that compares against `:` (`0x3A`) and `\`
  (`0x5C`), stores `\`, and then calls the helper at `0x0A895`. The shape is a DOS directory-path copy.

### The overlay-open routine: `0x0A728` (prologue, prologue-entered)

- **decoded.** `push bp; mov bp,sp; sub sp,0x82`. Ret-complete, 85 instructions, ends `retf 4` at `0x0A7FF`
  (so it takes four bytes of caller-pushed arguments). The helper reads the Pascal name at `[bp+6]` by inheriting
  this BP. So the name is an argument of `0x0A728`, supplied by a caller this probe did not find.
- **decoded.** The mode comes from `mov al,[0x43E4]; mov [bp-2],al`, gated by `cmp [0x43EC],0`.
- **decoded.** It contains the 8-byte header read at `0x0A77A` (`MZ`/`FB`/`OV` check, per the earlier probe) and
  INT 21h AH=3Eh (close), 42h (seek), 25h (vector install). Its own [bp+6] is never read: the name belongs to the
  caller.
- **Callers: none found** by E8 (no decode-verified call targets it) and none by a 9A literal at model delta 0.
  A bounded delta sweep (±16) finds no 9A literal within span for this root either (model-conditional).

### The vector-3Fh installs

- **decoded.** `0x0A7F1` (in `0x0A728`): `push ds; mov dx,0x2E6; push cs; pop ds; mov ax,0x253F; int 21h`. The
  handler is at **CS:0x02E6** of the segment that holds `0x0A728`. The segment base is not established.
- **decoded.** `0x0ACF3` (in a walk from entry `0x0AC90`, tier B; the instructions before it set `dx` to `0x00D7`):
  the same pattern, handler at **CS:0x00D7**. Vectors 00h, 23h and 24h are installed just before it.
- Hypothesis: these are the INT 3Fh overlay dispatch that the VROOMM stubs use. Not established here.

### The four reads

| Site | Containing entry (tier) | Shape (decoded) | Callers (E8) |
| --- | --- | --- | --- |
| `0x0A9B5`, `0x0A9D6` | `0x0A97E` (B; ends `retf` at `0x0A9FB`) | `mov ah,42h` seek at `0x0A9A5`, then the reads | none |
| `0x0B333` | `0x0B306` (A, e8-verified from `0x0B2DD`; ends `ret` at `0x0B360`) | seek at `0x0B30F` and `0x0B326`; read of `0x80` bytes into `DX=DI+0x80` with the handle from `[DI]`; seek at `0x0B355`; write AH=40h at `0x0B35D` | `0x0B2DD` in `0x0B2D5` (B; ends `retf` at `0x0B306`), which has no callers |
| `0x0B374` | `0x0B360` (B; ends `retf` at `0x0B388`) | read with `les`/`lds` far operands | none |

- Two of the four read routines (`0x0A97E`, `0x0B360`) have no decode-verified E8 caller, and their enclosing
  routine ends in `retf` (a far procedure). That is consistent with a far or indirect entry. Far entries are
  checked only at model delta 0 and ±16 (no hit). Indirect calls (FF /2, FF /3) are **not** counted by this probe.
- The `0x80`-byte record read at `0x0B333` (handle at `[DI]`, buffer at `DI+0x80`) has the shape of record I/O on a
  file-variable record. Whether that is the DAX reader is **hypothesis**.

### A misaligned E8 near the read routine (not a decoded call)

- The bytes `E8` at `0x0A9C3` decode as a call to `0x0ACEC` when decoded alone. But on the decoded walk of
  `0x0A97E`, `0x0A9C2` is a `shr` (`D3 /5`) whose operand covers `0x0A9C3`, so that call is **not an instruction of
  the read routine**. `0x0ACEC` is the second byte of `CD 21` at `0x0ACEB`. An anchored sweep covers it and never starts
  there, so the probe grades it **e8-mid-insn** and it is not an entry. Treat this E8 as a misaligned decode. No
  call from the read routine into the vector-install sequence is established.

### Unresolved AH sites (walk-derived, not predecessor)

| Site | Entry | Walk-derived AH | Note |
| --- | --- | --- | --- |
| `0x09C1C` | `0x09BF3` | `4Ch` (terminate) | |
| `0x0ADDA` | `0x0ADB6` | `25h` (vector) | |
| `0x0B2AF` | `0x0B284` | `3Ch` (create) | near the reads; not 3Dh |
| `0x0C0CC` | `0x0C095` | other (`pop ax`) | unresolved |
| `0x0C15E` | `0x0C147` | other (`call 0x0C12C`) | unresolved |
| `0x0C19F` | `0x0C17D` | non-immediate (`mov` into AH from memory) | unresolved |
| `0x0C497` | `0x0C491` | none on the walk | unresolved |
| `0x0FA30` | none | no containing entry | unresolved |

**Five of the eight unknown-AH sites stay unresolved** (`0x0C0CC`, `0x0C15E`, `0x0C19F`, `0x0C497`, `0x0FA30`). This
probe therefore cannot exclude an AH=3Dh or AH=3Fh among them.

### Name pieces (START.EXE, Pascal, decoded length bytes)

- `8X8d1` at `0x0723B` (length byte `0x0723A`) and `.dax` at `0x07241` (length byte `0x07240`): both lie immediately
  before the routine at `0x07245`, which ends where the data begins and which the earlier probe found to have no
  decode-verified callers.
- `.dax` at `0x04786` (length byte `0x04785`), directly after `retf` at `0x04784`. Its referrer is not established.
  It is not paired with an `8X8d` stem in the census.

---

## Upward census: what it found

Roots are the tier-A entries of the four sites, plus the best tier-B entry where a site had no tier-A entry.
Census depth is limited to 3 caller levels with a node budget of 40. It was not truncated.

```
0x0A728 (prologue, retf 4, overlay header probe)   callers: none (E8; model delta 0 and +-16)
  <- E8 0x0A73D  0x0A7FF (call-helper, ES:DI = frame buffer)
       <- E8 0x0A806  0x0A89E  open helper, INT 21h AH=3Dh at 0x0A8B6
  <- E8 0x0A742  0x0A80B (DOS version check, path form)
       <- E8 0x0A841  0x0A89E
0x0A86A (path copy loop, tier B)                   callers: none (E8)
  -> E8 0x0A895  0x0A89E
0x0A97E (reads 0x0A9B5, 0x0A9D6)                  callers: none (E8)
0x0B2D5 (retf, tier B) <- E8 0x0B2DD  0x0B306 (reads 0x0B333)
0x0B360 (read 0x0B374)                            callers: none (E8)
```

**Pointer census: 0.** No `mov reg,imm16; push cs; push reg` triple (a CS-relative pointer argument) appears in
the 8-instruction pre-call windows of any census caller. So no decoded CS pointer on the chain names an 8X8D or
`.dax` piece. This is a negative result for the chain to depth 3, not for START as a whole.

---

## Hypotheses (not established)

- **H1.** Every START DOS open goes through `0x0A89E`, because it is the only decoded AH=3Dh. This holds only if the
  five unresolved AH sites are not AH=3Dh.
- **H2.** `0x0A728` opens GAME.OVR, since it checks the header it reads (`FBOV`) and is reached through the open helper.
  The name it opens is an argument from a caller not found here.
- **H3.** The reads at `0x0A9B5`, `0x0A9D6`, `0x0B333`, `0x0B374` serve the INT 3Fh overlay handlers (CS:0x02E6 or
  CS:0x00D7), not a DAX archive. Equally they could be a DAX record reader. The bytes here do not decide between them.
- **H4.** The 8X8D name, if it reaches the open helper at all, is built by the caller that pushes the far pointer for
  `0x0A728` or by the path routine at `0x0A86A`, not by the code at `0x07245`.

---

## Unresolved edges

- **D1** the routine containing the open: **entry established** (`0x0A89E`, e8-verified, tier A).
- **D2** callers of `0x0A89E` and of its callers: E8 callers established; the callers of `0x0A728`, `0x0A97E` and
  `0x0B360` are **not established** (no E8, no delta-0 or ±16 9A hit; indirect and jump callers not counted).
- **D3** the Pascal name and mode the open helper uses: the name comes from `[bp+6]`, the mode from `[bp-2]`, and
  the frame belongs to `0x0A728`. The caller that pushes the name is **not established**.
- **D4** the four AH=3Fh reads: **not established** whether they serve GAME.OVR (INT 3Fh overlay) or a DAX file.
- **D5** five AH-unresolved INT 21h sites (`0x0C0CC`, `0x0C15E`, `0x0C19F`, `0x0C497`, `0x0FA30`): **not excluded**
  as AH=3Dh or AH=3Fh.
- **D6** far calls (9A) into the chain: **model-conditional**. The delta sweep found no hit within ±16 for the roots.
- **D7** an 8X8D name on the upward chain: **not established** (pointer census empty to depth 3).
- **D8** the INT 3Fh handler segments (CS:0x02E6, CS:0x00D7) and the `.dax` at `0x04786`: their referrers are
  **not established**.
- **D9** indirect and jump-based callers (FF /2, FF /3, Jcc/JMP into the routines) are **not counted** by this probe.

---

## Commands and results

```sh
python tools/por_8x8d_dos_sites_probe.py --install "G:/Games/Pool of Radiance/POOLRAD" \
    -o data/work/por-8x8d-dos-sites-probe/retail          # exit 0; JSON + report written; re-run is byte-identical
python -m pytest tests/test_por_8x8d_dos_sites_probe.py -q
#   16 passed, 4 skipped (retail anchors skip without OPENUA_POR_INSTALL)
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_8x8d_dos_sites_probe.py -q
#   20 passed
OPENUA_POR_INSTALL="G:/Games/Pool of Radiance/POOLRAD" python -m pytest tests/test_por_8x8d_archive_chain_probe.py -q
#   24 passed   (regression: the shared module the new probe imports is intact)
```

---

## Side effects

- New files only: `tools/por_8x8d_dos_sites_probe.py`, `tests/test_por_8x8d_dos_sites_probe.py`,
  `docs/por-8x8d-dos-sites-probe.md`, and `data/work/por-8x8d-dos-sites-probe/` (ignored).
- No existing file was modified. Shared modules were imported read-only (`por_loadpieces_handler`,
  `por_farcall_resolve`, `por_8x8d_archive_chain_probe`, `por_convert`).
- No emulator was run (no DOSBox, no Hatari). GameLink and the codewheel were not touched. Nothing was committed or pushed.
- The retail install was read only (`START.EXE`, `GAME.OVR` and the eight 8X8D archives' TOCs). GoldBox was not opened.
- Python test runs created `__pycache__` folders (ignored).

---

## Limits

- Decode-verified prologue, byte-ret and E8 entries and linear walks only. A walk that hits an unsupported opcode is
  counted as incomplete, not as absent.
- The shared decoder raises `IndexError` (not `DecodeError`) for `mov sreg` with reg 6 or 7. A walk from an arbitrary
  offset can reach such bytes. This probe treats any such failure as a decode failure. The shared module is unchanged,
  so the fix belongs there if it is wanted.
- E8 is the only call form counted as model-free. 9A is counted only under the model. Indirect calls and jumps are not
  counted (D9), so "no callers" means no E8 and no model 9A caller only.
- The AH recovery is walk-derived: the nearest AH-writing instruction on the containing walk. It is not a dataflow
  analysis, and it does not follow a called routine's effect on AH.
- Nothing above binds a block to a PoR screen or a slot to a tile. `binding_established` is false.

---

## Next discriminating observation

Static, bounded, and still open: find the callers of `0x0A728`, `0x0A97E` and `0x0B360` through indirect calls
(FF /2, FF /3) and jump tables, which this probe does not count. Resolve the two INT 3Fh handler offsets against the
segment base that holds `0x0A728`. Decide the segment base from the far-call literals, which is the model question
D6. If those stay open, a live observation is the way to settle D3 and D4 (the `[bp+6]` string at the entry of
`0x0A89E`, and which handle reaches `0x0A9B5`). That observation is not run here.
