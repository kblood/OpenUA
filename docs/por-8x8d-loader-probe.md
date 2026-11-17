# Pool of Radiance: 0x7180 chain, callers and arguments vs 8X8D (static)

**Status: STATIC-PROBE-ONLY. `playable: false`. `mappings: []`. `binding_established: false`.**
**Answer: not-established.** No decoded caller on the START.EXE chain that starts at `0x7180`
passes an 8X8D block or tile index, and no routine on that chain reads an 8X8D archive. Both
statements are limited to the decoded bytes; the far callees are unresolved (see below).

`tools/por_8x8d_loader_probe.py` reads the pinned retail `START.EXE` and `GAME.OVR` read-only.
It decodes the chain with the repo's 16-bit decoder (`tools/por_loadpieces_handler.py`), finds
every caller it can, and simulates each call's straight-line argument pushes. It does not open
any 8X8D archive.

Related: [por-wall-render-probe.md](por-wall-render-probe.md) (the layout owner `0x7180` of the
literal `8X8d1`, and the WALLDEF owner), [por-8x8d-blocks.md](por-8x8d-blocks.md) (the 8X8D format
rule), [por-area-evidence.md](por-area-evidence.md) (the literal's layout owner, as a candidate),
[por-farcall-resolution.md](por-farcall-resolution.md) (the far-call resolver used here, read-only).

---

## Question and reading

Question: does any caller on the chain select a block or tile of a PoR 8X8D DAX archive?

The chain is `0x7180` (the layout-unique owner of the Pascal literal `8X8d1` at `0x723A`, a
layout candidate and not a reference), its four near callers, and the routines above them and
beside them. The question is answered for the decoded bytes only.

Evidence labels used below:

- **decoded**: the instruction decodes, and lies on a ret-stopped linear walk from a prologue.
- **byte-pattern**: the bytes match but the site is not on a decoded walk. Listed as a candidate, never counted as a caller.
- **shape-based**: the callee is unresolved, and its role is inferred from the caller's argument shape alone.
- **model**: the result depends on the stated START image model (file = image base `0x200` + `seg*16 + off`, the model `por_farcall_resolve` uses).

---

## Usage

```sh
# user-supplied install, read-only; output under data/ (git-ignored)
python tools/por_8x8d_loader_probe.py --install "PATH/TO/POOLRAD" \
    -o data/work/por-8x8d-loader-probe/retail

# focused tests; the retail anchor runs only when the variable names the install
python -m pytest tests/test_por_8x8d_loader_probe.py -q
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" python -m pytest tests/test_por_8x8d_loader_probe.py -q
```

Exit codes: `0` every pin matched and the scan completed; `1` output written with a diagnostic
(a pin did not match, under `--allow-unpinned`); `2` named refusal (missing install, unpinned
file without the flag, or an output folder inside the install).

Outputs in `OUT`: `por_8x8d_loader_probe.json` (schema `openua.por-8x8d-loader-probe`, version 1)
and `por_8x8d_loader_probe_report.md`. Both are deterministic: sorted keys, no timestamps, no
absolute paths.

---

## Pinned sources

Both files matched their pins before and after the run (`source_unchanged: true`).

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |

The 8X8D archives are not opened by this probe. Nothing here depends on their contents.

---

## What the bytes establish (decoded)

### 1. The chain routines and what each one does

Roles are inferred from the decoded bytes. They are labels, not established names.

| entry | role (inferred) | decoded facts |
| --- | --- | --- |
| `0x7180` | rectangle fill on an EGA screen page (owner of the literal) | Frame `[bp+6]..[bp+16]`, `retf 12`. Byte columns `P1..P3` (`[bp+16]`, `[bp+12]`), cell rows `P2..P4` (`[bp+14]`, `[bp+10]`). Each cell row is 8 scanlines (`shl ax,3`), each scanline is 40 bytes (`add [bp-3],0x28`). Page `P5` (`[bp+8]`) selects the write segment through `0x7169`. Colour `P6` (`[bp+6]`) is the byte pushed before a far call at `0x7209`. |
| `0x7169` | EGA page select | `retf 2`. Sets `[0x4A18] = 0xA000 + (arg << 9)`, that is a page 8 KB apart. |
| `0x70C9` | EGA sequencer and graphics controller reset | Writes Graphics Controller indices 0 to 5, 7 and 8 (index 6 is not written), and Sequencer index 2 (`0x0F`, all planes). Ports `0x3CE`, `0x3CF`, `0x3C4`, `0x3C5`. |
| `0x7D74` | video-mode dispatch: clear the screen | Dispatches on `[0x4A1E]`. In mode 1 it calls `0x7180` twice with cells `(0,0)..(39,24)` (40 bytes wide, 200 scanlines: a full 320 by 200 plane), page 0 then page 1, colour 0. Mode 0 fills `B800` and `BA00` with `0x1F40` bytes each; mode 2 fills `B800`, `BA00`, `BC00` and `BE00` the same way. |
| `0x7E9C` | rectangle erase: 4 word arguments | Dispatches on `[0x4A1E]`. Mode 1 calls `0x7180` twice with its four arguments forwarded, page 0 then page 1, colour 0. Mode 0 walks `B800`/`BA00` rows. |
| `0x7831` | text window: far Pascal string and a rectangle | `retf 16`. `les di,[bp+6]` loads a far pointer to a Pascal string. The flag is `[bp+10]`, and it clears the rectangle through `0x7E9C` when non-zero. The rectangle is `[bp+14]`, `[bp+16]`, `[bp+18]`, `[bp+20]`. The string is copied into a 255-byte local (`[bp-256]` is its length) and drawn character by character through far helpers. |

The layout owner's body (`0x7180`) has no pixel-source operand. Its only memory operands are
the globals `[0x4A1A]` (saved in and restored from a stack local) and `[0x4A18]` (the write
segment), plus the EGA ports. It has no far pointer from its frame, no register-indexed read
and no string read.

The far fill target `0x0AF8:0x16A8` is called with four pushed values (segment, offset, count,
colour). The shape is a byte fill, **shape-based**: its body is not resolved here.

### 2. The four near callers of `0x7180`

All four are `push cs ; call near`, the same-segment far-return idiom (**decoded**). Each one's
pushed word count times 2 equals the callee's `retf` width (6 words, 12 bytes), so the
arguments line up with the callee's frame at every site.

| call site | in routine | page `P5` | `P1..P4` (cols, rows) | verdict | what the pushes are |
| --- | --- | --- | --- | --- | --- |
| `0x7DC0` | `0x7D74` (mode 1) | `0x0` | `0x0, 0x0, 0x27, 0x18` | constants | Full-screen clear, page 0, colour 0 |
| `0x7DD6` | `0x7D74` (mode 1) | `0x1` | `0x0, 0x0, 0x27, 0x18` | constants | Full-screen clear, page 1, colour 0 |
| `0x7F57` | `0x7E9C` (mode 1) | `0x0` | forwarded `[bp+12], [bp+10], [bp+8], [bp+6]` | forwards | Page 0, colour 0 |
| `0x7F71` | `0x7E9C` (mode 1) | `0x1` | forwarded `[bp+12], [bp+10], [bp+8], [bp+6]` | forwards | Page 1, colour 0 |

Colour `P6` is the constant `0` at all four sites. No site passes a block or tile index, and no
site passes a value read from memory.

The forwarded words of `0x7E9C` come from its own caller `0x7831`, through the two sites below.

### 3. Callers of the other chain routines

| target | decoded callers | byte-pattern candidates | conclusion |
| --- | --- | --- | --- |
| `0x7169` | `0x71C5` (forwards `[bp+8]`, the page), `0x7231` (restores the saved `[0x4A1A]`, a global-state argument) | 0 | Both are inside `0x7180` |
| `0x70C9` | `0x71C9` (no arguments) | 0 | Inside `0x7180` |
| `0x7E9C` | `0x78AA`, `0x7A78` (both forward `[bp+20], [bp+18], [bp+16], [bp+14]` of `0x7831`) | 0 | Both are inside `0x7831` |
| `0x7831` | none | 0 | No decoded or byte-pattern caller; the word-table hit at `0x08AB` is a VROOMM descriptor field (below) |
| `0x7D74` | none | 0 | No decoded or byte-pattern caller |

Checked for `0x7D74` and `0x7831`: near `E8` sites (none), far `9A` sites under both the image
model and the zero-base model (none), VROOMM stub words `CD 3F <word> 00` (none), and 16-bit word
tables at any alignment (none that is a call target).

The one word-table hit for `0x7831` is at `START.EXE 0x08AB`. The bytes before it are
`CD 3F 00 00`, the VROOMM descriptor magic, so the word is the low half of a `fileofs` field
(`0x00017831`) and not a code pointer. It is recorded as noise.

### 4. The argument sources, by simulation

For each call site, the straight-line instructions before it are simulated forward. The window
stops at any control transfer and at the routine's frame setup (`push bp; mov bp,sp`). A register
the model does not track becomes unknown, so an unmodelled write can only make a source less
specific.

Classes, from most to least specific:

| class | meaning | effect on the verdict |
| --- | --- | --- |
| `const` | immediate | none |
| `local-address`, `frame-local` | `lea`/`[bp-d]` | none |
| `global-restore` | a fixed address written earlier in the same walk (save/restore) | `global-state-argument` |
| `global-read` | a fixed address with no earlier store | `global-state-argument` |
| `frame-forward` | the caller's own `[bp+d]`, `d >= 6` | `forwards-caller-frame`, followed upward |
| `indexed-memory` | a register-indexed read (`[bx+si]`, `[si]`, `[bp+di-d]`) | `index-like-argument` (the only class that is index evidence) |
| `unknown` | anything else, including a value that an `inc` or `add` has erased | `unclassified-argument` |

Verdicts across the nine decoded sites on the retail chain: 0 `index-like-argument`, 0
`unclassified-argument`, 1 `global-state-argument` (`0x7231`, a restore of `[0x4A1A]`), 5
`forwards-caller-frame` (`0x71C5`; `0x7F57` and `0x7F71`; `0x78AA` and `0x7A78`), and 3
`constants-and-locals-only` (`0x71C9`; `0x7DC0` and `0x7DD6`).

### 5. The upward chain for forwarded words

`0x7180` ← `0x7F57` / `0x7F71` in `0x7E9C` ← `0x78AA` / `0x7A78` in `0x7831` ← **no decoded
caller**. The terminal entry is `0x7831`, and above it nothing is found. The rectangle words
therefore have no established origin.

### 6. The owner's colour and the far fill

The window before the far call at `0x7209` holds five pushes, in order: `[0x4A18]` (the write
segment, a global read), `ES`, `DI` (`[bp-3]`, a local), the count (unknown: it is computed with
`sub` and `inc`), and the colour. The colour is the low byte `[bp+6]`, with the high byte not
established (the `inc ax` at `0x7203` erases it). This is `P6`. The callee's arity is not
established, so these are reported as pushes and not as named parameters.

### 7. The video-mode byte and its selector

| address | decoded fact |
| --- | --- |
| `0x447D`, `0x4480` | `mov al,[0x484C]`; `cmp al,0x45` (`'E'`) |
| `0x4484` | `mov [0x4A1E],1` when `'E'` |
| `0x44AF`, `0x44B3` | `cmp al,0x54` (`'T'`); `mov [0x4A1E],2` when `'T'` |
| `0x44E2` | `mov [0x4A1E],0` otherwise |

So the mode-1 arm, which is the only arm that reaches `0x7180`, is taken when the selector byte
`[0x484C]` is `'E'`. Where the selector is written (`0x43F4`, `0x4457`, `0x45A5`, `0x4650`) is
not established here. Its origin (a file, the keyboard or the installer) is open.

### 8. The literal `8X8d1` and its offset

Neither file has a decoded reference to the offset `0x723A`. There is no `mov r16,imm16` with
that value and no direct address that matches, in START.EXE or in GAME.OVR. The layout owner
`0x7180` does not reference it. The push-cs pointer forms were already checked by
`por_wall_render_probe` and give no hit. So the literal's referrer is not found, and the layout
adjacency is the only link.

---

## Far callees (existing resolver, read-only)

Every far literal in the chain goes to a `0x0AF8:xxxx` or `0x0899:xxxx` target (or `0x0A40`).
Under the START image model, `por_farcall_resolve` classifies all of them as `not-a-stub`. For
example the target of the fill call, file `0xC828`, holds `00 0A 07 04 01 01 00 00`: neither a
prologue nor a stub. Their identity is **not established**.
Under the load-segment model in [por-ecl-fixup-probe.md](por-ecl-fixup-probe.md) (conditional), a
segment word such as `0x0AF8` is a link-time value that the loader rebases, so these targets may
be overlay-loaded code and not START bytes. This probe does not resolve that model.

Consequence: the statements "no file I/O" and "no pixel source" are limited to the decoded bodies
of `0x7180`, `0x70C9`, `0x7169`, `0x7D74`, `0x7E9C` and `0x7831`, and to their near callees
(`0x7770`, `0x77DD`, `0x7CBE`), which contain no `INT` instruction. The far callees are not
inspected.

---

## Falsifiers in the tests

`tests/test_por_8x8d_loader_probe.py` (44 tests, 43 synthetic plus one retail anchor) contains
the checks that would change the answer:

- an `E8` byte inside an immediate is not a caller (decode-boundary falsifier);
- a window does not carry a push across a call (control-transfer barrier);
- a fixed global read is not a restore unless it follows a store in the same walk;
- a register-indexed argument flips the verdict to `index-like-argument`;
- an `inc` or `add` on the pushed register erases the forwarded frame word;
- a frame-width mismatch between the pushes and the callee's `retf` is reported;
- a far literal matches only under the stated segment model, and a zero-base match is a candidate;
- the retail anchor pins the four callers, their arguments, the two `0x7E9C` callers, the absent callers of `0x7831` and `0x7D74`, the zero literal references, the three mode writes, and the descriptor word-table hit.

---

## What the bytes do not establish

- Who calls `0x7831` and `0x7D74`. Neither has a decoded or byte-pattern caller. Indirect calls
  (`FF /2`, `FF /3`) through a pointer in memory are not traced beyond the table search.
- The bodies of the far callees `0x0AF8:0x16A8` (fill, shape-based), `0x0AF8:0x0B25` (string copy,
  shape-based), `0x0AF8:0x0D12` and `0x0AF8:0x0DC0` (glyph and width, shape-based), `0x0AF8:0x0B0B`,
  and `0x0899:0x0104`.
- Who reads the literal `8X8d1`. No referrer of offset `0x723A` exists in the decoded bytes.
- Which 8X8D block, tile, bank or palette any caller selects. No caller passes one.
- The origin of the selector byte `[0x484C]` and of the rectangle words above `0x7831`.
- The bounds in `0x7831`'s entry checks: `[bp+18]` is compared with `0x18` (24), but `[bp+14]`, which the callee uses as a row end, is compared with `0x27` (39). This probe records both compares and does not reconcile them.
- Any screen equivalence with the DOS game, the palette, or the transparency rule.

---

## Reusable method (this repo, not an external source)

The method is the one `tools/por_8x8d_loader_probe.py` uses: a prologue-anchored, ret-stopped
linear decode; a site counted as a caller only if it lies on such a walk; and a bounded
straight-line simulation of the pushes before each call, with unknown as the default. It is this
repo's own technique. No GoldBox file was read or used for this probe, and no claim here rests on
the CoK, DoK or Amiga notes in that reference repository.

---

## Next evidence that would settle it

1. Resolve the far callees. Decode the overlay group that holds `0x0AF8:0x16A8`, `0x0AF8:0x0B25`
   and `0x0AF8:0x0D12` under the load-segment model in [por-ecl-fixup-probe.md](por-ecl-fixup-probe.md),
   then check each body for a file call or a pixel-source read. Until then the "no file read" result
   is limited to the decoded chain.
2. Find the caller of `0x7831`. Either a far literal from overlay code with its segment resolved, or a
   runtime breakpoint on entry to `0x7831`. The second needs an emulator and was not done here.
3. Find the referrer of the literal `8X8d1` (or the `8x8d` piece without a digit at `GAME.OVR:0x32255`,
   see [por-wall-render-probe.md](por-wall-render-probe.md)). The layout owner `0x7180` is ruled out as
   a consumer of tile bytes by its body, so the search should start elsewhere.
4. Find the writers of the selector `[0x484C]` at `0x43F4`, `0x4457`, `0x45A5` and `0x4650`.

## Not claimed

- No DOSBox, Hatari, GameLink, codewheel or emulator step. Retail files were read only.
- No GoldBox file was read or written. The DOS CoK 8X8D note and the Amiga Pool graphics notes were not used as PoR evidence.
- No mapping, preview, module or event output. `mappings` is empty and `events_emitted` is 0.
- No 8X8D archive was opened.
