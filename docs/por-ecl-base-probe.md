# Pool of Radiance ECL base probe: the fetch arithmetic is pinned; the buffer origin is not

**Status: static probe. `playable: false`. No base promoted.** Tool:
`tools/por_ecl_base_probe.py`. Tests: `tests/test_por_ecl_base_probe.py`. Source:
the local GOG DOS install, `GAME.OVR` (pinned, 206,105 bytes, SHA-256
`872964a3...28614`). Read-only; outputs go under `data/work/` and are not committed.

This note asks whether PoR's own retail code fixes the mapping from an ECL virtual
address (vaddr) to a raw decoded DAX block offset, as `tools/por_ecl.py --vbase` needs.
The decoder's default stays unresolved. The candidate `0x98FE` stays a hypothesis.

---

## Verdict

- **Established (PoR code, static):** the VM's opcode fetch for vaddr `v` reads
  `ES:[X + 0x6700 + v]` (16-bit, wraps mod 65536), where `X` is the offset stored in
  `[0x49DE]`. The vaddr is the dispatcher's argument, stored unchanged in `[0x49ED]`.
  So the `0x6700` addend is PoR's, and no `+2` appears in the fetch.
- **Established (arithmetic only):** if decoded block byte 0 sits at `X + s`, then
  block offset `b = (v - vbase) mod 65536` with `vbase = (s - 0x6700) mod 65536`.
  `s = 0` gives `0x9900`. `s = -2` gives `0x98FE`. CoK's `0x7FFE` would need `s = -6402`,
  which is not a two-byte prefix.
- **Not established:** the origin shift `s`. No PoR code reached here shows whether the
  DAX member decoder writes block byte 0 at `X` (so `vbase = 0x9900`) or two bytes before
  it (so `vbase = 0x98FE`). The code that writes the decoded DAX block was not located.
- **Far call at `0x0E637..0x0E643`:** the caller loads `AX = 0x1E00`, pushes it, far-calls
  `0x0AF8:0x023F`, and stores the returned `AX:DX` to `[0x49DE]:[0x49E0]`. That is all
  the static evidence shows. There is no evidence that the far target allocates a buffer,
  and its behaviour and the origin of its returned `DX:AX` are **not established**.
- **Therefore `0x98FE` is not promoted.** The header-pointer check below discriminates
  between `s = 0` and `s = -2`, but it is pointer-start correlation, which cannot establish
  the origin.
- **Wrap:** the PoR address form is 16-bit, so `(v - vbase) & 0xffff` is the correct
  arithmetic. For the blocks in this tree (under 7680 bytes), wrapping cannot make an
  out-of-block target in-block: a backward target wraps to at least `0x6702` (26370),
  beyond the 7679-byte block 20. So the current `idx < 0 or idx >= block_len` check
  gives the same resolution either way. The wrap matters for the reported number only.

---

## The byte chain (GAME.OVR file offsets, all matched)

| Offset | Bytes | Instruction | Reached from parser seeds |
|---|---|---|---|
| `0x03EBA` | `8b 46 06` | `mov ax,[bp+6]` (the argument) | yes |
| `0x03EBD` | `a3 ed 49` | `mov [0x49ed],ax` (stream index `[0x49ED]` = vaddr) | yes |
| `0x03ED9` | `a1 ed 49` | `mov ax,[0x49ed]` | yes |
| `0x03EDC` | `c4 3e de 49` | `les di,[0x49de]` (far pointer `X`) | yes |
| `0x03EE0` | `03 f8` | `add di,ax` | yes |
| `0x03EE2` | `26 8a 85 00 67` | `mov al,es:[di+0x6700]` (opcode fetch) | yes |
| `0x0E637` | `b8 00 1e` | `mov ax,0x1e00` (AX loaded for the far call) | no |
| `0x0E63A` | `50` | `push ax` (the `0x1E00` is pushed as an argument) | no |
| `0x0E63B` | `9a 3f 02 f8 0a` | `call 0x0af8:0x023f` (far target not decodable here) | no |
| `0x0E640` | `a3 de 49` | `mov [0x49de],ax` (offset of `X`, from the returned `AX`) | no |
| `0x0E643` | `89 16 e0 49` | `mov [0x49e0],dx` (segment, from the returned `DX`) | no |
| `0x076C8`, `0x0E993` | `c7 06 ed 49 00 99` | `mov [0x49ed],0x9900` (literal; meaning not established) | no |

The fetch chain is reached from the parser seeds of `por_ecl_length_xref.py`. The
far call and the literal stores are not in that closure. The writes to `[0x49DE]` in
GAME.OVR are only at `0x0E640`. The far target `0x0AF8:0x023F` is a relocated segment, and its module is not identified.
Its bytes are not in GAME.OVR. At `START.EXE` image offset `0x023F` there is overlay-table
data, not a matching routine; that check is the only one made. So what it does with the
pushed `AX = 0x1E00`, and the origin of the `DX:AX` it returns, are **not established**.
Nothing here shows that it allocates a buffer. The caller of `0x0E600`
has no direct near or far call in the GAME.OVR bytes, so the routine is reached
indirectly and was not traced.

The falsifier: NOP-ing `0x03EBD..0x03EBF` (the store to `[0x49ED]`) makes the `ip-store`
check fail. The check detects the mutation.

---

## Header-pointer check (structural, not proof)

Block 20 of `ECL2.DAX` (the decoder's anchor block). Header vaddrs
`0x9914, 0x9975, 0x9A0E, 0x9A49, 0x9A5E`. Under the decoder's header convention, the body
starts at byte 22.

| Origin `s` | vbase | Slot 0 (`0x9914`) | Slots 1-4 | Starts |
|---|---|---|---|---|
| `0` (buffer start) | `0x9900` | offset 20, inside header | 117, 270, 329, 350 (mid-instruction) | 0 of 5 |
| `-2` (prefix) | `0x98FE` | offset 22, instruction start | 119, 272, 331, 352 (all instruction starts) | 5 of 5 |
| `+2` (control) | `0x9902` | offset 18, inside header | 115, 268, 327, 348 (mid-instruction) | 0 of 5 |

This discriminates the two origins by pointer starts. It is the kind of static
best-fit the decoder doc already calls diagnostic. It also assumes the header pointers
are instruction entries, which is not traced. So it does not establish the origin.

---

## Greybox and cross-title claims, labelled

- **GoldBox `pool-natural-encounter-route.md` (Greybox, reverse port):**
  - "Addend `0x6700`": **confirmed here** as PoR's fetch addend (the byte chain above).
  - "`file_offset = ((vaddr+0x6700)&0xffff)+2`": this equals `(v - 0x98FE) mod 65536`,
    which is the `-2` origin. **Not confirmed**: the `+2` comes from the "two-byte prefix"
    claim below.
  - "Retail DAX member decoding removes a two-byte prefix": **not confirmed for PoR**. The
    DAX member loader was not located in GAME.OVR. The GoldBox note is a Greybox claim, not
    evidence that the original DOS game executed that route.
- **CoK rule (`vbase 0x7FFE`):** title-specific. It needs `s = -6402` here, so it does not
  fit PoR's address form. Not used as PoR evidence.
- **"Two-byte prefix" in CoK docs:** in `cok-item-format.md` it describes the standalone
  `ITEMS` file, a different file in a different title. It is not PoR evidence.

---

## What would settle the origin (next evidence, static)

1. **Find the DAX member reader.** Trace the far target `0x0AF8:0x023F` and the routine
   that calls `0x0E600`. Show whether the decompressed member is written to `X` or to
   `X-2`, and whether it skips two source bytes. Any code that does this is the only PoR
   code that can settle `s`. (`docs/por-int3f-handler.md` discusses an INT 3Fh handler;
   it is not confirmed to be this target.)
2. **Find what the far call does with `AX = 0x1E00`.** Establish whether the target
   allocates, reads, or does something else with the pushed value, and what `DX:AX` it
   returns. Until this is known, the origin of the `[0x49DE]:[0x49E0]` pointer is
   unresolved.
3. **Meaning of the literal `0x9900`** (`0x076C8`, `0x0E993`). Under any origin, it fetches
   `X + 0`. Determine whether it is a block entry or a placeholder.

Until 1 is closed, any vbase is an assumption about the origin, and the decoder stays
unresolved by default.

---

## Reproduce

```sh
python -I tools/por_ecl_base_probe.py --install "PATH/TO/POOLRAD" \
    --dax "PATH/TO/POOLRAD/ECL2.DAX" -o data/work/por-ecl-base-probe/retail
tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_base_probe.py -q
OPENUA_POR_INSTALL="PATH/TO/POOLRAD" OPENUA_POR_ECL_DAX="PATH/TO/POOLRAD/ECL2.DAX" \
    tools/.venv/Scripts/python.exe -m pytest tests/test_por_ecl_base_probe.py -q
```

Exit codes: 0 all byte checks match; 1 outputs written but a byte check failed; 2 named
refusal (missing or unpinned `GAME.OVR`, output inside the install).

Last run (2026-11-17): without the env vars, `12 passed, 3 skipped`. The three skips are
the retail tests, which need `OPENUA_POR_INSTALL`. The `0x0E63A` push byte (`50`) is
checked only by those retail tests (and by the probe on a real install); it has not been
checked against retail bytes in this run.

---

## Not claimed

- No base promoted. `base_promoted` is `false` in the output. The decoder now has an
  opt-in `--por-vbase` mode for `0x98FE`, explicitly labelled CONDITIONAL and
  `promoted: false`; its default remains unresolved. See
  [`por-ecl-decoder.md`](por-ecl-decoder.md) section 6.
- No FRUA event mapping, no route reachability, no runtime claim. The fetch arithmetic is
  static code evidence only.
- No claim that the DOS game executed the GoldBox route.
- No claim that `0x9900` is an ECL entry.
