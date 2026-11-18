# Pool of Radiance START.EXE INT 3Fh install-site locator

**Status: STATIC-PROBE-ONLY. `playable: false`.** `tools/por_int3f_handler.py` reads the
user-supplied retail `START.EXE` and `GAME.OVR` read-only and locates the code that installs the
INT 3Fh vector. It reports the install sites, the routines that contain them, and the far-pointer
stores beside them. It does not establish the handler's code segment, so it does not decode the
handler body and does not establish the handler's stack effect. It does not give opcode `0x37` a
meaning, does not name a runtime callee, does not bind WALLDEF, and emits no module.

Follows [por-candidate-procs.md](por-candidate-procs.md), whose "next evidence" item 1 asked for this
decode, and [por-farcall-resolution.md](por-farcall-resolution.md), whose stubs are the `CD 3F`
entries that reach this handler.

---

## Pinned sources

| File | Size | SHA-256 |
| --- | ---: | --- |
| `GAME.OVR` | 206,105 | `872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614` |
| `START.EXE` | 65,231 | `d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd` |

Both matched their pins on the retail run. The tool opens both files read-only; their modification
times were unchanged across the run (2021-03-21). It refuses unpinned files unless `--allow-unpinned`
is given, and that output is marked as not retail evidence.

## Usage

```sh
python3 tools/por_int3f_handler.py --install "PATH/TO/POOLRAD" \
    -o data/work/por-int3f-handler/retail
```

Outputs: `por_int3f_handler.json` (schema `openua.por-int3f-handler` v1, `playable: false`) and
`por_int3f_handler_report.md`. Stdlib-only; it reuses the 8086 decoder in
`por_loadpieces_handler.py` and the pins and MZ base in `por_farcall_resolve.py`. Exit `0` clean,
`1` output written with a diagnostic, `2` named refusal. Output is deterministic (two runs produce
byte-identical JSON).

---

## What the bytes establish

1. **The resident image is an MZ with `cparhdr = 32` (image base file `0x200`) and `nreloc = 0`.**
   Segment literals in START are therefore image-relative (the zero-skew convention used by
   `por_farcall_resolve.py`). The entry is `CS:IP = 0xf72:0x12`.

2. **Two `mov ax,253Fh; int 21h` sites set INT 3Fh.** Both are preceded by `mov dx,imm16` whose
   chain decodes exactly to the `mov ax`, and both have `push cs; pop ds` within 64 bytes before the
   site, so DS is set to the code segment before the call.

   | Install site (file) | Image | DX handler offset | Enclosing prologue | First return after site |
   | ---: | ---: | ---: | --- | --- |
   | `0xa7ee` | `0xa5ee` | `0x2e6` | `0xa728`, 198 bytes earlier | `0xa7fc retf 4` |
   | `0xacf0` | `0xaaf0` | `0xd7` | `0xa9fc`, 756 bytes earlier | `0xad1e retf` |

3. **Install routine A (site `0xa7ee`, entry `0xa728`) is the GAME.OVR open-and-validate routine.**
   It makes DOS file calls: `mov ah,3Eh` (close, `0xa752`), `mov ax,4200h` (lseek, `0xa769`) and
   `mov ah,3Fh` (read, `0xa778`), and it tests the first bytes against `MZ`, `FB`, and `OV` (`0x5a4d`,
   `0x4246`, `0x564f`). Its far-pointer stores are:
   - `mov word [0x8504],0x268` then `mov [0x8506],cs` (`0xa7cb`): a far pointer `CS:0x268`;
   - `mov word [0x43f0],0x2e5` then `mov [0x43f2],cs` (`0xa7de`): a far pointer `CS:0x2e5`,
     stored only when `[0x43f0] | [0x43f2]` is zero (`or ax,[0x43f2]; jnz` at `0xa7d8`).
   The INT 3Fh install (`0xa7e8`–`0xa7f1`) is reached on every path, because the `jnz` lands on it.
   The routine ends at `0xa7fc` with `retf 4`.

4. **Install routine B (site `0xacf0`) is a save, install, and return block.** A loop of
   `mov ah,35h; int 21h` (get-vector, site `0xacc4`) saves vectors into a table at `0x8708`, using a
   vector-number table at `CS:0x1ee`. It then installs `00h -> CS:0xdf`, `23h -> CS:0xe6`,
   `24h -> CS:0xae` and `3Fh -> CS:0xd7`, each with DS set to CS. It stores one far pointer,
   `CS:0xa9` at `[0x4414]`. The block returns at `0xad1e` with `retf`. A separate loop at `0xadd0`
   restores the table with `mov ah,25h` and `lds dx,[di]`. The restore loop sits after an `iret`
   at `0xad4c`, so whether it is the same routine is not established.

5. **Both install routines run with a CS that the bytes do not fix.** The DX offsets are relative to
   that CS. Both offsets are small. That is consistent with a segment whose handlers sit near its
   start, but it is a guess, not a result; no base is established from the bytes (see below).

6. **No START-internal far-call literal names routine A's entry.** Under the zero-skew convention no
   `9A` literal in START targets `0xa728`, and the startup region near the entry (`0xf932` onward)
   has no far call in its first 200 instructions. So the segment of either install routine is not
   fixed by any far call found here.

## What the bytes do not establish

- **The CS value of either install routine.** Without it, the handler's file offset (`base + 0x2e6`
  or `base + 0xd7`) is not known, and so the handler body cannot be decoded. The naive segment-base
  scan (paragraph bases where the handler offsets reach `IRET` within 40 instructions) finds no base
  for `0xd7` and `0x2e6` together, and it selects none. Its passing bases for the four offsets of
  install B are not a selection either; the test cannot tell code from data.
- **The handler body and its stack effect.** Whether the handler preserves the caller's argument
  words on the INT 3Fh frame, and how it maps a stub's `proc_off` to an overlay entry, are not
  decoded here.
- **Which install is live at runtime.** Routine A installs once (guarded by the `0x43f0`/`0x43f2`
  pair), and routine B installs and then restores through a separate loop. Whether either runs
  during an overlay call, or in what order, is not shown.
- **The meaning of the stored far pointers** (`CS:0x268`, `CS:0x2e5`, `CS:0xa9`).
- **Opcode `0x37` semantics, any runtime callee, and any WALLDEF binding.** None are attempted.

## Consequence for the arity comparison

`docs/por-candidate-procs.md` compares the handler's two pushed bytes against the candidate targets'
declared argument bytes (`retf 6`, `retf 10`). That comparison is valid only if the INT 3Fh path
preserves the caller's argument words. This probe locates the INT 3Fh installs, but it does not
decode the handler, so the assumption is neither verified nor refuted here.

**The arity comparison is CONDITIONAL.** It is not shown to be invalid, since no stack-effect
evidence contradicts it. It is not valid either, because the handler's stack discipline is still
unestablished.

## Observed decoder hazard (not fixed here)

`por_loadpieces_handler.decode` raises `IndexError` (not its `DecodeError`) for an invalid
`mov sreg` encoding (`8E` with reg 6 or 7). Its `walk()` catches only `DecodeError`, so a walk
over such bytes would raise. This probe catches every decode failure, and the existing tool is
unchanged. Any new tool that walks arbitrary START bytes should expect this.

## Next evidence that would settle it

1. **A runtime read of the INT 3Fh vector.** A DOSBox-X capture of IVT entry `3Fh` (linear `0x00FC`)
   after startup gives the live handler `CS:IP` and shows which install is live. It also gives the
   real CS of the install routine, which the bytes here do not fix. This is the cheapest decisive
   step, and it was out of scope for this static pass.
2. **Decode the handler at that CS.** With the live CS, the handler's body, its stack effect on the
   INT 3Fh frame, and its treatment of `proc_off` can be decoded from the bytes.
3. **Then re-evaluate the arity comparison** in `por-candidate-procs.md`: valid, invalid, or still
   conditional. Opcode `0x37` stays open until then, and no WALLDEF binding should follow.

---

## Tests

`tests/test_por_int3f_handler.py` (12 tests on synthetic blobs, plus 1 retail test skipped without
`OPENUA_POR_INSTALL`). The synthetic tests cover the install-site and handler-offset extraction,
the DOS-call and far-pointer-store scan, the prologue-distance diagnostic, the no-site diagnostic,
the segment scan selecting no base, pin and missing-file refusal, the unpinned flag, JSON fields,
and determinism. With `OPENUA_POR_INSTALL` set, the retail test pins the install sites, handler
offsets, routine A's prologue and return, its DOS calls and far-pointer stores, the get-vector site,
`selected_base: none`, `arity_comparison: conditional`, and `playable: false`.

---

## Runtime update (2026-11-17)

A DOSBox-X debugger capture now exists. See [por-int3f-runtime-capture.md](por-int3f-runtime-capture.md). It reads
IVT `3Fh` during START's own init and places both install routines live. The live INT 3Fh vector after the install
sequence is `12C6:02E6` (routine A, file `0xA9FC`). Routine B's `131C:00D7` is overwritten by it. The
arity comparison and opcode `0x37` remain open. Nothing here establishes a runtime dispatch of ECL opcode `0x37`.
The file offsets are unique byte-window matches under the common shift `linear - file = 0x854A` (`k mod 16 = 6`),
not a proven paragraph-affine MZ image placement; see [`por-door-ds-entry-probe.md`](por-door-ds-entry-probe.md).
