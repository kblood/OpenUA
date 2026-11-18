# Pool of Radiance START.EXE INT 3Fh runtime capture (2026-11-17)

**Status: RUNTIME CAPTURE PERFORMED, START.EXE init only. `playable: false`.** A DOSBox-X debugger
session on a temporary copy of the retail install stopped inside START's own install routines and
read the live IVT entry for INT 3Fh. No keys were sent and no route was driven. Opcode `0x37`, ECL
dispatch, and WALLDEF are untouched.

Follows [por-int3f-handler.md](por-int3f-handler.md), whose "next evidence" item 1 asked for a
runtime read of IVT entry `3Fh` (linear `0x00FC`). Companion tool:
[`tools/por_int3f_runtime_capture.py`](../tools/por_int3f_runtime_capture.py) (verifies the captured
windows against the pinned file and decodes the handlers).

---

## Results

| Question | Answer | Evidence |
| --- | --- | --- |
| Was a runtime capture taken? | **Yes.** Live debugger stops and live memory reads, not static inference. | Sections below |
| IVT 3Fh before any START install | `F000:CA60` (bytes `60 CA 00 F0` at `0000:00FC`) | Read at the first INT 3Fh install stop |
| IVT 3Fh after routine B's install | `131C:00D7` (bytes `D7 00 1C 13`) | Read after `int 21h` returned, at `131C:007F` |
| IVT 3Fh after routine A's install | **`12C6:02E6`** (bytes `E6 02 C6 12`); this is the last install observed | Read after `int 21h` returned, at `12C6:00DD` |
| Which install is live | Routine **A** (`12C6:02E6`) overwrote routine B (`131C:00D7`) in the same startup | Both vector reads above |
| Does the live CS match the static guess? | Yes. Routine B's CS is `131C`, routine A's is `12C6`; both were unknown statically | Install stops; byte match below |
| Does the handler byte window match the pinned file? | Yes. Routine B's window includes file `0xAD4D` at `131C:00D7`; routine A's includes file `0xA9FC` at `12C6:02E6`. The common linear-minus-file shift is `0x854A` (`k mod 16 = 6`), not paragraph-affine. | `por_int3f_runtime_capture.py` unique byte-window matches; shift arithmetic checked in `por-door-ds-entry-probe.md` |
| Routine B's handler body at `131C:00D7` decoded | Yes (below). It is overwritten, so it is not the live handler | Live bytes match the file |
| Routine A's handler body at `12C6:02E6` decoded | Yes, prefix and exit (below). Return-address handling is **not** fully resolved | Live bytes match the file |
| State reached | START init in progress: install routines and the timer vector (`AH=25h AL=08h`) executed, and a `640 x 480` video-mode message printed. No keys, no route | Final debugger stop at `10D2:13C6` |

---

## Setup (all on a temporary copy; nothing was written to the original install or to GoldBox)

| Item | Value |
| --- | --- |
| DOSBox-X binary | `dosbox-x.exe`, **SHA-256 `3F548183DC0E937482B531CF72C024108636AF822F2C89E19E757A318CC4D509`**, DOSBox-X `v2026.07.02` x64 Release SDL2. Copied (without `.pdb`/`.lib`/`.exp`) from the GoldBox build folder into the temp copy. Matches the hash recorded in [por-runtime-capture-assessment.md](por-runtime-capture-assessment.md) |
| Debugger helper | `DosboxDebuggerInput.dll` (net9.0-windows), copied from `GoldBox/tools/dosbox_debugger_input/bin/Release/net9.0-windows`. Used read-only, sends one debugger command to an owned PID and writes the console to a file |
| Install copy | Full copy of `G:\Games\Pool of Radiance\POOLRAD` made under `%TEMP%`. Pins re-verified on the copy: `START.EXE` 65,231 bytes, `d825df2b…60b6a07bd`; `GAME.OVR` 206,105 bytes, `872964a3…7928614` |
| Original mtimes | `START.EXE` 2021-03-21 12:42:56 UTC; `GAME.OVR` 2021-03-21 12:43:04 UTC (checked before and after; see the cleanup note) |

Launch (the GoldBox DEBUGBOX shape, minus GameLink):

```text
dosbox-x.exe -conf run.conf -fastlaunch -nopromptfolder -defaultdir <scratch>
  (env SDL_VIDEODRIVER=dummy, SDL_AUDIODRIVER=dummy; window minimized; debugger console is attached)

run.conf:
[sdl]      fullscreen=false / output=surface / autolock=false
[mixer]    nosound=true
[render]   scaler=none
[cpu]      cycles=fixed 25000
[autoexec] @echo off / MOUNT C "<scratch>\game" / C: / DEBUGBOX START.EXE
```

The first debugger stop is the program entry: `CS:IP = 1796:0012`. That gives the load segment
`0x1796 - 0x0F72 = 0x0824` (the MZ entry CS is `0x0F72` in the pinned image). The same value is
confirmed by the PSP at DS `0x0814` (`0x0814 + 0x10`).

---

## Recipe (what was run)

Each step is a helper call `dotnet DosboxDebuggerInput.dll --pid <pid> --status <f> --command "<cmd>" --snapshot <txt>`
(read the snapshot with `--snapshot-only` when no command is needed). Wait about 1 s after each
command. `RUN` resumes the guest until the next breakpoint stop.

1. `DEBUGBOX START.EXE` breaks at `1796:0012`. Snapshot to confirm.
2. `BPINT 21 25`, then `RUN`. This arms a stop on every `INT 21h AH=25h` (set vector). Stops observed
   in order: `131C:0065` (`AL=00`), `131C:006D` (`AL=23`), `131C:0075` (`AL=24`), `131C:007D` (`AL=3F`, `DX=00D7`).
   Routine B's stops are four `mov ax,25xxh; int 21h` sites in a row.
3. At the `131C:007D` stop, `D 0000:00F0` and snapshot the data view: IVT `0x00FC..00FF` = `60 CA 00 F0`.
4. `BP 131C:007F`, then `RUN`. The stop at `131C:007F` (one instruction after the INT) and
   `D 0000:00F0`: IVT `0x00FC..00FF` = `D7 00 1C 13` = `131C:00D7`.
5. `RUN` continues. Other vectors are set (`AL=1B` at `1264:0093`). Routine A's stop is
   `12C6:00DB` (`mov dx,02E6; mov ax,253Fh; int 21h`, `DX=02E6`). At that stop IVT still reads `131C:00D7`.
6. `BP 12C6:00DD`, `RUN`, `D 0000:00F0`: IVT `0x00FC..00FF` = `E6 02 C6 12` = `12C6:02E6`.
7. `RUN` again. The next stops are `AH=25h AL=08h` (timer vector) at `10D2:139E` (`DX=13EA`) and `10D2:13C6`
   (`DX=FEA5`). The debugger was left stopped at `10D2:13C6`.
8. For the byte check, `D 131C:00D0` and `D 12C6:00D0` / `D 12C6:02E0` were read (128 bytes each), snapshotted,
   and passed to the verifier. The snapshots live in scratch and are not committed.

Verifier (run from OpenUA, output to scratch):

```text
python tools/por_int3f_runtime_capture.py --install <scratch>/game/START.EXE --entry-cs 1796 \
  --routine "routineB|<snap-131C-00D0>|131C|00D7|00D7" \
  --routine "routineA|<snap-12C6-00D0>|12C6|02E6|02E6" -o <scratch>/out
```

Result: both windows place uniquely. Routine B: file base `0x0AC76`, handler `0x0AD4D`. Routine A: file
base `0x0A716`, handler `0x0A9FC`. The routine A handler window (`12C6:02E0..`) also matches base `0x0A716`.

**Placement limit:** these are unique byte-window matches, not proof of a contiguous paragraph-loaded MZ image.
For both handlers, `linear_address - file_offset = 0x0854A`, whose low nibble is `0xA`; the MZ has no relocation
entries. The copied-image explanation is only a candidate. The labels below refer to matching file byte windows
under this placement relation, not to a proven global START.EXE base. See
[`por-door-ds-entry-probe.md`](por-door-ds-entry-probe.md).

---

## Byte-level evidence (live vs pinned file)

The live window at `131C:00D0..014F` matches the pinned file at `0x0AC76 + offset` (file `0x0AD46` for `00D0`) except
for two bytes. They are the immediate of `mov dx,imm16` at `131C:00ED` (file `0x0AD63`): the live value is `14A0`,
the file value is `0C7C`. The difference is `0x0824`, equal to the load segment derived from the entry stop. This is
consistent with a segment adjustment, but the mechanism that changes this literal is not established here. The
`START.EXE` MZ header has `nreloc = 0`, and the unique byte-window match does not establish a contiguous MZ-image
mapping. Do not use this one immediate as proof of a general zero-skew mapping rule.

Static site cross-check: the static tool's install site `0xacf0` (routine B, `mov ax,253Fh`) is live
`131C:007A`, and `0xa7ee` (routine A) is live `12C6:00D8`.

---

## Decoded handlers (from pinned START.EXE bytes at the live target)

Listings use the shared 8086 decoder (`tools/por_loadpieces_handler.py`). Its register names are
coarse: `r4` is SP and `r5` is BP here, so `add r4,6` is `add sp,6` and `mov r4` is `mov bp,sp`.

**Routine B handler, `131C:00D7` (byte-window match at file `0xAD4D`, under the placement limit above).** Entered by `INT 3Fh`. It is overwritten by routine A
(below) before any observed use, so it is recorded here as the handler installed at that stop.

```text
D7  mov ax,00D0          ; path marker
DA  add sp,6             ; discards the 3-word INT frame (IP, CS, FLAGS)
DD  jmp E2
DF  mov ax,00C8          ; not reached from D7 (skipped by the DD jump); another entry, not established
E2  pop cx               ; the two caller words pushed before CD 3F
E3  pop bx
E4  jmp ED
ED  mov dx,14A0 (reloc)  ; mov ds,dx; sti; mov [441C],ax
...  test cx|bx; jz file 0xAD91; otherwise a walk over ES-linked records at [43FA]
```

Stack effect on the first path: the INT frame is dropped and two caller words are popped. This handler does not
`iret`. Whether this path is taken in the live game is not established.

**Routine A handler, `12C6:02E6` (byte-window match at file `0xA9FC`, under the placement limit above). This is the live INT 3Fh vector after startup.**

```text
02E6  push bp ; mov bp,sp                   ; [bp+2]=saved IP, [bp+4]=saved CS, [bp+6]=saved FLAGS
      push ax, bx, cx, dx, si, di, ds, es   ; 8 registers saved
      mov ax,14A0 (reloc); mov ds,ax; sti   ; DS = load-relocated data segment
      les bx,[bp+2]                         ; ES:BX = interrupted return CS:IP (the byte after CD 3F)
      push word es:[bx]                     ; pushes the 16-bit word at that address
      sub word [bp+2],2                     ; saved IP -= 2
      jnz +5 ; call 0AA4E (near) ; jmp 0AA36
      (jnz path: add bp,6; xchg [bp-6] with [bp+0]; call 0AA4E; ...)
0AA36 pop bx ; mov ax,es:[0012h] ; cmp ax,1 ; sbb ax,ax ; callf [43F0h] (indirect far call)
0AA44 pop es, ds, di, si, dx, cx, bx, ax, bp
0AA4D iret
```

What this shows: the handler reads the word that follows the interrupted `CD 3F`. That is consistent with the
notes' "stub `CD 3F` entries", where a word follows each INT. It then rewrites the saved IP and makes a far call
through `[43F0h]`. The static note's far pointer `CS:0x2E5` is the value that `callf` uses in routine A's
setup. This is not confirmed at runtime.

---

## What is still open

1. **Routine A's return path.** The saved IP is decremented by 2 before the exit. Whether `iret` returns to the byte
   after the inline word, or to `CD 3F` itself, depends on the paths at `0AA19` and `0AA2A`, which are not
   fully decoded. The `xchg [bp-6]` / `mov [bp+0]` pair at `0AA21..0AA33` also rewrites saved state.
2. **The `callf [43F0h]` target.** Its runtime value was not read. The static note's `CS:0x2E5` is a guess until the
   far pointer is read at runtime.
3. **The inline word.** Its value at each `CD 3F` stub was not read, so the proc-offset mapping is still open.
4. **Whether INT 3Fh is re-installed after `10D2:13C6`.** The run stopped there. Later installs were not checked.
5. **Arity comparison.** [por-candidate-procs.md](por-candidate-procs.md) assumed two pushed words, consumed by the
   handler. The live routine A path reads an inline word and does not consume two caller words on this path, so the
   assumption is **not** shown by this capture. It stays conditional, now against routine A's path.
6. **`Packed file is corrupt` warning.** DOSBox-X printed `INT 21h WRITE warning: Detected 'Packed file is corrupt'`
   early in START's init, before the first `INT 21h AH=25h` stop. Startup went on to install vectors and set a
   `640 x 480` mode. The message may be a real START error path, or a DOSBox-X detector artefact. Not investigated.
   A `LOADFIX` variant (the GoldBox probe option) was **not** tried.

---

## Cleanup

- The DOSBox-X process (PID 39348) was stopped after the last snapshot.
- The temporary scratch folder (copy of the install, DOSBox-X copy, helper copy, snapshots, verifier output) was deleted.
- Original `GAME.OVR` and `START.EXE`: hashes and mtimes re-checked after cleanup (see the session report).
- GoldBox: no writes. Only read access to `GoldBox/build/...dosbox-x.exe` (copied) and `GoldBox/tools/dosbox_debugger_input` (copied).

---

## Tests

`tests/test_por_int3f_runtime_capture.py`: parser, IVT decode, relocation-tolerant placement (unique, and
rejects an unexplained byte), pin refusal, decode flow, and a retail test that checks the static sites this run
matched (`0xACED`, `0xAD4D`, `0xA9FC`). The retail test runs only when `OPENUA_POR_INSTALL` is set.
Run with `python -m pytest tests/test_por_int3f_runtime_capture.py tests/test_por_int3f_handler.py`.

---

## Follow-up (2026-11-17): live handler entry and callf target

[por-int3f-live-dispatch.md](por-int3f-live-dispatch.md) answers open items 2 and 3 of this document for the
START init window. Routine A is entered by the real INT 3Fh vector at `12C6:02E6`, its inline proc word is
`02AD` at the `CD 3F` caller `0C4C:0020`, and its `callf [43F0h]` (`12C6:032A`) reads `12C6:02E5`, a bare `retf`.
No overlay dispatch and no opcode `0x37` dispatch was observed. Verifier: `tools/por_int3f_live_probe.py`.
