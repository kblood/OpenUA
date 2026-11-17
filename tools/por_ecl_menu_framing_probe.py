#!/usr/bin/env python3
"""Pool of Radiance: ECL menu-operand framing probe (0x15 VERTICAL_MENU, 0x2B HORIZONTAL_MENU).

STATIC-PROBE-ONLY. ``playable: false``. Reads the pinned retail ``GAME.OVR`` and ``START.EXE``
read-only and reports four byte-level facts:

1. ``classify``: the concrete arm the ECL opcode classifier at GAME.OVR:0x9379 takes for each
   opcode. The classifier is a ``cmp al,imm`` / ``jcc`` chain; the interpreter follows it for one
   value at a time and reports which arm runs: ``push-cs-call`` (operand parser ``0x74D3``, with
   the class byte it pushed), ``inc-only`` (the default arm, ``inc [0x49ED]``: one byte, zero
   parsed operands), or a named refusal. It does not assume the table; it reads the bytes.
2. ``stubs``: the START.EXE overlay stub run of the group whose header is at START.EXE:0x45B
   (fileofs 0x74D3). Each far call with segment ``0x2B`` lands on stub ``index`` of that run, and
   the stub's ``proc_off``. The GAME.OVR target under the zero-skew model is ``fileofs + proc_off``.
   This is a model, not a resolution: the probe reports the arity facts beside it.
3. ``handlers``: every far call in the 0x15 handler (``0x1C4E``) and the 0x2B handler (``0x1E17``)
   reached by a linear sweep, with the two instructions before it (the pushed literals).
4. ``dispatch``: the case-to-handler map from ``por_loadpieces_handler.dispatch_cases`` for 0x15 and
   0x2B, so the handler entries are cross-checked by the bytes.

It does not decide the menu framing, does not give any target a meaning, and does not bind a module.

Companions: docs/por-ecl-menu-framing-probe.md (findings), docs/por-candidate-procs.md,
docs/por-farcall-resolution.md, docs/por-ecl-opcode2d-probe.md.

Usage::

    python tools/por_ecl_menu_framing_probe.py --install "PATH/TO/POOLRAD" -o data/work/por-ecl-menu-framing/retail

Exit: 0 clean, 1 a structural check failed, 2 a named refusal (missing or unpinned file, output inside install).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import por_loadpieces_handler as h  # noqa: E402  (read-only decoder + dispatch reader)

SCHEMA = "openua.por-ecl-menu-framing-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_ecl_menu_framing_probe.py"

PINS = {
    "GAME.OVR": (206105, "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"),
    "START.EXE": (65231, "d825df2b174675c9088ba1489488bdeebe66ad2a22943f17d3a198e60b6a07bd"),
}

CLASSIFIER_ENTRY = 0x9390        # first cmp al,imm after the key store at 0x938A/0x938D
PARSER = 0x74D3                  # operand parser (retf 2, reads one byte at [bp+6])
DEFAULT_STREAM_CELL = 0x49ED     # inc [0x49ED] in the default arm
HEADER_START = 0x45B             # START.EXE group header for fileofs 0x74D3
HEADER_FILEOFS = 0x74D3
HEADER_RUN = 0x471               # first stub of that header's run
HANDLER_15 = 0x1C4E
HANDLER_2B = 0x1E17
HANDLER_SPAN = 0x200
SEG_2B = 0x002B
DISPATCH_CASES = (0x15, 0x2B)
CLASSIFIER_CASES = (0x15, 0x2B, 0x2D, 0x27, 0x29, 0x37)
MAX_STEPS = 400


class ProbeRefusal(Exception):
    """A named refusal: the probe does not run on this input."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _s8(b: int) -> int:
    return b - 256 if b >= 128 else b


def _s16(lo: int, hi: int) -> int:
    v = lo | (hi << 8)
    return v - 65536 if v >= 32768 else v


def classify(data: bytes, value: int, entry: int = CLASSIFIER_ENTRY,
             call_target: int = PARSER) -> dict:
    """Follow the 0x9379 compare chain for one opcode value and report the arm it takes.

    Modelled instructions: ``cmp al,imm8``, short ``jcc``/``jmp``, ``mov al,imm8``,
    ``push ax``, ``push cs``, near ``call``, near ``jmp``, ``inc [m16]`` (only the default-arm
    form), ``pop bp``/``retf``. Anything else is a named refusal. The flags are the unsigned
    ``al - imm`` (carry and zero), as the ``jb``/``jbe``/``ja``/``jz``/``jnz`` tests need.
    """
    al = value & 0xFF
    cf = zf = False
    pushes: list[int] = []
    pc = entry
    for _ in range(MAX_STEPS):
        if pc < 0 or pc + 1 >= len(data):
            return {"arm": "refusal", "reason": "pc-out-of-range", "at": pc}
        b = data[pc]
        if b == 0x3C:                                   # cmp al, imm8
            imm = data[pc + 1]
            cf = al < imm
            zf = al == imm
            pc += 2
        elif b in (0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0xEB):   # short jcc / jmp
            rel = _s8(data[pc + 1])
            taken = {
                0x72: cf, 0x73: not cf, 0x74: zf, 0x75: not zf,
                0x76: cf or zf, 0x77: (not cf) and (not zf), 0xEB: True,
            }[b]
            pc = pc + 2 + (rel if taken else 0)
        elif b == 0xB0:                                 # mov al, imm8
            al = data[pc + 1]
            pc += 2
        elif b == 0x50:                                 # push ax (AL is the class byte)
            pushes.append(al)
            pc += 1
        elif b == 0x0E:                                 # push cs
            pc += 1
        elif b == 0xE8:                                 # near call
            target = pc + 3 + _s16(data[pc + 1], data[pc + 2])
            if target == call_target:
                return {"arm": "push-cs-call", "class": pushes[-1] if pushes else None,
                        "call": target, "at": pc}
            return {"arm": "other-call", "call": target, "at": pc}
        elif b == 0xE9:                                 # near jmp
            pc = pc + 3 + _s16(data[pc + 1], data[pc + 2])
        elif data[pc:pc + 2] == b"\xFF\x06":           # inc [m16] (default arm: inc [0x49ED])
            disp = data[pc + 2] | (data[pc + 3] << 8)
            return {"arm": "inc-only", "inc": disp, "at": pc,
                    "inc_is_stream_cell": disp == DEFAULT_STREAM_CELL,
                    "operands_parsed": 0}
        elif b in (0x5D, 0xCB):                         # pop bp / retf: join, no operand arm
            return {"arm": "exit-no-advance", "at": pc}
        else:
            return {"arm": "refusal", "reason": "unmodelled-byte", "at": pc, "byte": b}
    return {"arm": "refusal", "reason": "step-limit", "at": pc}


def stub_at(start: bytes, addr: int) -> Optional[tuple]:
    """Return (proc_off, trailer) if START.EXE has a ``CD 3F`` stub at ``addr``, else None."""
    if addr < 0 or addr + 5 > len(start):
        return None
    if start[addr] != 0xCD or start[addr + 1] != 0x3F:
        return None
    return struct.unpack("<H", start[addr + 2:addr + 4])[0], start[addr + 4]


def header_check(start: bytes) -> dict:
    """Read the group header at START.EXE:0x45B (CD 3F 00 00, fileofs, codesz, fixupsz, jmpcnt)."""
    b = start[HEADER_START:HEADER_START + 0x16]
    fileofs = struct.unpack("<I", b[4:8])[0]
    codesz, fixupsz, jmpcnt = struct.unpack("<HHH", b[8:14])
    return {"at": HEADER_START, "bytes": b[:4].hex(" "), "fileofs": fileofs,
            "codesz": codesz, "fixupsz": fixupsz, "jmpcnt": jmpcnt,
            "matches_fileofs_0x74d3": fileofs == HEADER_FILEOFS and b[:2] == b"\xcd\x3f"}


def seg2b_stubs(game: bytes, start: bytes) -> list[dict]:
    """Every far call in GAME.OVR with segment 0x2B, resolved under the zero-skew stub model.

    The stub address is ``0x200 + seg*16 + off`` in START.EXE (the resident image at file 0x200).
    The index is taken within the run that starts at ``HEADER_RUN``; the GAME.OVR target is the
    group's ``fileofs`` plus the stub's ``proc_off``. Both are model outputs, not resolutions.
    """
    rows: list[dict] = []
    for i in range(len(game) - 4):
        if game[i] != 0x9A:
            continue
        off, seg = struct.unpack("<HH", game[i + 1:i + 5])
        if seg != SEG_2B:
            continue
        addr = 0x200 + seg * 16 + off
        s = stub_at(start, addr)
        row = {"call_at": i, "seg": seg, "off": off, "stub_addr": addr, "stub": s is not None}
        if s is not None:
            proc_off, trailer = s
            in_run = HEADER_RUN <= addr < HEADER_RUN + 5 * 25 and (addr - HEADER_RUN) % 5 == 0
            row.update({
                "in_run": in_run,
                "index": (addr - HEADER_RUN) // 5 if in_run else None,
                "proc_off": proc_off,
                "trailer": trailer,
                "zero_skew_game_target": HEADER_FILEOFS + proc_off if in_run else None,
            })
        rows.append(row)
    return rows


def handler_far_calls(game: bytes, entry: int) -> list[dict]:
    """Linear sweep from ``entry`` for ``HANDLER_SPAN`` bytes; each far call with its two priors."""
    out: list[dict] = []
    prior: list[str] = []
    p = entry
    while p < entry + HANDLER_SPAN:
        try:
            ins = h.decode(game, p)
        except h.DecodeError as exc:
            out.append({"at": p, "error": str(exc)})
            break
        if ins.flow == "call_far" and ins.far is not None:
            out.append({"at": ins.off, "far": "0x%04x:0x%04x" % (ins.far[0], ins.far[1]),
                        "priors": list(prior[-2:])})
        prior.append("0x%04x %s" % (ins.off, ins.text()))
        prior = prior[-4:]
        p = ins.end
    return out


def dispatch_map(game: bytes) -> dict:
    r = h.dispatch_cases(game)
    cases = {c["case"]: c for c in r.get("cases", []) if "case" in c}
    out = {}
    for op in DISPATCH_CASES:
        c = cases.get(op)
        out["0x%02X" % op] = (None if c is None else
                              {"form": c["form"], "at": c["at"],
                               "call_target": c.get("call_target"),
                               "group_target": c.get("group_target")})
    return out


def probe(install: Path, out: Path, allow_unpinned: bool = False) -> tuple[dict, int]:
    install = Path(install)
    if not install.is_dir():
        raise ProbeRefusal("install folder not found: %s" % install)
    out_r, inst_r = out.resolve(), install.resolve()
    if out_r == inst_r or inst_r in out_r.parents:
        raise ProbeRefusal("output folder is inside the install")
    blobs: dict[str, bytes] = {}
    for name, (size, sha) in PINS.items():
        p = install / name
        if not p.is_file():
            raise ProbeRefusal("missing file: %s" % name)
        data = p.read_bytes()
        if not allow_unpinned and (len(data) != size or _sha(data) != sha):
            raise ProbeRefusal("unpinned file: %s (size %d)" % (name, len(data)))
        blobs[name] = data
    game, start = blobs["GAME.OVR"], blobs["START.EXE"]
    pins_ok = all(len(blobs[n]) == PINS[n][0] and _sha(blobs[n]) == PINS[n][1] for n in PINS)

    classifier = {}
    for v in CLASSIFIER_CASES:
        classifier["0x%02X" % v] = classify(game, v)
    header = header_check(start)
    stubs = seg2b_stubs(game, start)
    handlers = {
        "0x15_VERTICAL_MENU": {"entry": HANDLER_15, "far_calls": handler_far_calls(game, HANDLER_15)},
        "0x2B_HORIZONTAL_MENU": {"entry": HANDLER_2B, "far_calls": handler_far_calls(game, HANDLER_2B)},
    }
    dispatch = dispatch_map(game)

    checks = {
        "pins_match": pins_ok,
        "header_0x45b_is_group_0x74d3": header["matches_fileofs_0x74d3"],
        "menu_opcodes_take_default_arm": all(classifier["0x%02X" % v]["arm"] == "inc-only"
                                             for v in (0x15, 0x2B)),
        "dispatch_0x15_is_handler": (dispatch["0x15"] or {}).get("call_target") == HANDLER_15,
        "dispatch_0x2B_is_handler": (dispatch["0x2B"] or {}).get("call_target") == HANDLER_2B,
    }
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS,
        "tool": TOOL, "playable": False, "mappings": [], "events_emitted": 0,
        "pins": {n: {"size": len(blobs[n]), "sha256": _sha(blobs[n])} for n in PINS},
        "classifier_0x9379": classifier,
        "group_header": header,
        "seg_2b_calls": stubs,
        "handlers": handlers,
        "dispatch": dispatch,
        "checks": checks,
    }
    code = 0 if all(checks.values()) else 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_ecl_menu_framing_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc, code


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="folder holding GAME.OVR and START.EXE (read-only)")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder (outside the install)")
    ap.add_argument("--allow-unpinned", action="store_true", help="accept unpinned bytes (not retail evidence)")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(Path(args.install), args.out, args.allow_unpinned)
    except ProbeRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    for k, v in sorted(doc["checks"].items()):
        print("%-34s %s" % (k, "ok" if v else "FAIL"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
