#!/usr/bin/env python3
"""Observe-only supplemental probe: the caller stack frames at the ten static loader call sites.

Companion to tools/por_geo_loader_target_probe.py. That probe counted the ten pushed bytes at each
site (10) against the body's `retf 0x12` (18) and called the pair a prototype conflict. It did not
model the caller's own frame. This probe does, as far as the bytes allow:

1. For each of the ten sites (GAME.OVR x8, START.EXE x2), find the enclosing procedure: the nearest
   `push bp; mov bp,sp` from which a linear decode reaches the call exactly with no return between.
2. Walk that procedure's stack symbolically from its prologue to the start of the caller's 10-byte
   argument shape: `sub sp,N` (the allocation), pushes (with the register provenance of each word),
   pops, `add sp,N`, far calls (callee pops `retf K` = the top K bytes), and near calls (a `retf K`
   callee consumes its pushed CS word plus K bytes; a `ret K` callee consumes K bytes). Branches are
   checked for depth and slot agreement; a mismatch or an unknown callee fails the site closed.
3. At the shape start, the words still on the stack below the allocation are the LEFTOVER. The
   loader's `retf 0x12` consumes the 10 shape bytes plus the top 8 leftover bytes. So the caller's SP
   after the return sits (8 - L) bytes above its allocation floor, where L is the leftover in bytes.
   L = 8 means the return lands exactly on the allocation floor.
4. The callee's bp+16 and bp+20 map to caller addresses bp_caller - (N + L) and that plus 4.

The 0x0AF8 callees (copy routines) use base 0xAC76 (file = 0xAC76 + offset). That base was set by the
copy-helper probe's positive control and is checked here against both pinned memory dumps. The
loader's own contract is used only under the identity the loader-target probe reports (conditional).

Nothing here says the loader runs, that any caller runs, or what the output pointer holds. The
probe never promotes a pointer to a GEO block, never binds plane 2, and never claims execution.

Usage:
    python tools/por_geo_loader_caller_frame_probe.py [--install PATH/TO/POOLRAD] \
        [--dump data/work/por-live-memory-pid34644/ram-000000-100000.bin ...] \
        [-o data/work/por-geo-loader-caller-frame-probe]

Exit: 0 the probe ran (its verdict may be unresolved; that is the result); 2 a named refusal
(unpinned input, bad dump, output outside data/work or inside the install).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Callable, Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_farcall_resolve as fr  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_geo_callee_identity_probe as gcp  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_geo_loader_target_probe as ltp  # noqa: E402  (read-only: masked placement only)

SCHEMA = "openua.por-geo-loader-caller-frame-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "caller-frame-probe-only"
TOOL = "tools/por_geo_loader_caller_frame_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-loader-caller-frame-probe"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_DUMPS = ltp.DEFAULT_DUMPS
Refusal = om.Refusal
OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME

LOADER_SEG, LOADER_OFF = 0x0802, 0x0716
LOADER_CALL = bytes.fromhex("9a 16 07 02 08")
TARGET_FILE = 0x876D                     # START body reached under the loader identity (conditional)
TARGET_RETF = 0x12                       # its declared pop, read from bytes at 0x899E
COPY_SEG = 0x0AF8
COPY_BASE_FILE = 0xAC76                  # file = base + offset for segment 0x0AF8 (copy-helper probe)
LOAD = 0x1866                            # START load from the loader-target probe's live-segment rewrite
MAX_WALK = 4000
PUSH_SEG = {0x06: "es", 0x0E: "cs", 0x16: "ss", 0x1E: "ds"}
REG16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
SHAPE_RE = re.compile(rb"(?:\x8a\x46.\x50|\xb0.\x50)\x8d(?:\x7e.|\xbe..)\x16\x57\x8d(?:\x7e.|\xbe..)\x16\x57\Z",
                      re.S)

NOT_ESTABLISHED = [
    "that the loader 0x0802:0x0716 runs, or that any of the ten callers runs, at any instant",
    "that the body at START 0x876D is the loader (conditional on the loader-target probe's identity)",
    "that the 0x0AF8 copy routines copy as decoded: the Pascal-string reading is inferred from opcodes "
    "and corroborated only by the literal bytes; no run shows it",
    "what the loader writes through its output pointer, or whether that pointer names a GEO block",
    "the meaning of the id word, the status 0x402, or the name strings beyond their bytes",
    "the callee of segment 0x002B (site 0x279E) and 0x03C5 (site 0x78A6): no base for them is established",
    "the live stack contents at any call; the dumps are of unknown instant and carry no SS or SP",
    "plane 2 binding, any consumer of a buffer, or any area or descriptor mapping",
]

DISCRIMINATORS = [
    "A live capture at the fill call (GAME.OVR 0x2FA17), before the loader shape: the words at SS:(BP-280) "
    "to SS:(BP-273) should be two far pointers, offset then segment: SS:(BP-272) at BP-280 and SS:(BP-267) at "
    "BP-276. The bytes there should be 04 '.dax' at BP-272 and 03 'GEO' at BP-267 (the copy destinations).",
    "The same capture at the callee's first instruction (before its push bp, SP = S0-14 where S0 = BP-280): "
    "the far pointer at bp+16 is at SP+14 and the one at bp+20 is at SP+18. A callee that reads them as "
    "pointers, as the body does, would show the supply in action.",
    "The SP after the callee's retf 0x12 should equal BP-272 (the allocation floor). An SP of BP-264 would show "
    "an 8-byte over-pop, and BP-280 an 8-byte leftover.",
    "A live capture of the callee of segment 0x002B at site 0x279E and of segment 0x03C5 at site 0x78A6, and of "
    "0x0709:0x0BF5 (after the first loader call in 0x1EEAA), to close the sites this probe cannot model.",
]


# ---- small helpers --------------------------------------------------------------------------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def check_pins(ovr: bytes, exe: bytes) -> dict:
    return gcp.check_pins(ovr, exe, om.PINS)


def _positions(data: bytes, pat: bytes) -> list[int]:
    out, pos = [], data.find(pat)
    while pos != -1:
        out.append(pos)
        pos = data.find(pat, pos + 1)
    return out


def _decode(img: bytes, p: int):
    try:
        return lh.decode(img, p)
    except lh.DecodeError:
        return None


def _is_sp_op(i, reg_field: int) -> bool:
    return i.op in (0x81, 0x83) and i.modrm is not None and i.modrm == (3, reg_field, 4)


# ---- static call sites and enclosing procedures ---------------------------------------------

def call_sites(img: bytes) -> list[int]:
    return _positions(img, LOADER_CALL)


def shape_start(img: bytes, site: int) -> Optional[int]:
    m = SHAPE_RE.search(img[max(0, site - 20):site])
    return None if m is None else max(0, site - 20) + m.start()


def _reaches(img: bytes, proc: int, site: int) -> bool:
    p = proc
    while p < site:
        i = _decode(img, p)
        if i is None or i.flow in ("ret", "retf"):
            return False
        p = i.end
    return p == site


def find_proc(img: bytes, site: int, search: int = 0x800) -> tuple[Optional[int], list[int]]:
    """The nearest prologue from which a linear decode reaches the site, and up to four valid ones."""
    valid: list[int] = []
    for q in range(site - 1, max(-1, site - search), -1):
        if img[q] == 0x55 and img[q + 1:q + 3] in (b"\x89\xe5", b"\x8b\xec") and _reaches(img, q, site):
            valid.append(q)
            if len(valid) >= 4:
                break
    return (valid[0] if valid else None), valid


# ---- callees --------------------------------------------------------------------------------

def _returns(img: bytes, entry: int) -> Optional[list[tuple[str, int]]]:
    w = lh.walk(img, entry)
    if w.get("incomplete"):
        return None
    rets = sorted({(r["kind"], r["imm"] or 0) for r in w["returns"]})
    return rets or None


def make_resolver(exe: bytes) -> Callable[[int, int], Optional[dict]]:
    """Far-callee resolver. Returns {'retf': K, 'conditional': bool, 'source': str} or None (unknown)."""
    def resolve(seg: int, off: int) -> Optional[dict]:
        if (seg, off) == (LOADER_SEG, LOADER_OFF):
            return {"retf": TARGET_RETF, "conditional": True, "file": "0x%X" % TARGET_FILE,
                    "source": "START 0x876D retf 0x12 under the loader-target identity (conditional)"}
        if seg == COPY_SEG:
            f = COPY_BASE_FILE + off
            rets = _returns(exe, f)
            if rets is None or len({k for k, _ in rets}) != 1 or any(k != "retf" for k, _ in rets):
                return {"retf": None, "reason": "callee returns not one retf kind", "file": "0x%X" % f}
            imms = {imm for _, imm in rets}
            if len(imms) != 1:
                return {"retf": None, "reason": "callee has several retf counts %s" % sorted(imms),
                        "file": "0x%X" % f}
            return {"retf": next(iter(imms)), "conditional": False, "file": "0x%X" % f,
                    "source": "copy-helper base 0xAC76 (file-byte and memory placement)"}
        return None
    return resolve


def near_callee(img: bytes, target: int) -> Optional[dict]:
    rets = _returns(img, target)
    if rets is None or len({k for k, _ in rets}) != 1 or len({i for _, i in rets}) != 1:
        return None
    kind, imm = rets[0]
    return {"kind": kind, "imm": imm, "consume": imm + 2 if kind == "retf" else imm, "file": "0x%X" % target}


# ---- the symbolic walk ----------------------------------------------------------------------

class Walk:
    """One procedure's linear stack walk from its prologue to a site's argument shape."""

    def __init__(self, img: bytes, proc: int, site: int, resolve, ovr_group=None):
        self.img, self.proc, self.site = img, proc, site
        self.resolve = resolve
        self.alloc = 0
        self.slots: list[dict] = []           # oldest first; each word is 2 bytes
        self.prov = {"ax": "unknown", "di": "unknown"}
        self.log: list[dict] = []
        self.flags: list[str] = []
        self.conditional = False
        self.fail: Optional[str] = None
        self.snapshot: Optional[dict] = None
        self.bp_refs: list[dict] = []

    # -- helpers --
    def _state(self) -> dict:
        return {"alloc": self.alloc, "slots": [dict(s) for s in self.slots], "prov": dict(self.prov)}

    def _load(self, st: dict) -> None:
        self.alloc, self.slots, self.prov = st["alloc"], [dict(s) for s in st["slots"]], dict(st["prov"])

    def _pop_bytes(self, n: int) -> list[dict]:
        if n % 2:
            raise ValueError("odd consumption")
        words = n // 2
        if words > len(self.slots):
            raise ValueError("consumes below the pushed words (%d bytes, %d pushed)" % (n, 2 * len(self.slots)))
        popped = self.slots[len(self.slots) - words:] if words else []
        if words:
            del self.slots[len(self.slots) - words:]
        return popped

    def _push(self, reg: str, at: int, text: str) -> None:
        prov = self.prov.get(reg, "reg") if reg in ("ax", "di") else (
            "seg %s" % reg if reg in ("es", "cs", "ss", "ds") else "reg %s" % reg)
        self.slots.append({"at": at, "reg": reg, "text": text, "prov": prov})

    # -- the walk --
    def run(self) -> None:
        img, p = self.img, self.proc
        if img[p] != 0x55:
            self.fail = "no prologue at proc"
            return
        i = _decode(img, p + 1)
        if i is None or not (i.op == 0x89 and i.modrm == (3, 4, 5)):
            self.fail = "no mov bp,sp after push bp"
            return
        p = i.end
        shape_at = shape_start(img, self.site)
        if shape_at is None:
            self.fail = "no caller shape before the site"
            return
        pending: dict[int, dict] = {}
        reachable = True
        steps = 0
        while p < shape_at:
            steps += 1
            if steps > MAX_WALK:
                self.fail = "walk budget exhausted"
                return
            if p in pending:
                tgt = pending.pop(p)
                if not reachable:
                    self._load(tgt)
                    reachable = True
                elif self._depth(self._state()) != self._depth(tgt) or len(self.slots) != len(tgt["slots"]):
                    self.fail = "branch into 0x%05X with a different stack state" % p
                    self.flags.append(self.fail)
                    return
            i = _decode(img, p)
            if i is None:
                self.fail = "decode error at 0x%05X" % p
                return
            if not reachable:                     # linearly unreachable until a branch target arrives
                p = i.end
                continue
            if i.flow in ("jcc", "jmp") and i.target is not None:
                if self.proc < i.target < shape_at and i.target > p:
                    if i.target in pending and self._depth(pending[i.target]) != self._depth(self._state()):
                        self.fail = "two branches into 0x%05X with different depths" % i.target
                        self.flags.append(self.fail)
                        return
                    pending.setdefault(i.target, self._state())
                elif self.proc < i.target < shape_at:
                    self.fail = "backward branch inside the window at 0x%05X" % p
                    self.flags.append(self.fail)
                    return
                else:
                    self.log.append({"at": "0x%05X" % p, "kind": "branch-out-of-window",
                                     "target": "0x%05X" % i.target})
                if i.flow == "jmp":
                    reachable = False
                p = i.end
                continue
            if i.op == 0x9A:
                if not self._far_call(p, i):
                    return
            elif i.op == 0xE8:
                if not self._near_call(p, i):
                    return
            elif i.op in range(0x50, 0x58) or i.op in PUSH_SEG:
                reg = REG16[i.op - 0x50] if i.op in range(0x50, 0x58) else PUSH_SEG[i.op]
                self._push(reg, p, i.text())
            elif 0x58 <= i.op <= 0x5F or i.op in (0x07, 0x17, 0x1F):
                if not self.slots:
                    self.fail = "pop with no pushed word at 0x%05X" % p
                    return
                self.slots.pop()
            elif i.op in (0x81, 0x83) and _is_sp_op(i, 5):
                if self.slots:
                    self.fail = "sub sp below pushed words at 0x%05X" % p
                    return
                self.alloc += i.imm or 0
            elif i.op in (0x81, 0x83) and _is_sp_op(i, 0):
                try:
                    self._pop_bytes(i.imm or 0)
                except ValueError as exc:
                    self.fail = "add sp at 0x%05X: %s" % (p, exc)
                    return
            elif i.op == 0x89 and i.modrm == (3, 5, 4):
                self.fail = "mov sp,bp (epilogue) before the site at 0x%05X" % p
                return
            else:
                self._track_write(p, i)
            p = i.end
        if p != shape_at:
            self.fail = "shape start 0x%05X is not an instruction boundary" % shape_at
            return
        if not reachable:
            self.fail = "site shape start not linearly reachable"
            return
        self.snapshot = self._state()
        self.snapshot["shape_at"] = shape_at

    def _state(self) -> dict:
        return {"alloc": self.alloc, "slots": [dict(s) for s in self.slots], "prov": dict(self.prov)}

    def _load(self, st: dict) -> None:
        self.alloc, self.slots, self.prov = st["alloc"], [dict(s) for s in st["slots"]], dict(st["prov"])

    def _depth(self, st: dict) -> int:
        return st["alloc"] + sum(s.get("size", 2) for s in st["slots"])

    def _far_call(self, p: int, i) -> bool:
        seg, off = i.far
        info = self.resolve(seg, off)
        name = "%04x:%04x" % (seg, off)
        if info is None or info.get("retf") is None:
            self.fail = "unknown callee %s at 0x%05X (%s)" % (name, p, (info or {}).get("reason", "no base"))
            self.flags.append(self.fail)
            return False
        k = info["retf"]
        if info.get("conditional"):
            self.conditional = True
        try:
            popped = self._pop_bytes(k)
        except ValueError as exc:
            self.fail = "far call %s at 0x%05X: %s" % (name, p, exc)
            self.flags.append(self.fail)
            return False
        self.log.append({"at": "0x%05X" % p, "kind": "far-call", "callee": name, "retf": k,
                         "file": info.get("file"), "source": info.get("source"),
                         "conditional": bool(info.get("conditional")),
                         "consumed": [dict(s) for s in popped]})
        return True

    def _near_call(self, p: int, i) -> bool:
        target = i.target
        info = near_callee(self.img, target)
        if info is None:
            self.fail = "near callee 0x%05X returns are not one kind/count" % target
            self.flags.append(self.fail)
            return False
        if info["kind"] == "retf":
            top_cs = (self.slots and self.slots[-1]["reg"] == "cs")
            if not top_cs:
                self.fail = "near call to a retf callee at 0x%05X with no pushed CS word" % p
                self.flags.append(self.fail)
                return False
        try:
            popped = self._pop_bytes(info["consume"])
        except ValueError as exc:
            self.fail = "near call at 0x%05X: %s" % (p, exc)
            self.flags.append(self.fail)
            return False
        self.log.append({"at": "0x%05X" % p, "kind": "near-call", "callee": "0x%05X" % target,
                         "ret": info["kind"], "imm": info["imm"], "consumed_bytes": info["consume"],
                         "consumed": [dict(s) for s in popped]})
        return True

    def _track_write(self, p: int, i) -> None:
        """Provenance of ax and di for the words pushed later. Anything not recognised is 'unknown'."""
        mr = i.modrm
        if i.op == 0x8D and mr and mr[1] == 7 and i.bp_disp is not None:
            self.prov["di"] = "lea [bp%+d]" % i.bp_disp
        elif i.op == 0xC4 and mr and mr[1] == 7 and i.bp_disp is not None:
            self.prov["di"] = "les [bp%+d] (far pointer load)" % i.bp_disp
        elif 0xB8 <= i.op <= 0xBF and i.imm is not None:
            reg = REG16[i.op - 0xB8]
            if reg in self.prov:
                self.prov[reg] = "imm 0x%04x" % i.imm
        elif i.op == 0x8A and mr and mr[1] == 0 and i.bp_disp is not None:
            self.prov["ax"] = "byte [bp%+d]" % i.bp_disp
        elif i.op == 0x31 and mr == (3, 0, 0):
            self.prov["ax"] = "zero"
        else:
            if i.op in (0xA0, 0xA1):
                self.prov["ax"] = "unknown"
            if mr is not None:
                if mr[1] in (0, 4) or (mr[0] == 3 and mr[2] in (0, 4)):
                    self.prov["ax"] = "unknown"
                if mr[1] == 7 or (mr[0] == 3 and mr[2] == 7):
                    self.prov["di"] = "unknown"
            if 0x40 <= i.op <= 0x47:
                self.prov[REG16[i.op - 0x40]] = "unknown"
            if i.op in (0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF):
                self.prov["di"] = "unknown"
        if i.bp_disp is not None and i.bp_disp < 0:
            self.bp_refs.append({"at": "0x%05X" % p, "text": i.text(), "bp_disp": i.bp_disp})


# ---- per-site accounting --------------------------------------------------------------------

def leftover_pairs(slots_top_first: list[dict]) -> list[dict]:
    """Group the leftover words (top first) into far pointers: a seg word then an offset word."""
    out, k = [], 0
    while k < len(slots_top_first):
        off = slots_top_first[k]
        seg = slots_top_first[k + 1] if k + 1 < len(slots_top_first) else None
        if off["reg"] == "di" and seg is not None and seg["reg"] in ("es", "cs", "ss", "ds"):
            out.append({"offset_push": "0x%05X" % off["at"], "seg_push": "0x%05X" % seg["at"],
                        "seg": seg["reg"], "offset_prov": off["prov"]})
            k += 2
        else:
            out.append({"word_push": "0x%05X" % off["at"], "reg": off["reg"], "prov": off["prov"]})
            k += 1
    return out


def balance_row(snap: dict) -> dict:
    alloc = snap["alloc"]
    words = snap["slots"]
    L = sum(s.get("size", 2) for s in words)
    top_first = list(reversed(words))
    after = 8 - L        # SP after retf 0x12, relative to the allocation floor (bytes above = positive)
    if L == 8:
        status = "balanced"
    elif after > 0:
        status = "over-pop-into-locals"
    else:
        status = "leftover-remains"
    return {
        "allocation_bytes": alloc,
        "leftover_bytes": L,
        "leftover_top_first": [{"at": "0x%05X" % s["at"], "reg": s["reg"], "prov": s["prov"]} for s in top_first],
        "leftover_pairs_top_first": leftover_pairs(top_first),
        "target_bp16_caller_bp_rel": -(alloc + L),
        "target_bp20_caller_bp_rel": -(alloc + L) + 4,
        "sp_after_retf18_minus_floor_bytes": after,
        "stack_balance": status,
    }


def decode_pascal(code: bytes, off: int) -> Optional[dict]:
    if off < 0 or off >= len(code):
        return None
    n = code[off]
    body = code[off + 1:off + 1 + n]
    printable = n >= 1 and len(body) == n and all(32 <= b < 127 for b in body)
    return {"code_offset": "0x%04X" % off, "length_byte": n,
            "text": body.decode("ascii") if printable else None, "printable": printable}


def literal_rows(walk: Walk, code: Optional[bytes]) -> list[dict]:
    rows = []
    for ent in walk.log:
        if ent["kind"] != "far-call" or ent["callee"][:4] != "0af8":
            continue
        cons = ent["consumed"]
        src = cons[-2:] if len(cons) >= 2 else []
        if len(src) == 2 and src[0]["reg"] == "cs" and src[1]["reg"] == "di" and src[1]["prov"].startswith("imm "):
            off = int(src[1]["prov"].split()[1], 16)
            row = {"at": ent["at"], "callee": ent["callee"], "src_seg": "cs", "src_offset": "0x%04X" % off,
                   "pascal": None if code is None else decode_pascal(code, off),
                   "code_base": None if code is None else "owner group code (GAME.OVR)"}
            rows.append(row)
    return rows


# ---- top level ------------------------------------------------------------------------------

def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = check_pins(ovr, exe)
    groups = gcp.all_groups(exe, ovr)
    resolve = make_resolver(exe)

    dumps_meta, dumps = [], []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        base = om.resolve_dump_base(dp.name, len(raw), None)
        dumps.append(("%s/%s" % (dp.parent.name, dp.name), om.Dump(raw, base)))
        dumps_meta.append({"label": "%s/%s" % (dp.parent.name, dp.name), "size": len(raw),
                           "sha256_prefix": _sha(raw)[:16], "base": "0x%X" % base})

    # the copy routines the walks depend on: placement in each dump (memory-present, unknown instant)
    copy_offsets = [0x0B0B, 0x0B98, 0x1366, 0x0B25, 0x0C10]
    memory_checks = []
    for off in copy_offsets:
        row = {"callee": "0x%04X:0x%04X" % (COPY_SEG, off), "file": "0x%X" % (COPY_BASE_FILE + off), "dumps": []}
        for label, d in dumps:
            lin = (COPY_SEG + LOAD) * 16 + off
            if not d.covers(lin, 32):
                row["dumps"].append({"dump": label, "covered": False})
                continue
            pl = ltp.placements(exe, d.read(lin, 32), LOAD)
            row["dumps"].append({"dump": label, "covered": True, "placements": ["0x%X" % p["file_offset"] for p in pl],
                                 "agrees_with_base": [p["file_offset"] for p in pl] == [COPY_BASE_FILE + off]})
        memory_checks.append(row)

    rows, site_records = [], []
    for name, img, code_img in ((OVR_NAME, ovr, ovr), (EXE_NAME, exe, None)):
        for s in call_sites(img):
            rec = {"image": name, "site": "0x%05X" % s, "shape_matched": shape_start(img, s) is not None}
            proc, valid = find_proc(img, s)
            rec["proc"] = None if proc is None else "0x%05X" % proc
            rec["other_valid_proc_candidates"] = ["0x%05X" % v for v in valid[1:]]
            grp = gcp.owner_group(groups, proc) if (name == OVR_NAME and proc is not None) else None
            code = ovr[grp["fileofs"]:grp["fileofs"] + grp["codesz"]] if grp else None
            rec["owner_group"] = None if grp is None else "0x%X" % grp["fileofs"]
            if proc is None:
                rec.update({"walk_ok": False, "fail": "no enclosing prologue"})
                site_records.append(rec)
                continue
            w = Walk(img, proc, s, resolve)
            w.run()
            rec["walk_ok"] = w.fail is None and w.snapshot is not None
            rec["fail"] = w.fail
            rec["flags"] = w.flags
            rec["conditional_on_loader_identity"] = w.conditional
            rec["calls_before_shape"] = w.log
            rec["bp_relative_refs_in_window"] = w.bp_refs[:24]
            rec["literals_consumed_by_copy_calls"] = literal_rows(w, code)
            if rec["walk_ok"]:
                rec["stack"] = balance_row(w.snapshot)
            site_records.append(rec)
            rows.append(rec)

    determinable = [r for r in site_records if r.get("walk_ok")]
    balanced = [r["site"] for r in determinable if r["stack"]["stack_balance"] == "balanced"]
    unbalanced = [r["site"] for r in determinable if r["stack"]["stack_balance"] != "balanced"]
    unknown = [r["site"] for r in site_records if not r.get("walk_ok")]
    fill = next((r for r in site_records if r["site"] == "0x%05X" % 0x2FA17), None)

    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status_scope": STATUS_SCOPE, "tool": TOOL,
        "playable": False,
        "question": "What are the caller stack frames at the ten loader call sites, and does retf 0x12 fit them?",
        "pins": pins,
        "dumps": dumps_meta,
        "constants": {"loader": "0x%04X:0x%04X" % (LOADER_SEG, LOADER_OFF), "loader_call": LOADER_CALL.hex(" "),
                      "target_file": "0x%X" % TARGET_FILE, "target_retf": TARGET_RETF,
                      "copy_segment": "0x%04X" % COPY_SEG, "copy_base_file": "0x%X" % COPY_BASE_FILE,
                      "start_load_from_rewrite": "0x%04X" % LOAD},
        "copy_routine_memory_checks": memory_checks,
        "target_body_reads": body_reads(exe),
        "sites": site_records,
        "summary": {"sites_total": len(site_records), "sites_walked": len(determinable),
                    "balanced": balanced, "not_balanced": unbalanced, "unknown": unknown,
                    "prior_model_assumed_leftover_bytes": 0},
        "fill_site": fill and {"site": fill["site"], "proc": fill.get("proc"), "stack": fill.get("stack")},
        "verdict": verdict(site_records, balanced, unbalanced, unknown),
        "not_established": NOT_ESTABLISHED,
        "next_discriminating_observations": DISCRIMINATORS,
    }


def body_reads(exe: bytes) -> dict:
    ins, err = lh.linear(exe, TARGET_FILE, 400, stop_on_ret=True)
    first_branch = next((k for k, i in enumerate(ins) if i.flow in ("jcc", "jmp")), len(ins))
    reads = []
    for k, i in enumerate(ins[:first_branch]):
        if i.name in ("les", "lds") and i.bp_disp is not None and i.bp_disp > 0:
            reads.append({"at": "0x%05X" % i.off, "text": i.text(), "bp_disp": i.bp_disp,
                          "index_before_first_branch": k})
    call_targets = [{"at": "0x%05X" % i.off, "callee": "%04x:%04x" % i.far} for i in ins[:first_branch]
                    if i.far is not None]
    rets = [i for i in ins if i.flow in ("ret", "retf")]
    return {"entry": "0x%X" % TARGET_FILE, "decode_error": err, "first_branch_at": (
        "0x%05X" % ins[first_branch].off if first_branch < len(ins) else None),
        "far_pointer_loads_before_first_branch": reads, "calls_before_first_branch": call_targets,
        "first_return": None if not rets else {"at": "0x%05X" % rets[0].off, "text": rets[0].text(),
                                               "imm": rets[0].imm}}


def verdict(site_records: list[dict], balanced: list[str], unbalanced: list[str], unknown: list[str]) -> dict:
    if not balanced and not unbalanced:
        status = "unresolved-no-site-walked"
    elif unbalanced:
        status = "stack-accounting-inconsistent-at-some-sites"
    else:
        status = "stack-accounting-consistent-at-all-walked-sites"
    return {"status": status,
            "blocker": "identity of 0x0802:0x0716 is conditional (loader-target probe); the output pointer is not "
                       "traced; execution is unproven",
            "balanced_sites": balanced, "not_balanced_sites": unbalanced, "unknown_sites": unknown,
            "geo_output": "not_established", "plane2_binding": "not claimed", "playable": False}


# ---- report ---------------------------------------------------------------------------------

def render_report(doc: dict) -> str:
    v = doc["verdict"]
    lines = [
        "# Pool of Radiance: caller stack frames at the loader call sites (observe-only)", "",
        "**Status: %s. `playable: false`. `geo_output: %s`. `plane2_binding: %s`.**" % (
            v["status"], v["geo_output"], v["plane2_binding"]), "",
        "Blocker: %s" % v["blocker"], "",
        "## Pins and dumps", "", "| File | Size | SHA-256 |", "| --- | ---: | --- |",
    ]
    for name, p in doc["pins"].items():
        lines.append("| `%s` | %d | `%s` |" % (name, p["size"], p["sha256"]))
    lines += ["", "## Copy-routine memory placement (base 0xAC76)", "",
              "| Callee | File | Dump | Placements | Agrees with base |", "| --- | --- | --- | --- | --- |"]
    for row in doc["copy_routine_memory_checks"]:
        for d in row["dumps"]:
            lines.append("| %s | %s | %s | %s | %s |" % (row["callee"], row["file"], d["dump"],
                                                       d.get("placements", "-"), d.get("agrees_with_base", "-")))
    lines += ["", "## Ten call sites", "",
              "| Image | Site | Proc | Walk | Alloc | Leftover (bytes) | Stack | Conditional |",
              "| --- | --- | --- | --- | ---: | ---: | --- | --- |"]
    for r in doc["sites"]:
        st = r.get("stack") or {}
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["image"], r["site"], r.get("proc"), r.get("walk_ok"), st.get("allocation_bytes", "-"),
            st.get("leftover_bytes", "-"), st.get("stack_balance", r.get("fail", "-")),
            r.get("conditional_on_loader_identity", "-")))
    lines += ["", "## Fill site 0x2FA17 (the brief's site)", ""]
    fill = doc.get("fill_site")
    if fill and fill.get("stack"):
        s = fill["stack"]
        lines += [
            "- procedure %s; allocation %d bytes (`sub sp,0x%X`)." % (fill["proc"], s["allocation_bytes"],
                                                                     s["allocation_bytes"]),
            "- leftover below the allocation: %d bytes, top first: %s." % (
                s["leftover_bytes"], ", ".join("%s %s" % (x["reg"], x["prov"]) for x in s["leftover_top_first"])),
            "- target bp+16 = caller bp%+d, bp+20 = caller bp%+d." % (s["target_bp16_caller_bp_rel"],
                                                                     s["target_bp20_caller_bp_rel"]),
            "- SP after `retf 0x12` minus the allocation floor: %+d bytes (%s)." % (
                s["sp_after_retf18_minus_floor_bytes"], s["stack_balance"]),
        ]
    lines += ["", "## Name literals passed to the 0x0AF8 calls (walked sites only)", "",
              "A literal is the source a call consumed as `push cs; mov di,imm`. Pascal decoding is the length "
              "byte then the bytes; the helpers' semantics are inferred from opcodes, not run. START sites are not "
              "decoded: the code segment base of their procedure is not established.", "",
              "| Site | Call | Source literal | Length, text |", "| --- | --- | --- | --- |"]
    for r in doc["sites"]:
        if not r.get("walk_ok"):
            continue
        for lit in r.get("literals_consumed_by_copy_calls", []):
            pas = lit.get("pascal")
            if pas is None:
                txt = "not decoded (START code base not established)"
            else:
                txt = "%s, %s" % (pas["length_byte"], pas["text"] if pas["printable"] else "non-printable")
            lines.append("| %s | %s at %s | cs:0x%04X | %s |" % (
                r["site"], lit["callee"], lit["at"], int(lit["src_offset"], 16), txt))
    lines += ["", "## Not established", ""] + ["- " + x for x in doc["not_established"]]
    lines += ["", "## Next discriminating observations", ""]
    lines += ["%d. %s" % (i + 1, x) for i, x in enumerate(doc["next_discriminating_observations"])]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_geo_loader_caller_frame_probe.json").write_text(json.dumps(doc, indent=2, default=str),
                                                                encoding="utf-8")
    (out / "por_geo_loader_caller_frame_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only caller-frame probe of the loader call sites.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL)
    ap.add_argument("--dump", type=Path, action="append", default=None)
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    dumps = args.dump if args.dump else DEFAULT_DUMPS
    try:
        doc = probe(args.install, dumps)
    except (Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s (walked=%d/%d balanced=%s not_balanced=%s status=%s)" % (
        args.out, doc["summary"]["sites_walked"], doc["summary"]["sites_total"], doc["summary"]["balanced"],
        doc["summary"]["not_balanced"], doc["verdict"]["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
