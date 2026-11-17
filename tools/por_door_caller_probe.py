#!/usr/bin/env python3
"""Pool of Radiance: static callers of the plane-3 door-field routines.

Observe-only. Answers the open edge in docs/por-geo-door-semantics.md: which code calls the
plane-3 writer GAME.OVR:0x167D4 (sets a 2-bit field to 01), the clearer 0x166CB, and the
plane-3 reader 0x2EC47, and what each caller does with the result. It does not decide what
any door value means in play.

Evidence tiers for a call to a target, all from decoded instruction boundaries (lh.walk):
  A  decoded near call in a function reached from a well-formed VROOMM stub of the owner group,
     by following in-group near calls (call closure). Structural reachability only.
  B  decoded near call in a Borland-prologue function of the owner group that no stub reaches.
     A candidate: the function may be reached only through a path this probe does not model.
  C  byte-pattern E8/E9 whose site is not a decoded instruction start. Not a caller.

Far calls (9A) into an owner group go through its VROOMM stub in START.EXE. Two address models
are reported; neither is promoted to a law:
  M0  resolver zero-skew model, image = hdr + seg*16 + off (tools/por_farcall_resolve.py). The
      resolver doc says it fits only 2 of 11 handler calls.
  M1  dump-anchored model, file = seg*16 + off + 0x7E. The 0x7E is derived from one anchor,
      caller literal 03D5:0034 reaching stub 4 at START 0x3E02, identified in one RAM dump
      (docs/por-geo-callee-identity-probe.md). M1 is conditional on that identity. Under M1 the
      stub stride gives literal 03D5:(slot - 0x3DCE): the candidate for stub 3 (0x3DFD, which
      proc 0x350 = 0x2EC47) is 03D5:002F.
A far site is a candidate only when its bytes decode as a call instruction (9A) in a walk and its
segment word is listed in the containing group's fixup table (fixup table = group-relative words).

Read-only. Refuses unpinned GAME.OVR or START.EXE (no override), refuses output outside data/work
and output inside the install. Writes only the JSON and Markdown report.

Usage:
    python tools/por_door_caller_probe.py --install PATH/TO/POOLRAD -o data/work/por-door-caller-probe

Exit: 0 probe ran and every target's owner group resolved; 2 named refusal.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import deque
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_farcall_resolve as fr  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402
import por_overlay_group_map as om  # noqa: E402

SCHEMA = "openua.por-door-caller-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_door_caller_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
DEFAULT_OUT = DATA_WORK / "por-door-caller-probe"
DEFAULT_DUMPS = (DATA_WORK / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                 DATA_WORK / "por-wheel-live-capture" / "ram-000000-100000.bin")

# (name, GAME.OVR file offset of the routine, what the existing docs say it does)
TARGETS = (
    ("clear_field", 0x166CB, "clears one 2-bit plane-3 field (masks 3F/CF/F3/FC); no gate"),
    ("set_field_01", 0x167D4, "sets one plane-3 field to 01; gated on 0 <= X,Y <= 15"),
    ("plane3_reader", 0x2EC47, "reads plane 3 at +0x300; Y compares"),
)

STUB_SEG_RAW = 0x03D5                      # the stub-run segment literal (buffer-fill and callee docs)
M1_ANCHOR_LITERAL_OFF = 0x0034             # caller literal 03D5:0034 ...
M1_ANCHOR_STUB_FILE = 0x3E02               # ... reaches stub 4 at START 0x3E02 (callee-identity doc)
M1_DELTA = M1_ANCHOR_STUB_FILE - (STUB_SEG_RAW * 16 + M1_ANCHOR_LITERAL_OFF)   # 0x7E
STUB_LEN = fr.STUB_LEN
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
CONTEXT_BEFORE = 3
CONTEXT_AFTER = 4


class Refusal(Exception):
    pass


def _sha(data: bytes) -> str:
    return fr._sha(data)


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def load_pinned(install: Path) -> tuple[bytes, bytes, dict]:
    """Read both pinned files. An unpinned file is a refusal; there is no override."""
    pins = {}
    data = {}
    for name in (fr.OVR_NAME, fr.EXE_NAME):
        p = install / name
        if not p.is_file():
            raise Refusal("%s not found in the install folder" % name)
        raw = p.read_bytes()
        size, sha = fr.PINNED[name]
        ok = len(raw) == size and _sha(raw) == sha
        pins[name] = {"size": len(raw), "sha256": _sha(raw), "pin_match": ok}
        if not ok:
            raise Refusal("%s does not match its pinned size and SHA-256; refusing" % name)
        data[name] = raw
    return data[fr.OVR_NAME], data[fr.EXE_NAME], pins


def _context(walk: dict, at: int) -> list[dict]:
    """Listing rows around the instruction starting at ``at`` in a walk (for the report)."""
    rows = walk["listing"]
    idx = next((i for i, r in enumerate(rows) if r["at"] == at), None)
    if idx is None:
        return []
    lo = max(0, idx - CONTEXT_BEFORE)
    hi = min(len(rows), idx + CONTEXT_AFTER + 1)
    return [{"at": "0x%05X" % r["at"], "bytes": r["bytes"], "text": r["text"],
             "is_site": r["at"] == at} for r in rows[lo:hi]]


def stub_slot_for(group: dict, entry: int) -> Optional[dict]:
    """The stub of ``group`` whose proc word names ``entry``, valid or not, else None."""
    for k, proc in enumerate(group["procs"]):
        if group["fileofs"] + proc == entry:
            return {"index": k, "proc_rel": "0x%04X" % proc,
                    "stub_file": "0x%05X" % (group["stub_start"] + STUB_LEN * k),
                    "stub_valid": group["stub_valid"][k]}
    return None


def closure(ovr: bytes, group: dict, entries: list[int]) -> dict[int, dict]:
    """Walk each entry; follow in-group near calls to new function entries (tier A)."""
    fo, cs = group["fileofs"], group["codesz"]
    fns: dict[int, dict] = {}
    queue = deque(entries)
    while queue:
        e = queue.popleft()
        if e in fns:
            continue
        w = lh.walk(ovr, e)
        fns[e] = w
        for c in w["near_calls"]:
            t = c["target"]
            if t is not None and fo <= t < fo + cs and t not in fns:
                queue.append(t)
    return fns


def sweep(ovr: bytes, group: dict, reached: dict[int, dict]) -> dict[int, dict]:
    """Walk every Borland-prologue offset in the group body that no stub closure reaches (tier B)."""
    fo, cs = group["fileofs"], group["codesz"]
    out: dict[int, dict] = {}
    for p in range(fo, fo + cs - 3):
        if ovr[p:p + 3] in PROLOGUES and p not in reached:
            out[p] = lh.walk(ovr, p)
    return out


def _near_rows(fns: dict[int, dict], tier: str, target: int, skip: set[int]) -> list[dict]:
    rows = []
    for e, w in sorted(fns.items()):
        for c in w["near_calls"]:
            if c["target"] == target and c["at"] not in skip:
                rows.append({"tier": tier, "site": "0x%05X" % c["at"],
                             "caller_entry": "0x%05X" % e,
                             "caller_walk_complete": w["complete"],
                             "context": _context(w, c["at"])})
                skip.add(c["at"])
    return rows


def byte_only_near(ovr: bytes, group: dict, target: int, decoded_sites: set[int]) -> list[dict]:
    """E8/E9 byte patterns that name the target but whose site is not a decoded start. Not callers."""
    fo, cs = group["fileofs"], group["codesz"]
    out = []
    for p in range(fo, fo + cs - 2):
        if ovr[p] in (0xE8, 0xE9) and p + 3 <= len(ovr):
            rel = struct.unpack_from("<h", ovr, p + 1)[0]
            if (p - fo + 3 + rel) & 0xFFFF == target - fo and p not in decoded_sites:
                out.append({"site": "0x%05X" % p, "opcode": "%02X" % ovr[p]})
    return out


def far_index(fns_all: list[tuple[str, dict[int, dict]]]) -> dict[int, dict]:
    """Decoded far calls (9A) across all walks, keyed by site. Tier from the walk's class."""
    idx: dict[int, dict] = {}
    for tier, fns in fns_all:
        for e, w in fns.items():
            for c in w["far_calls"]:
                idx.setdefault(c["at"], {"tier": tier, "caller_entry": "0x%05X" % e,
                                         "caller_walk_complete": w["complete"],
                                         "context": _context(w, c["at"]),
                                         "seg": "0x%04X" % c["seg"], "off": "0x%04X" % c["off"]})
    return idx


def far_m1_candidates(ovr: bytes, allg: list[dict], slot_file: int, cache: "GroupCache") -> dict:
    """Byte-pattern 9A sites that match the M1 literal for a stub slot. Candidates only.

    Each site is checked against the walks of its OWN owner group (the group whose code holds
    the byte), not the group whose routine the stub names."""
    off = slot_file - M1_DELTA - STUB_SEG_RAW * 16
    if not 0 <= off <= 0xFFFF:
        return {"literal": None, "sites": []}
    pat = b"\x9a" + struct.pack("<HH", off, STUB_SEG_RAW)
    sites = []
    for m in re.finditer(re.escape(pat), ovr):
        p = m.start()
        g = fr.group_containing_code(allg, p)
        if g is None:
            fixup = None
            owner = None
            d = None
        else:
            fixup = (p + 3 - g["fileofs"]) in fr.fixup_table(ovr, g)
            owner = "0x%05X" % g["fileofs"]
            d = cache.get(g).far.get(p)
        sites.append({
            "site": "0x%05X" % p,
            "owner_group": owner,
            "seg_word_in_fixup_table": fixup,
            "decoded_call_insn": d is not None,
            "decode_tier": d["tier"] if d else None,
            "caller_entry": d["caller_entry"] if d else None,
            "context": d["context"] if d else [],
        })
    return {"literal": "03D5:%04X" % off, "sites": sites}


def start_far_counts(start: bytes, hdr: int, slot_file: int) -> dict:
    """Byte-pattern 9A in the resident START.EXE whose M0 or M1 arithmetic lands on the slot.

    Counted only. START.EXE is the resident image, so its raw segment words are not overlay
    words; both models are applied as candidate arithmetic, and no site is decoded here."""
    m0 = m1 = 0
    want1 = slot_file - M1_DELTA
    for p in range(len(start) - 4):
        if start[p] == 0x9A:
            off, seg = struct.unpack_from("<HH", start, p + 1)
            if hdr + seg * 16 + off == slot_file:
                m0 += 1
            if want1 >= 0 and seg * 16 + off == want1:
                m1 += 1
    return {"M0_count": m0, "M1_count": m1}


def far_m0_hits(ovr: bytes, hdr: int, slot_file: int) -> list[dict]:
    """Every byte-pattern 9A in GAME.OVR whose zero-skew image address is the slot. Resolver model."""
    hits = []
    for p in range(len(ovr) - 4):
        if ovr[p] == 0x9A:
            off, seg = struct.unpack_from("<HH", ovr, p + 1)
            if hdr + seg * 16 + off == slot_file:
                hits.append({"site": "0x%05X" % p, "literal": "%04X:%04X" % (seg, off)})
    return hits


def far_m1_any_segment(ovr: bytes, slot_file: int) -> dict:
    """9A sites (any segment) whose M1 image equals the slot. Shows whether the stub is reachable
    by a literal at all under M1; the 03D5 literal is only one segment choice."""
    want = slot_file - M1_DELTA
    hits = []
    if want >= 0:
        for p in range(len(ovr) - 4):
            if ovr[p] == 0x9A:
                off, seg = struct.unpack_from("<HH", ovr, p + 1)
                if seg * 16 + off == want:
                    hits.append({"site": "0x%05X" % p, "literal": "%04X:%04X" % (seg, off)})
    return {"count": len(hits), "sites": hits[:12], "target_seg_off_sum": "0x%05X" % want if want >= 0 else None}


class GroupWalks:
    """Closure, prologue sweep, and far/near indexes for one owner group (computed once)."""

    def __init__(self, ovr: bytes, group: dict):
        self.group = group
        self.valid_entries = [group["fileofs"] + p for k, p in enumerate(group["procs"])
                              if group["stub_valid"][k]]
        self.reached = closure(ovr, group, self.valid_entries)
        self.swept = sweep(ovr, group, self.reached)
        self.near_sites: set[int] = set()
        for w in list(self.reached.values()) + list(self.swept.values()):
            self.near_sites.update(c["at"] for c in w["near_calls"])
        self.far = far_index([("A-stub-closure", self.reached), ("B-prologue-unreached", self.swept)])
        # Per valid stub: the closure from that stub's entry alone. A target is reached by a stub
        # when it lies in that closure. Stub-to-proc is the VROOMM contract; closure is structural.
        self.per_root = {}
        for k, proc in enumerate(group["procs"]):
            if group["stub_valid"][k]:
                e0 = group["fileofs"] + proc
                self.per_root[k] = (e0, closure(ovr, group, [e0]))


class GroupCache:
    """Per-group walks keyed by file offset: each group is walked once however many checks use it."""

    def __init__(self, ovr: bytes):
        self._ovr = ovr
        self._by_fo: dict[int, GroupWalks] = {}

    def get(self, group: dict) -> GroupWalks:
        fo = group["fileofs"]
        if fo not in self._by_fo:
            self._by_fo[fo] = GroupWalks(self._ovr, group)
        return self._by_fo[fo]


def _literal_sites(ovr: bytes, allg: list[dict], literal_off: int) -> list[dict]:
    """Every byte-pattern 9A with literal 03D5:<literal_off>, with its owner group (file bytes)."""
    pat = b"\x9a" + struct.pack("<HH", literal_off, STUB_SEG_RAW)
    out = []
    for m in re.finditer(re.escape(pat), ovr):
        p = m.start()
        g = fr.group_containing_code(allg, p)
        out.append({"site": p, "owner": g})
    return out


def dump_live_check(ovr: bytes, allg: list[dict], dumps: list[Path], start: bytes) -> dict:
    """Read-only check of the live 9A operands in each RAM dump (observation, not a call proof).

    For each dump: map each owner group uniquely (tools/por_overlay_group_map.py map_group),
    then read the 5 live bytes at each literal site. The calibration literal 03D5:0034 is the
    one whose live segment the callee-identity doc recorded as 1C3B; the stride candidate
    03D5:002F is checked the same way. The stub-3 bytes are read at the predicted linear
    (calibration live segment * 16 + 0x2F). Nothing here decides which call executes."""
    sites_cal = _literal_sites(ovr, allg, M1_ANCHOR_LITERAL_OFF)
    sites_s3 = _literal_sites(ovr, allg, 0x002F)
    report = {"calibration_literal": "03D5:%04X" % M1_ANCHOR_LITERAL_OFF,
              "stride_literal": "03D5:002F", "dumps": []}
    for dpath in dumps:
        if not dpath.is_file():
            report["dumps"].append({"path": dpath.parent.name + "/" + dpath.name, "status": "missing"})
            continue
        raw = dpath.read_bytes()
        try:
            base_name = om.resolve_dump_base(dpath.name, len(raw), None)
        except om.Refusal as exc:
            report["dumps"].append({"path": dpath.parent.name + "/" + dpath.name, "status": "refused: %s" % exc})
            continue
        dump = om.Dump(raw, base_name)
        group_map: dict[int, dict] = {}

        def place(g: dict) -> Optional[int]:
            fo = g["fileofs"]
            if fo not in group_map:
                code = ovr[fo:fo + g["codesz"]]
                try:
                    res = om.map_group(g, code, om.read_fixups(ovr, g), dump)
                except om.Refusal as exc:
                    res = {"status": "refused: %s" % exc, "base_linear": None}
                group_map[fo] = res
            return group_map[fo]["base_linear"]

        def rows(sites: list[dict]) -> list[dict]:
            out = []
            for row in sites:
                g = row["owner"]
                if g is None:
                    out.append({"site": "0x%05X" % row["site"], "live": None, "reason": "no owner group"})
                    continue
                base = place(g)
                if base is None:
                    out.append({"site": "0x%05X" % row["site"], "live": None,
                                "reason": "owner group %s not unique in this dump" % ("0x%05X" % g["fileofs"])})
                    continue
                lin = base + (row["site"] - g["fileofs"])
                if not dump.covers(lin, 5):
                    out.append({"site": "0x%05X" % row["site"], "live": None, "reason": "outside dump"})
                    continue
                b = dump.read(lin, 5)
                out.append({"site": "0x%05X" % row["site"], "owner": "0x%05X" % g["fileofs"],
                            "live_linear": "0x%05X" % lin, "opcode": "%02X" % b[0],
                            "live_offset": "0x%04X" % struct.unpack_from("<H", b, 1)[0],
                            "live_segment": "0x%04X" % struct.unpack_from("<H", b, 3)[0]})
            return out

        cal = rows(sites_cal)
        s3 = rows(sites_s3)
        cal_segs = [r["live_segment"] for r in cal if r.get("live_segment")]
        entry = {"path": dpath.parent.name + "/" + dpath.name, "base_linear": "0x%05X" % base_name,
                 "group_map": {"0x%05X" % k: {"status": v["status"], "base_linear": (
                     "0x%05X" % v["base_linear"]) if v.get("base_linear") is not None else None,
                     "anchor_length": v.get("anchor_length"), "anchor_candidates": v.get("anchor_candidates")}
                     for k, v in group_map.items()},
                 "calibration_sites": cal, "stride_sites": s3, "status": "read"}
        if cal_segs:
            mode = max(set(cal_segs), key=cal_segs.count)
            pred = int(mode, 16) * 16 + 0x2F
            entry["calibration_live_segment_mode"] = mode
            entry["stub3_predicted_linear"] = "0x%05X" % pred
            if dump.covers(pred, 5):
                entry["stub3_live_bytes"] = dump.read(pred, 5).hex(" ")
                entry["stub3_start_bytes"] = start[0x3DFD:0x3E02].hex(" ")
                entry["stub3_bytes_match"] = entry["stub3_live_bytes"] == entry["stub3_start_bytes"]
        report["dumps"].append(entry)
    return report


def analyse(ovr: bytes, start: bytes, dumps: Optional[list[Path]] = None) -> dict:
    hdr = fr.mz_image_base(start)
    scan = fr.scan_all(start, ovr)
    allg = scan["groups"] + scan["partial_groups"]
    cache = GroupCache(ovr)
    targets_out = []
    for name, entry, note in TARGETS:
        owner = fr.group_containing_code(allg, entry)
        if owner is None:
            targets_out.append({"name": name, "entry": "0x%05X" % entry, "owner": None,
                                "refusal": "no stub-carrying group contains this offset"})
            continue
        fo = owner["fileofs"]
        gw = cache.get(owner)
        seen_a: set[int] = set()
        tier_a = _near_rows(gw.reached, "A-stub-closure", entry, seen_a)
        tier_b = _near_rows(gw.swept, "B-prologue-unreached", entry, seen_a)
        slot = stub_slot_for(owner, entry)
        row = {
            "name": name,
            "entry": "0x%05X" % entry,
            "note": note,
            "owner": {"fileofs": "0x%05X" % fo, "codesz": "0x%04X" % owner["codesz"],
                      "header_offset": "0x%04X" % owner["header_offset"], "status": owner["status"],
                      "entry_proc_rel": "0x%04X" % (entry - fo),
                      "valid_stub_entries": ["0x%05X" % e for e in gw.valid_entries],
                      "closure_functions": len(gw.reached), "prologue_functions_unreached": len(gw.swept)},
            "stub_slot": slot,
            "near_callers_decoded": tier_a + tier_b,
            "near_byte_only_not_decoded": byte_only_near(ovr, owner, entry, gw.near_sites),
        }
        roots = []
        for k, (e0, fns) in sorted(gw.per_root.items()):
            if entry in fns:
                slot_k = int(owner["stub_start"] + STUB_LEN * k)
                roots.append({
                    "stub_index": k,
                    "stub_file": "0x%05X" % slot_k,
                    "proc_rel": "0x%04X" % (e0 - fo),
                    "M1_literal_03D5": far_m1_candidates(ovr, allg, slot_k, cache)
                    if slot_k - M1_DELTA - STUB_SEG_RAW * 16 >= 0 else None,
                    "M1_any_segment": far_m1_any_segment(ovr, slot_k),
                    "M0_zero_skew_hits": far_m0_hits(ovr, hdr, slot_k),
                    "START_exe_byte_counts": start_far_counts(start, hdr, slot_k),
                })
        row["root_stubs"] = roots
        targets_out.append(row)
    return {
        "image_base": "0x%03X" % hdr,
        "m1_delta": "0x%02X" % M1_DELTA,
        "m1_anchor": {"literal": "03D5:0034", "stub_file": "0x%05X" % M1_ANCHOR_STUB_FILE,
                      "source": "docs/por-geo-callee-identity-probe.md"},
        "targets": targets_out,
        "dump_live_check": dump_live_check(ovr, allg, dumps or [], start),
    }


def probe(install: Path, dumps: Optional[list[Path]] = None) -> dict:
    ovr, start, pins = load_pinned(install)
    result = analyse(ovr, start, dumps)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "pins": pins,
        "models": {
            "M0": "resolver zero-skew: hdr + seg*16 + off (unproven; fits 2 of 11 handler calls)",
            "M1": "dump-anchored: seg*16 + off + 0x7E (conditional on one dump's stub-4 identity)",
        },
        "analysis": result,
        "open_edges": [
            "Runtime execution: every caller here is a static decode; nothing shows a call ran.",
            "Stub 1 of group 0x166CB (file 0x0089C), the only far entry that reaches the field writer "
            "and clearer, has no 9A literal in GAME.OVR or START.EXE under M0 or M1. Its trigger is unidentified.",
            "Group 0x166CB and group 0x2DB87 are absent from both pinned dumps, so the live state of the "
            "writer/clearer callers is unobserved. Three of four stride sites lie in 0x166CB.",
            "M1 (+0x7E) is anchored on one dump's stub-4 identity. The 0xC726 live operand 1C3B:002F "
            "and the stub-3 bytes at 1C3DF support M1 for that site only; they do not prove the call.",
            "The reader's 2-bit return is tested by callers with cmp/or on AL; the consequence of each "
            "branch (what a value means in play) is not decoded here.",
            "GoldBox and CoK/COAB evidence is not used. Nothing here is PoR semantics.",
        ],
    }


def render_report(doc: dict) -> str:
    L = ["# PoR door-field callers (static, observe-only)", "",
         "**Status: static-probe-only. `playable: false`.** Tool: `%s`." % TOOL, "",
         "## Pins", ""]
    for k, v in doc["pins"].items():
        L.append("- `%s` size %d sha256 `%s` pin_match %s" % (k, v["size"], v["sha256"], v["pin_match"]))
    L += ["", "## Models", ""]
    for k, v in doc["models"].items():
        L.append("- %s: %s" % (k, v))
    for t in doc["analysis"]["targets"]:
        L += ["", "## %s at %s" % (t["name"], t["entry"]), "", t.get("note", ""), ""]
        if t.get("owner") is None:
            L.append("- refusal: %s" % t["refusal"])
            continue
        o = t["owner"]
        L.append("- owner group `%s` (%s), entry proc-rel `%s`, closure functions %d, unreached prologues %d"
                 % (o["fileofs"], o["status"], o["entry_proc_rel"], o["closure_functions"],
                    o["prologue_functions_unreached"]))
        L.append("- stub slot: %s" % (t["stub_slot"] if t["stub_slot"] else "none in owner group"))
        L.append("- decoded near callers: %d" % len(t["near_callers_decoded"]))
        for r in t["near_callers_decoded"]:
            L.append("  - %s site `%s` in fn `%s` (walk complete %s)"
                     % (r["tier"], r["site"], r["caller_entry"], r["caller_walk_complete"]))
        L.append("- byte-only near sites (not decoded starts, not callers): %d" % len(t["near_byte_only_not_decoded"]))
        for rs in t.get("root_stubs", []):
            L.append("- root stub %d at `%s` (proc `%s`): M0 zero-skew hits %d; M1 any-segment hits %d; "
                     "START.EXE byte counts %s" % (rs["stub_index"], rs["stub_file"], rs["proc_rel"],
                                                   len(rs["M0_zero_skew_hits"]), rs["M1_any_segment"]["count"],
                                                   rs["START_exe_byte_counts"]))
            m1 = rs.get("M1_literal_03D5")
            if m1 is not None:
                L.append("  - M1 literal `%s`: %d byte-pattern site(s)" % (m1["literal"], len(m1["sites"])))
                for x in m1["sites"]:
                    L.append("    - site `%s` owner %s fixup-listed %s decoded %s (%s) fn %s"
                             % (x["site"], x["owner_group"], x["seg_word_in_fixup_table"],
                                x["decoded_call_insn"], x["decode_tier"], x["caller_entry"]))
    dl = doc["analysis"]["dump_live_check"]
    L += ["", "## Dump live-operand check (observation only)", "",
          "- calibration literal `%s`, stride literal `%s`" % (dl["calibration_literal"], dl["stride_literal"])]
    for d in dl["dumps"]:
        L.append("- dump `%s`: %s" % (d["path"], d.get("status", "read")))
        if d.get("status") != "read":
            continue
        L.append("  - group map: %s" % ", ".join("%s %s" % (k, v["status"]) for k, v in d["group_map"].items()))
        L.append("  - calibration sites (live seg): %s" % ", ".join(
            "%s=%s" % (r["site"], r.get("live_segment") or r.get("reason")) for r in d["calibration_sites"]))
        L.append("  - stride sites 03D5:002F (live seg): %s" % ", ".join(
            "%s=%s" % (r["site"], r.get("live_segment") or r.get("reason")) for r in d["stride_sites"]))
        if "stub3_bytes_match" in d:
            L.append("  - stub 3 at predicted linear %s: live %s; START 0x3DFD %s; match %s" % (
                d["stub3_predicted_linear"], d["stub3_live_bytes"], d["stub3_start_bytes"], d["stub3_bytes_match"]))
    L += ["", "## Open edges", ""] + ["- " + x for x in doc["open_edges"]] + [""]
    return "\n".join(L)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_door_caller_probe.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "por_door_caller_probe_report.md").write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Observe-only static callers of the PoR plane-3 door routines.")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL,
                    help="folder with the pinned GAME.OVR and START.EXE")
    ap.add_argument("--dump", type=Path, action="append", default=None,
                    help="raw RAM dump(s) for the read-only live operand check (repeatable)")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    if not _inside(args.out, DATA_WORK):
        print("refused: output must be under data/work", file=sys.stderr)
        return 2
    if _inside(args.out, args.install):
        print("refused: output inside the install", file=sys.stderr)
        return 2
    try:
        doc = probe(args.install, args.dump if args.dump else list(DEFAULT_DUMPS))
    except (Refusal, FileNotFoundError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
