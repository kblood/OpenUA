#!/usr/bin/env python3
"""Body and argument layout of the zero-fill 0x0AF8:0x16A8, and the two START callers of the module targets.

Follows tools/por_wall_0111_module_target_probe.py, which left 0x0AF8:0x16A8 undecoded and the START callers
at 0x227D (size 0x3F to 0x023F) and 0x2268 (size 0x3F and a far pointer to 0x0254) unclassified. This probe:

  1. decodes the fill body at module 0x16A8 (byte-exact template, fail closed), derives its argument layout
     from the callee's own SP-relative reads, and checks the three wall-helper call sites for the same layout;
  2. checks that each wall-helper fill count is the same byte expression as the size of the allocation it
     follows, and that the fill value is the pushed zero word;
  3. classifies the immediate caller frame of START 0x227D and 0x2268: the frame's entry (nearest prologue
     that reaches the call on an instruction boundary), the size pushed, the pointer source, and the byte-level
     operations on the same block (copy, link words) in the straight-line run around each call. It reports
     whether the two frames pair on size and pointer role. It does not trace the frames' own callers.

Read-only and stdlib-only. Reuses the module mapping of the module-target probe (file base 0xAC76, live
segment 0x235E, the anchor load 0x1866). Every claim is conditional on that mapping, as in its note.
It writes only under data/work/por-wall-0111-fill-callers-probe/ and never runs the code.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import por_overlay_group_map as om  # noqa: E402
import por_geo_copy_helper_probe as gcp  # noqa: E402
import por_loadpieces_handler as lp  # noqa: E402
import por_wall_0111_module_target_probe as mp  # noqa: E402

Refusal = om.Refusal
SCHEMA = "openua.por-wall-0111-fill-callers-probe"
SCHEMA_VERSION = 1
STATUS_SCOPE = "fill-callers-probe-only"
TOOL = "tools/por_wall_0111_fill_callers_probe.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-wall-0111-fill-callers-probe"
DEFAULT_INSTALL = mp.DEFAULT_INSTALL
DEFAULT_DUMPS = mp.DEFAULT_DUMPS
OVR_NAME = mp.OVR_NAME
EXE_NAME = mp.EXE_NAME
MODULE_SEG = mp.MODULE_SEG
EXPECT_LOAD = mp.EXPECT_LOAD
PARA = mp.PARA
WINDOW = mp.WINDOW
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")
SIZE = 0x3F

# ---- the fill body at module 0x16A8 (hand-decoded; byte-exact match, fail closed) ----------------

FILL_OFF = 0x16A8
FILL_STEPS = [
    ("8b dc", "mov bx,sp"),
    ("36 c4 7f 08", "les di,[ss:bx+0x08]"),       # ES:DI <- dst (offset at sp+8, segment at sp+10)
    ("36 8b 4f 06", "mov cx,[ss:bx+0x06]"),       # CX <- count (sp+6)
    ("36 8a 47 04", "mov al,[ss:bx+0x04]"),       # AL <- value, low byte of the word at sp+4
    ("fc", "cld"),
    ("f3 aa", "rep stosb"),                       # fill CX bytes of AL at ES:DI, forward
    ("ca 08 00", "retf 0x08"),                    # callee pops 4 words: value, count, dst off, dst seg
]
FILL_BODY = b"".join(bytes.fromhex(h) for h, _ in FILL_STEPS)
FILL_RETF_IMM = 8
FILL_LAYOUT = {"value_byte_sp": 4, "count_word_sp": 6, "dst_off_sp": 8, "dst_seg_sp": 10}

# ---- the wall-helper fill sites and the allocations they follow (START file offsets) -------------
# (label, alloc_start, alloc_call, fill_count_start, fill_call). Both helpers are the wall helpers 0x6B07
# and 0x6C0E of the module-target note; the offsets are checked against the decoder's boundaries below.
SIZE_PAIRS = [
    ("main", 0x6B32, 0x6B39, 0x6B50, 0x6B5A),
    ("sub-shr2", 0x6BA2, 0x6BAA, 0x6BC9, 0x6BD4),
    ("sub-raw", 0x6BDB, 0x6BDE, 0x6BFD, 0x6C03),
]
WALL_HELPER_ENTRY = 0x6B07
VALUE_PUSH = b"\xb0\x00\x50"                     # mov al,0 ; push ax
DST_PUSH = b"\x06\x57"                            # push es ; push di

# ---- the two START callers (file offsets of the 9A far-call opcode) ----------------------------

FRAME_SITES = {
    0x227D: {"target": 0x023F, "role": "alloc-copy"},
    0x2268: {"target": 0x0254, "role": "release"},
}
# Allocation: `mov ax,0x3F; push ax` before the call; the result DX:AX saved to [bp-8]/[bp-6].
ALLOC_PRE = bytes.fromhex("b8 3f 00 50")
ALLOC_RESULT = bytes.fromhex("89 46 f8 89 56 fa")
# Copy into the new block (helper 0x1685: src.seg, src.off, dst.seg, dst.off, count), starting at site+11.
ALLOC_COPY = bytes.fromhex("c4 7e 06 06 57 c4 7e f8 06 57 b8 3f 00 50 9a 85 16 f8 0a")
# Link words of the new block cleared after the copy, at site+30 (les [bp-8]; xor ax,ax; two es stores).
ALLOC_LINK_ZERO = bytes.fromhex("c4 7e f8 31 c0 26 89 45 2a 26 89 45 2c")
# Release: far pointer pushed as seg then off from the frame's [bp+8]/[bp+6], size 0x3F, call 0x0254.
RELEASE_PRE = bytes.fromhex("ff 76 08 ff 76 06 b8 3f 00 50")
# The same block's link words cleared straight before the pushes: les di,[bp+6]; xor ax,ax; two es stores.
RELEASE_LINK_ZERO = bytes.fromhex("c4 7e 06 31 c0 26 89 45 2a 26 89 45 2c")
# Entry guard on the frame's first far pointer: mov ax,[bp+6]; or ax,[bp+8]; jnz (error path otherwise).
RELEASE_ENTRY_GUARD = bytes.fromhex("8b 46 06 0b 46 08 75 1a")
ENTRY_GUARD_AT = 6                                # after push bp; mov bp,sp; sub sp,imm8

NOT_ESTABLISHED = [
    "That the fill runs on any real path at any instant, or with which dst, count or value: the call sites are decoded, not executed.",
    "That the destination of each fill is the block the allocation returned: the bytes show the dst load chain, not the heap state.",
    "That a fill count larger than the block (or a zero count) occurs: only the count expression is compared with the allocation's.",
    "That DF stays clear across the call: the callee executes cld and does not restore the flag; the caller's assumption is not checked.",
    "Whether the two START frames pair at run time: they pair on size and pointer role only (static). The pointer the allocation frame stores at [bp-8] is not shown to be the pointer the release frame receives.",
    "Who calls the two frames: no near call to either entry exists in START and no far call with their offset was found, but indirect or cross-segment callers were not traced.",
    "That the list words (+200/+202 of the second argument, +42/+44 of blocks) form a list: the frames read and write them; the reading is not established.",
    "The runtime segment of START's code (no dump-level identity is claimed for the frames).",
]


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "little")


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def _need_pinned(pins: dict) -> None:
    mp._need_pinned(pins)


# ---- fill body and its layout ------------------------------------------------------------------

def fill_body_facts(exe: bytes, base_file: int) -> dict:
    start = base_file + FILL_OFF
    body = exe[start:start + len(FILL_BODY)]
    insns, stop = lp.linear(exe, start, 16, True)
    expected = []
    acc = 0
    for h, _ in FILL_STEPS:
        expected.append(acc)
        acc += len(bytes.fromhex(h))
    got = [i.off - start for i in insns]
    facts = {
        "module_offset": _hex(FILL_OFF),
        "file_offset": _hex(start),
        "template_matched": body == FILL_BODY,
        "decode_boundaries_match_template": got == expected,
        "decode_stop": stop,
        "steps": [{"at": _hex(start + e), "bytes": h, "text": t} for e, (h, t) in zip(expected, FILL_STEPS)],
        "last_insn": insns[-1].raw.hex(" ") if insns else None,
        "retf_imm": FILL_RETF_IMM,
        "layout_from_callee_sp": dict(FILL_LAYOUT),
        "copy_semantics": "memset-like: rep stosb of CX bytes, value = low byte of the word at sp+4, forward (cld)",
        "matched": body == FILL_BODY and got == expected and stop is None,
    }
    return facts


def _size_pair_row(exe: bytes, label: str, a_start: int, a_call: int, f_start: int, f_call: int,
                   boundaries: set) -> dict:
    alloc_expr = exe[a_start:a_call]
    fill_expr = exe[f_start:f_call - len(VALUE_PUSH)]
    row = {
        "label": label,
        "alloc_start": _hex(a_start), "alloc_call": _hex(a_call),
        "fill_count_start": _hex(f_start), "fill_call": _hex(f_call),
        "alloc_call_is_0x023F": exe[a_call:a_call + 5] == mp.call_bytes(0x023F),
        "fill_call_is_0x16A8": exe[f_call:f_call + 5] == mp.call_bytes(FILL_OFF),
        "value_push_zero": exe[f_call - len(VALUE_PUSH):f_call] == VALUE_PUSH,
        "dst_pushed_es_di": exe[f_start - len(DST_PUSH):f_start] == DST_PUSH,
        "alloc_expr": exe[a_start:a_call].hex(" "),
        "fill_expr": fill_expr.hex(" "),
        "count_expression_equal": alloc_expr == fill_expr and len(alloc_expr) > 0,
        "alloc_before_fill": a_call < f_start,
        "boundaries_ok": all(x in boundaries for x in (a_start, a_call, f_start, f_call)),
    }
    row["matched"] = all(row[k] for k in ("alloc_call_is_0x023F", "fill_call_is_0x16A8", "value_push_zero",
                                          "dst_pushed_es_di", "count_expression_equal", "alloc_before_fill",
                                          "boundaries_ok"))
    return row


def size_pairs(exe: bytes) -> dict:
    insns, _ = lp.linear(exe, WALL_HELPER_ENTRY, 0x400, True)
    boundaries = {i.off for i in insns}
    rows = [_size_pair_row(exe, *p, boundaries) for p in SIZE_PAIRS]
    return {"helper_entry": _hex(WALL_HELPER_ENTRY), "rows": rows,
            "all_matched": all(r["matched"] for r in rows)}


# ---- START callers ---------------------------------------------------------------------------

def enclosing_frame(exe: bytes, site: int, lookback: int = 0x800) -> Optional[int]:
    """The nearest prologue before `site` whose linear decode (to the first ret) reaches `site` on a boundary."""
    for s in range(site - 1, max(-1, site - lookback), -1):
        if exe[s:s + 3] in PROLOGUES:
            insns, _ = lp.linear(exe, s, 0x800, True)
            if any(i.off == site for i in insns):
                return s
    return None


def _run_ok(insns: list, a: int, b: int, boundaries: set) -> bool:
    """A run [a, b] is straight-line when its ends are boundaries and no branch target lies in (a, b]."""
    targets = {i.target for i in insns if i.target is not None and i.flow in ("jcc", "jmp")}
    return a in boundaries and b in boundaries and not any(a < t <= b for t in targets)


def frame_facts(exe: bytes, site: int, target: int, role: str) -> dict:
    entry = enclosing_frame(exe, site)
    row = {"site": _hex(site), "target": _hex(target), "role_by_bytes": role,
           "call_bytes_match": exe[site:site + 5] == mp.call_bytes(target)}
    if entry is None:
        row.update({"enclosing_entry": None, "matched": False, "reason": "no prologue reaches the site"})
        return row
    insns, stop = lp.linear(exe, entry, 0x800, True)
    boundaries = {i.off for i in insns}
    bp_args = sorted({i.bp_disp for i in insns if i.bp_disp is not None and i.bp_disp > 0})
    retf = _u16(insns[-1].raw, 1) if insns and insns[-1].flow == "retf" else None
    row.update({
        "enclosing_entry": _hex(entry),
        "entry_prologue": exe[entry:entry + 3].hex(" "),
        "frame_stop": stop,
        "frame_bp_args": bp_args,
        "frame_retf_imm": retf,
        # The decoder reports each operand's displacement only (les [bp+10] shows 10, not its segment word at 12),
        # so the two far pointers are read from retf 8 plus operands at [bp+6] and [bp+10] inside the 6..12 span.
        "frame_args_are_two_far_pointers": (retf == 8 and set(bp_args) <= {6, 8, 10, 12}
                                            and {6, 10} <= set(bp_args)),
        "entry_guard_on_first_pointer": exe[entry + ENTRY_GUARD_AT:entry + ENTRY_GUARD_AT + len(RELEASE_ENTRY_GUARD)]
                                        == RELEASE_ENTRY_GUARD,
    })
    if role == "alloc-copy":
        pre = exe[site - len(ALLOC_PRE):site]
        row["size_imm"] = _u16(pre, 1) if pre == ALLOC_PRE else None
        row["pre_call_matched"] = pre == ALLOC_PRE
        row["result_stored_to"] = "[bp-8]:[bp-6]" if exe[site + 5:site + 5 + len(ALLOC_RESULT)] == ALLOC_RESULT else None
        copy_at = site + 11
        row["copy_run_matched"] = exe[copy_at:copy_at + len(ALLOC_COPY)] == ALLOC_COPY
        row["copy_size_imm"] = _u16(ALLOC_COPY, 11) if row["copy_run_matched"] else None
        row["copy_src"] = "[bp+6]:[bp+8] (first frame argument)" if row["copy_run_matched"] else None
        row["copy_dst"] = "[bp-8]:[bp-6] (the allocation result)" if row["copy_run_matched"] else None
        zero_at = site + 30
        row["link_zero_matched"] = exe[zero_at:zero_at + len(ALLOC_LINK_ZERO)] == ALLOC_LINK_ZERO
        row["straight_line_copy_run"] = _run_ok(insns, site - 4, zero_at, boundaries)
        row["matched"] = bool(row["pre_call_matched"] and row["call_bytes_match"]
                              and row["result_stored_to"] and row["copy_run_matched"]
                              and row["link_zero_matched"] and row["straight_line_copy_run"]
                              and row["size_imm"] == SIZE and row["copy_size_imm"] == SIZE
                              and row["frame_args_are_two_far_pointers"])
        row["size_imm_expected"] = SIZE
    else:
        pre = exe[site - len(RELEASE_PRE):site]
        row["pre_call_matched"] = pre == RELEASE_PRE
        # ff 76 08 (push [bp+8]) ; ff 76 06 (push [bp+6]) ; b8 3f 00 50 (mov ax,0x3f; push ax)
        row["size_imm"] = _u16(pre, 7) if row["pre_call_matched"] else None
        row["pointer_pushed"] = ({"seg": "[bp+%d]" % pre[2], "off": "[bp+%d]" % pre[5]}
                                 if row["pre_call_matched"] else None)
        row["pointer_source"] = ("frame argument 1 ([bp+6] offset, [bp+8] segment)"
                                 if row["pre_call_matched"] and pre[2] == 8 and pre[5] == 6 else None)
        zero_at = site - 23
        row["link_zero_matched"] = exe[zero_at:zero_at + len(RELEASE_LINK_ZERO)] == RELEASE_LINK_ZERO
        row["straight_line_release_run"] = _run_ok(insns, zero_at, site, boundaries)
        row["matched"] = bool(row["pre_call_matched"] and row["call_bytes_match"]
                              and row["link_zero_matched"] and row["straight_line_release_run"]
                              and row["size_imm"] == SIZE and row["pointer_source"] is not None
                              and row["frame_args_are_two_far_pointers"] and row["entry_guard_on_first_pointer"])
        row["size_imm_expected"] = SIZE
    return row


def pair_verdict(alloc: dict, release: dict) -> dict:
    size_ok = alloc.get("size_imm") == SIZE and release.get("size_imm") == SIZE
    alloc_ok = bool(alloc.get("matched"))
    release_ok = bool(release.get("matched"))
    return {
        "size_equal_both_frames": size_ok,
        "alloc_frame_shape": alloc_ok,
        "release_frame_shape": release_ok,
        "shapes_pair_on_size_and_pointer_role": bool(size_ok and alloc_ok and release_ok),
        "pointer_identity_between_frames": "not-established",
    }


def static_callers(exe: bytes, ovr: bytes, entries: list[int]) -> dict:
    out = {}
    for e in entries:
        near = [k for k in range(len(exe) - 2)
                if exe[k] == 0xE8 and k + 3 + int.from_bytes(exe[k + 1:k + 3], "little", signed=True) == e]
        seg_free = e.to_bytes(2, "little")
        far_start = sum(1 for k in range(len(exe) - 4) if exe[k] == 0x9A and exe[k + 1:k + 3] == seg_free)
        far_ovr = sum(1 for k in range(len(ovr) - 4) if ovr[k] == 0x9A and ovr[k + 1:k + 3] == seg_free)
        out[_hex(e)] = {"near_call_sites_in_START": [_hex(k) for k in near],
                        "far_calls_with_this_offset": {"START.EXE": far_start, "GAME.OVR": far_ovr},
                        "note": "same-segment near calls compared in file space; far calls match the offset only"}
    return out


# ---- identity of the fill target in the dumps --------------------------------------------------

def fill_identity(exe: bytes, base_file: int, dumps: list[dict]) -> dict:
    per_dump = []
    for d in dumps:
        per_dump.append({"dump": d["label"], "load_seg": _hex(d["load"]),
                         "window": mp._window_row(exe, base_file, FILL_OFF, d["dump"], d["load"])})
    states = [r["window"]["state"] for r in per_dump]
    good = bool(states) and all(s == "memory-agrees-unique-placement" for s in states)
    return {"verdict": "identified-by-bytes-in-pinned-dumps" if good else "unresolved",
            "per_dump": per_dump}


# ---- top level --------------------------------------------------------------------------------

def probe(install: Path, dump_paths: list[Path]) -> dict:
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = gcp.check_pins(ovr, exe)
    _need_pinned(pins)
    base_file = gcp.handler_base(exe)["base_file"]
    dumps, dump_meta = [], []
    for dp in dump_paths:
        if not dp.exists():
            raise Refusal("dump not found: %s" % dp)
        raw = dp.read_bytes()
        lin_base = om.resolve_dump_base(dp.name, len(raw), None)
        dump = om.Dump(raw, lin_base)
        mod = gcp.dump_module(dump, exe, base_file)
        if mod.get("status") != "unique" or mod.get("load_seg") != EXPECT_LOAD:
            raise Refusal("module anchor in %s is not a unique load 0x%04X: %s" % (dp.parent.name, EXPECT_LOAD, mod))
        label = "%s/%s" % (dp.parent.name, dp.name)
        dumps.append({"label": label, "dump": dump, "load": mod["load_seg"]})
        dump_meta.append({"label": label, "sha256_prefix": gcp._sha(raw)[:16], "dump_base": _hex(lin_base),
                          "module_anchor": mod})
    body = fill_body_facts(exe, base_file)
    ident = fill_identity(exe, base_file, dumps)
    pairs = size_pairs(exe)
    frames = {_hex(site): frame_facts(exe, site, spec["target"], spec["role"])
              for site, spec in FRAME_SITES.items()}
    alloc = next(v for v in frames.values() if v.get("role_by_bytes") == "alloc-copy")
    release = next(v for v in frames.values() if v.get("role_by_bytes") == "release")
    pair = pair_verdict(alloc, release)
    entries = sorted({int(v["enclosing_entry"], 16) for v in frames.values() if v.get("enclosing_entry")})
    checks = {
        "fill_body": body["matched"],
        "fill_identity": ident["verdict"] == "identified-by-bytes-in-pinned-dumps",
        "size_pairs": pairs["all_matched"],
        "frames": all(v.get("matched") for v in frames.values()),
        "pair": pair["shapes_pair_on_size_and_pointer_role"],
    }
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL, "status_scope": STATUS_SCOPE,
        "playable": False,
        "inputs": {"pins": pins, "dumps": dump_meta},
        "module": {"file_base": _hex(base_file), "module_segment": _hex(MODULE_SEG),
                   "load_segment_measured": _hex(EXPECT_LOAD),
                   "basis": "module-target probe (routine-B pattern and dump anchor); this probe reuses it"},
        "fill_body": body,
        "fill_identity": ident,
        "fill_size_pairs": pairs,
        "start_callers": frames,
        "pair": pair,
        "static_callers": static_callers(exe, ovr, entries),
        "call_site_counts": {
            "0x16A8": {"START.EXE": len(gcp._positions(exe, mp.call_bytes(FILL_OFF))),
                       "GAME.OVR": len(gcp._positions(ovr, mp.call_bytes(FILL_OFF)))},
        },
        "checks": checks,
        "not_established": NOT_ESTABLISHED,
        "verdict": ("0x16A8 is a rep-stosb fill of CX bytes with the low byte of its value word; the three "
                    "wall-helper fill counts equal their allocation sizes; the START frames pair on size "
                    "0x3F and pointer role (static)" if all(checks.values()) else
                    "not all checks matched; see fill_body, fill_identity, fill_size_pairs, start_callers, pair"),
        "executed": "not_established",
        "playable_claim": False,
    }
    return doc


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_wall_0111_fill_callers_probe.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Fill 0x0AF8:0x16A8 and the two START callers of 0x023F/0x0254.")
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
    print("wrote %s (checks=%s)" % (args.out, doc["checks"]))
    return 0 if all(doc["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
