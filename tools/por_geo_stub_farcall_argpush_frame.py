#!/usr/bin/env python3
"""Static caller-frame check of the nine argument-push-shape sites (observe-only, shape comparison).

Follow-up to tools/por_geo_stub_farcall_argpush_shape.py. That tool found nine strong residue-compatible
far calls whose ten pushed bytes match the GEO loader's shape. All nine call segment 0085 offset 005C.
The loader's far target is 0802:0716. So the nine are NOT established as loader calls. This tool asks one
narrower question: do their caller frames account for the stack the way the walked loader frames do?

For each site it runs the caller-frame probe's own walk (`por_geo_loader_caller_frame_probe.Walk`) from the
enclosing prologue to the start of the ten-byte shape, and reports:

1. the allocation (`sub sp`) and the leftover words the caller pushed before the shape and did not pop;
2. the shape's pushed words (id form, far-pointer displacements);
3. the pops of the far callees the walk passes through. Their segment bases are NOT established (the census
   carries the DI as unknown), so each unknown callee is a symbolic parameter K (its retf count, in bytes),
   swept over a word-aligned grid. One parameter per unknown seg:off, shared by every site that calls it:
     K_a = 0085:005C (the target of all nine sites)
     K_c = 03C5:0039 (window of sites 0x1820A, 0x182A0, 0x18422, 0x1861E)
     K_d = 0709:0D68 and K_f = 0085:0057 (window of site 0x1C900)

With callee pop K at a site's own call, the caller's SP sits K - 10 - L bytes above its allocation floor
(L = the leftover at the shape start). The frame balances exactly when K = 10 + L. That is a REQUIREMENT on
the unknown K, not evidence of it. The loader's retf 0x12 is never applied to these sites: 0802:0716 is not
their target, and the loader's resolver is replaced by "unknown" inside these walks.

Nothing here says the sites run, that any callee is a particular body, what any callee pops, or what any
pointer holds. Read-only: it reads the pinned GAME.OVR and START.EXE and writes only under data/work/.

Usage:
    python -I tools/por_geo_stub_farcall_argpush_frame.py [--install PATH/TO/POOLRAD] \
        [-o data/work/por-geo-stub-farcall-argpush-frame]

Exit: 0 the probe ran (its verdict may be unresolved; that is the result); 2 a named refusal (unpinned input,
the site set differs from the expected nine, or output outside data/work or inside the install).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Callable, Optional

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import por_farcall_resolve as fr  # noqa: E402
import por_overlay_group_map as om  # noqa: E402
import por_geo_callee_identity_probe as gcp  # noqa: E402
import por_geo_loader_caller_frame_probe as L  # noqa: E402
import por_geo_stub_farcall_argpush_shape as A  # noqa: E402

SCHEMA = "openua.por-geo-stub-farcall-argpush-frame"
SCHEMA_VERSION = 1
STATUS = "static-frame-probe-only"
TOOL = "tools/por_geo_stub_farcall_argpush_frame.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_WORK = REPO_ROOT / "data" / "work"
DEFAULT_OUT = DATA_WORK / "por-geo-stub-farcall-argpush-frame"
DEFAULT_INSTALL = DATA_WORK / "por-geo-run" / "POOLRAD"
RESULT_JSON = "por_geo_stub_farcall_argpush_frame.json"
RESULT_MD = "por_geo_stub_farcall_argpush_frame.md"
OVR_NAME, EXE_NAME = fr.OVR_NAME, fr.EXE_NAME
Refusal = om.Refusal

SHAPE_BYTES = 10                                 # id word + two far pointers, as in the loader probe
TARGET = (0x0085, 0x005C)                        # callee of all nine sites; segment base NOT established
CALLEE_C = (0x03C5, 0x0039)                      # unknown far callee in the windows of 0x1820A..0x1861E and 0x18422
CALLEE_G = (0x00BA, 0x16EC)                      # unknown far callee in the windows of 0x1820A, 0x182A0, 0x1861E
LOADER = (0x0802, 0x0716)                        # GEO loader identity: never applied to these sites

# Parameter name -> callee. The same seg:off shares one parameter across every site that calls it.
PARAMS = {TARGET: "K_a", CALLEE_C: "K_c", CALLEE_G: "K_g"}
# Sites swept exactly: every unknown callee in the window is a parameter (static enumeration of the linear
# window, every 9A, is recorded per site and checked). Sites with more than SWEEP_AUX_MAX auxiliary unknown
# callees are not swept (their windows hold too many unknowns for a grid) and are reported as such.
SWEEP_AUX_MAX = 2
SITE_PARAMS = {
    0x14C4E: (TARGET,), 0x17D07: (TARGET,), 0x18168: (TARGET,), 0x183B9: (TARGET,),
    0x18422: (TARGET, CALLEE_C),
    0x1820A: (TARGET, CALLEE_C, CALLEE_G), 0x182A0: (TARGET, CALLEE_C, CALLEE_G),
}
UNSWEPT_REASON = {
    0x1861E: "window holds 4 auxiliary unknown callees (03C5:0039, 00BA:16EC, 00BA:1693, 0096:003E); "
             "above the sweep limit of %d" % SWEEP_AUX_MAX,
    0x1C900: "window holds 9 auxiliary unknown callees and a backward branch (loop) at 0x1C602, which the "
             "existing walk fails closed on; above the sweep limit of %d" % SWEEP_AUX_MAX,
}
K_GRID_A = list(range(0, 0x41, 2))               # K_a: the target's pop, word-aligned, 0..0x40
K_GRID_X = list(range(0, 0x21, 2))               # the other unknown pops, word-aligned, 0..0x20

# The exact census-site set from the argpush-shape handoff (verified against a fresh analysis before use).
EXPECT_SITES = {
    # at        owner     id-imm  lea displacements (nearest first)
    0x14C4E: (0x127FB, 1, (-6, -5)),
    0x17D07: (0x17831, 1, (-3, -2)),
    0x18168: (0x17831, 0, (-2, -7)),
    0x1820A: (0x17831, 2, (-2, -7)),
    0x182A0: (0x17831, 0, (-2, -7)),
    0x183B9: (0x17831, 0, (-2, -8)),
    0x18422: (0x17831, 3, (-2, -8)),
    0x1861E: (0x17831, 0, (-2, -8)),
    0x1C900: (0x1997F, 4, (-28, -27)),
}
EXPECT_CENSUS = {"candidates": 181, "strong": 166, "analysed": 166, "loader_shape_imm": 9,
                 "loader_shape_documented": 0, "mismatches": 0}

NOT_ESTABLISHED = [
    "that any of the nine sites runs, or that any call at them is executed at any instant",
    "that 0085:005C is the GEO loader, the GEO stub, or any body in the census: its segment base is not established",
    "the pops of 0085:005C, 03C5:0039 and 00BA:16EC: swept as hypotheses only where a site's window is small enough; "
    "every other unknown callee (0709:0D68, 0085:0057, 0096:003E, 00BA:1693, and others) is unswept and unread",
    "that any shape id word, pushed pointer, or leftover word holds a GEO, block, or area value",
    "that the walk's leftover model matches the live stack: the dumps and the census carry no SS or SP",
    "any binding of the nine sites to a GEO archive, block, plane 2, or descriptor",
]

DISCRIMINATORS = [
    "A live capture at the first of the nine sites (GAME.OVR 0x14C4E) before its 9A: the words at SP are the "
    "shape and, below them, one leftover word. The frame requires the callee to pop 12 bytes there (K = 10 + L).",
    "A live capture of 0085:005C at its first instruction and after its retf: the stack difference gives its "
    "retf count K directly. A K other than the joint set falsifies the single-callee premise.",
    "A segment-base establishment for segments 0085 and 03C5 and 0709 (a DI or paragraph fact). That would turn "
    "each sweep into a read of the callee's own retf count from its bytes.",
    "A model of the loops inside the windows of 0x182A0 (backward branches 0x18263->0x1824E and 0x18282->0x181B8) "
    "and 0x1C900 (0x1C602->0x1C3BB and others). The existing walk fails closed on backward branches, so those sites "
    "have no walkable hypothesis or are unswept and remain undecided.",
]


# ---- helpers ------------------------------------------------------------------------------------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def check_out(out: Path, install: Path) -> None:
    if _inside(out, install):
        raise Refusal("output %s lies inside the install; refusing" % out)
    if not _inside(out, DATA_WORK):
        raise Refusal("output %s is outside data/work; refusing" % out)


def hashes(install: Path) -> dict:
    return {name: _sha((install / name).read_bytes()) for name in (OVR_NAME, EXE_NAME)}


def u16(img: bytes, p: int) -> int:
    return img[p] | (img[p + 1] << 8)


def site_target(img: bytes, at: int) -> tuple[int, int]:
    """Operand of the far call at `at` (opcode 9A, off16, seg16)."""
    if img[at] != 0x9A:
        raise Refusal("site 0x%05X is not a 9A far call (byte 0x%02X)" % (at, img[at]))
    return u16(img, at + 3), u16(img, at + 1)


def verify_site_set(rows: list[dict]) -> dict:
    """Refuse unless the fresh census analysis reproduces the expected nine sites exactly."""
    got = {int(r["at"], 16): r for r in rows}
    if set(got) != set(EXPECT_SITES):
        raise Refusal("site set differs from the expected nine: extra %s, missing %s" % (
            sorted("0x%05X" % a for a in set(got) - set(EXPECT_SITES)),
            sorted("0x%05X" % a for a in set(EXPECT_SITES) - set(got))))
    for at, (owner, imm, lea) in EXPECT_SITES.items():
        r = got[at]
        if (int(r["owner_fileofs"], 16), r["id_operand"], tuple(r["lea_bp_disp"])) != (owner, imm, lea):
            raise Refusal("site 0x%05X row differs from the expected owner/id/lea" % at)
        if r["shape_class"] != A.CLS_IMM or not r["clean_shape"]:
            raise Refusal("site 0x%05X is not a clean imm-id loader-shape site" % at)
    return {"sites": ["0x%05X" % a for a in sorted(got)], "count": len(got)}


def census_counts(doc: dict) -> dict:
    t = doc["totals"]
    return {"candidates": t["census_candidate_sites"], "strong": t["strong_candidate_sites"],
            "analysed": t["analysed_strong_sites"], "loader_shape_imm": t["loader_shape_imm_id"],
            "loader_shape_documented": t["loader_shape_documented_id"],
            "mismatches": len(doc["mismatches"])}


def resolver_for(exe: bytes, params: dict) -> Callable[[int, int], Optional[dict]]:
    """The caller-frame resolver with the unknown callees replaced by the given hypotheses.

    `params` maps a seg:off to its hypothesised retf count. Any other unknown callee is None (unknown), and the
    loader is always None: its 0x12 is never borrowed for these sites.
    """
    base = L.make_resolver(exe)

    def resolve(seg: int, off: int) -> Optional[dict]:
        key = (seg, off)
        if key in params:
            return {"retf": params[key], "conditional": False, "file": None,
                    "source": "hypothesis (segment %04X base not established)" % seg}
        if key == LOADER:
            return None
        if key in PARAMS:
            return None
        return base(seg, off)
    return resolve


def classify_failure(fail: str) -> str:
    if "consumes below" in fail:
        return "infeasible-over-pop"
    if fail.startswith("unknown callee"):
        return "unknown-callee"
    if fail.startswith("branch into") or "different depths" in fail:
        return "join-depth-mismatch"
    if fail.startswith("backward branch"):
        return "loop-not-modelled"
    if "is not modelled" in fail:
        return "unmodelled-stack-op"
    return "other"


MEM_PUSH_OPS = (0xFF,)                           # FF /6 = push r/m16; the existing Walk does not count it
UNMODELLED_STACK_OPS = (0x68, 0x6A, 0x9C, 0x9D, 0x60, 0x61, 0xC8, 0xC9)


class FrameWalk(L.Walk):
    """The caller-frame probe's Walk, plus the one push form it ignores: `push r/m16` (FF /6).

    The existing Walk counts register and segment pushes only, so a memory push (for example `push [0x5D94]`)
    leaves its word out of the leftover. Left uncounted, a later `retf 4` consumes the wrong words, and the walk
    then reports a join mismatch that is an artefact of the model. This subclass counts FF /6 as a word push.
    Any other stack-touching form the walk does not model (`pop r/m`, `pushf`, `push imm`, `pusha`, `enter`,
    `leave`) fails the walk closed. The existing module is not changed.
    """

    def _track_write(self, p: int, i) -> None:
        if i.op in MEM_PUSH_OPS and i.modrm is not None and i.modrm[1] == 6:
            self._push("mem", p, i.text())
            return
        if i.op == 0x8F:
            self.fail = "pop r/m16 at 0x%05X is not modelled" % p
            return
        if i.op in UNMODELLED_STACK_OPS:
            self.fail = "stack op 0x%02X at 0x%05X is not modelled" % (i.op, p)
            return
        super()._track_write(p, i)


def stack_op_scan(img: bytes, at: int) -> Optional[dict]:
    """Stack-touching forms in the linear window from the procedure's prologue to the shape (for the record)."""
    proc, _ = L.find_proc(img, at)
    sh = L.shape_start(img, at)
    if proc is None or sh is None:
        return None
    counts = {"push-r/m16 (FF /6)": 0, "pop-r/m16 (8F)": 0, "unmodelled": 0}
    p = proc + 1
    i = L._decode(img, p)
    if i is None:
        return None
    p = i.end
    while p < sh:
        i = L._decode(img, p)
        if i is None:
            return None
        if i.op in MEM_PUSH_OPS and i.modrm is not None and i.modrm[1] == 6:
            counts["push-r/m16 (FF /6)"] += 1
        elif i.op == 0x8F:
            counts["pop-r/m16 (8F)"] += 1
        elif i.op in UNMODELLED_STACK_OPS:
            counts["unmodelled"] += 1
        p = i.end
    return counts


def walk_site(ovr: bytes, exe: bytes, at: int, params: dict) -> dict:
    proc, valid = L.find_proc(ovr, at)
    rec = {"proc": None if proc is None else "0x%05X" % proc}
    if proc is None:
        rec.update({"walk_ok": False, "fail": "no enclosing prologue"})
        return rec
    w = FrameWalk(ovr, proc, at, resolver_for(exe, params))
    w.run()
    rec["walk_ok"] = w.fail is None and w.snapshot is not None
    rec["fail"] = w.fail
    if rec["walk_ok"]:
        snap = w.snapshot
        rec["alloc"] = snap["alloc"]
        rec["leftover_bytes"] = sum(s.get("size", 2) for s in snap["slots"])
        rec["leftover_top_first"] = [{"at": "0x%05X" % s["at"], "reg": s["reg"], "prov": s["prov"]}
                                     for s in reversed(snap["slots"])]
        rec["leftover_pairs_top_first"] = L.leftover_pairs(list(reversed(snap["slots"])))
    return rec


def bytes_above_floor(K: int, leftover: int) -> int:
    """Bytes the caller's SP sits above its allocation floor after the call (0 = balanced)."""
    return K - SHAPE_BYTES - leftover


def _grids_for(names: list[str]) -> list[dict]:
    """Every assignment of word-aligned values to the named parameters (K_a has its own, larger grid)."""
    combos: list[dict] = [{}]
    for name in names:
        grid = K_GRID_A if name == "K_a" else K_GRID_X
        combos = [dict(c, **{name: v}) for c in combos for v in grid]
    return combos


def unswept_record(ovr: bytes, at: int) -> dict:
    """A site whose window is too large for the grid. No balance is claimed for it."""
    proc, _ = L.find_proc(ovr, at)
    return {"swept": False, "proc": None if proc is None else "0x%05X" % proc, "parameters": [],
            "reason": UNSWEPT_REASON[at], "hypotheses": 0, "walk_ok": 0, "walk_failed_by_reason": {},
            "allocation_bytes_seen": [], "leftover_bytes_seen": [], "balanced_count": 0, "balanced_K": []}


def sweep_site(ovr: bytes, exe: bytes, at: int) -> dict:
    """Walk one site under every hypothesis for its own unknown callees; record balance and failures."""
    callees = SITE_PARAMS[at]
    names = [PARAMS[c] for c in callees]
    fail_counts: dict[str, int] = {}
    ok_rows: list[dict] = []
    proc = None
    alloc_seen: set[int] = set()
    for combo in _grids_for(names):
        params = {c: combo[PARAMS[c]] for c in callees}
        r = walk_site(ovr, exe, at, params)
        proc = r.get("proc", proc)
        if not r["walk_ok"]:
            key = classify_failure(r["fail"] or "unknown")
            fail_counts[key] = fail_counts.get(key, 0) + 1
            continue
        alloc_seen.add(r["alloc"])
        K_a = combo["K_a"]
        above = bytes_above_floor(K_a, r["leftover_bytes"])
        ok_rows.append({"K": {k: v for k, v in combo.items()}, "leftover_bytes": r["leftover_bytes"],
                        "bytes_above_floor": above, "balanced": above == 0})
    balanced = [row for row in ok_rows if row["balanced"]]
    return {
        "swept": True,
        "proc": proc,
        "parameters": names,
        "hypotheses": len(_grids_for(names)),
        "walk_ok": len(ok_rows),
        "walk_failed_by_reason": dict(sorted(fail_counts.items())),
        "allocation_bytes_seen": sorted(alloc_seen),
        "leftover_bytes_seen": sorted({row["leftover_bytes"] for row in ok_rows}),
        "balanced_count": len(balanced),
        "balanced_K": balanced,              # the full set of hypotheses that balance this frame
    }


def static_far_callees(img: bytes, exe: bytes, at: int) -> list[dict]:
    """Every 9A in the linear window (prologue to shape), with its target and whether a base is established.

    Control flow is ignored on purpose: this lists the callees a path could reach, so it bounds the parameters.
    """
    proc, _ = L.find_proc(img, at)
    sh = L.shape_start(img, at)
    if proc is None or sh is None:
        return []
    out: list[dict] = []
    p = proc + 1
    i = L._decode(img, p)
    if i is None:
        return []
    p = i.end
    base = L.make_resolver(exe)
    while p < sh:
        i = L._decode(img, p)
        if i is None:
            break
        if i.op == 0x9A:
            out.append({"at": "0x%05X" % p, "target": "%04X:%04X" % i.far,
                        "base": "known" if base(*i.far) else "unknown"})
        p = i.end
    return out


def backward_branches(img: bytes, at: int) -> list[str]:
    """Branches inside the window whose target is at or before the branch (a loop as far as this walk can tell)."""
    proc, _ = L.find_proc(img, at)
    sh = L.shape_start(img, at)
    if proc is None or sh is None:
        return []
    out, p = [], proc + 1
    i = L._decode(img, p)
    p = i.end if i else sh
    while p < sh:
        i = L._decode(img, p)
        if i is None:
            break
        if i.flow in ("jcc", "jmp") and i.target is not None and proc < i.target < sh and i.target <= p:
            out.append("0x%05X->0x%05X" % (p, i.target))
        p = i.end
    return out


def joint_over_swept(sweeps: dict) -> dict:
    """Joint hypotheses (K_a, K_c, K_g) under which every DECIDED site balances at once.

    A site is decided when at least one hypothesis for it walks (so the frame can be balanced or refuted). A site
    with no walkable hypothesis, or one that is not swept, is UNDECIDED: it is listed, and it is not refuted.
    Each decided site balances on a projection of the joint tuple onto its own parameters; a tuple is kept only
    if every decided site's projection is in that site's balanced set.
    """
    grid = {"K_a": K_GRID_A, "K_c": K_GRID_X, "K_g": K_GRID_X}
    decided: dict = {}
    undecided: dict = {}
    for at, sw in sweeps.items():
        if not sw.get("swept"):
            undecided["0x%05X" % at] = sw["reason"]
        elif sw["walk_ok"] == 0:
            fails = ", ".join("%s %d" % (k, n) for k, n in sw["walk_failed_by_reason"].items())
            undecided["0x%05X" % at] = "no walkable hypothesis (%s)" % fails
        else:
            cols = sw["parameters"]
            decided[at] = (cols, {tuple(row["K"][c] for c in cols) for row in sw["balanced_K"]})
    joint = []
    if decided:
        for ka in grid["K_a"]:
            for kc in grid["K_c"]:
                for kg in grid["K_g"]:
                    vals = {"K_a": ka, "K_c": kc, "K_g": kg}
                    if all(tuple(vals[c] for c in cols) in bset for cols, bset in decided.values()):
                        joint.append(vals)
    joint_ka = sorted({j["K_a"] for j in joint})
    return {
        "decided_sites": ["0x%05X" % a for a in sorted(decided)],
        "undecided_sites": undecided,
        "joint_tuple_count": len(joint),
        "joint_examples": [{k: "0x%02X" % v for k, v in j.items()} for j in joint[:16]],
        "joint_K_a_over_decided_sites": ["0x%02X" % k for k in joint_ka],
    }


def control_row(exe: bytes, img_name: str, img: bytes, at: int) -> dict:
    """The loader's own walked site under the same walk, with the loader's 0x12 (control only, not applied above).

    Run under the existing Walk and under FrameWalk: the two must agree, because these windows hold no FF /6.
    """
    proc, _ = L.find_proc(img, at)
    w = L.Walk(img, proc, at, L.make_resolver(exe))
    w.run()
    f = FrameWalk(img, proc, at, L.make_resolver(exe))
    f.run()
    if not (w.fail is None and w.snapshot):
        return {"image": img_name, "site": "0x%05X" % at, "walk_ok": False, "fail": w.fail}
    lo = sum(s.get("size", 2) for s in w.snapshot["slots"])
    lo_f = sum(s.get("size", 2) for s in f.snapshot["slots"]) if (f.fail is None and f.snapshot) else None
    above = bytes_above_floor(L.TARGET_RETF, lo)
    return {"image": img_name, "site": "0x%05X" % at, "walk_ok": True, "leftover_bytes": lo,
            "frame_walk_leftover_bytes": lo_f, "frame_walk_agrees": lo_f == lo,
            "stack_op_counts": stack_op_scan(img, at),
            "bytes_above_floor_with_loader_K": above, "balanced_with_loader_K": above == 0}


# ---- top level ------------------------------------------------------------------------------

def probe(install: Path, out: Path) -> tuple[dict, int]:
    check_out(out, install)
    for name in (OVR_NAME, EXE_NAME):
        if not (install / name).is_file():
            raise Refusal("%s not found in %s; the pinned install is required" % (name, install))
    before = hashes(install)
    ovr = (install / OVR_NAME).read_bytes()
    exe = (install / EXE_NAME).read_bytes()
    pins = L.check_pins(ovr, exe)                    # refuses unpinned input
    census_doc = A.analyse(exe, ovr)                 # the argpush-shape tool's own analysis (read-only)
    site_set = verify_site_set(census_doc["loader_shape_rows"])
    counts = census_counts(census_doc)
    if counts != EXPECT_CENSUS:
        raise Refusal("census counts differ from the expected handoff: %s" % counts)

    groups = gcp.all_groups(exe, ovr)
    sweeps: dict[int, dict] = {}
    site_rows = []
    for at in sorted(EXPECT_SITES):
        seg, off = site_target(ovr, at)
        owner_expect = EXPECT_SITES[at][0]
        shape_at = L.shape_start(ovr, at)
        sw = sweep_site(ovr, exe, at) if at in SITE_PARAMS else unswept_record(ovr, at)
        sweeps[at] = sw
        proc_val = int(sw["proc"], 16) if sw["proc"] else None
        owner = gcp.owner_group(groups, proc_val) if proc_val is not None else None
        static = static_far_callees(ovr, exe, at)
        site_rows.append({
            "at": "0x%05X" % at,
            "opcode": "0x%02X" % ovr[at],
            "target": "%04X:%04X" % (seg, off),
            "target_is_loader_identity": (seg, off) == LOADER,
            "target_is_0085_005C": (seg, off) == TARGET,
            "shape_start": None if shape_at is None else "0x%05X" % shape_at,
            "owner_expected": "0x%X" % owner_expect,
            "owner_of_walked_proc": None if owner is None else "0x%X" % owner["fileofs"],
            "owner_matches_expected": owner is not None and owner["fileofs"] == owner_expect,
            "static_far_callees_in_window": static,
            "static_unknown_callees": sorted({s["target"] for s in static if s["base"] == "unknown"}),
            "backward_branches_in_window": backward_branches(ovr, at),
            "sweep": sw,
        })

    joint = joint_over_swept(sweeps)
    controls = [control_row(exe, OVR_NAME, ovr, 0x2F767), control_row(exe, EXE_NAME, exe, 0x07276)]
    after = hashes(install)
    if not joint["joint_tuple_count"]:
        frame_status = "no-joint-hypothesis-balances-the-decided-sites; %d site(s) undecided" % len(
            joint["undecided_sites"])
    elif joint["undecided_sites"]:
        frame_status = "joint-consistent-on-decided-sites-requirement-only; %d site(s) undecided" % len(
            joint["undecided_sites"])
    else:
        frame_status = "joint-consistent-requirement-only"
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS, "tool": TOOL,
        "playable": False, "established": False, "mappings": [],
        "question": ("Do the caller frames of the nine argument-push-shape sites (all calling 0085:005C) "
                     "account for their stack the way the walked GEO loader frames do?"),
        "pins": pins,
        "inputs_hashes_before": before, "inputs_hashes_after": after,
        "census_expected": EXPECT_CENSUS, "census_counts": counts,
        "site_set": site_set,
        "hypothesis_grid": {"K_a": "0x00..0x40 step 2", "other_unknown_pops": "0x00..0x20 step 2",
                            "formula": "bytes_above_floor = K - 10 - L; balanced iff K = 10 + L"},
        "parameters": {PARAMS[k]: "0x%04X:0x%04X" % k for k in PARAMS},
        "sites": site_rows,
        "sites_stack_ops": {"0x%05X" % a: stack_op_scan(ovr, a) for a in sorted(EXPECT_SITES)},
        "static_window_callees_checked": True,
        "joint": joint,
        "control_loader_sites": controls,
        "summary": {
            "sites_total": len(site_rows),
            "target_0085_005C": sum(1 for r in site_rows if r["target_is_0085_005C"]),
            "owner_mismatches": [r["at"] for r in site_rows if not r["owner_matches_expected"]],
            "decided_sites": joint["decided_sites"],
            "undecided_sites": joint["undecided_sites"],
            "sites_balancing_some_hypothesis": ["0x%05X" % a for a, s in sweeps.items() if s["balanced_count"]],
            "decided_sites_with_no_balancing_hypothesis": ["0x%05X" % a for a, s in sweeps.items()
                                                           if s["walk_ok"] and not s["balanced_count"]],
            "joint_K_a_over_decided_sites": joint["joint_K_a_over_decided_sites"],
            "joint_tuple_count": joint["joint_tuple_count"],
        },
        "verdict": {
            "callee_pop_0085_005C": "unresolved (segment base not established)",
            "frame_status": frame_status,
            "loader_retf_0x12_applied": False,
            "label": "shape-frame comparison; not a loader, runtime, or GEO binding",
        },
        "not_established": NOT_ESTABLISHED,
        "next_discriminating_observations": DISCRIMINATORS,
    }
    doc["self_checks"] = self_checks(doc, before, after, pins, site_set, controls, sweeps)
    code = 0 if all(c["ok"] for c in doc["self_checks"]) else 1
    return doc, code


def self_checks(doc: dict, before: dict, after: dict, pins: dict, site_set: dict, controls: list,
                sweeps: dict) -> list:
    rows = doc["sites"]
    # An unknown callee that is not a swept parameter for its site fails the walk closed as "unknown-callee".
    unlisted = {"0x%05X" % a: s["walk_failed_by_reason"]["unknown-callee"]
                for a, s in sweeps.items() if s["walk_failed_by_reason"].get("unknown-callee")}
    return [
        {"name": "pins match the expected GAME.OVR and START.EXE", "ok": bool(pins)},
        {"name": "exact nine-site census set verified before analysis", "ok": site_set["count"] == 9},
        {"name": "every site is a 9A whose target is 0085:005C (not the loader)",
         "ok": all(r["target_is_0085_005C"] and not r["target_is_loader_identity"] for r in rows)},
        {"name": "every site's walked proc lies in its expected census owner group",
         "ok": not doc["summary"]["owner_mismatches"]},
        {"name": "allocation is one value per site across hypotheses",
         "ok": all(len(s["allocation_bytes_seen"]) <= 1 for s in sweeps.values())},
        {"name": "no swept walk failed on an unlisted unknown callee", "ok": not unlisted},
        {"name": "every unknown callee in a swept site's linear window is one of its swept parameters "
                 "(static enumeration of every 9A)",
         "ok": all(set(r["static_unknown_callees"]) <= {"%04X:%04X" % c for c in SITE_PARAMS[int(r["at"], 16)]}
                   for r in rows if r["sweep"]["swept"])},
        {"name": "the four single-callee sites balance only at K_a = 10 + L (leftover is constant)",
         "ok": all(s["leftover_bytes_seen"] == [2] for a, s in sweeps.items() if a in SITE_PARAMS and
                   SITE_PARAMS[a] == (TARGET,))},
        {"name": "inputs unchanged by the run", "ok": before == after},
        {"name": "no walk window holds an unmodelled stack form (pop r/m, push imm, pushf, pusha, enter, leave)",
         "ok": all(c is not None and c["unmodelled"] == 0 and c["pop-r/m16 (8F)"] == 0
                   for c in doc["sites_stack_ops"].values())},
        {"name": "FrameWalk reproduces the existing Walk on the loader control sites (no FF /6 there)",
         "ok": all(c.get("frame_walk_agrees") for c in controls)},
        {"name": "loader control sites balance under the loader's own 0x12 (model not altered)",
         "ok": all(c.get("walk_ok") and c.get("balanced_with_loader_K") for c in controls)},
        {"name": "the loader's 0x12 is not applied to the nine sites", "ok": doc["verdict"]["loader_retf_0x12_applied"] is False},
    ]


def render_md(doc: dict) -> str:
    v = doc["verdict"]
    j = doc["joint"]
    lines = [
        "# Pool of Radiance: caller frames at the nine argument-push-shape sites (0085:005C)",
        "",
        "**Status: %s. `playable: false`, `established: false`, `mappings: []`.**" % v["frame_status"],
        "",
        "- Callee pop of `0085:005C`: **%s**. The loader's `retf 0x12` is not applied (%s)." % (
            v["callee_pop_0085_005C"], v["label"]),
        "- Joint hypotheses over the decided sites (K_a, K_c, K_g): %d. Their K_a values: `%s`. Undecided "
        "(not refuted): `%s`." % (
            j["joint_tuple_count"], ", ".join(j["joint_K_a_over_decided_sites"]) or "none",
            ", ".join(list(j["undecided_sites"])) or "none"),
        "",
        "| Site | Owner | Target | Parameters | Alloc | Leftover L | Balancing hypotheses | Walk failures |",
        "| --- | --- | --- | --- | ---: | --- | ---: | --- |",
    ]
    for r in doc["sites"]:
        s = r["sweep"]
        if not s["swept"]:
            lines.append("| `%s` | `%s` | `%s` | not swept | - | - | not claimed | %s |" % (
                r["at"], r["owner_of_walked_proc"], r["target"], s["reason"]))
            continue
        fails = ", ".join("%s %d" % (k, n) for k, n in s["walk_failed_by_reason"].items()) or "none"
        lines.append("| `%s` | `%s` | `%s` | %s | %s | %s | %d of %d walked | %s |" % (
            r["at"], r["owner_of_walked_proc"], r["target"], ", ".join(s["parameters"]),
            ", ".join(str(a) for a in s["allocation_bytes_seen"]) or "-",
            ", ".join(str(x) for x in s["leftover_bytes_seen"]) or "-",
            s["balanced_count"], s["walk_ok"], fails))
    lines += ["", "## Limits", "",
              "- Walks use the caller-frame probe's model: linear fall-through; a forward branch's join must agree "
              "in depth; pops are limited to pushed words (over-pop into locals is infeasible here); a backward "
              "branch inside the window is not modelled and fails closed.",
              "- Each sweep is a finite grid (K_a 0..0x40, other pops 0..0x20, word-aligned). A balance found in the grid "
              "is a requirement on the unknown pop, not a value of it; a grid miss is not a refutation.",
              "- The callee of each parameter is one body per seg:off, which the single operand implies; it does not "
              "establish the body or its segment base. The census DI and paragraph assumptions are inherited.",
              "", "## Not established", ""]
    lines += ["- " + x for x in doc["not_established"]]
    lines += ["", "## Pins and hashes", ""]
    for name, p in doc["pins"].items():
        lines.append("- `%s`: %d bytes, sha256 `%s`" % (name, p["size"], p["sha256"]))
    lines += ["", "## Self-checks", ""]
    lines += ["- [%s] %s" % ("x" if c["ok"] else " ", c["name"]) for c in doc["self_checks"]]
    return "\n".join(lines) + "\n"


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    (out / RESULT_MD).write_text(render_md(doc), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Caller frames at the nine argument-push-shape sites (static, read-only).")
    ap.add_argument("--install", type=Path, default=DEFAULT_INSTALL,
                    help="folder holding the pinned GAME.OVR and START.EXE (default: data/work/por-geo-run/POOLRAD)")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT, help="output folder, under data/work/")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out)
    except Refusal as e:
        print("refused: %s" % e, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("frame_status=%s joint_K_a=%s joint_tuples=%d sites=%d self_checks=%s" % (
        doc["verdict"]["frame_status"], doc["summary"]["joint_K_a_over_decided_sites"],
        doc["summary"]["joint_tuple_count"], doc["summary"]["sites_total"], "pass" if code == 0 else "FAIL"))
    return code


if __name__ == "__main__":
    sys.exit(main())
