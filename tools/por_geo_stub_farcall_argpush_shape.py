#!/usr/bin/env python3
"""Pool of Radiance: argument-push shape of the strong residue-compatible far calls (STATIC, DIAGNOSTIC).

STATUS: static-probe-only. ``playable: false``. No events, no mappings, no module output.

Question. The census tools/por_geo_stub_farcall_census.py reports 181 far-call sites whose listed seg word and
residue rule are compatible with the GEO stub, 166 of them strong (reached by decoded control flow from a stub
proc). For those 166 strong sites ONLY: does the instruction sequence immediately before the ``9A`` call resemble
the GEO loader's known caller shape?

The known shape (docs/por-geo-loader-caller-frame-probe.md, and the loader probe's SHAPE_RE it reuses) is ten
pushed bytes before ``9A 16 07 02 08``: one id word, then two far pointers. Each far pointer is pushed as
``lea di,[bp+d]; push ss; push di``. The id word is pushed as ``mov al,[bp+d8]; push ax`` (documented form) or
``mov al,imm8; push ax`` (the form the loader probe's regex also accepts). Those two id forms are reported
separately, because they differ: a constant id and an id read from the caller's own argument are not the same
push.

Method (read-only; the census and decoder are imported, never edited):

* Candidates. ``por_geo_stub_farcall_census.analyse`` supplies the candidate sites. Each candidate has exactly one
  owner row; a strong candidate is one whose owner row is strong.
* Strong decode. The owner group is re-walked with the census's own pass 1 (``por_geo_stub_farcall_census._walk``
  seeded from the group's well-formed stub procs). The census's per-group far-call set is checked against this
  re-walk. A mismatch fails the run; it is not patched over.
* Fall-through chain. The instruction covering byte ``at-1`` must end at ``at``. The chain is the run of
  instructions reached by walking back through decoded instruction ends, nearest first, up to 16 instructions.
  A missing or non-abutting predecessor is ``ambiguous``. Nothing is inferred across a gap.
* Shape scan (instruction-aligned, not a byte search). Nearest first: three instructions ``push di``,
  ``push ss``, ``lea di,[bp+d]`` are one far pointer; two of them, then an id pair (``push ax`` and
  ``mov al,...``), are the shape. The scan reports the pointer-pair count and the id form.
* Join check. A branch target inside the consumed window (strictly after its first byte, before the call) is a
  join: the window is not the only way to reach the call. A branch whose target is the call is ``entered_by_branch``.
  Only strong-pass control flow is used. Weak (prologue-seeded) decode is not evidence of a path.
* Control. The ten static loader call sites (GAME.OVR x8, START.EXE x2, found by the loader caller-frame probe's
  ``call_sites``) are scanned by the same instruction scan on their linear chain from the procedure found by
  ``find_proc``. The instruction scan must agree with the loader probe's byte-level ``shape_start`` at every site,
  and the documented id form must be the one that appears at the walked loader sites.

Scope. Each row's shape class is a fact about the bytes and the decoded chain. A shape match is not a call to
the loader, not a runtime reachability, not a target identity, not a GEO archive or block mapping, and not a binding.
The DI delta and the MZ paragraph model are still assumptions inherited from the census.

Evidence labels. ``decoded`` = a decoder result. ``strong`` = reached from a stub proc by decoded control flow.
``shape-scan`` = instruction-aligned byte match. ``control`` = the loader's own call sites. Nothing is ``established``.

Usage::

    python tools/por_geo_stub_farcall_argpush_shape.py --install "PATH/TO/POOLRAD" \\
        -o data/work/por-geo-stub-farcall-argpush-shape/retail

Exit: 0 every self-check passes; 1 a self-check failed; 2 a named refusal (missing or unpinned input, output inside
the install, output outside ``data/work/``).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"

sys.path.insert(0, str(TOOLS_DIR))
import por_farcall_resolve as fr  # noqa: E402  (read-only; PINNED sizes and hashes)
import por_loadpieces_handler as h  # noqa: E402  (read-only; decoder)
import por_ecl_21_dispatch_probe as p  # noqa: E402  (read-only; load_inputs, ProbeRefusal)
import por_geo_stub_farcall_census as c  # noqa: E402  (read-only; candidates, strong walk, output refusals)
import por_geo_loader_caller_frame_probe as lcf  # noqa: E402  (read-only; loader call sites, byte SHAPE_RE)

SCHEMA = "openua.por-geo-stub-farcall-argpush-shape"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_geo_stub_farcall_argpush_shape.py"
RESULT_JSON = "por_geo_stub_farcall_argpush_shape.json"
RESULT_MD = "por_geo_stub_farcall_argpush_shape.md"

OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME

MAX_CHAIN = 16                     # decoded instructions examined before each call

# Instruction-level patterns over the raw bytes of one decoded instruction.
PUSH_AX = re.compile(rb"\x50", re.DOTALL)
PUSH_SS = re.compile(rb"\x16", re.DOTALL)
PUSH_DI = re.compile(rb"\x57", re.DOTALL)
LEA_DI_BP = re.compile(rb"\x8d(?:\x7e.|\xbe..)", re.DOTALL)   # lea di,[bp+disp8] / lea di,[bp+disp16]
ID_BP = re.compile(rb"\x8a\x46.", re.DOTALL)                    # mov al,[bp+disp8]   (documented id form)
ID_IMM = re.compile(rb"\xb0.", re.DOTALL)                       # mov al,imm8         (variant id form)

ID_BP_FORM = "mov-al-bp"
ID_IMM_FORM = "mov-al-imm"

CLS_DOC = "loader-shape-documented-id"      # two far pointers + id mov al,[bp+d8]
CLS_IMM = "loader-shape-imm-id"             # two far pointers + id mov al,imm8
CLS_PAIR_NOID = "pointer-pair-no-id"        # two far pointers, no id word before them
CLS_ONE = "one-pointer"
CLS_MORE = "more-than-two-pointers"
CLS_NONE = "no-pointer-pair"
CLS_AMBIG = "ambiguous-no-fallthrough-predecessor"
LOADER_SHAPE_CLASSES = (CLS_DOC, CLS_IMM)

VERDICT_NONE = "no-strong-candidate-resembles-loader-shape"
VERDICT_IMM = "imm-id-shape-only"
VERDICT_DOC = "documented-id-shape-present"
STATUS_PRECONDITION = "precondition-failed"

# Pinned expectations from the census (checked, not trusted). A census change makes these fail loudly.
EXPECT_CANDIDATES = 181
EXPECT_STRONG_CANDIDATES = 166
EXPECT_CONTROL_SITES = 10
EXPECT_STRONG_CLEAN_SHAPE_IMM = 9          # strict scan result: see the retail doc
EXPECT_STRONG_DOC_SHAPE = 0
EXPECT_CONTROL_DOC_ID = 9                  # the loader's own sites: nine documented mov al,[bp+d8] ids
EXPECT_CONTROL_IMM_ID = 1                  # and START 0x7276, a mov al,imm8 id (walked, balanced in the frame probe)


class ArgShapeRefusal(Exception):
    """A named refusal: the probe does not run and writes nothing."""


# ---------------------------------------------------------------------------------------------
# Instruction scan
# ---------------------------------------------------------------------------------------------

def _m(rx: re.Pattern, ins) -> bool:
    return rx.fullmatch(ins.raw) is not None


def _disp(ins) -> Optional[int]:
    """Signed displacement of a [bp+disp] pointer or id operand, read from the raw bytes."""
    raw = ins.raw
    if raw[:1] == b"\x8d" and len(raw) == 3:
        return raw[2] - 256 if raw[2] >= 128 else raw[2]
    if raw[:1] == b"\x8d" and len(raw) == 4:
        v = raw[2] | (raw[3] << 8)
        return v - 65536 if v >= 32768 else v
    if raw[:1] == b"\x8a" and len(raw) == 3:
        return raw[2] - 256 if raw[2] >= 128 else raw[2]
    return None


def shape_scan(back: list) -> dict:
    """Scan the decoded chain nearest-first for the loader shape. ``back[0]`` is the instruction before the call.

    Returns the class, the pointer-pair count, the id form, and the number of instructions the match consumed.
    Pure function of the instruction bytes: no branch information is used here.
    """
    if not back:
        return {"class": CLS_AMBIG, "pointer_pairs": 0, "id_form": None, "consumed": 0,
                "lea_disp": [], "id_operand": None}
    pos = 0
    lea_disp = []
    while (pos + 3 <= len(back) and _m(PUSH_DI, back[pos]) and _m(PUSH_SS, back[pos + 1])
           and _m(LEA_DI_BP, back[pos + 2])):
        lea_disp.append(_disp(back[pos + 2]))
        pos += 3
    pairs = pos // 3
    id_form = None
    id_operand = None
    if pos + 2 <= len(back) and _m(PUSH_AX, back[pos]):
        if _m(ID_BP, back[pos + 1]):
            id_form = ID_BP_FORM
            id_operand = _disp(back[pos + 1])
        elif _m(ID_IMM, back[pos + 1]):
            id_form = ID_IMM_FORM
            id_operand = back[pos + 1].raw[1]
    consumed = pos + (2 if id_form else 0)
    if pairs == 2 and id_form == ID_BP_FORM:
        cls = CLS_DOC
    elif pairs == 2 and id_form == ID_IMM_FORM:
        cls = CLS_IMM
    elif pairs == 2:
        cls = CLS_PAIR_NOID
    elif pairs == 1:
        cls = CLS_ONE
    elif pairs > 2:
        cls = CLS_MORE
    else:
        cls = CLS_NONE
    return {"class": cls, "pointer_pairs": pairs, "id_form": id_form, "consumed": consumed,
            "lea_disp": lea_disp, "id_operand": id_operand}


def chain_before(insns: dict, owned: dict, at: int, limit: int = MAX_CHAIN) -> list:
    """Decoded instructions that abut ``at`` by fall-through, nearest first. Stops at any gap."""
    back = []
    cur = at
    while len(back) < limit and (cur - 1) in owned:
        rec = insns.get(owned[cur - 1])
        if rec is None:
            break
        ins = rec["ins"]
        if ins.end != cur:
            break
        back.append(ins)
        cur = ins.off
    return back


def branch_targets(insns: dict) -> dict:
    """Every decoded near branch/call target in the strong pass, keyed by target offset (file space)."""
    out: dict = {}
    for at, rec in insns.items():
        ins = rec["ins"]
        if ins.target is not None and ins.flow in ("jcc", "jmp", "call"):
            out.setdefault(ins.target, []).append(at)
    return out


def classify_site(ovr: bytes, insns: dict, owned: dict, targets: dict, at: int) -> dict:
    """One strong call site: its fall-through chain, shape scan, and join checks."""
    back = chain_before(insns, owned, at)
    scan = shape_scan(back)
    consumed = back[:scan["consumed"]]
    lo_w = consumed[-1].off if consumed else at
    joins = sorted(t for t in targets if lo_w < t < at)
    entered = at in targets
    clean = scan["class"] in LOADER_SHAPE_CLASSES and not joins and not entered
    window = b"".join(i.raw for i in reversed(consumed))
    raw_ok = all(i.raw == ovr[i.off:i.end] for i in back)
    return {
        "raw_bytes_match_input": raw_ok,
        "fallthrough_predecessor": _hex(back[0].off) if back else None,
        "chain_len": len(back),
        "shape_class": scan["class"],
        "pointer_pairs": scan["pointer_pairs"],
        "id_form": scan["id_form"],
        "id_operand": scan["id_operand"],
        "lea_bp_disp": scan["lea_disp"],
        "window_start": _hex(lo_w) if consumed else None,
        "window_bytes": window.hex(),
        "window_branch_joins": [_hex(t) for t in joins],
        "entered_by_branch": entered,
        "clean_shape": clean,
    }


# ---------------------------------------------------------------------------------------------
# Helpers and controls
# ---------------------------------------------------------------------------------------------

def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def strong_walk(ovr: bytes, g: dict) -> tuple:
    """The census's pass 1, re-run for one owner group. Returns (insns, owned, strong_far_set)."""
    lo, hi = g["fileofs"], g["fileofs"] + g["codesz"]
    insns: dict = {}
    owned: dict = {}
    errors: list = []
    stats = {"out_of_body": 0, "overlaps": 0, "budget": False}
    seeds = [lo + pr for pr in c.strong_procs(g) if lo <= lo + pr < hi]
    c._walk(ovr, lo, hi, seeds, insns, owned, True, errors, stats)
    far = {at for at, rec in insns.items() if rec["ins"].flow == "call_far"}
    return insns, owned, far


def linear_chain(img: bytes, proc: int, site: int, limit: int = MAX_CHAIN) -> Optional[list]:
    """Control only: the linear decode from ``proc`` to ``site``, nearest first. None if it does not land on site."""
    chain = []
    q = proc
    while q < site:
        try:
            ins = h.decode(img, q)
        except (h.DecodeError, IndexError):
            return None
        chain.append(ins)
        q = ins.end
    if q != site:
        return None
    return list(reversed(chain))[:limit]


def control_rows(start: bytes, ovr: bytes) -> list[dict]:
    """The ten static loader call sites, classified by the same instruction scan (linear chain, no join check)."""
    rows = []
    for name, img in ((OVR_NAME, ovr), (EXE_NAME, start)):
        for site in lcf.call_sites(img):
            proc, _ = lcf.find_proc(img, site)
            back = linear_chain(img, proc, site) if proc is not None else None
            scan = shape_scan(back or [])
            byte_hit = lcf.shape_start(img, site) is not None
            rows.append({
                "image": name,
                "at": _hex(site),
                "proc": _hex(proc),
                "linear_chain_found": back is not None,
                "shape_class": scan["class"] if back is not None else CLS_AMBIG,
                "id_form": scan["id_form"],
                "pointer_pairs": scan["pointer_pairs"],
                "lea_bp_disp": scan["lea_disp"],
                "byte_shape_regex_hit": byte_hit,
                "scan_agrees_with_byte_regex": (scan["class"] in LOADER_SHAPE_CLASSES) == byte_hit
                and back is not None,
            })
    return rows


# ---------------------------------------------------------------------------------------------
# Whole-install analysis
# ---------------------------------------------------------------------------------------------

def analyse(start: bytes, ovr: bytes) -> dict:
    groups = c.groups_of(start, ovr)
    by_fo = {g["fileofs"]: g for g in groups}
    census = c.analyse(start, ovr)
    strong_sites = [s for s in census["candidates"] if s["strong"]]

    walks: dict = {}
    coverage: dict = {}
    mirror_ok: dict = {}
    rows = []
    mismatches = []
    for s in strong_sites:
        at, seg, off = int(s["at"], 16), int(s["seg"], 16), int(s["off"], 16)
        strong_owners = [o for o in s["owners"] if o["strong"]]
        if len(strong_owners) != 1:
            mismatches.append({"at": s["at"], "reason": "strong-owner-count-%d" % len(strong_owners)})
            continue
        owner = strong_owners[0]
        fo = int(owner["owner_fileofs"], 16)
        g = by_fo[fo]
        if fo not in walks:
            walks[fo] = strong_walk(ovr, g)
            cg = c.census_group(ovr, g)
            coverage[fo] = cg["coverage"]
            census_far_strong = {f["at"] for f in cg["far_decoded"] if f["strong"]}
            mirror_ok[fo] = census_far_strong == walks[fo][2]
        insns, owned, far_set = walks[fo]
        targets = branch_targets(insns)
        if at not in insns or insns[at]["ins"].flow != "call_far" or insns[at]["ins"].far != (seg, off):
            mismatches.append({"at": s["at"], "reason": "not-the-census-call-in-strong-walk"})
            continue
        row = {
            "at": _hex(at), "seg": _hex(seg), "off": _hex(off),
            "owner_fileofs": _hex(fo), "owner_status": g["status"], "owner_coverage": coverage[fo],
            "owner_mirror_matches_census": mirror_ok[fo],
        }
        row.update(classify_site(ovr, insns, owned, targets, at))
        rows.append(row)

    ctrl = control_rows(start, ovr)
    counts: dict = {}
    for r in rows:
        counts[r["shape_class"]] = counts.get(r["shape_class"], 0) + 1
    shape_rows = [r for r in rows if r["shape_class"] in LOADER_SHAPE_CLASSES]
    clean = [r for r in shape_rows if r["clean_shape"]]
    doc_rows = [r for r in shape_rows if r["shape_class"] == CLS_DOC]
    imm_rows = [r for r in shape_rows if r["shape_class"] == CLS_IMM]
    ambiguous = [r for r in rows if r["shape_class"] == CLS_AMBIG]
    totals = {
        "census_candidate_sites": len(census["candidates"]),
        "strong_candidate_sites": len(strong_sites),
        "analysed_strong_sites": len(rows),
        "mismatched_strong_sites": len(mismatches),
        "ambiguous_no_fallthrough_predecessor": len(ambiguous),
        "entered_by_branch": sum(1 for r in rows if r["entered_by_branch"]),
        "shape_class_counts": dict(sorted(counts.items())),
        "loader_shape_any_id": len(shape_rows),
        "loader_shape_documented_id": len(doc_rows),
        "loader_shape_imm_id": len(imm_rows),
        "loader_shape_clean": len(clean),
        "loader_shape_with_branch_join": len(shape_rows) - len(clean),
        "owner_coverage_of_strong_sites": dict(sorted(_count(r["owner_coverage"] for r in rows).items())),
        "owner_status_of_strong_sites": dict(sorted(_count(r["owner_status"] for r in rows).items())),
        "distinct_callees_of_loader_shape": sorted({"%s:%s" % (r["seg"], r["off"]) for r in shape_rows}),
        "control_sites": len(ctrl),
    }

    if not all(mirror_ok.values()) or mismatches:
        verdict = {"shape_status": STATUS_PRECONDITION,
                   "reason": "strong-walk mirror or census operand mismatch; no shape verdict"}
    elif doc_rows:
        verdict = {"shape_status": VERDICT_DOC,
                   "reason": "%d strong candidate(s) match the documented id form; shape only, not a binding"
                             % len(doc_rows)}
    elif imm_rows:
        verdict = {"shape_status": VERDICT_IMM,
                   "reason": ("%d strong candidate(s) match the two-far-pointer push shape with an id of the form "
                              "mov al,imm8 and no documented mov al,[bp+d8] id. The same id form occurs at one "
                              "of the ten loader call sites (START 0x7276), so the id form does not separate "
                              "them from the loader shape; shape only, not a binding") % len(imm_rows)}
    else:
        verdict = {"shape_status": VERDICT_NONE,
                   "reason": "no strong residue-compatible call is preceded by the loader's pushed shape"}
    return {
        "census_totals": census["totals"],
        "census_verdict": census["verdict"],
        "rows": rows,
        "loader_shape_rows": shape_rows,
        "mismatches": mismatches,
        "mirror_matches_census": mirror_ok,
        "control": ctrl,
        "totals": totals,
        "verdict": verdict,
    }


def _count(items) -> dict:
    out: dict = {}
    for k in items:
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------------------------
# Self-checks, probe driver, output
# ---------------------------------------------------------------------------------------------

def self_checks(doc: dict, hashes_before: dict, hashes_after: dict, pins_ok: bool) -> list:
    t = doc["totals"]
    ctrl = doc["control"]
    ctrl_doc = [r for r in ctrl if r["byte_shape_regex_hit"]]
    checks = [
        ("inputs_pinned", pins_ok),
        ("census_candidates_181", t["census_candidate_sites"] == EXPECT_CANDIDATES),
        ("strong_candidates_166", t["strong_candidate_sites"] == EXPECT_STRONG_CANDIDATES),
        ("every_strong_site_analysed", t["analysed_strong_sites"] == t["strong_candidate_sites"]),
        ("no_mismatched_strong_sites", t["mismatched_strong_sites"] == 0),
        ("strong_walk_mirror_matches_census_per_group", all(doc["mirror_matches_census"].values())),
        ("raw_bytes_of_chain_are_input_bytes", all(r["raw_bytes_match_input"] for r in doc["rows"])),
        ("control_has_ten_loader_sites", len(ctrl) == EXPECT_CONTROL_SITES),
        ("control_scan_agrees_with_byte_regex_at_every_site",
         all(r["scan_agrees_with_byte_regex"] for r in ctrl)),
        ("control_id_forms_pinned",
         sum(1 for r in ctrl if r["shape_class"] == CLS_DOC) == EXPECT_CONTROL_DOC_ID
         and sum(1 for r in ctrl if r["shape_class"] == CLS_IMM) == EXPECT_CONTROL_IMM_ID),
        ("strong_documented_id_matches_pinned", t["loader_shape_documented_id"] == EXPECT_STRONG_DOC_SHAPE),
        ("strong_imm_id_matches_pinned", t["loader_shape_imm_id"] == EXPECT_STRONG_CLEAN_SHAPE_IMM),
        ("verdict_never_established",
         doc["verdict"]["shape_status"] in (VERDICT_NONE, VERDICT_IMM, VERDICT_DOC, STATUS_PRECONDITION)),
        ("inputs_unchanged", hashes_before == hashes_after),
    ]
    return [{"name": n, "ok": bool(ok)} for n, ok in checks]


def probe(install: Path, out: Path) -> tuple:
    try:
        c.check_out(out, install)
    except c.CensusRefusal as e:
        raise ArgShapeRefusal(str(e))
    pins = {name: (len((install / name).read_bytes()), c._sha((install / name).read_bytes())) for name in (OVR_NAME, EXE_NAME)}
    pins_ok = all(pins[n] == (fr.PINNED[n][0], fr.PINNED[n][1]) for n in (OVR_NAME, EXE_NAME))
    before = c._hashes(install)
    inputs = p.load_inputs(install)
    doc = analyse(inputs[EXE_NAME], inputs[OVR_NAME])
    after = c._hashes(install)
    out_doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "established": False,
        "mappings": [],
        "inputs": {k: {"size": len(v), "sha256": c._sha(v)} for k, v in inputs.items()},
        "inputs_pinned": pins_ok,
        "scope": {
            "question": "strong residue-compatible far calls (census: 166 of 181) only",
            "known_shape": "ten pushed bytes: id word + two far pointers (lea di,[bp+d]; push ss; push di)",
            "not_claimed": ["runtime reachability", "target identity", "GEO archive or block mapping", "binding"],
        },
        **doc,
    }
    out_doc["self_checks"] = self_checks(out_doc, before, after, pins_ok)
    return out_doc, (0 if all(x["ok"] for x in out_doc["self_checks"]) else 1)


def render_md(doc: dict) -> str:
    v = doc["verdict"]
    t = doc["totals"]
    lines = [
        "# Pool of Radiance: argument-push shape of the strong residue-compatible far calls (static, diagnostic)",
        "",
        "**Status: STATIC-PROBE-ONLY. `playable: false`, `established: false`, `mappings: []`.**",
        "",
        "## Verdict",
        "",
        "- `shape_status`: **%s**" % v["shape_status"],
        "- Reason: %s" % v["reason"],
        "- Scope: only the strong residue-compatible far calls of the census (%d of %d candidates). Shape only: "
        "no runtime reachability, target identity, GEO archive/block mapping, or binding is claimed."
        % (t["strong_candidate_sites"], t["census_candidate_sites"]),
        "",
        "## Totals",
        "",
        "| Item | Value |",
        "| --- | ---: |",
    ]
    for k in ("census_candidate_sites", "strong_candidate_sites", "analysed_strong_sites",
              "mismatched_strong_sites", "ambiguous_no_fallthrough_predecessor", "entered_by_branch",
              "loader_shape_any_id", "loader_shape_documented_id", "loader_shape_imm_id", "loader_shape_clean",
              "loader_shape_with_branch_join", "control_sites"):
        lines.append("| %s | %s |" % (k, t[k]))
    lines += ["", "Shape classes (strong sites): `%s`" % json.dumps(t["shape_class_counts"], sort_keys=True),
              "",
              "Owner coverage (strong sites): `%s`; owner status: `%s`"
              % (json.dumps(t["owner_coverage_of_strong_sites"], sort_keys=True),
                 json.dumps(t["owner_status_of_strong_sites"], sort_keys=True)),
              ""]
    lines += ["## Loader-shape rows (strong sites)", ""]
    if not doc["loader_shape_rows"]:
        lines.append("None.")
    else:
        lines += ["| at | seg:off | owner | class | id form | id operand | lea [bp+d] | window | joins | clean |",
                  "| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |"]
        for r in doc["loader_shape_rows"]:
            lines.append("| %s | %s:%s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
                r["at"], r["seg"], r["off"], r["owner_fileofs"], r["shape_class"], r["id_form"],
                r["id_operand"], ", ".join(str(d) for d in r["lea_bp_disp"]), r["window_start"],
                ", ".join(r["window_branch_joins"]) or "-", "yes" if r["clean_shape"] else "no"))
    lines += ["", "## Control: the ten static loader call sites", "",
              "| image | at | proc | class | id form | pointer pairs | byte regex hit | scan agrees |",
              "| --- | --- | --- | --- | --- | ---: | --- | --- |"]
    for r in doc["control"]:
        lines.append("| %s | %s | %s | %s | %s | %d | %s | %s |" % (
            r["image"], r["at"], r["proc"], r["shape_class"], r["id_form"], r["pointer_pairs"],
            "yes" if r["byte_shape_regex_hit"] else "no", "yes" if r["scan_agrees_with_byte_regex"] else "NO"))
    lines += ["", "## Self-checks", ""]
    lines += ["- %s: %s" % (x["name"], "pass" if x["ok"] else "FAIL") for x in doc["self_checks"]]
    lines += [
        "",
        "## Limits",
        "",
        "- Only the census's strong decode is used for the chain and the joins. Weak (prologue-seeded) decode is",
        "  not evidence of a path, and weak-only sites are not in this table.",
        "- The chain is the fall-through run of decoded instructions. Indirect branches are not followed, so a",
        "  branch from an undecoded or indirect source is invisible to the join check.",
        "- The shape scan is instruction-aligned and strict. The documented loader id form is `mov al,[bp+d8]`;",
        "  the loader probe's own regex also admits `mov al,imm8`, and this tool reports the two forms apart.",
        "  The loader's own call sites use both: nine documented, one imm8 (START `0x7276`). So the imm8 form is",
        "  a loader-caller form too, and the id form alone does not rule a strong candidate out.",
        "- The inherited census limits apply: the DI delta and the MZ paragraph model are assumed.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    (out / RESULT_MD).write_text(render_md(doc), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="PoR argument-push shape of strong residue-compatible far calls "
                                             "(static, read-only).")
    ap.add_argument("--install", required=True, type=Path, help="folder holding the pinned GAME.OVR and START.EXE")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder, under data/work/")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out)
    except (p.ProbeRefusal, ArgShapeRefusal) as e:
        print("refused: %s" % e, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("shape_status=%s strong_candidates=%d documented=%d imm=%d self_checks=%s" % (
        doc["verdict"]["shape_status"], doc["totals"]["strong_candidate_sites"],
        doc["totals"]["loader_shape_documented_id"], doc["totals"]["loader_shape_imm_id"],
        "pass" if code == 0 else "FAIL"))
    return code


if __name__ == "__main__":
    sys.exit(main())
