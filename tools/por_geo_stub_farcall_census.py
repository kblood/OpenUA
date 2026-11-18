#!/usr/bin/env python3
"""Pool of Radiance: PoR-wide static census of far calls toward START stub 6 (STATIC, DIAGNOSTIC).

Naming. The ``geo`` in this file name and in its identifiers is historical. Stub 6 (proc ``0x0E08``) enters the
WALLDEF wrapper at ``GAME.OVR:0x2F6FF`` (it builds ``WALLDEF<d>.dax``; see ``docs/por-ecl-stub6-key-arg-probe.md``),
not the GEO fill at ``GAME.OVR:0x2F9BE``. Every result here is about stub 6 and the WALLDEF wrapper.

STATUS: static-probe-only. ``playable: false``. No events, no mappings, no module output.

Question. Stub 6 is ``START.EXE`` offset ``15884`` (``0x3E0C``): stub index 6 of the VROOMM group at
header ``0x3DD7`` (partial; stub run at header+``0x17``), proc ``0x0E08`` into the WALLDEF wrapper
``GAME.OVR:0x2F6FF`` (group fileofs ``0x2E8F7``). Across every parsed GAME.OVR overlay body, which
instruction-decoded far calls (``9A seg:off``) could resolve to that stub, and which near calls (``E8``)
reach the WALLDEF wrapper?

Method (read-only, bounded, stdlib plus the read-only probe modules):

* Groups. ``por_farcall_resolve.scan_all`` supplies the parsed descriptor groups: ``well-formed`` and
  ``partial``. A body is ``[fileofs, fileofs+codesz)``; its fixup table is ``fixupsz/2`` words at ``fileofs+codesz``.
* Decode. Per group, two passes over ``por_loadpieces_handler.decode`` (recursive descent through fall-through,
  ``jcc``/``jmp`` and ``E8`` targets inside the body; stops at ``ret``/``retf``/far or indirect jumps).
  Pass 1 (**strong**) seeds only from the group's well-formed stub procs. Pass 2 (**weak**) seeds from every
  ``55 89 E5`` / ``55 8B EC`` byte pattern in the body and skips instructions pass 1 decoded. A weak site is a
  decode from a byte pattern with no stub entry: it is reported, but it is not a proof of code.
* Owner tables. A far call's seg word is at body offset ``at+3-fileofs``; its offset word is at ``at+1-fileofs``.
  Both are tested against the OWNER group's own fixup table.
* Residue rule, per (site, owner). The resident MZ image is at file ``hdr`` (``cparhdr*16``, 0x200 here), so a
  stub at file ``F`` is at image ``F-hdr``.
  - Seg word listed, offset word not listed: the loader adds an unknown delta ``DI`` to the seg word, so the image
    is ``hdr + (seg+DI)*16 + off``. It can reach the stub only if ``off ≡ (F-hdr) (mod 16)``, whatever ``DI`` is.
    Such a site is ``candidate-given-di-not-established``. The DI it would need is a constraint
    (``di_constraint_mod64k``), not a value.
  - Seg word not listed: the literal image ``hdr + seg*16 + off`` is tested for exact equality with ``F``.
  - Offset word listed: the offset itself receives ``DI``; no exact or residue test applies, so the row is
    ``undecided-*`` and never a candidate.
* Near calls. ``E8`` decoded in a body with a target equal to the WALLDEF wrapper is reported with its owner; the target is
  body-relative and only reaches bytes of its own body.

Controls (checked, not trusted). The eleven far calls of the 0x19BA handler must be decoded in group ``0x0D46``,
and each residue must agree with ``por_ecl_21_fixup_residue_probe.residue_for``. The stub-6 bytes, group, index
and proc, and the wrapper decode must hold; otherwise the verdict is ``precondition-failed``.

Evidence labels. ``decoded`` = a decoder result. ``strong`` = reached from a stub proc by decoded control flow.
``weak`` = reached only from a prologue byte pattern. ``table-membership`` = exact test against the owner's table.
``arithmetic`` = residue and literal tests. Nothing here is ``established``.

Usage::

    python tools/por_geo_stub_farcall_census.py --install "PATH/TO/POOLRAD" \\
        -o data/work/por-geo-stub-farcall-census/retail

Exit: 0 every self-check passes; 1 a self-check failed; 2 a named refusal (missing or unpinned file, output
inside the install, output outside ``data/work/``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"

sys.path.insert(0, str(TOOLS_DIR))
import por_farcall_resolve as fr  # noqa: E402  (read-only; not edited)
import por_loadpieces_handler as h  # noqa: E402  (read-only; not edited)
import por_ecl_21_dispatch_probe as p  # noqa: E402  (read-only; not edited)
import por_ecl_21_fixup_residue_probe as r  # noqa: E402  (read-only; not edited)

SCHEMA = "openua.por-geo-stub-farcall-census"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_geo_stub_farcall_census.py"
RESULT_JSON = "por_geo_stub_farcall_census.json"
RESULT_MD = "por_geo_stub_farcall_census.md"

OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME
PINS = fr.PINNED

STUB6_F = 15884                          # START.EXE offset of stub 6 (0x3E0C)
STUB6_BYTES = bytes.fromhex("cd 3f 08 0e 00")
STUB6_HEADER = 0x3DD7
STUB6_INDEX = 6
STUB6_GROUP_FILEOFS = 0x2E8F7
STUB6_PROC = 0x0E08
WALLDEF_BODY = 0x2F6FF                          # WALLDEF wrapper = STUB6_GROUP_FILEOFS + STUB6_PROC

HANDLER = 0x19BA
HANDLER_GROUP_FILEOFS = 0x0D46
EXPECT_HANDLER_FAR = 11

PARA = 16
SEG_MOD = 0x10000
MAX_INSNS = 50000                           # per group, per pass
PROLOGUES = (b"\x55\x89\xe5", b"\x55\x8b\xec")

STATUS_PRECONDITION = "precondition-failed"
STATUS_CANDIDATE = "candidate-given-di-not-established"
STATUS_NONE = "no-candidate-under-paragraph-model"

SITE_CANDIDATE_RESIDUE = "candidate-given-di-not-established"
SITE_CANDIDATE_LITERAL = "candidate-literal-exact"
SITE_RESIDUE_NO = "residue-incompatible"
SITE_LITERAL_MISS = "literal-miss"
SITE_UNDECIDED_OFF = "undecided-offset-listed"
SITE_UNDECIDED_BOTH = "undecided-both-words-listed"
CANDIDATE_STATUSES = (SITE_CANDIDATE_RESIDUE, SITE_CANDIDATE_LITERAL)


class CensusRefusal(Exception):
    """A named refusal: the probe does not run and writes nothing."""


# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def _hashes(install: Path) -> dict:
    return {name: _sha((install / name).read_bytes()) for name in (OVR_NAME, EXE_NAME)}


def groups_of(start: bytes, ovr: bytes) -> list[dict]:
    """Every parsed descriptor group: accepted (well-formed) and partial, sorted by fileofs."""
    res = fr.scan_all(start, ovr)
    out = [dict(g) for g in res["groups"] + res["partial_groups"]]
    out.sort(key=lambda g: g["fileofs"])
    return out


def strong_procs(g: dict) -> list[int]:
    """Proc offsets of the group's well-formed stubs. A malformed slot is never a stub."""
    return [g["procs"][k] for k, ok in enumerate(g["stub_valid"]) if ok]


def table_info(ovr: bytes, g: dict) -> dict:
    """The owner's fixup table: fixupsz/2 16-bit words at fileofs+codesz. Unread if it runs past the overlay."""
    base = g["fileofs"] + g["codesz"]
    n = g["fixupsz"] // 2
    info = {"fixupsz": g["fixupsz"], "odd_size": g["fixupsz"] % 2 == 1, "count": n,
            "present": base + 2 * n <= len(ovr), "listed": set()}
    if not info["present"]:
        info.update({"sorted": False, "all_below_codesz": False, "duplicates": 0, "bare_offsets": False})
        return info
    words = list(struct.unpack_from("<%dH" % n, ovr, base)) if n else []
    info["listed"] = set(words)
    info["sorted"] = all(a <= b for a, b in zip(words, words[1:]))
    info["all_below_codesz"] = all(w < g["codesz"] for w in words)
    info["duplicates"] = len(words) - len(set(words))
    info["bare_offsets"] = info["sorted"] and info["all_below_codesz"]
    return info


def site_eval(at: int, seg: int, off: int, owner_fo: int, listed: set, hdr: int,
              target: int = STUB6_F) -> dict:
    """Classify one far call against one owner's table (see the module docstring for the rule)."""
    seg_body = at + 3 - owner_fo
    off_body = at + 1 - owner_fo
    seg_listed = seg_body in listed
    off_listed = off_body in listed
    literal = hdr + seg * PARA + off
    row = {
        "owner_fileofs": _hex(owner_fo),
        "seg_body": _hex(seg_body),
        "off_body": _hex(off_body),
        "seg_word_listed": seg_listed,
        "off_word_listed": off_listed,
        "literal_image": _hex(literal),
        "target_file": _hex(target),
    }
    if seg_listed and off_listed:
        row["status"] = SITE_UNDECIDED_BOTH
    elif seg_listed:
        d = target - hdr - off
        row["skew_needed_mod16"] = d % PARA
        if d % PARA == 0:
            row["status"] = SITE_CANDIDATE_RESIDUE
            row["di_constraint_mod64k"] = ((d // PARA) - seg) % SEG_MOD
        else:
            row["status"] = SITE_RESIDUE_NO
    elif off_listed:
        row["status"] = SITE_UNDECIDED_OFF
    else:
        row["status"] = SITE_CANDIDATE_LITERAL if literal == target else SITE_LITERAL_MISS
    row["candidate"] = row["status"] in CANDIDATE_STATUSES
    return row


# ---------------------------------------------------------------------------------------------
# Decoding one group body
# ---------------------------------------------------------------------------------------------

def _walk(ovr: bytes, lo: int, hi: int, seeds: list, insns: dict, owned: dict, strong: bool,
          errors: list, stats: dict) -> None:
    """Recursive descent restricted to [lo, hi). Adds to ``insns`` and ``owned`` in place."""
    work = list(seeds)
    while work:
        at = work.pop()
        while True:
            if not (lo <= at < hi):
                stats["out_of_body"] += 1
                break
            if at in insns:
                break
            if at in owned:
                stats["overlaps"] += 1
                break
            if len(insns) >= MAX_INSNS:
                stats["budget"] = True
                break
            try:
                ins = h.decode(ovr, at)
            except (h.DecodeError, IndexError) as exc:
                errors.append({"at": at, "strong": strong, "reason": str(exc)})
                break
            if ins.end > hi:
                errors.append({"at": at, "strong": strong, "reason": "crosses-body-end"})
                break
            if any(b in owned for b in range(ins.off, ins.end)):
                stats["overlaps"] += 1
                break
            insns[at] = {"ins": ins, "strong": strong}
            for b in range(ins.off, ins.end):
                owned[b] = at
            fl = ins.flow
            if fl in ("seq", "call_far", "indirect_call", "indirect_callf"):
                at = ins.end
            elif fl in ("call", "jcc"):
                if ins.target is not None and lo <= ins.target < hi:
                    work.append(ins.target)
                else:
                    stats["out_of_body"] += 1
                at = ins.end
            elif fl == "jmp":
                if ins.target is not None and lo <= ins.target < hi:
                    at = ins.target
                else:
                    stats["out_of_body"] += 1
                    break
            else:  # ret, retf, jmp_far, indirect_jmp, indirect_jmpf, anything unknown: stop
                break


def census_group(ovr: bytes, g: dict) -> dict:
    """Decode one group body in two passes (strong from stub procs, weak from prologue patterns)."""
    lo, hi = g["fileofs"], g["fileofs"] + g["codesz"]
    insns: dict = {}
    owned: dict = {}
    errors: list = []
    stats = {"strong": {"out_of_body": 0, "overlaps": 0, "budget": False},
             "weak": {"out_of_body": 0, "overlaps": 0, "budget": False}}
    strong_seeds = [lo + pr for pr in strong_procs(g) if lo <= lo + pr < hi]
    _walk(ovr, lo, hi, strong_seeds, insns, owned, True, errors, stats["strong"])
    n_strong = len(insns)
    body = ovr[lo:hi]
    weak_seeds = sorted({lo + i for i in range(len(body) - 2) if body[i:i + 3] in PROLOGUES})
    _walk(ovr, lo, hi, weak_seeds, insns, owned, False, errors, stats["weak"])

    strong_errs = [e for e in errors if e["strong"]]
    s = stats["strong"]
    if not strong_seeds:
        coverage = "no-strong-seed"
    elif strong_errs or s["out_of_body"] or s["overlaps"] or s["budget"]:
        coverage = "strong-walk-incomplete"
    else:
        coverage = "strong-walk-clean"

    far_rows = []
    near_rows = []
    for at in sorted(insns):
        rec = insns[at]
        ins = rec["ins"]
        if ins.flow == "call_far" and ins.far is not None:
            far_rows.append({"at": at, "seg": ins.far[0], "off": ins.far[1], "strong": rec["strong"],
                             "owner": g["fileofs"]})
        elif ins.op == 0xE8 and ins.target is not None:
            near_rows.append({"at": at, "target": ins.target, "strong": rec["strong"],
                              "owner": g["fileofs"], "body_target": ins.target - lo})
    return {
        "_starts": set(insns),
        "fileofs": g["fileofs"],
        "codesz": g["codesz"],
        "fixupsz": g["fixupsz"],
        "status": g["status"],
        "header_offset": g["header_offset"],
        "stub_delta": g["stub_delta"],
        "stub_count": g["stub_count"],
        "stub_valid_count": sum(1 for v in g["stub_valid"] if v),
        "strong_seed_count": len(strong_seeds),
        "coverage": coverage,
        "instructions": len(insns),
        "instructions_strong": n_strong,
        "instructions_weak": len(insns) - n_strong,
        "decode_errors_strong": len(strong_errs),
        "decode_errors_weak": len(errors) - len(strong_errs),
        "overlaps_strong": s["overlaps"],
        "overlaps_weak": stats["weak"]["overlaps"],
        "out_of_body_strong": s["out_of_body"],
        "budget_hit": s["budget"] or stats["weak"]["budget"],
        "far_decoded": far_rows,
        "near_decoded": near_rows,
        "errors": errors,
    }


# ---------------------------------------------------------------------------------------------
# Whole-install analysis
# ---------------------------------------------------------------------------------------------

def stub6_precondition(start: bytes, groups: list[dict]) -> dict:
    """Stub 6, its group, index and proc, and the WALLDEF wrapper's owner. Structural only."""
    out = {"stub6_bytes": start[STUB6_F:STUB6_F + 5] == STUB6_BYTES}
    slot = fr.stub_slot(groups, STUB6_F)
    if slot is None:
        out.update({"stub6_slot": False, "stub6_group_is_header": False, "stub6_index": False,
                    "stub6_proc": False, "walldef_owner_is_group": False})
        return out
    g, k = slot
    out["stub6_slot"] = True
    out["stub6_group_is_header"] = g["header_offset"] == STUB6_HEADER
    out["stub6_index"] = k == STUB6_INDEX and bool(g["stub_valid"][k])
    out["stub6_proc"] = g["procs"][k] == STUB6_PROC and g["fileofs"] + STUB6_PROC == WALLDEF_BODY
    owner = fr.group_containing_code(groups, WALLDEF_BODY)
    out["walldef_owner_is_group"] = owner is not None and owner["fileofs"] == STUB6_GROUP_FILEOFS
    out["stub6_status"] = g["status"]
    return out


def analyse(start: bytes, ovr: bytes) -> dict:
    hdr = fr.mz_image_base(start)
    groups = groups_of(start, ovr)
    pre = stub6_precondition(start, groups)

    group_rows = []
    group_full = []          # per group: decoded instruction starts (not serialised)
    site_map: dict = {}      # at -> row
    near_map: dict = {}      # (at, owner) -> row
    for g in groups:
        tinfo = table_info(ovr, g)
        res = census_group(ovr, g)
        listed = tinfo["listed"]
        row = {k: v for k, v in res.items() if k not in ("_starts", "far_decoded", "near_decoded", "errors")}
        row["table_present"] = tinfo["present"]
        row["table_bare_offsets"] = tinfo["bare_offsets"]
        row["table_odd_size"] = tinfo["odd_size"]
        row["table_count"] = tinfo["count"]
        row["table_duplicates"] = tinfo["duplicates"]
        row["table_ok"] = tinfo["present"] and tinfo["bare_offsets"] and not tinfo["odd_size"]
        row["far_calls"] = len(res["far_decoded"])
        row["far_calls_strong"] = sum(1 for f in res["far_decoded"] if f["strong"])
        row["near_calls"] = len(res["near_decoded"])
        row["near_calls_to_walldef_body"] = sum(1 for n in res["near_decoded"] if n["target"] == WALLDEF_BODY)
        row["contains_walldef_body"] = g["fileofs"] <= WALLDEF_BODY < g["fileofs"] + g["codesz"]
        group_rows.append(row)
        group_full.append({"_starts": res["_starts"], "contains_walldef_body": row["contains_walldef_body"]})

        for f in res["far_decoded"]:
            ev = site_eval(f["at"], f["seg"], f["off"], g["fileofs"], listed, hdr)
            site = site_map.setdefault(f["at"], {"at": f["at"], "seg": f["seg"], "off": f["off"],
                                                 "owners": [], "strong": False})
            site["strong"] = site["strong"] or f["strong"]
            ev["group_status"] = g["status"]
            ev["strong"] = f["strong"]
            site["owners"].append(ev)

        for n in res["near_decoded"]:
            if n["target"] == WALLDEF_BODY:
                near_map[(n["at"], g["fileofs"])] = {
                    "at": _hex(n["at"]), "owner_fileofs": _hex(g["fileofs"]),
                    "body_target": _hex(n["body_target"]), "target_file": _hex(n["target"]),
                    "strong": n["strong"], "group_status": g["status"]}

    # Control: the handler's eleven far calls, decoded in group 0x0D46, residue agrees with the 0x21 probe.
    handler = p.handler_report(ovr, HANDLER)["far_calls"]
    hl = [{"at": int(c["at"], 16), "seg": c["seg"], "off": c["off"]} for c in handler]
    handler_rows = []
    residue_agree = []
    for c in hl:
        site = site_map.get(c["at"])
        owner_rows = site["owners"] if site else []
        in_handler_group = any(o["owner_fileofs"] == _hex(HANDLER_GROUP_FILEOFS) for o in owner_rows)
        rr = r.residue_for(c["off"], c["seg"], hdr)
        residue_agree.append(bool(owner_rows) and owner_rows[0].get("skew_needed_mod16") == rr["skew_needed_mod16"])
        handler_rows.append({
            "at": _hex(c["at"]), "seg": c["seg"], "off": c["off"],
            "decoded": site is not None, "in_handler_group": in_handler_group,
            "census_status": owner_rows[0]["status"] if owner_rows else None,
            "census_skew_mod16": owner_rows[0].get("skew_needed_mod16") if owner_rows else None,
            "residue_probe_skew_mod16": rr["skew_needed_mod16"],
        })

    far_sites = []
    for at in sorted(site_map):
        s = site_map[at]
        s["owners"].sort(key=lambda o: o["owner_fileofs"])
        far_sites.append(s)
    near_walldef = [near_map[k] for k in sorted(near_map)]

    status_counts: dict = {}
    for s in far_sites:
        for o in s["owners"]:
            status_counts[o["status"]] = status_counts.get(o["status"], 0) + 1
    candidates = [{"at": _hex(s["at"]), "seg": _hex(s["seg"]), "off": _hex(s["off"]),
                   "strong": s["strong"], "owners": [o for o in s["owners"] if o["candidate"]]}
                  for s in far_sites if any(o["candidate"] for o in s["owners"])]
    distinct_targets = {(s["seg"], s["off"]) for s in far_sites}
    walldef_body_decoded = any(WALLDEF_BODY in g["_starts"] for g in group_full if g["contains_walldef_body"])

    totals = {
        "parsed_groups": len(groups),
        "well_formed_groups": sum(1 for g in groups if g["status"] == "well-formed"),
        "partial_groups": sum(1 for g in groups if g["status"] == "partial"),
        "coverage_strong_clean": sum(1 for g in group_rows if g["coverage"] == "strong-walk-clean"),
        "coverage_strong_incomplete": sum(1 for g in group_rows if g["coverage"] == "strong-walk-incomplete"),
        "coverage_no_strong_seed": sum(1 for g in group_rows if g["coverage"] == "no-strong-seed"),
        "instructions": sum(g["instructions"] for g in group_rows),
        "far_call_sites": len(far_sites),
        "far_call_owner_rows": sum(len(s["owners"]) for s in far_sites),
        "far_call_sites_strong": sum(1 for s in far_sites if s["strong"]),
        "far_call_sites_weak_only": sum(1 for s in far_sites if not s["strong"]),
        "distinct_seg_off_targets": len(distinct_targets),
        "near_calls_to_walldef_body": len(near_walldef),
        "status_counts": dict(sorted(status_counts.items())),
    }

    failed = [k for k, v in pre.items() if v is False]
    if len(hl) != EXPECT_HANDLER_FAR or not all(rw["decoded"] and rw["in_handler_group"] for rw in handler_rows):
        failed.append("handler_far_calls_decoded_in_group_0x0D46")
    if len(residue_agree) != EXPECT_HANDLER_FAR or not all(residue_agree):
        failed.append("handler_residue_agrees_with_0x21_probe")
    if not walldef_body_decoded:
        failed.append("walldef_body_decoded")
    if failed:
        status = STATUS_PRECONDITION
        reason = "structural precondition(s) failed: %s; no verdict" % ", ".join(failed)
    elif candidates:
        status = STATUS_CANDIDATE
        reason = ("%d far-call site(s) are candidates under the residue rule or the literal test; "
                  "reaching the stub still needs a DI value or a decoded path that the bytes do not establish"
                  % len(candidates))
    else:
        status = STATUS_NONE
        reason = ("no decoded far call across %d parsed groups is a candidate for stub 6 under a "
                  "paragraph-aligned resident image (scope: decoded coverage, see per-group coverage)"
                  % len(groups))
    return {
        "hdr": _hex(hdr),
        "stub6_file": _hex(STUB6_F),
        "stub6_target_residue_mod16": (STUB6_F - hdr) % PARA,
        "precondition": pre,
        "walldef_body_decoded": walldef_body_decoded,
        "groups": group_rows,
        "far_call_sites": far_sites,
        "near_calls_to_walldef_body": near_walldef,
        "handler_control": handler_rows,
        "candidates": candidates,
        "totals": totals,
        "verdict": {"stub6_status": status, "reason": reason, "failed_preconditions": failed,
                    "candidate_count": len(candidates)},
        "notes": fr.scan_all(start, ovr)["notes"],
    }


# ---------------------------------------------------------------------------------------------
# Self-checks, probe driver, output
# ---------------------------------------------------------------------------------------------

def self_checks(doc: dict, hashes_before: dict, hashes_after: dict) -> list:
    owner_keys = [(s["at"], o["owner_fileofs"]) for s in doc["far_call_sites"] for o in s["owners"]]
    checks = [
        ("preconditions_hold", not doc["verdict"]["failed_preconditions"]),
        ("handler_eleven_far_calls_decoded_in_0xd46",
         len(doc["handler_control"]) == EXPECT_HANDLER_FAR
         and all(rw["decoded"] and rw["in_handler_group"] for rw in doc["handler_control"])),
        ("handler_residue_agrees_with_0x21_probe",
         all(rw["census_skew_mod16"] == rw["residue_probe_skew_mod16"] for rw in doc["handler_control"])),
        ("walldef_body_decoded", doc["walldef_body_decoded"] is True),
        ("every_far_site_has_an_owner", all(s["owners"] for s in doc["far_call_sites"])),
        ("owner_rows_unique", len(owner_keys) == len(set(owner_keys))),
        ("owner_rows_match_totals", len(owner_keys) == doc["totals"]["far_call_owner_rows"]),
        ("verdict_never_established",
         doc["verdict"]["stub6_status"] in (STATUS_CANDIDATE, STATUS_NONE, STATUS_PRECONDITION)),
        ("inputs_unchanged", hashes_before == hashes_after),
    ]
    return [{"name": n, "ok": bool(ok)} for n, ok in checks]


def check_out(out: Path, install: Path) -> None:
    o = out.resolve()
    i = install.resolve()
    if o == i or i in o.parents:
        raise CensusRefusal("output folder is inside the install folder")
    try:
        o.relative_to(DATA_WORK.resolve())
    except ValueError:
        raise CensusRefusal("output folder must be under data/work/")


def probe(install: Path, out: Path) -> tuple:
    check_out(out, install)
    before = _hashes(install)
    inputs = p.load_inputs(install)
    doc = analyse(inputs[EXE_NAME], inputs[OVR_NAME])
    after = _hashes(install)
    out_doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "established": False,
        "mappings": [],
        "inputs": {k: {"size": len(v), "sha256": _sha(v)} for k, v in inputs.items()},
        "target": {"stub6_file": _hex(STUB6_F), "stub6_header": _hex(STUB6_HEADER), "stub6_index": STUB6_INDEX,
                   "stub6_proc": _hex(STUB6_PROC), "walldef_body": _hex(WALLDEF_BODY),
                   "stub6_group_fileofs": _hex(STUB6_GROUP_FILEOFS)},
        **doc,
    }
    out_doc["self_checks"] = self_checks(out_doc, before, after)
    return out_doc, (0 if all(c["ok"] for c in out_doc["self_checks"]) else 1)


def render_md(doc: dict) -> str:
    v = doc["verdict"]
    t = doc["totals"]
    lines = [
        "# Pool of Radiance: far-call census toward START stub 6 (WALLDEF wrapper; static, diagnostic)",
        "",
        "**Status: STATIC-PROBE-ONLY. `playable: false`, `established: false`, `mappings: []`.**",
        "",
        "## Verdict",
        "",
        "- `stub6_status`: **%s**" % v["stub6_status"],
        "- Reason: %s" % v["reason"],
        "- Candidate sites: %d" % v["candidate_count"],
        "- Stub 6: START.EXE %s, header %s index %d, proc %s into the WALLDEF wrapper %s (not the GEO fill)"
        % (doc["target"]["stub6_file"], doc["target"]["stub6_header"], doc["target"]["stub6_index"],
           doc["target"]["stub6_proc"], doc["target"]["walldef_body"]),
        "- Residue a listed seg word needs: `off ≡ %d (mod 16)` (hdr %s)"
        % (doc["stub6_target_residue_mod16"], doc["hdr"]),
        "",
        "## Totals",
        "",
        "| Item | Value |",
        "| --- | ---: |",
    ]
    for k in ("parsed_groups", "well_formed_groups", "partial_groups", "coverage_strong_clean",
              "coverage_strong_incomplete", "coverage_no_strong_seed", "instructions", "far_call_sites",
              "far_call_owner_rows", "far_call_sites_strong", "far_call_sites_weak_only",
              "distinct_seg_off_targets", "near_calls_to_walldef_body"):
        lines.append("| %s | %s |" % (k, t[k]))
    lines += ["", "Status counts (per site, per owner): `%s`" % json.dumps(t["status_counts"], sort_keys=True), ""]
    lines += [
        "## Parsed groups",
        "",
        "| fileofs | codesz | fixupsz | status | coverage | insns | far (strong) | near | E8 to WALLDEF wrapper | table ok | strong errs |",
        "| --- | ---: | ---: | --- | --- | ---: | --- | ---: | ---: | --- | ---: |",
    ]
    for g in doc["groups"]:
        lines.append("| %s | %s | %d | %s | %s | %d | %d (%d) | %d | %d | %s | %d |" % (
            _hex(g["fileofs"]), _hex(g["codesz"]), g["fixupsz"], g["status"], g["coverage"],
            g["instructions"], g["far_calls"], g["far_calls_strong"], g["near_calls"],
            g["near_calls_to_walldef_body"], "yes" if g["table_ok"] else "NO", g["decode_errors_strong"]))
    lines += ["", "## Candidate far-call sites", ""]
    if not doc["candidates"]:
        lines.append("None.")
    else:
        lines += ["| at | seg:off | strong | owner | status | seg listed | off listed | DI constraint mod 64K |",
                  "| --- | --- | --- | --- | --- | --- | --- | ---: |"]
        for cand in doc["candidates"]:
            for o in cand["owners"]:
                lines.append("| %s | %s:%s | %s | %s | %s | %s | %s | %s |" % (
                    cand["at"], cand["seg"], cand["off"], "yes" if cand["strong"] else "no", o["owner_fileofs"],
                    o["status"], o["seg_word_listed"], o["off_word_listed"], o.get("di_constraint_mod64k", "-")))
    lines += ["", "## Near E8 calls to the WALLDEF wrapper", ""]
    if not doc["near_calls_to_walldef_body"]:
        lines.append("None decoded.")
    else:
        for n in doc["near_calls_to_walldef_body"]:
            lines.append("- at %s in group %s (body target %s), strong: %s"
                         % (n["at"], n["owner_fileofs"], n["body_target"], n["strong"]))
    lines += ["", "## Handler control (the eleven 0x19BA far calls)", "",
              "| at | seg:off | census status | census skew | 0x21-probe skew |",
              "| --- | --- | --- | ---: | ---: |"]
    for rw in doc["handler_control"]:
        lines.append("| %s | %04X:%04X | %s | %s | %s |" % (
            rw["at"], rw["seg"], rw["off"], rw["census_status"], rw["census_skew_mod16"],
            rw["residue_probe_skew_mod16"]))
    lines += ["", "## Self-checks", ""]
    lines += ["- %s: %s" % (c["name"], "pass" if c["ok"] else "FAIL") for c in doc["self_checks"]]
    lines += [
        "",
        "## Limits",
        "",
        "- Only descriptor groups with a stub run (accepted or partial) are parsed. An overlay body with no stub run",
        "  is not in the census.",
        "- Weak sites come from prologue byte patterns and may be data decoded as code.",
        "- The DI delta is not established. A candidate is a residue or literal match, not a runtime fact.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    (out / RESULT_MD).write_text(render_md(doc), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="PoR far-call census toward START stub 6 (static, read-only).")
    ap.add_argument("--install", required=True, type=Path, help="folder holding the pinned GAME.OVR and START.EXE")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder, under data/work/")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out)
    except (p.ProbeRefusal, CensusRefusal) as e:
        print("refused: %s" % e, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("stub6_status=%s candidates=%d self_checks=%s" % (
        doc["verdict"]["stub6_status"], doc["verdict"]["candidate_count"], "pass" if code == 0 else "FAIL"))
    return code


if __name__ == "__main__":
    sys.exit(main())
