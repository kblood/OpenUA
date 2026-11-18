#!/usr/bin/env python3
"""Pool of Radiance: PoR-wide static census of far calls that could reach START stub 6 (STATIC, DIAGNOSTIC).

Naming. This census was first written as a GEO-loader census, and the ``geo`` in its file name is historical.
Its anchor is wrong for that purpose: START stub 6 (proc ``0x0E08``) enters the WALLDEF wrapper at
``GAME.OVR:0x2F6FF``, which builds ``WALLDEF<d>.dax`` (see ``docs/por-ecl-stub6-key-arg-probe.md``). The GEO
fill is the separate procedure ``GAME.OVR:0x2F9BE``, which this census does not test. Every result here is about
stub 6 and the WALLDEF wrapper; none is a GEO-loader result.

STATUS: static-probe-only. ``playable: false``. No events, no mappings, no module output.

Question. Stub 6 is ``START.EXE`` offset ``15884`` (``0x3E0C``): stub index 6 of the VROOMM descriptor
group at header ``0x3DD7`` (partial, stub run at header+``0x17``), proc ``0x0E08`` into the WALLDEF wrapper
``GAME.OVR:0x2F6FF`` (group fileofs ``0x2E8F7``). Across every parsed GAME.OVR overlay body, which
instruction-decoded far calls (``9A seg:off``) could resolve to that stub, and which near calls (``E8``)
reach the WALLDEF wrapper?

Method (read-only, bounded, stdlib only):

* Groups. ``por_farcall_resolve.scan_all`` supplies the parsed descriptor groups: ``well-formed`` (every
  stub well-formed) and ``partial`` (a strict majority well-formed). Each group's body is
  ``[fileofs, fileofs+codesz)`` and its fixup table is ``fixupsz/2`` words at ``fileofs+codesz``.
* Decode. Per group, two passes over ``por_loadpieces_handler.decode``, a recursive descent that follows
  fall-through, ``jcc``/``jmp`` and ``E8`` targets inside the body and stops at ``ret``/``retf``/far or
  indirect jumps. Pass 1 (**strong**) seeds only from the group's well-formed stub procs. Pass 2 (**weak**)
  seeds from every ``55 89 E5`` / ``55 8B EC`` prologue byte pattern in the body, skipping instructions pass 1
  already decoded. A far call is ``strong`` if pass 1 reached it. A weak call is a decode of a byte pattern
  with no stub entry: it is reported, but it is not a proof of code.
* Owner tables. A far call's seg word is at body offset ``at+3-fileofs`` and its offset word at ``at+1-fileofs``.
  Both are tested against the OWNER group's fixup table only (a table applies to the code it was built for).
* Residue rule, per (site, owner). The resident image is an MZ image at file ``hdr`` (``cparhdr*16``, 0x200
  here), so a stub at file ``F`` sits at image ``F-hdr``.
  - Seg word listed, offset word not listed: the loader adds an unknown delta ``DI`` to the seg word, so the
    image is ``hdr + (seg+DI)*16 + off``. The site can reach the stub only if ``off ≡ (F-hdr) (mod 16)``, whatever
    ``DI`` is. Such a site is ``candidate-given-di-not-established``; the DI it would need is reported as a
    constraint (``di_constraint_mod64k``), not as a value.
  - Seg word not listed: the literal image ``hdr + seg*16 + off`` is tested for exact equality with ``F``.
  - Offset word listed: the offset itself receives ``DI``, so no exact or residue test applies; the row is
    ``undecided-*`` and never a candidate.
* Near calls. ``E8`` decoded inside a body with a target equal to the WALLDEF wrapper is reported with its owner.
  A near call only reaches bytes of its own body; its target is body-relative.

Controls (checked, not trusted). The eleven far calls of the 0x19BA handler (the 0x21/0x37 handler) must be
decoded in group ``0x0D46``, and each per-site residue must agree with
``por_ecl_21_fixup_residue_probe.residue_for``. The stub-6 bytes, its group, index and proc, and the wrapper
decode must hold (``precondition-failed`` otherwise).

Evidence labels. ``decoded`` = a decoder result. ``strong`` = reached from a stub proc by decoded control flow.
``weak`` = reached only from a prologue byte pattern. ``table-membership`` = exact test against the owner's table.
``arithmetic`` = residue and literal tests. Nothing here is ``established``.

Verdict scope. ``stub6_status`` is one of:

* ``precondition-failed``: a structural check failed; no verdict.
* ``candidate-given-di-not-established``: at least one decoded far call (strong or weak) is a candidate under
  the residue rule or the literal test. Reaching it still needs a DI value, or a literal match, that the bytes
  do not establish, and a decoded path from a real entry.
* ``no-candidate-under-paragraph-model``: no decoded far call is a candidate. This is scoped to the decoded
  coverage, which is reported per group.

Usage::

    python tools/por_geo_farcall_census.py --install "PATH/TO/POOLRAD" \\
        -o data/work/por-geo-farcall-census/retail

Exit: 0 every self-check passes; 1 a self-check failed; 2 a named refusal (missing or unpinned file,
output inside the install, output outside ``data/work/``).
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

SCHEMA = "openua.por-geo-farcall-census"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_geo_farcall_census.py"
RESULT_JSON = "por_geo_farcall_census.json"
RESULT_MD = "por_geo_farcall_census.md"

OVR_NAME = fr.OVR_NAME
EXE_NAME = fr.EXE_NAME
PINS = fr.PINNED

STUB6_F = 15884                          # START.EXE offset of stub 6 (0x3E0C)
STUB6_BYTES = bytes.fromhex("cd 3f 08 0e 00")
STUB6_HEADER = 0x3DD7                         # descriptor header holding stub 6 (partial, stub run at +0x17)
STUB6_INDEX = 6
STUB6_GROUP_FILEOFS = 0x2E8F7
STUB6_PROC = 0x0E08
WALLDEF_BODY = 0x2F6FF                          # GAME.OVR body stub 6 enters: the WALLDEF wrapper (= 0x2E8F7 + 0x0E08)

HANDLER = 0x19BA                            # the 0x21/0x37 handler whose eleven far calls are the control set
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
    out = {}
    for name in (OVR_NAME, EXE_NAME):
        out[name] = _sha((install / name).read_bytes())
    return out


def groups_of(start: bytes, ovr: bytes) -> list[dict]:
    """Every parsed descriptor group: accepted (well-formed) then partial, each tagged with its status."""
    res = fr.scan_all(start, ovr)
    out = []
    for g in res["groups"] + res["partial_groups"]:
        out.append(dict(g))
    out.sort(key=lambda g: g["fileofs"])
    return out


def strong_procs(g: dict) -> list[int]:
    """Proc offsets of the group's well-formed stubs. A malformed slot is never a stub."""
    return [g["procs"][k] for k, ok in enumerate(g["stub_valid"]) if ok]


def table_info(ovr: bytes, g: dict) -> dict:
    """The owner's fixup table: fixupsz/2 sorted 16-bit words at fileofs+codesz.

    ``listed`` is the set of body offsets of listed words (seg words; the table has no other field).
    A table that runs past the overlay is not read and is reported as ``present: False``.
    """
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
    """Recursive descent restricted to [lo, hi). Adds to ``insns``/``owned`` in place."""
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
            elif fl == "call":
                if ins.target is not None and lo <= ins.target < hi:
                    work.append(ins.target)
                else:
                    stats["out_of_body"] += 1
                at = ins.end
            elif fl == "jcc":
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
    """Decode one group body in two passes (strong from stub procs, weak from prologues)."""
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

def stub6_precondition(start: bytes, ovr: bytes, groups: list[dict], hdr: int) -> dict:
    """Stub 6, its group, index and proc, and the WALLDEF wrapper's owner. Structural only."""
    out = {"stub6_bytes": start[STUB6_F:STUB6_F + 5] == STUB6_BYTES}
    slot = fr.stub_slot(groups, STUB6_F)
    if slot is None:
        out["stub6_slot"] = False
        out["stub6_group_is_header"] = False
        out["stub6_index"] = False
        out["stub6_proc"] = False
        out["walldef_owner_is_group"] = False
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
    pre = stub6_precondition(start, ovr, groups, hdr)

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
                near_map[(n["at"], g["fileofs"])] = {"at": n["at"], "owner_fileofs": _hex(g["fileofs"]),
                                                     "body_target": _hex(n["body_target"]),
                                                     "target_file": _hex(n["target"]),
                                                     "strong": n["strong"],
                                                     "group_status": g["status"]}

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
        agree = bool(owner_rows) and owner_rows[0].get("skew_needed_mod16") == rr["skew_needed_mod16"]
        residue_agree.append(agree)
        handler_rows.append({
            "at": _hex(c["at"]), "seg": c["seg"], "off": c["off"],
            "decoded": site is not None,
            "in_handler_group": in_handler_group,
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
# Pinned input wrapper, reports and CLI
# ---------------------------------------------------------------------------------------------

def check_out(out: Path, install: Path) -> None:
    out_r = out.resolve()
    install_r = install.resolve()
    if out_r == install_r or install_r in out_r.parents:
        raise p.ProbeRefusal("output folder is inside the install folder")
    data_work_r = DATA_WORK.resolve()
    try:
        if out_r == data_work_r:
            raise ValueError("output cannot be the data/work root")
        out_r.relative_to(data_work_r)
    except ValueError as exc:
        raise p.ProbeRefusal("output folder must be under data/work/") from exc


def self_checks(doc: dict, hashes_before: dict, hashes_after: dict) -> list[dict]:
    pre = doc["precondition"]
    handler = doc["handler_control"]
    checks = [
        ("stub6_preconditions_hold", all(v is not False for v in pre.values())),
        ("walldef_body_decoded", doc["walldef_body_decoded"] is True),
        ("handler_control_count", len(handler) == EXPECT_HANDLER_FAR),
        ("handler_control_decoded_in_owner", all(
            h["decoded"] and h["in_handler_group"] for h in handler)),
        ("handler_residue_control", len(handler) == EXPECT_HANDLER_FAR and all(
            h["census_skew_mod16"] == h["residue_probe_skew_mod16"] for h in handler)),
        ("group_rows_match_parse_count", len(doc["groups"]) == doc["totals"]["parsed_groups"]),
        ("site_owner_rows_match_totals",
         sum(len(s["owners"]) for s in doc["far_call_sites"])
         == doc["totals"]["far_call_owner_rows"]),
        ("no_geo_binding_claimed", doc["geo_binding_established"] is False),
        ("never_established", doc["verdict"]["stub6_status"] != "established"),
        ("inputs_unchanged", hashes_before == hashes_after),
    ]
    return [{"name": name, "ok": bool(ok)} for name, ok in checks]


def probe(install: Path, out: Path) -> tuple[dict, int]:
    check_out(out, install)
    hashes_before = _hashes(install)
    inputs = p.load_inputs(install)
    doc = analyse(inputs[EXE_NAME], inputs[OVR_NAME])
    hashes_after = _hashes(install)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "geo_binding_established": False,
        "inputs": {name: {"size": len(data), "sha256": _sha(data)}
                   for name, data in sorted(inputs.items())},
        **doc,
    }
    doc["self_checks"] = self_checks(doc, hashes_before, hashes_after)
    return doc, (0 if all(c["ok"] for c in doc["self_checks"]) else 1)


def render_report(doc: dict) -> str:
    t = doc["totals"]
    v = doc["verdict"]
    lines = [
        "# PoR far-call census toward START stub 6 (WALLDEF wrapper entry; static diagnostic)",
        "",
        "**`playable: false`; `geo_binding_established: false`.** This report",
        "does not identify a runtime call or map an overlay to a GEO archive,",
        "block, game area or campaign location.",
        "",
        "## Verdict",
        "",
        "- status: **%s**" % v["stub6_status"],
        "- %s" % v["reason"],
        "- Stub 6: START.EXE %s; WALLDEF wrapper: GAME.OVR %s; MZ image header: %s"
        % (doc["stub6_file"], _hex(WALLDEF_BODY), doc["hdr"]),
        "- Direct near calls to the WALLDEF wrapper: %d" % t["near_calls_to_walldef_body"],
        "- Not a GEO-loader census: the GEO fill (GAME.OVR 0x2F9BE) is not the anchor. No GEO binding is claimed.",
        "",
        "## Coverage",
        "",
        "| measure | count |",
        "| --- | ---: |",
        "| parsed overlay groups (well-formed + partial) | %d |" % t["parsed_groups"],
        "| strongly seeded walks clean / incomplete | %d / %d"
        % (t["coverage_strong_clean"], t["coverage_strong_incomplete"]),
        "| decoded instruction starts | %d |" % t["instructions"],
        "| decoded far-call sites | %d (%d strong, %d weak-only)"
        % (t["far_call_sites"], t["far_call_sites_strong"], t["far_call_sites_weak_only"]),
        "| far-call owner rows | %d |" % t["far_call_owner_rows"],
        "| distinct literal seg:off operands | %d |" % t["distinct_seg_off_targets"],
        "| candidates under unknown-delta residue/literal test | %d |"
        % v["candidate_count"],
        "",
        "## Candidate boundary",
        "",
        "A candidate is an arithmetic possibility, not a target binding. A listed",
        "segment word can receive an unknown fixup delta; the table itself stores",
        "only body offsets. Strong means reached from a parsed overlay stub by the",
        "bounded decoder. Weak means reached only from a prologue byte pattern.",
        "Neither label proves runtime reachability. The census is restricted to",
        "decoded paths in the parsed group bodies, and its paragraph-aligned MZ",
        "image model is explicit and unverified.",
        "",
        "## Candidate sites",
        "",
        "| site | literal seg:off | strong path | owner group(s) | candidate owner(s) |",
        "| --- | --- | --- | --- | --- |",
    ]
    for site in doc["candidates"]:
        owners = site["owners"]
        lines.append("| %s | %04X:%04X | %s | %s | %s |" % (
            site["at"], int(site["seg"], 16), int(site["off"], 16),
            str(site["strong"]).lower(),
            ", ".join(o["owner_fileofs"] for o in owners),
            ", ".join("%s (%s, %s)" % (o["owner_fileofs"], o["status"],
                                        "strong" if o["strong"] else "weak") for o in owners)))
    if not doc["candidates"]:
        lines.append("| none | | | | |")
    lines += ["", "## Handler control against the 0x21 residue probe", "",
              "| handler far call | decoded in owner group | census residue mod 16 | 0x21 residue mod 16 |",
              "| --- | --- | ---: | ---: |"]
    for hrow in doc["handler_control"]:
        lines.append("| %s %04X:%04X | %s | %s | %s |" % (
            hrow["at"], hrow["seg"], hrow["off"],
            str(hrow["decoded"] and hrow["in_handler_group"]).lower(),
            hrow["census_skew_mod16"], hrow["residue_probe_skew_mod16"]))
    lines += ["", "## Input pins", ""]
    for name, pin in doc["inputs"].items():
        lines.append("- `%s`: %d bytes, SHA-256 `%s`" % (name, pin["size"], pin["sha256"]))
    lines += ["", "## Self-checks", ""]
    lines += ["- %s: %s" % (c["name"], "PASS" if c["ok"] else "FAIL")
              for c in doc["self_checks"]]
    lines.append("")
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / RESULT_MD).write_text(render_report(doc), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="PoR far-call census toward START stub 6 (static, read-only).")
    ap.add_argument("--install", required=True, type=Path,
                    help="folder containing pinned GAME.OVR and START.EXE")
    ap.add_argument("-o", "--out", required=True, type=Path,
                    help="output folder under data/work/")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out)
    except (p.ProbeRefusal, OSError, ValueError, struct.error) as exc:
        print("por_geo_farcall_census: refused: %s" % exc, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("stub6_status=%s candidates=%d self_checks=%s" % (
        doc["verdict"]["stub6_status"], doc["verdict"]["candidate_count"],
        "pass" if code == 0 else "FAIL"))
    return code


if __name__ == "__main__":
    sys.exit(main())
