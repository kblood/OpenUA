#!/usr/bin/env python3
"""Pool of Radiance: 0x21 far-call fixup-record residue probe (STATIC, DIAGNOSTIC ONLY).

STATUS: static-probe-only. ``playable: false``. No events, no mappings, no module output.

Question. The 0x21 dispatch probe (``tools/por_ecl_21_dispatch_probe.py``) left nine far calls of the
handler at ``GAME.OVR:0x19BA`` model-dependent: their segment words are listed in the fixup table of the
overlay group whose descriptor header is at ``START.EXE`` offset ``0x3C3`` (code at ``GAME.OVR`` ``0x0D46``).
Does any fixup record tie one of those sites to a base that resolves its target to the GEO stub at
``START.EXE`` offset ``15884`` (``0x3E0C``, stub index 6 of group ``0x3DD7``), or do the records leave the
question ambiguous?

Only PoR bytes are used. No GoldBox or other-title rule, no emulator, no runtime capture, no retail write.

Method (read-only, bounded):

* Header. ``START.EXE`` ``0x3C3`` must read ``CD 3F 00 00`` then fileofs ``0x0D46``, codesz ``0x350D``,
  fixupsz ``804``, jmpcnt ``2``. The group's code and fixup table are read from the parsed values.
* Table. The fixup table is ``fixupsz/2`` sorted 16-bit words at ``fileofs + codesz``. Each word is an
  overlay-relative body offset (``< codesz``). The table has no other field, so no record carries a base
  value by itself.
* Applier. ``START.EXE`` ``0xA9E8`` is ``AD 8B D8 26 01 3F E2`` (``lodsw; mov bx,ax; add es:[bx],di; loop``):
  each listed word receives ``+DI``. ``DI`` is not established (``docs/por-ecl-fixup-probe.md``). It is treated
  here as an unknown integer and is never assumed.
* Residue. A call ``seg:off`` whose seg word is listed reaches the image address ``hdr + (seg + DI)*16 + off``
  with ``hdr = 0x200`` (the MZ header size). ``DI`` moves the target only in whole paragraphs. So for a
  paragraph-aligned resident image, the target can be the GEO stub only if ``off == (15884 - hdr) mod 16``,
  i.e. ``off ≡ 0xC (mod 16)``, whatever ``DI`` is. For each site the probe reports the sub-paragraph skew
  ``k`` it would need, and whether ``k`` is ``0`` (paragraph-consistent), ``15`` (the CoK ``-1`` skew), or
  ``10``/``6`` (the quoted ``0x50A`` displacement, both signs).
* Unlisted seg words (not expected) are read as literals: the target is ``hdr + seg*16 + off`` exactly.
* Checks (preconditions for the residue argument): header bytes and fields; applier bytes; the GEO stub
  bytes and its candidate row; eleven far calls from a complete walk; every offset word NOT listed; the
  table is bare sorted in-range body offsets.

Evidence labels. ``decoded`` = a walk or byte read. ``table-membership`` = exact byte test against the
fixup table. ``arithmetic`` = residue and skew computed from the two above. Nothing here is ``established``.

Verdict scope. ``geo_status`` is one of:

* ``precondition-failed``: a structural check failed; no verdict.
* ``candidate-given-di-not-established``: some site is paragraph-consistent with the GEO stub (or is a
  literal hit); reaching it still needs a DI value that is not in the bytes.
* ``no-site-reaches-geo-under-paragraph-base``: no site can reach the GEO stub for any integer DI under a
  paragraph-aligned resident image. Each site would need a sub-paragraph base skew, which no byte supports.

The probe never returns ``established``.

Usage::

    python tools/por_ecl_21_fixup_residue_probe.py --install "PATH/TO/POOLRAD" \\
        -o data/work/por-ecl-21-fixup-residue-probe/retail

Stdlib + the read-only modules above. Exit: 0 every self-check passes; 1 a self-check failed;
2 a named refusal (missing or unpinned file, output inside the install, output outside ``data/work/``).
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
import por_ecl_21_dispatch_probe as p  # noqa: E402  (read-only; not edited)
import por_farcall_resolve as fr  # noqa: E402  (read-only; not edited)

SCHEMA = "openua.por-ecl-21-fixup-residue-probe"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_ecl_21_fixup_residue_probe.py"
RESULT_JSON = "por_ecl_21_fixup_residue_probe.json"
RESULT_MD = "por_ecl_21_fixup_residue_probe.md"

HANDLER = 0x19BA                    # the 0x21 and 0x37 handler (checked by the 0x21 probe)
EXPECT_FAR_CALLS = 11
EXPECT_LISTED_SEG_WORDS = 11        # the 0x21 probe's finding: every seg word is listed (checked, not trusted)
HEADER_AT = 0x3C3                   # START.EXE descriptor header of the handler's overlay group
HEADER_MAGIC = bytes.fromhex("cd 3f 00 00")
EXPECT_GROUP = {"fileofs": 0x0D46, "codesz": 0x350D, "fixupsz": 804, "jmpcnt": 2}
APPLIER_AT = 0xA9E8                 # START.EXE: lodsw; mov bx,ax; add es:[bx],di; loop
APPLIER_BYTES = bytes.fromhex("ad 8b d8 26 01 3f e2")
GEO_STUB_F = 15884                  # START.EXE offset of the GEO stub (0x3E0C)
GEO_STUB_BYTES = bytes.fromhex("cd 3f 08 0e 00")
GEO_HEADER = 0x3DD7                 # group that holds the GEO stub (partial, stub run at +0x17)
GEO_INDEX = 6
GEO_BODY = 0x2F6FF                  # GAME.OVR body the GEO stub enters (proc 0x0E08 of group 0x2E8F7)
PARA = 16
SEG_MOD = 0x10000
QUOTED_DISPLACEMENT = 0x50A         # the displacement the fixup-entry doc quotes (not paragraph-aligned)
SKEW_LABELS = {
    "zero": 0,
    "cok_minus_1": PARA - 1,
    "quoted_0x50a_plus": QUOTED_DISPLACEMENT % PARA,
    "quoted_0x50a_minus": (-QUOTED_DISPLACEMENT) % PARA,
}
STATUS_PRECONDITION = "precondition-failed"
STATUS_CANDIDATE = "candidate-given-di-not-established"
STATUS_NONE = "no-site-reaches-geo-under-paragraph-base"


class ResidueRefusal(p.ProbeRefusal):
    """A named refusal (the same class as the 0x21 probe, so one handler covers both)."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%04X" % v


def _hashes(install: Path) -> dict:
    return {name: _sha((install / name).read_bytes()) for name in p.PINS}


# ---------------------------------------------------------------------------------------------
# Pure pieces (bytes or integers in, dict out). Tests drive these directly with synthetic values.
# ---------------------------------------------------------------------------------------------

def read_header(start: bytes) -> dict:
    """The descriptor header at START.EXE 0x3C3, read from its bytes."""
    if len(start) < HEADER_AT + 12:
        raise ResidueRefusal("START.EXE is too short to hold the 0x3C3 header")
    magic_ok = start[HEADER_AT:HEADER_AT + 4] == HEADER_MAGIC
    fo, cs, fs, jc = struct.unpack_from("<IHHH", start, HEADER_AT + 4)
    matches = magic_ok and {"fileofs": fo, "codesz": cs, "fixupsz": fs, "jmpcnt": jc} == EXPECT_GROUP
    return {
        "at": _hex(HEADER_AT),
        "bytes": start[HEADER_AT:HEADER_AT + 12].hex(" "),
        "magic_ok": magic_ok,
        "fileofs": fo,
        "codesz": cs,
        "fixupsz": fs,
        "jmpcnt": jc,
        "matches_expected_group": matches,
    }


def fixup_words(ovr: bytes, fileofs: int, codesz: int, fixupsz: int) -> list[int]:
    """The fixup table: fixupsz/2 16-bit words at fileofs + codesz. Refuses a short overlay."""
    base = fileofs + codesz
    n = fixupsz // 2
    if base + 2 * n > len(ovr):
        raise ResidueRefusal("GAME.OVR is too short for the fixup table at 0x%x" % base)
    return list(struct.unpack_from("<%dH" % n, ovr, base)) if n else []


def table_facts(words: list[int], codesz: int) -> dict:
    """Structural facts about the table: sorted, in-range body offsets, no duplicates."""
    return {
        "count": len(words),
        "sorted": all(a <= b for a, b in zip(words, words[1:])),
        "all_below_codesz": all(w < codesz for w in words),
        "duplicates": len(words) - len(set(words)),
        "bare_offsets": (all(a <= b for a, b in zip(words, words[1:]))
                         and all(w < codesz for w in words)),
    }


def residue_for(off: int, seg: int, hdr: int, target: int = GEO_STUB_F) -> dict:
    """Sub-paragraph skew a listed site would need to reach ``target`` for some integer DI.

    The image address is ``hdr + (seg + DI)*16 + off``. DI moves it only in multiples of 16, so the
    skew needed is ``(target - hdr - off) mod 16``. Zero means the site is paragraph-consistent: a DI
    value exists (``di_needed_mod64k``), but DI itself is not established.
    """
    d = target - hdr - off
    skew = d % PARA
    rec = {
        "skew_needed_mod16": skew,
        "skew_labels": [k for k, v in SKEW_LABELS.items() if v == skew],
        "paragraph_consistent": skew == 0,
    }
    if skew == 0:
        s_needed = d // PARA
        rec["seg_needed_mod64k"] = s_needed % SEG_MOD
        rec["di_needed_mod64k"] = (s_needed - seg) % SEG_MOD
    return rec


def site_record(at: int, seg: int, off: int, fileofs: int, listed: set[int], hdr: int,
                target: int = GEO_STUB_F) -> dict:
    """One far call: its body offsets, list membership, and whether it can reach the target."""
    seg_body = at + 3 - fileofs
    off_body = at + 1 - fileofs
    seg_listed = seg_body in listed
    off_listed = off_body in listed
    literal = hdr + seg * PARA + off
    rec = {
        "at": _hex(at),
        "seg": _hex(seg),
        "off": _hex(off),
        "seg_body": _hex(seg_body),
        "off_body": _hex(off_body),
        "seg_word_listed": seg_listed,
        "off_word_listed": off_listed,
        "literal_image": _hex(literal),
    }
    if seg_listed:
        rec["model"] = "fixup-delta (DI not established)"
        rec["residue"] = residue_for(off, seg, hdr, target)
        rec["geo_candidate_site"] = rec["residue"]["paragraph_consistent"]
    else:
        rec["model"] = "literal (no fixup delta)"
        rec["residue"] = None
        rec["geo_candidate_site"] = literal == target
    return rec


def decide(rows: list[dict], preconditions: dict) -> dict:
    """The verdict. Never returns 'established'."""
    failed = [k for k, v in preconditions.items() if not v]
    candidates = [r["at"] for r in rows if r["geo_candidate_site"]]
    if failed:
        status = STATUS_PRECONDITION
        reason = "structural precondition(s) failed: %s; no verdict" % ", ".join(failed)
    elif candidates:
        status = STATUS_CANDIDATE
        reason = ("site(s) %s are paragraph-consistent with the GEO stub; reaching it still needs a DI value "
                  "that is not in the bytes" % ", ".join(candidates))
    else:
        status = STATUS_NONE
        reason = ("no far call can reach the GEO stub for any integer DI under a paragraph-aligned resident "
                  "image; each would need a sub-paragraph base skew, which no byte supports")
    return {
        "geo_status": status,
        "candidate_sites": candidates,
        "reason": reason,
        "failed_preconditions": failed,
    }


# ---------------------------------------------------------------------------------------------
# Analysis (bytes in, dict out)
# ---------------------------------------------------------------------------------------------

def analyse(start: bytes, ovr: bytes) -> dict:
    hdr = fr.mz_image_base(start)
    header = read_header(start)
    fileofs, codesz, fixupsz = header["fileofs"], header["codesz"], header["fixupsz"]
    words = fixup_words(ovr, fileofs, codesz, fixupsz)
    table = table_facts(words, codesz)
    listed = set(words)

    hr = p.handler_report(ovr, HANDLER)
    far = [{"at": int(c["at"], 16), "seg": c["seg"], "off": c["off"]} for c in hr["far_calls"]]
    resolved = fr.resolve(start, ovr, far)
    cls_by_at = {r["at"]: r.get("classification") for r in resolved["far_calls"]}

    rows = []
    for c in far:
        rec = site_record(c["at"], c["seg"], c["off"], fileofs, listed, hdr)
        rec["zero_skew_classification"] = cls_by_at.get(c["at"])
        rec["in_group"] = fileofs <= c["at"] and c["at"] + 5 <= fileofs + codesz
        rows.append(rec)

    geo_stub = [c for c in p.geo_stub_candidates(start, ovr, GEO_BODY)
                if c["stub_image_f"] == GEO_STUB_F and c["stub_valid"]
                and c["group_header"] == _hex(GEO_HEADER) and c["stub_index"] == GEO_INDEX]

    preconditions = {
        "header_matches_expected_group": header["matches_expected_group"],
        "fixup_table_bare_offsets": table["bare_offsets"],
        "applier_bytes_match": start[APPLIER_AT:APPLIER_AT + len(APPLIER_BYTES)] == APPLIER_BYTES,
        "geo_stub_bytes_match": start[GEO_STUB_F:GEO_STUB_F + len(GEO_STUB_BYTES)] == GEO_STUB_BYTES,
        "geo_stub_is_index6_of_0x3DD7": len(geo_stub) == 1,
        "far_calls_eleven_and_walk_complete": len(far) == EXPECT_FAR_CALLS and hr["walk_complete"] is True,
        "all_far_calls_in_group": all(r["in_group"] for r in rows),
        "no_offset_word_listed": not any(r["off_word_listed"] for r in rows),
    }
    verdict = decide(rows, preconditions)

    # Sub-paragraph skew each site needs (reporting only; not a verdict).
    skew_summary = {
        "paragraph_consistent_sites": [r["at"] for r in rows if r.get("residue") and r["residue"]["paragraph_consistent"]],
        "cok_minus_1_sites": [r["at"] for r in rows if r.get("residue") and "cok_minus_1" in r["residue"]["skew_labels"]],
        "quoted_0x50a_sites": [r["at"] for r in rows if r.get("residue")
                               and any(l.startswith("quoted_0x50a") for l in r["residue"]["skew_labels"])],
    }

    return {
        "image_base": _hex(hdr),
        "group": {"header": header, "table": table, "table_offset": _hex(fileofs + codesz),
                  "fixup_words_read": len(words)},
        "handler": {"entry": _hex(HANDLER), "walk_complete": hr["walk_complete"],
                    "instruction_count": hr["instruction_count"], "far_call_count": len(far)},
        "geo_stub": {"start_f": _hex(GEO_STUB_F), "bytes": GEO_STUB_BYTES.hex(" "),
                     "group_header": _hex(GEO_HEADER), "index": GEO_INDEX,
                     "candidate_rows": geo_stub, "body": _hex(GEO_BODY)},
        "preconditions": preconditions,
        "sites": rows,
        "skew_summary": skew_summary,
        "listed_seg_word_count": sum(1 for r in rows if r["seg_word_listed"]),
        "verdict": verdict,
        "fixup_records_give_base": False,
        "fixup_records_basis": "each entry is a bare sorted body offset (table_facts); DI is the only "
                               "other input and is not in the table or established by the bytes",
        "di_established": False,
        "status": STATUS,
        "playable": False,
    }


def self_checks(doc: dict, hashes_before: dict, hashes_after: dict) -> list:
    pre = doc["preconditions"]
    checks = [
        ("preconditions_hold", all(pre.values())),
        ("listed_seg_words_expected", doc["listed_seg_word_count"] == EXPECT_LISTED_SEG_WORDS),
        ("fixup_records_give_base_false", doc["fixup_records_give_base"] is False),
        ("di_not_established", doc["di_established"] is False),
        ("never_established", doc["verdict"]["geo_status"] != "established"),
        ("inputs_unchanged", hashes_before == hashes_after),
    ]
    return [{"name": n, "ok": bool(ok)} for n, ok in checks]


# ---------------------------------------------------------------------------------------------
# Driver and output
# ---------------------------------------------------------------------------------------------

def check_out(out: Path, install: Path) -> None:
    o = out.resolve()
    i = install.resolve()
    if o == i or i in o.parents:
        raise ResidueRefusal("output folder is inside the install folder")
    if DATA_WORK.resolve() not in o.parents:
        raise ResidueRefusal("output folder must be under data/work/")


def probe(install: Path, out: Path) -> tuple:
    check_out(out, install)
    before = _hashes(install)
    inputs = p.load_inputs(install)
    doc = analyse(inputs["START.EXE"], inputs["GAME.OVR"])
    after = _hashes(install)
    checks = self_checks(doc, before, after)
    doc = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "inputs": {k: {"size": len(v), "sha256": _sha(v)} for k, v in inputs.items()},
        **doc,
        "self_checks": checks,
    }
    ok = all(c["ok"] for c in checks)
    return doc, (0 if ok else 1)


def render_md(doc: dict) -> str:
    v = doc["verdict"]
    lines = [
        "# PoR 0x21 far-call fixup-record residue probe (static, retail)",
        "",
        "`playable: false`, `status: %s`, `di_established: false`." % doc["status"],
        "",
        "- geo_status: **%s**" % v["geo_status"],
        "- reason: %s" % v["reason"],
        "- fixup_records_give_base: %s (%s)" % (doc["fixup_records_give_base"], doc["fixup_records_basis"]),
        "- image base: %s; GEO stub file offset %s (group %s, index %d)"
        % (doc["image_base"], doc["geo_stub"]["start_f"], doc["geo_stub"]["group_header"], doc["geo_stub"]["index"]),
        "",
        "## Sites",
        "",
        "| at | seg:off | seg_body | seg listed | off listed | skew mod 16 | labels | DI needed mod 64k | GEO candidate |",
        "| --- | --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for r in doc["sites"]:
        res = r.get("residue")
        skew = "" if res is None else str(res["skew_needed_mod16"])
        labels = "" if res is None else ",".join(res["skew_labels"])
        di = "" if res is None or "di_needed_mod64k" not in res else _hex(res["di_needed_mod64k"])
        lines.append("| %s | %s:%s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["at"], r["seg"], r["off"], r["seg_body"], str(r["seg_word_listed"]).lower(),
            str(r["off_word_listed"]).lower(), skew, labels, di, str(r["geo_candidate_site"]).lower()))
    lines += ["", "## Self-checks", ""]
    lines += ["- %s: %s" % (c["name"], "pass" if c["ok"] else "FAIL") for c in doc["self_checks"]]
    lines.append("")
    return "\n".join(lines)


def write_outputs(doc: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(json.dumps(doc, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    (out / RESULT_MD).write_text(render_md(doc), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="PoR 0x21 fixup-record residue probe (static, read-only).")
    ap.add_argument("--install", required=True, type=Path, help="folder holding the pinned GAME.OVR and START.EXE")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder, under data/work/")
    args = ap.parse_args(argv)
    try:
        doc, code = probe(args.install, args.out)
    except p.ProbeRefusal as e:
        print("refused: %s" % e, file=sys.stderr)
        return 2
    write_outputs(doc, args.out)
    print("geo_status=%s self_checks=%s" % (doc["verdict"]["geo_status"],
                                            "pass" if code == 0 else "FAIL"))
    return code


if __name__ == "__main__":
    sys.exit(main())
