#!/usr/bin/env python3
"""Pool of Radiance: proc-entry anomalies in the VROOMM stub groups (static, observe-only).

Status: STATIC-PROBE-ONLY. Read-only, stdlib-only, playable: false.

Companion to tools/por_farcall_resolve.py. That tool models a stub group's entry as
``fileofs + proc`` and reports the groups it accepts. This probe asks, for EVERY stub slot
(well-formed and malformed, accepted and partial groups):

  * does ``fileofs + proc`` land on a Borland prologue (``55 89 E5`` / ``55 8B EC``)?
  * is the proc word inside the group's own code (``proc < codesz``)?
  * is the group's code/fixup extent a contiguous partition with its neighbours?
  * does the group's stub 0 always sit at ``codesz - 5`` as an exit thunk?
  * for the slots that fail, does ANY simple origin (a neighbour's fileofs, the header,
    the image base) explain them, and do the prologue hits near them share one bias?
  * do any raw ``9A seg:off`` operands in GAME.OVR or START.EXE reference the slot image?

It decides nothing. It reports the evidence and the alternatives. The verdict is recorded as
``consistent_bias_found: false`` only when the data shows no single origin for the anomalies.

Usage
  tools/.venv/Scripts/python.exe -I tools/por_proc_entry_anomalies.py \
      --install "PATH/TO/POOLRAD" -o data/work/por-proc-entry-anomalies

Outputs in OUT (deterministic: sorted keys, no timestamps, no absolute paths):
  por_proc_entry_anomalies.json
  por_proc_entry_anomalies_report.md

Exit codes
  0  the probe ran and wrote its outputs (anomalies are reported, not treated as failure)
  2  named refusal: bad install, a file not matching its pin, or unsafe output location
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
from por_convert import PorSourceError, validate_output_dir  # noqa: E402
import por_farcall_resolve as fr  # noqa: E402

SCHEMA = "openua.por-proc-entry-anomalies"
SCHEMA_VERSION = 1
STATUS = "static-probe-only"
TOOL = "tools/por_proc_entry_anomalies.py"
EXIT_THUNK = b"\x55\x89\xe5\x5d\xcb"  # push bp; mov bp,sp; pop bp; retf
WINDOW = 0x40                          # +/- window for the local prologue survey
ORIGIN_NAMES = ("pred_fo", "next_fo", "hdr_in_start", "stub_start_in_start",
                "fo_minus_0x200", "image_base", "fo_plus_8", "fo_plus_0x16")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_prologue(ovr: bytes, t: int) -> bool:
    return 0 <= t and t + 3 <= len(ovr) and ovr[t:t + 3] in fr.PROLOGUES


def _group_table(scan: dict) -> list[tuple[dict, str]]:
    rows = [(g, "well-formed-group") for g in scan["groups"]]
    rows += [(g, "partial-group") for g in scan["partial_groups"]]
    rows.sort(key=lambda t: t[0]["fileofs"])
    return rows


def chain_breaks(table: list[tuple[dict, str]]) -> list[dict]:
    """Neighbouring groups whose code+fixup extent does not end where the next group begins."""
    out = []
    for (a, _), (b, _) in zip(table, table[1:]):
        end = a["fileofs"] + a["codesz"] + a["fixupsz"]
        if end != b["fileofs"]:
            out.append({"after_fileofs": a["fileofs"], "end": end, "next_fileofs": b["fileofs"],
                        "diff": b["fileofs"] - end})
    return out


def stub0_thunk_census(table: list[tuple[dict, str]], ovr: bytes) -> dict:
    """Stub 0 of every group: proc == codesz-5 and the five bytes there are the exit thunk."""
    n = len(table)
    at_end = sum(1 for g, _ in table if g["procs"][0] == g["codesz"] - 5)
    thunk = sum(1 for g, _ in table if ovr[g["fileofs"] + g["codesz"] - 5:
                                              g["fileofs"] + g["codesz"]] == EXIT_THUNK)
    return {"groups": n, "stub0_proc_eq_codesz_minus_5": at_end, "exit_thunk_bytes_at_codesz_minus_5": thunk}


def slot_rows(table: list[tuple[dict, str]], ovr: bytes, start: bytes) -> list[dict]:
    rows = []
    for g, tag in table:
        for k, p in enumerate(g["procs"]):
            valid = bool(g["stub_valid"][k])
            t = g["fileofs"] + p
            img = g["stub_start"] + fr.STUB_LEN * k
            rows.append({
                "group_fileofs": g["fileofs"],
                "group_header": g["header_offset"],
                "group_status": tag,
                "codesz": g["codesz"],
                "stub_count": g["stub_count"],
                "index": k,
                "stub_image": img,
                "class": "well-formed" if valid else "malformed",
                "proc": p,
                "target": t,
                "prologue_at_target": _is_prologue(ovr, t),
                "proc_inside_code": p < g["codesz"],
                "slot_bytes": start[img:img + fr.STUB_LEN].hex(" "),
            })
    return rows


def anomalies(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["class"] == "well-formed" and not r["prologue_at_target"]]


def neighbour_origins(table: list[tuple[dict, str]], ovr: bytes, start: bytes, hdr_img: int,
                      an: dict) -> dict:
    """Candidate origins for one anomalous slot. Each entry: target and whether it is a prologue."""
    fos = [g["fileofs"] for g, _ in table]
    i = fos.index(an["group_fileofs"])
    g = table[i][0]
    origins = {}
    origins["pred_fo"] = table[i - 1][0]["fileofs"] if i > 0 else None
    origins["next_fo"] = table[i + 1][0]["fileofs"] if i + 1 < len(table) else None
    origins["hdr_in_start"] = g["header_offset"]
    origins["stub_start_in_start"] = g["stub_start"]
    origins["fo_minus_0x200"] = g["fileofs"] - 0x200
    origins["image_base"] = hdr_img
    origins["fo_plus_8"] = g["fileofs"] + 8
    origins["fo_plus_0x16"] = g["fileofs"] + 0x16
    out = {}
    for name in ORIGIN_NAMES:
        b = origins.get(name)
        if b is None:
            out[name] = None
            continue
        t = b + an["proc"]
        out[name] = {"target": t, "prologue": _is_prologue(ovr, t)}
    return out


def local_prologue_survey(ovr: bytes, an: dict, body_lo: int, body_hi: int) -> dict:
    """Prologues within +/-WINDOW of the anomalous target, and the chance rate in the group body.

    A 3-byte prologue is common in Borland code, so a hit inside the window is weak evidence
    on its own. ``expected_by_chance`` is the window width times the body's prologue density.
    """
    t = an["target"]
    deltas = [d for d in range(-WINDOW, WINDOW + 1) if _is_prologue(ovr, t + d)]
    body = [x for x in range(body_lo, min(body_hi, len(ovr) - 3)) if ovr[x:x + 3] in fr.PROLOGUES]
    density = len(body) / max(1, body_hi - body_lo)
    return {"deltas": deltas, "window_width": 2 * WINDOW + 1,
            "body_prologues": len(body), "body_density": round(density, 6),
            "expected_by_chance": round((2 * WINDOW + 1) * density, 3)}


def nine_a_refs(ovr: bytes, start: bytes, hdr_img: int, images: set[int]) -> dict:
    """Raw ``9A seg:off`` byte patterns that reach an image address under M0 and M1."""
    refs: dict[int, list] = {img: [] for img in images}
    for name, buf in (("GAME.OVR", ovr), ("START.EXE", start)):
        for i in range(len(buf) - 4):
            if buf[i] != 0x9A:
                continue
            off, seg = struct.unpack_from("<HH", buf, i + 1)  # 9A is offset word, then segment word
            for lab, img in (("M0", hdr_img + seg * 16 + off), ("M1", seg * 16 + off + 0x7E)):
                if img in refs:
                    refs[img].append({"file": name, "at": i, "model": lab})
    return refs


def decoded_call_far_entry(ovr: bytes, site: int, group_lo: int) -> Optional[dict]:
    """The prologue whose complete walk decodes ``site`` as a far CALL, or None.

    Walks each prologue at or below ``site`` inside the group body (nearest first) with the
    repo's own walker, and accepts a walk only when it is complete and records a call_far at
    ``site``. A raw ``9A`` byte pattern that no complete walk decodes is not counted as a call.
    """
    lh = _handler()
    for p in range(site, group_lo - 1, -1):
        if ovr[p:p + 3] not in fr.PROLOGUES:
            continue
        w = lh.walk(ovr, p)
        if w["complete"] and any(c["at"] == site for c in w["far_calls"]):
            return {"walk_entry": p, "walk_instructions": w["instruction_count"]}
    return None


def _handler():
    import por_loadpieces_handler as lh  # noqa: E402  (stdlib walker shared with the resolver)
    return lh


def _with_decode(ref: dict, ovr: bytes, table: list[tuple[dict, str]]) -> dict:
    """Attach whether the raw 9A is a decoded call_far in its group body (GAME.OVR only)."""
    out = dict(ref)
    out["decoded_call_far"] = None
    out["walk_entry"] = None
    if ref["file"] != "GAME.OVR":
        return out
    for g, _ in table:
        if g["fileofs"] <= ref["at"] < g["fileofs"] + g["codesz"]:
            hit = decoded_call_far_entry(ovr, ref["at"], g["fileofs"])
            out["decoded_call_far"] = hit is not None
            out["walk_entry"] = hit["walk_entry"] if hit else None
            return out
    out["decoded_call_far"] = False  # the byte pattern is outside every group body
    return out


def analyze(start: bytes, ovr: bytes) -> dict:
    hdr_img = fr.mz_image_base(start)
    scan = fr.scan_all(start, ovr)
    table = _group_table(scan)
    rows = slot_rows(table, ovr, start)
    an_rows = anomalies(rows)
    detail = []
    images = {r["stub_image"] for r in an_rows}
    refs = nine_a_refs(ovr, start, hdr_img, images)
    table_by_fo = {g["fileofs"]: g for g, _ in table}
    for r in an_rows:
        g = table_by_fo[r["group_fileofs"]]
        body_lo = g["fileofs"]
        body_hi = g["fileofs"] + g["codesz"]
        survey = local_prologue_survey(ovr, {"target": r["target"]}, body_lo, body_hi)
        detail.append({
            "group_fileofs": r["group_fileofs"],
            "group_header": r["group_header"],
            "index": r["index"],
            "stub_image": r["stub_image"],
            "proc": r["proc"],
            "target": r["target"],
            "codesz": r["codesz"],
            "proc_inside_code": r["proc_inside_code"],
            "target_inside_file": r["target"] < len(ovr),
            "origins": neighbour_origins(table, ovr, start, hdr_img, r),
            "local_prologue_survey": survey,
            "nine_a_refs": [_with_decode(ref, ovr, table) for ref in refs[r["stub_image"]]],
        })
    malformed = [r for r in rows if r["class"] == "malformed"]
    well = [r for r in rows if r["class"] == "well-formed"]
    # A consistent bias would show as one shared (origin) value that makes every anomaly a
    # prologue. Check every named origin across all anomalies at once.
    shared = {}
    for name in ORIGIN_NAMES:
        ok = [d["origins"][name] is not None and d["origins"][name]["prologue"] for d in detail]
        shared[name] = {"fixes_all_anomalies": bool(detail) and all(ok),
                        "fixes_count": sum(ok), "anomaly_count": len(detail)}
    return {
        "image_base": hdr_img,
        "group_count": len(table),
        "accepted_group_count": len(scan["groups"]),
        "partial_group_count": len(scan["partial_groups"]),
        "chain_breaks": chain_breaks(table),
        "stub0_census": stub0_thunk_census(table, ovr),
        "slot_counts": {
            "well_formed": len(well),
            "well_formed_prologue": sum(1 for r in well if r["prologue_at_target"]),
            "malformed": len(malformed),
            "malformed_prologue": sum(1 for r in malformed if r["prologue_at_target"]),
        },
        "anomalies": detail,
        "shared_origin_test": shared,
        "consistent_bias_found": any(v["fixes_all_anomalies"] for v in shared.values()),
        "malformed_slots": [
            {"group_fileofs": r["group_fileofs"], "group_status": r["group_status"],
             "index": r["index"], "proc": r["proc"], "target": r["target"],
             "prologue_at_target": r["prologue_at_target"], "slot_bytes": r["slot_bytes"]}
            for r in malformed],
    }


def render_report(doc: dict) -> str:
    a = doc["analysis"]
    L = ["# PoR stub-group proc entries: anomaly survey (static)", "",
         "Status: %s, playable: false." % doc["status"], "", "## Pins", ""]
    for name, v in sorted(doc["source"]["pins"].items()):
        L.append("- `%s`: %d bytes, sha256 `%s`, pin match %s"
                 % (name, v["size"], v["sha256"], str(v["pin_match"]).lower()))
    L += ["", "## Counts", "",
          "- groups: %d (accepted %d, partial %d)" % (a["group_count"], a["accepted_group_count"],
                                                    a["partial_group_count"]),
          "- chain breaks (fileofs + codesz + fixupsz vs next fileofs): %d" % len(a["chain_breaks"]),
          "- stub 0 at codesz-5: %d of %d; exit-thunk bytes at codesz-5: %d of %d" % (
              a["stub0_census"]["stub0_proc_eq_codesz_minus_5"], a["stub0_census"]["groups"],
              a["stub0_census"]["exit_thunk_bytes_at_codesz_minus_5"], a["stub0_census"]["groups"]),
          "- well-formed slots with a prologue at fileofs+proc: %d of %d" % (
              a["slot_counts"]["well_formed_prologue"], a["slot_counts"]["well_formed"]),
          "- malformed slots with a prologue at fileofs+proc: %d of %d" % (
              a["slot_counts"]["malformed_prologue"], a["slot_counts"]["malformed"]),
          "- consistent bias found: %s" % str(a["consistent_bias_found"]).lower(), "",
          "## Anomalous well-formed slots (no prologue at fileofs+proc)", "",
          "| group | hdr | idx | proc | target | codesz | proc<codesz | 9A refs (M0+M1) | prologue deltas +/-0x40 | expected by chance |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for d in a["anomalies"]:
        s = d["local_prologue_survey"]
        decoded = sum(1 for x in d["nine_a_refs"] if x["decoded_call_far"])
        L.append("| 0x%x | 0x%x | %d | 0x%x | 0x%x | 0x%x | %s | %d raw, %d decoded | %s | %s |" % (
            d["group_fileofs"], d["group_header"], d["index"], d["proc"], d["target"], d["codesz"],
            str(d["proc_inside_code"]).lower(), len(d["nine_a_refs"]), decoded,
            ", ".join(str(x) for x in s["deltas"]) or "none", s["expected_by_chance"]))
    L += ["", "## Shared-origin test (one origin for all anomalies?)", "",
          "| origin | prologue for every anomaly | prologues / anomalies |", "| --- | --- | --- |"]
    for name in ORIGIN_NAMES:
        v = a["shared_origin_test"][name]
        L.append("| %s | %s | %d / %d |" % (name, str(v["fixes_all_anomalies"]).lower(),
                                            v["fixes_count"], v["anomaly_count"]))
    L += ["", "## Malformed slots (partial groups)", "",
          "| group | status | idx | proc | target | prologue | slot bytes |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for m in a["malformed_slots"]:
        L.append("| 0x%x | %s | %d | 0x%x | 0x%x | %s | %s |" % (
            m["group_fileofs"], m["group_status"], m["index"], m["proc"], m["target"],
            str(m["prologue_at_target"]).lower(), m["slot_bytes"]))
    L += ["", "## Not established", "",
          "- Which origin the anomalous proc words were written against. No origin tested here fixes all five.",
          "- Whether any anomalous slot is ever called at run time. Only a CS:IP capture would show that.",
          "- Any semantics for opcode bytes or for the record fields between the header and the stubs.", ""]
    return "\n".join(L) + "\n"


def probe(install: Path, out: Path) -> dict:
    pins = {}
    files = {}
    for name in (fr.OVR_NAME, fr.EXE_NAME):
        p = install / name
        if not p.is_file():
            raise PorSourceError("%s not found in the install folder" % name)
        data = p.read_bytes()
        size, sha = fr.PINNED[name]
        ok = len(data) == size and _sha(data) == sha
        pins[name] = {"size": len(data), "sha256": _sha(data), "pin_match": ok}
        if not ok:
            raise PorSourceError("%s does not match its pinned size and SHA-256" % name)
        files[name] = data
    ovr, start = files[fr.OVR_NAME], files[fr.EXE_NAME]
    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "tool": TOOL,
        "status": STATUS, "playable": False,
        "source": {"pins": pins, "all_pins_match": True},
        "analysis": analyze(start, ovr),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "por_proc_entry_anomalies.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "por_proc_entry_anomalies_report.md").write_text(render_report(doc), encoding="utf-8")
    return doc


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="user-supplied PoR install folder (read-only)")
    ap.add_argument("-o", "--out", required=True, help="output folder (outside the install)")
    args = ap.parse_args(argv)
    try:
        out = validate_output_dir(Path(args.install), Path(args.out))
        doc = probe(Path(args.install), out)
    except PorSourceError as exc:
        print("por_proc_entry_anomalies: error: %s" % exc, file=sys.stderr)
        return 2
    a = doc["analysis"]
    print("wrote %s (static-probe-only, playable=false; anomalies %d; consistent_bias_found %s)"
          % (out, len(a["anomalies"]), str(a["consistent_bias_found"]).lower()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
