#!/usr/bin/env python3
"""Pool of Radiance: ECL stream walk under the PoR-native operand framing (DIAGNOSTIC ONLY).

STATUS: diagnostic-only. ``playable: false``. No events, no mappings, no module output.

Reads one ECL block from a retail ``ECL<n>.DAX`` (read-only) and walks its instruction stream from
the header end, using ONLY the framing that ``tools/por_ecl_native_framing_probe.py`` derives from the
pinned ``GAME.OVR`` / ``START.EXE`` bytes (the probe's own JSON is the evidence object; this tool
reads no other framing source):

* A classified opcode (classifier class ``c``) takes ``c`` operands. Each operand's tag (cursor+1) and
  value (cursor+2) select exactly one probe operand kind; the kind's cursor delta is the operand's
  byte count (2 or 3). The record advances ``1 + sum(delta_i)``.
* Operands are decoded only for CLOSED kinds: tags 1, 2, 3 (3 bytes), ordinary two-byte tags, and tag
  0x80 with count 0 (2 bytes). Decoded values are raw bytes only; no meaning is given to any of them.
* An operand whose kind is OPEN (tag 0x81, or tag 0x80 with count > 0) STOPS the walk before that
  operand: the cursor effect of its far helpers (0x87CE, 0x8626) is not established. The operand and
  the rest of its record are not decoded or listed as records.
* A default-arm opcode advances one byte (classifier ``inc [0x49ED]``). Those that also have a
  dispatcher case in the probe's ``0x3C73`` reader are marked ``handler_reads: unresolved``: the
  handler may read more bytes and that is not established. They do not stop the walk, so the
  report marks them and counts them, and ``supported_prefix`` ends at the first one.

Container and header come from ``tools/por_ecl.py`` (read-only import): the DAX TOC and signed-byte
RLE (GoldBox ``docs/dax-format.md`` sections 1-2) and the 22-byte ECL header with magic ``0x1388``
(GoldBox ``ecl-krynn-gen1-opcodes.md`` 3.2). Both were validated on the retail ``ECL2.DAX`` in
``docs/por-ecl-decoder.md``. The stream origin (block offset 22) is an inherited assumption: the
framing is cursor-relative, and the entry cursor and its ``0x6700`` displacement are not established.

Refusals (exit 2, named): a missing or unpinned install file (raised by the framing probe), a framing
probe with a failed check, a framing gap (an opcode without an arm, a tag/value with no or two kinds,
a closed kind whose delta is not its read extent), a malformed DAX or block, an ambiguous block id,
output inside the install, output outside ``data/work/`` (CLI only).
Exit 1: a self-check of this run failed. Exit 0: report written and every self-check passes.

Usage::

    python tools/por_ecl_native_stream_probe.py --install "PATH/TO/POOLRAD" --ecl 2 --block 20 \\
        -o data/work/por-ecl-native-stream/ecl2-20

Stdlib + the two read-only modules above.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
DATA_WORK = REPO_ROOT / "data" / "work"

sys.path.insert(0, str(TOOLS_DIR))
import por_ecl as ecl  # noqa: E402  (read-only: DAX container, RLE, ECL header; not edited)
import por_ecl_native_framing_probe as framing  # noqa: E402  (read-only: operand framing; not edited)

SCHEMA = "openua.por-ecl-native-stream-probe"
SCHEMA_VERSION = 1
STATUS = "diagnostic-only"
TOOL = "tools/por_ecl_native_stream_probe.py"
FRAMING_TOOL = "tools/por_ecl_native_framing_probe.py"
FRAMING_JSON = "por_ecl_native_framing_probe.json"
RESULT_JSON = "por_ecl_native_stream_probe.json"
RESULT_MD = "por_ecl_native_stream_probe.md"
STREAM_ORIGIN = ecl.ECL_HEADER_LEN          # block offset 22: header end (inherited assumption)
HANDLER_UNRESOLVED = "unresolved"
HANDLER_NO_CASE = "no-dispatch-case"
REASON_OPEN = "open-operand"
REASON_TRUNC = "truncated-operand"
REASON_HANDLER = "unresolved-handler-read"
STATUS_END = "reached-end-of-stream"


class StreamRefusal(Exception):
    """A named refusal: the probe does not run on this input."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%02X" % v


def _dumps(obj: dict) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _in_ranges(ranges: list, v: int) -> bool:
    return any(lo <= v <= hi for lo, hi in ranges)


# ---------------------------------------------------------------------------------------------
# Framing evidence: the probe's JSON is the only source of opcode classes and operand kinds
# ---------------------------------------------------------------------------------------------

def framing_from_probe(doc: dict) -> tuple[dict, list]:
    """Opcode table and operand kinds from the framing probe's JSON. Any gap is a refusal."""
    checks = doc.get("checks", {})
    failed = sorted(k for k, v in checks.items() if not v)
    if not checks or failed:
        raise StreamRefusal("framing probe has failed or empty checks: %s" % (failed or "none recorded"))
    per = doc["classifier"]["per_opcode"]
    dispatch = set(doc["classifier"]["default_arm_with_dispatch_case"])
    table: dict = {}
    for v in range(256):
        key = _hex(v)
        arm = per.get(key)
        if arm is None:
            raise StreamRefusal("framing gap: no classifier entry for opcode %s" % key)
        if arm.get("arm") == "class":
            table[v] = {"class": int(arm["operands_parser"]), "dispatch_case": False}
        elif arm.get("arm") == "default":
            table[v] = {"class": None, "dispatch_case": key in dispatch}
        else:
            raise StreamRefusal("framing gap: opcode %s has arm %r" % (key, arm.get("arm")))
    body = doc["parser"]["body"]
    if not (body.get("tiling_complete") and body.get("tiling_disjoint")) or body.get("refused_paths"):
        raise StreamRefusal("framing gap: operand kinds do not tile the tag/value space cleanly")
    kinds = doc["parser"]["operand_kinds"]
    for k in kinds:
        if k["open"]:
            continue
        extent = max(r["rel"] for r in k["reads"])
        if extent != k["cursor_delta"]:
            raise StreamRefusal("framing gap: closed kind %r has delta %d but read extent %d"
                                % (k["tag_set"], k["cursor_delta"], extent))
    return table, kinds


def kinds_for_tag(kinds: list, tag: int) -> list:
    return [k for k in kinds if _in_ranges(k["tag_set"], tag)]


def operand_rule(kinds: list, tag: int, value: int) -> dict:
    """The one probe kind holding (tag, value). Zero or two matches are a framing gap, not a guess."""
    hits = [k for k in kinds_for_tag(kinds, tag)
            if k["value_set"] is None or _in_ranges(k["value_set"], value)]
    if len(hits) != 1:
        raise StreamRefusal("framing gap: %d operand kinds match tag 0x%02X value 0x%02X"
                            % (len(hits), tag, value))
    return hits[0]


def _open_label(tag: int) -> str:
    if tag == 0x81:
        return "open-0x81-post-step"
    if tag == 0x80:
        return "open-0x80-count-gt-0"
    return "open-other"


def _closed_label(tag: int, delta: int) -> str:
    if tag == 0x80:
        return "closed-0x80-count0-%d-byte" % delta
    return "closed-%d-byte" % delta


# ---------------------------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------------------------

def _stop(reason: str, origin: int, stream: bytes, pos: int, index: int, s: int,
          tag: Optional[int], value: Optional[int], label: str) -> dict:
    return {"reason": reason, "block_offset": origin + s, "opcode": _hex(stream[pos]),
            "opcode_block_offset": origin + pos, "operand_index": index,
            "tag": _hex(tag), "value": _hex(value), "label": label}


def _walk_classed(stream: bytes, pos: int, c: int, kinds: list, origin: int) -> tuple[Optional[dict], Optional[dict]]:
    """One classified record at ``pos``. Returns (record, None) or (None, stop)."""
    n = len(stream)
    cur = pos                       # cursor: operand i's tag is at cur+1, value at cur+2
    ops: list = []
    for i in range(1, c + 1):
        s = cur + 1
        if s >= n:
            return None, _stop(REASON_TRUNC, origin, stream, pos, i, s, None, None, "no-tag-byte")
        tag = stream[s]
        cands = kinds_for_tag(kinds, tag)
        if not cands:
            raise StreamRefusal("framing gap: no operand kind for tag 0x%02X" % tag)
        if all(k["open"] for k in cands):
            return None, _stop(REASON_OPEN, origin, stream, pos, i, s, tag, None, _open_label(tag))
        if s + 1 >= n:
            return None, _stop(REASON_TRUNC, origin, stream, pos, i, s, tag, None, "no-value-byte")
        value = stream[s + 1]
        kind = operand_rule(kinds, tag, value)
        if kind["open"]:
            return None, _stop(REASON_OPEN, origin, stream, pos, i, s, tag, value, _open_label(tag))
        delta = kind["cursor_delta"]
        if cur + delta >= n:
            return None, _stop(REASON_TRUNC, origin, stream, pos, i, s, tag, value,
                               "closed-%d-byte-runs-past-end" % delta)
        ops.append({"index": i, "block_offset": origin + s, "tag": _hex(tag), "value": _hex(value),
                    "extra": _hex(stream[s + 2]) if delta == 3 else None,
                    "bytes": delta, "label": _closed_label(tag, delta)})
        cur += delta
    advance = 1 + (cur - pos)       # opcode byte + operand bytes
    rec = {"block_offset": origin + pos, "opcode": _hex(stream[pos]), "kind": "classed",
           "class": c, "advance": advance, "operands": ops}
    return rec, None


def walk_stream(stream: bytes, table: dict, kinds: list, origin: int = STREAM_ORIGIN) -> dict:
    """Walk from the header end, stopping before unresolved handler reads or open operands.

    A default opcode with a PoR dispatcher case stops here: the classifier's one-byte increment is
    established, but the handler may move the cursor further. Never reports the program boundary.
    """
    n = len(stream)
    records: list = []
    stop: Optional[dict] = None
    pos = 0
    while pos < n:
        op = stream[pos]
        f = table[op]
        if f["class"] is None:
            if f["dispatch_case"]:
                stop = {"reason": REASON_HANDLER, "block_offset": origin + pos,
                        "opcode": _hex(op), "opcode_block_offset": origin + pos,
                        "operand_index": None, "tag": None, "value": None,
                        "label": "default-dispatch-handler-reads-unresolved"}
                break
            records.append({"block_offset": origin + pos, "opcode": _hex(op), "kind": "default",
                            "class": None, "dispatch_case": False,
                            "handler_reads": HANDLER_NO_CASE,
                            "advance": 1})
            pos += 1
            continue
        rec, stop = _walk_classed(stream, pos, f["class"], kinds, origin)
        if stop is not None:
            break
        records.append(rec)
        pos += rec["advance"]
    status = ("stopped-" + stop["reason"]) if stop is not None else STATUS_END
    return {"status": status, "records": records, "stop": stop,
            "covered": pos, "stream_length": n}


def _walk_summary(walk: dict, origin: int) -> dict:
    recs = walk["records"]
    stop = walk["stop"]
    first_unres = next((r for r in recs if r["kind"] == "default" and r["handler_reads"] == HANDLER_UNRESOLVED), None)
    # A stopped record is unsupported from its opcode byte on, so the prefix ends there.
    bounds = [x for x in ((first_unres or {}).get("block_offset"),
                          (stop or {}).get("opcode_block_offset")) if x is not None]
    prefix_end = min(bounds) if bounds else origin + walk["stream_length"]
    labels: dict = {}
    for r in recs:
        for o in r.get("operands", []):
            labels[o["label"]] = labels.get(o["label"], 0) + 1
    if stop is not None:
        labels[stop["label"]] = labels.get(stop["label"], 0) + 1
    n_class = sum(1 for r in recs if r["kind"] == "classed")
    n_def = len(recs) - n_class
    n_unres = sum(1 for r in recs if r["kind"] == "default" and r["handler_reads"] == HANDLER_UNRESOLVED)
    n_unres += int(stop is not None and stop["reason"] == REASON_HANDLER)
    n = walk["stream_length"]
    return {
        "status": walk["status"],
        "stream_origin_block_offset": origin,
        "stream_length": n,
        "covered_stream_bytes": walk["covered"],
        "covered_permille": (walk["covered"] * 1000) // n if n else 0,
        "records_total": len(recs),
        "records_classed": n_class,
        "records_default": n_def,
        "records_default_handler_reads_unresolved": n_unres,
        "supported_prefix_end_block_offset": prefix_end,
        "supported_prefix_records": sum(1 for r in recs if r["block_offset"] < prefix_end),
        "operand_labels": dict(sorted(labels.items())),
        "stop": stop,
    }


# ---------------------------------------------------------------------------------------------
# Analysis, report, I/O
# ---------------------------------------------------------------------------------------------

def load_block(dax_bytes: bytes, block_id: Optional[int], index: Optional[int]) -> tuple[ecl.TocEntry, bytes]:
    """Container and block through tools/por_ecl.py (validated container, exact RLE length)."""
    entries, base = ecl.parse_dax(dax_bytes)
    entry = ecl.select_entry(entries, block_id, index)
    start = base + entry.data_offset
    block = ecl.rle_decode(dax_bytes[start:start + entry.comp_size], entry.raw_size)
    return entry, block


def analyse_block(block: bytes, framing_doc: dict, source: dict, probe_sha: Optional[str] = None) -> dict:
    """Walk one decoded ECL block under the probe's framing. Pure: no I/O."""
    try:
        header = ecl.parse_header(block)
    except ecl.EclError as exc:
        raise StreamRefusal(str(exc))
    table, kinds = framing_from_probe(framing_doc)
    walk = walk_stream(block[STREAM_ORIGIN:], table, kinds, origin=STREAM_ORIGIN)
    summary = _walk_summary(walk, STREAM_ORIGIN)
    recs = walk["records"]
    # Records must be contiguous from the header end; the stop (if any) sits at the covered end.
    expect = STREAM_ORIGIN
    contiguous = True
    for r in recs:
        contiguous = contiguous and r["block_offset"] == expect
        expect += r["advance"]
    stop = walk["stop"]
    # The stop is at the covered end: open/truncated operand, or an unresolved dispatch handler.
    stop_ok = stop is None or (stop["opcode_block_offset"] == expect and
                               (stop["reason"] in (REASON_TRUNC, REASON_HANDLER) or
                                stop["label"].startswith("open-")))
    p_checks = framing_doc.get("checks", {})
    body = framing_doc["parser"]["body"]
    checks = {
        "framing_probe_checks_all_pass": bool(p_checks) and all(p_checks.values()),
        "every_opcode_has_framing": len(table) == 256,
        "operand_kinds_tile_tag_value_space": bool(body.get("tiling_complete") and body.get("tiling_disjoint")),
        "records_contiguous_from_header_end": contiguous,
        "stop_at_open_operand_or_unresolved_handler_or_truncated": stop_ok,
        "covered_within_stream": walk["covered"] <= walk["stream_length"],
    }
    result = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "status": STATUS, "tool": TOOL,
        "playable": False, "mappings": [], "events_emitted": 0,
        "claims": {"complete": False, "program_boundary": "not-established",
                   "operand_meaning": "not-established",
                   "handler_reads_for_default_arm": "walk stops at default dispatch cases; reads remain unresolved"},
        "source": dict(sorted(source.items())),
        "header": {"magic": "0x%04X" % header["magic"], "header_length": header["header_length"],
                   "pointers": header["pointers"], "segment_all_expected": header["segment_all_expected"]},
        "evidence": {
            "framing": {"tool": FRAMING_TOOL, "schema": framing_doc.get("schema"),
                        "json_sha256": probe_sha, "checks_passed": sum(1 for v in p_checks.values() if v),
                        "checks_total": len(p_checks), "pins": framing_doc.get("pins", {})},
            "container": {"basis": "tools/por_ecl.py: GoldBox docs/dax-format.md sections 1-2 "
                                   "(TOC, contiguity, signed-byte RLE); validated on retail ECL2.DAX per "
                                   "docs/por-ecl-decoder.md"},
            "header": {"basis": "tools/por_ecl.py: GoldBox ecl-krynn-gen1-opcodes.md 3.2 (magic 0x1388, "
                                "22-byte header); validated per docs/por-ecl-decoder.md"},
            "stream_origin": {"block_offset": STREAM_ORIGIN,
                              "basis": "header end, inherited from tools/por_ecl.py; the framing probe "
                                       "does not establish the entry cursor"},
        },
        "walk": summary,
        "records": recs,
        "checks": checks,
    }
    return result


def render_report(result: dict) -> str:
    w = result["walk"]
    s = result["source"]
    lines = [
        "# PoR-native ECL stream walk (diagnostic only)",
        "",
        "`playable: false`. No events, mappings or module output. `complete: false`: the program boundary is not established.",
        "",
        "- Source: %s, sha256 %s, TOC index %d, block id %d, decoded sha256 %s"
        % (s["file"], s["sha256"], s["toc_index"], s["block_id"], s["decoded_sha256"]),
        "- Framing: %s, json sha256 %s, checks %d/%d"
        % (result["evidence"]["framing"]["tool"], result["evidence"]["framing"]["json_sha256"],
           result["evidence"]["framing"]["checks_passed"], result["evidence"]["framing"]["checks_total"]),
        "- Stream origin: block offset %d (header end, inherited; entry cursor not established)" % w["stream_origin_block_offset"],
        "",
        "## Walk",
        "",
        "- status: `%s`" % w["status"],
        "- covered: %d of %d stream bytes (%d permille)" % (w["covered_stream_bytes"], w["stream_length"], w["covered_permille"]),
        "- records: %d total (%d classed, %d default); default with dispatch case (handler reads unresolved): %d"
        % (w["records_total"], w["records_classed"], w["records_default"], w["records_default_handler_reads_unresolved"]),
        "- supported prefix ends at block offset %d (%d records)" % (w["supported_prefix_end_block_offset"], w["supported_prefix_records"]),
        "- operand labels: " + ", ".join("%s=%d" % kv for kv in w["operand_labels"].items()),
        "",
        "## Stop",
        "",
    ]
    if w["stop"] is None:
        lines.append("No open operand, truncated operand, or unresolved default handler before the end of the stream.")
    else:
        st = w["stop"]
        if st["operand_index"] is None:
            detail = "(dispatch-case opcode %s at %d; handler cursor effect unresolved)" % (
                st["opcode"], st["opcode_block_offset"])
        else:
            detail = "(opcode %s at %d, operand %d, tag %s, value %s)" % (
                st["opcode"], st["opcode_block_offset"], st["operand_index"], st["tag"], st["value"])
        lines.append("- reason `%s` at block offset %d %s, label `%s`"
                     % (st["reason"], st["block_offset"], detail, st["label"]))
    lines += ["", "## Checks", ""]
    lines += ["- %s: %s" % (k, "ok" if v else "FAIL") for k, v in sorted(result["checks"].items())]
    return "\n".join(lines) + "\n"


def validate_output_dir(out: Path, install: Path, require_data_work: bool) -> Path:
    o = Path(out).resolve()
    i = Path(install).resolve()
    if o == i or i in o.parents:
        raise StreamRefusal("output folder is inside the install")
    if require_data_work:
        d = DATA_WORK.resolve()
        if not (o == d or d in o.parents):
            raise StreamRefusal("output folder must be under data/work/ (git-ignored)")
    return o


def run(install: Path, out: Path, ecl_no: int, block_id: Optional[int], index: Optional[int]) -> tuple[dict, int]:
    install = Path(install)
    if not install.is_dir():
        raise StreamRefusal("install folder not found")
    out = validate_output_dir(out, install, require_data_work=False)
    ev_dir = out / "framing-evidence"
    try:
        doc, code = framing.probe(install, ev_dir)
    except framing.ProbeRefusal as exc:
        raise StreamRefusal("framing evidence refused: %s" % exc)
    if code != 0:
        raise StreamRefusal("framing probe: %d check(s) failed" % sum(1 for v in doc["checks"].values() if not v))
    probe_sha = _sha((ev_dir / FRAMING_JSON).read_bytes())
    try:
        dax_path = ecl.resolve_source(None, str(install), ecl_no)
        dax_bytes = dax_path.read_bytes()
        entry, block = load_block(dax_bytes, block_id, index)
    except ecl.EclError as exc:
        raise StreamRefusal(str(exc))
    source = {"file": dax_path.name, "size": len(dax_bytes), "sha256": _sha(dax_bytes),
              "toc_index": entry.index, "block_id": entry.block_id, "raw_size": entry.raw_size,
              "comp_size": entry.comp_size, "decoded_size": len(block), "decoded_sha256": _sha(block)}
    result = analyse_block(block, doc, source, probe_sha)
    # Path-free: no absolute path may appear in the outputs.
    body = _dumps(result)
    forbidden = {str(install.resolve()), install.resolve().as_posix(),
                 str(REPO_ROOT.resolve()), REPO_ROOT.resolve().as_posix()}
    result["checks"]["output_path_free"] = not any(f in body for f in forbidden)
    code = 0 if all(result["checks"].values()) else 1
    out.mkdir(parents=True, exist_ok=True)
    (out / RESULT_JSON).write_text(_dumps(result), encoding="utf-8", newline="\n")
    (out / RESULT_MD).write_text(render_report(result), encoding="utf-8", newline="\n")
    return result, code


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--install", required=True, help="PoR install folder (POOLRAD); read-only")
    ap.add_argument("--ecl", required=True, type=int, help="ECL file number n (reads ECL<n>.DAX)")
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--block", type=int, help="TOC block id (must be unique)")
    sel.add_argument("--index", type=int, help="TOC index")
    ap.add_argument("-o", "--out", required=True, type=Path, help="output folder under data/work/")
    args = ap.parse_args(argv)
    try:
        install = Path(args.install)
        validate_output_dir(args.out, install, require_data_work=True)
        result, code = run(install, args.out, args.ecl, args.block, args.index)
    except (StreamRefusal, ecl.EclError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    except framing.ProbeRefusal as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    for k, v in sorted(result["checks"].items()):
        print("%-40s %s" % (k, "ok" if v else "FAIL"))
    w = result["walk"]
    print("walk status: %s; covered %d of %d stream bytes; records %d; unresolved default %d"
          % (w["status"], w["covered_stream_bytes"], w["stream_length"], w["records_total"],
             w["records_default_handler_reads_unresolved"]))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
