#!/usr/bin/env python3
"""Hatari GEMDOS trace checker: did OpenUA open (and read) DSN GEO files?

Read-only evidence checker. It parses a Hatari verbose GEMDOS log, follows each
file-handle lifecycle (Fopen/Fcreate -> "-> FD n" line -> Fread/Fwrite/Fseek ->
Fclose), and compares every GEO###.DAT open with a supplied DSN folder.

What it reports (runtime trace evidence only):
  - which GEO###.DAT files were opened from the supplied design folder, per
    lifecycle: open-only (no Fread before Fclose) or open+read (>=1 Fread);
  - the design file's size and sha256 (identity of the design side only).

What it does NOT report:
  - that the emulator consumed every byte of a design file (Hatari logs the
    requested Fread count, not the returned count);
  - that a map was displayed, that the campaign is playable, or that original
    Pool of Radiance was matched. The report always carries playable:false;
  - anything about the executable that produced the trace. The trace carries no
    binary identity, and this tool hashes no executable.

Refusals (exit 2, named in the report): FD reused while still open, an event on
an FD with no open lifecycle, a GEO lifecycle never closed, a GEO path that is
not exactly <design folder>\\<file> (traversal, absolute, drive, nested, bare),
a host path that does not end in <design folder>/<file>, a GEO name missing
from the design, a GEO file created or written, and a second open of a GEO file
that is already open.

Usage:
    python tools/por_hatari_load_trace.py --trace <hatari-gemdos.log> \
        --design <dir>\\PORALL29.DSN [--out data/<...>.json] [--note "<text>"] \
        [--source-status historical-runtime-log|fresh-bounded-run|unspecified]

--out must resolve under data/. Reports carry no absolute paths.

Exit: 0 evidence observed; 1 no GEO open observed (nothing to claim); 2 refusal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATA_ROOT = REPO / "data"

SCHEMA = "openua.por-hatari-load-trace"
SCHEMA_VERSION = 1
STATUS = "runtime-trace-evidence"
TOOL = "tools/por_hatari_load_trace.py"
# GEMDOS handles 0-5 are the standard CON/AUX/PRN devices, not disk files.
DEVICE_HANDLE_MAX = 5
GEO_NAME = re.compile(r"^GEO\d{3}\.DAT$", re.I)

RE_OPEN = re.compile(r'^GEMDOS 0x3D Fopen\("(?P<name>[^"]*)",\s*(?P<mode>[^)]*)\)', re.I)
RE_CREATE = re.compile(r'^GEMDOS 0x3C Fcreate\("(?P<name>[^"]*)"', re.I)
RE_HOST = re.compile(r"^GEMDOS: (?P<name>.+?) -> host: (?P<host>.+?)\s*$", re.I)
RE_FD = re.compile(r"^-> FD (?P<fd>\d+) \((?P<mode>[^)]*)\)", re.I)
RE_READ = re.compile(r"^GEMDOS 0x3F Fread\((?P<fd>\d+),\s*(?P<count>\d+),", re.I)
RE_WRITE = re.compile(r"^GEMDOS 0x40 Fwrite\((?P<fd>\d+),\s*(?P<count>\d+),", re.I)
RE_SEEK = re.compile(r"^GEMDOS 0x42 Fseek\((?P<off>-?\d+),\s*(?P<fd>\d+),\s*(?P<whence>\d+)\)", re.I)
RE_CLOSE = re.compile(r"^GEMDOS 0x3E Fclose\((?P<fd>\d+)\)", re.I)
RE_CALL = re.compile(r"^GEMDOS 0x[0-9a-f]{2} ", re.I)

NOT_CLAIMED = [
    "playable is false: no claim that the campaign or any map is playable",
    "no claim that any map was displayed or rendered",
    "no claim that original Pool of Radiance was matched",
    "no claim that the emulator consumed every byte of a design file "
    "(Hatari logs the requested Fread count, not the returned count)",
    "no claim about which executable produced the trace; none is hashed or pinned here",
    "no rerun or verification of current source; the trace is the only input read",
]


def check_path(raw: str, folder_name: str) -> Optional[str]:
    """None if `raw` is exactly <design folder>\\<file>; else the refusal reason."""
    norm = raw.replace("/", "\\")
    if norm.startswith("\\") or ":" in norm:
        return "absolute or drive-qualified name"
    parts = norm.split("\\")
    if any(p in ("", ".", "..") for p in parts):
        return "empty or traversal component"
    if len(parts) != 2:
        return "not <design folder>\\<file>"
    if parts[0].upper() != folder_name.upper():
        return "folder is not the supplied design folder"
    return None


def check_host(host: str, folder_name: str, base: str) -> Optional[str]:
    parts = [p for p in re.split(r"[\\/]", host) if p]
    if len(parts) < 2 or parts[-2].upper() != folder_name.upper() or parts[-1].upper() != base.upper():
        return "host path does not end in <design folder>/<file>"
    return None


def design_inventory(folder: Path) -> dict:
    """GEO###.DAT files of the design folder: name -> size and sha256."""
    out: dict = {}
    for p in sorted(folder.iterdir()):
        if p.is_file() and GEO_NAME.match(p.name):
            data = p.read_bytes()
            out[p.name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return out


def parse_trace(lines: list, folder_name: str, geo_by_upper: dict):
    """Follow FD lifecycles through the trace. Returns (refusals, counters, lifecycles)."""
    refusals: list = []
    counters = {
        "device_handle_events": 0,
        "failed_opens": 0,
        "other_gemdos_calls": 0,
        "non_geo_open_at_end": 0,
    }
    live: dict = {}
    finished: list = []
    pending: Optional[dict] = None

    def refuse(code: str, lineno: int, detail: str) -> None:
        refusals.append({"code": code, "line": lineno, "detail": detail})

    def open_fd(p: dict, fd: int, lineno: int) -> None:
        if fd <= DEVICE_HANDLE_MAX:
            refuse("reserved-handle", lineno, f"open returned reserved handle {fd}")
            return
        base = re.split(r"[\\/]", p["name"])[-1]
        is_geo = bool(GEO_NAME.match(base))
        if fd in live:
            old = live.pop(fd)
            refuse("fd-reuse-while-live", lineno,
                   f"FD {fd} reopened while still open since line {old['open_line']}")
            finished.append(old)
        life = {
            "fd": fd,
            "observed_name": p["name"],
            "mode": p["mode"],
            "open_line": p["line"],
            "close_line": None,
            "closed": False,
            "geo": is_geo,
            "design_name": None,
            "host_checked": False,
            "reads": [],
            "writes": 0,
            "seeks": 0,
        }
        if is_geo:
            reason = check_path(p["name"], folder_name)
            if reason:
                refuse("path-outside-design", lineno, f"{p['name']}: {reason}")
            if p.get("host") is not None:
                reason = check_host(p["host"], folder_name, base)
                if reason:
                    refuse("host-mismatch", p["host_line"], f"{p['name']}: {reason}")
                else:
                    life["host_checked"] = True
            canon = geo_by_upper.get(base.upper())
            if canon is None:
                refuse("geo-not-in-design", lineno, f"{base} is not a GEO file in the design folder")
            else:
                life["design_name"] = canon
                if any(o["design_name"] == canon for o in live.values()):
                    refuse("duplicate-open-of-live-geo", lineno, f"{canon} opened again while already open")
            if p["kind"] == "create":
                refuse("geo-create", lineno, f"{base} created with Fcreate; GEO files are read-only here")
        live[fd] = life

    def fd_event(kind: str, fd: int, lineno: int) -> Optional[dict]:
        if fd <= DEVICE_HANDLE_MAX:
            counters["device_handle_events"] += 1
            return None
        life = live.get(fd)
        if life is None:
            refuse("event-on-non-live-fd", lineno, f"{kind} on FD {fd} with no open lifecycle")
        return life

    for lineno, text in enumerate(lines, 1):
        s = text.rstrip()
        m = RE_HOST.match(s)
        if m:
            if pending is not None and m.group("name").upper() == pending["name"].upper():
                pending["host"] = m.group("host")
                pending["host_line"] = lineno
            continue
        m = RE_FD.match(s)
        if m:
            if pending is None:
                refuse("fd-line-unbound", lineno, "FD line with no preceding open")
            else:
                open_fd(pending, int(m.group("fd")), lineno)
                pending = None
            continue
        if not RE_CALL.match(s):
            continue
        if pending is not None:
            # An open with no FD line before the next call returned an error.
            counters["failed_opens"] += 1
            pending = None
        m = RE_OPEN.match(s)
        if m:
            pending = {"name": m.group("name"), "mode": m.group("mode").strip(),
                       "line": lineno, "kind": "open", "host": None}
            continue
        m = RE_CREATE.match(s)
        if m:
            pending = {"name": m.group("name"), "mode": "create",
                       "line": lineno, "kind": "create", "host": None}
            continue
        m = RE_READ.match(s)
        if m:
            life = fd_event("Fread", int(m.group("fd")), lineno)
            if life is not None:
                life["reads"].append({"line": lineno, "requested": int(m.group("count"))})
            continue
        m = RE_WRITE.match(s)
        if m:
            life = fd_event("Fwrite", int(m.group("fd")), lineno)
            if life is not None:
                life["writes"] += 1
                if life["geo"]:
                    refuse("geo-write", lineno, f"Fwrite on GEO FD {life['fd']} ({life['observed_name']})")
            continue
        m = RE_SEEK.match(s)
        if m:
            life = fd_event("Fseek", int(m.group("fd")), lineno)
            if life is not None:
                life["seeks"] += 1
            continue
        m = RE_CLOSE.match(s)
        if m:
            fd = int(m.group("fd"))
            life = fd_event("Fclose", fd, lineno)
            if life is not None:
                life["close_line"] = lineno
                life["closed"] = True
                finished.append(live.pop(fd))
            continue
        counters["other_gemdos_calls"] += 1

    if pending is not None:
        counters["failed_opens"] += 1
    for fd in sorted(live):
        life = live[fd]
        if life["geo"]:
            refuse("incomplete-lifecycle", life["open_line"],
                   f"FD {fd} ({life['observed_name']}) not closed before end of trace")
        else:
            counters["non_geo_open_at_end"] += 1
        finished.append(life)
    return refusals, counters, finished


def _public(life: dict) -> dict:
    return {
        "fd": life["fd"],
        "observed_name": life["observed_name"],
        "mode": life["mode"],
        "open_line": life["open_line"],
        "close_line": life["close_line"],
        "closed": life["closed"],
        "host_checked": life["host_checked"],
        "reads": life["reads"],
        "read_requested_bytes": sum(r["requested"] for r in life["reads"]),
        "writes": life["writes"],
        "seeks": life["seeks"],
    }


SOURCE_STATUSES = ("historical-runtime-log", "fresh-bounded-run", "unspecified")


def build_report(trace: Path, folder: Path, note: str = "", source_status: str = "unspecified"):
    """Return (report dict, exit code). Pure: writes nothing."""
    if source_status not in SOURCE_STATUSES:
        raise ValueError(f"source_status must be one of {SOURCE_STATUSES}")
    raw = trace.read_bytes()
    lines = raw.decode("latin-1").splitlines()
    inv = design_inventory(folder)
    geo_by_upper = {n.upper(): n for n in inv}
    refusals, counters, finished = parse_trace(lines, folder.name, geo_by_upper)

    files = []
    for name in sorted(inv):
        lives = [life for life in finished if life.get("design_name") == name]
        if not lives:
            continue
        unclosed = sum(1 for life in lives if not life["closed"])
        read_occ = sum(1 for life in lives if life["closed"] and life["reads"])
        open_only = sum(1 for life in lives if life["closed"] and not life["reads"])
        if unclosed:
            status = "open-unclosed"
        elif read_occ:
            status = "open+read"
        else:
            status = "open-only"
        files.append({
            "design_name": name,
            "size": inv[name]["size"],
            "sha256": inv[name]["sha256"],
            "observed_names": sorted({life["observed_name"] for life in lives}),
            "opens": len(lives),
            "open_only_occurrences": open_only,
            "open_and_read_occurrences": read_occ,
            "unclosed_occurrences": unclosed,
            "status": status,
            "byte_consumption": "not-asserted",
            "lifecycles": [_public(life) for life in lives],
        })

    if refusals:
        verdict, code = "refused", 2
    elif files:
        verdict, code = "evidence", 0
    else:
        verdict, code = "no-geo-open-observed", 1

    claims: list = []
    if verdict == "evidence":
        claims.append("Runtime GEMDOS trace shows OpenUA opening DSN GEO files from the "
                      "supplied design folder. File-level evidence only.")
        for f in files:
            claims.append(
                f"{f['design_name']}: {f['opens']} open lifecycle(s); {f['open_only_occurrences']} "
                f"open-only, {f['open_and_read_occurrences']} open+read; file status {f['status']}.")

    report = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "status": STATUS,
        "playable": False,
        "verdict": verdict,
        "claims": claims,
        "not_claimed": NOT_CLAIMED,
        "provenance": {
            "trace_file": trace.name,
            "trace_sha256": hashlib.sha256(raw).hexdigest(),
            "trace_lines": len(lines),
            "source_status": source_status,
            "note": note,
            "binary_identity": "not recorded in the trace; not pinned by this tool",
        },
        "design": {
            "folder": folder.name,
            "geo_files": [{"name": n, "size": v["size"], "sha256": v["sha256"]} for n, v in sorted(inv.items())],
        },
        "observed": {"geo_files": files},
        "counters": counters,
        "refusals": refusals,
    }
    return report, code


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Check Hatari GEMDOS trace evidence for DSN GEO file opens/reads.")
    ap.add_argument("--trace", required=True, help="Hatari verbose GEMDOS log (read-only)")
    ap.add_argument("--design", required=True, help="DSN folder to compare against (read-only)")
    ap.add_argument("--out", help="optional JSON report; must resolve under data/")
    ap.add_argument("--note", default="", help="provenance note recorded verbatim in the report")
    ap.add_argument("--source-status", default="unspecified", choices=SOURCE_STATUSES,
                    help="what kind of run the trace is (recorded verbatim; not verified)")
    args = ap.parse_args(argv)

    trace = Path(args.trace)
    folder = Path(args.design)
    if not trace.is_file():
        print(f"refused: trace is not a file: {trace.name}", file=sys.stderr)
        return 2
    if not folder.is_dir():
        print(f"refused: design is not a directory: {folder.name}", file=sys.stderr)
        return 2
    out = None
    if args.out:
        out = Path(args.out).resolve()
        if not _under(out, DATA_ROOT):
            print("refused: --out must resolve under data/", file=sys.stderr)
            return 2

    report, code = build_report(trace, folder, args.note, args.source_status)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"{TOOL}: trace={trace.name} verdict={report['verdict']} playable=false")
    for f in report["observed"]["geo_files"]:
        print(f"  {f['design_name']}: {f['status']} (opens={f['opens']}, "
              f"open-only={f['open_only_occurrences']}, open+read={f['open_and_read_occurrences']})")
    for r in report["refusals"]:
        print(f"  refusal {r['code']} line {r['line']}: {r['detail']}")
    if out is not None:
        print(f"  report written: {out.name}")
    return code


if __name__ == "__main__":
    sys.exit(main())
