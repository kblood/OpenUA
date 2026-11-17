#!/usr/bin/env python3
"""Read-only census of a bounded FRUA_AREATEST Hatari run directory.

Classifies whether a bounded run stopped at an ERRMODAL before reaching its
GEO-load markers, or logged a successful GEO parse. It only READS the run directory (DBG.LOG, start.dat, the
design folder, frua.rsc, frua.prg) and an optional build directory's
.machine stamp. It never builds, boots or edits anything.

What it reports (each line is evidence, not a verdict on its own):

  * the first ERRMODAL line, and whether any harness/GEO marker came before it
  * whether the probe-only self-tests compiled into the binary ran
    ("L2856 self-test", "jt127 self-test" in DBG.LOG)
  * whether the DBG.LOG stub stream is the FLOOD form (repeated names; the
    ENGINE_PROBE=1 once-per-name form cannot repeat a name)
  * the start.dat design name and whether that design holds GEO040.DAT (the
    tutorial file the probe-only jt127 self-test asks for)
  * which DATA/ZERO/DREL resources frua.rsc carries (the A5-world replay
    needs all three; without them the freemap stays zero)
  * optionally, whether a build stamp's EXTRA_CFLAGS checksum matches a given
    flag string (Makefile: BUILDSTAMP ... -x<cksum of EXTRA_CFLAGS>)

Usage:
    areatest_modal_census.py <run-dir> [--build-dir DIR]
                             [--extra-cflags STR] [--out PATH]

Exit status is 0 whatever the verdict; the verdict is printed, not enforced.
"""
import argparse
import os
import re
import struct
import sys

MODAL_RE = re.compile(r"^ERRMODAL: Group (\d+) in use for '(.*)'\s*$")
# Harness / GEO-load markers. "stub: jt361" and "stub: jt198" are PROBE names;
# the others are dbg_log lines from the AREATEST harness and the GEO loader.
MARKER_RE = re.compile(
    r"(stub: jt361|stub: jt198|jt361 |jt198 |^== GEO level|areatest|AREATEST|evtsnd:|"
    r"GEO0\d\d)", re.IGNORECASE)
GEO_PARSE_RE = re.compile(r"^== GEO level(\d+)\s*$")
GEO_WIDTH_RE = re.compile(r"^\s*width\(ds2\)(\d+)\s*$")
GEO_HEIGHT_RE = re.compile(r"^\s*height\(ds3\)(\d+)\s*$")
STUB_RE = re.compile(r"^stub: (\S+)")
# Both strings live in the boot_a5_seed_defaults FRUA_ENGINE_PROBE block
# (boot.c ~12008-12181). "L2856 self-test" is logged at block entry, BEFORE the
# GEO040 jt127 read; "jt127 self-test" is logged only after that read returns,
# so a run that blocks in the GEO040 fallback never shows it.
PROBE_SELFTESTS = ("L2856 self-test", "jt127 self-test")
PROBE_BLOCK_ENTRY = "L2856 self-test"

# POSIX cksum (what `printf '%s' STR | cksum` prints), table-driven.
_CKSUM_TABLE = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = (((_c << 1) ^ 0x04C11DB7) if (_c & 0x80000000) else (_c << 1)) \
            & 0xFFFFFFFF
    _CKSUM_TABLE.append(_c)


def posix_cksum(data):
    """Return the POSIX cksum (CRC + length) of `data` as an unsigned int."""
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CKSUM_TABLE[((crc >> 24) ^ byte) & 0xFF]
    n = len(data)
    while n:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CKSUM_TABLE[((crc >> 24) ^ (n & 0xFF)) & 0xFF]
        n >>= 8
    return (~crc) & 0xFFFFFFFF


def read_dbg_log(run_dir):
    path = os.path.join(run_dir, "DBG.LOG")
    if not os.path.isfile(path):
        return None
    text = open(path, "rb").read().decode("latin-1")
    return [ln.rstrip("\r") for ln in text.split("\n")]


def start_design(run_dir):
    """Design folder named by start.dat (34-byte NUL-padded name + flag)."""
    path = os.path.join(run_dir, "start.dat")
    if not os.path.isfile(path):
        return None, None
    raw = open(path, "rb").read()
    name = raw[:34].split(b"\0", 1)[0].decode("latin-1")
    flag = raw[34] if len(raw) > 34 else None
    return name, flag


def design_geo_files(run_dir, design):
    if not design:
        return None
    ddir = os.path.join(run_dir, design)
    if not os.path.isdir(ddir):
        return None
    return sorted(f for f in os.listdir(ddir)
                  if re.fullmatch(r"GEO\d{3}\.DAT", f.upper()))


def frsc_types(path):
    """Resource types in a FRSC flat archive (16-byte header, 16-byte entries)."""
    if not os.path.isfile(path):
        return None
    b = open(path, "rb").read()
    if b[:4] != b"FRSC":
        return ["<not FRSC>"]
    _, _, count, hsize, _ = struct.unpack(">4sHHII", b[:16])
    types = set()
    off = hsize
    for _ in range(count):
        types.add(b[off:off + 4].decode("mac-roman"))
        off += 16
    return sorted(types)


def stamp_cksum(build_dir):
    path = os.path.join(build_dir, ".machine")
    if not os.path.isfile(path):
        return None, None
    stamp = open(path, "rb").read().decode("latin-1").strip()
    m = re.search(r"-x(\d+)$", stamp)
    return stamp, (int(m.group(1)) if m else None)


def successful_geo_parses(lines):
    """Read FRUA_CELLSCAN's post-read, post-parse GEO markers from DBG.LOG."""
    rows = []
    for idx, line in enumerate(lines):
        m = GEO_PARSE_RE.match(line)
        if not m:
            continue
        width = height = None
        for follow in lines[idx + 1:idx + 5]:
            wm = GEO_WIDTH_RE.match(follow)
            hm = GEO_HEIGHT_RE.match(follow)
            if wm:
                width = int(wm.group(1))
            if hm:
                height = int(hm.group(1))
        rows.append({"line": idx + 1, "level": int(m.group(1)),
                     "width": width, "height": height})
    return rows


def census(run_dir, build_dir=None, extra_cflags=None):
    """Collect the evidence as a dict. Pure function of the directory."""
    info = {"run_dir": run_dir}
    lines = read_dbg_log(run_dir)
    info["dbg_log"] = lines is not None
    lines = lines or []

    modal = None
    marker_before = []
    for idx, ln in enumerate(lines):
        if ln.startswith("ERRMODAL:") and modal is None:
            modal = {"line": idx + 1, "text": ln,
                     "match": MODAL_RE.match(ln) is not None}
            break
        if MARKER_RE.search(ln):
            marker_before.append(idx + 1)
    info["modal"] = modal
    info["markers_before_modal"] = marker_before[:5]
    info["marker_count_before_modal"] = len(marker_before)
    info["successful_geo_parses"] = successful_geo_parses(lines)

    stubs = [m.group(1) for ln in lines for m in [STUB_RE.match(ln)] if m]
    info["stub_lines"] = len(stubs)
    info["stub_unique"] = len(set(stubs))
    info["stub_form"] = ("flood (names repeat)" if len(stubs) > len(set(stubs))
                         else "once-per-name or no stub lines")

    info["probe_selftests_ran"] = {
        s: any(s in ln for ln in lines) for s in PROBE_SELFTESTS}

    design, flag = start_design(run_dir)
    info["start_design"] = design
    info["start_flag"] = flag
    geo = design_geo_files(run_dir, design)
    info["design_dir_present"] = geo is not None
    info["design_dir_with_dsn"] = bool(design) and os.path.isdir(
        os.path.join(run_dir, design + ".DSN"))
    info["design_geo_count"] = len(geo) if geo else 0
    info["design_has_geo040"] = bool(geo) and "GEO040.DAT" in [g.upper() for g in geo]

    types = frsc_types(os.path.join(run_dir, "frua.rsc"))
    info["frsc_types"] = types
    info["replay_resources_present"] = (
        types is not None and all(t in types for t in ("DATA", "ZERO", "DREL")))

    prg = os.path.join(run_dir, "frua.prg")
    if os.path.isfile(prg):
        blob = open(prg, "rb").read()
        info["prg_has_probe_selftests"] = {
            s: s.encode() in blob for s in PROBE_SELFTESTS}
    else:
        info["prg_has_probe_selftests"] = None

    if build_dir is not None:
        stamp, cks = stamp_cksum(build_dir)
        info["build_stamp"] = stamp
        info["build_stamp_cksum"] = cks
        if extra_cflags is not None:
            want = posix_cksum(extra_cflags.encode("utf-8"))
            info["extra_cflags_cksum"] = want
            info["extra_cflags_match"] = (cks == want)

    info["verdict"] = verdict(info)
    return info


def verdict(info):
    modal = info.get("modal")
    if not info.get("dbg_log"):
        return "NO_DBG_LOG: nothing to classify"
    if modal is None:
        if info.get("successful_geo_parses"):
            return ("GEO_PARSE_REACHED: FRUA_CELLSCAN logged after jt198's file-size "
                    "check and GEO parse completed")
        return "NO_MODAL: no ERRMODAL line in DBG.LOG"
    if info["marker_count_before_modal"] == 0 and \
            not info["design_dir_present"] and info.get("design_dir_with_dsn"):
        return ("DESIGN_NAME_MISSING: start.dat names '%s' but the design folder "
                "is '%s' (the .DSN suffix is missing); GAME001.DAT cannot open, so "
                "jt127 falls back to a .GLB group-19 load and ERRMODAL fires"
                % (info["start_design"], info["start_design"] + ".DSN"))
    if info["marker_count_before_modal"] == 0 and \
            info["probe_selftests_ran"].get(PROBE_BLOCK_ENTRY) and \
            not info["design_has_geo040"]:
        return ("PROBE_GEO040_SELFTEST: ERRMODAL before any harness/GEO marker, "
                "probe-only jt127 self-test ran, and the design lacks GEO040.DAT "
                "(consistent with the boot.c:12060 fallback to GEO.GLB group 19)")
    if info["marker_count_before_modal"] == 0:
        return ("MODAL_BEFORE_MARKERS: ERRMODAL before any harness/GEO marker; "
                "cause not identified by this census")
    return ("MODAL_AFTER_MARKERS: harness/GEO markers came before the ERRMODAL; "
            "see the DBG.LOG lines around it")


def render(info):
    out = []
    w = out.append
    w("# AREATEST run census")
    w("")
    w(f"run dir: `{info['run_dir']}`")
    w(f"verdict: **{info['verdict']}**")
    w("")
    m = info.get("modal")
    if m:
        w(f"- first ERRMODAL: DBG.LOG line {m['line']}: `{m['text']}`")
    else:
        w("- first ERRMODAL: none")
    w(f"- harness/GEO markers before the first ERRMODAL: "
      f"{info['marker_count_before_modal']} (first lines {info['markers_before_modal']})")
    w(f"- successful GEO parse markers: {info['successful_geo_parses']}")
    w(f"- stub lines: {info['stub_lines']} (unique {info['stub_unique']}): "
      f"{info['stub_form']}")
    w(f"- probe-only self-tests in DBG.LOG: {info['probe_selftests_ran']}")
    if info.get("prg_has_probe_selftests") is not None:
        w(f"- probe-only self-test strings in frua.prg: {info['prg_has_probe_selftests']}")
    w(f"- start.dat design: `{info['start_design']}` flag={info['start_flag']}")
    w(f"- design folder present: {info['design_dir_present']}; "
      f"GEO*.DAT count {info['design_geo_count']}; GEO040.DAT present: "
      f"{info['design_has_geo040']}")
    w(f"- frua.rsc resource types: {info['frsc_types']}; DATA/ZERO/DREL replay "
      f"resources present: {info['replay_resources_present']}")
    if "build_stamp" in info:
        w(f"- build stamp: `{info['build_stamp']}` (cksum {info['build_stamp_cksum']})")
    if "extra_cflags_match" in info:
        w(f"- EXTRA_CFLAGS cksum {info['extra_cflags_cksum']} matches stamp: "
          f"{info['extra_cflags_match']}")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run_dir")
    ap.add_argument("--build-dir")
    ap.add_argument("--extra-cflags")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    info = census(args.run_dir, args.build_dir, args.extra_cflags)
    text = render(info)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
