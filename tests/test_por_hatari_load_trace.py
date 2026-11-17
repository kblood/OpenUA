"""Tests for tools/por_hatari_load_trace.py — Hatari GEMDOS GEO open/read evidence.

Retail-independent and ignored-data-independent. The historical diag2 evidence is
represented by LITERAL excerpts copied from
data/work/por-openua-party-runtime-diag2-20261117/hatari-gemdos.log (lines
24047-24055 and 196-199). Design folders are synthetic, written into tmp_path.
The excerpts show only what the log says; the historical run is not rerun.
"""
import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import por_hatari_load_trace as hlt  # noqa: E402

FOLDER = "PORALL29.DSN"
GEO_BYTES = {"GEO005.DAT": b"\x5a" * 12962, "GEO006.DAT": b"\xa5" * 12962}

# Literal: historical log lines 24047-24055. GAME001 read at 24050 precedes the
# GEO005 open and must NOT be attributed to GEO005.
EXCERPT_24047_24055 = r"""GEMDOS 0x3D Fopen("PORALL29.DSN\GAME001.dat", read/write) at PC=0xE4DD6
GEMDOS: PORALL29.DSN\GAME001.dat -> host: /mnt/c/Modding/OpenUA/data/work/por-openua-party-runtime-diag2-20261117/PORALL29.DSN/GAME001.DAT
-> FD 64 (read/write -> read+write)
GEMDOS 0x3F Fread(64, 32766, 0x17dad0) at PC 0xE4EA6
GEMDOS 0x3E Fclose(64) at PC 0xE4E4A
GEMDOS 0x3D Fopen("PORALL29.DSN\GEO005.dat", read/write) at PC=0xE4DD6
GEMDOS: PORALL29.DSN\GEO005.dat -> host: /mnt/c/Modding/OpenUA/data/work/por-openua-party-runtime-diag2-20261117/PORALL29.DSN/GEO005.DAT
-> FD 64 (read/write -> read+write)
GEMDOS 0x3E Fclose(64) at PC 0xE4E4A"""

# Literal: historical log lines 24052-24055 (the exact open-only GEO005 sequence).
EXCERPT_24052_24055 = EXCERPT_24047_24055.splitlines()[5:]

# Literal: historical log lines 196-199 (the earlier GEO005 occurrence, also open-only).
EXCERPT_196_199 = r"""GEMDOS 0x3D Fopen("PORALL29.DSN\GEO005.dat", read/write) at PC=0xE4DD6
GEMDOS: PORALL29.DSN\GEO005.dat -> host: /mnt/c/Modding/OpenUA/data/work/por-openua-party-runtime-diag2-20261117/PORALL29.DSN/GEO005.DAT
-> FD 64 (read/write -> read+write)
GEMDOS 0x3E Fclose(64) at PC 0xE4E4A"""


def _host(base: str) -> str:
    return f"/synthetic/{FOLDER}/{base.upper()}"


def fopen(name: str, mode: str = "read/write") -> str:
    return f'GEMDOS 0x3D Fopen("{name}", {mode}) at PC=0xE4DD6'


def host(name: str, base: str) -> str:
    return f"GEMDOS: {name} -> host: {_host(base)}"


def fd(n: int) -> str:
    return f"-> FD {n} (read/write -> read+write)"


def fread(n: int, count: int = 32766) -> str:
    return f"GEMDOS 0x3F Fread({n}, {count}, 0x17dad0) at PC 0xE4EA6"


def fwrite(n: int) -> str:
    return f"GEMDOS 0x40 Fwrite({n}, 10, 0x17dad0) at PC 0xE4EA6"


def fclose(n: int) -> str:
    return f"GEMDOS 0x3E Fclose({n}) at PC 0xE4E4A"


def geo_open(name: str, base: str, fd_no: int, reads: int = 0, close: bool = True) -> list:
    lines = [fopen(name), host(name, base), fd(fd_no)]
    lines += [fread(fd_no) for _ in range(reads)]
    if close:
        lines.append(fclose(fd_no))
    return lines


@pytest.fixture
def design(tmp_path: Path) -> Path:
    d = tmp_path / FOLDER
    d.mkdir()
    for name, data in GEO_BYTES.items():
        (d / name).write_bytes(data)
    return d


def run(tmp_path: Path, design: Path, lines, note: str = "synthetic"):
    trace = tmp_path / "hatari-gemdos.log"
    trace.write_text("\n".join(lines) + "\n", encoding="latin-1")
    return hlt.build_report(trace, design, note)


def geo(report: dict, name: str) -> dict:
    return next(f for f in report["observed"]["geo_files"] if f["design_name"] == name)


def codes(report: dict) -> set:
    return {r["code"] for r in report["refusals"]}


def assert_no_playable_claim(report: dict) -> None:
    assert report["playable"] is False
    assert report["status"] == "runtime-trace-evidence"
    assert any("playable" in s for s in report["not_claimed"])


# --- historical diag2 excerpts (literal) ---------------------------------------

def test_real_excerpt_24047_24055_geo005_is_open_only(tmp_path, design):
    report, code = run(tmp_path, design, EXCERPT_24047_24055.splitlines())
    assert code == 0
    assert report["verdict"] == "evidence"
    assert_no_playable_claim(report)
    f = geo(report, "GEO005.DAT")
    assert f["status"] == "open-only"
    assert f["opens"] == 1
    assert f["open_only_occurrences"] == 1
    assert f["open_and_read_occurrences"] == 0
    life = f["lifecycles"][0]
    assert life["fd"] == 64
    # Excerpt line numbers: 6 = Fopen GEO005, 9 = Fclose(64). Nothing between them.
    assert life["open_line"] == 6
    assert life["close_line"] == 9
    assert life["reads"] == []
    assert life["read_requested_bytes"] == 0
    # The GAME001 Fread(64, ...) at excerpt line 4 sits on the GAME001 lifecycle
    # (not a GEO file), so GEO005 has no attributed read.
    assert [x["design_name"] for x in report["observed"]["geo_files"]] == ["GEO005.DAT"]


def test_regression_exact_open_only_sequence_24052_24055(tmp_path, design):
    report, code = run(tmp_path, design, EXCERPT_24052_24055)
    assert code == 0
    f = geo(report, "GEO005.DAT")
    assert f["status"] == "open-only"
    assert f["open_and_read_occurrences"] == 0
    assert report["claims"][1] == (
        "GEO005.DAT: 1 open lifecycle(s); 1 open-only, 0 open+read; file status open-only.")


def test_real_excerpt_196_199_second_occurrence_is_open_only(tmp_path, design):
    report, code = run(tmp_path, design, EXCERPT_196_199.splitlines())
    assert code == 0
    f = geo(report, "GEO005.DAT")
    assert f["status"] == "open-only"
    assert f["lifecycles"][0]["fd"] == 64
    assert f["lifecycles"][0]["reads"] == []


# Literal: fresh bounded run data/work/por-openua-runtime-allmap-smoke-20261117/
# hatari-gemdos.log lines 191-199. GAME001 read (line 194) is on its own FD-64
# lifecycle; the GEO001 lifecycle (lines 196-199) has no Fread.
SMOKE_191_199 = r"""GEMDOS 0x3D Fopen("PORALL29.DSN\GAME001.dat", read/write) at PC=0xE4642
GEMDOS: PORALL29.DSN\GAME001.dat -> host: /mnt/c/Modding/OpenUA/data/work/por-openua-runtime-allmap-smoke-20261117/PORALL29.DSN/GAME001.DAT
-> FD 64 (read/write -> read+write)
GEMDOS 0x3F Fread(64, 32766, 0x17d33c) at PC 0xE4712
GEMDOS 0x3E Fclose(64) at PC 0xE46B6
GEMDOS 0x3D Fopen("PORALL29.DSN\GEO001.dat", read/write) at PC=0xE4642
GEMDOS: PORALL29.DSN\GEO001.dat -> host: /mnt/c/Modding/OpenUA/data/work/por-openua-runtime-allmap-smoke-20261117/PORALL29.DSN/GEO001.DAT
-> FD 64 (read/write -> read+write)
GEMDOS 0x3E Fclose(64) at PC 0xE46B6"""


def test_fresh_smoke_excerpt_geo001_is_open_only(tmp_path):
    design = tmp_path / FOLDER
    design.mkdir()
    (design / "GEO001.DAT").write_bytes(b"\x00" * 12962)
    (design / "GAME001.DAT").write_bytes(b"\x00" * 388)
    report, code = run(tmp_path, design, SMOKE_191_199.splitlines(), note="smoke excerpt")
    assert code == 0
    assert_no_playable_claim(report)
    f = geo(report, "GEO001.DAT")
    assert f["status"] == "open-only"
    assert f["lifecycles"][0]["open_line"] == 6
    assert f["lifecycles"][0]["close_line"] == 9
    assert f["lifecycles"][0]["reads"] == []
    assert [x["design_name"] for x in report["observed"]["geo_files"]] == ["GEO001.DAT"]


def test_source_status_is_recorded_as_given(tmp_path, design):
    trace = tmp_path / "hatari-gemdos.log"
    trace.write_text("\n".join(geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64)) + "\n", encoding="latin-1")
    report, _ = hlt.build_report(trace, design, "note", "fresh-bounded-run")
    assert report["provenance"]["source_status"] == "fresh-bounded-run"
    report, _ = hlt.build_report(trace, design, "note")
    assert report["provenance"]["source_status"] == "unspecified"
    with pytest.raises(ValueError):
        hlt.build_report(trace, design, "note", "made-up")


# --- positive and falsification cases (synthetic) -----------------------------

def test_open_and_read_is_reported_separately(tmp_path, design):
    report, code = run(tmp_path, design, geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64, reads=2))
    assert code == 0
    f = geo(report, "GEO005.DAT")
    assert f["status"] == "open+read"
    assert f["open_and_read_occurrences"] == 1
    assert f["open_only_occurrences"] == 0
    assert f["lifecycles"][0]["read_requested_bytes"] == 2 * 32766
    assert f["byte_consumption"] == "not-asserted"


def test_no_read_is_not_reported_as_open_and_read(tmp_path, design):
    report, _ = run(tmp_path, design, geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64, reads=0))
    f = geo(report, "GEO005.DAT")
    assert f["status"] == "open-only"
    assert f["lifecycles"][0]["reads"] == []


def test_wrong_fd_read_is_refused(tmp_path, design):
    lines = [fopen(f"{FOLDER}\\GEO005.DAT"), host(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT"), fd(64),
             fread(65), fclose(64)]
    report, code = run(tmp_path, design, lines)
    assert code == 2
    assert report["verdict"] == "refused"
    assert "event-on-non-live-fd" in codes(report)
    assert report["claims"] == []


def test_missing_close_is_refused(tmp_path, design):
    report, code = run(tmp_path, design, geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64, reads=1, close=False))
    assert code == 2
    assert "incomplete-lifecycle" in codes(report)
    assert report["claims"] == []


def test_fd_reuse_while_live_is_refused(tmp_path, design):
    lines = [fopen(f"{FOLDER}\\GEO005.DAT"), host(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT"), fd(64),
             fopen(f"{FOLDER}\\GEO006.DAT"), host(f"{FOLDER}\\GEO006.DAT", "GEO006.DAT"), fd(64),
             fclose(64)]
    report, code = run(tmp_path, design, lines)
    assert code == 2
    assert "fd-reuse-while-live" in codes(report)


def test_duplicate_open_of_live_geo_is_refused(tmp_path, design):
    lines = [fopen(f"{FOLDER}\\GEO005.DAT"), host(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT"), fd(64),
             fopen(f"{FOLDER}\\GEO005.DAT"), host(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT"), fd(65),
             fclose(65), fclose(64)]
    report, code = run(tmp_path, design, lines)
    assert code == 2
    assert "duplicate-open-of-live-geo" in codes(report)


@pytest.mark.parametrize("name", [
    f"{FOLDER}\\..\\OTHER.DSN\\GEO005.dat",
    f"..\\{FOLDER}\\GEO005.DAT",
    f"C:\\{FOLDER}\\GEO005.DAT",
    f"\\{FOLDER}\\GEO005.DAT",
    "GEO005.DAT",
    f"{FOLDER}\\SAVE\\GEO005.DAT",
    "OTHER.DSN\\GEO005.dat",
])
def test_path_outside_design_is_refused(tmp_path, design, name):
    report, code = run(tmp_path, design, geo_open(name, "GEO005.DAT", 64, reads=1))
    assert code == 2
    assert "path-outside-design" in codes(report)
    assert report["claims"] == []


def test_case_variation_matches_design_name(tmp_path, design):
    report, code = run(tmp_path, design, geo_open("porall29.dsn\\geo005.dat", "GEO005.DAT", 64, reads=1))
    assert code == 0
    f = geo(report, "GEO005.DAT")
    assert f["observed_names"] == ["porall29.dsn\\geo005.dat"]
    assert f["status"] == "open+read"
    assert f["lifecycles"][0]["host_checked"] is True


def test_multiple_geo_files_are_independent(tmp_path, design):
    lines = []
    lines += geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64, reads=2)
    lines += geo_open(f"{FOLDER}\\GAME001.dat", "GAME001.DAT", 64, reads=1)
    lines += geo_open(f"{FOLDER}\\GEO006.DAT", "GEO006.DAT", 64, reads=0)
    report, code = run(tmp_path, design, lines)
    assert code == 0
    assert geo(report, "GEO005.DAT")["status"] == "open+read"
    assert geo(report, "GEO006.DAT")["status"] == "open-only"
    assert [f["design_name"] for f in report["observed"]["geo_files"]] == ["GEO005.DAT", "GEO006.DAT"]


def test_failed_open_is_not_evidence(tmp_path, design):
    lines = [fopen(f"{FOLDER}\\GEO005.DAT"), "GEMDOS didn't find filename"]
    report, code = run(tmp_path, design, lines)
    assert code == 1
    assert report["verdict"] == "no-geo-open-observed"
    assert report["observed"]["geo_files"] == []
    assert report["counters"]["failed_opens"] == 1


def test_geo_not_in_design_is_refused(tmp_path, design):
    report, code = run(tmp_path, design, geo_open(f"{FOLDER}\\GEO099.DAT", "GEO099.DAT", 64))
    assert code == 2
    assert "geo-not-in-design" in codes(report)


def test_host_mismatch_is_refused(tmp_path, design):
    lines = [fopen(f"{FOLDER}\\GEO005.DAT"),
             f"GEMDOS: {FOLDER}\\GEO005.DAT -> host: /elsewhere/OTHER.DSN/GEO005.DAT",
             fd(64), fclose(64)]
    report, code = run(tmp_path, design, lines)
    assert code == 2
    assert "host-mismatch" in codes(report)


def test_geo_write_is_refused(tmp_path, design):
    lines = [fopen(f"{FOLDER}\\GEO005.DAT"), host(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT"), fd(64),
             fwrite(64), fclose(64)]
    report, code = run(tmp_path, design, lines)
    assert code == 2
    assert "geo-write" in codes(report)


def test_report_is_deterministic_and_path_free(tmp_path, design):
    lines = geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64, reads=1)
    import json
    a, _ = run(tmp_path, design, lines)
    b, _ = run(tmp_path, design, lines)
    ja = json.dumps(a, sort_keys=True)
    assert ja == json.dumps(b, sort_keys=True)
    for needle in (str(tmp_path), "/synthetic", "/mnt/", "C:\\", "-> host"):
        assert needle not in ja
    geo005 = a["design"]["geo_files"][0]
    assert geo005["size"] == 12962
    assert geo005["sha256"] == hashlib.sha256(GEO_BYTES["GEO005.DAT"]).hexdigest()


def test_out_outside_data_is_refused(tmp_path, design):
    trace = tmp_path / "hatari-gemdos.log"
    trace.write_text("\n".join(geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64)) + "\n", encoding="latin-1")
    out = tmp_path / "report.json"
    assert hlt.main(["--trace", str(trace), "--design", str(design), "--out", str(out)]) == 2
    assert not out.exists()


def test_out_under_data_is_written(tmp_path, design, monkeypatch):
    monkeypatch.setattr(hlt, "DATA_ROOT", tmp_path / "data")
    trace = tmp_path / "hatari-gemdos.log"
    trace.write_text("\n".join(geo_open(f"{FOLDER}\\GEO005.DAT", "GEO005.DAT", 64, reads=1)) + "\n",
                     encoding="latin-1")
    out = tmp_path / "data" / "work" / "por-hatari-load-trace" / "report.json"
    assert hlt.main(["--trace", str(trace), "--design", str(design), "--out", str(out)]) == 0
    assert out.is_file()
