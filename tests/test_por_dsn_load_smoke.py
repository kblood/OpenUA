"""Tests for tools/por_dsn_load_smoke.py — loader-equivalent host checks.

Fixtures are synthetic and retail-independent: each design is written by the
real tools/dsn.py Design.write from geo.Geo.blank areas, into pytest's tmp_path.
No game data, no emulator, no DOSBox.

The tests pin the checks, and one divergence the tool exists to expose:
geo.Geo.parse accepts a 12963-byte GEO (odd-size padding) but the engine's
jt198 requires exactly 12962 bytes. A design with such a file parses in
tools/geo.py and is still refused here.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import por_dsn_load_smoke as smoke  # noqa: E402
from dsn import Design  # noqa: E402
from geo import GEO_SIZE, Geo, GeoError  # noqa: E402

TOOL = Path(__file__).resolve().parent.parent / "tools" / "por_dsn_load_smoke.py"


def make_design(base: Path, name: str = "SMOKE", extra_areas=()) -> Path:
    """Write a minimal design with the real writer; return its folder."""
    d = Design(name)
    d.start_area = 1
    d.add_area(1, Geo.blank(3, 3))
    for n in extra_areas:
        d.add_area(n, Geo.blank(3, 3))
    base.mkdir(parents=True, exist_ok=True)
    return Path(d.write(str(base)))


def statuses(report: dict) -> dict:
    return {c["id"]: c["status"] for c in report["checks"]}


def failing(report: dict) -> list:
    return [c["id"] for c in report["checks"] if c["status"] == "fail"]


def snapshot(folder: Path) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.iterdir()) if p.is_file()}


# --- the good case, from the real writer ------------------------------------

def test_generated_design_passes(tmp_path):
    folder = make_design(tmp_path / "out")
    report = smoke.validate_folder(folder)
    assert report["verdict"] == "pass", failing(report)
    assert report["start_area"] == 1
    assert report["start_entry"] == 1
    assert report["runtime_loaded"] is False
    assert report["engine_executed"] is False
    assert set(report["files"]) == {"GAME001.DAT", "GEO001.DAT"}
    assert report["files"]["GEO001.DAT"]["bytes"] == GEO_SIZE


def test_report_states_limitations(tmp_path):
    report = smoke.validate_folder(make_design(tmp_path / "out"))
    assert any("does not run it" in s for s in report["limitations"])


# --- GAME001.DAT ------------------------------------------------------------

def test_missing_game001_fails(tmp_path):
    folder = make_design(tmp_path / "out")
    (folder / "GAME001.DAT").unlink()
    report = smoke.validate_folder(folder)
    assert report["verdict"] == "fail"
    assert statuses(report)["game001-present"] == "fail"


def test_short_game001_fails(tmp_path):
    folder = make_design(tmp_path / "out")
    (folder / "GAME001.DAT").write_bytes(b"\x00" * 49)  # bytes 48-49 need 50
    report = smoke.validate_folder(folder)
    assert statuses(report)["game001-start-bytes"] == "fail"
    assert report["start_area"] is None


def test_start_area_zero_fails(tmp_path):
    folder = make_design(tmp_path / "out")
    rec = bytearray((folder / "GAME001.DAT").read_bytes())
    rec[48] = 0
    (folder / "GAME001.DAT").write_bytes(bytes(rec))
    report = smoke.validate_folder(folder)
    assert statuses(report)["start-area-nonzero"] == "fail"


def test_start_geo_missing_fails(tmp_path):
    folder = make_design(tmp_path / "out")
    (folder / "GEO001.DAT").unlink()
    report = smoke.validate_folder(folder)
    assert statuses(report)["start-geo-present"] == "fail"
    assert statuses(report)["geo-files-present"] == "fail"


# --- GEO size: the divergence from geo.Geo.parse ----------------------------

def test_padded_geo_parses_in_geo_py_but_is_refused_by_size(tmp_path):
    folder = make_design(tmp_path / "out")
    good = (folder / "GEO001.DAT").read_bytes()
    padded = good + b"\x00"                     # 12963 bytes: odd-size pad
    # tools/geo.py accepts it...
    assert Geo.parse(padded) is not None
    # ...but jt198 requires exactly 12962, so the smoke refuses it.
    (folder / "GEO001.DAT").write_bytes(padded)
    report = smoke.validate_folder(folder)
    assert statuses(report)["geo-size:GEO001.DAT"] == "fail"
    assert statuses(report)["geo-parse:GEO001.DAT"] == "fail"
    assert report["verdict"] == "fail"


def test_truncated_geo_fails_size_without_crashing(tmp_path):
    folder = make_design(tmp_path / "out")
    (folder / "GEO001.DAT").write_bytes((folder / "GEO001.DAT").read_bytes()[:100])
    report = smoke.validate_folder(folder)
    assert statuses(report)["geo-size:GEO001.DAT"] == "fail"
    assert "not parsed" in next(c["detail"] for c in report["checks"]
                                if c["id"] == "geo-parse:GEO001.DAT")


# --- GEO container, version, dims, and magic (geo.Geo.parse) ----------------

def test_bad_version_fails_parse(tmp_path):
    folder = make_design(tmp_path / "out")
    g = Geo.blank(3, 3)
    g.version = 99                              # engine range is 100..106
    (folder / "GEO001.DAT").write_bytes(g.build())
    report = smoke.validate_folder(folder)
    assert statuses(report)["geo-size:GEO001.DAT"] == "pass"
    assert statuses(report)["geo-parse:GEO001.DAT"] == "fail"


def test_zero_dims_fails_parse(tmp_path):
    folder = make_design(tmp_path / "out")
    g = Geo.blank(3, 3)
    g.width = 0
    (folder / "GEO001.DAT").write_bytes(g.build())
    report = smoke.validate_folder(folder)
    assert statuses(report)["geo-parse:GEO001.DAT"] == "fail"


def test_non_iff_payload_is_refused(tmp_path):
    # L7226 would accept a non-IFF first long as raw legacy data. This tool does
    # not, because geo.Geo.parse refuses it; the report's limitations say so.
    folder = make_design(tmp_path / "out")
    (folder / "GEO001.DAT").write_bytes(b"\x00" * GEO_SIZE)
    report = smoke.validate_folder(folder)
    assert statuses(report)["geo-size:GEO001.DAT"] == "pass"
    assert statuses(report)["geo-parse:GEO001.DAT"] == "fail"
    assert any("raw legacy" in s for s in report["limitations"])


# --- area numbering and folder name -----------------------------------------

def test_area_above_255_is_not_addressable(tmp_path):
    # tools/dsn.py allows 1..999; jt127 can only address 0..255.
    folder = make_design(tmp_path / "out", extra_areas=(300,))
    report = smoke.validate_folder(folder)
    assert statuses(report)["geo-addressable:GEO300.DAT"] == "fail"
    assert report["verdict"] == "fail"


def test_folder_not_named_dsn_fails(tmp_path):
    folder = make_design(tmp_path / "out")
    renamed = folder.with_name("SMOKE")
    folder.rename(renamed)
    report = smoke.validate_folder(renamed)
    assert statuses(report)["design-folder-name"] == "fail"


# --- refusals and read-only behaviour ---------------------------------------

def test_not_a_directory_is_refused(tmp_path):
    with pytest.raises(smoke.SmokeRefusal):
        smoke.validate_folder(tmp_path / "nope.DSN")


def test_cli_refuses_missing_folder_with_exit_2(tmp_path, capsys):
    assert smoke.main([str(tmp_path / "nope.DSN")]) == 2


def test_report_inside_folder_is_refused(tmp_path):
    folder = make_design(tmp_path / "out")
    before = snapshot(folder)
    rc = smoke.main([str(folder), "--report", str(folder / "r.json")])
    assert rc == 2
    assert snapshot(folder) == before           # nothing written into the folder


def test_validator_does_not_modify_the_folder(tmp_path):
    folder = make_design(tmp_path / "out")
    (folder / "GEO001.DAT").write_bytes(b"\x00" * 100)   # a failing folder too
    before = snapshot(folder)
    smoke.validate_folder(folder)
    assert snapshot(folder) == before
    assert sorted(p.name for p in folder.iterdir()) == sorted(before)


def test_cli_end_to_end_and_deterministic_report(tmp_path):
    folder = make_design(tmp_path / "out")
    r1, r2 = tmp_path / "r1.json", tmp_path / "r2.json"
    for out in (r1, r2):
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(folder), "--report", str(out)],
            capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "engine NOT run" in proc.stdout
    assert r1.read_bytes() == r2.read_bytes()
    report = json.loads(r1.read_text(encoding="utf-8"))
    assert report["verdict"] == "pass"
    assert str(tmp_path) not in r1.read_text(encoding="utf-8")   # no absolute paths


def test_cli_exit_1_on_failing_design(tmp_path):
    folder = make_design(tmp_path / "out")
    (folder / "GEO001.DAT").unlink()
    proc = subprocess.run([sys.executable, str(TOOL), str(folder)],
                          capture_output=True, text=True)
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout
