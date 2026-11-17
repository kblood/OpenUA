"""Tests for tools/areatest_modal_census.py (synthetic run directories).

The census is read-only; these tests build tiny run directories under
tmp_path that mimic a bounded FRUA_AREATEST Hatari run, then check the
verdict and the evidence fields. One optional test reads a real staged run
under data/work when it exists (skipped otherwise; data/ is git-ignored).
"""
import importlib.util
import os
import struct

import pytest

HERE = os.path.dirname(__file__)
TOOL = os.path.join(HERE, "..", "tools", "areatest_modal_census.py")

_spec = importlib.util.spec_from_file_location("areatest_modal_census", TOOL)
census_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(census_mod)

# The run-b build stamp's EXTRA_CFLAGS, recorded in
# data/work/por-openua-areatest-build-20261117/.machine (probe0, x1935877434).
RUN_B_FLAGS = "-DFRUA_AREATEST -DFRUA_SKIP_ENTRY_EVENTS -DFRUA_ENGINE_PROBE"
RUN_B_CKSUM = 1935877434


def _frsc(path, types):
    """Write a FRSC archive holding one empty resource per 4-char type."""
    entries = b""
    for i, t in enumerate(types):
        entries += struct.pack(">4shHII", t.encode("ascii"), i, 0, 0, 0)
    header = struct.pack(">4sHHII", b"FRSC", 1, len(types), 16, 0)
    with open(path, "wb") as f:
        f.write(header + entries)


def _run_dir(tmp_path, dbg_lines, design="TGALLMAP.DSN", geo=("GEO001.DAT",),
             rsc_types=("STRS",)):
    run = tmp_path / "run"
    run.mkdir()
    (run / "DBG.LOG").write_bytes(("\r\n".join(dbg_lines) + "\r\n").encode("latin-1"))
    name = design.encode("latin-1").ljust(34, b"\0") + b"\x01"
    (run / "start.dat").write_bytes(name)
    ddir = run / design
    ddir.mkdir()
    for g in geo:
        (ddir / g).write_bytes(b"FORM")
    _frsc(str(run / "frua.rsc"), list(rsc_types))
    return run


PROBE_BOOT = [
    "stub: jt1143",
    "stub: l0444",
    "stub: jt398",
    "jt398: open refnum = 64",
    "stub: jt127",
    "L2856 self-test: ret-base = 48",
    "stub: jt127",
    "stub: jt398",
    "jt398: open refnum = -1",
    "stub: jt464",
    "stub: L036a",
    "ERRMODAL: Group 19 in use for ''",
]


def test_posix_cksum_matches_stamp_and_empty_vector():
    # POSIX cksum of the empty input is 4294967295 (all-ones complement).
    assert census_mod.posix_cksum(b"") == 4294967295
    # Same value the Makefile puts in the run-b build stamp (-x1935877434).
    assert census_mod.posix_cksum(RUN_B_FLAGS.encode()) == RUN_B_CKSUM


def test_probe_geo040_verdict_when_design_lacks_geo040(tmp_path):
    run = _run_dir(tmp_path, PROBE_BOOT)
    info = census_mod.census(str(run))
    assert info["modal"]["line"] == 12
    assert info["modal"]["match"] is True
    assert info["marker_count_before_modal"] == 0
    assert info["probe_selftests_ran"]["L2856 self-test"] is True
    # The completion marker is never logged when the GEO040 read blocks.
    assert info["probe_selftests_ran"]["jt127 self-test"] is False
    assert info["design_has_geo040"] is False
    assert info["replay_resources_present"] is False
    assert info["verdict"].startswith("PROBE_GEO040_SELFTEST")


def test_start_dat_without_dsn_suffix_is_design_name_missing(tmp_path):
    # Run-a shape: start.dat names 'TGALLMAP' while the folder is TGALLMAP.DSN.
    run = _run_dir(tmp_path, PROBE_BOOT, design="TGALLMAP.DSN")
    (run / "start.dat").write_bytes(b"TGALLMAP".ljust(34, b"\0") + b"\x01")
    info = census_mod.census(str(run))
    assert info["start_design"] == "TGALLMAP"
    assert info["design_dir_present"] is False
    assert info["design_dir_with_dsn"] is True
    assert info["verdict"].startswith("DESIGN_NAME_MISSING")


def test_flood_stub_form_detected_by_repeated_names(tmp_path):
    run = _run_dir(tmp_path, PROBE_BOOT)
    info = census_mod.census(str(run))
    # stub: jt398 and stub: jt127 each appear twice in PROBE_BOOT.
    assert info["stub_unique"] < info["stub_lines"]
    assert info["stub_form"].startswith("flood")


def test_marker_before_modal_changes_verdict(tmp_path):
    lines = ["stub: jt361"] + PROBE_BOOT
    run = _run_dir(tmp_path, lines)
    info = census_mod.census(str(run))
    assert info["marker_count_before_modal"] == 1
    assert info["verdict"].startswith("MODAL_AFTER_MARKERS")


def test_geo040_present_does_not_claim_probe_cause(tmp_path):
    run = _run_dir(tmp_path, PROBE_BOOT, geo=("GEO001.DAT", "GEO040.DAT"))
    info = census_mod.census(str(run))
    assert info["design_has_geo040"] is True
    assert not info["verdict"].startswith("PROBE_GEO040_SELFTEST")


def test_replay_resources_detected_when_all_three_present(tmp_path):
    run = _run_dir(tmp_path, PROBE_BOOT, rsc_types=("STRS", "DATA", "ZERO", "DREL"))
    info = census_mod.census(str(run))
    assert info["replay_resources_present"] is True
    assert info["frsc_types"] == ["DATA", "DREL", "STRS", "ZERO"]


def test_no_modal_verdict(tmp_path):
    run = _run_dir(tmp_path, ["stub: jt361", "stub: jt198"])
    info = census_mod.census(str(run))
    assert info["modal"] is None
    assert info["verdict"].startswith("NO_MODAL")


def test_successful_geo_parse_markers_report_level_and_dimensions(tmp_path):
    run = _run_dir(tmp_path, [
        "== GEO level1", "   width(ds2)16", "   height(ds3)16",
        "   zone: norest*1000+event0",
        "== GEO level2", "   width(ds2)24", "   height(ds3)18",
    ])
    info = census_mod.census(str(run))
    assert info["successful_geo_parses"] == [
        {"line": 1, "level": 1, "width": 16, "height": 16},
        {"line": 5, "level": 2, "width": 24, "height": 18},
    ]
    assert info["marker_count_before_modal"] == 2
    assert info["verdict"].startswith("GEO_PARSE_REACHED")


def test_missing_dbg_log_reports_nothing_to_classify(tmp_path):
    info = census_mod.census(str(tmp_path))
    assert info["dbg_log"] is False
    assert info["verdict"].startswith("NO_DBG_LOG")


def test_build_stamp_cksum_match(tmp_path):
    run = _run_dir(tmp_path, PROBE_BOOT)
    build = tmp_path / "build"
    build.mkdir()
    (build / ".machine").write_text(
        "falcon-68000-nofpu-1-planar1-probe0-x%d\n" % RUN_B_CKSUM)
    info = census_mod.census(str(run), str(build), RUN_B_FLAGS)
    assert info["extra_cflags_match"] is True
    other = census_mod.census(str(run), str(build), "-DFRUA_AREATEST")
    assert other["extra_cflags_match"] is False


def test_render_contains_verdict_and_modal_line(tmp_path):
    run = _run_dir(tmp_path, PROBE_BOOT)
    text = census_mod.render(census_mod.census(str(run)))
    assert "PROBE_GEO040_SELFTEST" in text
    assert "DBG.LOG line 12" in text


def test_render_reports_successful_geo_parse(tmp_path):
    run = _run_dir(tmp_path, ["== GEO level1", "   width(ds2)16", "   height(ds3)16"])
    text = census_mod.render(census_mod.census(str(run)))
    assert "GEO_PARSE_REACHED" in text
    assert "'width': 16" in text
    assert "'height': 16" in text


@pytest.mark.skipif(
    not os.path.isdir(os.path.join(HERE, "..", "data", "work",
                                   "por-openua-areatest-20261117b")),
    reason="staged run directory not present (data/ is git-ignored)")
def test_real_run_b_is_classified_as_probe_geo040():
    run = os.path.join(HERE, "..", "data", "work", "por-openua-areatest-20261117b")
    info = census_mod.census(run)
    assert info["start_design"] == "TGALLMAP.DSN"
    assert info["modal"]["line"] == 412
    assert info["design_has_geo040"] is False
    assert info["verdict"].startswith("PROBE_GEO040_SELFTEST")


@pytest.mark.skipif(
    not os.path.isdir(os.path.join(HERE, "..", "data", "work",
                                   "por-openua-areatest-20261117a")),
    reason="staged run directory not present (data/ is git-ignored)")
def test_real_run_a_is_classified_as_design_name_missing():
    run = os.path.join(HERE, "..", "data", "work", "por-openua-areatest-20261117a")
    info = census_mod.census(run)
    assert info["start_design"] == "TGALLMAP"
    assert info["modal"]["line"] == 43
    assert info["verdict"].startswith("DESIGN_NAME_MISSING")
