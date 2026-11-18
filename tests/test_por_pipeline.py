"""Tests for tools/por_pipeline.py (one repeatable run over a PoR install).

Synthetic fixtures only, except the retail anchor, which runs only when the
local install is present and is skipped otherwise. Fixture writers come from
test_por_map.py, so the DAX/GEO layout is the one that file pins.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, TESTS)
import por_pipeline as pp  # noqa: E402
import por_dsn_load_smoke as pls  # noqa: E402
import por_ecl_text_diagnostic as ptd  # noqa: E402
from test_por_map import geo_raw, make_dax, _fixture_cells  # noqa: E402
from test_por_ecl_strings import ecl_block, ins, strop, lit, EXIT, full_archives  # noqa: E402

RETAIL = Path("G:/Games/Pool of Radiance")
ECL_NAMES = ["ECL%d.DAX" % n for n in range(1, 9)]


def _ecl_string_block() -> bytes:
    """A complete synthetic ECL block with two inline strings (both framings walk it)."""
    return ecl_block(ins(0x11, strop(b"\x01\x02")) + ins(0x0F, lit(0), strop(b"zz")) + EXIT)


def make_full_install(root: Path, *, geo_blocks=None, sub="POOLRAD", ecl=False) -> Path:
    """All eight GEO archives, GAME.OVR and START.EXE, GOG layout.
    ``ecl=True`` also writes ECL1..ECL8.DAX next to them (default: absent)."""
    install = root / "install"
    folder = install / sub if sub else install
    folder.mkdir(parents=True)
    for n in range(1, 9):
        blocks = (geo_blocks or {}).get(n, [(18 + n, geo_raw(_fixture_cells))])
        (folder / ("GEO%d.DAX" % n)).write_bytes(make_dax(blocks))
    (folder / "GAME.OVR").write_bytes(b"synthetic overlay\x00" * 4)
    (folder / "START.EXE").write_bytes(b"synthetic start\x00" * 4)
    if ecl:
        for name, data in full_archives(_ecl_string_block()).items():
            (folder / name).write_bytes(data)
    return install


def _plan(tmp: Path, designs, *, schema=pp.PLAN_SCHEMA, version=pp.PLAN_VERSION) -> Path:
    p = tmp / "plan.json"
    p.write_text(json.dumps({"schema": schema, "version": version,
                             "designs": designs}), encoding="utf-8")
    return p


def _good_design(**over):
    d = {"name": "PORMAP", "geo": 2, "index": 0, "area": 5,
         "entry": [3, 5], "facing": "east", "title": "synthetic"}
    d.update(over)
    return d


def _tree(root: Path) -> dict:
    out = {}
    for dirpath, _d, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


# ---- happy path ------------------------------------------------------------

def test_full_run_decodes_every_block_and_round_trips_design(tmp_path):
    install = make_full_install(tmp_path)
    plan = _plan(tmp_path, [_good_design()])
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, plan)
    assert code == 0
    s = manifest["summary"]
    assert s["blocks_total"] == 8 and s["blocks_decoded"] == 8
    assert s["designs_ok"] == 1 and s["designs_failed"] == 0
    assert manifest["playable"] is False
    assert manifest["install"]["unchanged"] is True
    assert any("one cited PoR DOS route reports a flag-2 locked door" in item
               and "GEO-to-reader binding and general flag-2 rule remain unproven" in item
               and "Flag 3 is a CoK/other-title hypothesis" in item
               for item in manifest["unsupported"])
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "one cited PoR DOS route reports a flag-2 locked door" in report
    assert "GEO-to-reader binding and general flag-2 rule remain unproven" in report
    d = manifest["designs"][0]
    assert d["checks"] == {"parses": True, "byte_round_trip": True, "entry_point": True}
    assert (out / "por_pipeline.json").is_file()
    assert (out / "por_pipeline_report.md").is_file()
    assert (out / "designs" / "PORMAP" / "PORMAP.DSN" / "GEO005.DAT").is_file()


def test_relative_output_path_publishes_and_cleans_staging(tmp_path, monkeypatch):
    # Python 3.12+ normalizes tempfile.mkdtemp's relative dir to an absolute path.
    install = make_full_install(tmp_path)
    plan = _plan(tmp_path, [_good_design()])
    monkeypatch.chdir(tmp_path)

    manifest, code = pp.run(install, Path("relative-out"), plan)

    assert code == 0
    assert manifest["summary"]["blocks_decoded"] == 8
    assert (tmp_path / "relative-out" / "por_pipeline.json").is_file()
    assert _staging_left(tmp_path) == []


def test_run_is_deterministic_and_leaks_no_paths(tmp_path):
    install = make_full_install(tmp_path)
    plan = _plan(tmp_path, [_good_design()])
    pp.run(install, tmp_path / "a", plan)
    pp.run(install, tmp_path / "b", plan)
    a = (tmp_path / "a" / "por_pipeline.json").read_bytes()
    b = (tmp_path / "b" / "por_pipeline.json").read_bytes()
    assert a == b
    text = a.decode("utf-8")
    assert str(tmp_path) not in text
    assert str(tmp_path).replace("\\", "/") not in text
    assert ":/" not in text and ":\\" not in text  # no drive-letter paths


def test_install_is_never_written(tmp_path):
    install = make_full_install(tmp_path)
    before = _tree(install)
    pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]))
    assert _tree(install) == before


def test_no_plan_means_no_designs_but_blocks_still_decoded(tmp_path):
    install = make_full_install(tmp_path)
    manifest, code = pp.run(install, tmp_path / "out", None)
    assert code == 0
    assert manifest["designs"] == []
    assert manifest["summary"]["blocks_decoded"] == 8
    assert manifest["plan"] == {"sha256": None, "designs": 0}


def test_flat_install_layout_without_poolrad(tmp_path):
    install = make_full_install(tmp_path, sub=None)
    manifest, code = pp.run(install, tmp_path / "out", None)
    assert code == 0 and manifest["summary"]["blocks_decoded"] == 8


# ---- degraded runs: recorded, exit 1 ----------------------------------------

def test_refused_block_is_recorded_and_run_continues(tmp_path):
    bad = [(40, b"\x00" * 4)]  # not a 1026-byte GEO block: the decoder refuses it
    install = make_full_install(tmp_path, geo_blocks={3: bad})
    manifest, code = pp.run(install, tmp_path / "out", None)
    assert code == 1
    refused = [b for b in manifest["blocks"] if b["status"] == "refused"]
    assert len(refused) == 1 and refused[0]["geo"] == 3
    assert refused[0]["reason"]
    assert manifest["summary"]["blocks_decoded"] == 7


def test_design_round_trip_failure_is_reported_not_hidden(tmp_path, monkeypatch):
    install = make_full_install(tmp_path)
    monkeypatch.setattr(pp, "_round_trip",
                        lambda dsn, entry, facing: {"parses": True,
                                                    "byte_round_trip": False,
                                                    "entry_point": True})
    manifest, code = pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]))
    assert code == 1
    assert manifest["designs"][0]["status"] == "failed"


def test_entry_point_is_checked_against_the_plan(tmp_path):
    install = make_full_install(tmp_path)
    manifest, _ = pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]))
    assert manifest["designs"][0]["entry"] == {"x": 3, "y": 5, "facing": "east"}
    assert manifest["designs"][0]["checks"]["entry_point"] is True


# ---- refusals: exit 2 --------------------------------------------------------

@pytest.mark.parametrize("bad, msg", [
    ({"schema": "nope"}, "plan schema"),
    ({"version": 9}, "plan version"),
    ({"designs": "x"}, "must be a list"),
])
def test_plan_envelope_refusals(tmp_path, bad, msg):
    install = make_full_install(tmp_path)
    body = {"schema": pp.PLAN_SCHEMA, "version": pp.PLAN_VERSION, "designs": []}
    body.update(bad)
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(pp.PorPipelineError, match=msg):
        pp.run(install, tmp_path / "out", p)


@pytest.mark.parametrize("over, msg", [
    ({"name": "toolongname9"}, "name"),
    ({"name": "bad name"}, "name"),
    ({"geo": 9}, "geo"),
    ({"index": -1}, "index"),
    ({"area": 0}, "area"),
    ({"entry": [16, 0]}, "entry"),
    ({"entry": [1]}, "entry"),
    ({"facing": "up"}, "facing"),
    ({"title": 5}, "title"),
])
def test_plan_design_field_refusals(tmp_path, over, msg):
    install = make_full_install(tmp_path)
    with pytest.raises(pp.PorPipelineError, match=msg):
        pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design(**over)]))


def test_duplicate_design_name_refused(tmp_path):
    install = make_full_install(tmp_path)
    plan = _plan(tmp_path, [_good_design(), _good_design()])
    with pytest.raises(pp.PorPipelineError, match="repeats"):
        pp.run(install, tmp_path / "out", plan)


def test_missing_member_refused(tmp_path):
    install = make_full_install(tmp_path)
    (install / "POOLRAD" / "GEO6.DAX").unlink()
    with pytest.raises(pp.PorPipelineError, match="GEO6.DAX"):
        pp.run(install, tmp_path / "out", None)


def test_output_inside_install_refused(tmp_path):
    from por_convert import PorSourceError
    install = make_full_install(tmp_path)
    with pytest.raises(PorSourceError):
        pp.run(install, install / "POOLRAD" / "out", None)


def test_output_in_repo_outside_data_refused(tmp_path):
    from por_convert import PorSourceError
    install = make_full_install(tmp_path)
    repo_tools = Path(pp.__file__).resolve().parent.parent / "docs" / "por-x-test"
    with pytest.raises(PorSourceError):
        pp.run(install, repo_tools, None)


def test_cli_exit_codes(tmp_path, capsys):
    install = make_full_install(tmp_path)
    assert pp.main(["--install", str(install), "-o", str(tmp_path / "ok")]) == 0
    assert pp.main(["--install", str(tmp_path / "nope"), "-o", str(tmp_path / "x")]) == 2
    err = capsys.readouterr().err
    assert "install folder not found" in err


# ---- retail anchor: runs only with the local GOG install ----------------------

@pytest.mark.skipif(not (RETAIL / "POOLRAD").is_dir(),
                    reason="local PoR retail install not present")
def test_retail_anchor(tmp_path):
    plan = _plan(tmp_path, [_good_design(geo=2, index=2, entry=[13, 8],
                                         facing="east", area=5)])
    manifest, code = pp.run(RETAIL, tmp_path / "retail", plan)
    assert code == 0
    assert manifest["summary"]["blocks_total"] == 29
    assert manifest["summary"]["blocks_decoded"] == 29
    assert manifest["designs"][0]["status"] == "ok"


# ---- optional ECL text stage (--with-ecl-text) -------------------------------
# The census and the diagnostic are read-only over the install and write only
# under OUT/ecl-census and OUT/ecl-text-diagnostic. Nothing here accepts a string.

ECL_DIRS = ("ecl-census", "ecl-text-diagnostic")


def _ecl_listing(out: Path) -> list:
    """Sorted POSIX paths of every file under the two ECL output folders."""
    rels = []
    for sub in ECL_DIRS:
        base = out / sub
        if base.is_dir():
            for dirpath, _d, files in os.walk(base):
                for f in files:
                    rels.append((Path(dirpath) / f).relative_to(out).as_posix())
    return sorted(rels)


def test_ecl_text_disabled_is_map_only_and_writes_no_ecl(tmp_path):
    install = make_full_install(tmp_path, ecl=True)  # present, but not requested
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None)
    assert code == 0
    assert "ecl_text" not in manifest
    assert not any(k.startswith("ECL") for k in manifest["install"]["members"])
    assert _ecl_listing(out) == []
    assert "ECL" not in (out / "por_pipeline_report.md").read_text(encoding="utf-8")


def test_ecl_text_enabled_runs_census_and_diagnostic(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True)
    assert code == 0
    e = manifest["ecl_text"]
    assert e["status"] == "diagnostic-unaccepted" and e["playable"] is False
    assert e["census"]["status"] == "census-only" and e["census"]["exit"] == 0
    assert e["census"]["archives_present"] == 8
    assert e["diagnostic"]["status"] == "diagnostic-unaccepted"
    assert e["diagnostic"]["frames_total"] == sum(
        e["census"]["string_frames_by_framing"].values())
    assert e["diagnostic"]["frames_total"] > 0
    assert e["diagnostic"]["accepted_frames"] == 0
    assert _ecl_listing(out) == sorted([
        "ecl-census/por_ecl_strings.json", "ecl-census/por_ecl_strings_report.md",
        "ecl-text-diagnostic/%s" % ptd.OUT_JSON, "ecl-text-diagnostic/%s" % ptd.OUT_MD])


def test_ecl_text_manifest_hashes_match_the_written_files(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    manifest, _ = pp.run(install, out, None, with_ecl_text=True)
    e = manifest["ecl_text"]
    for section in ("census", "diagnostic"):
        rows = e[section]["files"]
        assert rows, section
        for row in rows:
            data = (out / row["path"]).read_bytes()
            assert row["bytes"] == len(data)
            assert row["sha256"] == hashlib.sha256(data).hexdigest()


def test_ecl_text_fingerprints_all_eight_archives(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    manifest, _ = pp.run(install, tmp_path / "out", None, with_ecl_text=True)
    members = manifest["install"]["members"]
    for name in ECL_NAMES:
        data = (install / "POOLRAD" / name).read_bytes()
        assert members[name] == {"sha256": hashlib.sha256(data).hexdigest(),
                                 "bytes": len(data)}


def test_ecl_text_missing_member_is_refused_and_writes_nothing(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    (install / "POOLRAD" / "ECL5.DAX").unlink()
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="ECL5.DAX"):
        pp.run(install, out, None, with_ecl_text=True)
    assert not out.exists()


def test_ecl_text_all_members_absent_is_refused(tmp_path):
    install = make_full_install(tmp_path, ecl=False)
    with pytest.raises(pp.PorPipelineError, match="ECL1.DAX"):
        pp.run(install, tmp_path / "out", None, with_ecl_text=True)


def test_missing_ecl_member_is_ignored_without_the_flag(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    (install / "POOLRAD" / "ECL5.DAX").unlink()
    manifest, code = pp.run(install, tmp_path / "out", None)
    assert code == 0 and "ecl_text" not in manifest


def test_changed_ecl_member_during_run_is_refused(tmp_path, monkeypatch):
    install = make_full_install(tmp_path, ecl=True)
    real_census = pp.ps.census

    def census_then_touch(inst, out):
        result = real_census(inst, out)
        (install / "POOLRAD" / "ECL3.DAX").write_bytes(b"changed mid-run")
        return result

    monkeypatch.setattr(pp.ps, "census", census_then_touch)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="install changed"):
        pp.run(install, out, None, with_ecl_text=True)
    assert not (out / "por_pipeline.json").exists()


def test_ecl_census_diagnostics_exit_1_and_are_still_diagnosed(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    (install / "POOLRAD" / "ECL2.DAX").write_bytes(b"\xff" * 64)  # container error
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True)
    assert code == 1
    e = manifest["ecl_text"]
    assert e["census"]["exit"] == 1 and e["census"]["diagnostics"] >= 1
    assert e["diagnostic"]["status"] == "diagnostic-unaccepted"
    assert (out / "ecl-text-diagnostic" / ptd.OUT_JSON).is_file()


def test_ecl_text_with_a_plan_keeps_the_map_results(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    manifest, code = pp.run(install, tmp_path / "out", plan, with_ecl_text=True)
    assert code == 0
    assert manifest["summary"]["designs_ok"] == 1
    assert manifest["summary"]["blocks_decoded"] == 8


def test_ecl_text_does_not_touch_designs(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    off, on = tmp_path / "off", tmp_path / "on"
    pp.run(install, off, plan)
    pp.run(install, on, plan, with_ecl_text=True)
    assert _tree(on / "designs") == _tree(off / "designs")
    for rel in _ecl_listing(on):
        assert not rel.upper().endswith(".DSN") and "STRG" not in rel.upper()
    assert not any("STRG" in p.name.upper() for p in on.rglob("*"))


def test_ecl_text_diagnostic_marks_every_frame_unaccepted(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    manifest, _ = pp.run(install, out, None, with_ecl_text=True)
    doc = json.loads((out / "ecl-text-diagnostic" / ptd.OUT_JSON).read_text(encoding="utf-8"))
    assert doc["schema"] == ptd.SCHEMA and doc["status"] == "diagnostic-unaccepted"
    assert doc["playable"] is False
    assert doc["frames"], "fixture should yield string frames"
    assert all(f["accepted"] is False and f["status"] == "diagnostic-unaccepted"
               for f in doc["frames"])
    codes = {u["code"] for u in doc["unresolved"]}
    assert codes == {"runtime-text-binding", "census-framing-speculative"}
    assert {u["code"] for u in manifest["ecl_text"]["unresolved"]} == codes
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "diagnostic-unaccepted" in report and "`playable: false`" in report


def test_ecl_text_outputs_are_deterministic_and_path_free(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    a, b = tmp_path / "a", tmp_path / "b"
    pp.run(install, a, plan, with_ecl_text=True)
    pp.run(install, b, plan, with_ecl_text=True)
    rels = _ecl_listing(a) + ["por_pipeline.json", "por_pipeline_report.md"]
    assert _ecl_listing(a) == _ecl_listing(b)
    for rel in rels:
        assert (a / rel).read_bytes() == (b / rel).read_bytes(), rel
        text = (a / rel).read_text(encoding="utf-8")
        assert str(tmp_path) not in text and tmp_path.as_posix() not in text, rel
        assert ":/" not in text and ":\\" not in text, rel


def test_ecl_text_install_source_is_never_written(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    before = _tree(install)
    pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]), with_ecl_text=True)
    assert _tree(install) == before


def test_ecl_text_flat_install_layout(tmp_path):
    install = make_full_install(tmp_path, sub=None, ecl=True)
    manifest, code = pp.run(install, tmp_path / "out", None, with_ecl_text=True)
    assert code == 0 and manifest["ecl_text"]["census"]["archives_present"] == 8


def test_cli_with_ecl_text_flag(tmp_path, capsys):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "ok"
    assert pp.main(["--install", str(install), "-o", str(out), "--with-ecl-text"]) == 0
    msg = capsys.readouterr().out
    assert "ECL text diagnostic-unaccepted, playable=false" in msg
    assert _ecl_listing(out)


def test_cli_with_ecl_text_missing_member_exits_2(tmp_path, capsys):
    install = make_full_install(tmp_path, ecl=True)
    (install / "POOLRAD" / "ECL8.DAX").unlink()
    code = pp.main(["--install", str(install), "-o", str(tmp_path / "x"), "--with-ecl-text"])
    assert code == 2
    assert "ECL8.DAX" in capsys.readouterr().err


# ---- retail gated anchor for the ECL stage: local GOG install only ----------

@pytest.mark.skipif(not (RETAIL / "POOLRAD" / "ECL1.DAX").is_file(),
                    reason="local PoR retail install with ECL archives not present")
def test_retail_ecl_text_anchor(tmp_path):
    manifest, code = pp.run(RETAIL, tmp_path / "retail", None, with_ecl_text=True)
    assert code == 0
    assert manifest["install"]["unchanged"] is True
    assert manifest["summary"]["blocks_decoded"] == 29
    e = manifest["ecl_text"]
    assert e["census"]["exit"] == 0 and e["census"]["archives_present"] == 8
    # Same census pins as tests/test_por_ecl_strings.py::test_retail_census_anchor.
    assert e["census"]["string_frames_by_framing"] == {"conservative": 185,
                                                       "spec-menus": 1656}
    assert e["diagnostic"]["frames_total"] == 185 + 1656
    assert e["diagnostic"]["accepted_frames"] == 0


# ---- staged publication: OUT is replaced only on a clean, unchanged run -------
# Every stage writes into a staging folder beside OUT. A mid-run change to the
# install is refused before anything is published, and no staging folder is left.

def _staging_left(parent: Path) -> list:
    return sorted(p.name for p in parent.iterdir() if p.name.startswith(pp.STAGE_PREFIX))


def _owned_tree(out: Path) -> dict:
    return {k: v for k, v in _tree(out).items() if k.split("/")[0] in pp.OWNED_OUTPUTS}


def _prior_run_with_sentinels(install: Path, out: Path, plan: Path) -> dict:
    """A finished run into OUT, then unrelated user files and a stale generated-looking
    folder added beside it. Returns the OUT tree as it stands before the next run."""
    pp.run(install, out, plan, with_ecl_text=True)
    (out / "sentinel.txt").write_bytes(b"user file, must survive\n")
    (out / "user").mkdir()
    (out / "user" / "notes.md").write_bytes(b"# my notes\n")
    stale = out / "maps" / "geo9-i99-b999"
    stale.mkdir(parents=True)
    (stale / "por_map.json").write_bytes(b'{"stale": true}\n')
    return _tree(out)


def test_mutation_during_map_stage_publishes_nothing(tmp_path, monkeypatch):
    install = make_full_install(tmp_path)
    real_blocks = pp.stage_blocks

    def blocks_then_touch(inst, staging, *rest):
        rows = real_blocks(inst, staging, *rest)
        (install / "POOLRAD" / "GEO3.DAX").write_bytes(b"changed during the map stage")
        return rows

    monkeypatch.setattr(pp, "stage_blocks", blocks_then_touch)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="install changed"):
        pp.run(install, out, _plan(tmp_path, [_good_design()]))
    assert not out.exists()
    assert _staging_left(tmp_path) == []


def test_mutation_during_ecl_stage_publishes_no_map_or_ecl_output(tmp_path, monkeypatch):
    install = make_full_install(tmp_path, ecl=True)
    real_census = pp.ps.census

    def census_then_touch(inst, out):
        result = real_census(inst, out)
        (install / "POOLRAD" / "ECL3.DAX").write_bytes(b"changed during the ECL stage")
        return result

    monkeypatch.setattr(pp.ps, "census", census_then_touch)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="install changed"):
        pp.run(install, out, _plan(tmp_path, [_good_design()]), with_ecl_text=True)
    assert not out.exists()
    assert _staging_left(tmp_path) == []


@pytest.mark.parametrize("stage", ["map", "ecl"])
def test_refusal_leaves_existing_out_byte_identical(tmp_path, monkeypatch, stage):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    out = tmp_path / "out"
    before = _prior_run_with_sentinels(install, out, plan)

    if stage == "map":
        real_blocks = pp.stage_blocks

        def mutate_blocks(inst, staging, *rest):
            rows = real_blocks(inst, staging, *rest)
            (install / "POOLRAD" / "GEO5.DAX").write_bytes(b"x" * 9)
            return rows
        monkeypatch.setattr(pp, "stage_blocks", mutate_blocks)
    else:
        real_census = pp.ps.census

        def mutate_census(inst, staging):
            result = real_census(inst, staging)
            (install / "POOLRAD" / "ECL6.DAX").write_bytes(b"x" * 9)
            return result
        monkeypatch.setattr(pp.ps, "census", mutate_census)

    with pytest.raises(pp.PorPipelineError, match="install changed"):
        pp.run(install, out, plan, with_ecl_text=True)
    assert _tree(out) == before
    assert _staging_left(tmp_path) == []


def test_successful_rerun_keeps_unrelated_files_and_matches_fresh_output(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    ref = tmp_path / "ref"
    pp.run(install, ref, plan, with_ecl_text=True)

    out = tmp_path / "out"
    before = _prior_run_with_sentinels(install, out, plan)
    (out / "por_pipeline.json").write_bytes(b"stale manifest")

    manifest, code = pp.run(install, out, plan, with_ecl_text=True)
    assert code == 0
    after = _tree(out)
    for rel in ("sentinel.txt", "user/notes.md"):
        assert after[rel] == before[rel]
    assert _owned_tree(out) == _owned_tree(ref)
    assert "maps/geo9-i99-b999/por_map.json" not in after  # stale generated entry replaced
    assert _staging_left(tmp_path) == []

    # a rerun into the same OUT is byte-identical again and keeps the sentinels
    pp.run(install, out, plan, with_ecl_text=True)
    assert _owned_tree(out) == _owned_tree(ref)
    assert _tree(out)["sentinel.txt"] == before["sentinel.txt"]


def test_rerun_without_ecl_removes_stale_ecl_outputs_only(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    out = tmp_path / "out"
    pp.run(install, out, plan, with_ecl_text=True)
    (out / "sentinel.txt").write_bytes(b"keep")
    assert _ecl_listing(out)
    pp.run(install, out, plan)
    assert _ecl_listing(out) == []
    assert (out / "sentinel.txt").read_bytes() == b"keep"
    assert "ecl_text" not in json.loads((out / "por_pipeline.json").read_text("utf-8"))


def test_publish_failure_rolls_back_to_previous_output(tmp_path, monkeypatch):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    out = tmp_path / "out"
    before = _prior_run_with_sentinels(install, out, plan)

    real_move = pp._move
    calls = {"n": 0}

    def fail_fourth(src, dst):
        calls["n"] += 1
        if calls["n"] == 4:
            raise OSError("simulated rename failure")
        real_move(src, dst)

    monkeypatch.setattr(pp, "_move", fail_fourth)
    with pytest.raises(pp.PorPipelineError, match="previous output restored"):
        pp.run(install, out, plan, with_ecl_text=True)
    assert _tree(out) == before
    assert _staging_left(tmp_path) == []


def test_failed_rollback_keeps_replaced_output_in_staging(tmp_path, monkeypatch):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    out = tmp_path / "out"
    pp.run(install, out, plan, with_ecl_text=True)

    real_move = pp._move
    state = {"n": 0, "failed": False}

    def flaky(src, dst):
        state["n"] += 1
        if state["n"] == 4:
            state["failed"] = True
            raise OSError("simulated rename failure")
        if state["failed"] and pp.REPLACED_DIR in Path(src).parts:
            raise OSError("simulated rollback failure")
        real_move(src, dst)

    monkeypatch.setattr(pp, "_move", flaky)
    with pytest.raises(pp.PorPipelineError, match="rollback failed"):
        pp.run(install, out, plan, with_ecl_text=True)
    kept = _staging_left(tmp_path)
    assert len(kept) == 1
    replaced = tmp_path / kept[0] / pp.REPLACED_DIR
    assert (replaced / "maps").is_dir() and (replaced / "designs").is_dir()


@pytest.mark.parametrize("target", ["stage_blocks", "stage_designs"])
def test_unexpected_error_removes_only_the_staging_folder(tmp_path, monkeypatch, target):
    install = make_full_install(tmp_path)
    parent = tmp_path / "made" / "here"           # created by the run: removed on failure
    out = parent / "out"

    def explode(*_a, **_k):
        raise RuntimeError("simulated stage crash")

    monkeypatch.setattr(pp, target, explode)
    with pytest.raises(RuntimeError, match="simulated stage crash"):
        pp.run(install, out, _plan(tmp_path, [_good_design()]))
    assert not out.exists()
    assert not (tmp_path / "made").exists()  # the run's own created folders are removed too


def test_refuses_output_path_that_is_a_file(tmp_path):
    install = make_full_install(tmp_path)
    target = tmp_path / "not-a-folder"
    target.write_bytes(b"precious")
    with pytest.raises(pp.PorPipelineError, match="not a folder"):
        pp.run(install, target, None)
    assert target.read_bytes() == b"precious"
    assert _staging_left(tmp_path) == []


# ---- multi-area (grouped) designs: MULTI-AREA, MAP-ONLY, playable=false -------
# One plan row with "areas" becomes one NAME.DSN folder holding one GEO per area.
# Synthetic fixtures only. Area 5 comes from GEO2 and area 6 from GEO3, so the two
# areas are different blocks. Nothing here is recovered from the install.

from geo import Geo  # noqa: E402

MULTI_OUT_FILES = {"GAME001.DAT", "GEO005.DAT", "GEO006.DAT"}


def _area(**over):
    a = {"geo": 2, "index": 0, "area": 5, "entry": [3, 5], "facing": "east"}
    a.update(over)
    return a


def _group(**over):
    g = {"name": "TWOAREA", "title": "two areas", "start_area": 5, "start_entry": 1,
         "areas": [_area(),
                   _area(geo=3, area=6, entry=[1, 2], facing="south")]}
    g.update(over)
    return g


def _group_area(i, **over):
    g = _group()
    g["areas"][i].update(over)
    return g


def _group_without(key, **over):
    g = _group(**over)
    del g[key]
    return g


def _group_area_without(i, key):
    g = _group()
    del g["areas"][i][key]
    return g


def test_two_area_design_is_one_folder_with_two_round_tripped_geos(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, _plan(tmp_path, [_group()]))
    assert code == 0
    assert manifest["playable"] is False
    assert manifest["summary"]["designs_planned"] == 1
    assert manifest["summary"]["designs_ok"] == 1
    (d,) = manifest["designs"]
    assert d["kind"] == pp.GROUP_KIND
    assert d["scope"] == "multi-area map-only"
    assert d["playable"] is False and d["status"] == "ok"
    assert d["start_area"] == 5 and d["start_entry"] == 1
    assert d["folder"] == "designs/TWOAREA/TWOAREA.DSN"
    assert d["checks"] == {"files_exact": True, "game001_bytes_match": True,
                           "game001_start_area": True, "game001_start_entry": True}
    assert [a["area"] for a in d["areas"]] == [5, 6]
    for a in d["areas"]:
        assert a["status"] == "ok"
        assert a["checks"] == {"parses": True, "byte_round_trip": True,
                               "entry_point": True, "file_equals_built": True}
    # Exactly one .DSN folder: GAME001 plus one GEO file per area.
    assert sorted(os.listdir(out / "designs" / "TWOAREA")) == ["TWOAREA.DSN"]
    dsn = out / "designs" / "TWOAREA" / "TWOAREA.DSN"
    assert {p.name for p in dsn.iterdir()} == MULTI_OUT_FILES
    # GAME001: start area byte 48, start entry byte 49 (1-based).
    game = (dsn / "GAME001.DAT").read_bytes()
    assert len(game) == 388 and game[48] == 5 and game[49] == 1
    # Each GEO reads back through OpenUA's loader; entry point is (row, col, facing).
    raw5 = (dsn / "GEO005.DAT").read_bytes()
    raw6 = (dsn / "GEO006.DAT").read_bytes()
    g5, g6 = Geo.parse(raw5), Geo.parse(raw6)
    assert g5.build() == raw5 and g6.build() == raw6
    assert g5.entry_point(0) == (3, 5, 2)     # row=x, col=y; entry [3,5], east
    assert g6.entry_point(0) == (1, 2, 4)     # row=x, col=y; entry [1,2], south
    # Standalone map reports are still written for every source block.
    assert len(list((out / "maps").iterdir())) == 8
    assert manifest["summary"]["blocks_decoded"] == 8


def test_grouped_area_geo_bytes_equal_the_flat_row_output(tmp_path):
    install = make_full_install(tmp_path)
    grouped_out = tmp_path / "grouped"
    flat_out = tmp_path / "flat"
    pp.run(install, grouped_out, _plan(tmp_path, [_group()]))
    flat_plan = _plan(tmp_path, [
        _good_design(name="AREA5", geo=2, index=0, area=5, entry=[3, 5], facing="east"),
        _good_design(name="AREA6", geo=3, index=0, area=6, entry=[1, 2], facing="south"),
    ])
    pp.run(install, flat_out, flat_plan)
    dsn = grouped_out / "designs" / "TWOAREA" / "TWOAREA.DSN"
    assert (dsn / "GEO005.DAT").read_bytes() == \
        (flat_out / "designs" / "AREA5" / "AREA5.DSN" / "GEO005.DAT").read_bytes()
    assert (dsn / "GEO006.DAT").read_bytes() == \
        (flat_out / "designs" / "AREA6" / "AREA6.DSN" / "GEO006.DAT").read_bytes()


def test_grouped_output_is_deterministic_and_install_is_unchanged(tmp_path):
    install = make_full_install(tmp_path)
    before = _tree(install)
    plan = _plan(tmp_path, [_group()])
    pp.run(install, tmp_path / "a", plan)
    pp.run(install, tmp_path / "b", plan)
    for name in ("por_pipeline.json", "por_pipeline_report.md"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
    assert _tree(tmp_path / "a" / "designs") == _tree(tmp_path / "b" / "designs")
    assert _tree(install) == before
    text = (tmp_path / "a" / "por_pipeline.json").read_text(encoding="utf-8")
    assert str(tmp_path).replace("\\", "/") not in text and ":\\" not in text


def test_grouped_design_invents_no_events_art_text_or_strg(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    manifest, _ = pp.run(install, out, _plan(tmp_path, [_group()]))
    assert manifest["playable"] is False
    (d,) = manifest["designs"]
    assert d["playable"] is False
    assert not any(k in d for k in ("events", "art", "text", "strg", "monsters", "shops"))
    # The design folder holds GAME001 and GEO files only: no STRG, art or event data.
    for name in os.listdir(out / "designs" / "TWOAREA" / "TWOAREA.DSN"):
        assert name == "GAME001.DAT" or name.startswith("GEO")
    names = [p.name.upper() for p in out.rglob("*") if p.is_file()]
    assert not any("STRG" in n or n.endswith(".STR") for n in names)
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "multi-area map-only" in report.lower() and "full-game" not in report.lower()
    assert "playable=false" in report


def test_flat_and_grouped_rows_share_one_plan(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, _plan(tmp_path, [_good_design(), _group()]))
    assert code == 0
    flat, grouped = manifest["designs"]
    assert "kind" not in flat and flat["status"] == "ok"
    assert flat["checks"] == {"parses": True, "byte_round_trip": True, "entry_point": True}
    assert grouped["kind"] == pp.GROUP_KIND and grouped["status"] == "ok"
    assert (out / "designs" / "PORMAP" / "PORMAP.DSN" / "GEO005.DAT").is_file()
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "## Designs" in report and "## Multi-area design TWOAREA" in report


def test_flat_only_plan_rows_keep_their_v0_fields(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    manifest, _ = pp.run(install, out, _plan(tmp_path, [_good_design()]))
    (d,) = manifest["designs"]
    assert set(d) == {"name", "geo", "index", "area", "entry", "status", "file", "checks",
                      "loader_equivalent"}
    assert "Multi-area" not in (out / "por_pipeline_report.md").read_text(encoding="utf-8")


# ---- grouped plan validation: refused before anything is written -------------

@pytest.mark.parametrize("plan_design, msg", [
    (_group(areas=[]), "non-empty"),
    (_group(areas="x"), "non-empty"),
    (_group(areas=["x"]), "must be an object"),
    (_group_area_without(0, "facing"), "missing facing"),
    (_group_area_without(1, "entry"), "missing entry"),
    (_group_area(0, events=[1]), "unknown key"),
    (_group_area(0, geo=9), "geo"),
    (_group_area(0, index=-1), "index"),
    (_group_area(0, area=0), "area"),
    (_group_area(0, area=1000), "area"),
    (_group_area(0, entry=[16, 0]), "entry"),
    (_group_area(0, facing="up"), "facing"),
    (_group(geo=2), "mixes"),
    (_group(index=0), "mixes"),
    (_group(titel="typo"), "unknown key"),
    (_group(title=5), "title"),
    (_group(start_entry=2), "start_entry must be 1"),
    (_group(start_entry=True), "start_entry must be 1"),
    (_group_without("start_entry"), "missing start_entry"),
    (_group_without("start_area"), "missing start_area"),
    (_group(start_area=9), "not one of"),
])
def test_malformed_group_is_refused_and_writes_nothing(tmp_path, plan_design, msg):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match=msg):
        pp.run(install, out, _plan(tmp_path, [plan_design]))
    assert not out.exists()


def test_duplicate_area_number_in_a_design_is_refused(tmp_path):
    install = make_full_install(tmp_path)
    bad = _group_area(1, area=5)
    with pytest.raises(pp.PorPipelineError, match="repeats within design"):
        pp.run(install, tmp_path / "out", _plan(tmp_path, [bad]))


def test_duplicate_block_reference_in_a_design_is_refused(tmp_path):
    install = make_full_install(tmp_path)
    bad = _group_area(1, geo=2, index=0, area=6)        # same GEO2 index 0 as area 5
    with pytest.raises(pp.PorPipelineError, match="used twice"):
        pp.run(install, tmp_path / "out", _plan(tmp_path, [bad]))


def test_missing_start_area_is_refused(tmp_path):
    install = make_full_install(tmp_path)
    bad = _group(start_area=7)                           # areas are 5 and 6
    with pytest.raises(pp.PorPipelineError, match="start_area 7 is not one of"):
        pp.run(install, tmp_path / "out", _plan(tmp_path, [bad]))


def test_group_name_repeating_a_flat_row_is_refused(tmp_path):
    install = make_full_install(tmp_path)
    plan = _plan(tmp_path, [_good_design(name="TWOAREA"), _group()])
    with pytest.raises(pp.PorPipelineError, match="repeats"):
        pp.run(install, tmp_path / "out", plan)


def test_group_with_unknown_toc_index_is_refused_and_writes_no_folder(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    bad = _group_area(1, index=99)                       # GEO3 has one block
    manifest, code = pp.run(install, out, _plan(tmp_path, [bad]))
    assert code == 1
    (d,) = manifest["designs"]
    assert d["status"] == "refused" and "1 of 2 areas refused" in d["reason"]
    statuses = {a["area"]: a["status"] for a in d["areas"]}
    assert statuses == {5: "decoded", 6: "refused"}
    assert "out of range" in d["areas"][1]["reason"]
    assert not (out / "designs" / "TWOAREA").exists()
    assert manifest["summary"]["designs_failed"] == 1
    assert "Refused: 1 of 2 areas refused" in (out / "por_pipeline_report.md").read_text(
        encoding="utf-8")


# ---- loader-equivalent host checks (tools/por_dsn_load_smoke.py) -------------
# The pipeline delegates to validate_folder. These tests pin the wiring: every
# emitted DSN is checked, a loader failure fails the design, an area above the
# engine's 0..255 range is a design failure, and nothing claims a runtime load.

def _fake_loader(verdict, failed_ids=()):
    """A stand-in validate_folder: same report shape, forced verdict."""
    def fake(folder):
        return {"verdict": verdict, "start_area": 5, "start_entry": 1,
                "runtime_loaded": False, "engine_executed": False,
                "checks": [{"id": i, "status": "fail", "detail": "forced",
                            "source": "test"} for i in failed_ids]}
    return fake


def test_flat_design_gets_a_loader_equivalent_pass(tmp_path):
    install = make_full_install(tmp_path)
    manifest, code = pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]))
    assert code == 0
    (d,) = manifest["designs"]
    le = d["loader_equivalent"]
    assert d["status"] == "ok" and le["verdict"] == "pass" and le["failed"] == []
    assert le["engine_area_max"] == 255 and le["areas_above_engine_range"] == []
    assert le["runtime_loaded"] is False and le["engine_executed"] is False
    ids = {c["id"]: c["status"] for c in le["checks"]}
    assert ids["design-folder-name"] == "pass"
    assert ids["geo-addressable:GEO005.DAT"] == "pass"
    assert ids["geo-parse:GEO005.DAT"] == "pass"
    assert all(c["status"] == "pass" for c in le["checks"])
    assert manifest["summary"]["designs_loader_passed"] == 1


def test_group_gets_a_loader_equivalent_pass_over_its_whole_folder(tmp_path):
    install = make_full_install(tmp_path)
    manifest, code = pp.run(install, tmp_path / "out", _plan(tmp_path, [_group()]))
    assert code == 0
    (d,) = manifest["designs"]
    le = d["loader_equivalent"]
    assert d["status"] == "ok" and le["verdict"] == "pass"
    ids = {c["id"] for c in le["checks"]}
    assert {"geo-addressable:GEO005.DAT", "geo-addressable:GEO006.DAT",
            "geo-size:GEO006.DAT", "start-geo-present"} <= ids
    assert le["start_area"] == 5 and le["start_entry"] == 1


def test_area_above_engine_range_is_a_design_failure_not_accepted(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, _plan(tmp_path, [_good_design(area=300)]))
    assert code == 1
    (d,) = manifest["designs"]
    le = d["loader_equivalent"]
    assert d["status"] == "failed" and le["verdict"] == "fail"
    assert "geo-addressable:GEO300.DAT" in le["failed"]
    assert le["areas_above_engine_range"] == [300]
    assert manifest["summary"]["designs_failed"] == 1
    assert manifest["summary"]["designs_loader_passed"] == 0
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "areas above engine range 0..255: 300" in report
    assert "geo-addressable:GEO300.DAT" in report


def test_grouped_area_above_engine_range_fails_the_group(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    bad = _group_area(1, area=300)                       # start_area stays 5
    manifest, code = pp.run(install, out, _plan(tmp_path, [bad]))
    assert code == 1
    (d,) = manifest["designs"]
    assert d["status"] == "failed"
    assert d["loader_equivalent"]["verdict"] == "fail"
    assert d["loader_equivalent"]["failed"] == ["geo-addressable:GEO300.DAT"]
    assert d["loader_equivalent"]["areas_above_engine_range"] == [300]
    # A design failure, as for a round-trip failure: the folder is published.
    assert (out / "designs" / "TWOAREA" / "TWOAREA.DSN" / "GEO300.DAT").is_file()


def test_loader_failure_fails_a_design_whose_round_trip_passed(tmp_path, monkeypatch):
    install = make_full_install(tmp_path)
    monkeypatch.setattr(pls, "validate_folder", _fake_loader("fail", ["start-geo-present"]))
    manifest, code = pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]))
    assert code == 1
    (d,) = manifest["designs"]
    assert d["checks"] == {"parses": True, "byte_round_trip": True, "entry_point": True}
    assert d["status"] == "failed"
    assert d["loader_equivalent"]["failed"] == ["start-geo-present"]


def test_loader_refusal_is_recorded_and_fails_the_design(tmp_path, monkeypatch):
    install = make_full_install(tmp_path)

    def refuse(folder):
        raise pls.SmokeRefusal("not a directory: test")
    monkeypatch.setattr(pls, "validate_folder", refuse)
    manifest, code = pp.run(install, tmp_path / "out", _plan(tmp_path, [_good_design()]))
    assert code == 1
    (d,) = manifest["designs"]
    assert d["status"] == "failed"
    assert d["loader_equivalent"]["verdict"] == "refused"
    assert d["loader_equivalent"]["checks"] == [] and d["loader_equivalent"]["failed"] == []


def test_loader_check_is_read_only_and_runs_before_publish(tmp_path, monkeypatch):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    seen = []
    real = pls.validate_folder

    def spy(folder):
        # Runs on the staged copy (never on OUT), and must not write into it.
        assert not out.exists()
        assert any(p.name.startswith(pp.STAGE_PREFIX) for p in folder.parents)
        before = _tree(folder)
        report = real(folder)
        assert _tree(folder) == before
        seen.append(folder.name)
        return report
    monkeypatch.setattr(pls, "validate_folder", spy)
    pp.run(install, out, _plan(tmp_path, [_good_design()]))
    assert seen == ["PORMAP.DSN"]


def test_loader_section_is_deterministic_and_path_free(tmp_path):
    install = make_full_install(tmp_path)
    plan = _plan(tmp_path, [_good_design(), _group()])
    m1, _ = pp.run(install, tmp_path / "a", plan)
    m2, _ = pp.run(install, tmp_path / "b", plan)
    assert [d["loader_equivalent"] for d in m1["designs"]] == \
        [d["loader_equivalent"] for d in m2["designs"]]
    text = json.dumps(m1["designs"], sort_keys=True)
    assert str(tmp_path) not in text and "\\" not in text


def test_engine_is_never_claimed_as_run_or_loaded(tmp_path):
    install = make_full_install(tmp_path)
    out = tmp_path / "out"
    manifest, _ = pp.run(install, out, _plan(tmp_path, [_good_design(), _group()]))
    assert manifest["playable"] is False
    for d in manifest["designs"]:
        assert d["loader_equivalent"]["runtime_loaded"] is False
        assert d["loader_equivalent"]["engine_executed"] is False
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "engine NOT run" in report
    assert "Loader-equivalent checks (tools/por_dsn_load_smoke.py) are host readings" in report


# ---- opt-in ECL 0x80 candidate strings (--por-decode-strings) ----------------
# Synthetic ECL blocks only. Every record and the section must say accepted:false,
# runtime_verified:false, playable:false. Incomplete walks are never absences.

CAND_DIR = "ecl-candidate-strings"
CAND_JSON = "por_ecl_candidate_strings.json"
CAND_MD = "por_ecl_candidate_strings_report.md"

# Pinned from the PRE-CHANGE pipeline (HEAD 97e5d8ec, before this feature) over the
# synthetic fixture used below. Any change to the default or --with-ecl-text output fails.
PRE_CHANGE_GOLDEN = {
    "map-only": {"json": "e39b88868f76519280be1f7163645d4d115ab5e1055e5bdef072156cfda20631",
                 "report": "4baa581135b83f3d5f8b52e42b67d0dce49b0d37515c4784846d6e833b1bdc88",
                 "tree": "7ff8055cf31aa832b77909f789c01a227a4790cdd7780a29b79e6001c5a33c52"},
    "ecl-text": {"json": "8e941c2a73ba46c73102eb0759e0b355edbef87dee06471209e3b572629aac03",
                 "report": "75712d8ccee1335f64be619ac00aa7908912e5c3373e049b711f962fc7501bbe",
                 "tree": "74d7f36943322c11133804cea41836352fa6a28cc5c9ec29817daad0bfd33c91"},
}


def _golden_hashes(out: Path) -> dict:
    return {
        "json": hashlib.sha256((out / "por_pipeline.json").read_bytes()).hexdigest(),
        "report": hashlib.sha256((out / "por_pipeline_report.md").read_bytes()).hexdigest(),
        "tree": hashlib.sha256(json.dumps(_tree(out), sort_keys=True).encode()).hexdigest(),
    }


def _write_ecl(install: Path, n: int, data: bytes) -> None:
    """Replace ECL<n>.DAX in the POOLRAD folder with raw archive bytes."""
    (install / "POOLRAD" / ("ECL%d.DAX" % n)).write_bytes(data)


def _write_block(install: Path, n: int, body: bytes) -> None:
    """A one-block ECL<n>.DAX whose ECL block is ``body`` after the 22-byte header."""
    _write_ecl(install, n, make_dax([(18, ecl_block(body))]))


def _cand_doc(out: Path) -> dict:
    return json.loads((out / CAND_DIR / CAND_JSON).read_text(encoding="utf-8"))


def _cand_blocks(doc: dict, archive: str) -> list:
    return [b for b in doc["blocks"] if b["archive"] == archive]


def test_disabled_path_matches_pre_change_golden_outputs(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design(), _group()])
    default = tmp_path / "map-only"
    pp.run(install, default, plan)
    assert _golden_hashes(default) == PRE_CHANGE_GOLDEN["map-only"]
    ecl = tmp_path / "ecl-text"
    pp.run(install, ecl, plan, with_ecl_text=True)
    assert _golden_hashes(ecl) == PRE_CHANGE_GOLDEN["ecl-text"]


def test_flag_off_adds_no_candidate_section_or_folder(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True)
    assert code == 0
    assert "ecl_candidate_strings" not in manifest
    assert not (out / CAND_DIR).exists()
    assert "candidate" not in (out / "por_pipeline_report.md").read_text(encoding="utf-8").lower()


def test_enabled_run_adds_candidate_output_on_the_synthetic_fixture(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert code == 0
    c = manifest["ecl_candidate_strings"]
    assert c["status"] == "candidate-unaccepted"
    assert c["dir"] == CAND_DIR
    s = c["summary"]
    assert s["archives_read"] == 8 and s["blocks_decoded"] == 8 and s["read_errors"] == 0
    # Each fixture block is a complete walk with two 0x80 operands, in both framings.
    assert s["walks_complete"] == {"conservative": 8, "spec-menus": 8}
    assert s["walks_incomplete"] == {"conservative": 0, "spec-menus": 0}
    assert s["records_by_framing"] == {"conservative": 16, "spec-menus": 16}
    assert s["agreed_in_both_framings"] == 16
    assert s["framing_only"] == {"conservative": 0, "spec-menus": 0}
    assert sorted(os.listdir(out / CAND_DIR)) == sorted([CAND_JSON, CAND_MD])
    # Manifest hashes match the files on disk.
    for row in c["files"]:
        data = (out / row["path"]).read_bytes()
        assert row["bytes"] == len(data)
        assert row["sha256"] == hashlib.sha256(data).hexdigest()
    report = (out / "por_pipeline_report.md").read_text(encoding="utf-8")
    assert "ECL 0x80 candidate strings" in report and "`accepted: false`" in report


def test_every_record_and_the_section_are_unaccepted(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    manifest, _ = pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    doc = _cand_doc(out)
    assert doc["records"], "fixture should yield candidate records"
    for top in (doc, manifest["ecl_candidate_strings"]):
        assert top["accepted"] is False and top["runtime_verified"] is False
        assert top["playable"] is False
    for r in doc["records"]:
        assert r["accepted"] is False and r["runtime_verified"] is False and r["playable"] is False
        assert r["status"] in ("candidate", "empty", "refused")
        # provenance and limits travel with every record
        assert r["source"]["archive"] in ECL_NAMES and len(r["source"]["file_sha256"]) == 64
        assert r["source"]["decoded_sha256"] and r["evidence"]["level"] == "pinned-retail-static"
        assert r["limits"] and any("not accepted" in x for x in r["limits"])
    text = (out / CAND_DIR / CAND_JSON).read_text(encoding="utf-8")
    assert '"accepted": true' not in text and '"runtime_verified": true' not in text
    assert '"playable": true' not in text


def test_ambiguous_framing_is_shown_in_both_modes_not_chosen(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    # PRINT string, then a VERTICAL_MENU (0x15). Conservative stops at the menu; spec-menus
    # frames it (count 0) and reaches the INPUT string and EXIT.
    _write_block(install, 3, ins(0x11, strop(b"\x01\x02")) + ins(0x15, lit(0), lit(0), lit(0))
                 + ins(0x0F, lit(0), strop(b"zz")) + EXIT)
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert code == 0
    doc = _cand_doc(out)
    (b3,) = _cand_blocks(doc, "ECL3.DAX")
    cons, spec = b3["framings"]["conservative"], b3["framings"]["spec-menus"]
    assert cons["complete"] is False and cons["stop"]["kind"] == "ambiguous-framing"
    assert cons["stop"]["opcode"] == "0x15"
    assert spec["complete"] is True and spec["stop"]["kind"] == "end-of-block"
    assert b3["framing_comparison"] == {"both": 1, "conservative-only": 0, "spec-menus-only": 1}
    recs = [r for r in doc["records"] if r["archive"] == "ECL3.DAX"]
    prints = [r for r in recs if r["mnemonic"] == "PRINT"]
    inputs = [r for r in recs if r["mnemonic"] == "INPUT_NUMBER"]
    assert sorted(r["framing"] for r in prints) == ["conservative", "spec-menus"]
    for r in prints:
        other = "spec-menus" if r["framing"] == "conservative" else "conservative"
        assert r["also_in"] == [other]
    assert [r["framing"] for r in inputs] == ["spec-menus"]     # only where it is reached
    assert inputs[0]["also_in"] == []
    assert doc["summary"]["walks_incomplete"] == {"conservative": 1, "spec-menus": 0}
    assert doc["summary"]["framing_only"] == {"conservative": 0, "spec-menus": 1}
    report = (out / CAND_DIR / CAND_MD).read_text(encoding="utf-8")
    assert "INCOMPLETE at 27 (ambiguous-framing)" in report
    assert "## Framings (both shown; neither is chosen)" in report


def test_incomplete_walk_never_implies_an_absent_string(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    # An unknown opcode (0xFE) after one string. The second string sits after the stop.
    _write_block(install, 4, ins(0x11, strop(b"\x01\x02")) + b"\xfe"
                 + ins(0x11, strop(b"\x03\x04")) + EXIT)
    out = tmp_path / "out"
    _, code = pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert code == 0
    doc = _cand_doc(out)
    (b4,) = _cand_blocks(doc, "ECL4.DAX")
    for fr in ("conservative", "spec-menus"):
        assert b4["framings"][fr]["complete"] is False
        assert b4["framings"][fr]["stop"]["kind"] == "unknown-opcode"
        assert b4["framings"][fr]["stop"]["opcode"] == "0xFE"
    recs = [r for r in doc["records"] if r["archive"] == "ECL4.DAX"]
    assert recs and all(r["operand_offset"] < 27 for r in recs), \
        "a string after the stop must not be read"
    assert doc["summary"]["absence_claimed"] is False
    assert doc["summary"]["walks_incomplete"] == {"conservative": 1, "spec-menus": 1}
    report = (out / CAND_DIR / CAND_MD).read_text(encoding="utf-8")
    assert "INCOMPLETE at 27 (unknown-opcode)" in report
    assert "no block or framing is declared complete for absence" in report
    assert any("INCOMPLETE" in u for u in doc["limits"])


def test_por_decode_strings_without_with_ecl_text_is_refused_before_output(tmp_path, capsys):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="needs --with-ecl-text"):
        pp.run(install, out, None, por_decode_strings=True)
    assert not out.exists() and _staging_left(tmp_path) == []
    code = pp.main(["--install", str(install), "-o", str(out), "--por-decode-strings"])
    assert code == 2
    assert "needs --with-ecl-text" in capsys.readouterr().err


def test_candidate_missing_member_is_refused_and_writes_nothing(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    (install / "POOLRAD" / "ECL5.DAX").unlink()
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="ECL5.DAX"):
        pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert not out.exists()


def test_candidate_input_changed_during_the_stage_publishes_nothing(tmp_path, monkeypatch):
    install = make_full_install(tmp_path, ecl=True)
    real = pp.stage_ecl_candidates

    def then_touch(inst, staging):
        result = real(inst, staging)
        (install / "POOLRAD" / "ECL3.DAX").write_bytes(b"changed during the candidate stage")
        return result

    monkeypatch.setattr(pp, "stage_ecl_candidates", then_touch)
    out = tmp_path / "out"
    with pytest.raises(pp.PorPipelineError, match="install changed"):
        pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert not (out / "por_pipeline.json").exists()
    assert not (out / CAND_DIR).exists()
    assert _staging_left(tmp_path) == []


def test_unreadable_archive_is_degraded_and_the_rest_still_walk(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    _write_ecl(install, 2, b"\xff" * 64)                  # container error on ECL2
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert code == 1                                      # degraded, not refused
    c = manifest["ecl_candidate_strings"]
    assert c["summary"]["container_errors"] == 1 and c["summary"]["read_errors"] == 1
    assert c["summary"]["archives_read"] == 7
    doc = _cand_doc(out)
    (row,) = [b for b in doc["blocks"] if b["archive"] == "ECL2.DAX"]
    assert row["status"] == "container-error"
    assert c["summary"]["records_by_framing"] == {"conservative": 14, "spec-menus": 14}


def test_candidate_outputs_are_deterministic_and_path_free(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    a, b = tmp_path / "a", tmp_path / "b"
    ma, _ = pp.run(install, a, plan, with_ecl_text=True, por_decode_strings=True)
    mb, _ = pp.run(install, b, plan, with_ecl_text=True, por_decode_strings=True)
    assert ma["ecl_candidate_strings"] == mb["ecl_candidate_strings"]
    for rel in (CAND_JSON, CAND_MD):
        assert (a / CAND_DIR / rel).read_bytes() == (b / CAND_DIR / rel).read_bytes(), rel
    for rel in ("por_pipeline.json", "por_pipeline_report.md",
                CAND_DIR + "/" + CAND_JSON, CAND_DIR + "/" + CAND_MD):
        text = (a / rel).read_text(encoding="utf-8")
        assert str(tmp_path) not in text and tmp_path.as_posix() not in text, rel
        assert ":/" not in text and ":\\" not in text, rel


def test_candidate_stage_never_writes_the_install_designs_or_strg(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    before = _tree(install)
    plan = _plan(tmp_path, [_good_design()])
    off, on = tmp_path / "off", tmp_path / "on"
    pp.run(install, off, plan, with_ecl_text=True)
    pp.run(install, on, plan, with_ecl_text=True, por_decode_strings=True)
    assert _tree(install) == before
    assert _tree(on / "designs") == _tree(off / "designs")
    for p in (on / CAND_DIR).rglob("*"):
        assert "STRG" not in p.name.upper() and p.suffix.upper() != ".DSN"


def test_rerun_without_the_flag_removes_stale_candidate_output(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    plan = _plan(tmp_path, [_good_design()])
    out = tmp_path / "out"
    pp.run(install, out, plan, with_ecl_text=True, por_decode_strings=True)
    assert (out / CAND_DIR).is_dir()
    (out / "sentinel.txt").write_bytes(b"keep")
    manifest, _ = pp.run(install, out, plan, with_ecl_text=True)
    assert "ecl_candidate_strings" not in manifest and not (out / CAND_DIR).exists()
    assert (out / "sentinel.txt").read_bytes() == b"keep"


def test_cli_por_decode_strings_flag(tmp_path, capsys):
    install = make_full_install(tmp_path, ecl=True)
    out = tmp_path / "ok"
    assert pp.main(["--install", str(install), "-o", str(out), "--with-ecl-text",
                    "--por-decode-strings"]) == 0
    msg = capsys.readouterr().out
    assert "ECL 0x80 candidates candidate-unaccepted, accepted=false, playable=false" in msg
    assert "incomplete walks are not absences" in msg
    assert (out / CAND_DIR / CAND_JSON).is_file()


def test_refused_block_is_recorded_as_a_read_error_and_the_run_goes_on(tmp_path):
    install = make_full_install(tmp_path, ecl=True)
    # A block without the ECL magic word: the decoder refuses it; the others still walk.
    _write_ecl(install, 6, make_dax([(18, b"\x00" * 30)]))
    out = tmp_path / "out"
    manifest, code = pp.run(install, out, None, with_ecl_text=True, por_decode_strings=True)
    assert code == 1
    s = manifest["ecl_candidate_strings"]["summary"]
    assert s["blocks_refused"] == 1 and s["read_errors"] == 1
    assert s["blocks_decoded"] == 7
    doc = _cand_doc(out)
    (row,) = _cand_blocks(doc, "ECL6.DAX")
    assert row["status"] == "refused" and "magic" in row["reason"]
    report = (out / CAND_DIR / CAND_MD).read_text(encoding="utf-8")
    assert "| ECL6.DAX | - | - | refused:" in report
