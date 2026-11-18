"""Tests for tools/por_geo_single_block_plan.py (one smoke-plan block -> one-design plan).

Synthetic inputs are built with the smoke tool's own plan and manifest builders,
so the schema under test is the producer's. One test runs the real enumerator
over a synthetic install (helpers from test_por_geo_smoke_plan). Nothing here
reads the retail install, runs the pipeline on it, or writes outside tmp_path.
DATA_ROOT is patched to a folder under tmp_path so the output rule can be tested.
"""
import copy
import hashlib
import itertools
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, TESTS)
import por_geo_single_block_plan as spb  # noqa: E402
import por_geo_smoke_plan as sp  # noqa: E402
import por_pipeline as pp  # noqa: E402
from test_por_geo_smoke_plan import _produce  # noqa: E402

# (geo, TOC index, block id) of the synthetic decoded blocks.
BLOCKS = [(1, 0, 18), (2, 0, 9), (2, 1, 15), (2, 2, 20), (3, 0, 30)]
ENTRY = {"x": 14, "y": 10, "facing": "west"}
_SEQ = itertools.count()


@pytest.fixture(autouse=True)
def data_root(tmp_path, monkeypatch):
    """Outputs must live under DATA_ROOT; point it at a folder under tmp_path."""
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setattr(spb, "DATA_ROOT", root)
    return root


def _ctx():
    decoded = []
    for geo, index, bid in BLOCKS:
        decoded.append({"key": sp.KEY_FMT % (geo, index, bid), "geo": geo, "index": index,
                        "block_id": bid,
                        "decoded_sha256": hashlib.sha256(("%d-%d-%d" % (geo, index, bid))
                                                         .encode()).hexdigest()})
    return {"scope": sp.SCOPE_PARTIAL, "archive_geos": [1, 2, 3], "refused_archives": [],
            "blocks_refused": 0, "test_entry": dict(ENTRY), "decoded": decoded}


def _dump(data) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _inputs(tmp_path, smoke_mut=None, plan_mut=None, rehash=False):
    """Write a synthetic smoke plan and the pipeline plan it names; return both paths.

    ``smoke_mut`` edits the smoke manifest. ``plan_mut`` edits the pipeline plan
    AFTER the smoke plan has recorded its hash, so the file no longer matches
    unless ``rehash`` also updates ``plan.sha256`` (to test field-level checks).
    """
    folder = tmp_path / ("in%03d" % next(_SEQ))
    ctx = _ctx()
    plan, table = sp.build_plan(ctx)
    plan_bytes = _dump(plan)
    smoke = sp.build_smoke_manifest(ctx, table, "b" * 64, plan_bytes)
    if smoke_mut:
        smoke_mut(smoke)
    if plan_mut:
        plan_mut(plan)
        plan_bytes = _dump(plan)
        if rehash:
            smoke["plan"]["sha256"] = hashlib.sha256(plan_bytes).hexdigest()
    smoke_path = folder / sp.SMOKE_FILE
    plan_path = folder / sp.PLAN_FILE
    folder.mkdir(parents=True, exist_ok=True)
    smoke_path.write_bytes(_dump(smoke))
    plan_path.write_bytes(plan_bytes)
    return smoke_path, plan_path


def _out(data_root):
    return data_root / ("out%03d" % next(_SEQ))


def _run(smoke, plan, out, geo=2, index=2, block_id=20, entry="14,10,west"):
    return spb.run(smoke, plan, geo, index, block_id, entry, out)


# ---- valid selection --------------------------------------------------------

def test_selects_one_block_and_writes_one_test_only_design(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    m = _run(smoke, plan, out)
    assert _load(out / spb.PLAN_FILE) == {
        "schema": "openua.por-pipeline-plan", "version": 0,
        "designs": [{"name": "TG2I002", "geo": 2, "index": 2, "area": 5,
                     "entry": [14, 10], "facing": "west",
                     "title": "test-only geo2 TOC 2 block 20 (invented area and entry)"}]}
    assert m["playable"] is False
    assert m["selector"] == {"geo": 2, "index": 2, "block_id": 20, "key": "geo2-i02-b020"}
    assert m["summary"]["designs_planned"] == 1
    assert m["summary"]["designs_not_selected"] == len(BLOCKS) - 1
    assert m["summary"]["dsn_emitted"] == 0
    assert m["block"]["decoded_sha256"] == hashlib.sha256(b"2-2-20").hexdigest()


def test_hashes_bind_the_manifest_to_both_files(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    m = _run(smoke, plan, out)
    assert m["plan"]["sha256"] == hashlib.sha256((out / spb.PLAN_FILE).read_bytes()).hexdigest()
    assert m["source"]["pipeline_plan_sha256"] == hashlib.sha256(plan.read_bytes()).hexdigest()
    assert m["source"]["geo_manifest_sha256"] == "b" * 64


def test_plan_is_accepted_by_the_pipeline_loader(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    _run(smoke, plan, out)
    rows, _ = pp.load_plan(out / spb.PLAN_FILE)
    assert len(rows) == 1
    row = rows[0]
    assert (row["name"], row["geo"], row["index"], row["area"]) == ("TG2I002", 2, 2, 5)
    assert row["entry"] == (14, 10) and row["facing"] == "west"


def test_manifest_labels_area_and_entry_as_invented(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    m = _run(smoke, plan, _out(data_root))
    assert m["status"] == spb.STATUS and m["label"] == "test-only"
    assert m["area"]["status"] == "invented-test-only"
    assert "not GEO2 area 1" in m["area"]["basis"]
    assert m["entry"]["status"] == "test-only"
    assert "invented" in m["entry"]["basis"]
    assert any("is game area 1 or any authentic area" in s for s in m["not_claimed"])
    assert any("runtime_loaded and engine_executed are false" in s for s in m["not_claimed"])


def test_same_inputs_give_byte_identical_output(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    a, b = _out(data_root), _out(data_root)
    _run(smoke, plan, a)
    _run(smoke, plan, b)
    assert (a / spb.PLAN_FILE).read_bytes() == (b / spb.PLAN_FILE).read_bytes()
    assert (a / spb.MANIFEST_FILE).read_bytes() == (b / spb.MANIFEST_FILE).read_bytes()


def test_output_has_no_absolute_paths(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    _run(smoke, plan, out)
    text = (out / spb.PLAN_FILE).read_text("utf-8") + (out / spb.MANIFEST_FILE).read_text("utf-8")
    assert str(tmp_path) not in text
    assert "Pool of Radiance" not in text and "G:" not in text


def test_main_exit_codes_and_refusal_writes_nothing(tmp_path, data_root, capsys):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    argv = ["--smoke-plan", str(smoke), "--pipeline-plan", str(plan), "--geo", "2",
            "--index", "2", "--block-id", "20", "--entry", "14,10,west", "-o", str(out)]
    assert spb.main(argv) == 0
    assert (out / spb.PLAN_FILE).is_file()
    bad = _out(data_root)
    argv_bad = argv[:-1] + [str(bad)]
    argv_bad[argv_bad.index("14,10,west")] = "14,9,west"
    assert spb.main(argv_bad) == 2
    assert "differs from the smoke plan test entry" in capsys.readouterr().err
    assert not bad.exists()


def test_select_refuses_ambiguous_match_directly():
    row = {"geo": 2, "index": 2, "block_id": 20, "key": "x", "name": "TG2I002"}
    with pytest.raises(spb.SingleBlockError, match="ambiguous"):
        spb.select([row, dict(row, name="TG2I0X")], 2, 2, 20)


# ---- selection refusals -----------------------------------------------------

@pytest.mark.parametrize("geo,index,block_id,message", [
    (2, 9, 20, "no decoded block at GEO2 TOC index 9"),
    (2, 2, 21, "is block 20 in the smoke plan, not block 21"),
    (9, 2, 20, "--geo 1..8"),
    (2, -1, 20, "--index 0..999"),
    (2, 2, -3, "--block-id >= 0"),
])
def test_refuses_block_that_is_not_the_exact_request(tmp_path, data_root, geo, index,
                                                     block_id, message):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    with pytest.raises(spb.SingleBlockError, match=message):
        _run(smoke, plan, out, geo=geo, index=index, block_id=block_id)
    assert not out.exists()


@pytest.mark.parametrize("entry,message", [
    ("14,9,west", "differs from the smoke plan test entry"),
    ("16,10,west", "x and y must be integers 0..15"),
    ("-1,10,west", "x and y must be integers 0..15"),
    ("14,10,up", "facing must be one of"),
    ("14,10", "expects X,Y,FACING"),
    ("a,10,west", "must be integers"),
])
def test_refuses_entry_out_of_range_or_not_the_smoke_entry(tmp_path, data_root, entry,
                                                           message):
    smoke, plan = _inputs(tmp_path)
    out = _out(data_root)
    with pytest.raises(spb.SingleBlockError, match=message):
        _run(smoke, plan, out, entry=entry)
    assert not out.exists()


# ---- smoke plan refusals ----------------------------------------------------

def test_refuses_smoke_plan_that_is_not_playable_false(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path, smoke_mut=lambda m: m.update(playable=True))
    with pytest.raises(spb.SingleBlockError, match="playable: false"):
        _run(smoke, plan, _out(data_root))


def test_refuses_unknown_top_level_field_in_smoke_plan(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path, smoke_mut=lambda m: m.update(note="x"))
    with pytest.raises(spb.SingleBlockError, match="unknown field\\(s\\): note"):
        _run(smoke, plan, _out(data_root))


def test_refuses_unknown_field_in_design_row(tmp_path, data_root):
    def mut(m):
        m["designs"][0]["extra"] = 1
    smoke, plan = _inputs(tmp_path, smoke_mut=mut)
    with pytest.raises(spb.SingleBlockError, match="unknown field\\(s\\): extra"):
        _run(smoke, plan, _out(data_root))


def test_refuses_missing_entry_basis(tmp_path, data_root):
    def mut(m):
        del m["test_entry"]["basis"]
    smoke, plan = _inputs(tmp_path, smoke_mut=mut)
    with pytest.raises(spb.SingleBlockError, match="missing field\\(s\\): basis"):
        _run(smoke, plan, _out(data_root))


def test_refuses_duplicate_design_row(tmp_path, data_root):
    def mut(m):
        m["designs"].append(copy.deepcopy(m["designs"][3]))
        m["summary"]["designs_planned"] = len(m["designs"])
    smoke, plan = _inputs(tmp_path, smoke_mut=mut)
    with pytest.raises(spb.SingleBlockError, match="repeats a key"):
        _run(smoke, plan, _out(data_root))


def test_refuses_summary_that_disagrees_with_designs(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path,
                          smoke_mut=lambda m: m["summary"].update(designs_planned=99))
    with pytest.raises(spb.SingleBlockError, match="summary.designs_planned disagrees"):
        _run(smoke, plan, _out(data_root))


def test_refuses_design_with_wrong_name_for_its_position(tmp_path, data_root):
    def mut(m):
        m["designs"][3]["name"] = "TG2I009"
    smoke, plan = _inputs(tmp_path, smoke_mut=mut)
    with pytest.raises(spb.SingleBlockError, match="name 'TG2I009' is not 'TG2I002'"):
        _run(smoke, plan, _out(data_root))


def test_refuses_missing_smoke_plan(tmp_path, data_root):
    with pytest.raises(spb.SingleBlockError, match="smoke plan file not found"):
        _run(tmp_path / "nope.json", tmp_path / "nope2.json", _out(data_root))


# ---- pipeline plan refusals (hash and field provenance) --------------------

def test_refuses_pipeline_plan_whose_hash_does_not_match(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path, plan_mut=lambda p: p["designs"][0].update(title="x"))
    with pytest.raises(spb.SingleBlockError, match="SHA-256 does not match"):
        _run(smoke, plan, _out(data_root))


def test_refuses_pipeline_entry_that_disagrees_even_when_rehashed(tmp_path, data_root):
    def mut(p):
        p["designs"][3]["entry"] = [13, 10]
    smoke, plan = _inputs(tmp_path, plan_mut=mut, rehash=True)
    with pytest.raises(spb.SingleBlockError, match="disagrees with the smoke plan design table"):
        _run(smoke, plan, _out(data_root))


def test_refuses_pipeline_unknown_field_even_when_rehashed(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path,
                          plan_mut=lambda p: p["designs"][0].update(playable=True),
                          rehash=True)
    with pytest.raises(spb.SingleBlockError, match="unknown field\\(s\\): playable"):
        _run(smoke, plan, _out(data_root))


def test_refuses_pipeline_design_the_smoke_plan_does_not_list(tmp_path, data_root):
    def mut(p):
        p["designs"][0]["name"] = "TGX"
    smoke, plan = _inputs(tmp_path, plan_mut=mut, rehash=True)
    with pytest.raises(spb.SingleBlockError, match="names 'TGX', which the smoke plan does not list"):
        _run(smoke, plan, _out(data_root))


def test_refuses_duplicate_json_key_in_pipeline_plan(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    text = plan.read_text("utf-8").replace('"version": 0', '"version": 0, "version": 0', 1)
    plan.write_text(text, encoding="utf-8")
    with pytest.raises(spb.SingleBlockError, match="repeats object key"):
        _run(smoke, plan, _out(data_root))


# ---- output location --------------------------------------------------------

def test_refuses_output_inside_an_input_folder(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    with pytest.raises(spb.SingleBlockError, match="must not be inside the source folder"):
        _run(smoke, plan, smoke.parent / "inside")


def test_refuses_output_outside_the_data_folder(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    with pytest.raises(spb.SingleBlockError, match="must be a folder under data/"):
        _run(smoke, plan, tmp_path / "elsewhere")


def test_refuses_output_path_that_is_a_file(tmp_path, data_root):
    smoke, plan = _inputs(tmp_path)
    target = data_root / "a-file"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(spb.SingleBlockError, match="exists and is not a folder"):
        _run(smoke, plan, target)


# ---- the real enumerator's output ------------------------------------------

def test_real_enumerator_smoke_plan_yields_one_block(tmp_path, data_root):
    """The adapter reads what tools/por_geo_smoke_plan.py actually writes."""
    src = _produce(tmp_path)
    smoke_dir = tmp_path / "smoke"
    sp.run(src, smoke_dir)
    smoke = _load(smoke_dir / sp.SMOKE_FILE)
    row = next(r for r in smoke["designs"] if r["geo"] == 2)
    out = data_root / "real"
    m = spb.run(smoke_dir / sp.SMOKE_FILE, smoke_dir / sp.PLAN_FILE,
                row["geo"], row["index"], row["block_id"], "13,8,east", out)
    assert m["summary"]["designs_planned"] == 1
    assert m["summary"]["designs_not_selected"] == len(smoke["designs"]) - 1
    rows, _ = pp.load_plan(out / spb.PLAN_FILE)
    assert rows[0]["entry"] == (13, 8) and rows[0]["facing"] == "east"
