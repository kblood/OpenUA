"""Tests for tools/por_walls.py (Pool of Radiance wall census, slice 4).

All fixtures are synthetic and written to pytest's tmp_path. No retail data is
needed or read. The DAX container layout follows tests/test_por_map.py: a
2-byte TOC size, 9-byte TOC entries (u8 id, u32 offset, u16 raw, u16 comp),
a contiguous data chain closing at EOF, and signed-byte RLE blocks. The
literal-only encoder below is test-only.

These pin the census tool's behaviour. They do not prove that a retail PoR
wall slot draws any particular art. The census emits no binding at all.
"""
import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_walls as pw  # noqa: E402
from por_convert import PorSourceError  # noqa: E402
from por_map import PorMapError  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---- synthetic writers (test-only) -----------------------------------------

def literal_rle(data: bytes) -> bytes:
    """Signed-byte RLE using literal runs only: control c < 0x80 copies c+1 bytes."""
    out = bytearray()
    for i in range(0, len(data), 128):
        chunk = data[i:i + 128]
        out.append(len(chunk) - 1)
        out += chunk
    return bytes(out)


def make_dax(entries):
    """entries: list of (block_id, raw_bytes). Returns a DAX container."""
    comps = [literal_rle(raw) for _, raw in entries]
    toc = bytearray()
    off = 0
    for (bid, raw), comp in zip(entries, comps):
        toc += struct.pack("<BIHH", bid, off, len(raw), len(comp))
        off += len(comp)
    return struct.pack("<H", len(toc)) + bytes(toc) + b"".join(comps)


def geo_raw(walls=None):
    """A 1026-byte Gen1 GEO block. ``walls`` maps cell index -> (N, E, S, W)
    wall slots. Planes 2 and 3 are zero (no descriptor, no door flags)."""
    walls = walls or {}
    planes = [bytearray(256) for _ in range(4)]
    for i, (n, e, s, w) in walls.items():
        planes[0][i] = ((n & 15) << 4) | (e & 15)
        planes[1][i] = ((s & 15) << 4) | (w & 15)
    return struct.pack("<H", 1024) + b"".join(bytes(p) for p in planes)


def walldef_raw(records):
    """``records`` * 780 bytes. Row r, column c holds 1 + 10*r + (c % 10), so
    every row has min 1+10r, max 10+10r and 10 distinct values."""
    rec = bytearray()
    for r in range(5):
        for c in range(156):
            rec.append(1 + 10 * r + (c % 10))
    return bytes(rec) * records


def make_install(root: Path, files: dict) -> Path:
    """Write ``files`` (name -> bytes) into root/POOLRAD and return the install."""
    install = root / "install"
    pool = install / "POOLRAD"
    pool.mkdir(parents=True)
    for name, data in files.items():
        (pool / name).write_bytes(data)
    return install


def _hash_tree(folder: Path) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


# ---- resolution -------------------------------------------------------------

def test_resolve_archive_is_case_insensitive_and_checks_poolrad(tmp_path):
    install = tmp_path / "install"
    (install / "POOLRAD").mkdir(parents=True)
    (install / "POOLRAD" / "geo1.dax").write_bytes(b"x")
    found = pw.resolve_archive(install, "GEO", 1)
    assert found is not None and found.name == "geo1.dax"


def test_resolve_archive_absent_returns_none(tmp_path):
    install = tmp_path / "install"
    (install / "POOLRAD").mkdir(parents=True)
    assert pw.resolve_archive(install, "GEO", 3) is None


def test_resolve_archive_ambiguous_is_an_error(tmp_path):
    install = tmp_path / "install"
    (install / "POOLRAD").mkdir(parents=True)
    (install / "GEO1.DAX").write_bytes(b"a")
    (install / "POOLRAD" / "GEO1.DAX").write_bytes(b"b")
    with pytest.raises(PorMapError, match="ambiguous"):
        pw.resolve_archive(install, "GEO", 1)


# ---- per-archive census -----------------------------------------------------

def test_geo_census_counts_every_edge_slot(tmp_path):
    # Cell 0: N=1, E=6, S=11, W=0. 256 cells x 4 edges = 1024 edges, and
    # only three of them are non-zero, so the other 1021 are slot 0.
    path = tmp_path / "GEO1.DAX"
    path.write_bytes(make_dax([(7, geo_raw({0: (1, 6, 11, 0)}))]))
    census = pw.census_geo(path)
    blk = census["blocks"][0]
    assert blk["status"] == "ok"
    counts = {int(k): v for k, v in blk["edge_slot_counts"].items()}
    assert counts[1] == 1 and counts[6] == 1 and counts[11] == 1
    assert counts[0] == 1024 - 3
    assert sum(counts.values()) == 1024
    assert blk["slots_used"] == [1, 6, 11]
    assert blk["wallsets_used"] == [0, 1, 2]


def test_geo_census_keeps_going_past_a_bad_block(tmp_path):
    good = geo_raw({5: (2, 2, 2, 2)})
    bad = b"\x00" * 1000                      # raw size 1000 is not a GEO block
    path = tmp_path / "GEO2.DAX"
    path.write_bytes(make_dax([(20, good), (21, bad)]))
    census = pw.census_geo(path)
    statuses = [(b["block_id"], b["status"]) for b in census["blocks"]]
    assert statuses == [(20, "ok"), (21, "error")]
    assert "expected 1026" in census["blocks"][1]["message"]


def test_walldef_census_records_and_row_stats(tmp_path):
    path = tmp_path / "WALLDEF1.DAX"
    path.write_bytes(make_dax([(23, walldef_raw(1)), (1, walldef_raw(2))]))
    census = pw.census_walldef(path)
    b23, b1 = census["blocks"]
    assert (b23["block_id"], b23["records"]) == (23, 1)
    assert (b1["block_id"], b1["records"]) == (1, 2)
    rows = b1["record_stats"][1]["rows"]
    assert [r["row"] for r in rows] == [0, 1, 2, 3, 4]
    assert rows[0] == {"row": 0, "min": 1, "max": 10, "distinct": 10}
    assert rows[4] == {"row": 4, "min": 41, "max": 50, "distinct": 10}


def test_walldef_block_not_a_record_multiple_is_an_error(tmp_path):
    path = tmp_path / "WALLDEF2.DAX"
    path.write_bytes(make_dax([(4, b"\x01" * 700)]))
    blk = pw.census_walldef(path)["blocks"][0]
    assert blk["status"] == "error"
    assert "not a multiple of 780" in blk["message"]


def test_8x8d_is_inventory_only(tmp_path):
    path = tmp_path / "8X8D1.DAX"
    path.write_bytes(make_dax([(201, b"\x00" * 16), (11, b"\x01" * 32)]))
    inv = pw.inventory_8x8d(path)
    assert [(b["block_id"], b["status"]) for b in inv["blocks"]] == [
        (201, "not-decoded"), (11, "not-decoded")]
    assert "tile_bytes" not in inv["blocks"][0]


# ---- index arithmetic and pairing ------------------------------------------

@pytest.mark.parametrize("slot,row,wallset", [
    (1, 0, 0), (5, 4, 0), (6, 0, 1), (10, 4, 1), (11, 0, 2), (15, 4, 2)])
def test_slot_index_matches_documented_rule(slot, row, wallset):
    idx = pw.slot_index(slot)
    assert idx["walldef_row"] == row
    assert idx["walldef_wallset"] == wallset
    # The OpenUA group/facet index is the same arithmetic, labelled as an index.
    assert idx["openua_group"] == wallset and idx["openua_facet"] == row


def test_pairing_candidates_follow_b_times_10_rule(tmp_path):
    xref = pw.cross_reference(
        1,
        geo=None,
        wd={"file": "WALLDEF1.DAX", "blocks": [
            {"block_id": 23, "status": "ok", "records": 1},
            {"block_id": 2, "status": "ok", "records": 2},
        ]},
        x8={"file": "8X8D1.DAX", "blocks": [
            {"block_id": 23}, {"block_id": 21}]},
    )
    by = {p["walldef_block"]: p for p in xref["pairing_candidates"]}
    assert by[23]["candidate_8x8d_ids"] == [23]
    assert by[23]["all_present"] is True
    assert by[2]["candidate_8x8d_ids"] == [21, 22]
    assert by[2]["present_8x8d_ids"] == [21]
    assert by[2]["all_present"] is False


# ---- whole census ------------------------------------------------------------

def _synthetic_install(tmp_path):
    geo = make_dax([(18, geo_raw({0: (1, 6, 11, 0), 17: (4, 4, 4, 4)}))])
    wd = make_dax([(1, walldef_raw(1)), (3, walldef_raw(2))])
    x8 = make_dax([(11, b"\x00" * 8), (31, b"\x00" * 8), (32, b"\x00" * 8)])
    return make_install(tmp_path, {"GEO1.DAX": geo, "WALLDEF1.DAX": wd,
                                    "8X8D1.DAX": x8})


def test_census_emits_every_slot_unresolved_and_no_binding(tmp_path):
    install = _synthetic_install(tmp_path)
    out = tmp_path / "out"
    res = pw.census(install, out, areas=(1,))
    norm = res["norm"]
    assert norm["status"] == "census-only" and norm["playable"] is False
    assert norm["summary"]["slots_bound"] == 0
    slots = norm["per_area"][0]["slots"]
    assert [s["slot"] for s in slots] == [1, 4, 6, 11]
    for s in slots:
        assert s["binding"] is None
        assert s["binding_status"] == "unresolved"
        assert set(s["unresolved_reasons"]) == set(pw.SLOT_REASONS)


def test_census_reports_absent_archives_without_failing(tmp_path):
    install = make_install(tmp_path, {"GEO1.DAX": make_dax([(18, geo_raw())])})
    res = pw.census(install, tmp_path / "out", areas=(1,))
    absent = {(a["area"], a["family"]) for a in res["norm"]["absent"]}
    assert absent == {(1, "WALLDEF"), (1, "8X8D")}
    assert res["norm"]["diagnostics"] == []


def test_census_outputs_are_deterministic_and_path_free(tmp_path):
    install = _synthetic_install(tmp_path)
    before = _hash_tree(install)
    out_a, out_b = tmp_path / "out_a", tmp_path / "out_b"
    for out in (out_a, out_b):
        result = pw.census(install, out, areas=(1,))
        pw.write_outputs(result)
    for name in ("por_walls.json", "por_walls_report.md"):
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes()
    text = (out_a / "por_walls.json").read_text(encoding="utf-8") + \
        (out_a / "por_walls_report.md").read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert str(install) not in text
    assert '"_archives"' not in text
    assert _hash_tree(install) == before


def test_output_inside_source_is_refused(tmp_path):
    install = _synthetic_install(tmp_path)
    with pytest.raises(PorSourceError, match="inside the source"):
        pw.census(install, install / "sub", areas=(1,))


def test_output_in_repo_outside_data_is_refused(tmp_path):
    install = _synthetic_install(tmp_path)
    target = REPO_ROOT / "tests" / "por-walls-should-not-exist"
    with pytest.raises(PorSourceError, match="under data/"):
        pw.census(install, target, areas=(1,))
    assert not target.exists()


def test_missing_install_is_a_named_error(tmp_path):
    with pytest.raises(PorSourceError):
        pw.census(tmp_path / "nope", tmp_path / "out", areas=(1,))


# ---- CLI exit codes ----------------------------------------------------------

def test_cli_exit_0_for_clean_census(tmp_path):
    install = _synthetic_install(tmp_path)
    assert pw.main(["--install", str(install), "-o", str(tmp_path / "out"),
                    "--area", "1"]) == 0


def test_cli_exit_1_when_a_block_fails_to_decode(tmp_path):
    install = make_install(tmp_path, {
        "GEO1.DAX": make_dax([(18, b"\x00" * 1000)])})
    assert pw.main(["--install", str(install), "-o", str(tmp_path / "out"),
                    "--area", "1"]) == 1
    assert (tmp_path / "out" / "por_walls.json").is_file()


def test_cli_exit_2_for_refused_output(tmp_path):
    install = _synthetic_install(tmp_path)
    assert pw.main(["--install", str(install), "-o", str(install / "x"),
                    "--area", "1"]) == 2
