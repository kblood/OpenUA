"""Tests for tools/por_geo_door_census.py (census-only, read-only on the install).

Synthetic fixtures only; no retail PoR data is read by the test suite. The
DAX and GEO writers below follow the same layout that tests/test_por_map.py
pins (docs/dax-format.md, Gen1 plane layout in tools/por_map.py).
"""
import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_door_census as dc  # noqa: E402
import por_map as pm  # noqa: E402


# ---- synthetic writers (test-only) -----------------------------------------

def rle_encode(data: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        run = 1
        while i + run < n and data[i + run] == data[i] and run < 127:
            run += 1
        if run >= 3:
            out += bytes((256 - run, data[i]))
            i += run
            continue
        j = i
        while j < n and (j - i) < 126:
            if j + 2 < n and data[j] == data[j + 1] == data[j + 2]:
                break
            j += 1
        out += bytes((j - i - 1,)) + data[i:j]
        i = j
    return bytes(out)


def make_dax(blocks) -> bytes:
    toc = bytearray()
    body = bytearray()
    off = 0
    for bid, raw in blocks:
        comp = rle_encode(raw)
        toc += struct.pack("<BIHH", bid, off, len(raw), len(comp))
        body += comp
        off += len(comp)
    return struct.pack("<H", len(toc)) + bytes(toc) + bytes(body)


def geo_raw(cell_fn=None, size_field=1024) -> bytes:
    """cell_fn(x, y) -> (N, E, S, W, descriptor); each wall is (slot, door)."""
    planes = [bytearray(256) for _ in range(4)]
    for y in range(16):
        for x in range(16):
            n = e = s = w = (0, 0)
            desc = 0
            if cell_fn is not None:
                n, e, s, w, desc = cell_fn(x, y)
            i = y * 16 + x
            planes[0][i] = (n[0] << 4) | e[0]
            planes[1][i] = (s[0] << 4) | w[0]
            planes[2][i] = desc
            planes[3][i] = n[1] | (e[1] << 2) | (s[1] << 4) | (w[1] << 6)
    return struct.pack("<H", size_field) + b"".join(bytes(p) for p in planes)


def cells_of(cell_fn=None):
    return pm.decode_gen1_geo(geo_raw(cell_fn))


def _only(cell_map):
    """cell_fn with a fixed wall at the listed (x, y); every other cell open."""
    def fn(x, y):
        return cell_map.get((x, y), ((0, 0), (0, 0), (0, 0), (0, 0), 0))
    return fn


# ---- census counts ----------------------------------------------------------

def test_census_counts_every_edge_once_by_door_value():
    # 256 cells x 4 edges = 1024 edge reads. One cell carries four doors.
    c = cells_of(_only({(5, 5): ((3, 1), (4, 2), (6, 3), (7, 0), 0)}))
    r = dc.census_cells([c])
    assert r["cells"] == 256
    # Exact: N=1, E=2, S=3, W=0 on one cell; every other edge is door 0.
    assert r["edge_door"] == {"0": 1024 - 3, "1": 1, "2": 1, "3": 1}


def test_census_separates_slot0_doors_from_wall_doors():
    # slot 0 with door 2 on the north: an edge that map_edge calls open.
    c = cells_of(_only({(2, 2): ((0, 2), (0, 0), (0, 0), (0, 0), 0)}))
    r = dc.census_cells([c])
    assert r["edge_door_slot0"].get("2") == 1
    assert "2" not in r["edge_door_wall"]


def test_census_agrees_shared_edge_when_both_sides_are_door_one():
    # E(4,4) and W(5,4) both (slot 9, door 1): one shared edge, agreeing.
    c = cells_of(_only({(4, 4): ((0, 0), (9, 1), (0, 0), (0, 0), 0),
                        (5, 4): ((0, 0), (0, 0), (0, 0), (9, 1), 0)}))
    r = dc.census_cells([c])
    assert r["shared_both_walls"] == {"1-1": 1}
    assert r["shared_both_walls_door_agree"] == 1


def test_census_records_one_sided_door_as_disagreeing_pair():
    # E(4,4) door 1 with a wall, W(5,4) door 0 with a wall: keyed "0-1", not agreed.
    c = cells_of(_only({(4, 4): ((0, 0), (9, 1), (0, 0), (0, 0), 0),
                        (5, 4): ((0, 0), (0, 0), (0, 0), (9, 0), 0)}))
    r = dc.census_cells([c])
    assert r["shared_both_walls"] == {"0-1": 1}
    assert r["shared_both_walls_door_agree"] == 0


def test_census_puts_open_side_pairs_under_some_open_not_both_walls():
    # E(4,4) slot 0 (door 1) against W(5,4) slot 5 (door 0): one side is open.
    c = cells_of(_only({(4, 4): ((0, 0), (0, 1), (0, 0), (0, 0), 0),
                        (5, 4): ((0, 0), (0, 0), (0, 0), (5, 0), 0)}))
    r = dc.census_cells([c])
    assert r["shared_some_open"]["0-1"] == 1
    assert r["slot_mismatch"]["0-1"] == 1
    # the (4,4)E/(5,4)W pair must not be counted as both-walls
    assert r["shared_both_walls"] == {}


def test_census_door_value_two_and_three_are_kept_distinct():
    # A two-bit field holds 0..3; the census must not fold 2 into 3 or back.
    c = cells_of(_only({(1, 1): ((7, 3), (7, 2), (0, 0), (0, 0), 0)}))
    r = dc.census_cells([c])
    assert r["edge_door_wall"]["2"] == 1
    assert r["edge_door_wall"]["3"] == 1


# ---- scan on a synthetic install -------------------------------------------

def make_install(root: Path, blocks=None, name="GEO1.DAX", sub="POOLRAD") -> Path:
    install = root / "install"
    target = install / sub if sub else install
    target.mkdir(parents=True)
    if blocks is None:
        blocks = [(18, geo_raw(_only({(3, 3): ((0, 0), (9, 1), (0, 0), (0, 0), 0)})))]
    (target / name).write_bytes(make_dax(blocks))
    return install


def _tree_hashes(root: Path) -> dict:
    out = {}
    for dirpath, _d, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_scan_pins_before_and_after_and_reports_census(tmp_path):
    install = make_install(tmp_path)
    r = dc.scan(install)
    assert r["pins"]["unchanged"] is True
    assert r["pins"]["before"] == r["pins"]["after"]
    assert r["blocks_decoded"] == 1
    assert r["census"]["edge_door_wall"].get("1") == 1


def test_scan_skips_non_geo_sized_blocks_and_records_them(tmp_path):
    install = make_install(tmp_path, blocks=[(18, geo_raw()), (7, b"\x00" * 100)])
    r = dc.scan(install)
    assert r["blocks_decoded"] == 1
    assert len(r["skipped_non_geo_blocks"]) == 1
    assert r["skipped_non_geo_blocks"][0]["raw_size"] == 100


def test_scan_records_wrong_size_field_as_error_not_census(tmp_path):
    bad = geo_raw(size_field=1000)
    install = make_install(tmp_path, blocks=[(18, bad), (19, geo_raw())])
    r = dc.scan(install)
    assert r["blocks_decoded"] == 1
    assert any("size field is 1000" in e for e in r["errors"])


def test_scan_refuses_when_a_file_changes_during_the_run(tmp_path, monkeypatch):
    install = make_install(tmp_path)
    calls = {"n": 0}
    real = dc._sha

    def drifting(data):
        calls["n"] += 1
        return real(data) if calls["n"] <= 1 else "0" * 64

    monkeypatch.setattr(dc, "_sha", drifting)
    with pytest.raises(pm.PorMapError, match="changed during the census"):
        dc.scan(install)


def test_main_writes_report_and_leaves_install_untouched(tmp_path):
    install = make_install(tmp_path)
    before = _tree_hashes(install)
    out = tmp_path / "out"
    rc = dc.main(["--install", str(install), "-o", str(out)])
    assert rc == 0
    assert (out / "por_geo_door_census.json").is_file()
    assert (out / "por_geo_door_census.md").is_file()
    assert _tree_hashes(install) == before


def test_report_is_deterministic_and_census_only(tmp_path):
    install = make_install(tmp_path)
    a = tmp_path / "a"
    b = tmp_path / "b"
    assert dc.main(["--install", str(install), "-o", str(a)]) == 0
    assert dc.main(["--install", str(install), "-o", str(b)]) == 0
    assert (a / "por_geo_door_census.json").read_bytes() == \
        (b / "por_geo_door_census.json").read_bytes()
    text = (a / "por_geo_door_census.json").read_text(encoding="utf-8")
    assert '"status": "census-only"' in text
    assert '"playable": false' in text


def test_output_inside_install_is_refused(tmp_path):
    install = make_install(tmp_path)
    assert dc.main(["--install", str(install), "-o", str(install / "out")]) == 2
    assert not (install / "out").exists()


def test_duplicate_geo_name_in_install_and_poolrad_is_refused(tmp_path):
    install = make_install(tmp_path)
    (install / "GEO1.DAX").write_bytes(make_dax([(18, geo_raw())]))
    assert dc.main(["--install", str(install), "-o", str(tmp_path / "o")]) == 2


def test_flat_layout_without_poolrad_is_found(tmp_path):
    install = make_install(tmp_path, sub=None)
    files = dc.find_geo_files(install)
    assert [f.name for f in files] == ["GEO1.DAX"]


def test_no_geo_files_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert dc.main(["--install", str(empty), "-o", str(tmp_path / "o")]) == 2
