"""Tests for tools/por_geo_plane2_observe.py (observe-only GEO plane-2 census).

Synthetic tests build tiny GEO blocks and DAX containers in tmp_path, so no
game data is needed. They check the counts, the refusals, the no-emission
contract and the anchor agree/disagree reporting.

The retail run is gated on OPENUA_POR_INSTALL (for example
G:\\Games\\Pool of Radiance\\POOLRAD). It is read-only and checks the 29-block
census, the five anchors and that the install bytes do not change.
"""
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_geo_plane2_observe as obs  # noqa: E402
import por_map as pm  # noqa: E402


# --------------------------------------------------------------------------
# Synthetic builders
# --------------------------------------------------------------------------

def make_geo_raw(p2: bytes = bytes(256), walls: bytes = bytes(256),
                 p3: bytes = bytes(256)) -> bytes:
    """A 1026-byte Gen1 GEO block: size field 1024, planes 0..3. Planes 0 and 1
    (walls) are ``walls`` for plane 0 and zero for plane 1."""
    assert len(p2) == 256 and len(walls) == 256 and len(p3) == 256
    return struct.pack("<H", 1024) + walls + bytes(256) + p2 + p3


def rle_literal(raw: bytes) -> bytes:
    """Encode raw as signed-byte RLE literal runs (control c = count-1 < 0x80)."""
    out = bytearray()
    for i in range(0, len(raw), 128):
        chunk = raw[i:i + 128]
        out.append(len(chunk) - 1)
        out += chunk
    return bytes(out)


def make_dax(blocks: list[tuple[int, bytes, int]]) -> bytes:
    """blocks: (block_id, compressed bytes, raw_size). Builds a contiguous DAX."""
    toc = bytearray()
    data = bytearray()
    for bid, comp, raw_size in blocks:
        toc += struct.pack("<BIHH", bid, len(data), raw_size, len(comp))
        data += comp
    return struct.pack("<H", len(toc)) + bytes(toc) + bytes(data)


def make_install(tmp: Path, geos: dict[int, list[tuple[int, bytes]]]) -> Path:
    """Write GEO<n>.DAX files into tmp (no POOLRAD subfolder). geos maps the GEO
    number to (block_id, raw GEO block) pairs."""
    tmp.mkdir(parents=True, exist_ok=True)
    for n, blocks in geos.items():
        dax = make_dax([(bid, rle_literal(raw), len(raw)) for bid, raw in blocks])
        (tmp / ("GEO%d.DAX" % n)).write_bytes(dax)
    return tmp


def _tree_hashes(folder: Path) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.iterdir()) if p.is_file()}


# --------------------------------------------------------------------------
# Counts over one block
# --------------------------------------------------------------------------

def test_observe_block_counts_on_known_bytes():
    p2 = bytearray(256)
    p2[0] = 0x80          # bit 7 only, low7 = 0
    p2[1] = 0x86          # bit 7 and low7 = 6
    p2[2] = 0x06          # low7 = 6, no bit 7
    p2[3] = 0x00          # zero
    raw = make_geo_raw(p2=bytes(p2))
    cells = pm.decode_gen1_geo(raw)
    rec = obs.observe_block(raw, cells)
    assert rec["cells"] == 256
    assert rec["plane2_nonzero"] == 3
    assert rec["plane2_bit7_set"] == 2
    assert rec["plane2_distinct_raw"] == 4        # 0x80, 0x86, 0x06, 0x00
    assert rec["plane2_distinct_low7"] == 2       # 0x00 and 0x06
    # no walls anywhere: every nonzero cell is all-open
    assert rec["nonzero_on_all_open_cells"] == 3
    assert rec["nonzero_on_walled_cells"] == 0


def test_walled_cell_with_descriptor_is_counted_as_walled():
    p2 = bytearray(256)
    p2[5] = 0x01                  # cell (5,0)
    walls = bytearray(256)
    walls[5] = 0x10               # plane 0: N slot 1, E slot 0
    raw = make_geo_raw(p2=bytes(p2), walls=bytes(walls))
    rec = obs.observe_block(raw, pm.decode_gen1_geo(raw))
    assert rec["plane2_nonzero"] == 1
    assert rec["nonzero_on_walled_cells"] == 1
    assert rec["nonzero_on_all_open_cells"] == 0


def test_sha_pins_change_with_plane2_bytes():
    a = obs.observe_block(make_geo_raw(), pm.decode_gen1_geo(make_geo_raw()))
    p2 = bytearray(256)
    p2[9] = 1
    raw_b = make_geo_raw(p2=bytes(p2))
    b = obs.observe_block(raw_b, pm.decode_gen1_geo(raw_b))
    assert a["plane2_sha256"] != b["plane2_sha256"]
    assert a["block_sha256"] != b["block_sha256"]


# --------------------------------------------------------------------------
# Census, anchors, no-emission contract
# --------------------------------------------------------------------------

def test_census_reports_anchor_agree_and_disagree(tmp_path):
    p2_ok = bytearray(256)
    p2_ok[5 * 16 + 1] = 0x8E                       # GEO2#20 (1,5) agrees
    p2_bad = bytearray(256)
    p2_bad[10 * 16 + 13] = 0x84                    # GEO2#20 (13,10): 0x83 expected
    # the block id 20 appears once; keep the first block as the anchor block
    install = make_install(tmp_path / "inst", {2: [(20, make_geo_raw(p2=bytes(p2_ok)))]})
    res = obs.build_result(install, [2])
    assert res["anchors"]
    by = {(a["geo"], a["block_id"], a["x"], a["y"]): a for a in res["anchors"]}
    assert by[(2, 20, 1, 5)]["status"] == "agrees"
    assert by[(2, 20, 13, 10)]["status"] == "disagrees"
    assert by[(2, 20, 13, 10)]["observed"] == 0

    install_b = make_install(tmp_path / "instb", {2: [(20, make_geo_raw(p2=bytes(p2_bad)))]})
    res_b = obs.build_result(install_b, [2])
    by_b = {(a["geo"], a["block_id"], a["x"], a["y"]): a for a in res_b["anchors"]}
    assert by_b[(2, 20, 13, 10)]["observed"] == 0x84
    assert by_b[(2, 20, 13, 10)]["status"] == "disagrees"


def test_missing_block_is_not_found_not_an_error(tmp_path):
    install = make_install(tmp_path / "inst", {1: [(7, make_geo_raw())]})
    res = obs.build_result(install, [1])
    statuses = {(a["geo"], a["block_id"]): a["status"] for a in res["anchors"]}
    assert statuses[(1, 18)] == "block-not-found"


def test_duplicate_block_id_makes_anchor_ambiguous(tmp_path):
    first = bytearray(256)
    second = bytearray(256)
    first[5 * 16 + 1] = 0x8E
    second[5 * 16 + 1] = 0x01
    install = make_install(tmp_path / "inst", {
        2: [(20, make_geo_raw(p2=bytes(first))),
            (20, make_geo_raw(p2=bytes(second)))]})
    res = obs.build_result(install, [2])
    anchor = next(a for a in res["anchors"]
                  if (a["geo"], a["block_id"], a["x"], a["y"]) == (2, 20, 1, 5))
    assert anchor["status"] == "ambiguous-block-id"
    assert anchor["candidates"] == [
        {"toc_index": 0, "observed": 0x8E},
        {"toc_index": 1, "observed": 0x01},
    ]
    report = obs.render_report(res)
    assert "ambiguous-block-id" in report
    assert "idx 0: 0x8E, idx 1: 0x01" in report


def test_malformed_block_is_recorded_and_census_continues(tmp_path):
    good = make_geo_raw()
    bad_raw = struct.pack("<H", 1024) + bytes(10)  # wrong length for a GEO block
    tmp = tmp_path / "inst"
    tmp.mkdir()
    (tmp / "GEO3.DAX").write_bytes(make_dax([
        (14, rle_literal(bad_raw), len(bad_raw)),
        (0, rle_literal(good), len(good)),
    ]))
    res = obs.build_result(tmp, [3])
    assert len(res["blocks"]) == 2
    assert "error" in res["blocks"][0]
    assert res["blocks"][1]["block_id"] == 0
    assert res["blocks"][1]["cells"] == 256


def test_result_emits_nothing_and_maps_nothing(tmp_path):
    p2 = bytearray(256)
    p2[0] = 0x81
    install = make_install(tmp_path / "inst", {1: [(18, make_geo_raw(p2=bytes(p2)))]})
    res = obs.build_result(install, [1])
    assert res["status"] == "observe-only"
    assert res["emitted"] == []
    assert res["mappings"] == []
    text = json.dumps(res)
    assert "zone_map" not in text and "event_map" not in text


def test_hypotheses_are_all_unresolved_with_falsifiers():
    ids = [h["id"] for h in obs.HYPOTHESES]
    assert ids == ["H1", "H2", "H3", "H4", "H5"]
    for h in obs.HYPOTHESES:
        assert h["falsifier"] and h["settles_with"]
        assert "status" not in h


def test_goldbox_por_anchors_are_title_scoped_crosschecks():
    tiers = {a[5] for a in obs.ANCHORS}
    assert tiers == {"retail-recorded", "goldbox-por-cross-check"}
    assert all(a[5] == "goldbox-por-cross-check"
               for a in obs.ANCHORS if a[0] == 1 and a[1] == 18)


def test_report_states_observe_only(tmp_path):
    install = make_install(tmp_path / "inst", {1: [(18, make_geo_raw())]})
    md = obs.render_report(obs.build_result(install, [1]))
    assert "observe-only" in md
    assert "Not claimed" in md


# --------------------------------------------------------------------------
# Refusals and immutability
# --------------------------------------------------------------------------

def test_output_inside_install_is_refused(tmp_path):
    install = make_install(tmp_path / "inst", {1: [(18, make_geo_raw())]})
    rc = obs.main(["--install", str(install), "--geo", "1",
                   "-o", str(install / "out")])
    assert rc == 2
    assert not (install / "out").exists()


def test_run_writes_outside_and_leaves_install_unchanged(tmp_path):
    install = make_install(tmp_path / "inst", {1: [(18, make_geo_raw())]})
    before = _tree_hashes(install)
    out = tmp_path / "report"
    rc = obs.main(["--install", str(install), "--geo", "1", "-o", str(out)])
    assert rc == 0
    assert _tree_hashes(install) == before
    data = json.loads((out / "por_geo_plane2_observe.json").read_text(encoding="utf-8"))
    assert data["emitted"] == [] and data["mappings"] == []


# --------------------------------------------------------------------------
# Retail anchor (gated)
# --------------------------------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_INSTALL")


@pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_INSTALL to the PoR POOLRAD folder")
def test_retail_census_and_anchors_unchanged(tmp_path):
    install = Path(RETAIL)
    before = _tree_hashes(install) if install.is_dir() else None
    res = obs.build_result(install, list(range(1, 9)))
    assert len(res["blocks"]) == 29
    assert all("error" not in b for b in res["blocks"])
    assert res["emitted"] == [] and res["mappings"] == []
    assert {a["status"] for a in res["anchors"]} == {"agrees"}
    assert len(res["anchors"]) == 5
    if before is not None:
        assert before == _tree_hashes(install)
