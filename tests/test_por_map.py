"""Tests for tools/por_map.py (Pool of Radiance GEO block -> map-only design).

Fixture contract (synthetic; no retail data is needed or used):
  * DAX container: 2-byte TOC size, 9-byte TOC entries, contiguous data chain
    from offset 0 closing exactly at EOF, signed-byte RLE blocks (the layout in
    GoldBox docs/dax-format.md). `make_dax` below writes that layout.
  * Gen1 GEO block: 1026 bytes = uint16 LE 1024, then four 256-byte planes,
    cell index y*16+x. Plane 0 = N<<4|E, plane 1 = S<<4|W, plane 2 =
    descriptor, plane 3 = door flags (N 0-1, E 2-3, S 4-5, W 6-7). `geo_raw`
    below writes that layout.
These pin OUR decoder to the documented contract. They do not prove that a
retail PoR block decodes this way; that remains open (see docs/por-converter.md).
"""
import hashlib
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_map as pm  # noqa: E402
from geo import Geo  # noqa: E402
from dsn import ART_BLOCK  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---- synthetic writers (test-only) -----------------------------------------

def rle_encode(data: bytes) -> bytes:
    """Signed-byte RLE with the writer envelope from docs/dax-format.md §2a:
    literal runs capped at 126 (control 0x7D), repeat runs at 127 (0x81)."""
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
    """blocks: list of (block_id, raw_bytes). Returns a well-formed DAX."""
    toc = bytearray()
    body = bytearray()
    off = 0
    for bid, raw in blocks:
        comp = rle_encode(raw)
        toc += struct.pack("<BIHH", bid, off, len(raw), len(comp))
        body += comp
        off += len(comp)
    return struct.pack("<H", len(toc)) + bytes(toc) + bytes(body)


def geo_raw(cell_fn=None) -> bytes:
    """cell_fn(x, y) -> (N, E, S, W, descriptor), each wall (slot, door)."""
    planes = [bytearray(256) for _ in range(4)]
    for y in range(16):
        for x in range(16):
            if cell_fn is None:
                n = e = s = w = (0, 0)
                desc = 0
            else:
                n, e, s, w, desc = cell_fn(x, y)
            i = y * 16 + x
            planes[0][i] = (n[0] << 4) | e[0]
            planes[1][i] = (s[0] << 4) | w[0]
            planes[2][i] = desc
            planes[3][i] = n[1] | (e[1] << 2) | (s[1] << 4) | (w[1] << 6)
    return struct.pack("<H", 1024) + b"".join(bytes(p) for p in planes)


OPEN = (0, 0)


def _fixture_cells(x, y):
    """A small synthetic room: solid perimeter on N/S/E/W, one open passage
    east of (3,5), one door (flag 1) on the north of (7,2), one locked edge
    (flag 2) on the south of (10,10), and a descriptor value at (1,5)."""
    n = s = e = w = (0, 0)
    if y == 0:
        n = (3, 0)
    if y == 15:
        s = (3, 0)
    if x == 0:
        w = (3, 0)
    if x == 15:
        e = (3, 0)
    if (x, y) == (3, 5):
        e = (0, 0)
    if (x, y) == (7, 2):
        n = (9, 1)
    if (x, y) == (10, 10):
        s = (6, 2)
    desc = 0x8E if (x, y) == (1, 5) else 0
    return n, e, s, w, desc


def run(argv, capsys=None):
    return pm.main(argv)


def make_install(root: Path, blocks=None, name="GEO1.DAX", sub="POOLRAD") -> Path:
    """A synthetic DOS-install-shaped folder (GOG layout: POOLRAD/GEO1.DAX)."""
    install = root / "install"
    target_dir = install / sub if sub else install
    target_dir.mkdir(parents=True)
    if blocks is None:
        blocks = [(18, geo_raw(_fixture_cells))]
    (target_dir / name).write_bytes(make_dax(blocks))
    return install


def _tree_hashes(root: Path) -> dict:
    out = {}
    for dirpath, _d, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


# ---- RLE ----------------------------------------------------------------------

def test_rle_roundtrip_mixed_runs():
    data = bytes([1, 2, 3]) + bytes([9]) * 300 + bytes(range(200)) + bytes([7]) * 2
    assert pm.rle_decode(rle_encode(data), len(data)) == data


def test_rle_control_bytes_match_envelope():
    # 0x81 = 127 repeats; 0x7D = 126 literals (see docs/dax-format.md §2a)
    assert pm.rle_decode(bytes([0x81, 0x55]), 127) == b"\x55" * 127
    assert pm.rle_decode(bytes([0x00, 0xAA, 0x01, 0xBB, 0xCC]), 3) == b"\xAA\xBB\xCC"


@pytest.mark.parametrize("comp,raw,msg", [
    (bytes([0x05, 1, 2]), 6, "literal run overruns"),
    (bytes([0x81]), 127, "no value byte"),
    (bytes([0x81, 0x55]), 10, "exceeds the TOC raw size"),
    (bytes([0x81, 0x55]), 100, "exceeds the TOC raw size"),
    (bytes([0x00, 0xAA]), 2, "TOC raw size is 2"),
])
def test_rle_rejects_malformed(comp, raw, msg):
    with pytest.raises(pm.PorMapError, match=msg):
        pm.rle_decode(comp, raw)


# ---- DAX container -----------------------------------------------------------

def test_dax_toc_and_chain_parse():
    dax = make_dax([(18, b"\x00" * 1026), (20, b"\x01" * 50)])
    entries, base = pm.parse_dax(dax)
    assert base == 2 + 18
    assert [(e.block_id, e.raw_size) for e in entries] == [(18, 1026), (20, 50)]
    assert entries[1].data_offset == entries[0].comp_size


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d[:1], "no TOC size"),
    (lambda d: struct.pack("<H", 10) + d[2:], "multiple of 9"),
    (lambda d: struct.pack("<H", 0) + d[2:], "multiple of 9"),
    (lambda d: struct.pack("<H", 9 * 900) + d[2:], "past end of file"),
    (lambda d: d[:-3], "truncated or trailing"),
    (lambda d: d + b"\x00", "truncated or trailing"),
])
def test_dax_rejects_malformed_container(mutate, msg):
    dax = make_dax([(18, b"\x00" * 1026)])
    with pytest.raises(pm.PorMapError, match=msg):
        pm.parse_dax(mutate(dax))


def test_dax_rejects_broken_chain():
    dax = bytearray(make_dax([(18, b"\x01" * 40), (20, b"\x02" * 40)]))
    # data_offset of entry 1 lives at 2 + 9 + 1
    struct.pack_into("<I", dax, 2 + 9 + 1, 5)
    with pytest.raises(pm.PorMapError, match="contiguous"):
        pm.parse_dax(bytes(dax))


# ---- block selection ----------------------------------------------------------

def test_select_block_rules():
    entries, _ = pm.parse_dax(make_dax([(18, b"\x00" * 4), (20, b"\x00" * 4),
                                        (20, b"\x01" * 4)]))
    assert pm.select_block(entries, 18, None).index == 0
    with pytest.raises(pm.PorMapError, match="appears 2 times"):
        pm.select_block(entries, 20, None)
    assert pm.select_block(entries, 20, 2).index == 2
    with pytest.raises(pm.PorMapError, match="out of range"):
        pm.select_block(entries, None, 9)
    with pytest.raises(pm.PorMapError, match="holds block 18"):
        pm.select_block(entries, 19, 0)
    with pytest.raises(pm.PorMapError, match="no block id 77"):
        pm.select_block(entries, 77, None)
    with pytest.raises(pm.PorMapError, match="name a block"):
        pm.select_block(entries, None, None)


# ---- GEO block decode ----------------------------------------------------------

def test_geo_plane_layout_at_known_cell():
    """Cell (x=3, y=5) lives at index 83 in every plane (y*16+x)."""
    raw = bytearray(geo_raw(lambda x, y: ((0, 0), (0, 0), (0, 0), (0, 0), 0)))
    i = 5 * 16 + 3
    raw[2 + i] = (7 << 4) | 4                  # plane 0: N=7, E=4
    raw[2 + 256 + i] = (9 << 4) | 2            # plane 1: S=9, W=2
    raw[2 + 512 + i] = 0x8E                    # plane 2: descriptor
    raw[2 + 768 + i] = 0b10_01_11_00           # plane 3: W=2 S=1 E=3 N=0
    cells = pm.decode_gen1_geo(bytes(raw))
    c = cells[i]
    assert (c["x"], c["y"], c["index"]) == (3, 5, 83)
    assert c["edges"] == {"N": (7, 0), "E": (4, 3), "S": (9, 1), "W": (2, 2)}
    assert c["planes"][2] == 0x8E


def test_geo_rejects_bad_block():
    good = geo_raw()
    with pytest.raises(pm.PorMapError, match="must be 1026"):
        pm.decode_gen1_geo(good[:-1])
    with pytest.raises(pm.PorMapError, match="must be 1026"):
        pm.decode_gen1_geo(good + b"\x00")
    with pytest.raises(pm.PorMapError, match="size field is 1023"):
        pm.decode_gen1_geo(struct.pack("<H", 1023) + good[2:])


# ---- edge mapping ------------------------------------------------------------

@pytest.mark.parametrize("slot,door,byte,rule", [
    (0, 0, 0x00, "open"),
    (0, 3, 0x00, "open"),          # no wall: the door byte is ignored
    (5, 0, 0xE5, "solid"),
    (5, 1, 0x15, "auto-door"),     # passes automatically -> secret-door passage
    (5, 2, 0xF5, "locked"),       # PoR DOS runtime example: interaction-gated
    (5, 3, 0xF5, "door3-unresolved"),  # same byte for now; PoR meaning open
])
def test_map_edge_table(slot, door, byte, rule):
    assert pm.map_edge(slot, door) == (byte, rule)


def test_door_two_and_three_keep_same_byte_but_distinct_evidence_labels():
    # Door 2 has one PoR DOS locked-door interaction trace. Door 3 is still
    # only a CoK-derived hypothesis; preserve bytes until its semantics resolve.
    assert pm.map_edge(10, 2) == (0xFA, "locked")
    assert pm.map_edge(10, 3) == (0xFA, "door3-unresolved")
    evidence = pm.EDGE_MAPPING_EVIDENCE
    assert evidence["por_door_rule_proven"] is False
    assert evidence["status"] == "single-por-runtime-case; general-mapping-unverified"
    assert "GEO2.DAX block 20" in evidence["por_runtime_observation"]["case"]


# ---- OpenUA geo: coordinate and wall mapping -------------------------------

def test_openua_geo_coordinates_are_not_transposed():
    """Gen1 (x,y) -> OpenUA cell(col=x, row=y); FRUA stores edges W,S,E,N."""
    cells = pm.decode_gen1_geo(geo_raw(lambda x, y: (
        (2, 0), (4, 0), (6, 0), (8, 0), 0) if (x, y) == (3, 5) else (
        (0, 0), (0, 0), (0, 0), (0, 0), 0)))
    g = pm.build_openua_geo(cells, (3, 5, 1))
    assert g.width == 16 and g.height == 16
    cell = g.cell(3, 5)
    assert list(cell[:4]) == [0xE8, 0xE6, 0xE4, 0xE2]
    # the transposed cell (5,3) and its neighbours stay open
    assert list(g.cell(5, 3)[:4]) == [0, 0, 0, 0]
    assert g.entry_point(0) == (5, 3, 1)        # (row, col, facing)
    assert Geo.parse(g.build()).cell(3, 5) == cell
    assert bytes(g.hdr[4:14]) == ART_BLOCK


def test_openua_geo_builds_round_trip_and_fixed_size():
    cells = pm.decode_gen1_geo(geo_raw(_fixture_cells))
    raw = pm.build_openua_geo(cells, (3, 5, 1)).build()
    assert len(raw) == 12962
    back = Geo.parse(raw)
    assert list(back.cell(7, 2)[:4]) == [0, 0, 0, 0x19]     # N slot 9 door 1 -> secret-door passage
    assert list(back.cell(10, 10)[:4]) == [0, 0xF6, 0, 0]   # S slot 6 door 2 -> blocked (bash/knock)
    assert list(back.cell(1, 5)[:4]) == [0, 0, 0, 0]        # descriptor 0x8E is not mapped
    assert back.cell_special(1, 5) == 0
    assert list(back.cell(0, 5)[:4]) == [0xE3, 0, 0, 0]     # W perimeter: slot 3 solid


# ---- diagnostics -------------------------------------------------------------

def test_reachability_open_and_sealed():
    open_cells = pm.decode_gen1_geo(geo_raw())
    assert len(pm.entry_reachable(open_cells, 0, 0)) == 256
    sealed = pm.decode_gen1_geo(geo_raw(lambda x, y: ((1, 0), (1, 0), (1, 0), (1, 0), 0)))
    assert pm.entry_reachable(sealed, 4, 4) == {(4, 4)}


def test_reachability_respects_locked_edges():
    # door flag 2 on an edge is not an unconditional exit
    cells = pm.decode_gen1_geo(geo_raw(lambda x, y: (
        (0, 0), (1, 2), (1, 0), (1, 0), 0) if (x, y) == (0, 0) else (
        (1, 0), (1, 0), (1, 0), (1, 0), 0)))
    assert pm.entry_reachable(cells, 0, 0) == {(0, 0)}


def test_shared_edge_stats_detects_disagreement():
    cells = pm.decode_gen1_geo(geo_raw())
    assert pm.shared_edge_stats(cells) == {"shared_edges": 480,
                                           "slot_agree": 480, "slot_disagree": 0}
    cells = pm.decode_gen1_geo(geo_raw(lambda x, y: (
        (0, 0), (0, 0), (5, 0), (0, 0), 0) if (x, y) == (2, 2) else (
        (0, 0), (0, 0), (0, 0), (0, 0), 0)))
    s = pm.shared_edge_stats(cells)
    assert s["slot_disagree"] == 1


# ---- parsing helpers ---------------------------------------------------------

def test_expectation_parsing():
    assert pm.parse_expectation("1,5=0x8e") == {"x": 1, "y": 5, "value": 0x8E, "mask": 0xFF}
    assert pm.parse_expectation("7,8=0x02/0x7f") == {"x": 7, "y": 8, "value": 2, "mask": 0x7F}
    for bad in ("1,5", "x,y=1", "16,0=1", "1,1=0x100"):
        with pytest.raises(pm.PorMapError):
            pm.parse_expectation(bad)


def test_point_parsing_rejects_out_of_range():
    assert pm.parse_point("3,5") == (3, 5)
    for bad in ("16,0", "0,-1", "3", "a,b"):
        with pytest.raises(pm.PorMapError):
            pm.parse_point(bad)


# ---- end to end --------------------------------------------------------------

def test_end_to_end_emits_map_only_design(tmp_path, capsys):
    install = make_install(tmp_path)
    before = _tree_hashes(install)
    out = tmp_path / "out"
    rc = run(["--install", str(install), "--geo", "1", "--block", "18",
              "--entry", "3,5", "--facing", "east", "--area", "5",
              "--name", "PORMAP", "--expect", "1,5=0x8e", "-o", str(out)])
    assert rc == 0
    assert _tree_hashes(install) == before, "source must be untouched"

    import json
    norm = json.loads((out / "por_map.json").read_text(encoding="utf-8"))
    assert norm["status"] == "map-only" and norm["playable"] is False
    assert norm["edge_mapping_evidence"] == {
        "status": "single-por-runtime-case; general-mapping-unverified",
        "source_boundary": "PoR DOS runtime supports interaction-gated crossing for one flag-2 edge; GEO field binding and general semantics remain open; flag 3 is CoK-only hypothesis",
        "por_door_rule_proven": False,
        "wall_art_binding_proven": False,
        "por_runtime_observation": {
            "source": "GoldBox read-only reference: docs/engine/research/gen1-dosbox-runtime-trace.md, PoR DOS runtime sections dated 2026-07-22",
            "case": "GEO2.DAX block 20, cell (14,10), west, wall slot 10, observed plane-3 flag 2",
            "outcome": "LOCKED. BASH PICK EXIT; Pick failed in one attempt; Bash succeeded, party crossed to (13,10), and the original persisted the opened edge",
            "scope": "one native route observation; not a full proof that every stored flag-2 byte feeds this runtime edge reader",
        },
    }
    assert norm["source"]["block_id"] == 18 and norm["source"]["raw_size"] == 1026
    assert norm["source"]["sha256"] == hashlib.sha256(
        (install / "POOLRAD" / "GEO1.DAX").read_bytes()).hexdigest()
    assert norm["expectations"][0]["ok"] is True
    assert len(norm["cells"]) == 256

    report = (out / "por_map_report.md").read_text(encoding="utf-8")
    assert "MAP-ONLY" in report and "Not a playable module claim" in report
    assert "One PoR DOS runtime route supports" in report
    assert "Flag 3 is a CoK-only hypothesis" in report
    assert "ECL scripts and every event" in report

    dsn = out / "PORMAP.DSN"
    game = (dsn / "GAME001.DAT").read_bytes()
    assert game[48] == 5 and game[49] == 1           # start area, entry 1
    geo = Geo.parse((dsn / "GEO005.DAT").read_bytes())
    assert geo.width == 16 and geo.height == 16
    assert geo.entry_point(0) == (5, 3, 1)           # row, col, facing east


def test_end_to_end_is_deterministic(tmp_path):
    install = make_install(tmp_path)
    outs = []
    for name in ("a", "b"):
        out = tmp_path / name
        assert run(["--install", str(install), "--geo", "1", "--block", "18",
                    "--entry", "3,5", "-o", str(out)]) == 0
        outs.append(out)
    assert _tree_hashes(outs[0]) == _tree_hashes(outs[1])


def test_dax_explicit_path_and_index(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    p = src / "GEO8.DAX"
    p.write_bytes(make_dax([(18, geo_raw()), (29, geo_raw(_fixture_cells))]))
    out = tmp_path / "out"
    assert run(["--dax", str(p), "--index", "1", "-o", str(out)]) == 0
    import json
    norm = json.loads((out / "por_map.json").read_text(encoding="utf-8"))
    assert norm["source"]["block_id"] == 29 and norm["openua"]["emitted"] is False


def test_list_prints_toc(tmp_path, capsys):
    p = tmp_path / "GEO1.DAX"
    p.write_bytes(make_dax([(18, geo_raw()), (20, geo_raw())]))
    assert run(["--dax", str(p), "--list"]) == 0
    text = capsys.readouterr().out
    assert "block_id" in text and "18" in text and "20" in text


def test_expectation_failure_exits_nonzero_but_writes(tmp_path, capsys):
    install = make_install(tmp_path)
    out = tmp_path / "out"
    rc = run(["--install", str(install), "--geo", "1", "--block", "18",
              "--expect", "1,5=0x00", "-o", str(out)])
    assert rc == 1
    assert "FAIL" in (out / "por_map_report.md").read_text(encoding="utf-8")


def test_refusals_exit_2(tmp_path, capsys):
    install = make_install(tmp_path)
    src_file = install / "POOLRAD" / "GEO1.DAX"
    base = ["--dax", str(src_file), "--block", "18"]
    # output inside the source folder
    assert run(base + ["-o", str(install / "POOLRAD" / "nested")]) == 2
    # output inside the repository, outside data/ (must not be created)
    stray = REPO_ROOT / "tools" / "por_map_should_not_exist"
    assert run(base + ["-o", str(stray)]) == 2
    assert not stray.exists()
    # no block selected
    assert run(["--dax", str(src_file), "-o", str(tmp_path / "x")]) == 2
    # missing source file is a named error, not a traceback
    assert run(["--dax", str(tmp_path / "nope.DAX"), "--block", "18",
                "-o", str(tmp_path / "x")]) == 2
    # bad entry, bad area, bad design name
    assert run(base + ["-o", str(tmp_path / "y"), "--entry", "16,0"]) == 2
    assert run(base + ["-o", str(tmp_path / "z"), "--entry", "1,1",
                       "--area", "0"]) == 2
    assert run(base + ["-o", str(tmp_path / "w"), "--entry", "1,1",
                       "--name", "TOOLONGNAME"]) == 2
    err = capsys.readouterr().err
    assert "por_map: error:" in err


def test_install_resolution(tmp_path):
    install = make_install(tmp_path, sub="")          # GEO1.DAX directly in root
    assert pm.resolve_geo(install, 1).name == "GEO1.DAX"
    with pytest.raises(pm.PorMapError, match="no GEO2.DAX"):
        pm.resolve_geo(install, 2)
    nested = make_install(tmp_path / "n", sub="POOLRAD")
    assert pm.resolve_geo(nested, 1).parent.name == "POOLRAD"
