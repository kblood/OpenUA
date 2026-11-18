"""Tests for tools/por_area_evidence.py (GEO map-load evidence probe).

Synthetic fixtures for the logic: a GAME.OVR-shaped blob with a Turbo Pascal
style literal block and a layout-owner procedure, and a POOLRAD-shaped install
with synthetic GEO archives. The retail anchor runs only when the local install
is present and is skipped otherwise.
"""
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, TESTS)
import por_area_evidence as ev  # noqa: E402
from test_por_map import geo_raw, make_dax, _fixture_cells  # noqa: E402

RETAIL = Path(os.environ.get("OPENUA_POR_INSTALL") or "G:/Games/Pool of Radiance/POOLRAD")
RETAIL_GEO_LITERAL = 0x2F994     # "\x03GEO\x04.dax" block start in GAME.OVR
RETAIL_OWNER = 0x2F6FF           # layout owner: push bp at this offset, retf 4 at 0x2F991
RETAIL_WALL_LITERAL = 0x2F6AB    # "\x07WALLDEF\x04.dax" block start in GAME.OVR
RETAIL_WALL_OWNER = 0x2EEF4      # layout owner: 827 instructions, retf 6 at 0x2F6A8


def _tree_hashes(root: Path) -> dict:
    out = {}
    for dirpath, _d, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def ovr_fixture():
    """Layout: a procedure at P (push bp; mov bp,sp; cmp [bp+6],1; jb; nop nop;
    mov sp,bp; pop bp; retf 4) whose retf ends exactly where a Pascal literal block
    "\\x03GEO\\x04.dax ..." begins; one near call to P from later in the blob."""
    body = bytearray(b"\x90" * 16)
    p = len(body)
    body += b"\x55\x89\xe5" + b"\x80\x7e\x06\x01" + b"\x72\x02" + b"\x90\x90"
    body += b"\x89\xec\x5d\xca\x04\x00"
    block = len(body)
    body += b"\x03GEO\x04.dax Unable to load geo in Load3DMap."
    body += b"\x90" * 8
    call_at = len(body)
    body += b"\xe8" + struct.pack("<h", p - (call_at + 3)) + b"\x90"
    body += b"\x90" * 8
    return bytes(body), p, block, call_at


def long_owner_fixture(n_insns=827):
    """A procedure of exactly ``n_insns`` instructions (push bp; mov bp,sp; nops;
    mov sp,bp; pop bp; retf 6) whose retf ends where a WALLDEF literal block begins."""
    body = bytearray(b"\x90" * 16)
    p = len(body)
    body += b"\x55\x89\xe5" + b"\x90" * (n_insns - 5)
    body += b"\x89\xec\x5d\xca\x06\x00"
    block = len(body)
    body += b"\x07WALLDEF\x04.dax Wall art file name."
    body += b"\x90" * 8
    return bytes(body), p, block


def make_install(root: Path, *, sub="POOLRAD", ovr=None, geo3_corrupt=False) -> Path:
    install = root / "install"
    folder = install / sub if sub else install
    folder.mkdir(parents=True)
    (folder / "GAME.OVR").write_bytes(ovr if ovr is not None else ovr_fixture()[0])
    (folder / "START.EXE").write_bytes(b"MZ" + b"\x00" * 300)
    for n in range(1, 9):
        raw = make_dax([(10 * n + k, geo_raw(_fixture_cells)) for k in range(2)])
        if n == 3 and geo3_corrupt:
            raw = raw[:-3]
        (folder / ("GEO%d.DAX" % n)).write_bytes(raw)
    (folder / "SAVGAMA.DAT").write_bytes(b"A" * 40)
    (folder / "SAVGAMJ.DAT").write_bytes(b"J" * 40)
    return install


def run_probe(install, out, *, allow_unpinned=True, artifacts=None):
    return ev.probe(install, out, allow_unpinned=allow_unpinned, artifacts=artifacts)


# ---- pure helpers -----------------------------------------------------------

def test_literal_piece_chain_takes_the_last_fragment():
    data = b"\x0c\x00\x03MON\x03CHA\x04.dax" + b"\x00"
    rows = ev.dax_literals(data)
    assert len(rows) == 1
    assert rows[0]["piece"] == "CHA"
    assert rows[0]["suffix_offset"] == data.index(b"\x04.dax")
    assert rows[0]["block_start"] == data.index(b"\x03CHA")


def test_literal_block_start_is_the_length_byte_of_the_piece():
    data, _p, block, _c = ovr_fixture()
    rows = ev.dax_literals(data)
    geo = [r for r in rows if r["piece"] == "GEO"]
    assert len(geo) == 1
    assert geo[0]["block_start"] == block
    assert geo[0]["extension"] == ".dax"


def test_layout_owner_is_the_unique_procedure_ending_at_the_block():
    data, p, block, _c = ovr_fixture()
    own = ev.owner_for(data, block)
    assert own["status"] == "layout-unique"
    assert own["owner"] == p
    assert own["matches"] == [p]


def test_walk_bound_is_the_prologue_window():
    # A matching walk spans at most PROLOGUE_WINDOW bytes, so it needs at most that
    # many instructions; the bound must not be smaller.
    assert ev.MAX_WALK == ev.PROLOGUE_WINDOW


def test_layout_owner_of_827_instructions_is_detected_under_the_default_bound():
    data, p, block = long_owner_fixture(827)
    own = ev.owner_for(data, block)
    assert own["status"] == "layout-unique"
    assert own["owner"] == p
    assert own["truncated_walks"] == 0
    facts = ev.proc_facts(data, p)
    assert facts["instructions"] == 827
    assert facts["ret_flow"] == "retf" and facts["ret_imm"] == 6


def test_a_bound_below_the_owner_length_hides_it_and_is_reported(monkeypatch):
    data, _p, block = long_owner_fixture(827)
    monkeypatch.setattr(ev, "MAX_WALK", 800)
    own = ev.owner_for(data, block)
    assert own["status"] == "no-layout-match"
    assert own["truncated_walks"] >= 1


def test_no_owner_without_a_block_start():
    data, _p, _b, _c = ovr_fixture()
    assert ev.owner_for(data, None)["status"] == "no-block-start"


def test_owner_rejects_a_block_not_preceded_by_a_return():
    data, _p, block, _c = ovr_fixture()
    # Move the block one byte: nothing ends a procedure at block+1 - 1.
    own = ev.owner_for(data, block + 1)
    assert own["owner"] is None


def test_proc_facts_report_arguments_and_return_width():
    data, p, block, _c = ovr_fixture()
    facts = ev.proc_facts(data, p)
    assert facts["status"] == "decoded"
    assert facts["ret_flow"] == "retf"
    assert facts["ret_imm"] == 4
    cmps = [(c["bp_disp"], c["imm"]) for c in facts["arg_compares"]]
    assert cmps == [(6, 1)]


def test_near_call_candidate_is_found_and_decoded_as_call():
    data, p, _b, call_at = ovr_fixture()
    hits = ev.near_calls_to(data, p)
    assert [h["offset"] for h in hits] == [call_at]
    assert hits[0]["decoded_flow"] == "call"
    assert hits[0]["target"] == p


def test_near_call_to_a_different_target_is_not_reported():
    data, p, _b, _c = ovr_fixture()
    assert ev.near_calls_to(data, p + 1) == []


def test_string_base_test_counts_bases_where_all_operands_are_strings():
    # Operand 0 with base 0 names the length byte of "ABC" at offset 0.
    data = b"\x03ABC" + b"\x00" * 16
    res = ev.string_base_test(data, [0])
    assert res["bases_all_strings"] >= 1
    assert "0x0" in res["first_bases"]


def test_string_base_test_zero_when_operands_are_not_strings():
    data = b"\x00" * 64
    res = ev.string_base_test(data, [3, 9])
    assert res["bases_all_strings"] == 0
    assert res["bases_tested"] == len(data)


def test_empty_operand_list_tests_nothing():
    assert ev.string_base_test(b"\x03ABC", [])["bases_tested"] == 0


def test_mov_immediate_before_push_cs_is_a_cs_operand_candidate():
    # mov di, 0x0DB4 ; push cs ; push di
    data = b"\xbf\xb4\x0d\x0e\x57" + b"\x90" * 4
    insns, _ = ev.handler.linear(data, 0, 8)
    ops = ev.cs_string_operands(insns)
    assert ops == [{"offset": 0, "imm": 0x0DB4}]


# ---- probe on the synthetic install ----------------------------------------

def test_probe_emits_no_mapping_and_names_unknowns(tmp_path):
    inst = make_install(tmp_path)
    doc, code = run_probe(inst, tmp_path / "out")
    assert doc["mappings"] == []
    assert doc["playable"] is False
    names = {u["field"] for u in doc["unknown"]}
    assert {"block_to_area", "start_area", "start_entry"} <= names
    lr = doc["load_routine"]
    assert lr is not None and lr["claim_level"].startswith("layout candidate")
    assert lr["stub_export_matches"] == []
    assert code == 1  # pins do not match the synthetic fixture


def test_probe_writes_json_and_report(tmp_path):
    inst = make_install(tmp_path)
    run_probe(inst, tmp_path / "out")
    j = json.loads((tmp_path / "out" / "por_area_evidence.json").read_text(encoding="utf-8"))
    assert j["schema"] == ev.SCHEMA and j["playable"] is False
    assert (tmp_path / "out" / "por_area_evidence_report.md").is_file()


def test_probe_refuses_unpinned_without_flag(tmp_path, capsys):
    inst = make_install(tmp_path)
    rc = ev.main(["--install", str(inst), "-o", str(tmp_path / "out")])
    assert rc == 2
    assert "pinned" in capsys.readouterr().err


def test_output_inside_install_is_refused(tmp_path, capsys):
    inst = make_install(tmp_path)
    folder = inst / "POOLRAD"
    rc = ev.main(["--install", str(inst), "-o", str(folder / "evidence"), "--allow-unpinned"])
    assert rc == 2


def test_missing_install_files_are_a_refusal(tmp_path, capsys):
    rc = ev.main(["--install", str(tmp_path), "-o", str(tmp_path / "out"), "--allow-unpinned"])
    assert rc == 2


def test_corrupt_archive_is_recorded_and_exit_is_one(tmp_path):
    inst = make_install(tmp_path, geo3_corrupt=True)
    doc, code = run_probe(inst, tmp_path / "out")
    statuses = {a["file"]: a["status"] for a in doc["source"]["geo_archives"]}
    assert statuses["GEO3.DAX"] == "refused"
    assert statuses["GEO1.DAX"] == "parsed"
    assert doc["diagnostics"] and "GEO3.DAX refused" in doc["diagnostics"][0]
    assert code == 1


def test_deterministic_and_install_unchanged(tmp_path):
    inst = make_install(tmp_path)
    before = _tree_hashes(inst)
    run_probe(inst, tmp_path / "a")
    run_probe(inst, tmp_path / "b")
    assert _tree_hashes(inst) == before
    for name in ("por_area_evidence.json", "por_area_evidence_report.md"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_no_absolute_path_in_outputs(tmp_path):
    inst = make_install(tmp_path)
    run_probe(inst, tmp_path / "out")
    text = (tmp_path / "out" / "por_area_evidence.json").read_text(encoding="utf-8")
    text += (tmp_path / "out" / "por_area_evidence_report.md").read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert str(inst) not in text


def test_run_artifacts_count_only_geo_dax_lines_in_logs(tmp_path):
    inst = make_install(tmp_path)
    art = tmp_path / "art"
    (art / "sub").mkdir(parents=True)
    (art / "run.log").write_text("open GEO2.DAX\nopen game.ovr\nseek GEO8.dax 12\n", encoding="utf-8")
    (art / "sub" / "x.log").write_text("nothing here\n", encoding="utf-8")
    (art / "notes.txt").write_text("GEO1.DAX mentioned in a txt file\n", encoding="utf-8")
    doc, _ = run_probe(inst, tmp_path / "out", artifacts=art)
    ra = doc["run_artifacts"]
    assert ra["status"] == "scanned"
    assert ra["files_scanned"] == 2
    assert ra["geo_dax_lines"] == 2
    assert {f["name"] for f in ra["per_file"]} == {"run.log", "sub/x.log"}


def test_run_artifacts_not_requested_by_default(tmp_path):
    inst = make_install(tmp_path)
    doc, _ = run_probe(inst, tmp_path / "out")
    assert doc["run_artifacts"] == {"status": "not-requested"}


# ---- retail anchor (skipped when the install is absent) ----------------------

@pytest.mark.skipif(not (RETAIL / "GAME.OVR").is_file(),
                    reason="retail PoR install not present")
def test_retail_anchor(tmp_path):
    doc, code = ev.probe(RETAIL, tmp_path / "retail", allow_unpinned=False)
    assert code == 0
    assert doc["source"]["all_pins_match"] is True
    assert doc["source"]["install_unchanged"] is True
    assert doc["geo_toc"]["block_count"] == 29
    assert doc["geo_toc"]["block_ids_absent_in_0_to_32"] == [8, 11, 12, 19]
    assert doc["geo_toc"]["duplicate_block_ids_within_install"] == []
    geo = [r for r in doc["literals"] if r["piece"] == "GEO" and r["file"] == "GAME.OVR"]
    assert len(geo) == 1
    assert geo[0]["block_start"] == RETAIL_GEO_LITERAL
    assert geo[0]["owner"]["status"] == "layout-unique"
    assert geo[0]["owner"]["owner"] == RETAIL_OWNER
    assert geo[0]["overlay_group"] == "uncovered"
    wall = [r for r in doc["literals"] if r["piece"] == "WALLDEF" and r["file"] == "GAME.OVR"]
    assert len(wall) == 1
    assert wall[0]["block_start"] == RETAIL_WALL_LITERAL
    assert wall[0]["owner"]["status"] == "layout-unique"
    assert wall[0]["owner"]["owner"] == RETAIL_WALL_OWNER
    assert wall[0]["owner"]["truncated_walks"] == 0
    wf = wall[0]["owner"]["facts"]
    assert wf["instructions"] == 827
    assert (wf["ret_flow"], wf["ret_imm"], wf["ret_offset"]) == ("retf", 6, 0x2F6A8)
    lr = doc["load_routine"]
    assert lr["owner"] == RETAIL_OWNER
    assert lr["string_operand_base_test"]["bases_all_strings"] == 0
    assert lr["near_callers"] == []
    assert lr["stub_export_matches"] == []
    assert doc["mappings"] == []
    cmps = [(c["bp_disp"], c["imm"]) for c in lr["facts"]["arg_compares"] if c["bp_disp"] > 0]
    assert (6, 1) in cmps and (6, 3) in cmps
    presence = doc["external_leads"][0]["dos_toc_presence"]
    assert presence["15"] == [{"geo": 2, "toc_index": 1}]
    assert presence["16"] == [{"geo": 8, "toc_index": 1}]
