"""Tests for the PoR DAX open-chain census (tools/por_geo_loader_open_chain_probe.py).

Synthetic tests need no install. The retail-gated test runs only when the pinned POOLRAD install is
present (OPENUA_POR_INSTALL or data/work/por-geo-run/POOLRAD).
"""
import os
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import por_geo_loader_open_chain_probe as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") else p.DEFAULT_INSTALL
HAVE_RETAIL = (INSTALL / "START.EXE").is_file() and (INSTALL / "GAME.OVR").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR START.EXE/GAME.OVR not present")


def _rows(data: bytes):
    return p.suffix_census(data, "T")


# --- Pascal piece census -------------------------------------------------------------------------

def test_two_name_pieces_form_one_chain_and_the_shorter_reading_is_flagged():
    row = _rows(b"\x03MON\x03CHA\x04.dax")[0]
    assert row["stem"] == "MON+CHA"
    assert row["stem_pieces"] == ["MON", "CHA"]
    assert row["ambiguous"] is True          # 'CHA' alone also parses; bytes do not choose


def test_single_geo_piece_is_unambiguous_with_its_length_offset():
    row = _rows(b"\x00\x00\x03GEO\x04.dax")[0]
    assert row["stem"] == "GEO"
    assert row["stem_len_at"] == "0x00002"
    assert row["suffix_len_at"] == "0x00006"
    assert row["ambiguous"] is False and row["bare"] is False


def test_message_text_before_a_name_is_rejected_not_taken_as_the_stem():
    row = _rows(b"\x15Loading...Please Wait\x03ECL\x04.dax")[0]
    assert row["stem"] == "ECL"
    assert row["rejected_non_name_parses"] >= 1


def test_bare_suffix_has_no_stem():
    row = _rows(b"\xcb\x04.dax")[0]
    assert row["bare"] is True and row["stem"] is None


def test_length_byte_falsifier_breaks_the_stem():
    row = _rows(b"\x02GEO\x04.dax")[0]
    assert row["bare"] is True and row["stem"] is None


def test_suffix_text_falsifier_removes_the_suffix_piece():
    assert _rows(b"\x03GEO\x04.daz") == []


def test_digit_piece_before_geo_is_reported_as_candidate_not_established():
    data = b"\x01\x31\x03GEO\x04.dax"
    row = _rows(data)[0]
    assert row["stem"] == "1+GEO"            # the digit piece joins the chain; census reports it
    cands = p.digit_pieces_near(data, row)
    assert cands == ["0x00000"]
    assert p.digit_slot_status(cands) == "candidate_digit_literal_unverified"
    assert p.digit_slot_status([]) == "not_established_no_digit_literal"


def test_no_digit_piece_beside_geo_in_synthetic_geo_run():
    data = b"\xcb\x03GEO\x04.dax\xcb"
    row = _rows(data)[0]
    assert p.digit_pieces_near(data, row) == []


# --- install slot cross-check --------------------------------------------------------------------

def test_install_slot_matches_are_counted_per_pattern():
    names = ["GEO1.DAX", "GEO8.DAX", "GEO.DAX", "MON1CHA.DAX", "8X8D1.DAX"]
    geo = p.install_matches(names, ["GEO"])
    assert geo["after_last"] == ["GEO1.DAX", "GEO8.DAX"]
    assert geo["exact_name"] == ["GEO.DAX"]
    mon = p.install_matches(names, ["MON", "CHA"])
    assert mon["between_pieces"] == ["MON1CHA.DAX"]
    assert p.install_matches(names, ["8X8d1"])["exact_name"] == ["8X8D1.DAX"]


# --- open-routine call scan ----------------------------------------------------------------------

def _start_with_call(site: int, target: int) -> bytearray:
    b = bytearray(0x9000)
    rel = target - (site + 3)
    b[site] = 0xE8
    b[site + 1:site + 3] = (rel & 0xFFFF).to_bytes(2, "little")
    return b


def test_single_near_call_site_to_open_routine_is_expected():
    got = p.open_call_scan(bytes(_start_with_call(p.OPEN_CALL_SITE, p.OPEN_ROUTINE)))
    assert got["near_pattern_candidates"] == ["0x087CC"]
    assert got["single_near_pattern_candidate_expected"] is True


def test_call_scan_falsifier_wrong_target_is_not_matched():
    got = p.open_call_scan(bytes(_start_with_call(p.OPEN_CALL_SITE, p.OPEN_ROUTINE + 1)))
    assert got["near_pattern_candidates"] == []
    assert got["single_near_pattern_candidate_expected"] is False


def test_far_call_to_open_routine_is_reported_and_fails_the_single_site_rule():
    b = bytearray(0x9000)
    b[0x100:0x105] = bytes.fromhex("9a 24 86 f8 0a")
    got = p.open_call_scan(bytes(b))
    assert got["far_pattern_candidates"] == ["0x00100"]
    assert got["single_near_pattern_candidate_expected"] is False


# --- memory presence -----------------------------------------------------------------------------

def test_relocated_far_call_segment_is_masked_for_memory_match():
    pat = bytes.fromhex("9a 0b 0b f8 0a 26")   # the segment word (f8 0a) differs live
    dump = b"\x00" * 16 + bytes.fromhex("9a 0b 0b 34 12 26") + b"\x00" * 8
    res = p.find_window(dump, pat)
    assert res == {"status": "unique", "linear": ["0x10"]}


def test_unmasked_byte_falsifier_makes_the_window_absent():
    pat = bytes.fromhex("9a 0b 0b f8 0a 26")
    dump = b"\x00" * 16 + bytes.fromhex("9a 0c 0b 34 12 26") + b"\x00" * 8
    assert p.find_window(dump, pat)["status"] == "absent"


def test_two_hits_are_ambiguous_and_none_is_absent():
    pat = bytes.fromhex("55 89 e5")
    assert p.find_window(b"\x55\x89\xe5\x00\x55\x89\xe5", pat)["status"] == "ambiguous"
    assert p.find_window(b"\x00\x00", pat)["status"] == "absent"


def test_displacement_is_taken_from_unique_anchors_and_checked_on_other_windows():
    memory = {
        "dumps": [{"label": "d1"}],
        "windows": [
            {"label": "open_routine_8624", "file_offset": "0x08624",
             "dumps": [{"status": "unique", "linear": ["0x20C4D"], "displacement": "0x18629"}]},
            {"label": "caller_body_876D", "file_offset": "0x0876D",
             "dumps": [{"status": "unique", "linear": ["0x20D96"], "displacement": "0x18629"}]},
            {"label": "selector_chain_8671", "file_offset": "0x08671",
             "dumps": [{"status": "ambiguous", "linear": ["0x20C9A", "0x3C0B4"]}]},
        ],
    }
    got = p.displacement_consistency(memory)["d1"]
    assert got["shared_displacement"] == "0x18629"
    assert got["windows"]["selector_chain_8671"]["hit_at_shared_displacement"] is True
    assert got["windows"]["open_routine_8624"]["hit_at_shared_displacement"] is True


def test_dump_name_must_carry_its_base_and_length():
    with pytest.raises(p.Refusal, match="ram-LO-HI"):
        p.dump_base(Path("dump.bin"), 4)
    with pytest.raises(p.Refusal, match="says"):
        p.dump_base(Path("ram-000000-000004.bin"), 3)
    assert p.dump_base(Path("ram-000000-000004.bin"), 4) == 0


# --- pins, verdict, refusals ---------------------------------------------------------------------

def test_unpinned_inputs_are_refused():
    with pytest.raises(p.Refusal, match="START.EXE"):
        p.inspect(b"not START.EXE", b"", [])


def _fake_doc(digit=None, checked=False):
    chains = {k: True for k in ("open_routine_prologue", "body_prologue", "selector_chain", "open_setup",
                                "path_guard", "open_int", "selector_writer")}
    return {
        "inspect": {
            "chains": chains,
            "open_call_scan": {"single_near_pattern_candidate_expected": True},
            "geo": {"unique_geo_row": True, "stem_len_at": "0x2F994",
                    "digit_piece_candidates_near_stem": digit},
            "byte_checks_ok": True,
        },
        "memory": {"checked": checked, "windows": [
            {"label": "geo_fill_proc_2F9BE", "dumps": [{"status": "absent"}]}]} if checked else {"checked": False},
    }


def test_verdict_never_claims_the_archive_or_the_digit():
    doc = _fake_doc()
    doc["verdict"] = p.verdict(doc)
    v = doc["verdict"]
    assert v["archive"] == "not_established" and v["requested_block"] == "not_established"
    assert v["playable"] is False
    status = {c["id"]: c["status"] for c in v["claims"]}
    assert status["C8"] == "not_established"
    assert status["C4"] == "not_established_no_digit_literal"
    assert status["C7"] == "not_checked"
    assert status["C6"] == "byte_pattern_candidate"


def test_verdict_downgrades_a_digit_candidate_and_marks_overlay_absence():
    doc = _fake_doc(digit=["0x00000"], checked=True)
    doc["verdict"] = p.verdict(doc)
    status = {c["id"]: c["status"] for c in doc["verdict"]["claims"]}
    assert status["C4"] == "candidate_digit_literal_unverified"
    assert status["C7"] == "not_established_overlay_not_resident"


def test_cli_refuses_output_outside_data_work(tmp_path):
    assert p.main(["--install", str(tmp_path), "-o", str(tmp_path / "outside")]) == 2


def test_cli_refuses_output_inside_install():
    # The install sits under data/work, so the output passes the data/work check and must fail the
    # install check on its own.
    inst = p.DATA_WORK / "por-geo-loader-open-chain-probe-test-install"
    inst.mkdir(parents=True, exist_ok=True)
    try:
        assert p.main(["--install", str(inst), "-o", str(inst / "out")]) == 2
    finally:
        for child in sorted(inst.rglob("*"), reverse=True):
            child.rmdir() if child.is_dir() else child.unlink()
        inst.rmdir()


def test_cli_refuses_missing_explicit_dump(tmp_path):
    out = p.DATA_WORK / "por-geo-loader-open-chain-probe-test"
    assert p.main(["--install", str(tmp_path), "-o", str(out),
                   "--dump", str(tmp_path / "ram-000000-000001.bin")]) == 2


def test_render_is_deterministic_and_marks_unknowns():
    doc = _fake_doc()
    doc["memory"] = {"checked": False}
    doc["inspect"]["suffix_census"] = []
    doc["inspect"]["open_call_scan"] = {"near_pattern_candidates": [], "far_pattern_candidates": [],
                                        "single_near_pattern_candidate_expected": False}
    doc["pins"] = {}
    doc["verdict"] = p.verdict(doc)
    assert p.render_report(doc) == p.render_report(doc)
    text = p.render_report(doc)
    assert "Archive: `not_established`" in text
    assert "No pinned RAM dump was present" in text


# --- retail-gated census -------------------------------------------------------------------------

@needs_retail
def test_retail_suffix_census_and_chains_match_the_pinned_bytes():
    start = (INSTALL / "START.EXE").read_bytes()
    ovr = (INSTALL / "GAME.OVR").read_bytes()
    names = sorted(x.name for x in INSTALL.iterdir() if x.is_file())
    got = p.inspect(start, ovr, names)
    assert got["byte_checks_ok"] is True
    seen = [(r["file"], r["stem"], r["stem_len_at"]) for r in got["suffix_census"]]
    assert seen == [
        ("GAME.OVR", "ECL", "0x0190E"),
        ("GAME.OVR", "ITEM", "0x026D3"),
        ("GAME.OVR", "ECL", "0x0780B"),
        ("GAME.OVR", "MON+CHA", "0x1EE7E"),
        ("GAME.OVR", "PIC+FINAL", "0x2E161"),
        ("GAME.OVR", "WALLDEF", "0x2F6AB"),
        ("GAME.OVR", "GEO", "0x2F994"),
        ("START.EXE", None, None),
        ("START.EXE", "8X8d1", "0x0723A"),
    ]
    geo = got["geo"]
    assert geo["unique_geo_row"] is True
    assert geo["digit_piece_candidates_near_stem"] == []
    assert len(geo["install_matches"]["after_last"]) == 8
    assert got["open_call_scan"]["near_pattern_candidates"] == ["0x087CC"]


@needs_retail
def test_probe_without_any_dump_reports_unchecked_memory_not_a_crash(tmp_path):
    doc = p.probe(INSTALL, [tmp_path / "absent" / "ram-000000-100000.bin"])
    assert doc["memory"]["checked"] is False
    assert doc["all_byte_checks_match"] is True
    status = {c["id"]: c["status"] for c in doc["verdict"]["claims"]}
    assert status["C7"] == "not_checked"
    assert doc["verdict"]["archive"] == "not_established"
