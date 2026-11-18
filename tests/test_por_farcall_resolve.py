"""Tests for tools/por_farcall_resolve.py (PoR GAME.OVR far-call / VROOMM stub probe).

The default suite runs on synthetic START.EXE and GAME.OVR blobs built here. The
layout mirrors the retail structure: a 0x200-byte MZ header, a descriptor header
(CD 3F 00 00, fileofs, codesz, fixupsz, jmpcnt) followed by its stub run at
header+0x16 (the original groups) or header+0x17 (the group at fileofs 0x2E8F7),
5-byte CD 3F <proc> 00 stubs, an overlay body with Borland prologues, and a fixup
table of 16-bit words after the code.

Two kinds of group are tested apart: ACCEPTED groups (every stub well-formed at
one alignment) and PARTIAL candidates (a strict majority well-formed, never a
verdict). A malformed slot is never a stub, in either list.

The retail tests run only when OPENUA_POR_INSTALL names a PoR install folder and
are skipped otherwise. They pin the facts the probe reports for the user-supplied
files; they do not test any PoR semantics.
"""
import json
import os
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_farcall_resolve as r  # noqa: E402
from por_convert import PorSourceError  # noqa: E402

HDR = 0x200
OVR_FO = 0x100          # synthetic overlay body starts here in GAME.OVR
OVR_CODE = 0x200
GROUP_H = 0x100         # descriptor header offset inside the MZ image
PROCS = (0x40, 0x80, 0x10)   # two real prologues and one that is not a prologue


def build_ovr() -> bytes:
    """GAME.OVR: 8-byte FBOV header, padding to OVR_FO, then one overlay body.

    The body is OVR_CODE bytes of code followed by a fixup table holding one
    16-bit word: the segment word of the far call at body offset 0x20.
    """
    code = bytearray(b"\x90" * OVR_CODE)
    for p in (0x40, 0x80):
        code[p:p + 3] = b"\x55\x89\xe5"                      # Borland prologues
    code[0x20:0x25] = b"\x9a\x00\x00\x11\x00"               # call 0x11:0x0000
    fix = struct.pack("<H", 0x20 + 3)                       # lists the seg word (site+3)
    head = b"FBOV" + struct.pack("<I", 0)
    return head + b"\x00" * (OVR_FO - len(head)) + bytes(code) + fix


def place_group(start: bytearray, h: int, delta: int, fo: int, codesz: int, fixupsz: int,
                procs, malformed=()) -> None:
    """Write a descriptor header at h and its stub run at h+delta.

    Slots listed in ``malformed`` get trailer 0x27 instead of 0x00.
    """
    start[h:h + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<IHHH", start, h + 4, fo, codesz, fixupsz, len(procs))
    st = h + delta
    for k, p in enumerate(procs):
        start[st + 5 * k:st + 5 * k + 5] = b"\xcd\x3f" + struct.pack("<H", p) + b"\x00"
    for k in malformed:
        start[st + 5 * k + 4] = 0x27


def build_layout(placements, size: int = HDR + 0x800) -> bytes:
    """START.EXE with several groups. Each placement is a tuple
    (header_offset, delta, fileofs, codesz, fixupsz, procs, malformed)."""
    start = bytearray(b"\x00" * size)
    start[0:2] = b"MZ"
    struct.pack_into("<H", start, 0x08, HDR // 16)     # cparhdr
    for h, delta, fo, codesz, fixupsz, procs, malformed in placements:
        place_group(start, h, delta, fo, codesz, fixupsz, procs, malformed)
    return bytes(start)


def build_start(fixupsz: int = 2, procs=PROCS, fo: int = OVR_FO, codesz: int = OVR_CODE,
                delta: int = 0x16, malformed=()) -> bytes:
    return build_layout([(HDR + GROUP_H, delta, fo, codesz, fixupsz, procs, malformed)],
                        size=HDR + 0x400)


def stub_file(index: int, delta: int = 0x16) -> int:
    return HDR + GROUP_H + delta + 5 * index


def call_for_image(image_f: int, at: int = OVR_FO + 0x20) -> dict:
    """Far call whose zero-skew image address is image_f (seg*16 + off = image_f - HDR)."""
    rel = image_f - HDR
    return {"at": at, "seg": rel >> 4, "off": rel & 0xF}


# ---- MZ and descriptor scan -------------------------------------------------

def test_mz_image_base_and_refusal():
    assert r.mz_image_base(build_start()) == HDR
    with pytest.raises(ValueError):
        r.mz_image_base(b"NE" + b"\x00" * 40)


def test_scan_finds_group_with_prologue_counts():
    groups = r.scan_groups(build_start(), build_ovr())
    assert len(groups) == 1
    g = groups[0]
    assert g["fileofs"] == OVR_FO and g["stub_count"] == 3
    assert g["procs"] == list(PROCS)
    assert g["prologue_hits"] == 2 and g["prologue_total"] == 3


def test_scan_rejects_group_with_malformed_stub():
    start = bytearray(build_start())
    start[stub_file(1) + 4] = 0x01          # trailing byte must be 00
    assert r.scan_groups(bytes(start), build_ovr()) == []


def test_scan_rejects_out_of_pool_fileofs():
    start = build_start(fo=0x10000)
    assert r.scan_groups(start, build_ovr()) == []


# ---- alignment: header+0x16 (original) and header+0x17 ----------------------

def test_accepted_plus_0x16_group_records_alignment_and_slot_validity():
    g = r.scan_groups(build_start(), build_ovr())[0]
    assert g["stub_delta"] == 0x16 and g["status"] == "well-formed"
    assert g["stub_valid"] == [True, True, True] and g["valid_stub_count"] == 3
    assert g["stub_start"] == HDR + GROUP_H + 0x16


def test_zero_skew_fields_of_plus_0x16_group_are_unchanged():
    g = r.scan_groups(build_start(), build_ovr())[0]
    got = (g["header_offset"], g["stub_start"], g["stub_count"], g["stub_end"],
           g["fileofs"], g["codesz"], g["fixupsz"], g["procs"],
           g["prologue_hits"], g["prologue_total"])
    assert got == (HDR + GROUP_H, HDR + GROUP_H + 0x16, 3, HDR + GROUP_H + 0x16 + 15,
                   OVR_FO, OVR_CODE, 2, list(PROCS), 2, 3)


def test_plus_0x17_group_is_accepted_at_its_own_alignment():
    start = build_start(delta=0x17, procs=(0x40, 0x80))
    groups = r.scan_groups(start, build_ovr())
    assert len(groups) == 1
    g = groups[0]
    assert g["stub_delta"] == 0x17 and g["stub_start"] == HDR + GROUP_H + 0x17
    assert g["status"] == "well-formed"
    assert g["prologue_hits"] == 2 and g["prologue_total"] == 2
    assert r.scan_partial_groups(start, build_ovr()) == []


def test_plus_0x17_call_resolves_on_its_own_alignment():
    ovr, start = build_ovr(), build_start(delta=0x17, procs=(0x40, 0x80))
    row = r.resolve(start, ovr, [call_for_image(stub_file(1, 0x17))])["far_calls"][0]
    assert row["classification"] == "stub-candidate"
    assert row["stub"]["group_stub_delta"] == 0x17
    assert row["stub"]["index"] == 1 and row["stub"]["proc_off"] == 0x80
    assert row["stub"]["gameovr_target"] == OVR_FO + 0x80
    assert row["stub"]["target_prologue"] is True


def test_call_on_the_other_alignment_is_not_a_stub_for_plus_0x17_group():
    ovr, start = build_ovr(), build_start(delta=0x17, procs=(0x40, 0x80))
    row = r.resolve(start, ovr, [call_for_image(stub_file(1, 0x16))])["far_calls"][0]
    assert row["classification"] == "not-a-stub"
    assert row["stub"] is None


# ---- partial candidates and malformed slots --------------------------------

def test_partial_plus_0x17_group_is_partial_not_accepted():
    ovr = build_ovr()
    start = build_start(delta=0x17, procs=(0x40, 0x80, 0x10), malformed=(2,))
    assert r.scan_groups(start, ovr) == []
    parts = r.scan_partial_groups(start, ovr)
    assert len(parts) == 1
    g = parts[0]
    assert g["status"] == "partial" and g["stub_delta"] == 0x17
    assert g["stub_valid"] == [True, True, False] and g["valid_stub_count"] == 2
    # The malformed slot's proc word (0x10) is not counted; both valid procs are prologues.
    assert g["prologue_hits"] == 2 and g["prologue_total"] == 2


def test_partial_plus_0x16_group_keeps_its_alignment_label():
    start = build_start(malformed=(1,))
    assert r.scan_groups(start, build_ovr()) == []
    parts = r.scan_partial_groups(start, build_ovr())
    assert len(parts) == 1
    assert parts[0]["stub_delta"] == 0x16 and parts[0]["stub_valid"] == [True, False, True]


def test_run_with_one_well_formed_stub_is_not_partial():
    start = build_start(delta=0x17, malformed=(1, 2))
    assert r.scan_groups(start, build_ovr()) == []
    assert r.scan_partial_groups(start, build_ovr()) == []


def test_malformed_partial_slot_is_never_classified_as_a_stub():
    ovr = build_ovr()
    # Slot 2's proc (0x40) is a prologue, so only the malformed trailer excludes it.
    start = build_start(delta=0x17, procs=(0x40, 0x80, 0x40), malformed=(2,))
    res = r.resolve(start, ovr, [call_for_image(stub_file(2, 0x17)),
                                 call_for_image(stub_file(1, 0x17))])
    bad, good = res["far_calls"]
    assert bad["classification"] == "malformed-stub" and bad["stub"] is None
    assert bad["partial_group"]["stub_valid"] is False
    assert good["classification"] == "partial-stub-candidate"
    assert good["stub"]["group_status"] == "partial"
    assert good["stub"]["gameovr_target"] == OVR_FO + 0x80
    assert any("malformed stub 2" in d for d in res["diagnostics"])
    assert any("well-formed stub 1" in d for d in res["diagnostics"])
    assert res["groups"] == []


def test_partial_candidate_is_a_diagnostic_not_a_stub_verdict():
    ovr = build_ovr()
    start = build_start(delta=0x17, procs=(0x40, 0x80, 0x40), malformed=(2,))
    res = r.resolve(start, ovr, [call_for_image(stub_file(0, 0x17))])
    row = res["far_calls"][0]
    assert row["classification"] == "partial-stub-candidate"
    assert any("not a resolved target" in d for d in res["diagnostics"])
    assert res["far_calls"][0]["classification"] != "stub-candidate"


def test_group_for_stub_refuses_malformed_slots():
    start = build_start(delta=0x17, procs=(0x40, 0x80, 0x40), malformed=(2,))
    parts = r.scan_partial_groups(start, build_ovr())
    assert r.group_for_stub(parts, stub_file(2, 0x17)) is None
    assert r.group_for_stub(parts, stub_file(1, 0x17))[1] == 1
    assert r.stub_slot(parts, stub_file(2, 0x17))[1] == 2


def test_group_for_stub_refuses_a_slot_marked_invalid_in_an_accepted_row():
    g = r.scan_groups(build_start(), build_ovr())[0]
    g["stub_valid"][1] = False
    assert r.group_for_stub([g], stub_file(1)) is None
    assert r.group_for_stub([g], stub_file(0)) is not None


# ---- ambiguity, duplicates and mutation ------------------------------------

def test_duplicate_fileofs_across_alignments_keeps_first_header_only():
    start = build_layout([
        (HDR + GROUP_H, 0x16, OVR_FO, OVR_CODE, 2, PROCS, ()),
        (HDR + 0x300, 0x17, OVR_FO, OVR_CODE, 2, (0x40, 0x80), ()),
    ])
    res = r.scan_all(start, build_ovr())
    assert [g["header_offset"] for g in res["groups"]] == [HDR + GROUP_H]
    assert res["partial_groups"] == []
    assert any("already accepted" in n for n in res["notes"])


def test_partial_header_with_an_accepted_fileofs_is_suppressed():
    start = build_layout([
        (HDR + GROUP_H, 0x16, OVR_FO, OVR_CODE, 2, PROCS, ()),
        (HDR + 0x300, 0x17, OVR_FO, OVR_CODE, 3, (0x40, 0x80, 0x40), (2,)),
    ])
    res = r.scan_all(start, build_ovr())
    assert len(res["groups"]) == 1 and res["partial_groups"] == []
    assert any("already held" in n for n in res["notes"])


def test_no_fileofs_appears_twice_across_accepted_and_partial():
    start = build_layout([
        (HDR + GROUP_H, 0x16, OVR_FO, OVR_CODE, 2, PROCS, ()),
        (HDR + 0x300, 0x17, OVR_FO, OVR_CODE, 2, (0x40, 0x80), ()),
        (HDR + 0x400, 0x17, OVR_FO + 0x10, OVR_CODE - 0x10, 2, (0x40, 0x80, 0x40), (2,)),
        (HDR + 0x500, 0x16, OVR_FO + 0x10, OVR_CODE - 0x10, 2, (0x40, 0x80), ()),
    ])
    res = r.scan_all(start, build_ovr())
    fos = [g["fileofs"] for g in res["groups"] + res["partial_groups"]]
    assert len(fos) == len(set(fos))
    assert all(all(g["stub_valid"]) for g in res["groups"])


def test_mutating_partial_slot_to_well_formed_promotes_the_group():
    ovr = build_ovr()
    start = bytearray(build_start(delta=0x17, procs=(0x40, 0x80, 0x10), malformed=(2,)))
    assert r.scan_groups(bytes(start), ovr) == []
    start[stub_file(2, 0x17) + 4] = 0x00
    groups = r.scan_groups(bytes(start), ovr)
    assert len(groups) == 1 and groups[0]["stub_delta"] == 0x17
    assert groups[0]["status"] == "well-formed"
    assert r.scan_partial_groups(bytes(start), ovr) == []


def test_mutating_accepted_slot_demotes_the_group_to_partial():
    ovr = build_ovr()
    start = bytearray(build_start())
    start[stub_file(0) + 4] = 0x27
    assert r.scan_groups(bytes(start), ovr) == []
    parts = r.scan_partial_groups(bytes(start), ovr)
    assert len(parts) == 1 and parts[0]["stub_valid"] == [False, True, True]


def test_mutating_a_malformed_slot_proc_does_not_change_partial_prologue_counts():
    ovr = build_ovr()
    a = build_start(delta=0x17, procs=(0x40, 0x80, 0x10), malformed=(2,))
    b = build_start(delta=0x17, procs=(0x40, 0x80, 0x40), malformed=(2,))
    ga = r.scan_partial_groups(a, ovr)[0]
    gb = r.scan_partial_groups(b, ovr)[0]
    assert (ga["prologue_hits"], ga["prologue_total"]) == (gb["prologue_hits"], gb["prologue_total"]) == (2, 2)


# ---- stub candidates and classification -------------------------------------

def test_call_onto_stub_resolves_to_proc_and_target():
    ovr, start = build_ovr(), build_start(procs=(0x40, 0x80))   # fully prologue-valid group
    res = r.resolve(start, ovr, [call_for_image(stub_file(1))])
    row = res["far_calls"][0]
    assert row["classification"] == "stub-candidate"
    assert row["stub"]["index"] == 1
    assert row["stub"]["proc_off"] == 0x80
    assert row["stub"]["gameovr_target"] == OVR_FO + 0x80
    assert row["stub"]["target_prologue"] is True
    assert res["diagnostics"] == []


def test_partial_group_is_diagnosed_only_when_used():
    ovr, start = build_ovr(), build_start()
    res = r.resolve(start, ovr, [call_for_image(stub_file(2))])     # proc 0x10: no prologue
    assert res["far_calls"][0]["stub"]["target_prologue"] is False
    assert any("fails its prologue check" in d for d in res["diagnostics"])


def test_call_off_grid_is_not_a_stub():
    ovr, start = build_ovr(), build_start()
    res = r.resolve(start, ovr, [call_for_image(stub_file(1) + 1)])
    row = res["far_calls"][0]
    assert row["classification"] == "not-a-stub"
    assert row["stub"] is None
    assert row["skew_minus_1_is_stub"] is True   # the -1 skew would have hit stub 1


def test_skew_minus_one_is_reported_and_not_adopted():
    ovr, start = build_ovr(), build_start()
    res = r.resolve(start, ovr, [call_for_image(stub_file(1))])
    row = res["far_calls"][0]
    assert row["classification"] == "stub-candidate"
    assert row["skew_minus_1_is_stub"] is False


# ---- fixup table and overlay containment ------------------------------------

def test_seg_word_in_fixup_table_is_detected():
    ovr, start = build_ovr(), build_start(fixupsz=2)
    call = {"at": OVR_FO + 0x20, "seg": 0x11, "off": 0}   # site inside the overlay body
    res = r.resolve(start, ovr, [call])
    assert res["far_calls"][0]["overlay"]["fileofs"] == OVR_FO
    assert res["far_calls"][0]["seg_word_in_fixup_table"] is True


def test_seg_word_absent_from_fixup_table_is_reported():
    ovr = bytearray(build_ovr())
    fix_at = OVR_FO + OVR_CODE
    struct.pack_into("<H", ovr, fix_at, 0x999)           # replace the listed site
    call = {"at": OVR_FO + 0x20, "seg": 0x11, "off": 0}
    res = r.resolve(build_start(fixupsz=2), bytes(ovr), [call])
    assert res["far_calls"][0]["seg_word_in_fixup_table"] is False


def test_call_outside_every_overlay_is_diagnosed():
    res = r.resolve(build_start(), build_ovr(), [{"at": 0x1, "seg": 0, "off": 0}])
    assert res["far_calls"][0]["overlay"] is None
    assert any("outside every stub-carrying overlay" in d for d in res["diagnostics"])


# ---- parser stub -------------------------------------------------------------

def test_parser_stub_is_located_and_uncalled(monkeypatch):
    monkeypatch.setattr(r, "PARSER_FILEOFS", OVR_FO)
    ovr, start = build_ovr(), build_start(procs=(0x40, 0x0, 0x80))
    res = r.resolve(start, ovr, [call_for_image(stub_file(0))])
    p = res["parser"]
    assert p["found"] is True and p["stub_index"] == 1
    assert p["stub_image_f"] == stub_file(1)
    assert p["called_by_far_call"] is False


def test_parser_stub_called_is_detected(monkeypatch):
    monkeypatch.setattr(r, "PARSER_FILEOFS", OVR_FO)
    ovr, start = build_ovr(), build_start(procs=(0x40, 0x0, 0x80))
    res = r.resolve(start, ovr, [call_for_image(stub_file(1))])
    assert res["parser"]["called_by_far_call"] is True


# ---- probe, pins, refusal, determinism ---------------------------------------

def _install(tmp_path: Path, ovr: bytes, start: bytes) -> Path:
    d = tmp_path / "install"
    d.mkdir()
    (d / "GAME.OVR").write_bytes(ovr)
    (d / "START.EXE").write_bytes(start)
    return d


def test_probe_refuses_unpinned_without_flag(tmp_path, monkeypatch):
    install = _install(tmp_path, build_ovr(), build_start())
    with pytest.raises(PorSourceError):
        r.probe(install, tmp_path / "out")


def test_probe_with_unpinned_flag_is_not_clean(tmp_path, monkeypatch):
    install = _install(tmp_path, build_ovr(), build_start())
    monkeypatch.setattr(r, "_far_calls_from_handler",
                        lambda ovr: [{"at": OVR_FO + 0x20, "seg": 0x11, "off": 0}])
    doc, code = r.probe(install, tmp_path / "out", allow_unpinned=True)
    assert doc["source"]["all_pins_match"] is False
    assert doc["playable"] is False
    assert code == 1


def test_probe_document_lists_partial_candidates_separately(tmp_path, monkeypatch):
    install = _install(tmp_path, build_ovr(),
                       build_start(delta=0x17, procs=(0x40, 0x80, 0x10), malformed=(2,)))
    monkeypatch.setattr(r, "_far_calls_from_handler", lambda ovr: [])
    doc, code = r.probe(install, tmp_path / "out", allow_unpinned=True)
    assert doc["groups"] == []
    assert len(doc["partial_groups"]) == 1
    assert doc["partial_groups"][0]["status"] == "partial"
    assert doc["scan_notes"] == []
    report = (tmp_path / "out" / "por_farcall_resolve_report.md").read_text(encoding="utf-8")
    assert "Partial stub candidates" in report and "+0x17" in report


def test_output_inside_install_is_refused(tmp_path):
    install = _install(tmp_path, build_ovr(), build_start())
    assert r.main(["--install", str(install), "-o", str(install / "out")]) == 2


def test_output_is_deterministic(tmp_path, monkeypatch):
    install = _install(tmp_path, build_ovr(), build_start())
    monkeypatch.setattr(r, "_far_calls_from_handler",
                        lambda ovr: [{"at": OVR_FO + 0x20, "seg": 0x11, "off": 0}])
    monkeypatch.setattr(r, "PINNED", {
        "GAME.OVR": (len(build_ovr()), r._sha(build_ovr())),
        "START.EXE": (len(build_start()), r._sha(build_start())),
    })
    r.probe(install, tmp_path / "a")
    r.probe(install, tmp_path / "b")
    a = (tmp_path / "a" / "por_farcall_resolve.json").read_bytes()
    b = (tmp_path / "b" / "por_farcall_resolve.json").read_bytes()
    assert a == b
    assert str(tmp_path) not in a.decode("utf-8")
    doc = json.loads(a)
    assert doc["playable"] is False and doc["status"] == "static-probe-only"


# ---- retail (opt-in) ----------------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
CONTROL_FO = 0x74D3          # the operand parser's overlay: established, +0x16
GROUP29_FO = 0x2E8F7         # the WALLDEF layout candidate's overlay: partial, +0x17


def _retail_scan():
    install = Path(RETAIL)
    start = (install / "START.EXE").read_bytes()
    ovr = (install / "GAME.OVR").read_bytes()
    return start, ovr, r.scan_all(start, ovr)


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")
def test_retail_far_call_resolution(tmp_path):
    install = Path(RETAIL)
    doc, code = r.probe(install, tmp_path / "retail")
    assert doc["source"]["all_pins_match"] is True
    rows = {(x["seg"], x["off"]): x for x in doc["far_calls"]}
    a = rows[(0x2B, 0x2A)]
    b = rows[(0x2B, 0x25)]
    assert a["stub"]["proc_off"] == 0x1DF0 and a["stub"]["gameovr_target"] == 0x92C3
    assert b["stub"]["proc_off"] == 0x1CC3 and b["stub"]["gameovr_target"] == 0x9196
    assert a["skew_minus_1_is_stub"] is False and b["skew_minus_1_is_stub"] is False
    assert doc["parser"]["found"] is True and doc["parser"]["called_by_far_call"] is False
    assert doc["diagnostics"] == [] and code == 0


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")
def test_retail_control_group_0x74d3_stays_accepted_at_plus_0x16():
    _, _, scan = _retail_scan()
    ctl = [g for g in scan["groups"] if g["fileofs"] == CONTROL_FO]
    assert len(ctl) == 1
    g = ctl[0]
    assert g["header_offset"] == 0x45B and g["stub_delta"] == 0x16
    assert g["stub_start"] == 0x471 and g["stub_count"] == 25
    assert g["valid_stub_count"] == 25 and g["status"] == "well-formed"
    assert not any(p["fileofs"] == CONTROL_FO for p in scan["partial_groups"])


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")
def test_retail_group29_is_partial_at_plus_0x17_and_not_accepted():
    _, _, scan = _retail_scan()
    assert GROUP29_FO not in [g["fileofs"] for g in scan["groups"]]
    (g,) = [p for p in scan["partial_groups"] if p["fileofs"] == GROUP29_FO]
    assert g["header_offset"] == 0x3DD7 and g["stub_delta"] == 0x17
    assert g["stub_start"] == 0x3DEE and g["stub_count"] == 8
    assert g["codesz"] == 0x120B and g["fixupsz"] == 0x50
    assert g["stub_valid"] == [True] * 7 + [False]
    assert g["procs"][5] == 0x05FD and g["procs"][7] == 0x10C7
    assert g["status"] == "partial"


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")
def test_retail_group29_stub5_is_candidate_and_stub7_is_malformed():
    start, ovr, _ = _retail_scan()
    # The zero-skew image address is hdr + seg*16 + off, compared with START file offsets.
    # Stub 5 is file 0x3E07 (seg*16+off = 0x3C07); stub 7 is file 0x3E11 (0x3C11).
    res = r.resolve(start, ovr, [{"at": 0x19C3, "seg": 0x3C0, "off": 0x7},
                                 {"at": 0x19C3, "seg": 0x3C1, "off": 0x1}])
    s5, s7 = res["far_calls"]
    assert s5["classification"] == "partial-stub-candidate"
    assert s5["stub"]["proc_off"] == 0x05FD
    assert s5["stub"]["gameovr_target"] == 0x2EEF4 and s5["stub"]["target_prologue"] is True
    assert s7["classification"] == "malformed-stub" and s7["stub"] is None


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set")
def test_retail_plus_0x17_accepted_set_is_the_documented_one():
    _, _, scan = _retail_scan()
    plus17 = sorted(g["fileofs"] for g in scan["groups"] if g["stub_delta"] == 0x17)
    assert plus17 == [0x2DB87, 0x2DE38, 0x31A6C, 0x3211F, 0x32235]
    assert all(all(g["stub_valid"]) for g in scan["groups"])
    fos = [g["fileofs"] for g in scan["groups"] + scan["partial_groups"]]
    assert len(fos) == len(set(fos))
