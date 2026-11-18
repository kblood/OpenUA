"""Tests for tools/por_ecl_21_stub7_dump_probe.py (ECL 0x21 far call vs. START stub 7, RAM dumps).

Default suite: synthetic bytes only. GAME.OVR, START.EXE and dumps are generated here with a
small self-consistent layout; the pins are computed from the generated blobs and passed to run().
Nothing is read from the install, no process is touched, and nothing is written.

The retail test runs only when the pinned install and both known dumps exist (data/ is git-ignored).
It calls run() on the real bytes and writes nothing.
"""
import hashlib
import os
import random
import struct
import sys
from dataclasses import replace
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_ecl_21_stub7_dump_probe as p  # noqa: E402
import por_overlay_group_map as pogm  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_DUMPS = [REPO / "data" / "work" / "por-live-memory-pid34644" / "ram-000000-100000.bin",
                REPO / "data" / "work" / "por-wheel-live-capture" / "ram-000000-100000.bin"]
RETAIL_INSTALL = REPO / "data" / "work" / "por-geo-run" / "POOLRAD"

# Synthetic layout (small, but the same shape as retail).
D = 0x40                  # START: header of the group holding the far call
D2 = 0x100                # START: header of the owner group of the stub run
RUN = D2 + 0x17           # START: stub run start (header + 0x17)
STUB4 = RUN + 5 * 4       # control stub
STUB7 = RUN + 5 * 7       # the stub under test
G = 0xD46                 # GAME.OVR: group code fileofs
C = 0xD00                 # group codesz; includes the handler call at 0x1A27
SITE_BODY = 0xCE1         # far call 9A at body 0xCE1 (= file 0x1A27)
SEG_BODY = 0xCE4          # its seg word, fixup-listed
OFF, RAW_SEG, LIVE_SEG = 0x0043, 0x0100, 0x2500
OWN_F = 0x2E8F7           # owner fileofs in GAME.OVR
OWN_C = 0x120B            # owner codesz
PROC = 0x10C7              # proc of stub 7 (inside owner codesz)
BASE = 0x20000            # dump base
DUMP_LEN = 0x10000
GROUP_LIN = 0x21000       # group base in the dump
T = LIVE_SEG * p.PARA + OFF   # live target linear (0x25043)
LABEL = "ram-020000-030000.bin"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def make_files():
    ovr = bytearray(random.Random(0x21).randbytes(0x30000))
    exe = bytearray(random.Random(0x22).randbytes(0x400))
    # group header at D: magic, fileofs, codesz, fixupsz, jmpcnt
    exe[D:D + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<I", exe, D + 4, G)
    struct.pack_into("<HHH", exe, D + 8, C, 2, 1)
    # owner header at D2 (fixupsz 0 keeps the owner table trivially valid)
    exe[D2:D2 + 4] = b"\xcd\x3f\x00\x00"
    struct.pack_into("<I", exe, D2 + 4, OWN_F)
    struct.pack_into("<HHH", exe, D2 + 8, OWN_C, 0, 0)
    # stub run: stub k = CD 3F proc(2) trailer; stub 7 carries trailer 0x27 (retail)
    for k, proc in ((4, 0x0010), (5, 0x0020), (6, 0x0030), (7, PROC)):
        base = RUN + 5 * k
        exe[base:base + 5] = b"\xcd\x3f" + struct.pack("<H", proc) + bytes([0x27 if k == 7 else 0x00])
    # group code: far call at SITE_BODY, seg word fixup-listed
    code = bytearray(random.Random(0x23).randbytes(C))
    code[SITE_BODY:SITE_BODY + 5] = b"\x9a" + struct.pack("<HH", OFF, RAW_SEG)
    ovr[G:G + C] = code
    struct.pack_into("<H", ovr, G + C, SEG_BODY)            # the one fixup word
    # Handler pushes one AX word from [bp-3] immediately before this far call.
    handler_push_at = G + SITE_BODY - 4
    ovr[handler_push_at:handler_push_at + 9] = bytes.fromhex("8a 46 fd 50 9a 43 00 00 01")
    ovr[p.HANDLER_OPERAND_LOOP_AT:
        p.HANDLER_OPERAND_LOOP_AT + len(p.HANDLER_OPERAND_LOOP)] = p.HANDLER_OPERAND_LOOP
    # Candidate fill proc: prologue, low argument byte read, and retf 2.
    ovr[OWN_F + PROC:OWN_F + PROC + 3] = p.PROLOGUE
    ovr[OWN_F + PROC + p.FILL_ARG_READ_DELTA:
        OWN_F + PROC + p.FILL_ARG_READ_DELTA + 3] = p.FILL_ARG_READ
    ovr[OWN_F + PROC + p.FILL_RETF_DELTA:
        OWN_F + PROC + p.FILL_RETF_DELTA + 3] = p.FILL_RETF
    return bytes(ovr), bytes(exe)


def cfg_for(exe, **over):
    base = p.Cfg(group_descriptor=D, group_fileofs=G, group_base_expected=GROUP_LIN,
                 site_file=G + SITE_BODY, site_raw_seg=RAW_SEG, site_off=OFF,
                 site_live_seg=LIVE_SEG, stub_file=STUB7, stub_slot=7,
                 stub_bytes=bytes(exe[STUB7:STUB7 + 5]), stub_proc=PROC,
                 owner_descriptor=D2, owner_fileofs=OWN_F,
                 control_stub_file=STUB4, control_slot=4)
    return replace(base, **over)


def make_dump(ovr, exe, *, live_seg=LIVE_SEG, trailer=0x00, window=None, group=True,
              duplicate=False, site_op=0x9A, control=None):
    d = bytearray(random.Random(0x24).randbytes(DUMP_LEN))
    if group:
        code = bytearray(ovr[G:G + C])
        code[SITE_BODY] = site_op
        struct.pack_into("<H", code, SEG_BODY, live_seg)     # the loader rewrote the seg word
        d[GROUP_LIN - BASE:GROUP_LIN - BASE + C] = code
        if duplicate:
            d[0x2A000 - BASE:0x2A000 - BASE + C] = code
    tgt = live_seg * p.PARA + OFF
    if window is None:
        win = bytearray(exe[STUB7:STUB7 + 16])
        win[4] = trailer
        window = bytes(win)
    d[tgt - BASE:tgt - BASE + 16] = window
    ctl = tgt - (STUB7 - STUB4)
    d[ctl - BASE:ctl - BASE + 16] = control if control is not None else exe[STUB4:STUB4 + 16]
    return bytes(d)


def run_one(ovr, exe, dump, cfg=None, label=LABEL, pins=None):
    cfg = cfg or cfg_for(exe)
    pins = pins or _pins(ovr, exe)
    return p.run(ovr, exe, [(label, dump)], pins=pins, cfg=cfg)


def _pins(ovr, exe):
    return {"GAME.OVR": {"size": len(ovr), "sha256": _sha(ovr)},
            "START.EXE": {"size": len(exe), "sha256": _sha(exe)}}


# ---------- synthetic positive and falsifiers -----------------------------------------------

def test_synthetic_retail_shape_is_ok_and_prefix_only():
    ovr, exe = make_files()
    doc = run_one(ovr, exe, make_dump(ovr, exe))
    assert doc["status"] == "ok" and doc["dumps_ok"] and doc["file_side"]["ok"]
    r = doc["dumps"][0]
    assert r["window_result"] == p.EXPECTED_RESULT
    assert r["group"]["base_linear"] == "0x%X" % GROUP_LIN
    assert r["target"]["linear"] == "0x%X" % T
    assert r["target"]["prefix4_match"] is True
    assert r["target"]["exact_full_stub_identity"] is False
    assert r["target"]["trailer_dump"] == "0x00" and r["target"]["trailer_file"] == "0x27"
    assert r["control"]["exact_16_match"] is True
    assert r["owner_group"]["status"] == "absent"          # not placed in the synthetic dump
    assert doc["claims"]["executed"] == "not_established"
    assert doc["claims"]["called"] == "not_established"


def test_candidate_fill_argument_shape_is_stack_compatible():
    ovr, exe = make_files()
    doc = run_one(ovr, exe, make_dump(ovr, exe))
    checks = doc["file_side"]["checks"]
    assert checks["candidate_handler_pushes_one_word"] is True
    assert checks["candidate_argument_local_filled_by_helper_loop"] is True
    assert checks["candidate_fill_reads_low_argument_byte"] is True
    assert checks["candidate_fill_returns_popping_one_word"] is True
    facts = doc["file_side"]["facts"]["candidate_frame"]
    assert facts["argument_source"] == "byte [bp-3], first helper-result local, pushed as AX word"
    assert "helper semantics unknown" in facts["argument_provenance"]
    assert facts["candidate_fill_reads"] == "AL <- byte [bp+6]"
    assert facts["shape"] == "one pushed word matches retf 2; conditional on candidate target"


@pytest.mark.parametrize(("offset", "check_id"), [
    (0x1A26, "candidate_handler_pushes_one_word"),
    (p.HANDLER_OPERAND_LOOP_AT + 33, "candidate_argument_local_filled_by_helper_loop"),
    (OWN_F + PROC + p.FILL_ARG_READ_DELTA + 2, "candidate_fill_reads_low_argument_byte"),
    (OWN_F + PROC + p.FILL_RETF_DELTA + 1, "candidate_fill_returns_popping_one_word"),
])
def test_candidate_frame_fails_when_call_abi_bytes_change(offset, check_id):
    ovr, exe = make_files()
    bad = bytearray(ovr)
    bad[offset] ^= 1
    doc = run_one(bytes(bad), exe, make_dump(bytes(bad), exe), pins=_pins(bytes(bad), exe))
    assert doc["file_side"]["checks"][check_id] is False


def test_trailer_equal_to_file_is_exact16_not_the_expected_result():
    ovr, exe = make_files()
    r = run_one(ovr, exe, make_dump(ovr, exe, trailer=0x27))["dumps"][0]
    assert r["window_result"] == "exact-16-match"
    assert r["target"]["exact_full_stub_identity"] is True
    assert r["dump_status"] == "diagnostic"               # changed from the known discrepancy


def test_stub5_only_match_is_flagged():
    ovr, exe = make_files()
    win = exe[STUB7:STUB7 + 5] + b"\x00" * 11              # five bytes equal, the rest zero
    r = run_one(ovr, exe, make_dump(ovr, exe, window=win))["dumps"][0]
    assert r["window_result"] == "stub5-match"
    assert r["dump_status"] == "diagnostic"


def test_proc_word_change_in_dump_is_prefix_absent():
    ovr, exe = make_files()
    win = bytearray(exe[STUB7:STUB7 + 16])
    win[4] = 0
    win[2:4] = b"\x41\x00"                                 # proc word differs
    doc = run_one(ovr, exe, make_dump(ovr, exe, window=bytes(win)))
    assert doc["dumps"][0]["window_result"] == "prefix-absent"
    assert doc["status"] == "diagnostic"


def test_group_absent_is_diagnostic_not_identity():
    ovr, exe = make_files()
    doc = run_one(ovr, exe, make_dump(ovr, exe, group=False))
    r = doc["dumps"][0]
    assert r["group"]["status"] == "absent" and r["window_result"] is None
    assert doc["status"] == "diagnostic"


def test_ambiguous_group_is_diagnostic():
    ovr, exe = make_files()
    r = run_one(ovr, exe, make_dump(ovr, exe, duplicate=True))["dumps"][0]
    assert r["group"]["status"] == "ambiguous"
    assert r["dump_status"] == "diagnostic"


def test_live_segment_moved_changes_target_and_fails_expectation():
    ovr, exe = make_files()
    doc = run_one(ovr, exe, make_dump(ovr, exe, live_seg=0x2501))
    r = doc["dumps"][0]
    assert r["target"]["linear"] == "0x%X" % (0x2501 * 16 + OFF)
    assert r["site"]["seg_live_matches_expected"] is False
    # make_dump stamps the window at the moved target too, so the bytes match there; the
    # falsifier is the segment expectation, which must fail the dump on its own.
    assert r["window_result"] == p.EXPECTED_RESULT
    assert r["checks"]["site_seg_live_expected"] is False
    assert r["dump_status"] == "diagnostic"
    assert doc["status"] == "diagnostic"


def test_far_call_opcode_changed_in_dump_leaves_group_unmapped():
    ovr, exe = make_files()
    r = run_one(ovr, exe, make_dump(ovr, exe, site_op=0x90))["dumps"][0]
    assert r["group"]["status"] == "absent"
    assert r["dump_status"] == "diagnostic"


def test_control_stub_mismatch_is_diagnostic():
    ovr, exe = make_files()
    ctl = bytearray(exe[STUB4:STUB4 + 16])
    ctl[0] ^= 0xFF
    doc = run_one(ovr, exe, make_dump(ovr, exe, control=bytes(ctl)))
    assert doc["dumps"][0]["control"]["exact_16_match"] is False
    assert doc["dumps"][0]["checks"]["control_exact"] is False
    assert doc["status"] == "diagnostic"


def test_seg_word_not_fixup_listed_fails_file_check():
    ovr, exe = make_files()
    bad = bytearray(ovr)
    struct.pack_into("<H", bad, G + C, SEG_BODY + 1)        # the table points elsewhere
    doc = run_one(bytes(bad), exe, make_dump(ovr, exe), pins=_pins(bytes(bad), exe))
    assert doc["file_side"]["checks"]["seg_word_fixup_listed"] is False
    assert doc["status"] == "diagnostic"


def test_stub_trailer_changed_in_file_fails_stub_check():
    ovr, exe = make_files()
    cfg = cfg_for(exe)                                     # expectation from the original file
    bad = bytearray(exe)
    bad[STUB7 + 4] = 0x00
    doc = run_one(ovr, bytes(bad), make_dump(ovr, exe), cfg=cfg, pins=_pins(ovr, bytes(bad)))
    assert doc["file_side"]["checks"]["stub_bytes"] is False
    assert doc["status"] == "diagnostic"


def test_owner_fileofs_mismatch_fails_file_check():
    ovr, exe = make_files()
    bad = bytearray(exe)
    struct.pack_into("<I", bad, D2 + 4, OWN_F + 0x10)
    doc = run_one(ovr, bytes(bad), make_dump(ovr, exe), cfg=cfg_for(exe), pins=_pins(ovr, bytes(bad)))
    assert doc["file_side"]["checks"]["owner_descriptor_fileofs"] is False
    assert doc["status"] == "diagnostic"


def test_proc_outside_owner_codesz_fails_file_check():
    ovr, exe = make_files()
    bad = bytearray(exe)
    bad[STUB7 + 2:STUB7 + 4] = struct.pack("<H", 0x1300)   # proc beyond owner codesz 0x120B
    cfg = cfg_for(bytes(bad), stub_proc=0x1300)
    doc = run_one(ovr, bytes(bad), make_dump(ovr, exe), cfg=cfg, pins=_pins(ovr, bytes(bad)))
    checks = doc["file_side"]["checks"]
    assert checks["proc_inside_owner_codesz"] is False
    assert doc["status"] == "diagnostic"


def test_pin_mismatch_is_refused():
    ovr, exe = make_files()
    wrong = {"GAME.OVR": {"size": len(ovr), "sha256": "0" * 64},
             "START.EXE": {"size": len(exe), "sha256": _sha(exe)}}
    with pytest.raises(pogm.Refusal):
        run_one(ovr, exe, make_dump(ovr, exe), pins=wrong)


def test_dump_name_without_base_is_refused():
    ovr, exe = make_files()
    with pytest.raises(pogm.Refusal):
        run_one(ovr, exe, make_dump(ovr, exe), label="dump.bin")


def test_dump_name_size_mismatch_is_refused():
    ovr, exe = make_files()
    with pytest.raises(pogm.Refusal):
        run_one(ovr, exe, make_dump(ovr, exe), label="ram-020000-020100.bin")


def test_no_dump_is_refused():
    ovr, exe = make_files()
    with pytest.raises(pogm.Refusal):
        p.run(ovr, exe, [], pins=_pins(ovr, exe), cfg=cfg_for(exe))


def test_output_outside_data_work_is_refused(tmp_path):
    with pytest.raises(pogm.Refusal):
        p._check_out(tmp_path / "install", tmp_path / "out")


def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(pogm.Refusal):
        p._check_out(install, install / "out")


def test_main_refuses_without_install(tmp_path, monkeypatch):
    monkeypatch.delenv(pogm.INSTALL_ENV, raising=False)
    dump = tmp_path / LABEL
    dump.write_bytes(b"\x00" * DUMP_LEN)
    assert p.main(["--dump", str(dump)]) == 2


# ---------- retail-gated (skips unless the pinned install and both dumps exist) -------------

def _retail_skip():
    if not all(d.is_file() for d in RETAIL_DUMPS):
        return "known dumps not present under data/work"
    try:
        pogm.find_install(RETAIL_INSTALL)
    except pogm.Refusal:
        return "pinned install not present (set OPENUA_POR_INSTALL or place POOLRAD)"
    return None


@pytest.mark.skipif(_retail_skip() is not None, reason=_retail_skip() or "")
def test_retail_both_dumps_show_the_known_discrepancy():
    folder = pogm.find_install(RETAIL_INSTALL)
    ovr = (folder / "GAME.OVR").read_bytes()
    exe = (folder / "START.EXE").read_bytes()
    dumps = [("%s/%s" % (d.parent.name, d.name), d.read_bytes()) for d in RETAIL_DUMPS]
    doc = p.run(ovr, exe, dumps, pins=pogm.PINS, cfg=p.Cfg())
    assert doc["status"] == "ok", doc["file_side"]["checks"]
    assert all(doc["file_side"]["checks"].values())
    assert len(doc["dumps"]) == 2
    for r in doc["dumps"]:
        assert r["known_dump"] in p.KNOWN_DUMPS.values()
        assert r["group"]["status"] == "unique" and r["group"]["base_linear"] == "0x45C40"
        assert r["site"]["seg_live"] == "0x1C3B" and r["site"]["offset_live"] == "0x43"
        assert r["target"]["linear"] == "0x1C3F3"
        assert r["target"]["prefix4_match"] is True
        assert r["target"]["trailer_dump"] == "0x00" and r["target"]["trailer_file"] == "0x27"
        assert r["target"]["exact_full_stub_identity"] is False
        assert r["window_result"] == p.EXPECTED_RESULT
        assert r["target"]["window_vs_pinned_files"]["status"] == "absent"
        assert r["control"]["linear"] == "0x1C3E4" and r["control"]["exact_16_match"] is True
        assert r["owner_group"]["status"] == "absent"
        assert r["dump_status"] == "ok"
