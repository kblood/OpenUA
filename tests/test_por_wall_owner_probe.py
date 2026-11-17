"""Tests for tools/por_wall_owner_probe.py (GAME.OVR 0x2EEF4 owner decode, static).

Synthetic fixtures check offset and control-flow claims, with mutations that must
change the result. The retail anchor runs only when OPENUA_POR_INSTALL names the
local Pool of Radiance DOS install and is skipped otherwise. Nothing here writes
outside a temporary folder, and the retail run reads the install read-only.
"""
import hashlib
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_wall_owner_probe as op  # noqa: E402

ENV = "OPENUA_POR_INSTALL"

# Synthetic routine at 0x10. Layout (file offsets):
#   10: 55 89 E5      push bp; mov bp,sp
#   13: E8 1A 00      call 0x30        (13+3+0x1A = 0x30, outside the routine)
#   16: 68 34 12      push 0x1234
#   19: CD 21         int 21h
#   1B: 89 EC         mov sp,bp
#   1D: 5D            pop bp
#   1E: CA 06 00      retf 6           (ends at 0x21 = the literal)
#   21: 07 ...        literal (length byte; not decoded as code)
#   30: C3            ret (call target, outside)
OWNER = 0x10
LIT = 0x21


def _blob(call_rel=b"\x1a\x00", push_imm=b"\x34\x12", pad_before_ret=b"", lit_len=0x07):
    b = bytearray(0x40)
    b[0x10:0x13] = b"\x55\x89\xe5"
    b[0x13] = 0xE8
    b[0x14:0x16] = call_rel
    b[0x16] = 0x68
    b[0x17:0x19] = push_imm
    b[0x19:0x1B] = b"\xcd\x21"
    b[0x1B:0x1D] = b"\x89\xec"
    b[0x1D] = 0x5D
    b[0x1E:0x1E + len(pad_before_ret)] = pad_before_ret
    ret_at = 0x1E + len(pad_before_ret)
    b[ret_at:ret_at + 3] = b"\xca\x06\x00"
    b[ret_at + 3] = lit_len
    b[0x30] = 0xC3
    return bytes(b)


def test_owner_ends_at_literal_and_is_clean():
    r = op.analyse(_blob(), owner=OWNER, literal=LIT)
    assert r["return"]["at"] == 0x1E
    assert r["return"]["flow"] == "retf"
    assert r["return"]["imm"] == 6
    assert r["owner_end"] == LIT
    assert r["diagnostics"] == []


def test_near_call_target_is_decoded_and_outside_routine():
    r = op.analyse(_blob(), owner=OWNER, literal=LIT)
    assert len(r["near_calls"]) == 1
    c = r["near_calls"][0]
    assert c["at"] == 0x13
    assert c["target"] == 0x30
    assert c["target_inside_routine"] is False
    assert c["target_on_boundary"] is False


def test_near_call_off_by_one_changes_target():
    # rel 0x1B lands on 0x31, not 0x30; the claim must follow the bytes.
    r = op.analyse(_blob(call_rel=b"\x1b\x00"), owner=OWNER, literal=LIT)
    assert r["near_calls"][0]["target"] == 0x31
    assert r["near_calls"][0]["target"] != 0x30


def test_argument_push_is_visible_before_interrupt():
    r = op.analyse(_blob(), owner=OWNER, literal=LIT)
    assert len(r["interrupts"]) == 1
    ii = r["interrupts"][0]
    assert ii["at"] == 0x19
    assert "int 0x21" in ii["text"] or "21" in ii["text"]
    assert any("0x1234" in t for t in ii["before"])


def test_no_operand_equals_literal_in_clean_fixture():
    r = op.analyse(_blob(), owner=OWNER, literal=LIT)
    assert r["literal_refs_file_offset_model"] == []
    assert r["literal_word_hits_raw_bytes"] == []


def test_push_of_literal_offset_is_a_literal_ref():
    # Mutation: the push immediate becomes the literal offset 0x21.
    r = op.analyse(_blob(push_imm=b"\x21\x00"), owner=OWNER, literal=LIT)
    refs = r["literal_refs_file_offset_model"]
    assert len(refs) == 1
    assert refs[0]["at"] == 0x16
    assert refs[0]["operand"] == "imm"


def test_return_not_adjacent_to_literal_is_flagged():
    # Mutation: one extra nop before the retf moves the return off the literal.
    r = op.analyse(_blob(pad_before_ret=b"\x90"), owner=OWNER, literal=LIT)
    assert r["return"]["at"] == 0x1F
    assert r["owner_end"] == 0x22
    assert "return-not-adjacent-to-literal" in r["diagnostics"]


def test_flow_counts_are_consistent():
    r = op.analyse(_blob(), owner=OWNER, literal=LIT)
    assert sum(r["flows"].values()) == r["instruction_count"]
    assert r["flows"].get("call") == 1
    assert r["flows"].get("retf") == 1


def test_unpinned_install_refused_without_flag(tmp_path):
    (tmp_path / op.OVR_NAME).write_bytes(b"not the pinned file")
    with pytest.raises(op.OwnerProbeError):
        op.read_pinned_ovr(tmp_path)
    data, sha, pinned = op.read_pinned_ovr(tmp_path, allow_unpinned=True)
    assert pinned is False
    assert sha == hashlib.sha256(b"not the pinned file").hexdigest()


def test_missing_install_refused(tmp_path):
    with pytest.raises(op.OwnerProbeError):
        op.read_pinned_ovr(tmp_path)


def _retail_install():
    raw = os.environ.get(ENV)
    if not raw:
        pytest.skip("set %s to the Pool of Radiance DOS install to run the retail anchor" % ENV)
    return Path(raw)


def test_retail_pins_and_owner_anchor(tmp_path):
    install = _retail_install()
    data, sha, pinned = op.read_pinned_ovr(install)
    assert pinned is True
    assert len(data) == op.OVR_SIZE
    assert sha == op.OVR_SHA
    r = op.analyse(data)
    # Counts established by docs/por-wall-render-probe.md; this test checks them again.
    assert r["instruction_count"] == 827
    assert r["return"]["at"] == op.RETF_AT
    assert r["return"]["flow"] == "retf"
    assert r["return"]["imm"] == 6
    assert r["owner_end"] == op.LITERAL
    assert len(r["near_calls"]) == 39
    assert r["far_calls"] == []
    assert r["diagnostics"] == []


def test_retail_literal_not_referenced_by_file_offset_model(tmp_path):
    install = _retail_install()
    data, _sha, _p = op.read_pinned_ovr(install)
    r = op.analyse(data)
    assert r["literal_refs_file_offset_model"] == []
    assert r["literal_word_hits_raw_bytes"] == []


def test_retail_source_unchanged_across_run(tmp_path):
    install = _retail_install()
    ovr = None
    for c in (install, install / "POOLRAD"):
        if (c / op.OVR_NAME).is_file():
            ovr = c / op.OVR_NAME
            break
    assert ovr is not None
    before = hashlib.sha256(ovr.read_bytes()).hexdigest()
    op.probe(install.resolve(), tmp_path / "out")
    after = hashlib.sha256(ovr.read_bytes()).hexdigest()
    assert before == after == op.OVR_SHA
