"""Tests for tools/por_ecl_menu_framing_probe.py.

Synthetic tests run everywhere. Retail tests are gated on OPENUA_POR_INSTALL (the pinned
POOLRAD folder) and skip without it.
"""

import json
import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_ecl_menu_framing_probe as p  # noqa: E402


def _chain(value_case: int, arm_call_target: int, base: int = 0x100) -> bytes:
    """A tiny synthetic classifier: cmp al,value_case; jz arm; default inc [0x49ED]; arm pushes 3, calls parser."""
    code = bytearray(0x400)
    # 0x100: cmp al, value_case
    code[base:base + 2] = bytes([0x3C, value_case])
    # 0x102: jz +4 -> arm at 0x108   (next ip 0x104, rel 4)
    code[base + 2:base + 4] = bytes([0x74, 0x04])
    # 0x104: default: inc [0x49ED]; jmp end
    code[base + 4:base + 8] = bytes([0xFF, 0x06, 0xED, 0x49])
    # 0x108: arm: mov al,3; push ax; push cs; call rel16 -> arm_call_target
    code[base + 8:base + 9] = bytes([0xB0])
    code[base + 9:base + 10] = bytes([0x03])
    code[base + 10:base + 11] = bytes([0x50])
    code[base + 11:base + 12] = bytes([0x0E])
    rel = arm_call_target - (base + 12 + 3)
    code[base + 12:base + 15] = bytes([0xE8]) + struct.pack("<h", rel)
    return bytes(code)


def test_classify_default_arm_is_inc_only_for_unmatched_value():
    data = _chain(0x15, arm_call_target=0x200)
    got = p.classify(data, 0x2B, entry=0x100, call_target=0x200)
    assert got["arm"] == "inc-only"
    assert got["inc"] == 0x49ED and got["operands_parsed"] == 0


def test_classify_matched_value_reaches_parser_with_class_byte():
    data = _chain(0x15, arm_call_target=0x200)
    got = p.classify(data, 0x15, entry=0x100, call_target=0x200)
    assert got == {"arm": "push-cs-call", "class": 3, "call": 0x200, "at": 0x10C}


def test_mutating_the_compare_value_flips_the_arm():
    base = _chain(0x15, arm_call_target=0x200)
    mutant = _chain(0x16, arm_call_target=0x200)
    assert p.classify(base, 0x15, entry=0x100, call_target=0x200)["arm"] == "push-cs-call"
    assert p.classify(mutant, 0x15, entry=0x100, call_target=0x200)["arm"] == "inc-only"


def test_unmodelled_byte_is_a_named_refusal():
    data = bytearray(_chain(0x15, arm_call_target=0x200))
    data[0x100] = 0x90  # nop: not in the modelled set
    got = p.classify(bytes(data), 0x15, entry=0x100, call_target=0x200)
    assert got["arm"] == "refusal" and got["reason"] == "unmodelled-byte"


def test_other_call_is_reported_not_mistaken_for_the_parser():
    data = _chain(0x15, arm_call_target=0x300)
    got = p.classify(data, 0x15, entry=0x100, call_target=0x200)
    assert got["arm"] == "other-call" and got["call"] == 0x300


def test_stub_at_reads_cd3f_stub_and_rejects_non_stub():
    start = bytearray(0x600)
    start[0x4DA:0x4DF] = bytes([0xCD, 0x3F, 0xF0, 0x1D, 0x00])
    assert p.stub_at(bytes(start), 0x4DA) == (0x1DF0, 0)
    assert p.stub_at(bytes(start), 0x4DB) is None


def test_refuses_unpinned_install(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"x" * 10)
    (tmp_path / "START.EXE").write_bytes(b"y" * 10)
    with pytest.raises(p.ProbeRefusal):
        p.probe(tmp_path, tmp_path / "out")


def test_refuses_output_inside_install(tmp_path):
    with pytest.raises(p.ProbeRefusal):
        p.probe(tmp_path, tmp_path)


RETAIL = os.environ.get("OPENUA_POR_INSTALL")


@pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_INSTALL to the pinned POOLRAD folder")
def test_retail_bytes_settle_the_checks_and_the_arms(tmp_path):
    out = tmp_path / "out"
    doc, code = p.probe(Path(RETAIL), out)
    assert code == 0
    assert all(doc["checks"].values()), doc["checks"]
    assert doc["playable"] is False and doc["mappings"] == []
    # the default arm for both menu opcodes: one byte, zero parsed operands
    assert doc["classifier_0x9379"]["0x15"]["arm"] == "inc-only"
    assert doc["classifier_0x9379"]["0x2B"]["arm"] == "inc-only"
    # the classifier's own arms for a sample of opcodes
    assert doc["classifier_0x9379"]["0x27"] == {"arm": "push-cs-call", "class": 8,
                                                 "call": 0x74D3, "at": 37996}
    # the group header at START.EXE 0x45B is the fileofs 0x74D3 group
    assert doc["group_header"]["fileofs"] == 0x74D3 and doc["group_header"]["jmpcnt"] == 25
    # the 2B:2A and 2B:25 stubs are run indices 21 and 20 (zero-skew model, not a resolution)
    idx = {r["index"]: r for r in doc["seg_2b_calls"] if r.get("in_run") and r["off"] in (0x25, 0x2A)}
    assert idx[21]["proc_off"] == 0x1DF0 and idx[21]["zero_skew_game_target"] == 0x92C3
    assert idx[20]["proc_off"] == 0x1CC3 and idx[20]["zero_skew_game_target"] == 0x9196
    # the 0x15 handler pushes the literal 3 before 2B:2A and 2B:25; the 0x2B handler pushes 2
    h15 = doc["handlers"]["0x15_VERTICAL_MENU"]["far_calls"]
    assert any(c.get("far") == "0x002b:0x002a" and "0x1c68 mov al 0x3" in c["priors"][0] for c in h15)
    h2b = doc["handlers"]["0x2B_HORIZONTAL_MENU"]["far_calls"]
    assert any(c.get("far") == "0x002b:0x0025" and "0x1e3e mov al 0x2" in c["priors"][0] for c in h2b)
    json.loads((out / "por_ecl_menu_framing_probe.json").read_text(encoding="utf-8"))
