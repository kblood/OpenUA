"""Tests for tools/por_wall_callee_probe.py (bounded call-edge probe from GAME.OVR 0x2EEF4).

Synthetic fixtures check the traversal rules (branch arms are followed, near calls are
queued by depth, far and indirect calls are recorded but not followed), the straight-line
AH and operand inference, and the closure verdict. Each claim has a mutated-byte
falsification that must change the result. The retail anchor runs only when
OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and is skipped otherwise.
Nothing here writes outside a temporary folder; the retail run reads the install read-only.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_wall_callee_probe as cp  # noqa: E402

ENV = "OPENUA_POR_INSTALL"

ROOT = 0x100
A = 0x140
B = 0x180


def _fixture(*, root_rel=b"\x3d\x00", jne_rel=0x05, a_ah=0x3D, b_int=0x21, a_call=None):
    """Root at 0x100 calls A (fall-through) and, on the taken arm of a JNE, calls B.

    100: E8 3D 00      call A (0x140)            end 0x103 + 0x3D = 0x140
    103: 84 C0         test al,al
    105: 75 05         jne 0x10C                  end 0x107 + 5 = 0x10C
    107: C3            ret
    10C: E8 71 00      call B (0x180)            end 0x10F + 0x71 = 0x180
    10F: C3            ret
    140: B4 3D         mov ah,3Dh                 (A)
    142: CD 21         int 21h
    144: C3            ret
    180: B4 3F         mov ah,3Fh                 (B)
    182: CD 21         int 21h
    184: C3            ret
    """
    b = bytearray(0x400)
    b[0x100:0x103] = b"\xe8" + root_rel
    b[0x103:0x105] = b"\x84\xc0"
    b[0x105:0x107] = bytes([0x75, jne_rel])
    b[0x107] = 0xC3
    b[0x108:0x10C] = b"\x90\x90\x90\x90"
    b[0x10C:0x10F] = b"\xe8\x71\x00"
    b[0x10F] = 0xC3
    b[A:A + 2] = bytes([0xB4, a_ah])
    b[A + 2:A + 4] = bytes([0xCD, 0x21])
    b[A + 4] = 0xC3
    b[B:B + 2] = b"\xb4\x3f"
    b[B + 2:B + 4] = bytes([0xCD, b_int])
    b[B + 4] = 0xC3
    return bytes(b)


def _run(data, **kw):
    kw.setdefault("max_depth", 3)
    return cp.analyse(data, root=ROOT, **kw)


def _proc_entries(doc):
    return {p["entry"] for p in doc["procs"]}


def _edge(doc, frm, at):
    for e in doc["call_edges"]:
        if e["from"] == frm and e["at"] == at:
            return e
    return None


# ---- traversal: near calls queued by depth, branch arms followed --------------

def test_near_calls_and_branch_arm_are_traversed():
    doc = _run(_fixture(), max_depth=1)
    assert _proc_entries(doc) == {ROOT, A, B}
    assert _edge(doc, ROOT, 0x100)["to"] == A
    assert _edge(doc, ROOT, 0x10C)["to"] == B          # only on the taken arm of the JNE
    assert _edge(doc, ROOT, 0x10C)["callee_depth"] == 1
    assert doc["verdict"]["closure_complete"] is True
    assert doc["frontier"] == []


def test_branch_only_call_is_in_root_coverage_without_entering_callees():
    doc = _run(_fixture(), max_depth=0)
    root = next(p for p in doc["procs"] if p["entry"] == ROOT)
    assert [c["target"] for c in root["near_calls"]] == [A, B]
    assert any(s <= 0x10C < e for s, e in root["ranges"])  # the taken-arm call is decoded
    assert _proc_entries(doc) == {ROOT}
    assert {f["entry"] for f in doc["frontier"]} == {A, B}
    assert all(f["reason"] == "depth-limit" for f in doc["frontier"])
    assert doc["verdict"]["closure_complete"] is False
    assert doc["verdict"]["dos_file_function_hits"] == []
    assert doc["verdict"]["answer"] == "no-dos-file-function-found-but-bounded-incomplete"


def test_dos_open_and_read_found_in_bounds():
    doc = _run(_fixture(), max_depth=1)
    hits = {(h["proc"], h["ah"], h["function"]) for h in doc["verdict"]["dos_file_function_hits"]}
    assert hits == {(A, 0x3D, "open"), (B, 0x3F, "read")}
    assert doc["verdict"]["answer"] == "dos-file-function-reached-in-bounds"
    assert doc["verdict"]["selection_reached"] == "not-established"


# ---- mutated-byte falsifications ----------------------------------------------

def test_mutated_jne_displacement_removes_the_branch_only_call():
    base = _run(_fixture(), max_depth=1)
    mut = _run(_fixture(jne_rel=0x00), max_depth=1)
    assert _edge(base, ROOT, 0x10C) is not None
    assert _edge(mut, ROOT, 0x10C) is None
    assert B in _proc_entries(base) and B not in _proc_entries(mut)
    assert all(h["proc"] != B for h in mut["verdict"]["dos_file_function_hits"])


def test_mutated_call_displacement_changes_the_edge_target():
    doc = _run(_fixture(root_rel=b"\x3e\x00"), max_depth=1)
    assert _edge(doc, ROOT, 0x100)["to"] == 0x141
    assert A not in _proc_entries(doc)


def test_mutated_ah_immediate_changes_the_dos_function():
    doc = _run(_fixture(a_ah=0x4C), max_depth=1)
    a_ints = [s for p in doc["procs"] if p["entry"] == A for s in p["ints"]]
    assert a_ints[0]["ah"]["value"] == 0x4C
    hits = {(h["proc"], h["function"]) for h in doc["verdict"]["dos_file_function_hits"]}
    assert (A, "open") not in hits
    assert hits == {(B, "read")}


def test_mutated_int_vector_removes_the_dos_call():
    doc = _run(_fixture(b_int=0x20), max_depth=1)
    hits = {(h["proc"], h["function"]) for h in doc["verdict"]["dos_file_function_hits"]}
    assert (B, "read") not in hits
    assert hits == {(A, "open")}


# ---- AH inference: a join or an intervening writer makes AH unknown -----------

def test_int_at_branch_target_has_unknown_ah():
    b = bytearray(0x200)
    b[0x100:0x104] = b"\xb4\x3d\x75\x00"      # mov ah,3Dh ; jne +0 -> 0x104 (the INT is a join)
    b[0x104:0x106] = b"\xcd\x21"
    b[0x106] = 0xC3
    doc = cp.analyse(bytes(b), root=0x100, max_depth=0)
    rec = doc["verdict"]["int21_ah_unknown"]
    assert len(rec) == 1 and rec[0]["ah_rule"] == "int-is-branch-target"
    assert doc["verdict"]["dos_file_function_hits"] == []
    assert doc["verdict"]["answer"] == "no-dos-file-function-found-but-bounded-incomplete"


def test_intervening_writer_makes_ah_unknown():
    b = bytearray(0x200)
    b[0x100:0x104] = b"\xb4\x3d\x04\x01"      # mov ah,3Dh ; add al,1 (conservative: not neutral)
    b[0x104:0x106] = b"\xcd\x21"
    b[0x106] = 0xC3
    doc = cp.analyse(bytes(b), root=0x100, max_depth=0)
    rec = doc["verdict"]["int21_ah_unknown"]
    assert rec and rec[0]["ah_rule"] == "intervening-unknown-writer"
    assert doc["verdict"]["dos_file_function_hits"] == []


def test_push_is_neutral_but_pop_ax_is_an_unknown_writer():
    b = bytearray(0x200)
    b[0x100:0x104] = b"\xb4\x3f\x50\x58"      # mov ah,3Fh ; push ax ; pop ax  -> pop writes AX, unknown
    b[0x104:0x106] = b"\xcd\x21"
    b[0x106] = 0xC3
    doc = cp.analyse(bytes(b), root=0x100, max_depth=0)
    assert doc["verdict"]["int21_ah_unknown"]  # pop ax is a writer, so the rule must not guess
    b2 = bytearray(0x200)
    b2[0x100:0x103] = b"\xb4\x3f\x51"          # mov ah,3Fh ; push cx (neutral)
    b2[0x103:0x105] = b"\xcd\x21"
    b2[0x105] = 0xC3
    doc2 = cp.analyse(bytes(b2), root=0x100, max_depth=0)
    assert [h["function"] for h in doc2["verdict"]["dos_file_function_hits"]] == ["read"]


# ---- far, indirect, decode and budget limits ----------------------------------

def _single(code, **kw):
    b = bytearray(0x400)
    b[0x100:0x100 + len(code)] = code
    return cp.analyse(bytes(b), root=0x100, max_depth=0, **kw)


def test_far_call_is_recorded_not_followed():
    doc = _single(b"\x9a\x00\x00\x10\x00\xc3")
    far = doc["verdict"]["far_calls_not_followed"]
    assert [(f["seg"], f["off"]) for f in far] == [(0x0010, 0x0000)]
    # closure_complete is about the followed closure; an unfollowed far call makes the answer incomplete.
    assert doc["verdict"]["closure_complete"] is True
    assert doc["verdict"]["answer"] == "no-dos-file-function-found-but-bounded-incomplete"


def test_mutated_far_call_opcode_removes_the_edge():
    doc = _single(b"\x90\x90\x90\x90\x90\xc3")
    assert doc["verdict"]["far_calls_not_followed"] == []
    assert doc["verdict"]["answer"] == "no-dos-file-function-in-closure"  # the unfollowed edge was what kept it open


def test_indirect_call_is_recorded_not_followed():
    doc = _single(b"\xff\xd0\xc3")            # call ax
    ind = doc["verdict"]["indirect_calls_not_followed"]
    assert [i["kind"] for i in ind] == ["indirect_call"]
    assert _single(b"\x90\x90\xc3")["verdict"]["indirect_calls_not_followed"] == []


def test_zero_f_opcode_marks_the_procedure_incomplete():
    doc = _single(b"\x0f\x80\x00\x00\xc3")
    codes = [x["code"] for x in doc["verdict"]["incomplete"]]
    assert any(c.startswith("unsupported-opcode-0x0f") for c in codes)
    assert doc["verdict"]["closure_complete"] is False


def test_instruction_budget_truncation_is_reported():
    doc = _run(_fixture(), max_depth=1, max_insns=2)
    codes = {x["code"] for x in doc["verdict"]["incomplete"]}
    assert "insn-budget" in codes
    assert doc["verdict"]["closure_complete"] is False
    assert doc["verdict"]["answer"] != "no-dos-file-function-in-closure"


# ---- selector and operand candidates -------------------------------------------

def test_mul_operand_from_straight_line_mov_is_reported():
    doc = _single(b"\xba\x9c\x00\xf7\xe2\xc3")   # mov dx,0x9C ; mul dx
    sel = [s for s in doc["verdict"]["selector_candidates"] if s["kind"] == "mul-div"]
    assert len(sel) == 1
    assert sel[0]["at"] == 0x103
    assert sel[0]["operand"]["value"] == 156
    assert sel[0]["operand"]["source"] == 0x100


def test_mutated_mov_immediate_changes_the_operand():
    doc = _single(b"\xba\x9d\x00\xf7\xe2\xc3")   # 0x9D = 157
    sel = [s for s in doc["verdict"]["selector_candidates"] if s["kind"] == "mul-div"]
    assert sel[0]["operand"]["value"] == 157


def test_mutated_mul_opcode_removes_the_selector():
    doc = _single(b"\xba\x9c\x00\x90\x90\xc3")
    assert [s for s in doc["verdict"]["selector_candidates"] if s["kind"] == "mul-div"] == []


def test_shift_by_immediate_is_a_selector_candidate():
    doc = _single(b"\xc1\xe0\x03\xc3")          # shl ax,3
    sel = doc["verdict"]["selector_candidates"]
    assert [(s["kind"], s["imm"]) for s in sel] == [("shift-imm", 3)]
    doc2 = _single(b"\xc1\xe0\x05\xc3")         # shl ax,5
    assert [s["imm"] for s in doc2["verdict"]["selector_candidates"]] == [5]


# ---- string-token candidates (necessary-condition checks only) -----------------

def test_low16_token_offset_match_is_a_candidate_and_mutation_removes_it():
    b = bytearray(0x400)
    b[0x3A1:0x3A8] = b"WALLDEF"
    b[0x100:0x103] = b"\xb8\xa1\x03"            # mov ax, 0x3A1 (low 16 bits of WALLDEF's offset)
    b[0x103] = 0xC3
    doc = cp.analyse(bytes(b), root=0x100, max_depth=0)
    assert [t["token"] for t in doc["verdict"]["string_token_candidates"]] == ["WALLDEF"]
    b[0x101] = 0xA2                             # mutate the immediate
    doc2 = cp.analyse(bytes(b), root=0x100, max_depth=0)
    assert doc2["verdict"]["string_token_candidates"] == []


# ---- determinism, output shape, refusals ---------------------------------------

def test_analysis_is_deterministic_and_path_free():
    a = json.dumps(_run(_fixture(), max_depth=2), sort_keys=True)
    b = json.dumps(_run(_fixture(), max_depth=2), sort_keys=True)
    assert a == b
    assert "\\" not in a and "C:" not in a  # no path text in the output


def test_unpinned_source_is_refused_without_flag(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"\x00" * 100)
    assert cp.main(["--install", str(install), "-o", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out").exists()


def test_unpinned_with_flag_writes_marked_output(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"\x00" * 100)
    out = tmp_path / "out"
    code = cp.main(["--install", str(install), "-o", str(out), "--allow-unpinned"])
    assert code == 1
    doc = json.loads((out / "por_wall_callee_probe.json").read_text(encoding="utf-8"))
    assert doc["source"]["pin"] == "unpinned"
    assert "unpinned-source" in doc["diagnostics"]
    assert doc["playable"] is False and doc["mappings"] == []


def test_output_inside_install_is_refused(tmp_path):
    install = tmp_path / "install"
    install.mkdir()
    (install / "GAME.OVR").write_bytes(b"\x00" * 100)
    assert cp.main(["--install", str(install), "-o", str(install / "out"), "--allow-unpinned"]) == 2


# ---- retail anchor (gated) -----------------------------------------------------

def _retail_dir():
    p = os.environ.get(ENV)
    if not p:
        pytest.skip("set %s to the Pool of Radiance POOLRAD folder to run" % ENV)
    return Path(p)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retail_owner_closure_matches_the_recorded_static_result(tmp_path):
    inst = _retail_dir()
    ovr = inst / "GAME.OVR" if (inst / "GAME.OVR").is_file() else inst / "POOLRAD" / "GAME.OVR"
    before = _sha(ovr)
    out = tmp_path / "out"
    code = cp.main(["--install", str(inst), "-o", str(out)])
    assert _sha(ovr) == before                        # read-only
    assert code == 0
    doc = json.loads((out / "por_wall_callee_probe.json").read_text(encoding="utf-8"))
    assert doc["source"]["pin"] == "pinned"
    chk = doc["owner_cross_check"]
    assert chk["seeds_match"] is True and chk["diagnostics"] == []
    assert chk["instruction_count"] == 827 and chk["near_call_count"] == 39
    assert chk["far_call_count"] == 0 and chk["interrupt_count"] == 0
    assert sorted(p["entry"] for p in doc["procs"]) == sorted([cp.OWNER] + list(cp.EXPECTED_SEEDS))
    v = doc["verdict"]
    assert v["closure_complete"] is True and doc["frontier"] == []
    assert v["dos_file_function_hits"] == [] and v["int21_ah_unknown"] == []
    assert v["answer"] == "no-dos-file-function-found-but-bounded-incomplete"
    assert v["selection_reached"] == "not-established"
    far = sorted({(f["seg"], f["off"]) for f in v["far_calls_not_followed"]})
    assert far == [(1064, 42), (1124, 6994), (1124, 9778)]
    mul156 = [s for s in v["selector_candidates"]
              if s["proc"] == 0x2EB08 and s["kind"] == "mul-div" and s["operand"]
              and s["operand"]["value"] == 156]
    assert len(mul156) == 2
    # Determinism: a second run gives byte-identical output.
    out2 = tmp_path / "out2"
    cp.main(["--install", str(inst), "-o", str(out2)])
    assert (out / "por_wall_callee_probe.json").read_bytes() == (out2 / "por_wall_callee_probe.json").read_bytes()
