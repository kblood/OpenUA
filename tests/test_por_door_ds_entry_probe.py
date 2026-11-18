"""Tests for tools/por_door_ds_entry_probe.py (DS of callf [0x43F0] in the INT 3Fh dispatcher, START 0x0A9FC).

Synthetic tests use hand-encoded 8086 bytes and need no install. Each has a falsifier: a single changed
byte or field must change the reported fact, or the probe must refuse. The retail tests run only when a
pinned PoR install is present (OPENUA_POR_INSTALL, or data/work/por-geo-run/POOLRAD) and pin the byte facts
the probe reports. They test no PoR semantics beyond those bytes and never run an emulator.
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
import por_door_ds_entry_probe as d  # noqa: E402
import por_door_caller_probe as dc  # noqa: E402
import por_loadpieces_handler as lh  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
RETAIL_INSTALL = Path(os.environ["OPENUA_POR_INSTALL"]) if os.environ.get("OPENUA_POR_INSTALL") \
    else REPO / "data" / "work" / "por-geo-run" / "POOLRAD"
HAVE_RETAIL = (RETAIL_INSTALL / "GAME.OVR").is_file() and (RETAIL_INSTALL / "START.EXE").is_file()
needs_retail = pytest.mark.skipif(not HAVE_RETAIL, reason="pinned PoR install not present")

# Synthetic layout (file offsets inside a 0x100-byte blob)
D0, MOV_AX, MOV_DS, CALL_SLOT, CALLF, POP_DS, IRET = 0x10, 0x14, 0x17, 0x19, 0x1C, 0x20, 0x21
CALLEE = 0x60


def _dispatch_blob(callee: bytes = b"\xc3", call_between: bool = True, mov_imm: int = 0x0C7C,
                   mov_ds: bytes = b"\x8e\xd8", ptr: int = 0x43F0, pre: bytes = b"") -> bytes:
    b = bytearray(0x100)
    b[D0:D0 + 3] = b"\x55\x8b\xec"                     # push bp; mov bp,sp
    if pre:
        b[D0:D0 + len(pre)] = pre                       # optional prologue override (falsifiers)
    b[0x13] = 0x1E                                      # push ds
    b[MOV_AX:MOV_AX + 3] = b"\xb8" + struct.pack("<H", mov_imm)
    b[MOV_DS:MOV_DS + 2] = mov_ds
    if call_between:
        rel = CALLEE - (CALL_SLOT + 3)
        b[CALL_SLOT:CALL_SLOT + 3] = b"\xe8" + struct.pack("<h", rel)
    else:
        b[CALL_SLOT:CALL_SLOT + 3] = b"\x90\x90\x90"
    b[CALLF:CALLF + 4] = b"\xff\x1e" + struct.pack("<H", ptr)
    b[POP_DS] = 0x1F
    b[IRET] = 0xCF
    b[CALLEE:CALLEE + len(callee)] = callee
    return bytes(b)


def _insns(data: bytes, roots: list[int]) -> dict:
    cl = d.closure(data, roots, 0, len(data))
    return d.decode_listings(data, list(cl.values()))


def _chain(data: bytes) -> dict:
    ins = _insns(data, [D0])
    return d.chain_facts(data, ins, D0, MOV_AX, MOV_DS, CALLF, 0x0C7C, 0x43F0)


# ---------------------------------------------------------------- chain: AX and DS established


def test_chain_positive_synthetic():
    ch = _chain(_dispatch_blob())
    assert ch["mov_ax_imm"]["ok"] and ch["mov_ds_ax"]["ok"] and ch["callf"]["ok"]
    assert ch["branch_before_ds_load"] == []
    assert ch["dispatch_walk_complete"] is True
    assert [c["flow"] for c in ch["calls_between_ds_and_callf"]] == ["call"]
    assert ch["ds_writers_between_ds_and_callf"] == []


def test_falsifier_changed_immediate_breaks_ax_check():
    ch = _chain(_dispatch_blob(mov_imm=0x0C7D))
    assert ch["mov_ax_imm"]["ok"] is False


def test_falsifier_mov_ds_from_bx_breaks_ds_check():
    ch = _chain(_dispatch_blob(mov_ds=b"\x8e\xdb"))      # mov ds,bx
    assert ch["mov_ds_ax"]["ok"] is False


def test_falsifier_callf_other_pointer_breaks_callf_check():
    ch = _chain(_dispatch_blob(ptr=0x43F2))
    assert ch["callf"]["ok"] is False


def test_falsifier_branch_before_ds_load_is_reported():
    # a jz at the prologue (0x10) before the AX/DS load
    ch = _chain(_dispatch_blob(pre=b"\x74\x00"))
    assert ch["branch_before_ds_load"], "a jcc before the DS load must be reported"


def test_bypass_edge_from_outside_is_detected():
    data = bytearray(_dispatch_blob())
    data[0x80:0x83] = b"\xe9" + struct.pack("<h", MOV_DS - (0x80 + 3))   # jmp to the mov ds
    data = bytes(data)
    ins = _insns(data, [D0, 0x80])
    body = {r["at"] for r in lh.walk(data, D0)["listing"]}
    edges = d.edges_into(ins, body, MOV_AX + 1, CALLF)
    assert edges["near_or_jump"], "a jump from outside into the AX/DS load must be reported"


def test_no_bypass_edge_without_outside_jump():
    data = _dispatch_blob()
    ins = _insns(data, [D0])
    body = {r["at"] for r in lh.walk(data, D0)["listing"]}
    edges = d.edges_into(ins, body, MOV_AX + 1, CALLF)
    assert edges == {"near_or_jump": [], "far_literal": []}


# ---------------------------------------------------------------- callee closure and DS discipline


def _callee_audit(callee: bytes):
    data = _dispatch_blob(callee=callee)
    ins = _insns(data, [D0])
    return d.callee_audit(data, [CALLEE], 0, len(data), ins)


def test_callee_bracketed_ds_write_is_not_open():
    # push ds; mov ds,bx; pop ds; ret
    res = _callee_audit(b"\x1e\x8e\xdb\x1f\xc3")
    fn = res["functions"][0]
    assert fn["ds"] == "bracketed"
    assert res["free_of_open_edges"] is True


def test_callee_audit_decodes_instructions_missing_from_the_census():
    # the image census may not walk a callee; the audit must decode it, not report it as "none"
    data = _dispatch_blob(callee=b"\x1e\x8e\xdb\x1f\xc3")
    res = d.callee_audit(data, [CALLEE], 0, len(data), {})
    assert res["functions"][0]["ds"] == "bracketed"


def test_falsifier_unbalanced_ds_write_is_open():
    # mov ds,bx; ret   (no push ds / pop ds)
    res = _callee_audit(b"\x8e\xdb\xc3")
    assert res["functions"][0]["ds"] == "open"
    assert res["free_of_open_edges"] is False
    assert any(e["kind"] == "ds-unbalanced" for e in res["open_edges"])


def test_falsifier_far_call_in_callee_is_open():
    # call far 0000:0000 ; ret
    res = _callee_audit(b"\x9a\x00\x00\x00\x00\xc3")
    assert res["free_of_open_edges"] is False
    assert any(e["kind"] == "far-call" for e in res["open_edges"])


def test_plain_callee_is_free():
    res = _callee_audit(b"\xc3")
    assert res["free_of_open_edges"] is True
    assert res["functions"][0]["ds"] == "none"


def test_ds_discipline_bracket_is_address_order_check():
    data = bytes.fromhex("1e8edb1fc3")
    ins = d.decode_listings(data, [lh.walk(data, 0)])
    dis = d.ds_discipline(data, ins, sorted(ins))
    assert dis["status"] == "bracketed"
    assert dis["pushes"] == ["0x00000"] and dis["restores"] == ["0x00003"]


def test_access_class_for_store_and_read():
    data = bytes.fromhex("c706f043e502") + bytes.fromhex("a1f043") + b"\xc3"
    ins = d.decode_listings(data, [lh.walk(data, 0)])
    assert d.access_class(ins[0]) == "write"
    assert d.access_class(ins[6]) == "read"


# ---------------------------------------------------------------- residue arithmetic


def test_routine_a_pointer_needs_skew_seven_to_reach_stub1():
    assert d.required_skew(0x02E5, d.STUB1) == 7
    assert d.reaches_under(0x02E5, d.STUB1, d.MODELS["M0"]) is False
    assert d.reaches_under(0x02E5, d.STUB1, d.MODELS["M1"]) is False


def test_positive_control_residue_match_reaches_under_m0():
    # offset 0x0C with seg 0x0069: seg*16+off = 0x069C = stub 1 under M0 (file = seg*16+off+0x200)
    assert d.reaches_under(0x000C, d.STUB1, d.MODELS["M0"]) is True
    assert d.required_skew(0x000C, d.STUB1) == 0


def test_quoted_live_shift_arithmetic_and_falsifier():
    # X: linear - file = 0x0854A (k = -shift, residue 6). The live pointer misses stub 1; INT 3Fh DX 0x2E6 hits 0xA9FC.
    live_k = -d.LIVE_QUOTED_SHIFT
    assert d.reaches_under(0x02E6, d.DISPATCH, live_k) is True
    assert d.reaches_under(0x02E5, d.STUB1, live_k) is False
    # falsifier: k = 7 (shift residue 9), the only residue that lets 0x2E5 reach stub 1, does reach it
    assert d.reaches_under(0x02E5, d.STUB1, 7) is True


def test_far_literal_site_hits_stub1_under_m0_only():
    data = bytearray(0x100)
    data[0x90:0x95] = b"\x9a\x0c\x00\x69\x00"          # call far 0069:000C
    hits = d.far_literal_sites(bytes(data), {"stub1": d.STUB1})
    assert [h["model"] for h in hits] == ["M0"]
    data[0x91] = 0x0D                                    # falsifier: off 0x000D
    assert d.far_literal_sites(bytes(data), {"stub1": d.STUB1}) == []


def test_near_raw_site_hits_dispatcher_entry():
    data = bytearray(0x100)
    rel = D0 - (0x90 + 3)
    data[0x90:0x93] = b"\xe8" + struct.pack("<h", rel)
    hits = d.near_raw_sites(bytes(data), {"dispatch": D0})
    assert hits and hits[0]["target"] == "dispatch"


def test_int3f_install_dx_residue_falsifier():
    base = bytearray(b"\x90" * 0x20)
    base[0x10:0x13] = b"\xba\xe6\x02"                   # mov dx,0x2E6
    base[0x13:0x18] = b"\xb8\x3f\x25\xcd\x21"           # mov ax,253Fh; int 21h
    inst = d.int3f_installs(bytes(base))
    assert inst[0]["dx"] == "0x02E6" and inst[0]["required_skew_to_dispatch"] == 6
    base[0x11] = 0xE7                                    # falsifier: dx 0x2E7
    assert d.int3f_installs(bytes(base))[0]["required_skew_to_dispatch"] == 5


# ---------------------------------------------------------------- DS:[43F0] references


def test_raw_refs_modrm_and_moffs_hit_but_data_pair_does_not():
    data = (b"\xc7\x06\xf0\x43\xe5\x02"        # mov word [43F0],0x2E5
            b"\xa3\xf0\x43"                    # mov [43F0],ax (moffs)
            b"\x43\xf0\x43\x06\x44")           # data: F0 43 not preceded by a ModRM disp16 opcode
    hits = d.raw_refs(data, {d.PTR_OFF}, None)
    assert sorted(h["kind"] for h in hits) == ["modrm-disp16", "moffs"]


def test_direct_refs_decoded_store_is_write():
    data = b"\xc7\x06\xf0\x43\xe5\x02\xc3"
    ins = d.decode_listings(data, [lh.walk(data, 0)])
    refs = d.direct_refs(ins, {d.PTR_OFF})
    assert len(refs) == 1 and refs[0]["class"] == "write" and refs[0]["disp"] == "0x43F0"


# ---------------------------------------------------------------- MZ facts and refusals


def _mz(nreloc_off: int) -> bytes:
    h = bytearray(0x40)
    h[0:2] = b"MZ"
    struct.pack_into("<H", h, 4, 1)           # e_cp
    struct.pack_into("<H", h, 6, 1)           # e_crlc (one relocation)
    struct.pack_into("<H", h, 8, 2)           # e_cparhdr -> hdr 0x20
    struct.pack_into("<H", h, 0x14, 0)        # ip
    struct.pack_into("<H", h, 0x16, 0)        # cs
    struct.pack_into("<H", h, 0x18, 0x1C)     # e_lfarlc
    struct.pack_into("<HH", h, 0x1C, nreloc_off, 0)   # fixup (off, seg)
    return bytes(h) + b"\x90" * 0x40


def test_mz_relocation_covers_fixup_word():
    data = _mz(0x08)
    mz = d.mz_facts(data)
    assert mz["hdr_bytes"] == 0x20 and mz["nreloc"] == 1
    assert d.reloc_covers(mz, 0x20 + 0x08, 0x20) is True       # first byte of the fixup word
    assert d.reloc_covers(mz, 0x20 + 0x09, 0x20) is True       # second byte of the same word
    assert d.reloc_covers(mz, 0x20 + 0x0A, 0x20) is False      # falsifier: the byte after the word


def test_probe_refuses_missing_install(tmp_path):
    with pytest.raises(dc.Refusal):
        d.probe(tmp_path)
    assert d.main(["--install", str(tmp_path), "-o", str(tmp_path / "out")]) == 2


def test_probe_refuses_unpinned_bytes(tmp_path):
    (tmp_path / "GAME.OVR").write_bytes(b"\x00" * 16)
    (tmp_path / "START.EXE").write_bytes(b"MZ" + b"\x00" * 16)
    with pytest.raises(dc.Refusal):
        d.probe(tmp_path)


# ---------------------------------------------------------------- retail anchor (gated)


@needs_retail
def test_retail_anchor_pins_the_byte_facts():
    ovr, start, pins = dc.load_pinned(RETAIL_INSTALL)
    doc = d.analyse(ovr, start)
    ch = doc["chain"]
    assert ch["mov_ax_imm"]["at"] == "0x0AA07" and ch["mov_ax_imm"]["ok"] is True
    assert ch["mov_ds_ax"]["at"] == "0x0AA0A" and ch["mov_ds_ax"]["ok"] is True
    assert ch["callf"]["at"] == "0x0AA40" and ch["callf"]["text"] == "callf [0x43f0]"
    assert ch["dispatch_instruction_count"] == 42 and ch["dispatch_walk_complete"] is True
    assert ch["branch_before_ds_load"] == []
    assert [c["target"] for c in ch["calls_between_ds_and_callf"]] == ["0x0AA4E", "0x0AA4E"]
    assert doc["bypass_edges_into_ax_ds_load_to_callf"] == {"near_or_jump": [], "far_literal": []}
    assert doc["decoded_or_raw_callers_of_dispatcher_entry"] == {"near_or_jump": [], "far_literal": []}
    # routine A: the only static initializer of DS:[43F0]
    ra = doc["routine_a"]
    assert ra["store_off"]["at"] == "0x0A7DE" and ra["store_off"]["imm"] == "0x02E5" and ra["store_off"]["ok"]
    assert ra["ds_before_store"]["status"] == "bracketed"
    assert ra["ds_at_store_equals_entry_ds"] is True
    assert ra["decoded_callers"] == {"near_or_jump": [], "far_literal": []}
    # callee closure between the DS load and the callf: exactly two open edges
    edges = doc["callee_audit_between_ds_and_callf"]["open_edges"]
    assert sorted((e["kind"], e["at"]) for e in edges) == [("far-call", "0x0A71C"), ("indirect_callf", "0x0AAC0")]
    # the two DS writers in the closure are bracketed (push ds / pop ds), not open
    fns = doc["callee_audit_between_ds_and_callf"]["functions"]
    assert sorted(f["entry"] for f in fns if f["ds"] == "bracketed") == ["0x0ABB4", "0x0ABFC"]
    assert sorted(f["entry"] for f in fns if f["ds"] == "open") == []
    # direct-address references to DS:[43F0]/[43F2]: five, all decoded; none in GAME.OVR
    assert len(doc["ds_43f0_refs_decoded"]) == 5 and doc["ds_43f0_refs_raw_start_uncovered"] == []
    assert doc["disp16_byte_pair_counts"]["F0 43 in GAME.OVR"] == 0
    assert doc["disp16_byte_pair_counts"]["F2 43 in GAME.OVR"] == 0
    # residues and models
    assert doc["required_skew"]["pointer_0x2E5_to_stub1"] == 7
    assert doc["model_reach"]["pointer_0x2E5_to_stub1"] == {"M0": False, "M1": False}
    lv = doc["live_quoted_shift"]
    assert lv["shift_linear_minus_file"] == "0x0854A" and lv["k_mod16"] == 6
    assert lv["pointer_0x2E5_reaches_stub1"] is False and lv["dx_0x2E6_reaches_dispatch"] is True
    assert lv["dx_0x0D7_reaches_dispatch"] is False
    assert lv["pointer_0x2E5_file_target_if_cs_is_12C6"] == "0x0A9FB"
    assert doc["verdict"]["live_quoted_shift_reaches_stub1"] is False
    assert doc["mz"]["nreloc"] == 0 and doc["mz_relocation_covers_mov_ax_immediate"] is False
    assert doc["census"]["covered_bytes"] == 34699
    assert doc["verdict"]["trigger_established"] is False and doc["playable"] is False
    assert [i["dx"] for i in doc["int3f_installs_raw"]] == ["0x02E6", "0x00D7"]
    assert doc["far_literal_sites_raw"] == [] and doc["near_literal_sites_raw"] == []


@needs_retail
def test_retail_run_is_read_only_and_deterministic(tmp_path):
    before = {n: hashlib.sha256((RETAIL_INSTALL / n).read_bytes()).hexdigest()
              for n in ("GAME.OVR", "START.EXE")}
    rc = d.main(["--install", str(RETAIL_INSTALL), "-o", str(tmp_path / "a")])
    assert rc == 0
    rc2 = d.main(["--install", str(RETAIL_INSTALL), "-o", str(tmp_path / "b")])
    assert rc2 == 0
    j1 = (tmp_path / "a" / "por_door_ds_entry_probe.json").read_text(encoding="utf-8")
    j2 = (tmp_path / "b" / "por_door_ds_entry_probe.json").read_text(encoding="utf-8")
    assert j1 == j2
    doc = json.loads(j1)
    assert doc["playable"] is False and doc["pins_rechecked"]["unchanged"] is True
    after = {n: hashlib.sha256((RETAIL_INSTALL / n).read_bytes()).hexdigest() for n in before}
    assert before == after
