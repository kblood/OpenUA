"""Tests for tools/por_loadpieces_handler.py (PoR GAME.OVR 0x37 handler probe).

Default suite: synthetic bytes only, hand-encoded. The decoder is checked
against instruction encodings written out by hand (lengths, flow classes,
branch targets), and the dispatcher, handler and caller analyses run on
synthetic blobs with the same shapes as the retail code.

The retail test runs only when OPENUA_POR_INSTALL names a PoR install folder
and is skipped otherwise. It pins the structural facts the probe reports for
the user-supplied GAME.OVR; it does not test any PoR semantics.
"""
import json
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_loadpieces_handler as h  # noqa: E402
from por_convert import PorSourceError  # noqa: E402


def dec(hexstr: str, at: int = 0):
    raw = bytes.fromhex(hexstr.replace(" ", ""))
    return h.decode(bytes(at) + raw, at)


# ---- decoder: hand-encoded instructions ------------------------------------

@pytest.mark.parametrize("hexstr,length,flow", [
    ("55", 1, "seq"),                  # push bp
    ("89 e5", 2, "seq"),               # mov bp, sp
    ("83 ec 0c", 3, "seq"),            # sub sp, imm8
    ("b0 03", 2, "seq"),               # mov al, 3
    ("50", 1, "seq"),                  # push ax
    ("0e", 1, "seq"),                  # push cs
    ("a0 7f 6f", 3, "seq"),            # mov al, [0x6f7f]
    ("80 7e fc 03", 4, "seq"),         # cmp byte [bp-4], 3
    ("c6 06 31 44 01", 5, "seq"),      # mov byte [0x4431], 1
    ("c3", 1, "ret"),                  # ret
    ("cb", 1, "retf"),                 # retf
    ("c2 02 00", 3, "ret"),            # ret 2
    ("9a 2a 00 2b 00", 5, "call_far"), # call far 0x2b:0x2a
    ("ff d0", 2, "indirect_call"),     # call ax
    ("ff e0", 2, "indirect_jmp"),      # jmp ax
    ("eb 03", 2, "jmp"),               # jmp short
    ("75 e2", 2, "jcc"),               # jne short
    ("e3 00", 2, "jcc"),               # jcxz
])
def test_decoder_length_and_flow(hexstr, length, flow):
    ins = dec(hexstr)
    assert ins.length == length
    assert ins.flow == flow


def test_decoder_near_call_and_branch_targets():
    call = dec("e8 14 dc", 0x3DA3)           # rel16 = 0xdc14 = -0x23ec
    assert call.flow == "call" and call.length == 3
    assert call.target == 0x3DA6 - 0x23EC == 0x19BA
    jne = dec("75 07", 0x3C7B)
    assert jne.target == 0x3C7D + 7
    jmp = dec("e9 31 02", 0x3C81)
    assert jmp.target == 0x3C84 + 0x231


def test_decoder_far_literal_and_direct_reference():
    far = dec("9a 2a 00 2b 00")
    assert far.far == (0x2B, 0x2A)           # (seg, off)
    direct = dec("a0 7f 6f")
    assert direct.direct == 0x6F7F
    bp = dec("88 46 fc")                     # mov [bp-4], al
    assert bp.bp_disp == -4


def test_decoder_refuses_unsupported_and_truncated():
    with pytest.raises(h.DecodeError) as exc:
        dec("0f 80 00 00")
    assert exc.value.reason.startswith("unsupported-opcode-0x0f")
    with pytest.raises(h.DecodeError) as exc:
        dec("e8 14")
    assert exc.value.reason == "truncated"


# ---- synthetic dispatcher and handler --------------------------------------

def _rel16(site_end: int, target: int) -> bytes:
    return ((target - site_end) & 0xFFFF).to_bytes(2, "little")


def _chain(base: int, cases: dict, break_path: bool = False) -> bytes:
    """Build a dispatcher-shaped blob at ``base``: a key load, then one
    ``cmp al,v; jne +7; push cs; call near T; jmp end`` block per case (11
    bytes each). ``break_path`` inserts ``inc al`` on the not-equal path just
    after the first case, which the path check must flag."""
    code = bytearray.fromhex("55 89 e5 a0 7f 6f")
    jmp_sites = []
    for idx, (v, target) in enumerate(cases.items()):
        s = len(code)
        code += bytes([0x3C, v, 0x75, 0x07, 0x0E, 0xE8, 0, 0, 0xE9, 0, 0])
        code[s + 6:s + 8] = _rel16(base + s + 8, target)  # call near at s+5, ends at s+8
        jmp_sites.append(s + 8)                        # jmp ends at s+11
        if break_path and idx == 0:
            code += bytes([0xFE, 0xC0])                # inc al
    end = len(code)
    code += bytes([0xC3])                              # ret ends the linear sweep
    for j in jmp_sites:
        code[j + 1:j + 3] = _rel16(base + j + 3, base + end)
    buf = bytearray(base) + code
    return bytes(buf)


def test_dispatch_finds_0x37_case_and_clean_path():
    base = h.DISPATCH_ENTRY
    data = _chain(base, {0x00: 0x0D47, 0x01: 0x0E3A, 0x37: h.HANDLER_0X37})
    d = h.dispatch_cases(data)
    assert d["key_source"] == "mov al, [0x6f7f]"
    assert d["opcode_0x37"]["call_target"] == h.HANDLER_0X37
    assert d["opcode_0x37"]["form"] == "jne-push-cs-call"
    assert d["not_equal_path_to_0x37"]["reached"] is True
    assert d["not_equal_path_to_0x37"]["clobber"] == []
    assert d["doc_count_matches"] is False        # synthetic chain is not 273 instructions


def test_dispatch_path_check_flags_an_instruction_on_the_path():
    base = h.DISPATCH_ENTRY
    data = _chain(base, {0x00: 0x0D47, 0x37: h.HANDLER_0X37}, break_path=True)
    d = h.dispatch_cases(data)
    path = d["not_equal_path_to_0x37"]
    assert path["reached"] is False
    assert path["reason"] == "non-compare-on-path" or path["reason"] == "unexpected-branch"


def test_walk_handler_shape_loop_and_retf():
    # push bp; mov bp,sp; mov byte [bp-4],1; L: inc byte[bp-4]; cmp byte[bp-4],3;
    # jne L; retf
    code = bytes.fromhex("55 89 e5 c6 46 fc 01"          # 0..6
                         "fe 46 fc"                       # 7: inc byte [bp-4]
                         "80 7e fc 03"                    # 10: cmp byte [bp-4], 3
                         "75 f7"                          # 14: jne back to 7
                         "cb")                            # 16: retf
    data = bytes(code)
    w = h.walk(data, 0)
    assert w["complete"] is True
    assert w["returns"][0]["kind"] == "retf"
    assert w["near_calls"] == []
    assert w["backedges"] and w["backedges"][0]["to"] == 7
    assert w["backedges"][0]["preceded_by"] == "cmp [bp-4], 0x3"
    assert -4 in w["bp_refs"]


def test_walk_marks_indirect_jump_incomplete():
    data = bytes.fromhex("55 89 e5 ff e0")
    w = h.walk(data, 0)
    assert w["complete"] is False
    assert any(item["code"] == "indirect_jmp" for item in w["incomplete"])


def test_walk_records_near_and_far_calls_without_entering_them():
    # 0: push bp; mov bp,sp | 3: push cs | 4: call near (to 12) | 7: call far 0x2b:0x2a | 12: retf
    code = bytearray.fromhex("55 89 e5 0e e8 00 00 9a 2a 00 2b 00 cb")
    code[5:7] = _rel16(7, 12)
    w = h.walk(bytes(code), 0)
    assert w["complete"] is True
    assert w["near_calls"] == [{"at": 4, "target": 12, "push_cs_before": True}]
    assert w["far_calls"] == [{"at": 7, "seg": 0x2B, "off": 0x2A}]


def test_near_call_candidates_exact_target_and_push_cs_flag():
    data = bytearray(b"\x90" * 0x20)
    data[0x10] = 0xE8
    data[0x11:0x13] = _rel16(0x13, 0x18)
    data[0x0F] = 0x0E
    got = h.near_call_candidates(bytes(data), 0x18)
    assert got == [{"at": 0x10, "push_cs_before": True}]


def test_far_literal_candidates_match_offset_only():
    data = bytes.fromhex("9a 2a 00 2b 00") + bytes.fromhex("9a 2b 00 2c 00")
    got = h.far_call_literal_candidates(data, 0x2A)
    assert got == [{"at": 0, "seg": 0x2B}]


# ---- probe: refusal, pin, determinism -------------------------------------

def _fake_install(tmp_path: Path, payload: bytes) -> Path:
    inst = tmp_path / "install"
    (inst / "POOLRAD").mkdir(parents=True)
    (inst / "POOLRAD" / "GAME.OVR").write_bytes(payload)
    return inst


def test_probe_refuses_unpinned_game_ovr_by_default(tmp_path):
    inst = _fake_install(tmp_path, b"\x00" * 64)
    with pytest.raises(PorSourceError) as exc:
        h.probe(inst, tmp_path / "out")
    assert "pinned" in str(exc.value)
    assert h.main(["--install", str(inst), "-o", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out").exists()


def test_probe_allow_unpinned_writes_outputs_and_marks_pin_false(tmp_path):
    inst = _fake_install(tmp_path, b"\x00" * 64)
    out = tmp_path / "out"
    code = h.main(["--install", str(inst), "-o", str(out), "--allow-unpinned"])
    assert code == 1                              # dispatcher absent in a 64-byte file
    doc = json.loads((out / "por_loadpieces_handler.json").read_text(encoding="utf-8"))
    assert doc["playable"] is False
    assert doc["status"] == h.STATUS
    assert doc["source"]["pin_match"] is False
    assert doc["not_established"]
    text = (out / "por_loadpieces_handler_report.md").read_text(encoding="utf-8")
    assert "Not established" in text and "NO (unpinned" in text


def test_outputs_are_deterministic(tmp_path):
    inst = _fake_install(tmp_path, b"\x00" * 64)
    a, b = tmp_path / "a", tmp_path / "b"
    h.main(["--install", str(inst), "-o", str(a), "--allow-unpinned"])
    h.main(["--install", str(inst), "-o", str(b), "--allow-unpinned"])
    assert (a / "por_loadpieces_handler.json").read_bytes() == (b / "por_loadpieces_handler.json").read_bytes()
    assert (a / "por_loadpieces_handler_report.md").read_bytes() == (b / "por_loadpieces_handler_report.md").read_bytes()


def test_output_inside_install_is_refused(tmp_path):
    inst = _fake_install(tmp_path, b"\x00" * 64)
    assert h.main(["--install", str(inst), "-o", str(inst / "POOLRAD" / "out"),
                   "--allow-unpinned"]) == 2


# ---- optional retail structural test --------------------------------------

RETAIL = os.environ.get("OPENUA_POR_INSTALL")


@pytest.mark.skipif(not RETAIL, reason="OPENUA_POR_INSTALL not set; retail GAME.OVR not used")
def test_retail_structure_pinned(tmp_path):
    install = Path(RETAIL)
    doc, code = h.probe(install, tmp_path / "out")
    assert doc["source"]["pin_match"] is True
    a = doc["analysis"]
    d = a["dispatcher"]
    assert d["doc_count_matches"] is True
    assert d["key_source"] == "mov al, [0x6f7f]"
    assert d["opcode_0x37"]["call_target"] == h.HANDLER_0X37
    assert d["not_equal_path_to_0x37"]["reached"] is True
    hd = a["handler_0x37"]
    assert hd["complete"] is True and hd["near_calls"] == []
    assert hd["returns"] == [{"at": 6964, "imm": None, "kind": "retf"}]
    assert a["handler_far_call_segments"] == [43, 186, 981, 1001, 2808]
    assert a["handler_reaches_parser_by_near_call"] is False
    p = a["parser"]
    assert p["complete"] is True and p["prologue_matches"] is True
    assert p["returns"] == [{"at": 30214, "imm": 2, "kind": "retf"}]
    assert len(a["callers"]["near_calls_to_parser_0x74d3"]) == 13
    assert code == 0
