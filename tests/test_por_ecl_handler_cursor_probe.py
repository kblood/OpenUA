"""Tests for tools/por_ecl_handler_cursor_probe.py.

Synthetic tests run everywhere. They use small hand-assembled byte buffers (a dispatcher case, a stream
loop, a handler) and mutate one thing at a time to exercise each falsifier. Retail tests are gated on
OPENUA_POR_INSTALL (the pinned POOLRAD folder) and skip without it; they write only under pytest's tmp_path.
"""

import json
import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import por_loadpieces_handler as h  # noqa: E402
import por_ecl_handler_cursor_probe as hc  # noqa: E402


# ---------------------------------------------------------------------------------------------
# A two-pass assembler for hand-built buffers. Parts: bytes | ("L", name) | ("AT", addr) |
# ("R8", opcode_bytes, label) | ("R16", opcode_bytes, label). R8/R16 put the displacement last.
# ---------------------------------------------------------------------------------------------

def assemble(parts: list, base: int = 0) -> tuple:
    labels: dict = {}
    pos = base
    for p in parts:
        if isinstance(p, bytes):
            pos += len(p)
        elif p[0] == "L":
            labels[p[1]] = pos
        elif p[0] == "AT":
            pos = p[1]
        elif p[0] == "R8":
            pos += len(p[1]) + 1
        elif p[0] == "R16":
            pos += len(p[1]) + 2
    size = 0x800
    out = bytearray(b"\x90" * size)
    pos = base
    for p in parts:
        if isinstance(p, bytes):
            out[pos:pos + len(p)] = p
            pos += len(p)
        elif p[0] == "AT":
            pos = p[1]
        elif p[0] == "R8":
            end = pos + len(p[1]) + 1
            rel = labels[p[2]] - end
            assert -128 <= rel <= 127, "rel8 out of range"
            out[pos:end] = p[1] + bytes([rel & 0xFF])
            pos = end
        elif p[0] == "R16":
            end = pos + len(p[1]) + 2
            out[pos:end] = p[1] + struct.pack("<h", labels[p[2]] - end)
            pos = end
    return bytes(out), labels


# The dispatcher case for one opcode, a shared group for two more, and a handler at 0x200.
def dispatcher(opcode: int = 0x1B, handler_is_0x200: bool = True, jnz_to: str = "next") -> tuple:
    parts = [
        b"\x55\x89\xe5",                           # push bp; mov bp,sp
        b"\xa0\x7f\x6f",                           # mov al,[0x6f7f]   (key read)
        ("L", "case"), bytes([0x3C, opcode]),      # cmp al,imm
        ("R8", b"\x75", jnz_to),                   # jnz next case
        b"\x0e",                                   # push cs
        ("R16", b"\xe8", "H"),                     # call handler
        ("R8", b"\xeb", "exit"),                   # jmp exit
        ("L", "next"), b"\x3c\x1c", b"\xc3",       # next case (cmp 0x1c); ret ends the linear sweep
        ("L", "exit"), b"\x5d\xcb",
        ("AT", 0x200), ("L", "H"), b"\x55\x5d\xcb",
    ]
    return assemble(parts, base=0x100)


def dispatcher_with_group(group_calls: int = 0x200, opcode_a: int = 0x16, opcode_b: int = 0x17) -> tuple:
    parts = [
        b"\x55\x89\xe5", b"\xa0\x7f\x6f",
        bytes([0x3C, opcode_a]), ("R8", b"\x74", "group"),          # je group
        bytes([0x3C, opcode_b]), ("R8", b"\x74", "group"),          # je group (second member)
        b"\xc3",
        ("AT", 0x180), ("L", "group"), b"\x0e", ("R16", b"\xe8", "G"), b"\x5d\xcb",
        ("AT", 0x200), ("L", "G"), b"\x55\x5d\xcb",
    ]
    data, labels = assemble(parts, base=0x100)
    # Patch the group's call so that its rel16 points at `group_calls` (lets a test use a different handler).
    g = labels["group"]
    rel = group_calls - (g + 1 + 3)
    data = bytearray(data)
    data[g + 2:g + 4] = struct.pack("<h", rel)
    return bytes(data), labels


# The stream loop: mov ax,[bp+6]; mov [0x49ed],ax; then head: key read, key store, dispatch, back-edge.
def loop_bytes(extra: bytes = b"", store_source: bytes = b"\xa2\x7f\x6f", inc_after: bytes = b"") -> tuple:
    parts = [
        ("L", "L"), b"\x55\x89\xe5",
        b"\x8b\x46\x06",                           # mov ax,[bp+6]
        b"\xa3\xed\x49",                           # mov [0x49ed],ax  (entry cursor from the argument)
        ("L", "head"), b"\x80\x3e\x2e\x44\x00",    # cmp [0x442e],0
        ("R8", b"\x75", "exit"),                   # jnz exit
        b"\xa0\x7f\x6f", b"\xa2\x7e\x6f",          # previous key -> [0x6f7e]
        b"\xa1\xed\x49",                           # mov ax,[0x49ed]
        b"\xc4\x3e\xde\x49",                       # les di,[0x49de]
        b"\x03\xf8",                               # add di,ax
        b"\x26\x8a\x85\x00\x67",                   # es mov al,[di+0x6700]  (stream byte at cursor)
    ] + ([extra] if extra else []) + [
        store_source,                              # mov [0x6f7f],al  (key store)
        b"\x0e",                                   # push cs
        ("R16", b"\xe8", "D"),                     # call dispatcher
    ] + ([inc_after] if inc_after else []) + [
        ("R8", b"\xeb", "head"),                   # jmp head
        ("L", "exit"), b"\x5d\xcb",
        ("AT", 0x400), ("L", "D"), b"\x5d\xcb",
    ]
    return assemble(parts, base=0x300)


# The primary handler (shape of the retail 0x1B handler, rebuilt by hand): inc cursor, key read, compare,
# guard compare, and a far call taken when the guard is zero.
def handler(mutate: str = "none") -> tuple:
    inc = b"\xff\x06\xed\x49"
    key = b"\xa0\x7f\x6f" if mutate != "key" else b"\xa0\x34\x12"
    far = b"\x9a\x8e\x00\x2b\x00" if mutate != "no-far" else b"\x90\x90\x90\x90\x90"
    if mutate == "unmodelled":
        far = b"\xe8\x00\x00"
    extra = b"\xa3\xed\x49" if mutate == "cursor" else b""
    parts = [
        ("L", "H"), b"\x55\x89\xe5",
        inc, extra,
        key,
        b"\x3c\x1b",                               # cmp al,0x1b
        ("R8", b"\x75", "end"),
        b"\x80\x3e\x7d\x6f\x00",                   # cmp byte [0x6f7d],0
        ("R8", b"\x75", "end"),
        far,
        ("L", "end"), b"\x5d\xcb",
    ]
    return assemble(parts, base=0x200)


def paths_of(data: bytes, entry: int, opcode: int = 0x1B) -> dict:
    return hc.handler_paths(data, entry, opcode)


# ---------------------------------------------------------------------------------------------
# Decoder cross-check and operand roles
# ---------------------------------------------------------------------------------------------

def test_raw_branch_target_agrees_with_decoder_on_branches():
    data, labels = dispatcher()
    for off in range(0x100, 0x120):
        ins = hc._decode(data, off)
        if ins is None or ins.flow not in ("jcc", "jmp", "call"):
            continue
        assert hc.raw_branch_target(data, off) == ins.target, hex(off)


@pytest.mark.parametrize("raw, role", [
    (b"\xff\x06\xed\x49", "rmw"),              # inc word [0x49ed]
    (b"\xa3\xed\x49", "write"),                # mov [0x49ed],ax
    (b"\xa1\xed\x49", "read"),                 # mov ax,[0x49ed]
    (b"\x80\x3e\x7d\x6f\x00", "cmp"),          # cmp byte [0x6f7d],0
    (b"\xa2\x7f\x6f", "write"),                # mov [0x6f7f],al
    (b"\xa0\x7f\x6f", "read"),                 # mov al,[0x6f7f]
])
def test_operand_roles(raw, role):
    data = raw + b"\x90" * 8
    ins = hc._decode(data, 0)
    assert ins is not None
    assert hc._mem_direct(ins) in (0x49ED, 0x6F7D, 0x6F7F)
    assert hc._role(ins) == role


# ---------------------------------------------------------------------------------------------
# Dispatch edge: wrong branch target, shared group, refusals
# ---------------------------------------------------------------------------------------------

def test_dispatch_edge_jne_form_is_decoded_and_consistent():
    data, labels = dispatcher(opcode=0x1B)
    e = hc.dispatch_edge(data, 0x1B, entry=0x100)
    assert e["status"] == "ok" and e["form"] == "jne-push-cs-call"
    assert e["handler"] == 0x200
    assert e["call_target"] == e["call_target_raw"] == 0x200
    assert e["jump_target"] == e["jump_target_raw"] == labels["next"]
    assert e["consistent"] is True and e["evidence"] == "decoded"


def test_wrong_branch_target_is_refused():
    # Falsifier: a jnz that lands inside the call instead of the next case. The decoded target and the
    # raw recomputation agree with each other, but the next-case structure does not hold.
    data, labels = dispatcher(opcode=0x1B, jnz_to="exit")
    e = hc.dispatch_edge(data, 0x1B, entry=0x100)
    assert e["consistent"] is False
    assert e["status"] == "refused"


def test_shared_group_members_and_handler():
    data, labels = dispatcher_with_group(group_calls=0x200)
    a = hc.dispatch_edge(data, 0x16, entry=0x100)
    b = hc.dispatch_edge(data, 0x17, entry=0x100)
    assert a["form"] == b["form"] == "je-group"
    assert a["group_members"] == [0x16, 0x17]
    assert a["handler"] == b["handler"] == 0x200
    # Falsifier: a group block that calls a different handler is visible in the edge.
    data2, _ = dispatcher_with_group(group_calls=0x210)
    assert hc.dispatch_edge(data2, 0x16, entry=0x100)["handler"] == 0x210


def test_dispatch_edge_refuses_missing_or_ambiguous_compare():
    data, _ = dispatcher(opcode=0x1B)
    assert hc.dispatch_edge(data, 0x2D, entry=0x100)["status"] == "refused"


# ---------------------------------------------------------------------------------------------
# Handler paths: the settled and open cases, and the four falsifiers
# ---------------------------------------------------------------------------------------------

def test_handler_has_two_paths_one_settled_one_far_call():
    data, labels = handler()
    hp = paths_of(data, labels["H"])
    assert len(hp["paths"]) == 2 and not hp["refusals"]
    settled = [p for p in hp["paths"] if not p["unresolved_reasons"]]
    open_ = [p for p in hp["paths"] if p["unresolved_reasons"]]
    assert len(settled) == 1 and len(open_) == 1
    assert settled[0]["cursor_delta_known"] == 1 and settled[0]["far_calls"] == []
    assert open_[0]["far_calls"] == [{"at": labels["end"] - 5, "seg": 0x2B, "off": 0x8E, "resolved": False}]
    assert "far-call-unresolved" in open_[0]["unresolved_reasons"]
    for p in hp["paths"]:
        assert p["cursor_increments"] == [labels["H"] + 3]
        assert p["cursor_touch_before_first_branch"] is True
        assert p["key_reads"] == [labels["H"] + 7]
        assert p["stream_reads"] == []
    s = hc.settlement(hp)
    assert s["status"] == "open" and s["settled_cursor_delta"] == 1 and s["settled_paths"] == 1


def test_falsifier_unknown_helper_is_the_only_open_reason():
    # Replace the far call with nops: both paths settle at +1, so the far callee is the sole open reason.
    data, labels = handler(mutate="no-far")
    s = hc.settlement(paths_of(data, labels["H"]))
    assert s["status"] == "settled" and s["settled_cursor_delta"] == 1 and s["open_paths"] == 0


def test_falsifier_cursor_mutation_is_not_an_increment():
    data, labels = handler(mutate="cursor")
    hp = paths_of(data, labels["H"])
    assert all("cursor-write-other" in " ".join(p["unresolved_reasons"]) for p in hp["paths"])
    assert all(p["cursor_delta_known"] is None for p in hp["paths"])
    assert hc.settlement(hp)["status"] == "open"


def test_falsifier_key_producer_must_be_the_key_cell():
    # The handler's compare reads a value that is not the key cell: the walk must not claim the key.
    data, labels = handler(mutate="key")
    hp = paths_of(data, labels["H"])
    assert all("compare-on-non-key-value" in p["unresolved_reasons"] for p in hp["paths"])
    assert all(p["key_reads"] == [] for p in hp["paths"])
    assert hc.settlement(hp)["status"] == "open"


def test_unmodelled_near_call_ends_the_path_open():
    data, labels = handler(mutate="unmodelled")
    hp = paths_of(data, labels["H"])
    assert any(p["terminal"] == "unmodelled-near-call" for p in hp["paths"])
    assert hc.settlement(hp)["status"] == "open"


# ---------------------------------------------------------------------------------------------
# Caller path: the stream loop, the key store, and the cursor
# ---------------------------------------------------------------------------------------------

def test_loop_key_store_is_immediately_before_the_dispatch_call():
    data, labels = loop_bytes()
    lp = hc.loop_report(data, loop_entry=labels["L"], dispatch_entry=labels["D"])
    assert lp["sequence_found"] is True
    assert lp["key_store_immediately_before_call"] is True
    assert lp["dispatch_call_target_matches"] is True
    assert lp["entry_cursor"] is not None and lp["entry_cursor"]["source"] == "argument [bp+6]"
    assert lp["loop_advances_cursor"] is False
    assert [c["kind"] for c in lp["cursor_writes"]] == ["store"]


def test_falsifier_key_producer_not_the_stream_byte_breaks_the_sequence():
    # A different value stored into the key cell (not es:[di+0x6700]) breaks the decoded sequence.
    data, labels = loop_bytes(extra=b"\xb0\x00")   # mov al,0 between the stream read and the store
    lp = hc.loop_report(data, loop_entry=labels["L"], dispatch_entry=labels["D"])
    assert lp["sequence_found"] is False


def test_falsifier_loop_that_advances_the_cursor_is_reported():
    data, labels = loop_bytes(inc_after=b"\xff\x06\xed\x49")
    lp = hc.loop_report(data, loop_entry=labels["L"], dispatch_entry=labels["D"])
    assert lp["loop_advances_cursor"] is True


def test_callers_of_reports_push_cell_and_evidence():
    buf = bytearray(b"\x90" * 0x400)
    buf[0x100:0x104] = b"\xff\x36\xe7\x49"      # push word [0x49e7]
    buf[0x104] = 0x0E                            # push cs
    buf[0x105:0x108] = b"\xe8" + struct.pack("<h", 0x300 - 0x108)
    c = hc.callers_of(bytes(buf), 0x300, walk_starts=set())
    assert c == [{"at": 0x105, "evidence": "byte-pattern", "push_cell": 0x49E7,
                  "push_evidence": "decodes-at-candidate-start"}]


def test_cell_census_classifies_by_instruction():
    buf = bytearray(b"\x90" * 0x200)
    buf[0x100:0x103] = b"\xa2\x7f\x6f"           # write
    buf[0x110:0x115] = b"\x80\x3e\x7f\x6f\x00"  # cmp
    hits = hc.cell_census(bytes(buf), 0x6F7F, walk_starts={0x100})
    by = {r["instruction"]: r for r in hits}
    assert by[0x100]["role"] == "write" and by[0x100]["evidence"] == "decoded"
    assert by[0x110]["role"] == "cmp" and by[0x110]["evidence"] == "decodes-at-candidate-start"


def test_block_compare_fields_follow_the_byte_chain():
    block = bytes([0] * 34) + b"\x1b\x09\x00" + bytes(10)
    handler_info = {"paths": [{"stream_reads": []}]}
    bc = hc.block_compare(block, 34, {"status": "open"}, handler_info)
    assert bc["matches_primary_opcode"] is True
    assert bc["next_key_byte_at"] == 35 and bc["next_key_byte"] == "0x09"
    assert bc["reads_operand_bytes_on_any_path"] is False
    assert bc["supported_prefix_extends_past_opcode"] is False


# ---------------------------------------------------------------------------------------------
# Refusals and CLI
# ---------------------------------------------------------------------------------------------

def test_main_refuses_output_outside_data_work(tmp_path):
    rc = hc.main(["--install", str(tmp_path / "nope"), "-o", str(tmp_path / "out")])
    assert rc == 2


def test_probe_refuses_missing_install(tmp_path):
    with pytest.raises(hc.ProbeRefusal):
        hc.probe(tmp_path / "nope", tmp_path / "out")


def test_probe_refuses_output_inside_install(tmp_path):
    inst = tmp_path / "inst"
    inst.mkdir()
    with pytest.raises(hc.ProbeRefusal):
        hc.probe(inst, inst / "out")


def test_probe_refuses_unpinned_files(tmp_path):
    inst = tmp_path / "inst"
    inst.mkdir()
    (inst / "GAME.OVR").write_bytes(b"\x00" * 10)
    (inst / "START.EXE").write_bytes(b"\x00" * 10)
    (inst / "ECL2.DAX").write_bytes(b"\x00" * 10)
    with pytest.raises(hc.ProbeRefusal, match="unpinned"):
        hc.probe(inst, tmp_path / "out")


# ---------------------------------------------------------------------------------------------
# Retail-gated (OPENUA_POR_INSTALL = the pinned POOLRAD folder). Reads only; writes under tmp_path.
# ---------------------------------------------------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_INSTALL")
needs_retail = pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_INSTALL to the pinned POOLRAD folder")


@needs_retail
def test_retail_probe_settles_nothing_past_the_opcode(tmp_path):
    doc, code = hc.probe(Path(RETAIL), tmp_path / "retail")
    assert code == 0 and all(doc["checks"].values())
    prim = doc["handlers"]["0x1B"]
    assert prim["handler_entry"] == "0x1898"
    s = prim["settlement"]
    assert s["status"] == "open" and s["settled_paths"] == 1 and s["open_paths"] == 1
    assert s["settled_cursor_delta"] == 1
    assert prim["far_calls_on_paths"] == [(6407, 0x2B, 0x8E)]
    assert doc["loop"]["key_store_at"] == 0x3EE7 and doc["loop"]["dispatch_call_at"] == 0x3EEB
    assert doc["block"]["matches_primary_opcode"] is True
    assert doc["block"]["supported_prefix_extends_past_opcode"] is False


@needs_retail
def test_retail_outputs_are_deterministic_and_path_free(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    hc.probe(Path(RETAIL), a)
    hc.probe(Path(RETAIL), b)
    ja = (a / hc.RESULT_JSON).read_bytes()
    jb = (b / hc.RESULT_JSON).read_bytes()
    assert ja == jb
    text = ja.decode("utf-8")
    assert "G:/" not in text and "POOLRAD" not in text and "C:\\" not in text
    assert (a / hc.RESULT_MD).read_text(encoding="utf-8") == (b / hc.RESULT_MD).read_text(encoding="utf-8")
    json.loads(text)
