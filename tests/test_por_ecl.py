"""Tests for tools/por_ecl.py (Pool of Radiance ECL decoder, decode only).

Fixture contract (synthetic; no retail data is needed for the default suite):
  * DAX container: 2-byte TOC size, 9-byte TOC entries, contiguous data chain
    closing exactly at EOF, signed-byte RLE blocks (GoldBox docs/dax-format.md
    sections 1-2). `make_dax` writes that layout.
  * ECL block: uint16 magic 0x1388, five 4-byte far pointers, then a body
    starting at byte 22. `ecl_block` writes that layout with synthetic operands.

These pin OUR decoder to the documented framing. They do not prove that a
retail PoR block decodes this way. The optional retail check at the end runs
only when OPENUA_POR_ECL_DAX names a local ECL2.DAX, and it is skipped
otherwise.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_ecl as pe  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---- synthetic writers (test-only) -----------------------------------------

def rle_encode(data: bytes) -> bytes:
    """Signed-byte RLE with the writer envelope from docs/dax-format.md 2a:
    literal runs capped at 126, repeat runs capped at 127."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        run = 1
        while i + run < n and data[i + run] == data[i] and run < 127:
            run += 1
        if run >= 3:
            out += bytes([256 - run, data[i]])
            i += run
            continue
        # literal stretch: stop before a repeat run of 3+ or at 126 bytes
        j = i
        while j < n and (j - i) < 126:
            if j + 2 < n and data[j] == data[j + 1] == data[j + 2]:
                break
            j += 1
        if j == i:
            j = i + 1
        out += bytes([j - i - 1]) + data[i:j]
        i = j
    return bytes(out)


def make_dax(blocks) -> bytes:
    """blocks: list of (block_id, raw_bytes). Returns a valid DAX container."""
    toc = bytearray()
    data = bytearray()
    for bid, raw in blocks:
        comp = rle_encode(raw)
        toc += bytes([bid]) + len(data).to_bytes(4, "little") \
            + len(raw).to_bytes(2, "little") + len(comp).to_bytes(2, "little")
        data += comp
    return len(toc).to_bytes(2, "little") + bytes(toc) + bytes(data)


def lit(v: int) -> bytes:
    return bytes([0x00, v & 0xFF])


def opp1(word: int) -> bytes:
    """Code-1 operand: word = (val << 8) | high."""
    return bytes([0x01, word & 0xFF, (word >> 8) & 0xFF])


def strop(payload: bytes) -> bytes:
    """Inline string: code 0x80, high = packed byte count, then the bytes."""
    return bytes([0x80, len(payload)]) + payload


def ins(op: int, *operands: bytes) -> bytes:
    return bytes([op]) + b"".join(operands)


def ecl_block(body: bytes, vbase: int = 0x8000) -> bytes:
    """Magic + five far pointers (segment 0x0101) + body. Pointer vaddrs are
    placed on the body so the header is well formed."""
    head = bytearray(b"\x88\x13")
    for k in range(5):
        head += b"\x01\x01" + (vbase + 22 + k).to_bytes(2, "little")
    return bytes(head) + body


def write_dax_file(tmp_path: Path, blocks, name="ECL2.DAX") -> Path:
    p = tmp_path / "src" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(make_dax(blocks))
    return p


def decode(block_bytes: bytes, framing="conservative", vbase=None):
    """Run the block decode path on a raw ECL block (no DAX) for focused tests."""
    insts, edges, stop = pe.walk_block(block_bytes, framing)
    starts = {i.offset for i in insts}
    decoded_end = pe.ECL_HEADER_LEN + sum(i.length for i in insts)
    resolved = pe.resolve_edges(edges, vbase, len(block_bytes), starts, decoded_end)
    return insts, edges, stop, resolved, block_bytes[decoded_end:]


# ---- DAX container and RLE --------------------------------------------------

def test_rle_roundtrip_mixed_runs():
    raw = b"\x07" * 300 + bytes(range(200)) + b"\xaa" * 5 + b"Z"
    comp = rle_encode(raw)
    assert pe.rle_decode(comp, len(raw)) == raw


def test_rle_control_bytes_stay_in_writer_envelope():
    raw = bytes(range(256)) * 4
    comp = rle_encode(raw)
    i = 0
    while i < len(comp):
        c = comp[i]
        assert c not in (0x7E, 0x7F, 0x80), "writer must not emit 0x7E/0x7F/0x80"
        i += (c + 1 + 1) if c < 0x80 else 2


@pytest.mark.parametrize("comp,raw,msg", [
    (bytes([0x05, 1, 2]), 6, "overruns"),          # literal run needs 6 bytes, has 2
    (bytes([0x81]), 1, "no value byte"),            # repeat with no value byte
    (bytes([0x00, 0x41]), 2, "raw_size"),           # produces 1 byte, TOC says 2
    (bytes([0xFF, 0x41, 0xFF, 0x41]), 1, "exceeds"),  # overproduces
])
def test_rle_rejects_malformed(comp, raw, msg):
    with pytest.raises(pe.EclError, match=msg):
        pe.rle_decode(comp, raw)


def test_dax_toc_and_chain_parse():
    dax = make_dax([(9, b"abc" * 10), (20, b"\x00" * 40)])
    entries, base = pe.parse_dax(dax)
    assert base == 2 + 18
    assert [(e.block_id, e.raw_size) for e in entries] == [(9, 30), (20, 40)]
    assert entries[1].data_offset == entries[0].comp_size
    assert base + sum(e.comp_size for e in entries) == len(dax)


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: b"\x05\x00" + d[2:], "multiple of 9"),
    (lambda d: b"\x00\x00" + d[2:], "multiple of 9"),
    (lambda d: (1800).to_bytes(2, "little") + d[2:], "past end"),  # 200 entries; far past EOF
    (lambda d: d + b"\x00", "end exactly"),
    (lambda d: d[:-1], "past end"),
])
def test_dax_rejects_malformed_container(mutate, msg):
    dax = make_dax([(20, b"\x01" * 12)])
    with pytest.raises(pe.EclError, match=msg):
        pe.parse_dax(mutate(dax))


def test_dax_rejects_broken_chain():
    dax = bytearray(make_dax([(1, b"aa"), (2, b"bb")]))
    # second TOC entry's data_offset (bytes 2+9+1 .. +4) moved off the chain
    dax[2 + 9 + 1] ^= 0x01
    with pytest.raises(pe.EclError, match="contiguous"):
        pe.parse_dax(bytes(dax))


def test_select_block_rules():
    dax = make_dax([(20, b"x" * 5), (9, b"y" * 5), (20, b"z" * 5)])
    entries, _ = pe.parse_dax(dax)
    assert pe.select_entry(entries, 9, None).index == 1
    assert pe.select_entry(entries, None, 2).index == 2
    assert pe.select_entry(entries, 20, 2).index == 2
    with pytest.raises(pe.EclError, match="not requested id"):
        pe.select_entry(entries, 9, 2)
    with pytest.raises(pe.EclError, match="ambiguous"):
        pe.select_entry(entries, 20, None)
    with pytest.raises(pe.EclError, match="no TOC entry"):
        pe.select_entry(entries, 77, None)
    with pytest.raises(pe.EclError, match="out of range"):
        pe.select_entry(entries, None, 9)
    with pytest.raises(pe.EclError, match="--block ID or --index"):
        pe.select_entry(entries, None, None)


# ---- ECL header --------------------------------------------------------------

def test_header_parses_magic_and_pointers():
    blk = ecl_block(b"\x00", vbase=0x8000)
    h = pe.parse_header(blk)
    assert h["magic"] == 0x1388
    assert [p["vaddr"] for p in h["pointers"]] == [0x8016 + k for k in range(5)]
    assert h["segment_all_expected"] is True


def test_header_rejects_bad_magic_and_short_block():
    with pytest.raises(pe.EclError, match="magic"):
        pe.parse_header(b"\x89\x13" + b"\x00" * 30)
    with pytest.raises(pe.EclError, match="22"):
        pe.parse_header(b"\x88\x13" + b"\x00" * 10)


def test_header_flags_unexpected_segment():
    blk = bytearray(ecl_block(b"\x00"))
    blk[2] = 0x02  # first pointer segment is not 0x0101
    h = pe.parse_header(bytes(blk))
    assert h["segment_all_expected"] is False


# ---- instruction walk ---------------------------------------------------------

def test_walk_offsets_and_lengths_for_known_forms():
    s = ins(0x09, lit(5), opp1(0x7D10))           # SAVE: 1 opcode + 2 + 3 bytes = 6
    g = ins(0x01, opp1(0x8000 + 32))              # GOTO at 28 (4 bytes), target EXIT at 32
    x = ins(0x00)                                  # EXIT at 32
    blk = ecl_block(s + g + x)
    insts, edges, stop, _, tail = decode(blk)
    assert [(i.offset, i.mnemonic, i.length) for i in insts] == [
        (22, "SAVE", 6), (28, "GOTO", 4), (32, "EXIT", 1)]
    assert stop.kind == "end-of-block"
    assert tail == b""
    assert len(edges) == 1 and edges[0].target_vaddr == 0x8000 + 32


def test_string_operand_keeps_length_and_hash_not_text():
    payload = b"SECRETTEXT"
    blk = ecl_block(ins(0x11, strop(payload)) + ins(0x00))
    insts, _, stop, _, _ = decode(blk)
    op = insts[0].operands[0]
    assert op["string_len"] == len(payload)
    assert op["string_sha256"] == hashlib.sha256(payload).hexdigest()
    assert payload not in repr(insts[0].operands).encode()
    assert stop.kind == "end-of-block"


def test_on_goto_counts_entries_and_resolves_targets():
    # ON_GOTO: opcode + selector (3) + count literal 2 (2) + two code-1 entries (3 each) = 12 bytes.
    # The EXIT that both targets name therefore sits at offset 22 + 12 = 34.
    exit_off = 22 + 12
    body = ins(0x25, opp1(0x9800), lit(2), opp1(0x8000 + exit_off), opp1(0x8000 + exit_off)) + ins(0x00)
    blk = ecl_block(body)
    insts, edges, stop, resolved, _ = decode(blk, vbase=0x8000)
    assert insts[0].mnemonic == "ON_GOTO" and len(insts[0].count_operands) == 2
    assert insts[0].length == 12
    assert [e["kind"] for e in resolved] == ["on_goto", "on_goto"]
    assert all(e["resolution"] == "instruction-start" for e in resolved)
    assert all(e["target_offset"] == exit_off for e in resolved)
    assert stop.kind == "end-of-block"


def test_edge_resolution_states_are_distinct():
    body = ins(0x01, opp1(0x8000 + 23)) + ins(0x00)   # GOTO into the middle of GOTO
    blk = ecl_block(body)
    _, _, _, resolved, _ = decode(blk, vbase=0x8000)
    assert resolved[0]["resolution"] == "mid-instruction"
    _, _, _, unresolved, _ = decode(blk, vbase=None)
    assert unresolved[0]["resolution"] == "unresolved-no-base"
    far = ins(0x01, opp1(0x9000)) + ins(0x00)
    _, _, _, out_, _ = decode(ecl_block(far), vbase=0x8000)
    assert out_[0]["resolution"] in ("out-of-block", "beyond-decoded-region")
    indirect = ins(0x01, bytes([0x09, 0x01])) + ins(0x00)   # code 0x09 target is not a literal address
    _, edges_i, _, res_i, _ = decode(ecl_block(indirect), vbase=0x8000)
    assert edges_i[0].indirect is True and res_i[0]["resolution"] == "indirect-operand"


def test_unknown_opcode_stops_and_keeps_raw_tail():
    body = ins(0x00) + bytes([0x41, 0xDE, 0xAD, 0xBE, 0xEF])
    blk = ecl_block(body)
    insts, _, stop, _, tail = decode(blk)
    assert [i.mnemonic for i in insts] == ["EXIT"]
    assert stop.kind == "unknown-opcode" and stop.opcode == 0x41 and stop.offset == 23
    assert tail == bytes([0x41, 0xDE, 0xAD, 0xBE, 0xEF])


def test_menu_framing_conservative_stops_and_spec_decodes():
    menu = ins(0x2B, lit(0), lit(1), strop(b"ab"))   # spec: 2 fixed, count at operand 1 = 1
    body = ins(0x00) + menu + ins(0x00)
    blk = ecl_block(body)
    insts, _, stop, _, tail = decode(blk, framing="conservative")
    assert stop.kind == "ambiguous-framing" and stop.opcode == 0x2B
    assert [i.mnemonic for i in insts] == ["EXIT"] and tail[0] == 0x2B
    insts2, _, stop2, _, tail2 = decode(blk, framing="spec-menus")
    assert [i.mnemonic for i in insts2] == ["EXIT", "HORIZONTAL_MENU", "EXIT"]
    assert stop2.kind == "end-of-block" and tail2 == b""
    assert len(insts2[1].count_operands) == 1


def test_vertical_menu_spec_count_is_operand_two():
    menu = ins(0x15, lit(0), strop(b"p"), lit(2), strop(b"a"), strop(b"b"))
    insts, _, stop, _, _ = decode(ecl_block(menu + ins(0x00)), framing="spec-menus")
    assert insts[0].mnemonic == "VERTICAL_MENU"
    assert len(insts[0].count_operands) == 2
    assert stop.kind == "end-of-block"


def test_non_literal_count_is_ambiguous_not_guessed():
    body = ins(0x25, opp1(0x9800), opp1(0x9801), opp1(0x8000 + 40), opp1(0x8000 + 40)) + ins(0x00)
    insts, _, stop, _, tail = decode(ecl_block(body))
    assert stop.kind == "ambiguous-count" and insts == []
    assert tail[0] == 0x25


def test_truncated_operand_stops_and_keeps_tail():
    body = ins(0x00) + bytes([0x09, 0x00])        # SAVE needs two operands, only one present
    insts, _, stop, _, tail = decode(ecl_block(body))
    assert stop.kind == "truncated-operand" and stop.opcode == 0x09
    assert tail == bytes([0x09, 0x00])


def test_string_overrun_is_truncation_not_a_guess():
    body = bytes([0x11, 0x80, 0x0A, 0x01, 0x02])  # PRINT, string claims 10 bytes, 2 present
    insts, _, stop, _, tail = decode(ecl_block(body))
    assert stop.kind == "truncated-operand" and insts == []


def test_opcode_1f_framed_but_semantics_unknown():
    blk = ecl_block(ins(0x1F, lit(0), lit(0)) + ins(0x00))
    insts, _, stop, _, _ = decode(blk)
    assert insts[0].mnemonic == "UNKNOWN_1F" and insts[0].semantics_known is False
    assert stop.kind == "end-of-block"


# ---- end to end, outputs and refusals ----------------------------------------

def test_block_decode_end_to_end_and_determinism(tmp_path):
    body = ins(0x09, lit(5), opp1(0x7D10)) + ins(0x00)
    src = write_dax_file(tmp_path, [(18, ecl_block(body)), (20, ecl_block(body))])
    before = hashlib.sha256(src.read_bytes()).hexdigest()
    data = src.read_bytes()
    res = pe.decode_block(data, 20, None, "conservative", None)
    res_again = pe.decode_block(data, 20, None, "conservative", None)
    r1 = pe.build_result(src.name, hashlib.sha256(data).hexdigest(), res)
    r2 = pe.build_result(src.name, hashlib.sha256(data).hexdigest(), res_again)
    assert r1 == r2
    assert r1["status"] == "decode-only" and r1["playable"] is False
    assert r1["source"]["block_id"] == 20 and r1["source"]["toc_index"] == 1
    assert str(tmp_path) not in pe.render_report(r1)
    out = tmp_path / "out"
    pe.write_outputs(r1, pe.render_report(r1), out)
    text = (out / "por_ecl.json").read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert str(tmp_path.anchor) not in text
    assert hashlib.sha256(src.read_bytes()).hexdigest() == before


def test_output_dir_refusals(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(pe.EclError, match="inside the source"):
        pe.validate_output_dir(src, src / "out")
    repo_out = REPO_ROOT / "tests" / "por_ecl_refused_probe"
    with pytest.raises(pe.EclError, match="under data/"):
        pe.validate_output_dir(src, repo_out)
    ok = pe.validate_output_dir(src, REPO_ROOT / "data" / "work" / "por-ecl-test")
    assert ok.is_relative_to((REPO_ROOT / "data").resolve())


def test_resolve_source_forms(tmp_path):
    f = write_dax_file(tmp_path, [(1, b"x")], name="ECL5.DAX")
    assert pe.resolve_source(str(f), None, None) == f
    root = tmp_path / "install"
    (root / "POOLRAD").mkdir(parents=True)
    (root / "POOLRAD" / "ECL5.DAX").write_bytes(f.read_bytes())
    assert pe.resolve_source(None, str(root), 5).name == "ECL5.DAX"
    with pytest.raises(pe.EclError, match="not found"):
        pe.resolve_source(None, str(root), 6)
    with pytest.raises(pe.EclError, match="--dax PATH"):
        pe.resolve_source(None, None, None)


def test_cli_exit_codes(tmp_path, capsys):
    src = write_dax_file(tmp_path, [(20, ecl_block(ins(0x00)))])
    assert pe.main(["--dax", str(src), "--list"]) == 0
    assert "20" in capsys.readouterr().out
    assert pe.main(["--dax", str(src), "--block", "20", "-o", str(tmp_path / "cli-out")]) == 0
    assert (tmp_path / "cli-out" / "por_ecl.json").is_file()
    assert pe.main(["--dax", str(src), "--block", "99", "-o", str(tmp_path / "o")]) == 2
    assert pe.main(["--dax", str(src), "--block", "20"]) == 2
    assert pe.main(["--dax", str(src), "--block", "20", "--vbase", "zzz",
                    "-o", str(tmp_path / "o2")]) == 2


def test_vbase_parse_bounds():
    assert pe.parse_vbase("0x98FE") == 0x98FE
    assert pe.parse_vbase(None) is None
    with pytest.raises(pe.EclError):
        pe.parse_vbase("0x10000")


# ---- optional retail check ----------------------------------------------------

RETAIL = os.environ.get("OPENUA_POR_ECL_DAX")


@pytest.mark.skipif(not RETAIL, reason="set OPENUA_POR_ECL_DAX to a local ECL2.DAX to run")
def test_retail_ecl2_block20_anchors():
    data = Path(RETAIL).read_bytes()
    res = pe.decode_block(data, 20, None, "spec-menus", 0x98FE)
    starts = {i.offset: i for i in res["instructions"]}
    # COMBAT at vaddr 0xab90 and 0xabf7, as cited by GoldBox persistent-natural-routes.md.
    assert starts[0xab90 - 0x98FE].mnemonic == "COMBAT"
    assert starts[0xabf7 - 0x98FE].mnemonic == "COMBAT"
    assert res["coverage"]["fraction"] > 0.99
    assert res["stop"].kind == "truncated-operand"


# ---- opt-in PoR-derived base (--por-vbase): CONDITIONAL, not promoted -------
#
# The base 0x98FE is evidence-backed only conditionally (docs/por-ecl-decoder.md).
# These tests pin: the option conflict, default-off behaviour, output metadata,
# the wrap-aware edge rule, mutation falsifiers, and (retail-gated) the pinned
# GAME.OVR bytes and all 29 ECL1-8 blocks. None of them claims reachability,
# event semantics, or that every target lands on an instruction start.

POR_BASE = 0x98FE
POR_TABLE_END = 0x9914
GAME_OVR_SHA256 = "872964a32cef0fc32bbf83bab68b15e04ad36d59076f37b00a179dfee7928614"
ECL_BLOCK_COUNT = 29
POR_INSTALL = os.environ.get("OPENUA_POR_INSTALL")
RETAIL_POR = pytest.mark.skipif(
    not POR_INSTALL or not Path(POR_INSTALL, "GAME.OVR").is_file(),
    reason="set OPENUA_POR_INSTALL to the pinned POOLRAD folder to run")


def ecl_block_por(body: bytes) -> bytes:
    """Synthetic block whose five header pointers sit at the table end 0x9914+k."""
    return ecl_block(body, vbase=POR_BASE)


def por_decode(block_bytes: bytes):
    """Real decode path (DAX container, RLE, header, walk) with --por-vbase on."""
    dax = make_dax([(20, block_bytes)])
    return pe.decode_block(dax, 20, None, "conservative", None, por_vbase=True)


def test_por_vbase_cannot_combine_with_vbase(tmp_path):
    src = write_dax_file(tmp_path, [(20, ecl_block_por(ins(0x00)))])
    out = tmp_path / "conflict-out"
    pe.check_vbase_options(None, True)        # alone: fine
    pe.check_vbase_options(0x98FE, False)     # plain --vbase: fine
    with pytest.raises(pe.EclError, match="cannot be combined"):
        pe.check_vbase_options(0x98FE, True)
    with pytest.raises(pe.EclError, match="cannot be combined"):
        pe.decode_block(src.read_bytes(), 20, None, "conservative", 0x98FE, por_vbase=True)
    assert pe.main(["--dax", str(src), "--block", "20", "--por-vbase",
                    "--vbase", "0x98FE", "-o", str(out)]) == 2
    assert not out.exists()                   # refused before anything is written


def test_default_mode_is_off_and_output_has_no_por_keys(tmp_path):
    body = ins(0x01, opp1(POR_TABLE_END)) + ins(0x00)
    src = write_dax_file(tmp_path, [(20, ecl_block_por(body))])
    res = pe.decode_block(src.read_bytes(), 20, None, "conservative", None)
    assert res["vbase"] is None and res["por_vbase"] is False
    assert res["edges"][0]["resolution"] == "unresolved-no-base"
    out = tmp_path / "default-out"
    assert pe.main(["--dax", str(src), "--block", "20", "-o", str(out)]) == 0
    doc = json.loads((out / "por_ecl.json").read_text(encoding="utf-8"))
    assert "vbase_evidence" not in doc
    assert doc["vbase"] is None
    assert "PoR-derived" not in (out / "por_ecl_report.md").read_text(encoding="utf-8")


def test_resolve_edges_default_does_not_wrap():
    # The default rule is plain vaddr - vbase. The opt-in wrap must not leak into it.
    edge = pe.Edge(source=0, kind="goto", target_vaddr=0x9000, indirect=False, operand_offset=1)
    plain = pe.resolve_edges([edge], POR_BASE, 27, {0}, 27)
    assert plain[0]["target_offset"] == 0x9000 - POR_BASE          # -2302, not wrapped
    assert plain[0]["resolution"] == "out-of-block"
    wrapped = pe.resolve_edges([edge], POR_BASE, 27, {0}, 27, wrap16=True)
    assert wrapped[0]["target_offset"] == 0xF702                    # (0x9000 - 0x98FE) mod 65536
    assert wrapped[0]["resolution"] == "out-of-block"


def test_por_vbase_edge_resolution_uses_0x98fe():
    # GOTO at block offset 22 (vaddr 0x9914), then EXIT at offset 26. Block length 27.
    def goto(t):
        return ins(0x01, opp1(t))
    edges = por_decode(ecl_block_por(goto(0x9914) + ins(0x00)))["edges"]
    assert edges[0]["target_offset"] == 22
    assert edges[0]["resolution"] == "instruction-start"      # the first instruction
    cases = {
        0x9918: (26, "instruction-start"),   # EXIT
        0x9916: (24, "mid-instruction"),     # inside the GOTO
        0x9900: (2, "in-header"),            # magic/header bytes
        0x98FE: (0, "in-header"),            # block byte 0
        0x9920: (34, "out-of-block"),        # past the block end
        0x9000: (0xF702, "out-of-block"),    # wraps mod 65536, far out of block
    }
    for target, (offset, label) in cases.items():
        rec = por_decode(ecl_block_por(goto(target) + ins(0x00)))["edges"][0]
        assert rec["target_offset"] == offset, hex(target)
        assert rec["resolution"] == label, hex(target)


def test_por_vbase_falsifier_changes_the_answer():
    # Mutation: the same GOTO resolved under the neighbouring candidate 0x9900 lands
    # two bytes early, inside the header. Under 0x98FE it is the first instruction.
    blk = ecl_block_por(ins(0x01, opp1(POR_TABLE_END)) + ins(0x00))
    dax = make_dax([(20, blk)])
    shifted = pe.decode_block(dax, 20, None, "conservative", 0x9900)["edges"][0]
    assert shifted["target_offset"] == 20
    assert shifted["resolution"] == "mid-instruction"          # plain labelling, not in-header
    por = pe.decode_block(dax, 20, None, "conservative", None, por_vbase=True)["edges"][0]
    assert por["resolution"] == "instruction-start"
    assert por["resolution"] != shifted["resolution"]


def test_por_vbase_metadata_and_report_are_deterministic(tmp_path):
    body = ins(0x01, opp1(POR_TABLE_END)) + ins(0x00)
    src = write_dax_file(tmp_path, [(20, ecl_block_por(body))])
    out_a, out_b = tmp_path / "por-a", tmp_path / "por-b"
    args = ["--dax", str(src), "--block", "20", "--por-vbase"]
    assert pe.main(args + ["-o", str(out_a)]) == 0
    assert pe.main(args + ["-o", str(out_b)]) == 0
    assert (out_a / "por_ecl.json").read_bytes() == (out_b / "por_ecl.json").read_bytes()
    assert (out_a / "por_ecl_report.md").read_bytes() == (out_b / "por_ecl_report.md").read_bytes()
    doc = json.loads((out_a / "por_ecl.json").read_text(encoding="utf-8"))
    assert doc["status"] == "decode-only" and doc["playable"] is False
    assert doc["vbase"] == "0x98FE"
    ev = doc["vbase_evidence"]
    assert ev["mode"] == "por-vbase"
    assert ev["vbase"] == "0x98FE" and ev["wrap16"] is True
    assert ev["rule"] == "block_offset = (vaddr - 0x98FE) mod 65536"
    assert ev["evidence_level"] == "conditional"
    assert ev["promoted"] is False
    assert ev["status"] == "conditional-checks-pass"
    chk = ev["header_table_check"]
    assert chk["segments_0101"] is True
    assert chk["pointers_at_or_after_table_end"] is True
    assert chk["pointers_inside_block"] is True
    assert chk["pointer_min_vaddr"] == "0x9914"
    assert any("not located" in x for x in ev["not_established"])
    assert any("other PoR revisions are not checked" in x for x in ev["not_established"])
    assert doc["edges"][0]["resolution"] == "instruction-start"
    report = (out_a / "por_ecl_report.md").read_text(encoding="utf-8")
    assert "CONDITIONAL, not promoted" in report
    assert "0x98FE" in report


def test_por_vbase_records_failed_header_check_without_refusing(tmp_path):
    # Pointers at 0x8016.. sit far below the table end 0x9914: the conditional base
    # does not fit this block. It is recorded as a failed check, not refused.
    src = write_dax_file(tmp_path, [(20, ecl_block(ins(0x00), vbase=0x8000))])
    out = tmp_path / "fail-out"
    assert pe.main(["--dax", str(src), "--block", "20", "--por-vbase", "-o", str(out)]) == 0
    ev = json.loads((out / "por_ecl.json").read_text(encoding="utf-8"))["vbase_evidence"]
    assert ev["status"] == "conditional-checks-fail"
    assert ev["header_table_check"]["pointers_at_or_after_table_end"] is False
    assert ev["promoted"] is False


def test_por_vbase_cli_refuses_conflict_and_writes_nothing(tmp_path, capsys):
    src = write_dax_file(tmp_path, [(20, ecl_block_por(ins(0x00)))])
    out = tmp_path / "cli-conflict"
    assert pe.main(["--dax", str(src), "--block", "20", "--por-vbase",
                    "--vbase", "0x9900", "-o", str(out)]) == 2
    assert "cannot be combined" in capsys.readouterr().err
    assert not out.exists()


# ---- retail-gated (OPENUA_POR_INSTALL = pinned POOLRAD folder) ---------------

def _retail_game_ovr() -> bytes:
    data = Path(POR_INSTALL, "GAME.OVR").read_bytes()
    assert hashlib.sha256(data).hexdigest() == GAME_OVR_SHA256, "GAME.OVR is not the pinned build"
    return data


def _retail_ecl_files():
    files = []
    for n in range(1, 9):
        p = Path(POR_INSTALL, "ECL%d.DAX" % n)
        if p.is_file():
            files.append((n, p))
    return files


@RETAIL_POR
def test_retail_pinned_game_ovr_fetch_and_loader_bytes():
    ovr = _retail_game_ovr()
    assert ovr[0x3EDC:0x3EE0].hex() == "c43ede49"       # les di,[0x49de]
    assert ovr[0x3EE0:0x3EE2].hex() == "03f8"           # add di,ax
    assert ovr[0x3EE2:0x3EE7].hex() == "268a850067"     # mov al,es:[di+0x6700]
    assert ovr[0x76C8:0x76CE].hex() == "c706ed490099"   # mov [0x49ed],0x9900
    assert ovr[0x78B1:0x78B4].hex() == "c47ef4"         # les di,[bp-12]
    assert ovr[0x78B4:0x78B8].hex() == "81c70200"       # add di,0x0002 (the +2 loader skip)


@RETAIL_POR
def test_retail_29_blocks_header_table_matches_the_equation():
    seen = 0
    for n, path in _retail_ecl_files():
        data = path.read_bytes()
        entries, base = pe.parse_dax(data)
        for e in entries:
            seen += 1
            comp = data[base + e.data_offset:base + e.data_offset + e.comp_size]
            blk = pe.rle_decode(comp, e.raw_size)
            hdr = pe.parse_header(blk)
            assert hdr["magic"] == 0x1388
            assert hdr["segment_all_expected"] is True
            for p in hdr["pointers"]:
                off = (p["vaddr"] - POR_BASE) & 0xFFFF
                assert p["vaddr"] >= POR_TABLE_END, (n, e.index)
                assert pe.ECL_HEADER_LEN <= off < len(blk), (n, e.index)
    assert seen == ECL_BLOCK_COUNT


@RETAIL_POR
def test_retail_29_blocks_por_vbase_edges_follow_the_equation_and_falsifiers():
    allowed = {"instruction-start", "mid-instruction", "beyond-decoded-region",
               "out-of-block", "in-header", "indirect-operand"}
    total = hits = hits_9900 = hits_7ffe = 0
    blocks = 0
    for n, path in _retail_ecl_files():
        data = path.read_bytes()
        entries, _ = pe.parse_dax(data)
        for e in entries:
            res = pe.decode_block(data, None, e.index, "spec-menus", None, por_vbase=True)
            blocks += 1
            starts = {i.offset for i in res["instructions"]}
            vaddrs = [p["vaddr"] for p in res["header"]["pointers"]]
            vaddrs += [r["target_vaddr"] for r in res["edges"] if r["target_vaddr"] is not None]
            for r in res["edges"]:
                assert r["resolution"] in allowed, (n, e.index, r)
                if r["target_vaddr"] is not None:
                    assert r["target_offset"] == (r["target_vaddr"] - POR_BASE) & 0xFFFF
            for v in vaddrs:
                total += 1
                if ((v - POR_BASE) & 0xFFFF) in starts:
                    hits += 1
                if ((v - 0x9900) & 0xFFFF) in starts:
                    hits_9900 += 1
                if ((v - 0x7FFE) & 0xFFFF) in starts:
                    hits_7ffe += 1
    assert blocks == ECL_BLOCK_COUNT
    # Measured 2026-11-18 on the pinned install (spec-menus walk). A change here means
    # the install, the walk or the target set changed. Diagnostic, not proof.
    assert (hits, total) == (2899, 3260)
    assert hits_9900 == 68
    assert hits_7ffe == 17


@RETAIL_POR
def test_retail_cli_por_vbase_writes_29_evidence_outputs(tmp_path):
    count = 0
    for n, path in _retail_ecl_files():
        entries, _ = pe.parse_dax(path.read_bytes())
        for e in entries:
            out = tmp_path / ("ecl%d-%d" % (n, e.index))
            rc = pe.main(["--install", POR_INSTALL, "--ecl", str(n), "--index", str(e.index),
                          "--framing", "spec-menus", "--por-vbase", "-o", str(out)])
            assert rc == 0, (n, e.index)
            doc = json.loads((out / "por_ecl.json").read_text(encoding="utf-8"))
            assert doc["vbase"] == "0x98FE" and doc["playable"] is False
            ev = doc["vbase_evidence"]
            assert ev["evidence_level"] == "conditional" and ev["promoted"] is False
            assert ev["status"] == "conditional-checks-pass", (n, e.index)
            count += 1
    assert count == ECL_BLOCK_COUNT
