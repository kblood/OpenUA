"""Tests for tools/por_wall_far_target_probe.py (owner far-target resolution through overlay evidence).

Default suite: synthetic bytes only. GAME.OVR, START.EXE and the RAM dump are generated here, and the
pins are computed from the generated blobs and passed into analyse(). Nothing is read from the
install and nothing is written outside a pytest tmp folder.

The retail test runs only when OPENUA_POR_INSTALL names the install and both local dumps exist under
data/work. It checks the facts the probe reports for the user-supplied pinned files; it asserts no
meaning and no runtime reachability.
"""
import os
import random
import struct
import sys
from pathlib import Path

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..", "tools")
sys.path.insert(0, TOOLS)
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_far_target_probe as p  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
DUMPS = [REPO / "data" / "work" / "por-live-memory-pid34644" / "ram-000000-100000.bin",
         REPO / "data" / "work" / "por-wheel-live-capture" / "ram-000000-100000.bin"]
INSTALL = os.environ.get("OPENUA_POR_INSTALL")

OWNER_FA, OWNER_CA = 0x100, 0x80          # owner group fileofs / codesz in GAME.OVR
OWNER_HDR = 0x000                          # owner descriptor header in START.EXE
SIB_B_FA, SIB_B_CA, SIB_B_HDR = 0x200, 0x80, 0x40
SIB_C_FA, SIB_C_CA, SIB_C_HDR = 0x300, 0x40, 0x80
OWNER_PARA, SIB_B_PARA, SIB_C_PARA = 0x1000, 0x1400, 0x1800
D = 0x0100                                 # the synthetic live-minus-raw delta
SEG_RAW_TARGET = 0x0428                    # raw far target segment (owner body)
OFF_TARGET = 0x0030                        # proc offset (the owner body's prologue)
DUMP_SIZE = 0x40000


def _body(seed: int, n: int) -> bytearray:
    """Non-repeating bytes, so the group's stable run anchors uniquely in a zero-filled dump."""
    rnd = random.Random(seed)
    b = bytearray(rnd.randrange(1, 256) for _ in range(n))
    return b


def _owner_body() -> bytearray:
    """Owner procedure at body 0: prologue, a far call at 0x10, leave/ret at 0x20 (linear decode)."""
    b = _body(1, OWNER_CA)
    b[0x00:0x03] = b"\x55\x89\xe5"
    b[0x03:0x10] = b"\x90" * 0x0D
    b[0x10:0x15] = b"\x9a" + struct.pack("<HH", OFF_TARGET, SEG_RAW_TARGET)   # far call -> 0428:0030
    b[0x15:0x20] = b"\x90" * 0x0B
    b[0x20:0x22] = b"\xc9\xc3"
    b[0x30:0x35] = b"\x55\x89\xe5\xc9\xc3"                      # the stub target's prologue (proc 0x30)
    return b


def _b_body() -> bytearray:
    b = _body(2, SIB_B_CA)
    b[0x1E:0x23] = b"\x9a" + struct.pack("<HH", 0x0010, 0x0464)
    return b


def _c_body() -> bytearray:
    b = _body(3, SIB_C_CA)
    b[0x10:0x12] = struct.pack("<H", 0x0AAA)
    return b


def _pins(ovr: bytes, exe: bytes) -> dict:
    return {p.OVR_NAME: {"size": len(ovr), "sha256": ogm.sha256(ovr)},
            p.EXE_NAME: {"size": len(exe), "sha256": ogm.sha256(exe)}}


def build(*, sib_c: bool = True):
    """Return (ovr, exe, owner_body, b_body, c_body, fixups) for the synthetic install."""
    ovr = bytearray(0x400)
    exe = bytearray(0x400)
    owner, bb, cb = _owner_body(), _b_body(), _c_body()
    # owner group A: fixup word at body 0x13 (the far-call segment word of 9A at 0x10)
    ovr[OWNER_FA:OWNER_FA + OWNER_CA] = owner
    ovr[OWNER_FA + OWNER_CA:OWNER_FA + OWNER_CA + 2] = struct.pack("<H", 0x13)
    # sibling B: fixup word at body 0x21 (seg of 9A at 0x1E)
    ovr[SIB_B_FA:SIB_B_FA + SIB_B_CA] = bb
    ovr[SIB_B_FA + SIB_B_CA:SIB_B_FA + SIB_B_CA + 2] = struct.pack("<H", 0x21)
    # sibling C: fixup word at body 0x10 (plain segment word)
    if sib_c:
        ovr[SIB_C_FA:SIB_C_FA + SIB_C_CA] = cb
        ovr[SIB_C_FA + SIB_C_CA:SIB_C_FA + SIB_C_CA + 2] = struct.pack("<H", 0x10)

    def header(at, fa, ca, fixupsz, jmpcnt):
        exe[at:at + 14] = (p.DESC_MAGIC + struct.pack("<I", fa) +
                           struct.pack("<HHH", ca, fixupsz, jmpcnt))

    header(OWNER_HDR, OWNER_FA, OWNER_CA, 2, 2)
    header(SIB_B_HDR, SIB_B_FA, SIB_B_CA, 2, 0)
    if sib_c:
        header(SIB_C_HDR, SIB_C_FA, SIB_C_CA, 2, 0)
    # owner stub run at header+0x17: stub0 -> proc 0x30, stub1 -> proc 0x40 (CD 3F off16 00)
    exe[0x17:0x1C] = b"\xcd\x3f" + struct.pack("<H", 0x0030) + b"\x00"
    exe[0x1C:0x21] = b"\xcd\x3f" + struct.pack("<H", 0x0040) + b"\x00"
    return bytes(ovr), bytes(exe), owner, bb, cb


def live_dump(ovr: bytes, owner: bytes, bb: bytes, cb: bytes, *, delta_b: int = D, delta_c: int = D,
              owner_at=(OWNER_PARA,)) -> bytearray:
    """A zero-filled dump with the groups placed and their fixup words rewritten by the delta."""
    dump = bytearray(DUMP_SIZE)

    def place(para, body, fixup_words, delta):
        base = para * 16
        live = bytearray(body)
        for w in fixup_words:
            live[w:w + 2] = struct.pack("<H", (struct.unpack_from("<H", body, w)[0] + delta) & 0xFFFF)
        dump[base:base + len(live)] = live

    for para in owner_at:
        place(para, owner, (0x13,), D)
    place(SIB_B_PARA, bb, (0x21,), delta_b)
    if cb:
        place(SIB_C_PARA, cb, (0x10,), delta_c)
    return dump


def _analyse(ovr, exe, dump, *, run_sweep=False):
    return p.analyse(ovr, exe, [("ram-000000-100000.bin", bytes(dump), 0)], p.OWNER,
                     pins=_pins(ovr, exe), run_sweep=run_sweep) if False else \
        p.analyse(ovr, exe, [("ram-000000-100000.bin", bytes(dump), 0)], OWNER_FA,
                  pins=_pins(ovr, exe), run_sweep=run_sweep)


def test_owner_group_is_unique_and_refuses_otherwise():
    ovr, exe, *_ = build()
    rows = p.descriptor_table(exe, ovr)
    og = p.owner_group(rows, OWNER_FA)
    assert og["fileofs"] == OWNER_FA and og["codesz"] == OWNER_CA
    with pytest.raises(ogm.Refusal):
        p.owner_group(rows, 0x3F0)                    # inside no group


def test_far_site_fixup_listing_is_checked_and_mutation_flips_it():
    ovr, exe, owner, bb, cb = build()
    og = p.owner_group(p.descriptor_table(exe, ovr), OWNER_FA)
    site = OWNER_FA + 0x10
    rows = p.owner_site_rows(og, [{"site": site, "seg": SEG_RAW_TARGET, "off": OFF_TARGET,
                                   "proc": OWNER_FA, "bytes": ""}])
    assert rows[0]["seg_word_fixup_listed"] is True
    # mutation: drop the owner fixup word; the same far site is no longer listed
    ovr2 = bytearray(ovr)
    ovr2[OWNER_FA + OWNER_CA:OWNER_FA + OWNER_CA + 2] = struct.pack("<H", 0x14)
    ovr2 = bytes(ovr2)
    og2 = p.owner_group(p.descriptor_table(exe, ovr2), OWNER_FA)
    assert p.owner_site_rows(og2, [{"site": site, "seg": SEG_RAW_TARGET, "off": OFF_TARGET,
                                    "proc": OWNER_FA, "bytes": ""}])[0]["seg_word_fixup_listed"] is False


def test_consensus_is_uniform_then_mutation_breaks_it():
    ovr, exe, owner, bb, cb = build()
    dump = live_dump(ovr, owner, bb, cb)
    rows = p.descriptor_table(exe, ovr)
    sib = p.map_siblings(rows, ogm.Dump(bytes(dump), 0))
    cons = p.consensus([s for s in sib if s["descriptor_offset"] != "0x0"])
    assert cons["consensus_delta"] == "0x%04X" % D and cons["groups_with_deltas"] == 2
    # mutation: sibling C's live fixup word is off by one -> two delta values, no consensus
    dump2 = live_dump(ovr, owner, bb, cb, delta_c=D + 1)
    sib2 = p.map_siblings(rows, ogm.Dump(bytes(dump2), 0))
    cons2 = p.consensus([s for s in sib2 if s["descriptor_offset"] != "0x0"])
    assert cons2["consensus_delta"] is None and len(cons2["delta_values"]) == 2


def test_owner_absent_or_ambiguous_in_dump_is_not_measured():
    ovr, exe, owner, bb, cb = build()
    rows = p.descriptor_table(exe, ovr)
    absent = live_dump(ovr, owner, bb, cb, owner_at=())
    s = p.map_siblings(rows, ogm.Dump(bytes(absent), 0))
    assert next(r for r in s if r["descriptor_offset"] == "0x0")["mapping_status"] == "absent"
    twice = live_dump(ovr, owner, bb, cb, owner_at=(OWNER_PARA, OWNER_PARA + 0x10))
    s2 = p.map_siblings(rows, ogm.Dump(bytes(twice), 0))
    assert next(r for r in s2 if r["descriptor_offset"] == "0x0")["mapping_status"] == "ambiguous"
    doc = _analyse(ovr, exe, absent)
    assert doc["delta_evidence"]["owner_delta_measured"] is False
    assert doc["verdict"]["owner_delta_measured"] is False


def test_jmp_stub_resolves_to_group_body_and_byte_mutation_removes_it():
    ovr, exe, owner, bb, cb = build()
    rows = p.descriptor_table(exe, ovr)
    dump = live_dump(ovr, owner, bb, cb)
    segs = p.mapped_segments(p.map_siblings(rows, ogm.Dump(bytes(dump), 0)), rows)
    files = {p.OVR_NAME: ovr, p.EXE_NAME: exe}
    lin = (SEG_RAW_TARGET + D) * 16 + OFF_TARGET
    # the overlay manager's JMP FAR over stub0: EA off16 seg16, then the stub file tail
    tail = exe[0x17 + 5:0x17 + p.WINDOW]
    stub_live = b"\xea" + struct.pack("<HH", OFF_TARGET, OWNER_PARA) + tail
    dump[lin:lin + p.WINDOW] = stub_live
    res = p.classify_at(SEG_RAW_TARGET, OFF_TARGET, D, ogm.Dump(bytes(dump), 0), files, segs, ovr, rows)
    assert res["status"] == "jmp-stub-to-mapped-group"
    assert res["group"]["gameovr_offset"] == "0x%X" % (OWNER_FA + OFF_TARGET)
    assert res["group"]["prologue_ok"] is True
    assert res["start_stub_hits"] == ["0x17"]
    assert res["start_stub_runs"][0]["index"] == 0 and res["start_stub_runs"][0]["dist"] == 0x17
    # mutation: the JMP opcode back to INT 3Fh -> no longer a patched stub
    dump[lin] = 0xCD
    res2 = p.classify_at(SEG_RAW_TARGET, OFF_TARGET, D, ogm.Dump(bytes(dump), 0), files, segs, ovr, rows)
    assert res2["status"] != "jmp-stub-to-mapped-group"


def test_stub_run_discriminator_singles_out_the_stub_delta():
    ovr, exe, owner, bb, cb = build()
    rows = p.descriptor_table(exe, ovr)
    files = {p.OVR_NAME: ovr, p.EXE_NAME: exe}
    dump = live_dump(ovr, owner, bb, cb)
    segs = p.mapped_segments(p.map_siblings(rows, ogm.Dump(bytes(dump), 0)), rows)
    tail = exe[0x17 + 5:0x17 + p.WINDOW]
    stub = b"\xea" + struct.pack("<HH", OFF_TARGET, OWNER_PARA) + tail
    lin = (SEG_RAW_TARGET + D) * 16 + OFF_TARGET
    dump[lin:lin + p.WINDOW] = stub
    # an alternative delta whose target also holds a JMP to the mapped group, with no START stub
    alt = 0x0200
    lin_alt = (SEG_RAW_TARGET + alt) * 16 + OFF_TARGET
    dump[lin_alt:lin_alt + p.WINDOW] = b"\xea" + struct.pack("<HH", OFF_TARGET, OWNER_PARA) + bytes(27)
    dmp = ogm.Dump(bytes(dump), 0)
    sw = p.sweep(SEG_RAW_TARGET, OFF_TARGET, dmp, files, segs, rows, D)
    assert "0x%04X" % alt not in sw["jmp_with_stub_run_slot"]
    assert sw["jmp_with_stub_run_slot"] == ["0x%04X" % D]
    assert sw["candidate_is_only_stub_run_delta"] is True
    # mutation: the stub's proc_off in START no longer matches the live JMP -> no stub-run slot
    exe2 = bytearray(exe)
    exe2[0x19:0x1B] = struct.pack("<H", 0x0031)
    files2 = {p.OVR_NAME: ovr, p.EXE_NAME: bytes(exe2)}
    sw2 = p.sweep(SEG_RAW_TARGET, OFF_TARGET, dmp, files2, segs, rows, D)
    assert sw2["jmp_with_stub_run_slot"] == []
    assert sw2["candidate_is_only_stub_run_delta"] is False


def test_masked_match_is_delta_consistent_only():
    ovr, exe, owner, bb, cb = build()
    rows = p.descriptor_table(exe, ovr)
    files = {p.OVR_NAME: ovr, p.EXE_NAME: exe}
    # a START window with a far call whose segment word is 0x0AF8 in the file
    win = bytearray(b"\x55\x89\xe5\x83\xec\x24\xc4\x7e\x0a\x06\x57\x8d\x7e\xf8\x16\x57\xb8\x08\x00\x50"
                    b"\x9a\x3f\x0a\xf8\x0a\x8b\x46\x06\x0b\x46\x08\x75")
    exe = bytearray(exe)
    exe[0x200:0x200 + 32] = win
    files = {p.OVR_NAME: ovr, p.EXE_NAME: bytes(exe)}
    raw, off = 0x0400, 0x0000
    lin = (raw + D) * 16 + off
    dump = bytearray(DUMP_SIZE)
    live = bytearray(win)
    live[23:25] = struct.pack("<H", (0x0AF8 + D) & 0xFFFF)     # rewritten by the delta
    dump[lin:lin + 32] = live
    dmp = ogm.Dump(bytes(dump), 0)
    got = p.resolve_masked(raw, off, D, dmp, files)
    assert got["status"] == "masked-unique"
    assert got["hits"][0]["file"] == p.EXE_NAME and got["hits"][0]["offset"] == "0x200"
    # mutation: a live seg word that differs from the file by a delta other than D -> no match
    live2 = bytearray(live)
    live2[23:25] = struct.pack("<H", (0x0AF8 + D + 1) & 0xFFFF)
    dump2 = bytearray(DUMP_SIZE)
    dump2[lin:lin + 32] = live2
    assert p.resolve_masked(raw, off, D, ogm.Dump(bytes(dump2), 0), files)["status"] == "masked-absent"


def test_exact_window_in_two_files_is_ambiguous_not_unique():
    ovr, exe, owner, bb, cb = build()
    rows = p.descriptor_table(exe, ovr)
    common = bytes(range(0x21, 0x21 + 32))
    ovr_b = bytearray(ovr)
    exe_b = bytearray(exe)
    ovr_b[0x380:0x380 + 32] = common
    exe_b[0x380:0x380 + 32] = common
    files = {p.OVR_NAME: bytes(ovr_b), p.EXE_NAME: bytes(exe_b)}
    raw, off = 0x0300, 0x0000
    lin = (raw + D) * 16 + off
    dump = bytearray(DUMP_SIZE)
    dump[lin:lin + 32] = common
    res = p.classify_at(raw, off, D, ogm.Dump(bytes(dump), 0), files, {}, bytes(ovr_b), rows)
    assert res["status"] == "no-exact-match"
    assert res["exact"]["status"] == "ambiguous"


def test_out_of_dump_and_closure_at_a_resolved_body():
    ovr, exe, owner, bb, cb = build()
    rows = p.descriptor_table(exe, ovr)
    files = {p.OVR_NAME: ovr, p.EXE_NAME: exe}
    small = ogm.Dump(bytes(0x100), 0)
    res = p.classify_at(0xF000, 0x0, D, small, files, {}, ovr, rows)
    assert res["status"] == "out-of-dump"
    doc = p.closure_at(ovr, OWNER_FA + OFF_TARGET)
    assert doc["answer"] in ("no-dos-file-function-in-closure", "no-dos-file-function-found-but-bounded-incomplete")
    assert doc["procs_explored"] == 1 and doc["closure_complete"] is True
    assert doc["int21_file_hits"] == 0 and doc["string_token_candidates"] == 0


def test_analyse_refuses_unpinned_inputs_and_needs_a_dump():
    ovr, exe, owner, bb, cb = build()
    with pytest.raises(ogm.Refusal):
        p.analyse(ovr, exe, [("ram-000000-100000.bin", bytes(DUMP_SIZE), 0)], OWNER_FA)
    with pytest.raises(ogm.Refusal):
        p.analyse(ovr, exe, [], OWNER_FA, pins=_pins(ovr, exe))


def test_full_synthetic_analysis_is_conditional_and_not_measured():
    ovr, exe, owner, bb, cb = build()
    dump = live_dump(ovr, owner, bb, cb)
    doc = _analyse(ovr, exe, dump)
    assert doc["playable"] is False
    assert doc["status"] == "diagnostic"
    assert doc["verdict"]["owner_delta_measured"] is True          # the owner maps uniquely here
    assert doc["owner_closure"]["procs_explored"] == 1
    assert [x["raw_target"] for x in doc["owner_far_sites"]] == ["0428:0030"]
    assert doc["delta_evidence"]["union_consensus_delta"] == "0x%04X" % D
    assert doc["owner"]["fileofs"] == "0x%X" % OWNER_FA
    assert doc["claims"]["owner_delta"].startswith("not_established")


@pytest.mark.skipif(not INSTALL or not all(d.is_file() for d in DUMPS),
                    reason="needs OPENUA_POR_INSTALL and both local dumps under data/work")
def test_retail_far_targets_match_documented_facts():
    folder = ogm.find_install(Path(INSTALL))
    ovr = (folder / p.OVR_NAME).read_bytes()
    exe = (folder / p.EXE_NAME).read_bytes()
    dumps = [(d.name, d.read_bytes(), ogm.resolve_dump_base(d.name, d.stat().st_size, None)) for d in DUMPS]
    doc = p.analyse(ovr, exe, dumps, p.OWNER)
    assert doc["owner"]["descriptor_offset"] == "0x3DD7" and doc["owner"]["fileofs"] == "0x2E8F7"
    assert len(doc["owner_far_sites"]) == 8
    assert all(s["seg_word_fixup_listed"] for s in doc["owner_far_sites"])
    assert doc["delta_evidence"]["union_consensus_delta"] == "0x1866"
    assert doc["delta_evidence"]["owner_delta_measured"] is False
    by = {t["raw"]: t for t in doc["targets"]}
    stub = by["0428:002A"]["per_dump"][0]["resolution"]
    assert stub["status"] == "jmp-stub-to-mapped-group"
    assert stub["group"]["gameovr_offset"] == "0x32392" and stub["group"]["prologue_ok"] is True
    assert by["0428:002A"]["per_dump"][0]["sweep"]["candidate_is_only_stub_run_delta"] is True
    assert by["0464:1B52"]["per_dump"][0]["resolution"]["exact"]["hits"]["START.EXE"] == ["0x61CB"]
    assert by["0464:2632"]["per_dump"][0]["masked"]["hits"][0]["offset"] == "0x6CAB"
    assert doc["verdict"]["sweep_unique_by_bytes"] is False

    # Conditional follow-up of far calls in those candidates. These mappings
    # remain under the sibling-delta model; no row claims a call executed.
    follow = doc["far_call_followups_conditional"]
    def mapped(ancestry, depth, raw, source_root=None):
        rows = [r for r in follow if r["ancestry_target"] == ancestry
                and r["source_depth"] == depth and r["raw_target"] == raw
                and (source_root is None or r["source_root"] == source_root)]
        assert len(rows) == 1, (ancestry, depth, raw, len(rows))
        return rows[0]

    assert mapped("0428:002A", 0, "0464:00FF")["mapping"]["file_offset"] == "0x4778"
    assert mapped("0428:002A", 0, "0464:08D4")["mapping"]["file_offset"] == "0x4F4D"
    assert mapped("0428:002A", 0, "0464:1951")["mapping"]["file_offset"] == "0x5FCA"
    helpers = [r for r in follow if r["ancestry_target"] == "0464:2632"
               and r["source_depth"] == 0 and r["raw_target"] == "0AF8:0A3F"]
    assert len(helpers) == 2
    assert all(r["mapping"]["status"] == "module-base-and-dump-match"
               and r["mapping"]["file_offset"] == "0xB6B5" for r in helpers)
    assert mapped("0428:002A", 1, "0A32:000B", "0x4778")["mapping"]["file_offset"] == "0xA024"
    assert mapped("0428:002A", 2, "0A32:00A2", "0x8BD3")["mapping"]["file_offset"] == "0xA0BB"
    assert mapped("0428:002A", 1, "0AF8:00E9", "0x89C7")["mapping"]["status"] == "module-base-not-cross-checked"
    assert all(r.get("conditional_closure", {}).get("int21_file_hits", 0) == 0
               for r in follow if "conditional_closure" in r)
    assert all(r.get("conditional_closure", {}).get("string_token_candidates", 0) == 0
               for r in follow if "conditional_closure" in r)
