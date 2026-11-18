"""Tests for tools/por_wall_0111_target_probe.py (identity and bounded body of far target 0x0464:0x0111).

Synthetic fixtures (default) check each claim with a mutated-byte falsifier that must change the result:
call-site search, the caller's measured-delta rule, the one-far-word window resolution (exact, masked,
ambiguous, out-of-dump, off-by-one delta), the ES:DI origin rule, the bounded body walk (passed-record
writes and reads, a far call that breaks the origin, INT 21h, a token inside versus outside the body).
The retail test runs only when OPENUA_POR_INSTALL names the local Pool of Radiance DOS install and is
skipped otherwise; it reads the install and the ignored RAM dumps read-only and writes nothing.
"""
import os
import sys
from pathlib import Path

import pytest

TESTS = os.path.dirname(__file__)
TOOLS = os.path.join(TESTS, "..", "tools")
sys.path.insert(0, TOOLS)
import por_overlay_group_map as ogm  # noqa: E402
import por_wall_0111_target_probe as tp  # noqa: E402
import por_wall_callee_probe as cp  # noqa: E402

ENV = "OPENUA_POR_INSTALL"
DELTA = 0x1866
LIN = ((tp.TARGET_SEG + DELTA) & 0xFFFF) * tp.PARA + tp.TARGET_OFF   # 0x1CDB1
W32 = bytes([0x55, 0x89, 0xE5]) + bytes(range(0x10, 0x10 + 17)) + bytes([0x9A, 0x25, 0x0B, 0xF8, 0x0A]) \
    + bytes(range(0x30, 0x37))
LIVE32 = W32[:23] + bytes([0x5E, 0x23]) + W32[25:]                   # 0AF8 + 0x1866 = 0x235E
assert len(W32) == 32 and len(LIVE32) == 32


def _blob(size: int, at: int, data: bytes) -> bytes:
    out = bytearray(size)
    out[at:at + len(data)] = data
    return bytes(out)


def _files(exe: bytes, ovr: bytes = b"\x00" * 0x200) -> dict:
    return {tp.OVR_NAME: ovr, tp.EXE_NAME: exe}


def _dump(at: int, window: bytes, total: int = 0) -> ogm.Dump:
    size = max(total, at + len(window) + 16)
    return ogm.Dump(_blob(size, at, window), 0)


def _proc(hexbytes: str):
    """Decode a straight-line blob at offset 0 with the wall-callee decoder (file-offset space)."""
    data = bytes.fromhex(hexbytes)
    ex = cp.explore(data, 0, 200)
    return sorted(ex["_insns"], key=lambda i: i.off), set(ex.get("branch_targets", set()))


# -- call sites -------------------------------------------------------------------------------------

def test_call_site_found_and_falsified():
    data = b"\x90" * 3 + tp.CALL_BYTES + b"\x90" * 4 + tp.CALL_BYTES
    assert tp.find_call_sites(data) == [3, 12]
    wrong_seg = data.replace(tp.CALL_BYTES, bytes([0x9A, 0x11, 0x01, 0x65, 0x04]))
    wrong_off = data.replace(tp.CALL_BYTES, bytes([0x9A, 0x12, 0x01, 0x64, 0x04]))
    assert tp.find_call_sites(wrong_seg) == []
    assert tp.find_call_sites(wrong_off) == []


# -- caller's measured delta ------------------------------------------------------------------------

def _focus(site_deltas=("0x1866", "0x1866"), groups=(["0x1866"], ["0x1866"]), listed=True, raw="0464",
           statuses=("unique", "unique")):
    per = []
    for sd, gd, st in zip(site_deltas, groups, statuses):
        row = {"dump": "d", "mapping_status": st}
        if st == "unique":
            row.update({"site_delta": sd, "group_fixup_deltas": list(gd)})
        per.append(row)
    return {"per_dump": per, "seg_word_fixup_listed": listed, "raw_seg_word": raw}


def test_caller_delta_measured_when_uniform_and_listed():
    assert tp.caller_delta(_focus(), 2) == DELTA


@pytest.mark.parametrize("focus", [
    _focus(groups=(["0x1866", "0x0001"], ["0x1866", "0x0001"])),       # group not uniform
    _focus(site_deltas=("0x1866", "0x1867"), groups=(["0x1866"], ["0x1867"])),   # dumps disagree
    _focus(listed=False),                                               # seg word not fixup-listed
    _focus(raw="0465"),                                                 # raw word is not the target seg
    _focus(statuses=("unique", "ambiguous")),                           # one dump does not map uniquely
])
def test_caller_delta_refused_by_each_falsifier(focus):
    assert tp.caller_delta(focus, 2) is None


# -- window resolution under one delta --------------------------------------------------------------

def test_resolution_masked_one_far_word_unique():
    exe = _blob(0x300, 0x100, W32)
    res = tp.resolve_under(DELTA, [("d1", _dump(LIN, LIVE32)), ("d2", _dump(LIN, LIVE32))], _files(exe))
    assert res["unique_and_agreeing_in_every_dump"] is True
    assert res["resolution"] == {"file": "START.EXE", "offset": "0x100"}
    assert res["per_dump"][0]["hits"][0]["mode"] == "masked-one-far-word"


def test_resolution_falsified_by_one_byte_outside_the_far_word():
    exe = _blob(0x300, 0x100, W32)
    bad = bytearray(LIVE32)
    bad[5] ^= 0xFF
    res = tp.resolve_under(DELTA, [("d", _dump(LIN, bytes(bad)))], _files(exe))
    assert res["unique_and_agreeing_in_every_dump"] is False


def test_resolution_falsified_by_delta_off_by_one():
    exe = _blob(0x300, 0x100, W32)
    res = tp.resolve_under(DELTA + 1, [("d", _dump(LIN, LIVE32))], _files(exe))
    assert res["unique_and_agreeing_in_every_dump"] is False


def test_resolution_exact_window_mode():
    exe = _blob(0x300, 0x100, LIVE32)
    res = tp.resolve_under(DELTA, [("d", _dump(LIN, LIVE32))], _files(exe))
    assert res["resolution"] == {"file": "START.EXE", "offset": "0x100"}
    assert res["per_dump"][0]["hits"][0]["mode"] == "exact-32-bytes"


def test_resolution_ambiguous_when_window_repeats():
    exe = bytearray(_blob(0x400, 0x100, W32))
    exe[0x200:0x220] = W32
    res = tp.resolve_under(DELTA, [("d", _dump(LIN, LIVE32))], _files(bytes(exe)))
    assert res["per_dump"][0]["status"] == "ambiguous"
    assert res["resolution"] is None


def test_resolution_out_of_dump():
    exe = _blob(0x300, 0x100, W32)
    small = ogm.Dump(b"\x00" * 0x100, 0)
    res = tp.resolve_under(DELTA, [("d", small)], _files(exe))
    assert res["per_dump"][0]["status"] == "out-of-dump"
    assert res["resolution"] is None


# -- ES:DI origin -----------------------------------------------------------------------------------

def _origin_at(hexbytes: str, target_off: int) -> str:
    insns, branches = _proc(hexbytes)
    return tp.origin_tags(insns, branches)[target_off]


LES_PASSED = "c47e06"          # les di,[bp+6]
ES_WRITE = "268905"            # es mov [di],ax


def test_origin_passed_after_les_bp6_then_cleared_by_clobbers():
    assert _origin_at(LES_PASSED + ES_WRITE, 3) == "passed-record"
    assert _origin_at("c47efa" + ES_WRITE, 3) == "unknown"            # les di,[bp-6] is a different pointer
    assert _origin_at(LES_PASSED + "9a00000000" + ES_WRITE, 8) == "unknown"   # a far call clobbers
    assert _origin_at(LES_PASSED + "bf0000" + ES_WRITE, 6) == "unknown"        # mov di,imm
    assert _origin_at(LES_PASSED + "b80000" + ES_WRITE, 6) == "passed-record"  # mov ax,imm does not touch DI


def test_touches_di_or_es_table():
    assert tp._touches_di_or_es(_proc("bf0000")[0][0]) is True          # mov di,imm
    assert tp._touches_di_or_es(_proc("b80000")[0][0]) is False         # mov ax,imm
    assert tp._touches_di_or_es(_proc("81ff0000")[0][0]) is False       # cmp di,imm (reads only)
    assert tp._touches_di_or_es(_proc("8bf7")[0][0]) is False           # mov si,di
    assert tp._touches_di_or_es(_proc("8bfb")[0][0]) is True            # mov di,bx


# -- bounded body walk ------------------------------------------------------------------------------

BODY = "55" "89e5" + LES_PASSED + ES_WRITE + "268955" + "02" + "c3"     # push bp; mov bp,sp; les; 2 writes; ret


def _body_exe(hexbytes: str, at: int = 0x100) -> bytes:
    return _blob(0x400, at, bytes.fromhex(hexbytes))


def test_body_passed_record_writes_found():
    exe = _body_exe(BODY)
    body = tp.decode_body(exe, 0x100, (0x100, 0x200))
    writes = [w["at"] for w in body["passed_record_access"]["passed_record_writes"]]
    assert writes == ["0x106", "0x109"]
    assert body["int_calls"] == []


def test_body_falsified_when_les_is_replaced_by_other_pointer():
    exe = _body_exe(BODY.replace(LES_PASSED, "c47efa", 1))
    body = tp.decode_body(exe, 0x100, (0x100, 0x200))
    assert body["passed_record_access"]["passed_record_writes"] == []
    assert len(body["passed_record_access"]["other_origin_es_writes"]) == 2


def test_body_falsified_by_far_call_between_les_and_write():
    exe = _body_exe(BODY.replace(LES_PASSED + ES_WRITE, LES_PASSED + "9a00000000" + ES_WRITE, 1))
    body = tp.decode_body(exe, 0x100, (0x100, 0x200))
    writes = [w["at"] for w in body["passed_record_access"]["passed_record_writes"]]
    assert "0x10B" not in writes                       # the first write now follows a far call
    assert len(body["passed_record_access"]["other_origin_es_writes"]) >= 1


def test_body_int21_detected_when_present():
    exe = _body_exe(BODY.replace("c3", "cd21c3", 1))
    body = tp.decode_body(exe, 0x100, (0x100, 0x200))
    assert [x["vector"] for x in body["int_calls"]] == [0x21]


def test_body_token_counted_only_inside_walked_bytes():
    inside = _body_exe(BODY.replace("c3", "bb444158c3", 1))           # mov bx,0x4144 carries 'DA'; 'X' follows
    body = tp.decode_body(inside, 0x100, (0x100, 0x200))
    assert body["string_tokens_in_body_bytes"] == {"0x0010E": "DAX"}   # bytes 44 41 58 at 0x10E, inside walked code
    outside = bytearray(0x400)
    outside[0x80:0x83] = b"DAX"
    outside[0x100:0x100 + len(bytes.fromhex(BODY))] = bytes.fromhex(BODY)
    body2 = tp.decode_body(bytes(outside), 0x100, (0x100, 0x200))
    assert body2["string_tokens_in_body_bytes"] == {}
    assert body2["string_tokens_in_start_file"] == 1


# -- retail pin (gated) -----------------------------------------------------------------------------

DUMPS = [Path("data/work/por-live-memory-pid34644/ram-000000-100000.bin"),
         Path("data/work/por-wheel-live-capture/ram-000000-100000.bin")]
REPO = Path(TESTS).parent


@pytest.mark.skipif(not os.environ.get(ENV), reason=f"set {ENV} to the Pool of Radiance install")
def test_retail_identity_and_body_facts():
    folder = ogm.find_install(Path(os.environ[ENV]))
    dumps = [(p.name, ogm.Dump(p.read_bytes(), ogm.resolve_dump_base(p.name, p.stat().st_size, None)))
             for p in (REPO / d for d in DUMPS)]
    ovr = (folder / tp.OVR_NAME).read_bytes()
    exe = (folder / tp.EXE_NAME).read_bytes()
    doc = tp.analyse(ovr, exe, dumps)
    assert all(p["pin_match"] for p in doc["inputs"]["pins"].values())
    assert len(doc["identity"]["call_sites_gameovr"]) == 19
    focus = doc["identity"]["focus_site"]
    assert focus["group"] == "0x42C2" and focus["body_offset"] == "0xBE"
    assert focus["seg_word_fixup_listed"] is True
    assert doc["identity"]["caller_measured_delta"] == "0x1866"
    assert doc["identity"]["resolution"] == {"file": "START.EXE", "offset": "0x478A"}
    assert doc["caller"]["site_text"] == "call 0x0464:0x0111"
    b = doc["body"]
    acc = b["passed_record_access"]
    assert [w["at"] for w in acc["passed_record_writes"]] == ["0x6B41", "0x6B44", "0x6C9E", "0x6CA1"]
    assert "0x47A8" in [r["at"] for r in acc["passed_record_reads"]]
    assert b["int_calls"] == []
    assert b["string_tokens_in_body_bytes"] == {}
    assert b["ds_region_matches"] == []
    assert b["region_address_immediates"] == []
    assert b["walk"]["incomplete"] == [] and b["walk"]["outside_near_calls"] == []
    assert doc["verdict"]["identified"] is True
    assert doc["verdict"]["reached_or_executed"] == "not-established"
