"""Source guard for the FRUA_GEO_SWEEPTEST harness in src/engine/boot.c.

FRUA_GEO_SWEEPTEST loads GEO001..GEO029 through the real jt198 loader inside
frua_areatest_entry. A host build cannot run the 68k engine, so these tests pin
the properties that must hold in the source:

1. Every sweep identifier and marker sits inside an #ifdef FRUA_GEO_SWEEPTEST
   region, so a build without the macro compiles none of it.
2. With the sweep compiled out, frua_areatest_entry is the original sequence:
   ... frua_spilltest (optional) ... jt948(); }.
3. The sweep order is begin marker -> existence probe -> jt198 -> check, one
   pass over 1..29, and a file that is absent is skipped, never handed to jt198
   (jt127 would fall through to the cold disk load).
4. The configured entry level and party cell are captured before the sweep and
   restored after it, and the restore happens before jt948. If the configured
   file is absent, the sweep returns before touching the live map.
5. The existence probe builds its path the way jt127 does (same design-name
   prefix, same GEMDOS open), and it does not call jt127 or jt198.

Nothing here runs the engine or Hatari. Runtime evidence is a separate step.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOOT_TEXT = (ROOT / "src" / "engine" / "boot.c").read_text(encoding="utf-8")
DOC = ROOT / "docs" / "por-geo-sweeptest.md"

SWEEP_MACRO = "FRUA_GEO_SWEEPTEST"
# The definition, not the forward declaration in main(): its next "{" is the body.
DEF_HEADER = "void frua_areatest_entry(void)\n{"
PP_IF = re.compile(r"^\s*#\s*if")
PP_ENDIF = re.compile(r"^\s*#\s*endif")
SWEEP_TOKENS = ("frua_geo_sweep_", "FRUA_GEO_SWEEP_", "GEO-SWEEP")


def _strip_comments(src):
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


def _function_body(src, header):
    """Text between the braces of the function whose header is `header`."""
    start = src.index(header)
    open_at = src.index("{", start)
    depth = 0
    for i in range(open_at, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at + 1:i]
    raise AssertionError(f"unbalanced braces after {header!r}")


def _sweep_line_flags(text):
    """For each line, True when it sits inside an #if region gated on the macro."""
    stack = []
    flags = []
    for line in text.splitlines():
        if PP_IF.match(line):
            stack.append(SWEEP_MACRO in line)
            flags.append(any(stack))
        elif PP_ENDIF.match(line):
            flags.append(any(stack))
            if stack:
                stack.pop()
        else:
            flags.append(any(stack))
    assert not stack, "unbalanced preprocessor conditionals in boot.c"
    return flags


def _sweep_block_span(body):
    """Span of the #ifdef FRUA_GEO_SWEEPTEST ... #endif block inside `body`."""
    m = re.search(r"^#ifdef FRUA_GEO_SWEEPTEST\b.*?^#endif[^\n]*$",
                  body, flags=re.S | re.M)
    assert m, "no #ifdef FRUA_GEO_SWEEPTEST block found in frua_areatest_entry"
    return m.span()


ENTRY_BODY = _function_body(BOOT_TEXT, DEF_HEADER)
SWEEP_BODY = ENTRY_BODY[slice(*_sweep_block_span(ENTRY_BODY))]
SWEEP_CODE = _strip_comments(SWEEP_BODY)
HELPER_START = BOOT_TEXT.index("static int frua_geo_sweep_present(short n)")
HELPER_END = BOOT_TEXT.index(DEF_HEADER)
HELPERS = BOOT_TEXT[HELPER_START:HELPER_END]
HELPER_CODE = _strip_comments(HELPERS)


# --- 1. the macro gates every sweep identifier and marker ------------------

def test_every_sweep_token_is_inside_the_macro_region():
    lines = BOOT_TEXT.splitlines()
    flags = _sweep_line_flags(BOOT_TEXT)
    assert len(flags) == len(lines)
    offenders = [
        (i + 1, line.strip())
        for i, (line, gated) in enumerate(zip(lines, flags))
        if not gated and any(tok in line for tok in SWEEP_TOKENS)
    ]
    assert offenders == [], f"sweep code outside #ifdef {SWEEP_MACRO}: {offenders}"


def test_sweep_macro_is_defined_only_as_a_gate():
    # The macro is an opt-in gate: it is only ever tested, never defined here.
    assert not re.search(r"^#\s*define\s+FRUA_GEO_SWEEPTEST\b", BOOT_TEXT, re.M)


def test_sweep_compiles_out_as_the_original_entry_tail():
    # With the macro off the body is exactly the original sequence, which ends
    # with the spill test (optional) and then jt948().
    stripped = ENTRY_BODY[:_sweep_block_span(ENTRY_BODY)[0]] + \
        ENTRY_BODY[_sweep_block_span(ENTRY_BODY)[1]:]
    code = _strip_comments(stripped)
    tail = re.sub(r"\s+", " ", code).strip()
    assert tail.endswith("jt948();"), tail[-200:]
    assert len(re.findall(r"\bjt948\s*\(\s*\)\s*;", code)) == 1
    assert "frua_geo_sweep" not in code


# --- 2. sweep order and bounds ----------------------------------------------

def test_range_is_one_to_twenty_nine_in_one_pass():
    assert re.search(r"#define\s+FRUA_GEO_SWEEP_FIRST\s+1\b", BOOT_TEXT)
    assert re.search(r"#define\s+FRUA_GEO_SWEEP_LAST\s+29\b", BOOT_TEXT)
    assert "for (n = FRUA_GEO_SWEEP_FIRST; n <= FRUA_GEO_SWEEP_LAST; n++)" in SWEEP_CODE
    assert len(re.findall(r"\bjt198\s*\(", SWEEP_CODE)) == 2  # loop + restore


def test_per_area_order_is_begin_probe_load_check():
    loop = SWEEP_CODE.index("for (n = FRUA_GEO_SWEEP_FIRST")
    tail = SWEEP_CODE[loop:]
    begin = tail.index('"GEO-SWEEP area %03d begin"')
    probe = tail.index("frua_geo_sweep_present(n)")
    load = tail.index("jt198(n);")
    check = tail.index("frua_geo_sweep_check(n)")
    assert begin < probe < load < check


def test_absent_area_is_skipped_before_jt198():
    loop = SWEEP_CODE.index("for (n = FRUA_GEO_SWEEP_FIRST")
    tail = SWEEP_CODE[loop:]
    probe = tail.index("frua_geo_sweep_present(n)")
    load = tail.index("jt198(n);")
    skip_block = tail[probe:load]
    assert "continue;" in skip_block, "an absent GEO must continue, not reach jt198"
    assert "skipped++" in skip_block


def test_jt198_is_never_called_on_the_failure_path_for_absent_files():
    # The only jt198 calls in the sweep are the loop body (after the probe) and
    # the restore (after the configured-level probe). No other call site exists.
    calls = [m.start() for m in re.finditer(r"\bjt198\s*\(", SWEEP_CODE)]
    assert len(calls) == 2
    probe_positions = [m.start() for m in re.finditer(r"frua_geo_sweep_present\(", SWEEP_CODE)]
    assert probe_positions[0] < calls[0]


# --- 3. restore and abort -----------------------------------------------------

def test_configured_level_and_party_saved_before_the_loop():
    loop = SWEEP_CODE.index("for (n = FRUA_GEO_SWEEP_FIRST")
    head = SWEEP_CODE[:loop]
    assert "configured = (short)g_a5_18878" in head
    assert "px = g_a5_12288" in head
    assert "py = g_a5_12287" in head
    assert "pf = g_a5_12286" in head


def test_restore_reloads_configured_and_puts_party_back_before_jt948():
    loop_end = SWEEP_CODE.index("GEO-SWEEP loop done")
    restore = SWEEP_CODE.index("jt198(configured);")
    assert loop_end < restore
    tail = SWEEP_CODE[restore:]
    assert "g_a5_12288 = px;" in tail
    assert "g_a5_12287 = py;" in tail
    assert "g_a5_12286 = pf;" in tail
    # the restore is inside the macro block, which sits before the real jt948()
    assert ENTRY_BODY.rindex("jt948();") > _sweep_block_span(ENTRY_BODY)[1] - 1


def test_absent_configured_level_returns_before_touching_the_map():
    head_end = SWEEP_CODE.index("for (n = FRUA_GEO_SWEEP_FIRST")
    head = SWEEP_CODE[:head_end]
    probe = head.index("frua_geo_sweep_present(configured)")
    ret = head.index("return;")
    assert probe < ret
    assert "jt198" not in head[probe:ret]


# --- 4. the probe mirrors jt127's first open, and reads nothing else ----------

def test_existence_probe_mirrors_jt127_direct_open():
    assert "jt394(path, \"%s%03d.dat\", \"GEO\"" in HELPER_CODE
    assert "jt431(dpath, &g_a5_31336);" in HELPER_CODE
    assert "jt431(dpath, path);" in HELPER_CODE
    assert "refnum = jt398(dpath, 0);" in HELPER_CODE
    assert "jt411(refnum);" in HELPER_CODE


def test_probe_does_not_load_or_fall_through():
    assert "jt127" not in HELPER_CODE
    assert "jt198" not in HELPER_CODE
    assert "jt987" not in HELPER_CODE
    assert "glb" not in HELPER_CODE


def test_check_helper_only_reads_the_map():
    start = BOOT_TEXT.index("static int frua_geo_sweep_check(short n)")
    end = BOOT_TEXT.index(DEF_HEADER)
    check = _strip_comments(BOOT_TEXT[start:end])
    for forbidden in ("jt198", "jt127", "jt69", "jt398", "g_a5_long(-12300) =",
                      "lv[290 + id * 6 + 4] =", "memcpy", "jt399"):
        assert forbidden not in check, forbidden
    assert "FRUA_GEO_SWEEP_CELLS" in check


# --- 5. the doc carries the build recipe and the limits -----------------------

def test_doc_has_recipe_and_limits():
    text = DOC.read_text(encoding="utf-8")
    assert "-DFRUA_GEO_SWEEPTEST" in text
    assert "-DFRUA_AREATEST" in text
    assert "invented" in text.lower()
    assert "not" in text.lower() and "gameplay" in text.lower()
    assert "45" in text
