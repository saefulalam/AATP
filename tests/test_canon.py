import pytest

from aatp.errors import AATPError
from aatp.canon import jcs, parse_jcs


def _nest(levels, leaf=None):
    """Top-level dict plus `levels` nested {"x": ...}; innermost is `leaf` or {}."""
    obj = {}
    cur = obj
    for i in range(levels):
        nxt = {} if (i < levels - 1 or leaf is None) else leaf
        cur["x"] = nxt
        cur = nxt
    return obj


def _malformed(fn, *args):
    with pytest.raises(AATPError) as ei:
        fn(*args)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
    assert ei.value.numeric == 1002


# --- V01 / V09 ---------------------------------------------------------------

def test_V01_jcs_sorts_keys():
    assert jcs({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert jcs({"b": 2, "a": 1}).hex() == "7b2261223a312c2262223a327d"


def test_V09_float_parse_rejected():
    _malformed(parse_jcs, b'{"a":1.5}')


# --- GEN-010: serializer -----------------------------------------------------

def test_GEN010_reject_float():
    _malformed(jcs, {"a": 1.5})


def test_GEN010_reject_integral_float():
    _malformed(jcs, {"a": 1.0})


def test_GEN010_reject_non_ascii_key():
    _malformed(jcs, {"é": 1})


def test_GEN010_reject_depth_over_16():
    _malformed(jcs, _nest(17))


def test_GEN010_accept_depth_exactly_16():
    obj = _nest(16)
    out = jcs(obj)
    assert out == b'{"x":' * 16 + b"{}" + b"}" * 16
    assert parse_jcs(out) == obj


def test_GEN010_reject_scalar_at_depth_17():
    # innermost container at depth 16 holds a scalar at depth 17
    _malformed(jcs, _nest(16, leaf={"x": 1}))


def test_GEN010_reject_deep_list():
    obj = []
    cur = obj
    for _ in range(17):
        nxt = []
        cur.append(nxt)
        cur = nxt
    _malformed(jcs, obj)


def test_GEN010_int_range_boundary():
    m = 2**53 - 1
    assert jcs([m, -m]) == b"[9007199254740991,-9007199254740991]"
    _malformed(jcs, [m + 1])
    _malformed(jcs, [-(m + 1)])


def test_GEN010_bools_and_null():
    assert jcs([True, False, None]) == b"[true,false,null]"
    assert jcs({"t": True}) == b'{"t":true}'


def test_GEN010_reject_non_str_key():
    _malformed(jcs, {1: "a"})
    _malformed(jcs, {None: "a"})
    _malformed(jcs, {True: "a"})


def test_GEN010_reject_unsupported_types():
    for bad in [(1, 2), b"ab", {1, 2}, object(), {"a": (1,)}, [b"x"]]:
        _malformed(jcs, bad)


def test_GEN010_reject_lone_surrogate_value():
    _malformed(jcs, {"a": "\ud800"})


def test_GEN010_reject_lone_surrogate_key():
    _malformed(jcs, {"\ud800": 1})


def test_GEN010_string_escaping_rfc8785():
    s = "\x01\n\"\\/é\u2028\x1f\t\b\f\r\x7f"
    expected = (
        b'"\\u0001\\n\\"\\\\/'
        + "é".encode("utf-8")
        + "\u2028".encode("utf-8")
        + b'\\u001f\\t\\b\\f\\r\x7f"'
    )
    assert jcs(s) == expected
    assert parse_jcs(expected) == s


def test_GEN010_keys_sorted_by_code_unit():
    assert jcs({"b": 1, "B": 2, "a": 3, "_": 4}) == b'{"B":2,"_":4,"a":3,"b":1}'


def test_GEN010_utf8_output_non_ascii_value():
    assert jcs({"a": "日本"}) == '{"a":"日本"}'.encode("utf-8")


# --- GEN-011: parser rejects, never repairs ----------------------------------

def test_GEN011_reject_noncanonical_parse():
    _malformed(parse_jcs, b'{ "a":1 }')


def test_GEN011_reject_trailing_newline():
    _malformed(parse_jcs, b'{"a":1}\n')


def test_GEN011_reject_unsorted_keys():
    _malformed(parse_jcs, b'{"b":2,"a":1}')


def test_GEN011_reject_unneeded_escape():
    _malformed(parse_jcs, b'{"a":"\\u0041"}')


def test_GEN011_reject_escaped_slash():
    _malformed(parse_jcs, b'{"a":"\\/"}')


def test_GEN011_reject_negative_zero():
    _malformed(parse_jcs, b"[-0]")


def test_GEN011_reject_duplicate_keys():
    _malformed(parse_jcs, b'{"a":1,"a":2}')


def test_GEN011_reject_float_parse():
    _malformed(parse_jcs, b'{"a":1.5}')


def test_GEN011_reject_exponent_and_fraction():
    for raw in [b'{"a":1e5}', b'{"a":1E5}', b'{"a":1.0}', b"[0.0]"]:
        _malformed(parse_jcs, raw)


def test_GEN011_reject_nan_infinity():
    for raw in [b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}']:
        _malformed(parse_jcs, raw)


def test_GEN011_reject_invalid_utf8():
    _malformed(parse_jcs, b'{"a":"\xff"}')
    _malformed(parse_jcs, b'{"a":"\xc3"}')


def test_GEN011_reject_bom():
    _malformed(parse_jcs, b'\xef\xbb\xbf{"a":1}')


def test_GEN011_reject_invalid_json():
    for raw in [b"", b"{", b'{"a":}', b"[1,]", b"01", b"{'a':1}", b'{"a":1}{"b":2}']:
        _malformed(parse_jcs, raw)


def test_GEN011_reject_depth_over_16_parse():
    raw = b'{"x":' * 17 + b"{}" + b"}" * 17
    _malformed(parse_jcs, raw)


def test_GEN011_reject_huge_nesting_parse():
    # must not leak RecursionError
    raw = b"[" * 100000 + b"]" * 100000
    _malformed(parse_jcs, raw)


def test_GEN011_reject_non_ascii_key_parse():
    _malformed(parse_jcs, '{"é":1}'.encode("utf-8"))


def test_GEN011_reject_int_out_of_range_parse():
    _malformed(parse_jcs, b"[9007199254740992]")
    _malformed(parse_jcs, b"[-9007199254740992]")
    _malformed(parse_jcs, b"[" + b"9" * 5000 + b"]")


def test_GEN011_reject_lone_surrogate_escape():
    _malformed(parse_jcs, b'{"a":"\\ud800"}')


def test_GEN011_reject_non_bytes_input():
    _malformed(parse_jcs, '{"a":1}')


def test_GEN011_surrogate_pair_raw_utf8_ok():
    raw = '{"a":"\U0001f600"}'.encode("utf-8")
    assert parse_jcs(raw) == {"a": "\U0001f600"}
    # escaped pair is non-canonical (JCS emits raw UTF-8)
    _malformed(parse_jcs, b'{"a":"\\ud83d\\ude00"}')


# --- GEN-012 -------------------------------------------------------------------

def test_GEN012_unknown_field_preserved():
    raw = b'{"a":1,"zz_unknown":{"k":[1,2]}}'
    assert jcs(parse_jcs(raw)) == raw
