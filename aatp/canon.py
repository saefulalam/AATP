"""Canonical JSON (GEN-010/011/012): RFC 8785 JCS restricted subset.

Restrictions on top of JCS: ASCII-only object keys, integers only with
|n| <= 2^53-1 (no floats), no duplicate keys, max nesting depth 16.

Depth convention (D-002): the top-level value is depth 0; every value
directly inside an object/array is one deeper than its container. Any value
at depth > MAX_DEPTH is rejected. So 16 nested containers below the root are
allowed; a 17th is not.

Every failure raises AATPError(ERR_MALFORMED_MESSAGE). Parsing never repairs:
input must equal jcs(parsed) byte-for-byte (GEN-011).
"""
import json

from aatp.errors import err

MAX_DEPTH = 16
MAX_SAFE_INT = 2**53 - 1
# len("-9007199254740991"); longer digit strings are out of range by definition
# and are rejected before int() so Python's int-string-length limit never fires.
_MAX_INT_CHARS = 17


def _bad(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def _check_str(s: str, what: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise _bad(f"{what} not encodable as UTF-8 (lone surrogate)") from None


def _validate(obj, depth: int = 0) -> None:
    """Check obj is within the GEN-010 subset. Bounded recursion (depth <= 17)."""
    if depth > MAX_DEPTH:
        raise _bad(f"nesting depth > {MAX_DEPTH}")
    if obj is None or isinstance(obj, bool):
        return
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INT:
            raise _bad("integer magnitude exceeds 2^53-1")
        return
    if isinstance(obj, float):
        raise _bad("floating-point numbers forbidden")
    if isinstance(obj, str):
        _check_str(obj, "string")
        return
    if isinstance(obj, list):
        for v in obj:
            _validate(v, depth + 1)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise _bad(f"object key must be str, got {type(k).__name__}")
            if not k.isascii():
                raise _bad("non-ASCII object key")
            _validate(v, depth + 1)
        return
    raise _bad(f"unsupported type {type(obj).__name__}")


def jcs(obj) -> bytes:
    """Serialize obj to canonical JSON bytes."""
    _validate(obj)
    # For the validated subset (ASCII keys, safe ints, no floats) this matches
    # RFC 8785: code-unit key order, escapes only " \\ and C0 controls
    # (\b \f \n \r \t short forms, others \u00xx lowercase), raw UTF-8 otherwise.
    return json.dumps(
        obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _no_dup(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _bad("duplicate object key")
        out[k] = v
    return out


def _parse_int(s: str) -> int:
    if len(s) > _MAX_INT_CHARS:
        raise _bad("integer magnitude exceeds 2^53-1")
    return int(s)


def _reject_float(_s: str):
    raise _bad("floating-point numbers forbidden")


def _reject_constant(s: str):
    raise _bad(f"non-finite number {s} forbidden")


def parse_jcs(data: bytes):
    """Parse canonical JSON bytes; reject (never repair) anything non-canonical."""
    if not isinstance(data, (bytes, bytearray)):
        raise _bad(f"expected bytes, got {type(data).__name__}")
    data = bytes(data)
    try:
        text = data.decode("utf-8")
        obj = json.loads(
            text,
            object_pairs_hook=_no_dup,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError:
        raise _bad("invalid UTF-8") from None
    except RecursionError:
        raise _bad(f"nesting depth > {MAX_DEPTH}") from None
    except ValueError as e:  # includes json.JSONDecodeError
        raise _bad(f"invalid JSON: {e}") from None
    if jcs(obj) != data:
        raise _bad("not in canonical form")
    return obj
