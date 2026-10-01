"""GEN-003: base64url without padding (RFC 4648 §5), strict decoding."""
import base64
import re

from aatp.errors import err

_B64U_RE = re.compile(r"[A-Za-z0-9_-]*")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    """Reject padding, non-alphabet chars, impossible lengths and non-zero trailing bits."""
    if not isinstance(s, str) or not _B64U_RE.fullmatch(s) or len(s) % 4 == 1:
        raise err("ERR_MALFORMED_MESSAGE", "invalid base64url")
    out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u(out) != s:
        raise err("ERR_MALFORMED_MESSAGE", "non-canonical base64url")
    return out
