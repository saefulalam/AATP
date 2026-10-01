"""M5 control messages (blueprint section 5.1/5.3, 8.1; MSG-001..006, GEN-006).

A message is the signed object inside a DSSE ``message+json`` envelope::

    {"v", "type", "id", "sender", "sender_key_id", "recipient",
     "created_at", "expires_at", "corr", "crit", "body"}

``build_message`` constructs the unsigned dict; callers sign it with
``dsse.make_envelope(PT_MESSAGE, jcs(msg), signer)`` and seal it with
``seal.seal_packet`` (sign, then seal per MSG-011). Registry types come from
section 8.1; CHUNK is a data-plane frame, not a message, and is handled in
``aatp.transfer`` (TRF-010).

Never log keys / CEKs / plaintext.
"""
import re
import uuid
from datetime import datetime, timedelta, timezone

from aatp.errors import err

# Blueprint section 8.1 message registry (CHUNK excluded: data plane, TRF-010).
MESSAGE_TYPES = frozenset({
    "OFFER", "ACCEPT", "REJECT", "STATUS", "COMPLETE", "RECEIPT",
    "HANDOFF_OFFER", "HANDOFF_RESPONSE", "TASK_UPDATE", "ERROR",
})

MESSAGE_LIFETIME_MAX_SECONDS = 86400
CLOCK_SKEW_SECONDS = 120

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_AGENT_RE = re.compile(r"^aatp:[a-z2-7]{52}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _malformed(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def parse_ts(s: str) -> datetime:
    """Parse a GEN-004 timestamp (exactly ``YYYY-MM-DDTHH:MM:SSZ``)."""
    if not isinstance(s, str) or not _TS_RE.match(s):
        raise _malformed("timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        raise _malformed("invalid timestamp") from None


def format_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shift_ts(ts: str, seconds: int) -> str:
    """Return the GEN-004 timestamp ``seconds`` after ``ts`` (may be negative)."""
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        raise _malformed("shift seconds must be an integer")
    return format_ts(parse_ts(ts) + timedelta(seconds=seconds))


def check_id(v: object, what: str) -> str:
    """GEN-006: opaque id, <=128 chars of ``[A-Za-z0-9_.:-]``."""
    if not isinstance(v, str) or not _ID_RE.match(v):
        raise _malformed(f"{what} must match [A-Za-z0-9_.:-]{{1,128}}")
    return v


def _check_agent(v: object, what: str) -> str:
    if not isinstance(v, str) or not _AGENT_RE.match(v):
        raise _malformed(f"{what} must be an agent_id")
    return v


def _check_corr(corr: object) -> dict:
    if not isinstance(corr, dict):
        raise _malformed("corr must be an object")
    for f in ("transfer_id", "task_id", "in_reply_to"):
        if f in corr and corr[f] is not None:
            check_id(corr[f], f"corr.{f}")
    return corr


def build_message(msg_type: str, sender: str, sender_key_id: str,
                  recipient: str, body: dict, *, now: str,
                  lifetime: int = 3600, msg_id: str | None = None,
                  corr: dict | None = None, crit: list | None = None) -> dict:
    """Build an unsigned control message (MSG-001 fields, GEN-004/006).

    Raises ``ERR_UNSUPPORTED_MESSAGE`` for unknown types (MSG-006) and
    ``ERR_MALFORMED_MESSAGE`` for bad ids (GEN-006), bad timestamps, or a
    lifetime outside ``[0, message_lifetime_max_seconds]``.
    """
    if msg_type not in MESSAGE_TYPES:
        raise err("ERR_UNSUPPORTED_MESSAGE", f"unknown message type {msg_type!r}")
    _check_agent(sender, "sender")
    _check_agent(recipient, "recipient")
    if not isinstance(sender_key_id, str) or not sender_key_id:
        raise _malformed("sender_key_id must be a non-empty string")
    if not isinstance(body, dict):
        raise _malformed("body must be an object")
    if msg_id is None:
        msg_id = "msg_" + str(uuid.uuid4())
    check_id(msg_id, "id")
    corr = _check_corr({} if corr is None else corr)
    if crit is None:
        crit = []
    if (not isinstance(crit, list)
            or any(not isinstance(c, str) for c in crit)):
        raise _malformed("crit must be a list of strings")
    if (not isinstance(lifetime, int) or isinstance(lifetime, bool)
            or lifetime < 0 or lifetime > MESSAGE_LIFETIME_MAX_SECONDS):
        raise _malformed("lifetime must be within [0, 86400]")
    created = parse_ts(now)
    expires = created + timedelta(seconds=lifetime)
    return {"v": "0.2", "type": msg_type, "id": msg_id, "sender": sender,
            "sender_key_id": sender_key_id, "recipient": recipient,
            "created_at": format_ts(created), "expires_at": format_ts(expires),
            "corr": corr, "crit": list(crit), "body": body}


def check_shape(msg: object) -> dict:
    """Structural check of a decoded message (no type-registry check).

    Unknown *optional* fields are ignored (GEN-012); a non-empty ``crit``
    is rejected since M5 defines no extensions (``ERR_UNSUPPORTED_EXTENSION``).
    """
    if not isinstance(msg, dict):
        raise _malformed("message must be an object")
    if msg.get("v") != "0.2":
        raise err("ERR_PROTOCOL_VERSION", "message v must be 0.2")
    if not isinstance(msg.get("type"), str):
        raise _malformed("message type must be a string")
    check_id(msg.get("id"), "id")
    _check_agent(msg.get("sender"), "sender")
    if (not isinstance(msg.get("sender_key_id"), str)
            or not msg["sender_key_id"]):
        raise _malformed("sender_key_id must be a non-empty string")
    _check_agent(msg.get("recipient"), "recipient")
    parse_ts(msg.get("created_at"))
    parse_ts(msg.get("expires_at"))
    _check_corr(msg.get("corr", {}))
    crit = msg.get("crit", [])
    if (not isinstance(crit, list)
            or any(not isinstance(c, str) for c in crit)):
        raise _malformed("crit must be a list of strings")
    if crit:
        # GEN-012: no critical extensions are defined in M5 scope.
        raise err("ERR_UNSUPPORTED_EXTENSION",
                  f"unsupported critical extensions {crit!r}")
    if not isinstance(msg.get("body"), dict):
        raise _malformed("body must be an object")
    return msg


def validate_message(msg: object) -> dict:
    """Full structural validation including the type registry (MSG-006)."""
    check_shape(msg)
    assert isinstance(msg, dict)
    if msg["type"] not in MESSAGE_TYPES:
        raise err("ERR_UNSUPPORTED_MESSAGE",
                  f"unknown message type {msg['type']!r}")
    return msg


def check_time_window(msg: dict, now: str, *,
                      skew_seconds: int = CLOCK_SKEW_SECONDS,
                      max_lifetime: int = MESSAGE_LIFETIME_MAX_SECONDS) -> None:
    """MSG-003: lifetime bound plus created/expires window around ``now``."""
    created = parse_ts(msg["created_at"])
    expires = parse_ts(msg["expires_at"])
    if expires < created:
        raise err("ERR_MESSAGE_EXPIRED", "expires_at before created_at")
    if (expires - created).total_seconds() > max_lifetime:
        raise err("ERR_MESSAGE_EXPIRED", "message lifetime exceeds maximum")
    now_dt = parse_ts(now)
    skew = timedelta(seconds=skew_seconds)
    if now_dt < created - skew or now_dt > expires + skew:
        raise err("ERR_MESSAGE_EXPIRED", "message outside validity window")
