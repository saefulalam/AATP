"""M1 agent cards: rotation, revocation, verify_card (blueprint §4, ID-001..024)."""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_CARD, PT_ROTATION, make_envelope, verify_envelope
from aatp.errors import AATPError, err
from aatp.ids import derive_agent_id

CLOCK_SKEW_SECONDS = 120
CARD_VALIDITY_MAX_SECONDS = 30 * 86400
ENC_WINDOW_MAX_SECONDS = 7 * 86400

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_AGENT_RE = re.compile(r"^aatp:[a-z2-7]{52}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _malformed(detail: str) -> AATPError:
    return err("ERR_MALFORMED_MESSAGE", detail)


def _parse_ts(s: str) -> datetime:
    if not isinstance(s, str) or not _TS_RE.match(s):
        raise _malformed("timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise _malformed("invalid timestamp") from None


def _pub_raw(s: str, what: str) -> bytes:
    try:
        raw = b64u_dec(s)
    except AATPError:
        raise _malformed(f"{what} not valid base64url") from None
    if len(raw) != 32:
        raise _malformed(f"{what} must decode to 32 bytes")
    return raw


def _commitment(pub_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub_raw).hexdigest()


def _key_record(d: object, what: str) -> tuple[str, bytes, datetime, datetime]:
    if not isinstance(d, dict):
        raise _malformed(f"{what} must be an object")
    kid, pk, nb, na = d.get("key_id"), d.get("public_key"), d.get("not_before"), d.get("not_after")
    if not isinstance(kid, str) or not isinstance(pk, str):
        raise _malformed(f"{what} needs string key_id and public_key")
    raw = _pub_raw(pk, f"{what}.public_key")
    return kid, raw, _parse_ts(nb), _parse_ts(na)


class CardCache:
    """Durable highest verified card seq per agent_id (ID-011), JSON file."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._seqs = self._load()

    def _load(self) -> dict[str, int]:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return {}
        except OSError:
            raise err("ERR_INTERNAL", "card cache unreadable") from None
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise err("ERR_INTERNAL", "card cache corrupt") from None
        if not isinstance(obj, dict):
            raise err("ERR_INTERNAL", "card cache corrupt")
        for k, v in obj.items():
            if not isinstance(k, str) or not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise err("ERR_INTERNAL", "card cache corrupt")
        return dict(obj)

    def highest_seq(self, agent_id: str) -> int:
        return self._seqs.get(agent_id, 0)

    def record(self, agent_id: str, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise _malformed("card seq must be an integer >= 0")
        self._seqs[agent_id] = seq
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_bytes(json.dumps(self._seqs, sort_keys=True).encode("utf-8"))
        except OSError:
            raise err("ERR_INTERNAL", "card cache unwritable") from None


def make_rotation_statement(*, signer, agent_id: str, from_key_id: str,
                            to_key_id: str, to_public_key_raw32: bytes,
                            effective_at: str,
                            next_commitment: str | None = None) -> dict:
    if not isinstance(agent_id, str) or not _AGENT_RE.match(agent_id):
        raise _malformed("agent_id malformed")
    if not isinstance(from_key_id, str) or not isinstance(to_key_id, str):
        raise _malformed("rotation key ids must be strings")
    if not isinstance(to_public_key_raw32, bytes) or len(to_public_key_raw32) != 32:
        raise _malformed("to public key must be 32 bytes")
    _parse_ts(effective_at)
    if next_commitment is not None and (
            not isinstance(next_commitment, str) or not _DIGEST_RE.match(next_commitment)):
        raise _malformed("next_commitment must be sha256:<64 hex>")
    payload = {"v": "0.2", "type": "rotate", "agent_id": agent_id,
               "from_key_id": from_key_id, "to_key_id": to_key_id,
               "to_public_key": b64u(to_public_key_raw32), "effective_at": effective_at}
    if next_commitment is not None:
        payload["next_commitment"] = next_commitment
    return make_envelope(PT_ROTATION, jcs(payload), signer)


def make_revocation(*, signer, agent_id: str, key_id: str,
                    effective_at: str, reason: str,
                    public_key_raw32: bytes | None = None) -> dict:
    if not isinstance(agent_id, str) or not _AGENT_RE.match(agent_id):
        raise _malformed("agent_id malformed")
    if not isinstance(key_id, str) or not isinstance(reason, str):
        raise _malformed("revocation needs string key_id and reason")
    _parse_ts(effective_at)
    payload = {"v": "0.2", "type": "revoke", "agent_id": agent_id,
               "key_id": key_id, "effective_at": effective_at, "reason": reason}
    if public_key_raw32 is not None:
        if not isinstance(public_key_raw32, bytes) or len(public_key_raw32) != 32:
            raise _malformed("revocation public key must be 32 bytes")
        payload["public_key"] = b64u(public_key_raw32)
    return make_envelope(PT_ROTATION, jcs(payload), signer)


def _decode_payload(env: object, what: str) -> dict:
    if not isinstance(env, dict) or not isinstance(env.get("payload"), str):
        raise _malformed(f"{what} envelope must carry a string payload")
    try:
        raw = b64u_dec(env["payload"])
    except AATPError:
        raise _malformed(f"{what} payload not valid base64url") from None
    obj = parse_jcs(raw)
    if not isinstance(obj, dict):
        raise _malformed(f"{what} payload must be a JSON object")
    return obj


def _check_card_shape(card: dict) -> None:
    for f in ("v", "agent_id", "genesis_public_key", "signing_key", "enc_key",
              "key_history", "suites", "seq", "issued_at", "expires_at"):
        if f not in card:
            raise _malformed(f"card missing {f}")
    if card["v"] != "0.2":
        raise err("ERR_PROTOCOL_VERSION", "card v must be 0.2")
    if not isinstance(card["agent_id"], str) or not _AGENT_RE.match(card["agent_id"]):
        raise _malformed("card agent_id malformed")
    if not isinstance(card["genesis_public_key"], str):
        raise _malformed("genesis_public_key must be a string")
    _pub_raw(card["genesis_public_key"], "genesis_public_key")
    _key_record(card["signing_key"], "signing_key")
    _key_record(card["enc_key"], "enc_key")
    if not isinstance(card["key_history"], list):
        raise _malformed("key_history must be a list")
    for e in card["key_history"]:
        if not isinstance(e, dict):
            raise _malformed("key_history entry must be a DSSE envelope")
    suites = card["suites"]
    if not isinstance(suites, list):
        raise _malformed("suites must be a list")
    if "AATP-S1" not in suites:
        raise err("ERR_SUITE_UNSUPPORTED", "card suites lack AATP-S1")
    if not isinstance(card["seq"], int) or isinstance(card["seq"], bool) or card["seq"] < 0:
        raise _malformed("card seq must be an integer >= 0")
    _parse_ts(card["issued_at"])
    _parse_ts(card["expires_at"])
    if "next_commitment" in card and card["next_commitment"] is not None:
        if not isinstance(card["next_commitment"], str) or not _DIGEST_RE.match(card["next_commitment"]):
            raise _malformed("card next_commitment malformed")
    if "revoked" in card and card["revoked"] is not None:
        if not isinstance(card["revoked"], list):
            raise _malformed("revoked must be a list")
        for e in card["revoked"]:
            if not isinstance(e, dict):
                raise _malformed("revoked entry must be a DSSE envelope")
    for f in ("endpoints", "capabilities"):
        if f in card and card[f] is not None:
            if not isinstance(card[f], list) or not all(isinstance(x, str) for x in card[f]):
                raise _malformed(f"card {f} must be a list of strings")
    if "capabilities" in card and isinstance(card.get("capabilities"), list):
        for c in card["capabilities"]:
            if not c.startswith("aatp."):
                raise _malformed("capability must start with aatp.")


def _check_revocation_shape(rev: dict, agent_id: str) -> tuple[str, datetime]:
    if rev.get("v") != "0.2":
        raise err("ERR_PROTOCOL_VERSION", "revocation v must be 0.2")
    if rev.get("type") != "revoke":
        raise _malformed("revocation type must be revoke")
    if rev.get("agent_id") != agent_id:
        raise err("ERR_AUTH_FAILED", "revocation agent mismatch")
    if not isinstance(rev.get("key_id"), str):
        raise _malformed("revocation needs string key_id")
    if not isinstance(rev.get("reason"), str):
        raise _malformed("revocation needs string reason")
    return rev["key_id"], _parse_ts(rev.get("effective_at"))


def _resolve_active_commitment(card: dict, chain_commitment: str | None) -> str | None:
    card_nc = card.get("next_commitment")
    if card_nc is not None:
        if not isinstance(card_nc, str) or not _DIGEST_RE.match(card_nc):
            raise _malformed("card next_commitment malformed")
    if card_nc is not None and chain_commitment is not None and card_nc != chain_commitment:
        raise err("ERR_KEY_COMMITMENT_MISMATCH", "card next_commitment diverges from history")
    return card_nc if card_nc is not None else chain_commitment


def _chain_commitment(card: dict) -> str | None:
    hist = card.get("key_history")
    if not isinstance(hist, list):
        raise _malformed("key_history must be a list")
    if not hist:
        return None
    last = hist[-1]
    if not isinstance(last, dict):
        raise _malformed("key_history entry must be a DSSE envelope")
    payload = _decode_payload(last, "rotation")
    nc = payload.get("next_commitment")
    if nc is not None:
        if not isinstance(nc, str) or not _DIGEST_RE.match(nc):
            raise _malformed("rotation next_commitment malformed")
    return nc


def verify_card(card_env: dict, pinned_agent_id: str | None, cache: CardCache,
                now: str, clock_skew_seconds: int = CLOCK_SKEW_SECONDS) -> dict:
    if not isinstance(card_env, dict):
        raise _malformed("card envelope must be an object")
    if card_env.get("payloadType") != PT_CARD:
        raise _malformed("payloadType mismatch")
    card = _decode_payload(card_env, "card")
    _check_card_shape(card)

    if pinned_agent_id is None or card["agent_id"] != pinned_agent_id:
        raise err("ERR_AUTH_FAILED", "agent not admitted by pinned trust")

    genesis_raw = _pub_raw(card["genesis_public_key"], "genesis_public_key")
    if derive_agent_id(genesis_raw) != card["agent_id"]:
        raise err("ERR_AUTH_FAILED", "agent_id not derived from genesis key")

    skew = timedelta(seconds=clock_skew_seconds)
    history = card["key_history"]
    if history:
        first = _decode_payload(history[0], "rotation") if isinstance(history[0], dict) else None
        cur_id = first["from_key_id"] if isinstance(first, dict) and isinstance(
            first.get("from_key_id"), str) else card["signing_key"]["key_id"]
    else:
        cur_id = card["signing_key"]["key_id"]
    cur_pub = genesis_raw
    commitment = None
    for stmt_env in history:
        stmt = verify_envelope(stmt_env, PT_ROTATION, cur_pub, key_id=cur_id)
        if not isinstance(stmt, dict):
            raise _malformed("rotation payload must be a JSON object")
        if stmt.get("v") != "0.2":
            raise err("ERR_PROTOCOL_VERSION", "rotation v must be 0.2")
        if stmt.get("type") != "rotate":
            raise _malformed("rotation type must be rotate")
        if stmt.get("agent_id") != card["agent_id"]:
            raise err("ERR_AUTH_FAILED", "rotation agent mismatch")
        if stmt.get("from_key_id") != cur_id:
            raise err("ERR_SIGNATURE_INVALID", "rotation from_key_id break")
        if not isinstance(stmt.get("to_key_id"), str):
            raise _malformed("rotation needs string to_key_id")
        if not isinstance(stmt.get("to_public_key"), str):
            raise _malformed("rotation needs string to_public_key")
        to_pub = _pub_raw(stmt["to_public_key"], "rotation.to_public_key")
        _parse_ts(stmt.get("effective_at"))
        if "next_commitment" in stmt and stmt["next_commitment"] is not None:
            if not isinstance(stmt["next_commitment"], str) or not _DIGEST_RE.match(
                    stmt["next_commitment"]):
                raise _malformed("rotation next_commitment malformed")
        if commitment is not None and _commitment(to_pub) != commitment:
            raise err("ERR_KEY_COMMITMENT_MISMATCH", "rotation violates commitment")
        cur_id, cur_pub = stmt["to_key_id"], to_pub
        commitment = stmt.get("next_commitment")

    sign_id, sign_pub, sign_nb, sign_na = _key_record(card["signing_key"], "signing_key")
    if cur_id != sign_id or cur_pub != sign_pub:
        raise err("ERR_SIGNATURE_INVALID", "history does not end at signing_key")

    verified = verify_envelope(card_env, PT_CARD, sign_pub, key_id=sign_id)
    if not isinstance(verified, dict):
        raise _malformed("card payload must be a JSON object")
    card = verified

    now_dt = _parse_ts(now)
    issued, expires = _parse_ts(card["issued_at"]), _parse_ts(card["expires_at"])
    if expires < issued:
        raise _malformed("card expires_at before issued_at")
    if (expires - issued).total_seconds() > CARD_VALIDITY_MAX_SECONDS:
        raise err("ERR_MESSAGE_EXPIRED", "card validity exceeds 30 days")
    if not (issued - skew <= now_dt <= expires + skew):
        raise err("ERR_MESSAGE_EXPIRED", "card outside validity window")
    if sign_na < sign_nb:
        raise _malformed("signing_key window inverted")
    if not (sign_nb - skew <= now_dt <= sign_na + skew):
        raise err("ERR_KEY_EXPIRED", "signing key outside validity window")
    _, enc_pub, enc_nb, enc_na = _key_record(card["enc_key"], "enc_key")
    if enc_na < enc_nb:
        raise _malformed("enc_key window inverted")
    if (enc_na - enc_nb).total_seconds() > ENC_WINDOW_MAX_SECONDS:
        raise err("ERR_KEY_EXPIRED", "enc_key window exceeds 7 days")
    if not (enc_nb - skew <= now_dt <= enc_na + skew):
        raise err("ERR_KEY_EXPIRED", "enc_key outside validity window")
    _ = enc_pub

    seq = card["seq"]
    if seq < cache.highest_seq(card["agent_id"]):
        raise err("ERR_CARD_ROLLBACK", "card seq below cached highest")

    active_commitment = _resolve_active_commitment(card, commitment)
    revoked: list[tuple[str, datetime]] = []
    for rev_env in card.get("revoked") or []:
        rev = None
        try:
            rev = verify_envelope(rev_env, PT_ROTATION, sign_pub, key_id=sign_id)
        except AATPError as e:
            if e.code != "ERR_SIGNATURE_INVALID":
                raise
            if active_commitment is None:
                raise
            cand = _decode_payload(rev_env, "revocation")
            if not isinstance(cand.get("public_key"), str):
                raise err("ERR_SIGNATURE_INVALID", "no usable revocation signature") from None
            cand_pub = _pub_raw(cand["public_key"], "revocation.public_key")
            if _commitment(cand_pub) != active_commitment:
                raise err("ERR_SIGNATURE_INVALID", "revocation key not committed") from None
            rev = verify_envelope(rev_env, PT_ROTATION, cand_pub)
        if not isinstance(rev, dict):
            raise _malformed("revocation payload must be a JSON object")
        rid, reff = _check_revocation_shape(rev, card["agent_id"])
        revoked.append((rid, reff))

    for rid, reff in revoked:
        if rid == sign_id and reff <= now_dt:
            raise err("ERR_KEY_REVOKED", "current signing key revoked")

    cache.record(card["agent_id"], seq)
    return card


def check_key_not_revoked(card: dict, key_id: str, created_at: str) -> None:
    if not isinstance(card, dict):
        raise _malformed("card must be an object")
    agent_id = card.get("agent_id")
    if not isinstance(agent_id, str) or not _AGENT_RE.match(agent_id):
        raise _malformed("card agent_id malformed")
    sign_id, sign_pub, _, _ = _key_record(card.get("signing_key"), "signing_key")
    if not isinstance(key_id, str):
        raise _malformed("key_id must be a string")
    created = _parse_ts(created_at)
    chain_nc = _chain_commitment(card)
    active = _resolve_active_commitment(card, chain_nc)
    revoked_envs = card.get("revoked") or []
    if not isinstance(revoked_envs, list):
        raise _malformed("revoked must be a list")
    for rev_env in revoked_envs:
        if not isinstance(rev_env, dict):
            raise _malformed("revoked entry must be a DSSE envelope")
        rev = None
        try:
            rev = verify_envelope(rev_env, PT_ROTATION, sign_pub, key_id=sign_id)
        except AATPError as e:
            if e.code != "ERR_SIGNATURE_INVALID":
                raise
            if active is None:
                raise
            cand = _decode_payload(rev_env, "revocation")
            if not isinstance(cand.get("public_key"), str):
                raise err("ERR_SIGNATURE_INVALID", "no usable revocation signature") from None
            cand_pub = _pub_raw(cand["public_key"], "revocation.public_key")
            if _commitment(cand_pub) != active:
                raise err("ERR_SIGNATURE_INVALID", "revocation key not committed") from None
            rev = verify_envelope(rev_env, PT_ROTATION, cand_pub)
        if not isinstance(rev, dict):
            raise _malformed("revocation payload must be a JSON object")
        rid, reff = _check_revocation_shape(rev, agent_id)
        if rid == key_id and reff <= created:
            raise err("ERR_KEY_REVOKED", "key revoked before message creation")
