"""DSSE v1 envelopes signed with Ed25519 (blueprint §3.4, SIG-002/003, CRY-002/003)."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aatp.b64 import b64u, b64u_dec
from aatp.canon import parse_jcs
from aatp.errors import err

PT_MESSAGE = "application/vnd.aatp.message+json"
PT_NODE = "application/vnd.aatp.node+json"
PT_CARD = "application/vnd.aatp.card+json"
PT_GRANT = "application/vnd.aatp.grant+json"
PT_ROTATION = "application/vnd.aatp.rotation+json"

ED25519_L = 2**252 + 27742317777372353535851937790883648493


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def make_envelope(payload_type: str, payload: bytes, signer) -> dict:
    sig = signer.sign(payload_type, payload)
    return {"payloadType": payload_type, "payload": b64u(payload),
            "signatures": [{"keyid": signer.key_id(), "sig": b64u(sig)}]}


def _malformed(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def _select_signature(sigs, key_id: str | None) -> dict:
    if not isinstance(sigs, list) or not sigs:
        raise _malformed("signatures must be a non-empty list")
    for s in sigs:
        if not (isinstance(s, dict) and isinstance(s.get("keyid"), str)
                and isinstance(s.get("sig"), str)):
            raise _malformed("signature entry needs string keyid and sig")
    if key_id is None:
        return sigs[0]
    for s in sigs:
        if s["keyid"] == key_id:
            return s
    raise err("ERR_SIGNATURE_INVALID", "no signature for key_id")


def verify_envelope(env, expected_payload_type: str, public_key_raw: bytes,
                    key_id: str | None = None) -> object:
    """Verify one signature (by key_id, else signatures[0]) and return the parsed payload."""
    if not isinstance(env, dict):
        raise _malformed("envelope must be an object")
    pt = env.get("payloadType")
    if not isinstance(pt, str) or not isinstance(env.get("payload"), str):
        raise _malformed("payloadType and payload must be strings")
    if pt != expected_payload_type:  # SIG-003: before touching the payload
        raise _malformed("payloadType mismatch")
    entry = _select_signature(env.get("signatures"), key_id)
    payload = b64u_dec(env["payload"])
    sig = b64u_dec(entry["sig"])
    obj = parse_jcs(payload)  # SIG-002: rejects unless jcs(obj) == payload
    if len(sig) != 64:
        raise err("ERR_SIGNATURE_INVALID", "signature must be 64 bytes")
    if not isinstance(public_key_raw, bytes) or len(public_key_raw) != 32:
        raise err("ERR_SIGNATURE_INVALID", "public key must be 32 bytes")
    if int.from_bytes(sig[32:], "little") >= ED25519_L:  # CRY-003, backend-independent
        raise err("ERR_SIGNATURE_INVALID", "non-canonical signature (S >= L)")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(sig, pae(pt, payload))
    except InvalidSignature:
        raise err("ERR_SIGNATURE_INVALID") from None
    return obj
