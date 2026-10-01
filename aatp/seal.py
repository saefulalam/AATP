"""M4 HPKE sealed packets + CEK wraps (blueprint 5.2, 9.2; MSG-010..013, ENC-020..023).

Suite: HPKE Base mode, KEM 0x0020 (DHKEM X25519 HKDF-SHA256) /
KDF 0x0001 (HKDF-SHA256) / AEAD 0x0003 (ChaCha20Poly1305) via pyhpke 0.6.5.
pyhpke 0.6.5 single-shot CipherSuite.seal/open raise NotImplementedError, so
this module uses create_sender_context / create_recipient_context +
ctx.seal(pt, aad) / ctx.open(ct, aad) with aad == b"" throughout.

ENC-023 group caveat: all recipients share the same CEK, so any recipient
could forge chunks for another; authenticity still holds per recipient via
the sender-signed node / content_root check (ART-022, enforced in Task 8).

Never log keys / CEKs / plaintext.
"""
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.errors import AATPError, err

D_PACKET = b"AATP/0.2/PACKET\n"
D_CEKWRAP = b"AATP/0.2/CEK-WRAP\n"

MAX_MESSAGE_BYTES = 262144

# Single suite for all seal/wrap operations (KEM 0x0020 / KDF 0x0001 / AEAD 0x0003).
_SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)


def _malformed(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def _decrypt_failed(detail: str):
    return err("ERR_DECRYPT_FAILED", detail)


def _check_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise _malformed(f"{name} must be str")
    return v


class KeyStore:
    """Minimal in-memory recipient X25519 key store (Task 7).

    Holds raw 32-byte private keys by enc_key_id. Full OS/file-backed
    keystore with rotation/validity windows is M7+ scope.
    """

    def __init__(self, keys: dict | None = None):
        self._keys: dict[str, bytes] = {}
        for k, v in (keys or {}).items():
            self.add(k, v)

    def add(self, enc_key_id: str, priv_raw: bytes) -> None:
        if not isinstance(enc_key_id, str):
            raise _malformed("enc_key_id must be str")
        if not isinstance(priv_raw, (bytes, bytearray)) or len(priv_raw) != 32:
            raise _malformed("private key must be 32 bytes")
        self._keys[enc_key_id] = bytes(priv_raw)

    def open(self, enc_key_id, enc: bytes, ct: bytes, info: bytes) -> bytes:
        """HPKE open inside the store. ANY failure -> ERR_DECRYPT_FAILED (fail closed)."""
        try:
            if not isinstance(enc_key_id, str):
                raise _decrypt_failed("unknown key")
            sk_raw = self._keys.get(enc_key_id)
            if sk_raw is None:
                raise _decrypt_failed("unknown key id")
            if not isinstance(enc, (bytes, bytearray)) or not isinstance(ct, (bytes, bytearray)):
                raise _decrypt_failed("bad enc/ct")
            if not isinstance(info, (bytes, bytearray)):
                raise _decrypt_failed("bad info")
            skr = _SUITE.kem.deserialize_private_key(bytes(sk_raw))
            ctx = _SUITE.create_recipient_context(bytes(enc), skr, bytes(info))
            return ctx.open(bytes(ct), b"")
        except AATPError as e:
            if e.code == "ERR_DECRYPT_FAILED":
                raise
            raise _decrypt_failed("open failed") from None
        except Exception:
            # pyhpke raises pyhpke.exceptions.OpenError on auth failure
            # (tampered ct/enc, wrong info); map everything fail-closed.
            raise _decrypt_failed("open failed") from None


def _seal(pk_raw: bytes, info: bytes, pt: bytes) -> tuple[bytes, bytes]:
    if not isinstance(pk_raw, (bytes, bytearray)) or len(pk_raw) != 32:
        raise _malformed("recipient public key must be 32 bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise _malformed("info must be bytes")
    if not isinstance(pt, (bytes, bytearray)):
        raise _malformed("plaintext must be bytes")
    try:
        pkr = _SUITE.kem.deserialize_public_key(bytes(pk_raw))
    except Exception:
        raise _malformed("invalid recipient public key") from None
    try:
        enc, ctx = _SUITE.create_sender_context(pkr, bytes(info))
        ct = ctx.seal(bytes(pt), b"")
        return enc, ct
    except Exception as e:
        raise err("ERR_INTERNAL", "hpke seal failed") from e


def packet_info(to: str, to_key_id: str) -> bytes:
    return D_PACKET + to.encode("utf-8") + b"\n" + to_key_id.encode("utf-8")


def wrap_info(content_root: str, sender: str, recipient: str, transfer_id: str, enc_key_id: str) -> bytes:
    return D_CEKWRAP + jcs({"cr": content_root, "s": sender, "r": recipient, "t": transfer_id, "k": enc_key_id})


def seal_packet(recipient_agent_id: str, to_key_id: str, recipient_enc_pub_raw: bytes, envelope: dict) -> dict:
    _check_str(recipient_agent_id, "to")
    _check_str(to_key_id, "to_key_id")
    if not isinstance(envelope, dict):
        raise _malformed("envelope must be an object")
    pt = jcs(envelope)
    if len(pt) > MAX_MESSAGE_BYTES:
        raise err("ERR_SIZE_LIMIT", "plaintext envelope exceeds max_message_bytes")
    info = packet_info(recipient_agent_id, to_key_id)
    enc, ct = _seal(recipient_enc_pub_raw, info, pt)
    return {"aatp": "0.2", "to": recipient_agent_id, "to_key_id": to_key_id, "enc": b64u(enc), "ct": b64u(ct)}


def open_packet(packet: dict, keystore: KeyStore) -> dict:
    if not isinstance(packet, dict):
        raise _malformed("packet must be an object")
    if packet.get("aatp") != "0.2":
        raise _malformed("unsupported packet version")
    to = packet.get("to")
    kid = packet.get("to_key_id")
    enc_s = packet.get("enc")
    ct_s = packet.get("ct")
    _check_str(to, "to")
    _check_str(kid, "to_key_id")
    if not isinstance(enc_s, str) or not isinstance(ct_s, str):
        raise _malformed("enc/ct must be strings")
    enc = b64u_dec(enc_s)
    ct = b64u_dec(ct_s)
    # Rebuild info from PACKET fields, never the inner message (MSG-011/012).
    info = packet_info(to, kid)
    pt = keystore.open(kid, enc, ct, info)
    obj = parse_jcs(pt)
    if not isinstance(obj, dict):
        raise _malformed("packet plaintext must be an object")
    return obj


def wrap_cek(cek: bytes, content_root: str, sender_agent_id: str, recipient_agent_id: str,
             enc_key_id: str, transfer_id: str, recipient_enc_pub_raw: bytes) -> dict:
    if not isinstance(cek, (bytes, bytearray)) or len(cek) != 32:
        raise _malformed("CEK must be 32 bytes")
    _check_str(content_root, "content_root")
    _check_str(sender_agent_id, "sender")
    _check_str(recipient_agent_id, "recipient")
    _check_str(enc_key_id, "enc_key_id")
    _check_str(transfer_id, "transfer_id")
    info = wrap_info(content_root, sender_agent_id, recipient_agent_id, transfer_id, enc_key_id)
    enc, ct = _seal(recipient_enc_pub_raw, info, bytes(cek))
    return {"agent_id": recipient_agent_id, "enc_key_id": enc_key_id, "enc": b64u(enc), "ct": b64u(ct)}


def unwrap_cek(entry: dict, content_root: str, sender_agent_id: str, transfer_id: str, keystore: KeyStore) -> bytes:
    if not isinstance(entry, dict):
        raise _malformed("wrap entry must be an object")
    rid = entry.get("agent_id")
    kid = entry.get("enc_key_id")
    enc_s = entry.get("enc")
    ct_s = entry.get("ct")
    _check_str(rid, "agent_id")
    _check_str(kid, "enc_key_id")
    if not isinstance(enc_s, str) or not isinstance(ct_s, str):
        raise _malformed("enc/ct must be strings")
    _check_str(content_root, "content_root")
    _check_str(sender_agent_id, "sender")
    _check_str(transfer_id, "transfer_id")
    enc = b64u_dec(enc_s)
    ct = b64u_dec(ct_s)
    info = wrap_info(content_root, sender_agent_id, rid, transfer_id, kid)
    cek = keystore.open(kid, enc, ct, info)
    if len(cek) != 32:
        raise _decrypt_failed("bad CEK length")
    return cek
