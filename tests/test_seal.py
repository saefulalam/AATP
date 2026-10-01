"""M4 seal.py: HPKE sealed packets + CEK wraps (MSG-010..013, ENC-020..023)."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aatp.canon import jcs
from aatp.dsse import PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import AATPError
from aatp.signer import SoftwareSigner

SEED = bytes([0x11]) * 32


def _gen_recipient():
    # CRY-006: X25519PrivateKey.generate() draws from the OS CSPRNG (OpenSSL).
    sk = X25519PrivateKey.generate()
    sk_raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pk_raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk_raw, pk_raw


def _signer():
    return SoftwareSigner.from_seed(SEED, key_id="k1")


def _offer_envelope():
    s = _signer()
    body = {
        "type": "OFFER",
        "transfer_id": "tx_demo1",
        "content_root": "sha256:" + "0" * 64,
        "sender": "aatp:sender1",
        "recipient": "aatp:recv1",
    }
    return s, make_envelope(PT_MESSAGE, jcs(body), s)


def _keystore_for(enc_key_id, sk_raw):
    from aatp.seal import KeyStore
    return KeyStore({enc_key_id: sk_raw})


def test_MSG010_offer_sealed_roundtrip():
    from aatp.seal import open_packet, seal_packet
    s, env = _offer_envelope()
    sk_raw, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = _keystore_for("e5", sk_raw)
    out = open_packet(pkt, ks)
    assert out == env
    assert verify_envelope(out, PT_MESSAGE, s.public_key_raw())["type"] == "OFFER"


def test_MSG011_sign_then_seal_order():
    from aatp.seal import open_packet, seal_packet
    s, env = _offer_envelope()
    sk_raw, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = _keystore_for("e5", sk_raw)
    opened = open_packet(pkt, ks)
    assert verify_envelope(opened, PT_MESSAGE, s.public_key_raw()) is not None


def test_MSG012_relay_view_only():
    from aatp.seal import seal_packet
    _, env = _offer_envelope()
    _, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    assert set(pkt.keys()) == {"aatp", "to", "to_key_id", "enc", "ct"}
    assert pkt["aatp"] == "0.2"
    assert pkt["to"] == "aatp:recv1"
    assert pkt["to_key_id"] == "e5"


def test_MSG013_oversize_rejected():
    from aatp.seal import seal_packet
    s = _signer()
    big = {"type": "OFFER", "pad": "A" * 262145}
    env = make_envelope(PT_MESSAGE, jcs(big), s)
    _, pk_raw = _gen_recipient()
    with pytest.raises(AATPError) as ei:
        seal_packet("aatp:recv1", "e5", pk_raw, env)
    assert ei.value.code == "ERR_SIZE_LIMIT"


def test_MSG013_boundary_accepted():
    from aatp.seal import open_packet, seal_packet
    s = _signer()
    # Envelope JCS = outer JSON + b64(inner JCS); b64 expands ~4/3.
    # Target just under max_message_bytes=262144.
    from aatp.canon import jcs as _jcs
    pad_len = (262144 - 500) * 3 // 4
    env = make_envelope(PT_MESSAGE, _jcs({"pad": "A" * pad_len}), s)
    assert len(_jcs(env)) <= 262144
    sk_raw, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = _keystore_for("e5", sk_raw)
    assert open_packet(pkt, ks) == env


def test_ENC020_one_wrap_per_recipient_same_cek():
    from aatp.seal import unwrap_cek, wrap_cek
    import secrets
    cek = secrets.token_bytes(32)
    cr = "sha256:" + "0" * 64
    sk1, pk1 = _gen_recipient()
    sk2, pk2 = _gen_recipient()
    w1 = wrap_cek(cek, cr, "aatp:sender", "aatp:r1", "e1", "tx1", pk1)
    w2 = wrap_cek(cek, cr, "aatp:sender", "aatp:r2", "e9", "tx1", pk2)
    assert set(w1.keys()) == {"agent_id", "enc_key_id", "enc", "ct"}
    assert w1["agent_id"] == "aatp:r1" and w2["agent_id"] == "aatp:r2"
    assert w1["enc"] != w2["enc"] or w1["ct"] != w2["ct"]
    from aatp.seal import KeyStore
    ks1 = KeyStore({"e1": sk1})
    ks2 = KeyStore({"e9": sk2})
    assert unwrap_cek(w1, cr, "aatp:sender", "tx1", ks1) == cek
    assert unwrap_cek(w2, cr, "aatp:sender", "tx1", ks2) == cek


def test_ENC021_wrap_info_binds_fields():
    from aatp.seal import unwrap_cek, wrap_cek
    import secrets
    cek = secrets.token_bytes(32)
    cr = "sha256:" + "0" * 64
    sk_raw, pk_raw = _gen_recipient()
    w = wrap_cek(cek, cr, "aatp:sender", "aatp:recv1", "e5", "tx_demo1", pk_raw)
    from aatp.seal import KeyStore
    ks = KeyStore({"e5": sk_raw})
    with pytest.raises(AATPError) as ei:
        unwrap_cek(w, cr, "aatp:sender", "tx_other", ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"
    with pytest.raises(AATPError) as ei:
        unwrap_cek(w, "sha256:" + "1" * 64, "aatp:sender", "tx_demo1", ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"
    with pytest.raises(AATPError) as ei:
        unwrap_cek(w, cr, "aatp:other", "tx_demo1", ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"


def test_open_packet_uses_packet_fields_for_info():
    from aatp.seal import open_packet, seal_packet
    _, env = _offer_envelope()
    sk_raw, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = _keystore_for("e5", sk_raw)
    # Retargeting the packet to another recipient must fail: info is rebuilt
    # from packet["to"]/packet["to_key_id"], never the inner message.
    pkt2 = dict(pkt)
    pkt2["to"] = "aatp:other"
    with pytest.raises(AATPError) as ei:
        open_packet(pkt2, ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"


def test_packet_tampered_ct_rejected():
    from aatp.seal import open_packet, seal_packet
    from aatp.b64 import b64u, b64u_dec
    _, env = _offer_envelope()
    sk_raw, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = _keystore_for("e5", sk_raw)
    raw = bytearray(b64u_dec(pkt["ct"]))
    raw[0] ^= 1
    pkt["ct"] = b64u(bytes(raw))
    with pytest.raises(AATPError) as ei:
        open_packet(pkt, ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"


def test_packet_tampered_enc_rejected():
    from aatp.seal import open_packet, seal_packet
    from aatp.b64 import b64u, b64u_dec
    _, env = _offer_envelope()
    sk_raw, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = _keystore_for("e5", sk_raw)
    raw = bytearray(b64u_dec(pkt["enc"]))
    raw[0] ^= 1
    pkt["enc"] = b64u(bytes(raw))
    with pytest.raises(AATPError) as ei:
        open_packet(pkt, ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"


def test_packet_unknown_key_id_fail_closed():
    from aatp.seal import KeyStore, open_packet, seal_packet
    _, env = _offer_envelope()
    _, pk_raw = _gen_recipient()
    pkt = seal_packet("aatp:recv1", "e5", pk_raw, env)
    ks = KeyStore({})
    with pytest.raises(AATPError) as ei:
        open_packet(pkt, ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"


def test_packet_strict_shape_rejected():
    from aatp.seal import open_packet
    from aatp.seal import KeyStore
    ks = KeyStore({})
    bad_packets = [
        {},
        {"aatp": "0.1", "to": "a", "to_key_id": "e", "enc": "", "ct": ""},
        {"aatp": "0.2", "to": 123, "to_key_id": "e", "enc": "", "ct": ""},
        {"aatp": "0.2", "to": "a", "to_key_id": "e", "enc": "!!!", "ct": ""},
        {"aatp": "0.2", "to": "a", "to_key_id": "e", "enc": "", "ct": "==="},
        {"aatp": "0.2", "to": "a", "to_key_id": "e", "enc": ""},
    ]
    for p in bad_packets:
        with pytest.raises(AATPError) as ei:
            open_packet(p, ks)
        assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_wrap_tampered_ct_rejected():
    from aatp.seal import unwrap_cek, wrap_cek
    from aatp.b64 import b64u, b64u_dec
    import secrets
    cek = secrets.token_bytes(32)
    cr = "sha256:" + "0" * 64
    sk_raw, pk_raw = _gen_recipient()
    w = wrap_cek(cek, cr, "aatp:s", "aatp:r", "e5", "tx1", pk_raw)
    from aatp.seal import KeyStore
    ks = KeyStore({"e5": sk_raw})
    raw = bytearray(b64u_dec(w["ct"]))
    raw[0] ^= 1
    w["ct"] = b64u(bytes(raw))
    with pytest.raises(AATPError) as ei:
        unwrap_cek(w, cr, "aatp:s", "tx1", ks)
    assert ei.value.code == "ERR_DECRYPT_FAILED"


def test_wrap_strict_shape_rejected():
    from aatp.seal import unwrap_cek
    from aatp.seal import KeyStore
    ks = KeyStore({})
    with pytest.raises(AATPError) as ei:
        unwrap_cek({}, "cr", "s", "t", ks)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
    with pytest.raises(AATPError) as ei:
        unwrap_cek({"agent_id": "a", "enc_key_id": "e", "enc": "!!!", "ct": ""}, "cr", "s", "t", ks)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
