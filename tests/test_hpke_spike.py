"""HPKE spike gate (Task 0): pyhpke 0.6.5 vs RFC 9180 A.2.1.

pyhpke 0.6.5's single-shot CipherSuite.seal/open raise NotImplementedError,
so the gate uses the context API:
  create_sender_context(pkr, info=b"", sks=None, psk=b"", psk_id=b"", eks=None) -> (enc, ctx)
  create_recipient_context(enc, skr, info=b"", pks=None, psk=b"", psk_id=b"") -> ctx
  ctx.seal(pt, aad=b"") -> ct ; ctx.open(ct, aad=b"") -> pt
"""
import json
from pathlib import Path

VEC_PATH = Path(__file__).parent / "vectors" / "rfc9180_hpke.json"


def _vector():
    # RFC 9180 A.2.1: Base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
    return [x for x in json.loads(VEC_PATH.read_text())
            if x["mode"] == 0 and x["kem_id"] == 0x0020
            and x["kdf_id"] == 0x0001 and x["aead_id"] == 0x0003][0]


def _suite():
    from pyhpke import AEADId, CipherSuite, KDFId, KEMId
    return CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256,
                           AEADId.CHACHA20_POLY1305)


def test_pyhpke_rfc9180_A2_1_vector_opens():
    v = _vector()
    suite = _suite()
    skR = suite.kem.deserialize_private_key(bytes.fromhex(v["skRm"]))
    ctx = suite.create_recipient_context(bytes.fromhex(v["enc"]), skR, bytes.fromhex(v["info"]))
    # Encryptions are sequential (seq 0..n-1); the context nonce advances on each open.
    for e in v["encryptions"]:
        assert ctx.open(bytes.fromhex(e["ct"]), bytes.fromhex(e["aad"])) == bytes.fromhex(e["pt"])


def test_pyhpke_rfc9180_A2_1_sender_known_answer():
    # Deterministic ephemeral from ikmE, so enc and ct must match the vector exactly.
    v = _vector()
    suite = _suite()
    pkR = suite.kem.deserialize_public_key(bytes.fromhex(v["pkRm"]))
    eks = suite.kem.derive_key_pair(bytes.fromhex(v["ikmE"]))
    enc, ctx = suite.create_sender_context(pkR, bytes.fromhex(v["info"]), eks=eks)
    assert enc == bytes.fromhex(v["enc"])
    e0 = v["encryptions"][0]
    assert ctx.seal(bytes.fromhex(e0["pt"]), bytes.fromhex(e0["aad"])) == bytes.fromhex(e0["ct"])


def test_pyhpke_fresh_seal_open_roundtrip():
    v = _vector()
    suite = _suite()
    skR = suite.kem.deserialize_private_key(bytes.fromhex(v["skRm"]))
    pkR = suite.kem.deserialize_public_key(bytes.fromhex(v["pkRm"]))
    info = bytes.fromhex(v["info"])
    enc, sctx = suite.create_sender_context(pkR, info)
    ct = sctx.seal(b"roundtrip", b"aad")
    rctx = suite.create_recipient_context(enc, skR, info)
    assert rctx.open(ct, b"aad") == b"roundtrip"
