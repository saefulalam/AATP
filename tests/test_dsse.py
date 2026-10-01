import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs
from aatp.dsse import (
    PT_CARD, PT_GRANT, PT_MESSAGE, PT_NODE, PT_ROTATION,
    make_envelope, pae, verify_envelope,
)
from aatp.errors import AATPError
from aatp.signer import SoftwareSigner

SEED = bytes([0x11]) * 32  # V03/V06 key
L = 2**252 + 27742317777372353535851937790883648493


def _signer():
    return SoftwareSigner.from_seed(SEED, key_id="k1")


def _env(obj=None, pt=PT_NODE):
    s = _signer()
    return s, make_envelope(pt, jcs({"a": 1} if obj is None else obj), s)


def _code(env, pt=PT_NODE, pk=None, **kw):
    with pytest.raises(AATPError) as ei:
        verify_envelope(env, pt, _signer().public_key_raw() if pk is None else pk, **kw)
    return ei.value.code


def test_pae_grammar():
    # "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    assert pae("T", b"{}") == b"DSSEv1 1 T 2 {}"
    assert pae("", b"") == b"DSSEv1 0  0 "


def test_payload_type_constants():
    assert PT_MESSAGE == "application/vnd.aatp.message+json"
    assert PT_NODE == "application/vnd.aatp.node+json"
    assert PT_CARD == "application/vnd.aatp.card+json"
    assert PT_GRANT == "application/vnd.aatp.grant+json"
    assert PT_ROTATION == "application/vnd.aatp.rotation+json"


def test_roundtrip():
    s, env = _env({"b": [1, "x"], "a": 1})
    assert env["payloadType"] == PT_NODE
    assert env["signatures"][0]["keyid"] == "k1"
    assert verify_envelope(env, PT_NODE, s.public_key_raw()) == {"a": 1, "b": [1, "x"]}


def test_SIG001_signer_hides_key():
    s = _signer()
    sig = s.sign(PT_NODE, b"{}")
    assert isinstance(sig, bytes) and len(sig) == 64
    assert not hasattr(s, "private_key_pem")
    assert len(s.public_key_raw()) == 32
    assert s.key_id() == "k1"


def test_SIG001_repr_str_do_not_leak_key():
    s = _signer()
    for text in (repr(s), str(s)):
        assert SEED.hex() not in text
        assert SEED.hex().upper() not in text
        assert str(SEED) not in text
        assert b64u(SEED) not in text


def test_SIG001_generate_uses_fresh_keys():
    a, b = SoftwareSigner.generate("ka"), SoftwareSigner.generate("kb")
    assert a.public_key_raw() != b.public_key_raw()
    env = make_envelope(PT_CARD, jcs({"x": 1}), a)
    assert verify_envelope(env, PT_CARD, a.public_key_raw()) == {"x": 1}


def test_SIG002_reject_noncanonical_payload():
    _, env = _env({"b": 2, "a": 1})
    env["payload"] = base64.urlsafe_b64encode(b'{ "a":1,"b":2 }').rstrip(b"=").decode()
    assert _code(env) == "ERR_MALFORMED_MESSAGE"


def test_SIG003_wrong_payload_type():
    _, env = _env()
    assert _code(env, pt=PT_MESSAGE) == "ERR_MALFORMED_MESSAGE"


def test_SIG003_type_checked_before_payload_parse():
    _, env = _env()
    env["payload"] = "!!!"
    assert _code(env, pt=PT_MESSAGE) == "ERR_MALFORMED_MESSAGE"
    env["payloadType"] = PT_MESSAGE  # signature no longer matches either way
    assert _code(env, pt=PT_MESSAGE) == "ERR_MALFORMED_MESSAGE"


def test_CRY002_signs_pae_directly():
    s = _signer()
    payload = jcs({"a": 1})
    sig = s.sign(PT_NODE, payload)
    Ed25519PublicKey.from_public_bytes(s.public_key_raw()).verify(sig, pae(PT_NODE, payload))


def test_CRY003_reject_noncanonical_signature():
    _, env = _env()
    sig = b64u_dec(env["signatures"][0]["sig"])
    s_int = int.from_bytes(sig[32:], "little")
    s_mal = (s_int + L).to_bytes(32, "little")  # S' = S + L, valid mod L, non-canonical
    env["signatures"][0]["sig"] = b64u(sig[:32] + s_mal)
    assert _code(env) == "ERR_SIGNATURE_INVALID"


def test_CRY003_explicit_s_range_check():
    # Strict mode is enforced by AATP itself, independent of the crypto backend.
    _, env = _env()
    sig = b64u_dec(env["signatures"][0]["sig"])
    env["signatures"][0]["sig"] = b64u(sig[:32] + L.to_bytes(32, "little"))
    with pytest.raises(AATPError) as ei:
        verify_envelope(env, PT_NODE, _signer().public_key_raw())
    assert ei.value.code == "ERR_SIGNATURE_INVALID"
    assert ei.value.detail == "non-canonical signature (S >= L)"


def test_N01_tampered_payload_value():
    _, env = _env({"a": 1})
    env["payload"] = b64u(jcs({"a": 2}))
    assert _code(env) == "ERR_SIGNATURE_INVALID"


def test_wrong_public_key():
    _, env = _env()
    other = SoftwareSigner.from_seed(bytes([0x22]) * 32, "k2")
    assert _code(env, pk=other.public_key_raw()) == "ERR_SIGNATURE_INVALID"


@pytest.mark.parametrize("pk", [b"", b"\x00" * 31, b"\x00" * 33, b"\xff" * 32, "x" * 32])
def test_public_key_length(pk):
    _, env = _env()
    assert _code(env, pk=pk) == "ERR_SIGNATURE_INVALID"


@pytest.mark.parametrize("n", [0, 63, 65])
def test_signature_length(n):
    _, env = _env()
    env["signatures"][0]["sig"] = b64u(b"\x01" * n)
    assert _code(env) == "ERR_SIGNATURE_INVALID"


def test_key_id_selection():
    s, env = _env()
    good = env["signatures"][0]
    env["signatures"] = [{"keyid": "other", "sig": b64u(b"\x00" * 64)}, good]
    assert verify_envelope(env, PT_NODE, s.public_key_raw(), key_id="k1") == {"a": 1}
    # default: signatures[0] is verified
    assert _code(env) == "ERR_SIGNATURE_INVALID"
    assert _code(env, key_id="missing") == "ERR_SIGNATURE_INVALID"


def _mutations():
    yield "not_dict", lambda e: ["x"]
    yield "no_type", lambda e: {k: v for k, v in e.items() if k != "payloadType"}
    yield "no_payload", lambda e: {k: v for k, v in e.items() if k != "payload"}
    yield "no_sigs", lambda e: {k: v for k, v in e.items() if k != "signatures"}
    yield "type_int", lambda e: {**e, "payloadType": 1}
    yield "payload_bytes", lambda e: {**e, "payload": b"x"}
    yield "sigs_empty", lambda e: {**e, "signatures": []}
    yield "sigs_dict", lambda e: {**e, "signatures": {}}
    yield "sig_entry_str", lambda e: {**e, "signatures": ["x"]}
    yield "sig_no_keyid", lambda e: {**e, "signatures": [{"sig": e["signatures"][0]["sig"]}]}
    yield "sig_no_sig", lambda e: {**e, "signatures": [{"keyid": "k1"}]}
    yield "keyid_int", lambda e: {**e, "signatures": [{"keyid": 1, "sig": e["signatures"][0]["sig"]}]}
    yield "sig_int", lambda e: {**e, "signatures": [{"keyid": "k1", "sig": 5}]}


@pytest.mark.parametrize("name,mutate", list(_mutations()))
def test_strict_envelope_shape(name, mutate):
    _, env = _env()
    assert _code(mutate(env)) == "ERR_MALFORMED_MESSAGE"


@pytest.mark.parametrize("bad", ["eyJhIjoxfQ==", "eyJhIjoxfQ=", "eyJh+joxfQ", "eyJh/joxfQ",
                                 "eyJh IjoxfQ", "eyJhIjoxfQ\n", "eyJhIjoxfR", "e", "eyJ\u00e9"])
def test_GEN003_strict_b64u(bad):
    with pytest.raises(AATPError) as ei:
        b64u_dec(bad)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_GEN003_b64u_roundtrip():
    for n in range(0, 70):
        data = bytes(range(n))
        enc = b64u(data)
        assert "=" not in enc
        assert b64u_dec(enc) == data


def test_GEN003_envelope_rejects_padded_payload():
    _, env = _env()
    env["payload"] = env["payload"] + "=" * (-len(env["payload"]) % 4 or 4)
    assert _code(env) == "ERR_MALFORMED_MESSAGE"


def test_GEN003_envelope_rejects_bad_sig_encoding():
    _, env = _env()
    env["signatures"][0]["sig"] = env["signatures"][0]["sig"] + "=="
    assert _code(env) == "ERR_MALFORMED_MESSAGE"


def test_GEN003_make_envelope_unpadded():
    _, env = _env()
    assert "=" not in env["payload"] and "=" not in env["signatures"][0]["sig"]
