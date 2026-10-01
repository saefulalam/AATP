import hashlib
import json

import pytest

from aatp.b64 import b64u
from aatp.canon import jcs
from aatp.dsse import PT_CARD, PT_ROTATION, make_envelope
from aatp.errors import AATPError
from aatp.ids import derive_agent_id
from aatp.signer import SoftwareSigner
from aatp.card import (
    CardCache,
    check_key_not_revoked,
    make_revocation,
    make_rotation_statement,
    verify_card,
)

GENESIS_SEED = bytes([0x11]) * 32
K1_SEED = bytes([0x22]) * 32
K2_SEED = bytes([0x33]) * 32
ENC_RAW = bytes([0x44]) * 32

ISSUED = "2026-10-01T00:00:00Z"
EXPIRES_7D = "2026-10-08T00:00:00Z"
EXPIRES_30D = "2026-10-31T00:00:00Z"
EXPIRES_31D = "2026-11-01T00:00:00Z"
NOW = "2026-10-02T00:00:00Z"
SIGNING_NOT_AFTER = "2027-10-01T00:00:00Z"


def _signer(seed, key_id):
    return SoftwareSigner.from_seed(seed, key_id)


def _genesis():
    return _signer(GENESIS_SEED, "k0")


def _agent_id():
    return derive_agent_id(_genesis().public_key_raw())


def _commit(pub_raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub_raw).hexdigest()


def _key_entry(key_id, pub_raw, not_before=ISSUED, not_after=SIGNING_NOT_AFTER):
    return {"key_id": key_id, "public_key": b64u(pub_raw),
            "not_before": not_before, "not_after": not_after}


def _rotation_dict(agent_id, from_kid, to_kid, to_pub, eff=ISSUED, next_c=None):
    d = {"v": "0.2", "type": "rotate", "agent_id": agent_id,
         "from_key_id": from_kid, "to_key_id": to_kid,
         "to_public_key": b64u(to_pub), "effective_at": eff}
    if next_c is not None:
        d["next_commitment"] = next_c
    return d


def _rotation_env(signer, payload_dict):
    return make_envelope(PT_ROTATION, jcs(payload_dict), signer)


def _base_card(seq=1, issued=ISSUED, expires=EXPIRES_7D,
               signing=None, enc=None, history=None, next_c=None,
               revoked=None, suites=None):
    g = _genesis()
    agent_id = _agent_id()
    if signing is None:
        signing = _key_entry("k0", g.public_key_raw())
    if enc is None:
        enc = _key_entry("e0", ENC_RAW, ISSUED, EXPIRES_7D)
    card = {"v": "0.2", "agent_id": agent_id,
            "genesis_public_key": b64u(g.public_key_raw()),
            "signing_key": signing, "enc_key": enc,
            "key_history": [] if history is None else history,
            "suites": ["AATP-S1"] if suites is None else suites,
            "seq": seq, "issued_at": issued, "expires_at": expires}
    if next_c is not None:
        card["next_commitment"] = next_c
    if revoked is not None:
        card["revoked"] = revoked
    return card


def _sign_card(card, signer):
    return make_envelope(PT_CARD, jcs(card), signer)


def _cache(tmp_path, seqs=None):
    c = CardCache(str(tmp_path / "seq.json"))
    for aid, s in (seqs or {}).items():
        c.record(aid, s)
    return c


def _code(fn, *a, **k):
    with pytest.raises(AATPError) as ei:
        fn(*a, **k)
    return ei.value.code


def _rotated_card():
    # genesis(k0) -> k1 -> k2 chain; card signed by k2.
    g, s1, s2 = _genesis(), _signer(K1_SEED, "k1"), _signer(K2_SEED, "k2")
    agent_id = _agent_id()
    c2 = _commit(s2.public_key_raw())
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1",
                                         s1.public_key_raw(), next_c=c2))
    r1 = _rotation_env(s1, _rotation_dict(agent_id, "k1", "k2",
                                          s2.public_key_raw()))
    card = _base_card(signing=_key_entry("k2", s2.public_key_raw()),
                      history=[r0, r1])
    return agent_id, card, (g, s1, s2)


# ID-001 / trust (ID-003/004)

def test_ID001_genesis_mismatch_rejected(tmp_path):
    card = _base_card()
    card["agent_id"] = "aatp:" + "a" * 52
    env = _sign_card(card, _genesis())
    assert _code(verify_card, env, card["agent_id"], _cache(tmp_path), NOW) == "ERR_AUTH_FAILED"


def test_ID003_pinned_mismatch_rejected(tmp_path):
    env = _sign_card(_base_card(), _genesis())
    assert _code(verify_card, env, "aatp:" + "b" * 52, _cache(tmp_path), NOW) == "ERR_AUTH_FAILED"


def test_ID004_first_contact_denied_by_default(tmp_path):
    env = _sign_card(_base_card(), _genesis())
    assert _code(verify_card, env, None, _cache(tmp_path), NOW) == "ERR_AUTH_FAILED"


def test_ID001_valid_genesis_card_accepted(tmp_path):
    agent_id = _agent_id()
    env = _sign_card(_base_card(), _genesis())
    out = verify_card(env, agent_id, _cache(tmp_path), NOW)
    assert out["agent_id"] == agent_id


# ID-010

def test_ID010_card_signature_invalid(tmp_path):
    agent_id = _agent_id()
    env = _sign_card(_base_card(), _genesis())
    env["payload"] = b64u(jcs({**_base_card(), "seq": 999}))
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_SIGNATURE_INVALID"


def test_ID010_wrong_signing_key(tmp_path):
    agent_id = _agent_id()
    other = _signer(K1_SEED, "k0")
    env = _sign_card(_base_card(), other)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_SIGNATURE_INVALID"


# ID-011 (N07)

def test_ID011_card_rollback_rejected(tmp_path):
    agent_id = _agent_id()
    cache = _cache(tmp_path, {agent_id: 5})
    env = _sign_card(_base_card(seq=4), _genesis())
    assert _code(verify_card, env, agent_id, cache, NOW) == "ERR_CARD_ROLLBACK"
    assert cache.highest_seq(agent_id) == 5


def test_ID011_seq_equal_accepted(tmp_path):
    agent_id = _agent_id()
    cache = _cache(tmp_path, {agent_id: 5})
    env = _sign_card(_base_card(seq=5), _genesis())
    assert verify_card(env, agent_id, cache, NOW)["seq"] == 5


def test_ID011_cache_durable(tmp_path):
    agent_id = _agent_id()
    c1 = _cache(tmp_path)
    env = _sign_card(_base_card(seq=7), _genesis())
    verify_card(env, agent_id, c1, NOW)
    c2 = CardCache(str(tmp_path / "seq.json"))
    assert c2.highest_seq(agent_id) == 7
    env_old = _sign_card(_base_card(seq=6), _genesis())
    assert _code(verify_card, env_old, agent_id, c2, NOW) == "ERR_CARD_ROLLBACK"


# ID-012

def test_ID012_enc_key_window_gt_7d_rejected(tmp_path):
    agent_id = _agent_id()
    enc = _key_entry("e0", ENC_RAW, ISSUED, "2026-10-09T00:00:01Z")
    env = _sign_card(_base_card(enc=enc), _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_KEY_EXPIRED"


def test_ID012_enc_window_exactly_7d_accepted(tmp_path):
    agent_id = _agent_id()
    env = _sign_card(_base_card(), _genesis())
    assert verify_card(env, agent_id, _cache(tmp_path), NOW)["seq"] == 1


# ID-013

def test_ID013_card_validity_gt_30d_rejected(tmp_path):
    agent_id = _agent_id()
    env = _sign_card(_base_card(expires=EXPIRES_31D), _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_MESSAGE_EXPIRED"


def test_ID013_card_validity_exactly_30d_accepted(tmp_path):
    agent_id = _agent_id()
    enc = _key_entry("e0", ENC_RAW, "2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z")
    card = _base_card(expires=EXPIRES_30D, enc=enc)
    env = _sign_card(card, _genesis())
    assert verify_card(env, agent_id, _cache(tmp_path), "2026-10-15T00:00:00Z")["seq"] == 1


def test_ID013_card_expired_rejected(tmp_path):
    agent_id = _agent_id()
    env = _sign_card(_base_card(), _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), "2026-10-09T00:00:00Z") == "ERR_MESSAGE_EXPIRED"


# ID-014

def test_ID014_signing_key_expired_rejected(tmp_path):
    agent_id = _agent_id()
    sk = _key_entry("k0", _genesis().public_key_raw(), ISSUED, "2026-10-01T12:00:00Z")
    env = _sign_card(_base_card(signing=sk), _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_KEY_EXPIRED"


def test_ID014_skew_within_accepted(tmp_path):
    agent_id = _agent_id()
    # now 60s after not_after -> within 120s skew -> accept
    sk = _key_entry("k0", _genesis().public_key_raw(), ISSUED, "2026-10-02T00:00:00Z")
    env = _sign_card(_base_card(signing=sk), _genesis())
    assert verify_card(env, agent_id, _cache(tmp_path), "2026-10-02T00:01:00Z")["seq"] == 1


# ID-020 (N08) / ID-021

def test_ID020_commitment_mismatch(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    bad = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1",
                                          s1.public_key_raw(),
                                          next_c="sha256:" + "0" * 64))
    card["key_history"] = [bad, card["key_history"][1]]
    env = _sign_card(card, s2)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_KEY_COMMITMENT_MISMATCH"


def test_ID021_missing_link_rejected(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    bad = _rotation_env(g, _rotation_dict(agent_id, "kX", "k1",
                                          s1.public_key_raw(),
                                          next_c=_commit(s2.public_key_raw())))
    card["key_history"] = [bad, card["key_history"][1]]
    env = _sign_card(card, s2)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_SIGNATURE_INVALID"


def test_ID021_final_key_mismatch_rejected(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    card["signing_key"] = _key_entry("k9", s2.public_key_raw())
    env = _sign_card(card, s2)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_SIGNATURE_INVALID"


def test_ID021_rotation_chain_accepted(tmp_path):
    agent_id, card, (_g, _s1, s2) = _rotated_card()
    env = _sign_card(card, s2)
    assert verify_card(env, agent_id, _cache(tmp_path), NOW)["signing_key"]["key_id"] == "k2"


# ID-023 / ID-024

def _revoke_dict(agent_id, key_id, eff, reason="compromised", pub=None):
    d = {"v": "0.2", "type": "revoke", "agent_id": agent_id,
         "key_id": key_id, "effective_at": eff, "reason": reason}
    if pub is not None:
        d["public_key"] = b64u(pub)
    return d


def test_ID023_revoke_by_current_key_accepted(tmp_path):
    g, s1 = _genesis(), _signer(K1_SEED, "k1")
    agent_id = _agent_id()
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1", s1.public_key_raw()))
    rev = make_envelope(PT_ROTATION, jcs(_revoke_dict(agent_id, "k0", ISSUED)), s1)
    card = _base_card(seq=2, signing=_key_entry("k1", s1.public_key_raw()),
                      history=[r0], revoked=[rev])
    env = _sign_card(card, s1)
    out = verify_card(env, agent_id, _cache(tmp_path), NOW)
    assert out["revoked"] == [rev]


def test_ID023_revoke_by_next_commitment_key_accepted(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    c2 = _commit(s2.public_key_raw())
    card["next_commitment"] = c2
    rev = make_envelope(PT_ROTATION,
                        jcs(_revoke_dict(agent_id, "k1", ISSUED, pub=s2.public_key_raw())), s2)
    card["revoked"] = [rev]
    card["seq"] = 2
    env = _sign_card(card, s2)
    assert verify_card(env, agent_id, _cache(tmp_path), NOW)["seq"] == 2


def test_ID024_message_from_revoked_key_rejected(tmp_path):
    g, s1 = _genesis(), _signer(K1_SEED, "k1")
    agent_id = _agent_id()
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1", s1.public_key_raw()))
    rev = make_envelope(PT_ROTATION, jcs(_revoke_dict(agent_id, "k0", ISSUED)), s1)
    card = _base_card(seq=2, signing=_key_entry("k1", s1.public_key_raw()),
                      history=[r0], revoked=[rev])
    env = _sign_card(card, s1)
    out = verify_card(env, agent_id, _cache(tmp_path), NOW)
    # created after revocation -> revoked
    assert _code(check_key_not_revoked, out, "k0", NOW) == "ERR_KEY_REVOKED"
    # created before revocation -> still usable
    check_key_not_revoked(out, "k0", "2026-09-30T00:00:00Z")


def test_ID024_current_key_revoked_rejected(tmp_path):
    agent_id = _agent_id()
    g = _genesis()
    rev = make_envelope(PT_ROTATION, jcs(_revoke_dict(agent_id, "k0", ISSUED)), g)
    card = _base_card(revoked=[rev])
    env = _sign_card(card, g)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_KEY_REVOKED"


# suite / version / shape (CRY-005, GEN-004/010)

def test_CRY005_unknown_suite_rejected(tmp_path):
    agent_id = _agent_id()
    env = _sign_card(_base_card(suites=["UNKNOWN-X"]), _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_SUITE_UNSUPPORTED"


def test_version_mismatch_rejected(tmp_path):
    agent_id = _agent_id()
    card = _base_card()
    card["v"] = "0.3"
    env = _sign_card(card, _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_PROTOCOL_VERSION"


def test_malformed_card_missing_field(tmp_path):
    agent_id = _agent_id()
    card = _base_card()
    del card["suites"]
    env = _sign_card(card, _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_MALFORMED_MESSAGE"


def test_nondict_payload_rejected(tmp_path):
    agent_id = _agent_id()
    env = make_envelope(PT_CARD, jcs([1, 2, 3]), _genesis())
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_MALFORMED_MESSAGE"


# strict version (card requires explicit "0.2"; rotation/revocation must too)

def test_ID_version_rotation_missing_v_rejected(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    d = _rotation_dict(agent_id, "k0", "k1", s1.public_key_raw(),
                       next_c=_commit(s2.public_key_raw()))
    del d["v"]
    card["key_history"] = [_rotation_env(g, d), card["key_history"][1]]
    env = _sign_card(card, s2)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_PROTOCOL_VERSION"


def test_ID_version_rotation_wrong_v_rejected(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    d = _rotation_dict(agent_id, "k0", "k1", s1.public_key_raw(),
                       next_c=_commit(s2.public_key_raw()))
    d["v"] = "0.3"
    card["key_history"] = [_rotation_env(g, d), card["key_history"][1]]
    env = _sign_card(card, s2)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_PROTOCOL_VERSION"


def test_ID_version_revocation_missing_v_rejected(tmp_path):
    g, s1 = _genesis(), _signer(K1_SEED, "k1")
    agent_id = _agent_id()
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1", s1.public_key_raw()))
    d = _revoke_dict(agent_id, "k0", ISSUED)
    del d["v"]
    rev = make_envelope(PT_ROTATION, jcs(d), s1)
    card = _base_card(seq=2, signing=_key_entry("k1", s1.public_key_raw()),
                      history=[r0], revoked=[rev])
    env = _sign_card(card, s1)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_PROTOCOL_VERSION"


def test_ID_version_revocation_wrong_v_rejected(tmp_path):
    g, s1 = _genesis(), _signer(K1_SEED, "k1")
    agent_id = _agent_id()
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1", s1.public_key_raw()))
    d = _revoke_dict(agent_id, "k0", ISSUED)
    d["v"] = "0.3"
    rev = make_envelope(PT_ROTATION, jcs(d), s1)
    card = _base_card(seq=2, signing=_key_entry("k1", s1.public_key_raw()),
                      history=[r0], revoked=[rev])
    env = _sign_card(card, s1)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_PROTOCOL_VERSION"


# ID-020/022 card-vs-history commitment equality

def test_ID020_card_commitment_divergence_rejected(tmp_path):
    g, s1, s2 = _genesis(), _signer(K1_SEED, "k1"), _signer(K2_SEED, "k2")
    agent_id = _agent_id()
    k3_pub = bytes([0x55]) * 32
    c2 = _commit(s2.public_key_raw())
    c3 = _commit(k3_pub)
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1",
                                         s1.public_key_raw(), next_c=c2))
    r1 = _rotation_env(s1, _rotation_dict(agent_id, "k1", "k2",
                                          s2.public_key_raw(), next_c=c3))
    card = _base_card(signing=_key_entry("k2", s2.public_key_raw()),
                      history=[r0, r1], next_c="sha256:" + "ff" * 32)
    env = _sign_card(card, s2)
    assert _code(verify_card, env, agent_id, _cache(tmp_path), NOW) == "ERR_KEY_COMMITMENT_MISMATCH"


def test_ID020_card_commitment_equality_accepted(tmp_path):
    g, s1, s2 = _genesis(), _signer(K1_SEED, "k1"), _signer(K2_SEED, "k2")
    agent_id = _agent_id()
    k3_pub = bytes([0x55]) * 32
    c2 = _commit(s2.public_key_raw())
    c3 = _commit(k3_pub)
    r0 = _rotation_env(g, _rotation_dict(agent_id, "k0", "k1",
                                         s1.public_key_raw(), next_c=c2))
    r1 = _rotation_env(s1, _rotation_dict(agent_id, "k1", "k2",
                                          s2.public_key_raw(), next_c=c3))
    card = _base_card(signing=_key_entry("k2", s2.public_key_raw()),
                      history=[r0, r1], next_c=c3)
    env = _sign_card(card, s2)
    assert verify_card(env, agent_id, _cache(tmp_path), NOW)["seq"] == 1


# check_key_not_revoked re-verification (fail closed)

def test_ID024_forged_revocation_not_trusted(tmp_path):
    agent_id = _agent_id()
    g = _genesis()
    attacker = _signer(K2_SEED, "kX")
    forged = make_envelope(PT_ROTATION, jcs(_revoke_dict(agent_id, "k0", ISSUED)), attacker)
    card = _base_card(revoked=[forged])
    assert _code(check_key_not_revoked, card, "k0", NOW) == "ERR_SIGNATURE_INVALID"
    assert _code(verify_card, _sign_card(card, g), agent_id,
                _cache(tmp_path), NOW) == "ERR_SIGNATURE_INVALID"


def test_ID024_stripped_revocation_signature_rejected():
    agent_id = _agent_id()
    g = _genesis()
    rev = make_envelope(PT_ROTATION, jcs(_revoke_dict(agent_id, "k0", ISSUED)), g)
    stripped = dict(rev)
    stripped["signatures"] = []
    card = _base_card(revoked=[stripped])
    assert _code(check_key_not_revoked, card, "k0", NOW) == "ERR_MALFORMED_MESSAGE"


def test_ID024_tampered_revocation_effective_at_rejected():
    import copy
    from aatp.b64 import b64u_dec
    from aatp.canon import parse_jcs
    g = _genesis()
    agent_id = _agent_id()
    rev = make_envelope(PT_ROTATION, jcs(_revoke_dict(agent_id, "k0", ISSUED)), g)
    tampered = copy.deepcopy(rev)
    payload = parse_jcs(b64u_dec(rev["payload"]))
    payload["effective_at"] = NOW
    tampered["payload"] = b64u(jcs(payload))
    card = _base_card(revoked=[tampered])
    assert _code(check_key_not_revoked, card, "k0", NOW) == "ERR_SIGNATURE_INVALID"


def test_ID024_next_commitment_revocation_checked_by_helper(tmp_path):
    agent_id, card, (g, s1, s2) = _rotated_card()
    c2 = _commit(s2.public_key_raw())
    card["next_commitment"] = c2
    rev = make_envelope(PT_ROTATION,
                        jcs(_revoke_dict(agent_id, "k1", ISSUED, pub=s2.public_key_raw())), s2)
    card["revoked"] = [rev]
    card["seq"] = 2
    out = verify_card(_sign_card(card, s2), agent_id, _cache(tmp_path), NOW)
    assert _code(check_key_not_revoked, out, "k1", NOW) == "ERR_KEY_REVOKED"
    check_key_not_revoked(out, "k1", "2026-09-30T00:00:00Z")


# helpers

def test_make_rotation_statement_verifiable():
    agent_id = _agent_id()
    g, s1 = _genesis(), _signer(K1_SEED, "k1")
    env = make_rotation_statement(signer=g, agent_id=agent_id, from_key_id="k0",
                                  to_key_id="k1", to_public_key_raw32=s1.public_key_raw(),
                                  effective_at=ISSUED)
    from aatp.dsse import verify_envelope
    out = verify_envelope(env, PT_ROTATION, g.public_key_raw())
    assert out["to_key_id"] == "k1" and out["type"] == "rotate"


def test_make_revocation_verifiable():
    agent_id = _agent_id()
    g = _genesis()
    env = make_revocation(signer=g, agent_id=agent_id, key_id="k0",
                          effective_at=ISSUED, reason="compromised")
    from aatp.dsse import verify_envelope
    assert verify_envelope(env, PT_ROTATION, g.public_key_raw())["type"] == "revoke"


def test_vectors_file_has_v03():
    from pathlib import Path
    data = json.loads((Path(__file__).parent / "vectors" / "aatp_v0_2_vectors.json").read_bytes().decode("utf-8"))
    assert data["V03"]["agent_id"] == "aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma"
