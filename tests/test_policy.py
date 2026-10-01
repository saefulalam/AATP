"""M6 policy evaluation pipeline (blueprint §10.2 M6-scope, SEC-002, N22).

TDD RED: written before aatp/policy.py exists. One rule ID = one test.
"""
import pytest

from aatp.artifact import build as build_artifact
from aatp.errors import AATPError
from aatp.grants import grant_id_of
from aatp.ids import derive_agent_id
from aatp.signer import SoftwareSigner

T_NOW = "2026-10-01T12:00:00Z"
T_NBF = "2026-10-01T00:00:00Z"
T_EXP = "2026-10-02T00:00:00Z"

RECV = "aatp.artifact.receive"
INSTR = "aatp.artifact.instruct"
DELEGATE = "aatp.grant.delegate"
RES = "project:alpha/a"


def _signer(seed_byte, key_id="k1"):
    return SoftwareSigner.from_seed(bytes([seed_byte]) * 32, key_id)


def _actor(seed_byte):
    return derive_agent_id(_signer(seed_byte).public_key_raw())


OWNER = _actor(1)
ALICE = _actor(2)
BOB = _actor(3)
CAROL = _actor(4)

_SIGNERS = {a: _signer(b) for a, b in
            ((OWNER, 1), (ALICE, 2), (BOB, 3), (CAROL, 4))}


def _resolver(signers=_SIGNERS):
    pubs = {a: s.public_key_raw() for a, s in signers.items()}

    def resolve(agent_id):
        try:
            return pubs[agent_id]
        except KeyError:
            raise AATPError("ERR_AUTH_FAILED", 1102, "unknown agent") from None

    return resolve


def _grant(iss, aud, caps, nbf=T_NBF, exp=T_EXP, prf=(),
           cmax="CONFIDENTIAL", export=False):
    return {"v": "0.2", "iss": iss, "aud": aud, "cap": list(caps),
            "nbf": nbf, "exp": exp, "prf": list(prf),
            "constraints": {"classification_max": cmax, "export": export}}


def _env(grant, iss_seed):
    from aatp.grants import make_grant_envelope
    return make_grant_envelope(grant, _signer(iss_seed))


def _env_raw(grant, iss_seed):
    from aatp.canon import jcs
    from aatp.dsse import PT_GRANT, make_envelope
    return make_envelope(PT_GRANT, jcs(grant), _signer(iss_seed))


def _recv(res):
    return {"act": RECV, "res": res}


def _instr(res):
    return {"act": INSTR, "res": res}


def _deleg(res):
    return {"act": DELEGATE, "res": res}


def _chain(hops):
    """Build a linear chain root-first.

    hops: list of (iss_seed, iss, aud, caps, cmax, export).
    Returns (leaf_env, chain_envs[parent..root]).
    """
    grants = []
    envs = []
    for iss_seed, iss, aud, caps, cmax, export in hops:
        prf = [grant_id_of(g) for g in reversed(grants)]
        g = _grant(iss, aud, caps, prf=prf, cmax=cmax, export=export)
        grants.append(g)
        envs.append(_env(g, iss_seed))
    return envs[-1], list(reversed(envs[:-1]))


def _valid_chain():
    """Two-hop OWNER -> ALICE -> BOB chain covering RECV on RES."""
    leaf, chain = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "CONFIDENTIAL", False),
        (2, ALICE, BOB, [_recv(RES)], "CONFIDENTIAL", False),
    ])
    return leaf, chain


def _request(leaf, chain, **kw):
    req = {"action": RECV, "resource": RES,
           "classification": "INTERNAL",
           "grant_leaf_env": leaf, "grant_chain_envs": chain}
    req.update(kw)
    return req


def _evaluate(req, **kw):
    from aatp.policy import evaluate
    params = {"roots": {OWNER}, "key_resolver": _resolver(),
              "presenter": BOB, "now": T_NOW}
    params.update(kw)
    return evaluate(req, **params)


def _manifest():
    manifest, _, _ = build_artifact([(RES, b"hello", False)])
    # NOTE: build uses the resource string as a file path fixture; the
    # manifest content itself is irrelevant to policy (limits only).
    return manifest


# --- allow path ------------------------------------------------------------

def test_policy_allows_valid_receive():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain))
    assert out == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                   "code": None}


# --- step 1: grant chain -----------------------------------------------------

def test_policy_denies_widened_grant():
    leaf, chain = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "CONFIDENTIAL", False),
        (2, ALICE, BOB, [_recv("project:beta/*")], "CONFIDENTIAL", False),
    ])
    out = _evaluate(_request(leaf, chain, resource="project:beta/b"))
    assert out == {"decision": "deny", "rule_id": "AUT-002",
                   "code": "ERR_GRANT_ATTENUATION"}


def test_policy_grant_invalid_maps_AUT004():
    g = _grant(OWNER, BOB, [_recv(RES)], nbf=T_NBF,
               exp="2026-10-01T06:00:00Z")  # expired well before now - skew
    out = _evaluate(_request(_env(g, 1), [], presenter=BOB),
                    presenter=BOB)
    assert out == {"decision": "deny", "rule_id": "AUT-004",
                   "code": "ERR_GRANT_INVALID"}


def test_policy_grant_malformed_maps_GEN010():
    g = _grant(OWNER, BOB, [_recv(RES)])
    del g["cap"]
    out = _evaluate(_request(_env_raw(g, 1), []), presenter=BOB)
    assert out == {"decision": "deny", "rule_id": "GEN-010",
                   "code": "ERR_MALFORMED_MESSAGE"}


def test_policy_presenter_mismatch_maps_AUT006():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain), presenter=CAROL)
    assert out == {"decision": "deny", "rule_id": "AUT-006",
                   "code": "ERR_POLICY_DENIED"}


def test_policy_revoked_leaf_denied():
    g = _grant(OWNER, BOB, [_recv(RES)])
    env = _env(g, 1)
    from aatp.grants import grant_id_of as _gid
    out = _evaluate(_request(env, [], revoked={_gid(g)}), presenter=BOB)
    assert out == {"decision": "deny", "rule_id": "AUT-004",
                   "code": "ERR_GRANT_INVALID"}


def test_policy_order_grant_before_manifest():
    # Both grant and manifest fail: grant step must win (fail closed first).
    g = _grant(OWNER, BOB, [_recv(RES)])
    del g["cap"]
    bad_manifest = {"v": "0.2", "entries": "not-a-list"}
    out = _evaluate(_request(_env_raw(g, 1), [], manifest=bad_manifest),
                    presenter=BOB)
    assert out["rule_id"] == "GEN-010"
    assert out["code"] == "ERR_MALFORMED_MESSAGE"


# --- step 2: manifest limits ---------------------------------------------------

def test_policy_manifest_limits_ART006():
    leaf, chain = _valid_chain()
    manifest = _manifest()
    out = _evaluate(_request(leaf, chain, manifest=manifest,
                             limits={"max_total_artifact_bytes": 1}))
    assert out == {"decision": "deny", "rule_id": "ART-006",
                   "code": "ERR_MANIFEST_INVALID"}


def test_policy_manifest_shape_ART006():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain,
                             manifest={"v": "0.2", "entries": "not-a-list"}))
    assert out == {"decision": "deny", "rule_id": "ART-006",
                   "code": "ERR_MANIFEST_INVALID"}


# --- step 3: expiry ------------------------------------------------------------

def test_policy_expiry_MSG003():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain,
                             expires_at="2026-10-01T11:00:00Z"))
    assert out == {"decision": "deny", "rule_id": "MSG-003",
                   "code": "ERR_MESSAGE_EXPIRED"}


def test_policy_expiry_at_now_allowed():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain, expires_at=T_NOW))
    assert out["decision"] == "allow"


# --- step 4: classification -----------------------------------------------------

def test_policy_classification_AUT002():
    leaf, chain = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv(RES)], "INTERNAL", False),
    ])
    out = _evaluate(_request(leaf, chain, classification="CONFIDENTIAL"))
    assert out == {"decision": "deny", "rule_id": "AUT-002",
                   "code": "ERR_POLICY_DENIED"}


# --- step 5: consumption_mode (SEC-002, N22) --------------------------------------

def test_N22_instructions_without_grant_denied():
    leaf, chain = _valid_chain()  # RECV cap only, no instruct cap
    out = _evaluate(_request(leaf, chain,
                             consumption_mode="instructions_allowed"))
    assert out == {"decision": "deny", "rule_id": "SEC-002",
                   "code": "ERR_POLICY_DENIED"}


def test_SEC002_data_only_default():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain))  # no consumption_mode key
    assert out == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                   "code": None}


def test_SEC002_data_only_explicit():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain, consumption_mode="data_only"))
    assert out == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                   "code": None}


def test_SEC002_instruct_with_grant_allowed():
    leaf, chain = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _instr("project:alpha/*"),
                           _deleg("project:alpha/*")],
         "CONFIDENTIAL", False),
        (2, ALICE, BOB, [_recv(RES), _instr(RES)], "CONFIDENTIAL", False),
    ])
    out = _evaluate(_request(leaf, chain,
                             consumption_mode="instructions_allowed"))
    assert out == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                   "code": None}


def test_SEC002_instruct_wrong_resource_denied():
    # Valid chain (parent covers both caps), but the instruct cap does not
    # cover the requested resource -> SEC-002 deny at the consumption gate.
    leaf, chain = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _instr("project:other/*"),
                           _deleg("project:alpha/*"),
                           _deleg("project:other/*")],
         "CONFIDENTIAL", False),
        (2, ALICE, BOB, [_recv(RES), _instr("project:other/b")],
         "CONFIDENTIAL", False),
    ])
    out = _evaluate(_request(leaf, chain,
                             consumption_mode="instructions_allowed"))
    assert out == {"decision": "deny", "rule_id": "SEC-002",
                   "code": "ERR_POLICY_DENIED"}


# --- edge cases (M6 fix wave) --------------------------------------------------

def test_policy_unknown_consumption_mode_denied():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain,
                             consumption_mode="execute_everything"))
    assert out == {"decision": "deny", "rule_id": "SEC-002",
                   "code": "ERR_POLICY_DENIED"}


def test_policy_unknown_classification_denied():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain, classification="TOP-SECRET"))
    assert out == {"decision": "deny", "rule_id": "GEN-010",
                   "code": "ERR_MALFORMED_MESSAGE"}


def test_policy_malformed_expires_denied():
    leaf, chain = _valid_chain()
    out = _evaluate(_request(leaf, chain, expires_at="not-a-time"))
    assert out == {"decision": "deny", "rule_id": "GEN-010",
                   "code": "ERR_MALFORMED_MESSAGE"}


def test_policy_grant_auth_failed_maps_AUT001():
    # grants.verify_chain re-raises resolver AATPError as-is, so the
    # policy fallback maps ERR_AUTH_FAILED -> AUT-001.
    leaf, chain = _valid_chain()

    def bad_resolver(agent_id):
        raise AATPError("ERR_AUTH_FAILED", 1102, "boom")

    out = _evaluate(_request(leaf, chain), key_resolver=bad_resolver)
    assert out == {"decision": "deny", "rule_id": "AUT-001",
                   "code": "ERR_AUTH_FAILED"}


def test_policy_classification_default_PUBLIC_allows():
    leaf, chain = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv(RES)], "INTERNAL", False),
    ])
    req = _request(leaf, chain)
    del req["classification"]
    out = _evaluate(req)
    assert out == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                   "code": None}


def test_policy_missing_chain_key_allows():
    g = _grant(OWNER, BOB, [_recv(RES)], cmax="CONFIDENTIAL")
    req = _request(_env(g, 1), [])
    del req["grant_chain_envs"]
    out = _evaluate(req, presenter=BOB)
    assert out == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                   "code": None}
