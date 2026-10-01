"""M6 grant chain verification (blueprint §10.1, AUT-001..006, N19).

TDD RED: written before aatp/grants.py exists.
"""
import pytest

from aatp.errors import AATPError
from aatp.grants import grant_id_of, res_subset, verify_chain
from aatp.ids import derive_agent_id
from aatp.signer import SoftwareSigner

T_NOW = "2026-10-01T12:00:00Z"
T_NBF = "2026-10-01T00:00:00Z"
T_EXP = "2026-10-02T00:00:00Z"

RECV = "aatp.artifact.receive"
DELEGATE = "aatp.grant.delegate"


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
           cmax="INTERNAL", export=False):
    return {"v": "0.2", "iss": iss, "aud": aud, "cap": list(caps),
            "nbf": nbf, "exp": exp, "prf": list(prf),
            "constraints": {"classification_max": cmax, "export": export}}


def _env(grant, iss_seed):
    from aatp.grants import make_grant_envelope
    return make_grant_envelope(grant, _signer(iss_seed))


def _chain(hops, roots=None):
    """Build a linear chain root-first.

    hops: list of (iss_seed, iss, aud, caps, cmax, export).
    Returns (leaf_env, chain_envs[parent..root], leaf_grant).
    """
    grants = []
    envs = []
    for iss_seed, iss, aud, caps, cmax, export in hops:
        prf = [grant_id_of(g) for g in reversed(grants)]
        g = _grant(iss, aud, caps, prf=prf, cmax=cmax, export=export)
        grants.append(g)
        envs.append(_env(g, iss_seed))
    leaf_env = envs[-1]
    chain_envs = list(reversed(envs[:-1]))
    return leaf_env, chain_envs, grants[-1]


def _recv(res):
    return {"act": RECV, "res": res}


def _deleg(res):
    return {"act": DELEGATE, "res": res}


def _verify(leaf_env, chain_envs, roots, now=T_NOW, action=RECV,
            resource="project:alpha/a", presenter=BOB, revoked=None):
    return verify_chain(leaf_env, chain_envs, roots, now, action, resource,
                        presenter, revoked=revoked, key_resolver=_resolver())


# --- shape / pure helpers -------------------------------------------------

def test_AUT002_grant_id_shape():
    g = {"v": "0.2", "iss": "aatp:x", "aud": "aatp:y",
         "cap": [{"act": "aatp.artifact.receive", "res": "project:alpha/*"}],
         "nbf": "2026-10-01T00:00:00Z", "exp": "2026-10-02T00:00:00Z",
         "prf": [], "constraints": {"classification_max": "INTERNAL",
                                    "export": False}}
    gid = grant_id_of(g)
    assert gid.startswith("sha256:") and len(gid) == 7 + 64


def test_AUT002_res_subset():
    assert res_subset("project:alpha/a", "project:alpha/*")
    assert res_subset("project:alpha/a", "project:alpha/a")
    assert not res_subset("project:beta/a", "project:alpha/*")
    assert not res_subset("project:alpha", "project:alpha/*")


def test_N19_child_widens_res_rejected():
    # parent res "project:alpha/*", child res "project:beta/*"
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:beta/*")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, resource="project:beta/b")
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


# --- AUT-001 root trust ----------------------------------------------------

def test_AUT001_root_trusted_accepts():
    leaf, chain, want = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    got = _verify(leaf, chain, {OWNER})
    assert got == want


def test_AUT001_root_untrusted_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {CAROL})
    assert ei.value.code == "ERR_GRANT_INVALID"


def test_AUT001_single_self_rooted_grant():
    g = _grant(OWNER, ALICE, [_recv("project:alpha/a")])
    env = _env(g, 1)
    got = _verify(env, [], {OWNER}, presenter=ALICE)
    assert got == g


def test_AUT001_prf_link_order_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")])
    e0 = _env(g0, 1)
    id0 = grant_id_of(g0)
    g1 = _grant(ALICE, BOB, [_recv("project:alpha/*"),
                             _deleg("project:alpha/*")], prf=[id0])
    e1 = _env(g1, 2)
    id1 = grant_id_of(g1)
    g2 = _grant(BOB, CAROL, [_recv("project:alpha/a")],
                prf=[id0, id1])  # swapped: must be [id1, id0]
    e2 = _env(g2, 3)
    with pytest.raises(AATPError) as ei:
        _verify(e2, [e1, e0], {OWNER}, presenter=CAROL,
                resource="project:alpha/a")
    assert ei.value.code == "ERR_GRANT_INVALID"


# --- AUT-002 attenuation ----------------------------------------------------

def test_AUT002_attenuation_iss_link_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")])
    e0 = _env(g0, 1)
    id0 = grant_id_of(g0)
    # child.iss (CAROL) != parent.aud (ALICE)
    g1 = _grant(CAROL, BOB, [_recv("project:alpha/a")], prf=[id0])
    e1 = _env(g1, 4)
    with pytest.raises(AATPError) as ei:
        _verify(e1, [e0], {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT002_attenuation_cap_act_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [{"act": "aatp.artifact.send",
                          "res": "project:alpha/a"}], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, action="aatp.artifact.send")
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT002_attenuation_nbf_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")],
                nbf="2026-10-01T06:00:00Z")
    e0 = _env(g0, 1)
    g1 = _grant(ALICE, BOB, [_recv("project:alpha/a")],
                nbf=T_NBF, prf=[grant_id_of(g0)])
    e1 = _env(g1, 2)
    with pytest.raises(AATPError) as ei:
        _verify(e1, [e0], {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT002_attenuation_exp_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")])
    e0 = _env(g0, 1)
    g1 = _grant(ALICE, BOB, [_recv("project:alpha/a")],
                exp="2026-10-03T00:00:00Z", prf=[grant_id_of(g0)])
    e1 = _env(g1, 2)
    with pytest.raises(AATPError) as ei:
        _verify(e1, [e0], {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT002_attenuation_classification_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "CONFIDENTIAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT002_attenuation_export_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", True),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT002_malformed_missing_cap():
    g = _grant(OWNER, ALICE, [_recv("project:alpha/a")])
    del g["cap"]
    env = _env_raw(g, 1)
    with pytest.raises(AATPError) as ei:
        _verify(env, [], {OWNER}, presenter=ALICE)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_AUT002_malformed_bad_version():
    g = _grant(OWNER, ALICE, [_recv("project:alpha/a")])
    g["v"] = "0.3"
    env = _env_raw(g, 1)
    with pytest.raises(AATPError) as ei:
        _verify(env, [], {OWNER}, presenter=ALICE)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_AUT002_malformed_unknown_act():
    g = _grant(OWNER, ALICE, [{"act": "aatp.admin.wipe", "res": "x"}])
    env = _env_raw(g, 1)
    with pytest.raises(AATPError) as ei:
        _verify(env, [], {OWNER}, presenter=ALICE)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def _env_raw(grant, iss_seed):
    from aatp.canon import jcs
    from aatp.dsse import PT_GRANT, make_envelope
    return make_envelope(PT_GRANT, jcs(grant), _signer(iss_seed))


# --- AUT-003 delegation bit --------------------------------------------------

def test_AUT003_delegate_missing_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*")], "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_AUT003_delegate_wrong_resource_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"),
                           _deleg("project:beta/*")], "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


# --- AUT-004 depth + windows ---------------------------------------------------

def _deep_chain(n):
    seeds = list(range(1, n + 2))
    agents = [derive_agent_id(_signer(s).public_key_raw()) for s in seeds]
    signers = {a: _signer(s) for a, s in zip(agents, seeds)}
    caps = [_recv("project:alpha/*"), _deleg("project:alpha/*")]
    grants, envs = [], []
    for i in range(n):
        prf = [grant_id_of(g) for g in reversed(grants)]
        g = _grant(agents[i], agents[i + 1], caps, prf=prf)
        grants.append(g)
        from aatp.grants import make_grant_envelope
        envs.append(make_grant_envelope(g, signers[agents[i]]))
    pubs = {a: s.public_key_raw() for a, s in signers.items()}

    def resolve(agent_id):
        try:
            return pubs[agent_id]
        except KeyError:
            raise AATPError("ERR_AUTH_FAILED", 1102, "unknown") from None

    return envs[-1], list(reversed(envs[:-1])), agents[0], agents[-1], resolve


def test_AUT004_depth_boundary_accepts():
    leaf, chain, root, presenter, resolve = _deep_chain(8)
    got = verify_chain(leaf, chain, {root}, T_NOW, RECV, "project:alpha/a",
                       presenter, key_resolver=resolve)
    assert got["aud"] == presenter


def test_AUT004_depth_exceeded_rejected():
    leaf, chain, root, presenter, resolve = _deep_chain(9)
    with pytest.raises(AATPError) as ei:
        verify_chain(leaf, chain, {root}, T_NOW, RECV, "project:alpha/a",
                     presenter, key_resolver=resolve)
    assert ei.value.code == "ERR_GRANT_INVALID"


def test_AUT004_expired_rejected():
    g = _grant(OWNER, BOB, [_recv("project:alpha/a")],
               exp="2026-10-01T11:57:59Z")  # 121s before now, beyond 120s skew
    env = _env(g, 1)
    with pytest.raises(AATPError) as ei:
        _verify(env, [], {OWNER})
    assert ei.value.code == "ERR_GRANT_INVALID"


def test_AUT004_not_yet_rejected():
    g = _grant(OWNER, BOB, [_recv("project:alpha/a")],
               nbf="2026-10-01T12:02:01Z")  # 121s after now
    env = _env(g, 1)
    with pytest.raises(AATPError) as ei:
        _verify(env, [], {OWNER})
    assert ei.value.code == "ERR_GRANT_INVALID"


def test_AUT004_skew_accepted():
    g = _grant(OWNER, BOB, [_recv("project:alpha/a")],
               nbf="2026-10-01T12:01:00Z", exp=T_EXP)  # nbf 60s out, in skew
    assert _verify(_env(g, 1), [], {OWNER}) == g
    g2 = _grant(OWNER, BOB, [_recv("project:alpha/a")],
                nbf=T_NBF, exp="2026-10-01T11:59:00Z")  # exp 60s out, in skew
    assert _verify(_env(g2, 1), [], {OWNER}) == g2


def test_AUT004_ancestor_expired_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")],
                exp="2026-10-01T11:57:59Z")
    e0 = _env(g0, 1)
    g1 = _grant(ALICE, BOB, [_recv("project:alpha/a")],
                nbf=T_NBF, exp="2026-10-01T11:57:59Z",
                prf=[grant_id_of(g0)])
    e1 = _env(g1, 2)
    with pytest.raises(AATPError) as ei:
        _verify(e1, [e0], {OWNER})
    assert ei.value.code == "ERR_GRANT_INVALID"


# --- AUT-005 revocation ----------------------------------------------------------

def test_AUT005_revoked_leaf_rejected():
    leaf, chain, grant = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, revoked={grant_id_of(grant)})
    assert ei.value.code == "ERR_GRANT_INVALID"


def test_AUT005_revoked_ancestor_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")])
    e0 = _env(g0, 1)
    g1 = _grant(ALICE, BOB, [_recv("project:alpha/a")],
                prf=[grant_id_of(g0)])
    e1 = _env(g1, 2)
    with pytest.raises(AATPError) as ei:
        _verify(e1, [e0], {OWNER}, revoked={grant_id_of(g0)})
    assert ei.value.code == "ERR_GRANT_INVALID"


def test_AUT005_revoked_not_iterable():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, revoked=123)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


# --- AUT-006 presenter + action/resource --------------------------------------------

def test_AUT006_presenter_mismatch_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, presenter=CAROL)
    assert ei.value.code == "ERR_POLICY_DENIED"


def test_AUT006_action_not_covered_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, action="aatp.artifact.send")
    assert ei.value.code == "ERR_POLICY_DENIED"


def test_AUT006_resource_not_covered_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, resource="project:alpha/b")
    assert ei.value.code == "ERR_POLICY_DENIED"


# --- N19 attenuation widening ----------------------------------------------------------

def test_N19_act_widen_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a"),
                         {"act": "aatp.artifact.send",
                          "res": "project:alpha/a"}], "INTERNAL", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER}, action="aatp.artifact.send",
                resource="project:alpha/a")
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_N19_classification_widen_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "PUBLIC", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "RESTRICTED", False),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_N19_export_widen_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", True),
    ])
    with pytest.raises(AATPError) as ei:
        _verify(leaf, chain, {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


def test_N19_window_widen_rejected():
    g0 = _grant(OWNER, ALICE,
                [_recv("project:alpha/*"), _deleg("project:alpha/*")],
                nbf="2026-10-01T06:00:00Z", exp="2026-10-01T18:00:00Z")
    e0 = _env(g0, 1)
    g1 = _grant(ALICE, BOB, [_recv("project:alpha/a")],
                nbf=T_NBF, exp=T_EXP, prf=[grant_id_of(g0)])
    e1 = _env(g1, 2)
    with pytest.raises(AATPError) as ei:
        _verify(e1, [e0], {OWNER})
    assert ei.value.code == "ERR_GRANT_ATTENUATION"


# --- envelope integrity ---------------------------------------------------------------

def test_SIG_bad_signature_rejected():
    leaf, chain, _ = _chain([
        (1, OWNER, ALICE, [_recv("project:alpha/*"), _deleg("project:alpha/*")],
         "INTERNAL", False),
        (2, ALICE, BOB, [_recv("project:alpha/a")], "INTERNAL", False),
    ])
    import copy
    bad = copy.deepcopy(leaf)
    sig = bad["signatures"][0]["sig"]
    bad["signatures"][0]["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(AATPError) as ei:
        _verify(bad, chain, {OWNER})
    assert ei.value.code == "ERR_SIGNATURE_INVALID"
