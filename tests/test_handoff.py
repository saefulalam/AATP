"""M6 two-phase handoff with lease (blueprint section 10.3, HND-001..006, N20).

TDD RED: written before aatp/handoff.py exists.
"""
import pytest

from aatp.canon import jcs
from aatp.dsse import PT_MESSAGE, verify_envelope
from aatp.errors import AATPError
from aatp.grants import grant_id_of, make_grant_envelope
from aatp.handoff import HandoffStore
from aatp.ids import derive_agent_id
from aatp.messages import validate_message
from aatp.signer import SoftwareSigner

T_NOW = "2026-10-01T12:00:00Z"
T_LEASE = "2026-10-01T13:00:00Z"
T_LATE = "2026-10-01T14:00:00Z"
T_DEADLINE = "2026-10-02T00:00:00Z"
T_NBF = "2026-10-01T00:00:00Z"
T_EXP = "2026-10-02T00:00:00Z"

HANDOFF_ACT = "aatp.task.handoff"
DELEGATE_ACT = "aatp.grant.delegate"
RESOURCE = "project:alpha/report"

NODE_A = "sha256:" + "ab" * 32
NODE_B = "sha256:" + "cd" * 32


def _signer(seed_byte, key_id):
    return SoftwareSigner.from_seed(bytes([seed_byte]) * 32, key_id)


def _actor(seed_byte):
    return derive_agent_id(_signer(seed_byte, "k").public_key_raw())


OWNER = _actor(1)
ALICE = _actor(2)
BOB = _actor(3)

_SIGNERS = {OWNER: _signer(1, "k-owner"), ALICE: _signer(2, "k-alice"),
            BOB: _signer(3, "k-bob")}


def _resolver():
    pubs = {a: s.public_key_raw() for a, s in _SIGNERS.items()}

    def resolve(agent_id):
        try:
            return pubs[agent_id]
        except KeyError:
            raise AATPError("ERR_AUTH_FAILED", 1102, "unknown agent") from None

    return resolve


def _grant(iss, aud, caps, prf=()):
    return {"v": "0.2", "iss": iss, "aud": aud, "cap": list(caps),
            "nbf": T_NBF, "exp": T_EXP, "prf": list(prf),
            "constraints": {"classification_max": "INTERNAL", "export": False}}


def _cap(act, res):
    return {"act": act, "res": res}


def _chain_envs(root_caps, leaf_caps):
    """Root OWNER->ALICE then leaf ALICE->BOB; returns (leaf_env, [root_env])."""
    root = _grant(OWNER, ALICE, root_caps)
    leaf = _grant(ALICE, BOB, leaf_caps, prf=[grant_id_of(root)])
    return (make_grant_envelope(leaf, _signer(2, "k-alice")),
            [make_grant_envelope(root, _SIGNERS[OWNER])])


def _offer_body(leaf_env, resource=RESOURCE, lease=T_LEASE,
                constraints=None, handoff_id="handoff_1", task_id="task_1"):
    task = {"task_id": task_id, "title": "Triage report",
            "objective": "Summarize overnight alerts"}
    if constraints is not None:
        task["constraints"] = dict(constraints)
    return {"handoff_id": handoff_id, "task": task,
            "input_node_ids": [NODE_A, NODE_B], "grant_env": leaf_env,
            "expected_outputs": ["report"], "deadline": T_DEADLINE,
            "lease_expires_at": lease,
            "policy_context": {"resource": resource}}


def _offer(store, leaf_env, chain_envs, **kw):
    body = _offer_body(leaf_env, **kw)
    store.offer(body, T_NOW, grant_chain_envs=chain_envs,
                sender=ALICE, recipient=BOB, roots={OWNER},
                key_resolver=_resolver())
    return body


def _std_chain():
    return _chain_envs(
        [_cap(HANDOFF_ACT, "project:alpha/*"),
         _cap(DELEGATE_ACT, "project:alpha/*")],
        [_cap(HANDOFF_ACT, RESOURCE)])


# --- HND-001 ---------------------------------------------------------------

def test_HND001_accept_before_lease_transfers():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    assert store.state_of("handoff_1") == "PENDING"
    assert store.responsible("handoff_1") == ALICE
    env = store.respond("handoff_1", "accept", T_NOW,
                        responder=BOB, signer=_SIGNERS[BOB])
    assert store.state_of("handoff_1") == "ACCEPTED"
    assert store.responsible("handoff_1") == BOB
    msg = validate_message(verify_envelope(env, PT_MESSAGE,
                                           _SIGNERS[BOB].public_key_raw()))
    assert msg["type"] == "HANDOFF_RESPONSE"
    assert msg["sender"] == BOB and msg["recipient"] == ALICE
    assert msg["body"]["handoff_id"] == "handoff_1"
    assert msg["body"]["decision"] == "accept"


# --- HND-002 / N20 ----------------------------------------------------------

def test_HND002_late_accept_void_sender_still_responsible():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    with pytest.raises(AATPError) as ei:
        store.respond("handoff_1", "accept", T_LATE,
                      responder=BOB, signer=_SIGNERS[BOB])
    assert ei.value.code == "ERR_LEASE_EXPIRED"
    assert store.state_of("handoff_1") == "VOID"
    assert store.responsible("handoff_1") == ALICE
    assert store.audit_log("task_1") == []


def test_N20_accept_after_lease_rejected():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    with pytest.raises(AATPError) as ei:
        store.respond("handoff_1", "accept", T_LATE,
                      responder=BOB, signer=_SIGNERS[BOB])
    assert ei.value.code == "ERR_LEASE_EXPIRED"


# --- HND-003 ----------------------------------------------------------------

def test_HND003_grant_broader_than_sender_rejected():
    store = HandoffStore()
    leaf_env, chain = _chain_envs(
        [_cap(HANDOFF_ACT, "project:alpha/*"),
         _cap(DELEGATE_ACT, "project:alpha/*")],
        [_cap(HANDOFF_ACT, "project:beta/*")])
    with pytest.raises(AATPError) as ei:
        _offer(store, leaf_env, chain)
    assert ei.value.code == "ERR_GRANT_ATTENUATION"
    with pytest.raises(AATPError):
        store.state_of("handoff_1")


# --- HND-004 ----------------------------------------------------------------

def test_HND004_input_not_covered_rejected():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    with pytest.raises(AATPError) as ei:
        _offer(store, leaf_env, chain, resource="project:other/z")
    assert ei.value.code == "ERR_POLICY_DENIED"


# --- HND-005 ----------------------------------------------------------------

def test_HND005_conditional_accept_requires_matching_conditions():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain, constraints={"mode": "supervised"})
    with pytest.raises(AATPError) as ei:
        store.respond("handoff_1", "accept", T_NOW,
                      responder=BOB, signer=_SIGNERS[BOB])
    assert ei.value.code == "ERR_POLICY_DENIED"
    assert store.state_of("handoff_1") == "PENDING"
    with pytest.raises(AATPError) as ei:
        store.respond("handoff_1", "accept", T_NOW,
                      responder=BOB, signer=_SIGNERS[BOB],
                      conditions={"mode": "unsupervised"})
    assert ei.value.code == "ERR_POLICY_DENIED"
    env = store.respond("handoff_1", "accept", T_NOW,
                        responder=BOB, signer=_SIGNERS[BOB],
                        conditions={"mode": "supervised"})
    assert store.state_of("handoff_1") == "ACCEPTED"
    msg = validate_message(verify_envelope(env, PT_MESSAGE,
                                           _SIGNERS[BOB].public_key_raw()))
    assert msg["body"]["decision"] == "accept"


# --- HND-006 ----------------------------------------------------------------

def test_HND006_audit_appended_on_accept():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    store.respond("handoff_1", "accept", T_NOW,
                  responder=BOB, signer=_SIGNERS[BOB])
    assert store.audit_log("task_1") == [
        {"handoff_id": "handoff_1", "task_id": "task_1",
         "decision": "accept", "at": T_NOW}]
    assert store.audit_log("task_other") == []


# --- lease / shape / replay edges -------------------------------------------

def test_HND_offer_past_lease_malformed():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    with pytest.raises(AATPError) as ei:
        _offer(store, leaf_env, chain, lease=T_NOW)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_HND_malformed_body_rejected():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    body = _offer_body(leaf_env)
    body["input_node_ids"] = ["not-a-digest"]
    with pytest.raises(AATPError) as ei:
        store.offer(body, T_NOW, grant_chain_envs=chain,
                    sender=ALICE, recipient=BOB, roots={OWNER},
                    key_resolver=_resolver())
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_HND_reject_flow_no_audit_sender_responsible():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    env = store.respond("handoff_1", "reject", T_NOW,
                        responder=BOB, signer=_SIGNERS[BOB],
                        code="ERR_POLICY_DENIED")
    assert store.state_of("handoff_1") == "REJECTED"
    assert store.responsible("handoff_1") == ALICE
    assert store.audit_log("task_1") == []
    msg = validate_message(verify_envelope(env, PT_MESSAGE,
                                           _SIGNERS[BOB].public_key_raw()))
    assert msg["body"]["decision"] == "reject"


def test_HND_replay_same_decision_returns_identical_bytes():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    first = store.respond("handoff_1", "accept", T_NOW,
                          responder=BOB, signer=_SIGNERS[BOB])
    second = store.respond("handoff_1", "accept", T_LATE,
                           responder=BOB, signer=_SIGNERS[BOB])
    assert jcs(second) == jcs(first)


def test_HND_conflicting_decision_after_accept_denied():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    store.respond("handoff_1", "accept", T_NOW,
                  responder=BOB, signer=_SIGNERS[BOB])
    with pytest.raises(AATPError) as ei:
        store.respond("handoff_1", "reject", T_NOW,
                      responder=BOB, signer=_SIGNERS[BOB])
    assert ei.value.code == "ERR_POLICY_DENIED"
    assert store.state_of("handoff_1") == "ACCEPTED"


def test_HND_duplicate_offer_rejected():
    store = HandoffStore()
    leaf_env, chain = _std_chain()
    _offer(store, leaf_env, chain)
    with pytest.raises(AATPError) as ei:
        _offer(store, leaf_env, chain)
    assert ei.value.code == "ERR_POLICY_DENIED"


def test_HND_unknown_handoff_rejected():
    store = HandoffStore()
    with pytest.raises(AATPError) as ei:
        store.state_of("nope")
    assert ei.value.code == "ERR_POLICY_DENIED"
    with pytest.raises(AATPError) as ei:
        store.respond("nope", "accept", T_NOW,
                      responder=BOB, signer=_SIGNERS[BOB])
    assert ei.value.code == "ERR_POLICY_DENIED"
