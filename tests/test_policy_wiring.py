"""Policy gate wired into the OFFER path (D-044, AUT-006 / SEC-002).

Reuses the agent/offer helpers from tests/test_audit_wiring.py by import.

The gate's default presenter is the RECEIVER, not the OFFER sender: the action
being granted (``aatp.artifact.receive``) is the receiver's own, and blueprint
section 10.1 issues the example leaf to ``aud`` = the receiving agent. The
sender stays bound by pinned trust (ID-003) in ``receive_control``. So the
grants here are issued to the receiver B.
"""
import json

from aatp.b64 import b64u_dec
from aatp.canon import jcs
from aatp.dsse import PT_GRANT, PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import err
from aatp.node import DagStore
from aatp.policy import evaluate
from aatp.transfer import TransferReceiver

from tests.test_audit_wiring import _offer_parts, _sealed, _world

NOW = "2026-10-02T00:00:00Z"
TX = "tx_policy"
RECV_ACT = "aatp.artifact.receive"
RES = "project:alpha/*"


def _grant(issuer, audience, acts, res=RES, classification_max="INTERNAL",
           nbf="2026-10-01T00:00:00Z", exp="2026-10-03T00:00:00Z", prf=()):
    body = {
        "v": "0.2", "iss": issuer.agent_id, "aud": audience,
        "cap": [{"act": a, "res": res} for a in acts],
        "nbf": nbf, "exp": exp, "prf": list(prf),
        "constraints": {"classification_max": classification_max,
                        "export": False},
    }
    return make_envelope(PT_GRANT, jcs(body), issuer.signer)


def _receiver(B, cards, tmp_path, **kw):
    return TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid], trusted=set(cards.keys()),
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / "replay.json"),
        store_path=str(tmp_path / "xfer.json"), **kw)


def _real_policy(cards, roots):
    """Injected policy calling the real aatp.policy.evaluate."""
    def policy(req):
        return evaluate(req, roots=roots,
                        key_resolver=lambda aid: b64u_dec(
                            cards[aid]["signing_key"]["public_key"]),
                        presenter=req["presenter"], now=req["now"])
    return policy


def _decisions(tmp_path, decision):
    entries = json.loads((tmp_path / "audit.json").read_text())["entries"]
    return [e["entry"] for e in entries if e["entry"]["event"] == "policy_decision"
            and e["entry"]["decision"] == decision]


ALLOW = {"decision": "allow", "rule_id": "POLICY-ALLOW", "code": None}


def test_AUT006_wired_offer_accepted_when_policy_allows(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"policy ok", False)], tx_id=TX)
    leaf = _grant(A, B.agent_id, [RECV_ACT])
    recv = _receiver(B, cards, tmp_path, policy_fn=lambda req: dict(ALLOW),
                     grant_leaf_env=leaf, policy_resource=RES,
                     audit_log_path=str(tmp_path / "audit.json"))
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"
    assert recv.state_of(TX) == "ACCEPTED"
    allowed = _decisions(tmp_path, "allow")
    assert len(allowed) == 1
    assert allowed[0]["rule_id"] == "POLICY-ALLOW"
    assert allowed[0]["transfer_id"] == TX


def test_AUT006_wired_offer_denied_without_grant(tmp_path):
    """Fail closed: policy active but no grant leaf = deny, never implicit allow."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"no grant", False)], tx_id=TX)
    recv = _receiver(B, cards, tmp_path, policy_fn=lambda req: dict(ALLOW),
                     grant_leaf_env=None, policy_resource=RES,
                     audit_log_path=str(tmp_path / "audit.json"))
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"
    assert recv.state_of(TX) == "REJECTED"
    denied = _decisions(tmp_path, "deny")
    assert len(denied) == 1
    assert denied[0]["rule_id"] == "AUT-006"
    assert denied[0]["transfer_id"] == TX


def test_AUT002_wired_offer_denied_by_policy_code(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"denied", False)], tx_id=TX)
    leaf = _grant(A, B.agent_id, [RECV_ACT])
    seen = {}

    def policy(req):
        seen.update(req)
        return {"decision": "deny", "rule_id": "AUT-002",
                "code": "ERR_GRANT_ATTENUATION"}

    recv = _receiver(B, cards, tmp_path, policy_fn=policy, grant_leaf_env=leaf,
                     roots={A.agent_id}, policy_resource=RES,
                     revoked_grants=["sha256:" + "ab" * 32])
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_GRANT_ATTENUATION"
    # The gate hands the policy engine the OFFER's own attributes.
    assert seen["action"] == RECV_ACT
    assert seen["resource"] == RES
    assert seen["classification"] == "INTERNAL"
    assert seen["consumption_mode"] == "data_only"
    assert seen["presenter"] == B.agent_id
    assert seen["now"] == NOW
    assert seen["grant_leaf_env"] == leaf
    assert seen["roots"] == {A.agent_id}
    assert seen["revoked"] == {"sha256:" + "ab" * 32}
    assert seen["grant_chain_envs"] == []


def test_AUT_wired_offer_policy_exception_internal(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"boom", False)], tx_id=TX)
    leaf = _grant(A, B.agent_id, [RECV_ACT])

    def boom(req):
        raise RuntimeError("policy exploded")

    recv = _receiver(B, cards, tmp_path, policy_fn=boom, grant_leaf_env=leaf,
                     policy_resource=RES)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_INTERNAL"
    assert recv.state_of(TX) == "REJECTED"


def test_AUT001_wired_offer_error_code_maps_to_its_rule(tmp_path):
    """A policy AATPError names the rule its code belongs to, not AUT-004."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"mapping", False)], tx_id=TX)
    leaf = _grant(A, B.agent_id, [RECV_ACT])

    def bad_leaf(req):
        raise err("ERR_SIGNATURE_INVALID", "leaf signature bad")

    recv = _receiver(B, cards, tmp_path, policy_fn=bad_leaf, grant_leaf_env=leaf,
                     policy_resource=RES)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["body"]["code"] == "ERR_SIGNATURE_INVALID"
    assert rej["body"]["detail"] == "policy denied: AUT-001"


def test_AUT_wired_real_policy_evaluate_end_to_end(tmp_path):
    """Wire the real aatp.policy.evaluate (not a stub) into the OFFER path.

    Blueprint section 10.1: the leaf is issued to the receiver and carries
    aatp.artifact.receive, which is exactly the default presenter's own action.
    """
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"real policy", False)], tx_id=TX)
    leaf = _grant(A, B.agent_id, [RECV_ACT])
    recv = _receiver(B, cards, tmp_path, policy_fn=_real_policy(cards, {A.agent_id}),
                     grant_leaf_env=leaf, roots={A.agent_id},
                     policy_action=RECV_ACT, policy_resource=RES)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"


def test_AUT_wired_policy_presenter_overrides_receiver(tmp_path):
    """policy_presenter is the escape hatch for a sender-audience grant."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"override", False)], tx_id=TX)
    leaf = _grant(A, A.agent_id, [RECV_ACT])
    recv = _receiver(B, cards, tmp_path, policy_fn=_real_policy(cards, {A.agent_id}),
                     grant_leaf_env=leaf, roots={A.agent_id},
                     policy_action=RECV_ACT, policy_resource=RES,
                     policy_presenter=A.agent_id)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"


def test_AUT006_wired_offer_denied_when_resource_unconfigured(tmp_path):
    """policy_resource=None fails closed with a clear reason, not a mismatch."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"unconfigured", False)], tx_id=TX)
    leaf = _grant(A, B.agent_id, [RECV_ACT])
    recv = _receiver(B, cards, tmp_path, policy_fn=lambda req: dict(ALLOW),
                     grant_leaf_env=leaf, policy_resource=None)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"
    assert rej["body"]["detail"] == "policy_resource must be configured"
    assert recv.state_of(TX) == "REJECTED"


def test_SEC002_instructions_allowed_requires_grant(tmp_path):
    """SEC-002: instructions_allowed needs an aatp.artifact.instruct cap."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"instruct", False)], tx_id=TX)
    parts["body"]["consumption_mode"] = "instructions_allowed"
    leaf = _grant(A, B.agent_id, [RECV_ACT])
    recv = _receiver(B, cards, tmp_path, policy_fn=_real_policy(cards, {A.agent_id}),
                     grant_leaf_env=leaf, roots={A.agent_id},
                     policy_action=RECV_ACT, policy_resource=RES)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"


def test_default_no_policy_behaviour_unchanged(tmp_path):
    """policy_fn=None must be a true no-op (regression guard)."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"unchanged", False)], tx_id=TX)
    recv = _receiver(B, cards, tmp_path)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": TX}), now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"
