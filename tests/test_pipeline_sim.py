"""Coordinator -> Coder -> Reviewer pipeline, in-process (no HTTP).

Mirrors docs/superpowers/specs/2026-10-13-aatp-policy-wiring-pipeline-sim-design.md
section 3 with a real attenuated grant chain and the real ``aatp.policy.evaluate``:
C delegates to A, A attenuates into a narrower leaf for B, B receives under that
leaf, and the run is only complete when the audit log carries the whole chain.

Fixtures come from the two wiring modules they were written with:
``tests/test_audit_wiring.py`` (agents, OFFER parts, sealed packets, audit log)
and ``tests/test_policy_wiring.py`` (grant builder, real-policy closure).
"""
import json

from aatp.b64 import b64u, b64u_dec
from aatp.canon import parse_jcs
from aatp.card import CardCache, verify_card
from aatp.dsse import PT_MESSAGE, verify_envelope
from aatp.grants import grant_id_of
from aatp.node import DagStore
from aatp.quarantine import Quarantine
from aatp.transfer import TransferReceiver

from tests.test_audit_wiring import _Agent, _offer_parts, _read_log, _sealed
from tests.test_policy_wiring import _grant, _real_policy

NOW = "2026-10-02T00:00:00Z"
RECV_ACT = "aatp.artifact.receive"
SEND_RES = "project:alpha/*"
RECV_RES = "project:alpha/src/*"
TX = "tx_pipe"


def _grant_body(env: dict) -> dict:
    """The signed body behind a grant envelope (its ``grant_id`` source)."""
    return parse_jcs(b64u_dec(env["payload"]))


def _world3(tmp_path):
    """Three card-verified agents: Coordinator C, Coder A, Reviewer B."""
    C = _Agent(0xC3, "kc1", "ec1")
    A = _Agent(0xA1, "ka1", "ea1")
    B = _Agent(0xB2, "kb1", "eb2")
    cards = {a.agent_id: a.card for a in (C, A, B)}
    for name, a in (("c", C), ("a", A), ("b", B)):
        verify_card(a.card_env, a.agent_id,
                    CardCache(str(tmp_path / f"{name}-seq.json")), NOW)
    return C, A, B, cards


def _pipeline(tmp_path):
    """C issues G1 to A; A attenuates it into G2 for B. Returns the pieces."""
    C, A, B, cards = _world3(tmp_path)
    g1_env = _grant(C, A.agent_id,
                    ["aatp.artifact.send", "aatp.grant.delegate", RECV_ACT],
                    SEND_RES, classification_max="INTERNAL")
    g2_env = _grant(A, B.agent_id, [RECV_ACT], RECV_RES,
                    classification_max="INTERNAL",
                    prf=[grant_id_of(_grant_body(g1_env))])
    return C, A, B, cards, g1_env, g2_env


def _receiver(B, cards, tmp_path, tag, **kw):
    """Receiver for B with its own durable stores per ``tag``."""
    return TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid],
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / f"replay-{tag}.json"),
        store_path=str(tmp_path / f"xfer-{tag}.json"), **kw)


def _events(log_path, event):
    """Audit entries of one kind, in chain order."""
    entries = json.loads(log_path.read_text())["entries"]
    return [e["entry"] for e in entries if e["entry"]["event"] == event]


def test_AUT006_pipeline_grant_policy_transfer_audit(tmp_path):
    """AUT-006: grant -> policy -> transfer -> audit as one flow.

    The receiver's default presenter is B, and G2's ``aud`` is B, so the leaf
    satisfies AUT-006 while AUT-001 (prf link to G1), AUT-002 (attenuation)
    and AUT-003 (G1 carries aatp.grant.delegate) are all exercised on the way.
    """
    C, A, B, cards, g1_env, g2_env = _pipeline(tmp_path)
    files = [("src/app.py", b"print('halo')\n", False),
             ("src/util.py", b"def add(a, b):\n    return a + b\n", False),
             ("README.md", b"# demo project alpha\n", False)]
    parts = _offer_parts(A, B, files, tx_id=TX, chunk_size=16)
    log = tmp_path / "audit.json"
    recv = _receiver(B, cards, tmp_path, "happy", trusted={A.agent_id},
                     audit_log_path=str(log),
                     policy_fn=_real_policy(cards, {C.agent_id, A.agent_id}),
                     grant_leaf_env=g2_env, grant_chain_envs=[g1_env],
                     roots={C.agent_id, A.agent_id},
                     policy_action=RECV_ACT, policy_resource=RECV_RES)
    out = recv.receive_control(
        _sealed(A, B, "OFFER", parts["body"], corr={"transfer_id": TX}), now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"
    for i in range(parts["total"]):
        recv.receive_chunk({"transfer_id": TX, "index": i,
                            "data": b64u(parts["cts"][i])}, now=NOW)
    out = recv.receive_control(
        _sealed(A, B, "COMPLETE",
                {"transfer_id": TX, "total_chunks": parts["total"]},
                corr={"transfer_id": TX}), now=NOW)
    rcpt = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rcpt["type"] == "RECEIPT"
    assert rcpt["body"]["outcome"] == "accepted"
    assert rcpt["body"]["content_root"] == parts["cr"]
    assert recv.state_of(TX) == "COMPLETE"

    q = Quarantine()
    q.place(parts["cr"], parts["node_id"],
            [{"scanner_name": "demo", "scanner_version": "0.1",
              "verdict": "clean", "at": NOW}])
    assert q.state_of(parts["cr"])["state"] == "accepted"

    events = [e["entry"]["event"] for e in _read_log(tmp_path)["entries"]]
    for required in ("message_received", "transfer_state", "chunk_verified",
                     "artifact_verified", "policy_decision"):
        assert required in events, f"missing audit event: {required}"
    allowed = _events(log, "policy_decision")
    assert [e["decision"] for e in allowed] == ["allow"]
    assert allowed[0]["rule_id"] == "POLICY-ALLOW"
    states = [e.get("state") for e in _events(log, "transfer_state")]
    assert states == ["ACCEPTED", "COMPLETE"], states
    assert [e["index"] for e in _events(log, "chunk_verified")] == \
        list(range(parts["total"]))
    verified = _events(log, "artifact_verified")
    assert [e["content_root"] for e in verified] == [parts["cr"]]


def test_AUT006_AUT002_pipeline_negative_paths(tmp_path):
    """Both spec denies: no grant leaf (AUT-006) and class over grant (AUT-002)."""
    C, A, B, cards, g1_env, _ = _pipeline(tmp_path)
    roots = {C.agent_id, A.agent_id}

    # (a) policy active, OFFER arrives with no grant leaf -> AUT-006 deny.
    parts = _offer_parts(A, B, [("src/x.py", b"x = 1\n", False)],
                         tx_id="tx_nogrant", chunk_size=16)
    log_a = tmp_path / "audit-a.json"
    recv = _receiver(B, cards, tmp_path, "nogrant", trusted={A.agent_id},
                     audit_log_path=str(log_a),
                     policy_fn=_real_policy(cards, roots),
                     grant_leaf_env=None, roots=roots,
                     policy_action=RECV_ACT, policy_resource=RECV_RES)
    out = recv.receive_control(
        _sealed(A, B, "OFFER", parts["body"],
                corr={"transfer_id": "tx_nogrant"}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"
    # The resource is configured, so the deny is the missing leaf and not the
    # fail-closed "policy_resource must be configured" shortcut.
    assert rej["body"]["detail"] == "policy denied: AUT-006"
    assert recv.state_of("tx_nogrant") == "REJECTED"
    denied_a = _events(log_a, "policy_decision")
    assert [(e["decision"], e["rule_id"]) for e in denied_a] == \
        [("deny", "AUT-006")]

    # (b) grant max=PUBLIC but the OFFER claims RESTRICTED -> AUT-002 deny.
    parts2 = _offer_parts(A, B, [("src/y.py", b"y = 2\n", False)],
                          tx_id="tx_class", chunk_size=16)
    parts2["body"]["classification"] = "RESTRICTED"
    weak_env = _grant(A, B.agent_id, [RECV_ACT], RECV_RES,
                      classification_max="PUBLIC",
                      prf=[grant_id_of(_grant_body(g1_env))])
    log_b = tmp_path / "audit-b.json"
    recv2 = _receiver(B, cards, tmp_path, "class", trusted={A.agent_id},
                      audit_log_path=str(log_b),
                      policy_fn=_real_policy(cards, roots),
                      grant_leaf_env=weak_env, grant_chain_envs=[g1_env],
                      roots=roots, policy_action=RECV_ACT,
                      policy_resource=RECV_RES)
    out = recv2.receive_control(
        _sealed(A, B, "OFFER", parts2["body"],
                corr={"transfer_id": "tx_class"}), now=NOW)
    rej2 = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej2["type"] == "REJECT"
    assert rej2["body"]["code"] == "ERR_POLICY_DENIED"
    assert rej2["body"]["detail"] == "policy denied: AUT-002"
    assert recv2.state_of("tx_class") == "REJECTED"
    denied_b = _events(log_b, "policy_decision")
    assert [(e["decision"], e["rule_id"]) for e in denied_b] == \
        [("deny", "AUT-002")]
