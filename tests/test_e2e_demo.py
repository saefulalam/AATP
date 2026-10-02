"""M7-3 Appendix B end-to-end demo (blueprint section 16, steps 0-12).

TDD RED first: written before aatp/mcp_server.py exists. Three agents
(coordinator C, backend A, security B); every packet/chunk/card travels via
ONE shared Relay. One chunk dropped -> STATUS resume via sender_due_chunks;
RECEIPT accepted; quarantine clean -> accepted; report node N2 (parents [N1])
-> HANDOFF_OFFER -> coordinator accepts before lease.

Handoff direction note: App. B steps 11-12 send the offer Security->Coordinator
and the coordinator accepts, so post-accept responsible == coordinator (HND-001:
recipient after ACCEPTED). The pre-accept responsible == security (sender)
is asserted too.

Never logs keys / CEKs / plaintext.
"""
from aatp import artifact as artifact_mod
from aatp import node as node_mod
from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.card import CardCache, verify_card
from aatp.dsse import PT_CARD, PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import AATPError
from aatp.grants import grant_id_of, make_grant_envelope, verify_chain
from aatp.ids import derive_agent_id
from aatp.messages import build_message, shift_ts
from aatp.node import DagStore
from aatp.seal import KeyStore, seal_packet
from aatp.signer import SoftwareSigner
from aatp.transfer import TransferReceiver, sender_due_chunks

ISSUED = "2026-10-01T00:00:00Z"
CARD_EXP = "2026-10-08T00:00:00Z"
SIGN_EXP = "2027-10-01T00:00:00Z"
NOW = "2026-10-03T00:00:00Z"
T_NBF = "2026-10-01T00:00:00Z"
T_EXP = "2026-10-10T00:00:00Z"
SCAN_RES = "project:demo/scan"
MARKER = b"RELAY-OPACITY-MARKER-9f8e7d6c5b4a"


class _Agent:
    def __init__(self, seed_byte, sign_kid, enc_kid):
        self.signer = SoftwareSigner.from_seed(bytes([seed_byte]) * 32,
                                               sign_kid)
        self.agent_id = derive_agent_id(self.signer.public_key_raw())
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        sk = X25519PrivateKey.generate()
        self.enc_priv = sk.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        self.enc_pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.enc_key_id = enc_kid
        self.keystore = KeyStore({enc_kid: self.enc_priv})
        self.card = {
            "v": "0.2", "agent_id": self.agent_id,
            "genesis_public_key": b64u(self.signer.public_key_raw()),
            "signing_key": {"key_id": sign_kid,
                            "public_key": b64u(self.signer.public_key_raw()),
                            "not_before": ISSUED, "not_after": SIGN_EXP},
            "enc_key": {"key_id": enc_kid, "public_key": b64u(self.enc_pub),
                        "not_before": ISSUED, "not_after": CARD_EXP},
            "key_history": [], "suites": ["AATP-S1"], "seq": 1,
            "issued_at": ISSUED, "expires_at": CARD_EXP,
        }
        self.card_env = make_envelope(PT_CARD, jcs(self.card), self.signer)


def _grant(iss, aud, caps, prf=()):
    return {"v": "0.2", "iss": iss, "aud": aud, "cap": list(caps),
            "nbf": T_NBF, "exp": T_EXP, "prf": list(prf),
            "constraints": {"classification_max": "CONFIDENTIAL",
                            "export": False}}


def test_appendixB_coordinator_backend_security(tmp_path):
    from aatp.handoff import HandoffStore
    from aatp.mcp_server import (Context, aatp_fetch, aatp_handoff,
                                 aatp_offer, aatp_provenance, aatp_verify)
    from aatp.quarantine import Quarantine
    from aatp.transport.relay import Relay

    C = _Agent(0xC0, "kc1", "ec1")  # coordinator (root)
    A = _Agent(0xA1, "ka1", "ea1")  # backend
    B = _Agent(0xB2, "kb1", "eb1")  # security
    cards = {x.agent_id: x.card for x in (C, A, B)}
    for tag, ag in (("c", C), ("a", A), ("b", B)):
        verify_card(ag.card_env, ag.agent_id,
                    CardCache(str(tmp_path / f"{tag}-seq.json")), NOW)
    pubs = {aid: b64u_dec(c["signing_key"]["public_key"])
            for aid, c in cards.items()}

    def key_resolver(aid):
        try:
            return pubs[aid]
        except KeyError:
            raise AATPError("ERR_AUTH_FAILED", 1102, "unknown agent") from None

    relay = Relay()
    # Cards are published via the relay (opaque store; verification is the
    # receiver's job).
    for ag in (C, A, B):
        relay.put_card(ag.agent_id, ag.card_env)

    # -- Step 0: G1 Coordinator->Backend; G2 Backend->Security (delegated,
    # attenuated from G1: child.iss == parent.aud per AUT-002) ------------
    G1 = _grant(C.agent_id, A.agent_id,
                [{"act": "aatp.task.accept", "res": "project:demo/*"},
                 {"act": "aatp.grant.delegate",
                  "res": "project:demo/*"}])
    G1env = make_grant_envelope(G1, C.signer)
    G2 = _grant(A.agent_id, B.agent_id,
                [{"act": "aatp.task.accept", "res": SCAN_RES}],
                prf=[grant_id_of(G1)])
    G2env = make_grant_envelope(G2, A.signer)
    verify_chain(G1env, [], {C.agent_id}, NOW, "aatp.task.accept",
                 "project:demo/job", A.agent_id, key_resolver=key_resolver)
    verify_chain(G2env, [G1env], {C.agent_id}, NOW, "aatp.task.accept",
                 SCAN_RES, B.agent_id, key_resolver=key_resolver)

    # -- Shared state: one DAG, one handoff store, one quarantine ------------
    dag = DagStore()
    handoff = HandoffStore()
    quarantine = Quarantine()

    def ctx_for(ag, recv=None):
        return Context(agent=ag, cards=cards,
                       seq_dir=str(tmp_path), dag=dag, relay=relay,
                       quarantine=quarantine, handoff=handoff,
                       roots={C.agent_id}, key_resolver=key_resolver,
                       trusted={C.agent_id, A.agent_id, B.agent_id},
                       now=NOW, receiver=recv)

    recvB = TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid],
        trusted={A.agent_id, C.agent_id}, own_card=B.card, dag=dag,
        replay_path=str(tmp_path / "replay.json"),
        store_path=str(tmp_path / "xfer.json"))

    # -- Steps 1-4: Backend builds artifact + N1, offers via relay ------------
    payload = MARKER + b"|scan-target v1|"
    payload = payload + b"." * (60 - len(payload))  # 60 B -> 8 chunks of 8
    assert len(payload) == 60
    ctxA = ctx_for(A)
    offer = aatp_offer(ctxA, [("target.bin", payload, False)], [B],
                       "task_demo_scan", chunk_size=8)
    assert offer["total_chunks"] == 8
    tx = offer["transfer_id"]
    cr = offer["content_root"]
    # Relay opacity: the sealed packet carries no plaintext marker.
    relay.put_packet(offer["packets"][B.agent_id])
    for ch in offer["chunks"]:
        relay.put_chunk(tx, ch["index"], ch["data"])
    assert MARKER not in jcs(offer["packets"][B.agent_id])
    for ch in offer["chunks"]:
        assert MARKER not in b64u_dec(ch["data"])
    assert aatp_verify(ctxA, cr) == {"ok": True, "code": None}

    # -- Step 5: Security receives OFFER via relay -> ACCEPT -----------------
    (pkt,) = relay.take_packets(B.agent_id)
    out = recvB.receive_control(pkt, now=NOW)
    accept = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw(),
                             key_id="kb1")
    assert accept["type"] == "ACCEPT"

    # -- Steps 6-8: stream with one drop (5..7), STATUS resume ---------------
    for i in range(5):  # deliver 0..4 only
        data = relay.get_chunk(tx, i)
        assert data is not None
        recvB.receive_chunk({"transfer_id": tx, "index": i, "data": data},
                            now=NOW)
    assert relay.get_chunk(tx, 5) is not None  # present, "lost in transit"
    ctxB = ctx_for(B, recvB)
    st = aatp_fetch(ctxB, tx)
    assert st == {"have": [[0, 4]], "missing": [5, 6, 7], "total": 8}
    status_env = recvB.get_status(tx, now=NOW)
    status = parse_jcs(b64u_dec(status_env["payload"]))
    assert status["body"]["have"] == [[0, 4]]
    assert sender_due_chunks(status["body"]["have"], 8) == [5, 6, 7]
    for i in (5, 6, 7):
        recvB.receive_chunk(
            {"transfer_id": tx, "index": i,
             "data": relay.get_chunk(tx, i)}, now=NOW)

    # -- Steps 9-10: COMPLETE -> VERIFYING -> RECEIPT accepted ---------------
    cbody = {"transfer_id": tx, "total_chunks": 8}
    cmsg = build_message("COMPLETE", A.agent_id, A.signer.key_id(),
                         B.agent_id, cbody, now=NOW,
                         corr={"transfer_id": tx})
    cenv = make_envelope(PT_MESSAGE, jcs(cmsg), A.signer)
    cpkt = seal_packet(B.agent_id, B.enc_key_id, B.enc_pub, cenv)
    relay.put_packet(cpkt)
    (cpkt_got,) = relay.take_packets(B.agent_id)
    (receipt_env,) = recvB.receive_control(cpkt_got, now=NOW)
    receipt = verify_envelope(receipt_env, PT_MESSAGE,
                              B.signer.public_key_raw(), key_id="kb1")
    assert receipt["body"]["outcome"] == "accepted"
    assert receipt["body"]["content_root"] == cr
    node_id_1 = receipt["body"]["node_id"]
    assert node_id_1 == offer["node_id"]
    # Plaintext reassembled only at the endpoints, never in the relay.
    have_pt = b"".join(
        b64u_dec(recvB._store[tx]["chunks"][str(i)]) for i in range(8))
    assert have_pt == payload
    assert MARKER in have_pt

    # -- Quarantine (M7-1 tie-in): clean scan -> accepted --------------------
    rec = quarantine.place(cr, node_id_1,
                           [{"scanner_name": "demo-scanner",
                             "scanner_version": "1.0", "verdict": "clean",
                             "at": NOW}])
    assert rec["state"] == "accepted"
    assert quarantine.state_of(cr)["state"] == "accepted"

    # -- Provenance: N1 resolvable -------------------------------------------
    prov = aatp_provenance(ctxB, node_id_1)
    assert prov["code"] is None
    assert prov["node"]["content_root"] == cr
    assert prov["ancestry"] == "complete"

    # Steps 11-12: Security report N2 (parents [N1]) -> HANDOFF -----------
    # (App. B says "create"; PRV-006 arity requires create -> 0 parents, so
    # the derived report is a "modify", the closest valid operation.)
    rep_manifest, _rep_stream, rep_cr = artifact_mod.build(
        [("report.txt", b"scan clean: report for task_demo_scan", False)])
    N2, N2_id = node_mod.make_node(rep_cr, [node_id_1], "modify",
                                   B.agent_id, "task_demo_scan",
                                   {"kind": "ai",
                                    "assurance": "self_asserted"}, NOW)
    N2env = node_mod.make_node_envelope(N2, B.signer)
    assert dag.add(N2env, key_resolver) == N2_id
    assert dag.ancestry_status(N2_id) == "complete"
    Gh = _grant(C.agent_id, C.agent_id,
                [{"act": "aatp.task.handoff", "res": SCAN_RES}])
    Ghenv = make_grant_envelope(Gh, C.signer)
    ho = aatp_handoff(ctxB, "task_demo_scan", C.agent_id, Ghenv,
                      handoff_id="handoff_demo_1",
                      input_node_ids=[node_id_1],
                      expected_outputs=["report"],
                      deadline=shift_ts(NOW, 86400),
                      lease_expires_at=shift_ts(NOW, 3600),
                      policy_context={"resource": SCAN_RES},
                      title="scan", objective="review report")
    assert ho == {"handoff_id": "handoff_demo_1", "state": "PENDING"}
    assert handoff.responsible("handoff_demo_1") == B.agent_id
    resp = handoff.respond("handoff_demo_1", "accept", shift_ts(NOW, 600),
                           responder=C.agent_id, signer=C.signer)
    rmsg = parse_jcs(b64u_dec(resp["payload"]))
    assert rmsg["type"] == "HANDOFF_RESPONSE"
    assert handoff.state_of("handoff_demo_1") == "ACCEPTED"
    assert handoff.responsible("handoff_demo_1") == C.agent_id
