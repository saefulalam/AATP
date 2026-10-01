"""M5 transfer receiver + messages (TRF-001..026, MSG-001..006).

TDD: written before aatp/messages.py and aatp/transfer.py exist (RED first).
Fixtures build three agents (A sender, B receiver, C third party) with
genesis cards verified via verify_card, plus X25519 enc keys in KeyStores.
"""
import secrets

import pytest

from aatp import artifact as artifact_mod
from aatp import node as node_mod
from aatp import chunks as chunk_mod
from aatp import seal as seal_mod
from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs
from aatp.card import CardCache, verify_card
from aatp.dsse import PT_CARD, PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import AATPError
from aatp.ids import derive_agent_id
from aatp.messages import build_message, shift_ts
from aatp.node import DagStore
from aatp.seal import KeyStore
from aatp.signer import SoftwareSigner
from aatp.transfer import (
    TransferReceiver,
    sender_due_chunks,
    validate_have_ranges,
)

ISSUED = "2026-10-01T00:00:00Z"
CARD_EXP = "2026-10-08T00:00:00Z"
SIGN_EXP = "2027-10-01T00:00:00Z"
NOW = "2026-10-02T00:00:00Z"


class _Agent:
    def __init__(self, seed_byte, sign_kid, enc_kid):
        self.signer = SoftwareSigner.from_seed(bytes([seed_byte]) * 32, sign_kid)
        self.agent_id = derive_agent_id(self.signer.public_key_raw())
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        # CRY-006: generate() draws from the OS CSPRNG via OpenSSL.
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


class _World:
    def __init__(self, tmp_path):
        self.A = _Agent(0xA1, "ka1", "ea1")
        self.B = _Agent(0xB2, "kb1", "eb1")
        self.C = _Agent(0xC3, "kc1", "ec1")
        self.cards = {a.agent_id: a.card for a in (self.A, self.B, self.C)}
        for name, a in (("a", self.A), ("b", self.B), ("c", self.C)):
            verify_card(a.card_env, a.agent_id,
                        CardCache(str(tmp_path / f"{name}-seq.json")), NOW)
        self.tmp = tmp_path

    def receiver(self, tmp_sub=None, policy="lazy"):
        base = tmp_sub or self.tmp
        return TransferReceiver(
            agent_id=self.B.agent_id, signer=self.B.signer,
            keystore=self.B.keystore,
            card_resolver=lambda aid: self.cards[aid],
            trusted={self.A.agent_id, self.C.agent_id},
            own_card=self.B.card,
            dag=DagStore(parent_policy=policy),
            replay_path=str(base / "replay.json"),
            store_path=str(base / "xfer.json"))

    def actor_key(self, actor):
        return b64u_dec(self.cards[actor]["signing_key"]["public_key"])


def _offer_parts(W, files, chunk_size=8, tx_id="tx_test1", task_id="task_1",
                 now=NOW, offer_life=3600, parent_policy="lazy"):
    manifest, stream, cr = artifact_mod.build(files)
    anode, anid = node_mod.make_node(
        cr, [], "create", W.A.agent_id, task_id,
        {"kind": "human", "assurance": "self_asserted"}, now)
    nenv = node_mod.make_node_envelope(anode, W.A.signer)
    cek = secrets.token_bytes(32)
    total = (len(stream) + chunk_size - 1) // chunk_size if stream else 0
    cts = chunk_mod.encrypt_chunks(cek, stream, chunk_size, cr, tx_id) if total else []
    wrap = seal_mod.wrap_cek(cek, cr, W.A.agent_id, W.B.agent_id,
                             W.B.enc_key_id, tx_id, W.B.enc_pub)
    body = {"transfer_id": tx_id, "content_root": cr, "manifest": manifest,
            "node_env": nenv, "chunk_size": chunk_size, "total_chunks": total,
            "stream_len": len(stream), "cipher": "chacha20poly1305",
            "wraps": [wrap], "parent_policy": parent_policy,
            "classification": "INTERNAL",
            "expires_at": shift_ts(now, offer_life)}
    return {"manifest": manifest, "stream": stream, "cr": cr, "node": anode,
            "node_id": anid, "cek": cek, "cts": cts, "total": total, "body": body}


def _sealed(W, sender, recipient, msg_type, body, now=NOW, lifetime=3600,
            msg_id=None, corr=None):
    msg = build_message(msg_type, sender.agent_id, sender.signer.key_id(),
                        recipient.agent_id, body, now=now, lifetime=lifetime,
                        msg_id=msg_id, corr=corr)
    env = make_envelope(PT_MESSAGE, jcs(msg), sender.signer)
    pkt = seal_mod.seal_packet(recipient.agent_id, recipient.enc_key_id,
                               recipient.enc_pub, env)
    return pkt, msg, env


def _accept_flow(W, recv, parts, tx_id="tx_test1", now=NOW):
    pkt, msg, _env = _sealed(W, W.A, W.B, "OFFER", parts["body"], now=now,
                             corr={"transfer_id": tx_id})
    out = recv.receive_control(pkt, now=now)
    assert len(out) == 1
    acc = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw(),
                          key_id="kb1")
    assert acc["type"] == "ACCEPT" and acc["body"] == {"transfer_id": tx_id}
    assert acc["corr"]["in_reply_to"] == msg["id"]
    return msg


def _chunk(tx_id, i, ct):
    return {"transfer_id": tx_id, "index": i, "data": b64u(ct)}


def test_MSG002_recipient_mismatch(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_n04")
    # Sealed TO B, but inner recipient is C.
    msg = build_message("OFFER", W.A.agent_id, "ka1", W.C.agent_id,
                        parts["body"], now=NOW, lifetime=3600,
                        corr={"transfer_id": "tx_n04"})
    env = make_envelope(PT_MESSAGE, jcs(msg), W.A.signer)
    pkt = seal_mod.seal_packet(W.B.agent_id, W.B.enc_key_id, W.B.enc_pub, env)
    with pytest.raises(AATPError) as ei:
        recv.receive_control(pkt, now=NOW)
    assert ei.value.code == "ERR_RECIPIENT_MISMATCH"


def test_MSG003_expired_message(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_n05",
                         now="2026-10-01T00:00:00Z")
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", parts["body"],
                          now="2026-10-01T00:00:00Z", lifetime=3600,
                          corr={"transfer_id": "tx_n05"})
    with pytest.raises(AATPError) as ei:
        recv.receive_control(pkt, now=NOW)
    assert ei.value.code == "ERR_MESSAGE_EXPIRED"


def test_MSG003_lifetime_exceeds_max(tmp_path):
    W = _World(tmp_path)
    with pytest.raises(AATPError) as ei:
        build_message("OFFER", W.A.agent_id, "ka1", W.B.agent_id, {},
                      now=NOW, lifetime=90000)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_GEN006_bad_message_id(tmp_path):
    W = _World(tmp_path)
    with pytest.raises(AATPError) as ei:
        build_message("OFFER", W.A.agent_id, "ka1", W.B.agent_id, {},
                      now=NOW, lifetime=60, msg_id="bad id!")
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
    with pytest.raises(AATPError) as ei:
        build_message("OFFER", W.A.agent_id, "ka1", W.B.agent_id, {},
                      now=NOW, lifetime=60, msg_id="x" * 129)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_MSG004_replay_detected_persistent(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_n06")
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", parts["body"],
                          corr={"transfer_id": "tx_n06"})
    first = recv.receive_control(pkt, now=NOW)
    # Restart: new instance, same store files.
    recv2 = W.receiver()
    with pytest.raises(AATPError) as ei:
        recv2.receive_control(pkt, now=NOW)
    assert ei.value.code == "ERR_REPLAY_DETECTED"
    assert ei.value.previous_response == first


def test_MSG005_retransmit_returns_same_response(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_msg005")
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", parts["body"],
                          corr={"transfer_id": "tx_msg005"})
    first = recv.receive_control(pkt, now=NOW)
    with pytest.raises(AATPError) as ei:
        recv.receive_control(pkt, now=NOW)
    assert ei.value.code == "ERR_REPLAY_DETECTED"
    assert ei.value.previous_response == first
    assert ei.value.previous_response[0]["payloadType"] == PT_MESSAGE


def test_MSG006_unsupported_message(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    raw = {"v": "0.2", "type": "FUTURE_X", "id": "msg_future1",
           "sender": W.A.agent_id, "sender_key_id": "ka1",
           "recipient": W.B.agent_id, "created_at": NOW,
           "expires_at": shift_ts(NOW, 600), "corr": {}, "crit": [],
           "body": {}}
    env = make_envelope(PT_MESSAGE, jcs(raw), W.A.signer)
    pkt = seal_mod.seal_packet(W.B.agent_id, W.B.enc_key_id, W.B.enc_pub, env)
    with pytest.raises(AATPError) as ei:
        recv.receive_control(pkt, now=NOW)
    assert ei.value.code == "ERR_UNSUPPORTED_MESSAGE"


def test_TRF001_offer_node_root_mismatch(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_trf001")
    lied = "sha256:" + "1" * 64
    wrap = seal_mod.wrap_cek(parts["cek"], lied, W.A.agent_id, W.B.agent_id,
                             W.B.enc_key_id, "tx_trf001", W.B.enc_pub)
    body = dict(parts["body"], content_root=lied, wraps=[wrap])
    pkt, msg, _e = _sealed(W, W.A, W.B, "OFFER", body,
                           corr={"transfer_id": "tx_trf001"})
    out = recv.receive_control(pkt, now=NOW)
    assert len(out) == 1
    rej = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_ARTIFACT_HASH_MISMATCH"


def test_TRF002_stream_len_mismatch(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_trf002a")
    body = dict(parts["body"], stream_len=parts["body"]["stream_len"] + 1)
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", body,
                          corr={"transfer_id": "tx_trf002a"})
    out = recv.receive_control(pkt, now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_MANIFEST_INVALID"


def test_TRF002_total_chunks_mismatch(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_trf002b")
    body = dict(parts["body"], total_chunks=parts["body"]["total_chunks"] + 1)
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", body,
                          corr={"transfer_id": "tx_trf002b"})
    out = recv.receive_control(pkt, now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_MANIFEST_INVALID"


def test_TRF005_offer_expired(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_trf005",
                         offer_life=-600)
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", parts["body"],
                          corr={"transfer_id": "tx_trf005"})
    out = recv.receive_control(pkt, now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_MESSAGE_EXPIRED"


def test_TRF003_no_wrap_for_receiver(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], tx_id="tx_trf003")
    other = seal_mod.wrap_cek(parts["cek"], parts["cr"], W.A.agent_id,
                              W.C.agent_id, W.C.enc_key_id, "tx_trf003",
                              W.C.enc_pub)
    body = dict(parts["body"], wraps=[other])
    pkt, _m, _e = _sealed(W, W.A, W.B, "OFFER", body,
                          corr={"transfer_id": "tx_trf003"})
    out = recv.receive_control(pkt, now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_DECRYPT_FAILED"


def test_TRF011_chunk_bad_index_and_unknown_transfer(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("a.txt", b"hi", False)], chunk_size=8,
                         tx_id="tx_trf011")
    assert parts["total"] == 1
    _accept_flow(W, recv, parts, tx_id="tx_trf011")
    with pytest.raises(AATPError) as ei:
        recv.receive_chunk(_chunk("tx_nope", 0, parts["cts"][0]), now=NOW)
    assert ei.value.code == "ERR_TRANSFER_NOT_FOUND"
    with pytest.raises(AATPError) as ei:
        recv.receive_chunk(_chunk("tx_trf011", 5, parts["cts"][0]), now=NOW)
    assert ei.value.code == "ERR_SEQUENCE_INVALID"


def test_TRF012_TRF013_duplicate_and_out_of_order(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    files = [("big.bin", b"B" * 320, False)]
    parts = _offer_parts(W, files, chunk_size=8, tx_id="tx_win")
    assert parts["total"] == 40
    _accept_flow(W, recv, parts, tx_id="tx_win")
    # Beyond-window (contiguous -1, window 16): index 20 must fail.
    with pytest.raises(AATPError) as ei:
        recv.receive_chunk(_chunk("tx_win", 20, parts["cts"][20]), now=NOW)
    assert ei.value.code == "ERR_SEQUENCE_INVALID"
    # Out-of-order within window + duplicates are fine.
    for i in (5, 0, 5, 2, 0, 7, 3, 1, 4, 6):
        assert recv.receive_chunk(_chunk("tx_win", i, parts["cts"][i]),
                                  now=NOW) == []
    st = recv.state_of("tx_win")
    assert st == "RECEIVING"  # TRF-025: chunks alone never COMPLETE.
    status = recv.get_status("tx_win", now=NOW)
    body = verify_envelope(status, PT_MESSAGE, W.B.signer.public_key_raw())["body"]
    assert body["have"] == [[0, 7]]


def test_TRF023_bad_have_ranges():
    for bad in ([[0, 5], [3, 7]], [[2, 2], [0, 0]], [[5, 3]], [[-1, 2]],
                [[0, "x"]], "nope", [[0, 2], [2, 4]]):
        with pytest.raises(AATPError) as ei:
            validate_have_ranges(bad)
        assert ei.value.code == "ERR_RESUME_INVALID"
    assert validate_have_ranges([[0, 4]]) == [[0, 4]]
    assert validate_have_ranges([]) == []


def test_TRF024_sender_window():
    assert sender_due_chunks([[0, 0]], 40) == list(range(1, 17))
    assert sender_due_chunks([[0, 4]], 8) == [5, 6, 7]
    assert sender_due_chunks([], 3) == [0, 1, 2]
    assert sender_due_chunks([[0, 7]], 8) == []


def test_N16_partial_complete_stays_receiving(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [("hello.txt", b"hello world #1", False)],
                         chunk_size=5, tx_id="tx_n16")
    assert parts["total"] == 3
    _accept_flow(W, recv, parts, tx_id="tx_n16")
    recv.receive_chunk(_chunk("tx_n16", 0, parts["cts"][0]), now=NOW)
    recv.receive_chunk(_chunk("tx_n16", 1, parts["cts"][1]), now=NOW)
    pkt, _m, _e = _sealed(W, W.A, W.B, "COMPLETE",
                          {"transfer_id": "tx_n16", "total_chunks": 3},
                          corr={"transfer_id": "tx_n16"})
    out = recv.receive_control(pkt, now=NOW)
    assert len(out) == 1
    st = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert st["type"] == "STATUS"
    assert st["body"]["have"] == [[0, 1]]
    assert recv.state_of("tx_n16") == "RECEIVING"


def test_resume_after_disconnect(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    files = [("hello.txt", b"hello world, this is a resume test payload.", False)]
    parts = _offer_parts(W, files, chunk_size=5, tx_id="tx_resume")
    total = parts["total"]
    assert total == 9
    _accept_flow(W, recv, parts, tx_id="tx_resume")
    for i in range(5):
        recv.receive_chunk(_chunk("tx_resume", i, parts["cts"][i]), now=NOW)
    # Disconnect: restart receiver on the same durable files.
    recv2 = W.receiver()
    assert recv2.state_of("tx_resume") == "PAUSED"
    status = recv2.get_status("tx_resume", now=NOW)
    have = verify_envelope(status, PT_MESSAGE,
                           W.B.signer.public_key_raw())["body"]["have"]
    assert have == [[0, 4]]
    for i in sender_due_chunks(have, total):
        recv2.receive_chunk(_chunk("tx_resume", i, parts["cts"][i]), now=NOW)
    pkt, _m, _e = _sealed(W, W.A, W.B, "COMPLETE",
                          {"transfer_id": "tx_resume", "total_chunks": total},
                          corr={"transfer_id": "tx_resume"})
    out = recv2.receive_control(pkt, now=NOW)
    assert len(out) == 1
    rcpt = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw(),
                           key_id="kb1")
    assert rcpt["type"] == "RECEIPT"
    assert rcpt["body"]["outcome"] == "accepted"
    assert rcpt["body"]["content_root"] == parts["cr"]
    assert rcpt["body"]["node_id"] == parts["node_id"]
    assert recv2.state_of("tx_resume") == "COMPLETE"


def test_ART020_zero_chunks_complete(tmp_path):
    W = _World(tmp_path)
    recv = W.receiver()
    parts = _offer_parts(W, [], tx_id="tx_empty")
    assert parts["total"] == 0 and parts["stream"] == b""
    _accept_flow(W, recv, parts, tx_id="tx_empty")
    pkt, _m, _e = _sealed(W, W.A, W.B, "COMPLETE",
                          {"transfer_id": "tx_empty", "total_chunks": 0},
                          corr={"transfer_id": "tx_empty"})
    out = recv.receive_control(pkt, now=NOW)
    rcpt = verify_envelope(out[0], PT_MESSAGE, W.B.signer.public_key_raw())
    assert rcpt["type"] == "RECEIPT"
    assert rcpt["body"]["outcome"] == "accepted"
    assert rcpt["body"]["content_root"] == parts["cr"]
