"""AUD-001/002 wiring into TransferReceiver (TDD: written before the code)."""
import json

import pytest

from aatp import artifact as artifact_mod
from aatp import chunks as chunk_mod
from aatp import node as node_mod
from aatp import seal as seal_mod
from aatp.b64 import b64u
from aatp.canon import jcs
from aatp.card import CardCache, verify_card
from aatp.dsse import PT_CARD, PT_MESSAGE, make_envelope, verify_envelope
from aatp.ids import derive_agent_id
from aatp.messages import build_message, shift_ts
from aatp.node import DagStore
from aatp.seal import KeyStore
from aatp.signer import SoftwareSigner
from aatp.transfer import TransferReceiver

ISSUED = "2026-10-01T00:00:00Z"
NOW = "2026-10-02T00:00:00Z"


class _Agent:
    def __init__(self, seed_byte, sign_kid, enc_kid):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        self.signer = SoftwareSigner.from_seed(bytes([seed_byte]) * 32, sign_kid)
        self.agent_id = derive_agent_id(self.signer.public_key_raw())
        sk = X25519PrivateKey.generate()
        self.enc_priv = sk.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        self.enc_pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.enc_key_id = enc_kid
        self.keystore = KeyStore({enc_kid: self.enc_priv})
        card = {
            "v": "0.2", "agent_id": self.agent_id,
            "genesis_public_key": b64u(self.signer.public_key_raw()),
            "signing_key": {"key_id": sign_kid,
                            "public_key": b64u(self.signer.public_key_raw()),
                            "not_before": ISSUED,
                            "not_after": "2027-10-01T00:00:00Z"},
            "enc_key": {"key_id": enc_kid, "public_key": b64u(self.enc_pub),
                        "not_before": ISSUED, "not_after": "2026-10-08T00:00:00Z"},
            "key_history": [], "suites": ["AATP-S1"], "seq": 1,
            "issued_at": ISSUED, "expires_at": "2026-10-08T00:00:00Z",
        }
        self.card = card
        self.card_env = make_envelope(PT_CARD, jcs(card), self.signer)


def _world(tmp_path):
    A = _Agent(0xA1, "ka1", "ea1")
    B = _Agent(0xB2, "kb1", "eb1")
    cards = {A.agent_id: A.card, B.agent_id: B.card}
    for name, a in (("a", A), ("b", B)):
        verify_card(a.card_env, a.agent_id,
                    CardCache(str(tmp_path / f"{name}-seq.json")), NOW)
    return A, B, cards


def _offer_parts(A, B, files, tx_id="tx_audit", chunk_size=8, now=NOW):
    manifest, stream, cr = artifact_mod.build(files)
    anode, anid = node_mod.make_node(
        cr, [], "create", A.agent_id, "task_audit",
        {"kind": "human", "assurance": "self_asserted"}, now)
    nenv = node_mod.make_node_envelope(anode, A.signer)
    import secrets
    cek = secrets.token_bytes(32)
    total = (len(stream) + chunk_size - 1) // chunk_size
    cts = chunk_mod.encrypt_chunks(cek, stream, chunk_size, cr, tx_id)
    wrap = seal_mod.wrap_cek(cek, cr, A.agent_id, B.agent_id, B.enc_key_id,
                             tx_id, B.enc_pub)
    body = {"transfer_id": tx_id, "content_root": cr, "manifest": manifest,
            "node_env": nenv, "chunk_size": chunk_size, "total_chunks": total,
            "stream_len": len(stream), "cipher": "chacha20poly1305",
            "wraps": [wrap], "parent_policy": "lazy",
            "classification": "INTERNAL", "expires_at": shift_ts(now, 3600)}
    return {"cr": cr, "cts": cts, "total": total, "body": body,
            "node_id": anid, "manifest": manifest, "stream": stream}


def _sealed(sender, recipient, msg_type, body, now=NOW, corr=None):
    msg = build_message(msg_type, sender.agent_id, sender.signer.key_id(),
                        recipient.agent_id, body, now=now, lifetime=3600,
                        corr=corr)
    env = make_envelope(PT_MESSAGE, jcs(msg), sender.signer)
    pkt = seal_mod.seal_packet(recipient.agent_id, recipient.enc_key_id,
                               recipient.enc_pub, env)
    return pkt


def _receiver(B, cards, tmp_path, **kw):
    return TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid], trusted=set(cards.keys()),
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / "replay.json"),
        store_path=str(tmp_path / "xfer.json"), **kw)


def _read_log(tmp_path):
    return json.loads((tmp_path / "audit.json").read_text())


def test_AUD001_offer_transition_logged(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"audit payload", False)])
    recv = _receiver(B, cards, tmp_path,
                     audit_log_path=str(tmp_path / "audit.json"))
    pkt = _sealed(A, B, "OFFER", parts["body"], corr={"transfer_id": "tx_audit"})
    out = recv.receive_control(pkt, now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"
    log = _read_log(tmp_path)
    assert log["entries"], "audit log must not be empty"
    events = [e["entry"]["event"] for e in log["entries"]]
    assert "message_received" in events
    assert "transfer_state" in events


def test_AUD002_chain_links(tmp_path):
    import hashlib
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"chain payload", False)],
                         chunk_size=8)
    recv = _receiver(B, cards, tmp_path,
                     audit_log_path=str(tmp_path / "audit.json"))
    pkt = _sealed(A, B, "OFFER", parts["body"], corr={"transfer_id": "tx_audit"})
    recv.receive_control(pkt, now=NOW)
    for i in range(parts["total"]):
        recv.receive_chunk({"transfer_id": "tx_audit", "index": i,
                            "data": b64u(parts["cts"][i])}, now=NOW)
    log = _read_log(tmp_path)
    entries = log["entries"]
    assert len(entries) >= 2
    assert entries[0]["prev_hash"] == "00" * 32
    prev = entries[0]["prev_hash"]
    for rec in entries:
        assert rec["prev_hash"] == prev
        want = hashlib.sha256(bytes.fromhex(prev) + jcs(rec["entry"])).hexdigest()
        assert rec["entry_hash"] == want
        prev = rec["entry_hash"]
    assert log["head"] == prev


def test_AUD001_no_secrets_in_audit_entry(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"secret probe bytes", False)])
    recv = _receiver(B, cards, tmp_path,
                     audit_log_path=str(tmp_path / "audit.json"))
    recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                 corr={"transfer_id": "tx_audit"}), now=NOW)
    raw = (tmp_path / "audit.json").read_text()
    assert b"secret probe bytes" not in raw.encode()
    assert "cek" not in raw
    assert "private" not in raw


def test_AUD001_forbidden_field_rejected(tmp_path):
    A, B, cards = _world(tmp_path)
    recv = _receiver(B, cards, tmp_path,
                     audit_log_path=str(tmp_path / "audit.json"))
    from aatp.errors import AATPError
    with pytest.raises(AATPError) as ei:
        recv._audit("transfer_state", cek="b64-of-cek")
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
    assert not (tmp_path / "audit.json").exists()


def test_AUD001_unwritable_path_is_best_effort(tmp_path):
    """D-045: audit I/O failure warns, never aborts the transfer."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"best effort", False)])
    recv = _receiver(B, cards, tmp_path,
                     audit_log_path=str(tmp_path / "audit.json"),
                     warn=lambda msg: None)
    recv._audit_path = tmp_path / "nope" / "missing" / "audit.json"
    recv._audit("message_received", msg_id="msg_x")
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}),
                               now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"


def test_default_no_audit_path_writes_nothing(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"no audit", False)])
    recv = _receiver(B, cards, tmp_path)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}),
                               now=NOW)
    assert verify_envelope(out[0], PT_MESSAGE,
                           B.signer.public_key_raw())["type"] == "ACCEPT"
    assert not (tmp_path / "audit.json").exists()
