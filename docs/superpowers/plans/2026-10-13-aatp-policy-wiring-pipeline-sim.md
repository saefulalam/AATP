# AATP Policy Wiring + Audit Emit + 4-Agent Simulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two real integration gaps — `policy.evaluate` is never called by the transfer path and `audit_append` is never emitted — then build a 4-agent work simulation over the existing localhost HTTP relay.

**Architecture:** `TransferReceiver` gains five optional keyword parameters (`policy_fn`, `grant_leaf_env`, `grant_chain_envs`, `roots`, `audit_log_path`), all defaulting to `None`/empty so the 411 existing tests stay green unchanged. A private `_audit()` helper writes hash-chained entries through the existing `sec.audit_append`. New tests cover policy wiring, audit emit, and an in-process pipeline subset; a standalone demo script drives four agents over real HTTP.

**Tech Stack:** Python 3.12, existing `aatp/` modules only (`policy.evaluate`, `sec.audit_append`, `transfer.TransferReceiver`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-aatp-policy-wiring-pipeline-sim-design.md`

## Global Constraints

- One rule ID = one test, named after the rule ID, failing-first (§18.4.1).
- Never log or print private keys, CEKs, or plaintext artifact bytes (§18.4.2).
- Fail closed on ambiguity; record in `DECISIONS.md` (§0.4, §18.4.3).
- No changes to the wire format, so the TypeScript implementation (M8) needs no update.
- `policy_fn=None` and `audit_log_path=None` must be exact no-ops; the 411-test Python suite and 155-test TS suite must stay green.
- Policy DENY must produce a signed `REJECT` message, never an exception escaping to the caller.
- Audit I/O failure is best-effort (warn, do not abort the transfer); an entry carrying a forbidden field is still rejected (D-045).
- Branch `feat/core-m0-m5`; do NOT switch branches or change git config; PowerShell 5.1; tests via `.venv\Scripts\python -m pytest`.
- New decisions go into `DECISIONS.md` as D-044 (policy wiring) and D-045 (audit best-effort).

---

### Task P1: Audit emit in `TransferReceiver` (AUD-001/002)

**Files:**
- Create: `tests/test_audit_wiring.py`
- Modify: `aatp/transfer.py` (`__init__` signature, new `_audit` helper, call sites)

**Interfaces:**
- Consumes: `aatp.sec.audit_append(log: list, entry: dict, *, prev_hash: str) -> str` (exists, `aatp/sec.py:93`), `aatp.errors.AATPError`, `aatp.canon.jcs`.
- Produces: `TransferReceiver(..., audit_log_path: str | None = None)`; private `self._audit(event: str, **fields) -> None`. Audit file format: `{"entries": [{"entry": {...}, "prev_hash": hex, "entry_hash": hex}], "head": hex}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_audit_wiring.py
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_audit_wiring.py -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'audit_log_path'`

- [ ] **Step 3: Implement the audit helper**

In `aatp/transfer.py`, extend the constructor signature (keep every existing parameter name and order; append the new ones last so existing positional callers are unaffected):

```python
    def __init__(self, *, agent_id: str, signer, keystore, card_resolver,
                 trusted, own_card=None, dag=None, replay_path=None,
                 store_path=None, clock_skew_seconds: int = 120,
                 send_window_chunks: int = SEND_WINDOW_CHUNKS,
                 audit_log_path: str | None = None, warn=None):
        ...
        self._audit_path = Path(audit_log_path) if audit_log_path else None
        self._warn = warn if warn is not None else (
            lambda text: print(f"aatp: audit warning: {text}"))
```

Add the helper right after `_save_store`:

```python
    # -- audit (AUD-001/002) --------------------------------------------

    def _read_audit(self) -> dict:
        if self._audit_path is None:
            return {"entries": [], "head": "00" * 32}
        obj = self._read_json(self._audit_path)
        if (not isinstance(obj, dict) or not isinstance(obj.get("entries"), list)
                or not isinstance(obj.get("head"), str)):
            # Corrupt audit log: start a fresh chain but keep going (best-effort,
            # D-045). The gap is visible in the file, not hidden.
            return {"entries": [], "head": "00" * 32}
        return obj

    def _audit(self, event: str, **fields) -> None:
        """Append one hash-chained entry (AUD-002). No path = no-op.

        Forbidden fields are rejected by sec.audit_append before anything is
        written (AUD-001 fail-closed). I/O failure is best-effort (D-045).
        """
        if self._audit_path is None:
            return
        from aatp import sec as sec_mod
        state = self._read_audit()
        log = state["entries"]
        entry = {"event": event}
        entry.update(fields)
        new_hash = sec_mod.audit_append(log, entry, prev_hash=state["head"])
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_json(self._audit_path,
                         {"entries": log, "head": new_hash})
```

- [ ] **Step 4: Call `_audit` at the five transition points**

In `_handle_offer`, right after `txid = body["transfer_id"]` succeeds validation, add the receipt event (before any ACCEPT path):

```python
        self._audit("message_received", msg_id=msg["id"], msg_type="OFFER",
                    sender=sender, recipient=self._agent_id,
                    transfer_id=txid)
```

In `_reject`, after `self._store[txid] = {...}` add:

```python
        self._audit("transfer_state", transfer_id=txid, state="REJECTED",
                    sender=sender, recipient=self._agent_id, code=code)
```

In `receive_chunk`, immediately after `rec["chunks"][str(index)] = b64u(pt)`:

```python
            self._audit("chunk_verified", transfer_id=transfer_id, index=index)
```

In `_handle_complete`, in the branch that moves the record to VERIFYING:

```python
        self._audit("transfer_state", transfer_id=transfer_id, state="VERIFYING",
                    sender=msg["sender"], recipient=self._agent_id)
```

In `_finish_verified`, immediately before each `return` of a RECEIPT envelope:

```python
        self._audit("artifact_verified", content_root=rec["content_root"],
                    node_id=node_id, ancestry=self._dag.ancestry_status(node_id))
        self._audit("transfer_state", transfer_id=rec["transfer_id"],
                    state="COMPLETE", outcome=outcome)
```

Use the real local variable names in that function (`rec`, `outcome`, `node_id` — read the function first and match what is actually there).

- [ ] **Step 5: Run the new tests**

Run: `.venv\Scripts\python -m pytest tests/test_audit_wiring.py -v`
Expected: 6 passed.

- [ ] **Step 6: Run the full suite for regressions**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all previous tests plus the new ones pass (411 + 6).

- [ ] **Step 7: Commit**

```bash
git add aatp/transfer.py tests/test_audit_wiring.py
git commit -m "feat: audit emit AUD-001/002 in TransferReceiver"
```

---

### Task P2: Policy wiring in `TransferReceiver` (AUT/SEC gates)

**Files:**
- Create: `tests/test_policy_wiring.py`
- Modify: `aatp/transfer.py` (constructor, `_handle_offer`)

**Interfaces:**
- Consumes: `aatp.policy.evaluate(request, *, roots, key_resolver, presenter, now)` (exists), `aatp.grants.make_grant_envelope`? (NOT needed — the caller builds envelopes; see test helper below), `TransferReceiver` from Task P1.
- Produces: `TransferReceiver(..., policy_fn=None, grant_leaf_env=None, grant_chain_envs=None, roots=None, policy_action="aatp.artifact.receive", policy_resource="project:alpha/*", policy_presenter=None, revoked_grants=None)`. `policy_fn` may be any callable `(request: dict) -> {"decision","rule_id","code"}`; when it is the real `policy.evaluate`, the receiver supplies `roots`/`key_resolver` from its own `card_resolver` and `presenter` from `msg["sender"]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_policy_wiring.py
"""Policy gate wired into the OFFER path (TDD: written first).

Reuses the agent/offer helpers from tests/test_audit_wiring.py by import.
"""
import pytest

from aatp.b64 import b64u
from aatp.canon import jcs
from aatp.dsse import PT_GRANT, PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import AATPError
from aatp.messages import build_message, shift_ts

from tests.test_audit_wiring import _Agent, _offer_parts, _sealed, _world
from aatp.transfer import TransferReceiver
from aatp.node import DagStore

CR1 = "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf"


def _grant(issuer, audience, acts, res, classification_max="INTERNAL",
           nbf="2026-10-01T00:00:00Z", exp="2026-10-03T00:00:00Z", prf=None):
    body = {
        "v": "0.2", "iss": issuer, "aud": audience,
        "cap": [{"act": a, "res": res} for a in acts],
        "nbf": nbf, "exp": exp, "prf": list(prf or []),
        "constraints": {"classification_max": classification_max,
                        "export": False},
    }
    return make_envelope(PT_GRANT, jcs(body), issuer.signer), body


def _receiver(B, cards, tmp_path, **kw):
    return TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid], trusted=set(cards.keys()),
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / "replay.json"),
        store_path=str(tmp_path / "xfer.json"), **kw)


ALLOW = {"decision": "allow", "rule_id": "POLICY-ALLOW", "code": None}


def test_AUT_wired_offer_accepted_when_policy_allows(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"policy ok", False)])
    leaf, _ = _grant(A, B, ["aatp.artifact.receive"], "project:alpha/*")
    recv = _receiver(B, cards, tmp_path, policy_fn=lambda req: dict(ALLOW),
                     grant_leaf_env=leaf)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"


def test_AUT_wired_offer_denied_without_grant(tmp_path):
    """Fail closed: policy active but no grant leaf = deny."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"no grant", False)])
    seen = {}

    def policy(req):
        seen.update(req)
        return {"decision": "deny", "rule_id": "AUT-006",
                "code": "ERR_POLICY_DENIED"}

    recv = _receiver(B, cards, tmp_path, policy_fn=policy, grant_leaf_env=None)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"
    assert recv.state_of("tx_audit") == "REJECTED"
    assert seen["consumption_mode"] == "data_only"
    assert seen["classification"] == "INTERNAL"


def test_AUT_wired_offer_denied_by_policy_code(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"denied", False)])
    leaf, _ = _grant(A, B, ["aatp.artifact.receive"], "project:alpha/*")
    recv = _receiver(B, cards, tmp_path,
                     policy_fn=lambda req: {"decision": "deny",
                                            "rule_id": "AUT-002",
                                            "code": "ERR_GRANT_ATTENUATION"},
                     grant_leaf_env=leaf)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["body"]["code"] == "ERR_GRANT_ATTENUATION"


def test_AUT_wired_offer_policy_exception_internal(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"boom", False)])
    leaf, _ = _grant(A, B, ["aatp.artifact.receive"], "project:alpha/*")

    def boom(req):
        raise RuntimeError("policy exploded")

    recv = _receiver(B, cards, tmp_path, policy_fn=boom, grant_leaf_env=leaf)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_INTERNAL"


def test_AUT_wired_real_policy_evaluate_end_to_end(tmp_path):
    """Wire the real aatp.policy.evaluate (not a stub) into the OFFER path."""
    from aatp.policy import evaluate
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"real policy", False)])
    leaf, _ = _grant(A, B, ["aatp.artifact.receive"], "project:alpha/*")

    def policy(req):
        return evaluate(req, roots={A.agent_id},
                        key_resolver=lambda aid: b64u_dec_key(cards[aid]),
                        presenter=req["presenter"], now=req["now"])

    from aatp.b64 import b64u_dec

    def b64u_dec_key(card):
        return b64u_dec(card["signing_key"]["public_key"])

    recv = _receiver(B, cards, tmp_path, policy_fn=policy,
                     grant_leaf_env=leaf, roots={A.agent_id},
                     policy_action="aatp.artifact.receive",
                     policy_resource="project:alpha/*")
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"


def test_SEC002_instructions_allowed_requires_grant(tmp_path):
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"instruct", False)])
    parts["body"]["consumption_mode"] = "instructions_allowed"
    leaf, _ = _grant(A, B, ["aatp.artifact.receive"], "project:alpha/*")
    from aatp.policy import evaluate
    from aatp.b64 import b64u_dec

    def policy(req):
        return evaluate(req, roots={A.agent_id},
                        key_resolver=lambda aid: b64u_dec(
                            cards[aid]["signing_key"]["public_key"]),
                        presenter=req["presenter"], now=req["now"])

    recv = _receiver(B, cards, tmp_path, policy_fn=policy,
                     grant_leaf_env=leaf, roots={A.agent_id},
                     policy_action="aatp.artifact.receive",
                     policy_resource="project:alpha/*")
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"


def test_default_no_policy_behaviour_unchanged(tmp_path):
    """policy_fn=None must be a true no-op (regression guard)."""
    A, B, cards = _world(tmp_path)
    parts = _offer_parts(A, B, [("a.txt", b"unchanged", False)])
    recv = _receiver(B, cards, tmp_path)
    out = recv.receive_control(_sealed(A, B, "OFFER", parts["body"],
                                       corr={"transfer_id": "tx_audit"}), now="2026-10-02T00:00:00Z")
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"
```

Remove `from aatp.messages import build_message, shift_ts` if unused after the import fix — check the file and keep only names actually referenced.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_policy_wiring.py -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'policy_fn'`

- [ ] **Step 3: Extend the constructor**

Append to the `TransferReceiver.__init__` signature (after `audit_log_path`/`warn` from Task P1):

```python
                 policy_fn=None, grant_leaf_env=None, grant_chain_envs=None,
                 roots=None, policy_action: str = "aatp.artifact.receive",
                 policy_resource: str = "project:alpha/*",
                 policy_presenter: str | None = None,
                 revoked_grants=None):
        ...
        self._policy_fn = policy_fn
        self._grant_leaf_env = grant_leaf_env
        self._grant_chain_envs = list(grant_chain_envs or [])
        self._roots = set(roots) if roots else set()
        self._policy_action = policy_action
        self._policy_resource = policy_resource
        self._policy_presenter = policy_presenter
        self._revoked_grants = set(revoked_grants) if revoked_grants else set()
```

- [ ] **Step 4: Add the policy gate and wire it into `_handle_offer`**

Add this method next to `_handle_offer`:

```python
    def _policy_verdict(self, msg: dict, body: dict, now: str) -> dict:
        """Run the injected policy callable before ACCEPT.

        D-044: no grant leaf while a policy is active is a deny, not an
        allow-by-absence. Non-AATPError exceptions become ERR_INTERNAL so the
        transfer still answers with a signed REJECT instead of crashing.
        """
        from aatp.errors import AATPError as _AATPError
        if self._grant_leaf_env is None:
            verdict = {"decision": "deny", "rule_id": "AUT-006",
                       "code": "ERR_POLICY_DENIED"}
        else:
            request = {
                "action": self._policy_action,
                "resource": self._policy_resource,
                "classification": body.get("classification", "PUBLIC"),
                "consumption_mode": body.get("consumption_mode", "data_only"),
                "grant_leaf_env": self._grant_leaf_env,
                "grant_chain_envs": list(self._grant_chain_envs),
                "revoked": set(self._revoked_grants),
                "manifest": body.get("manifest"),
                "presenter": self._policy_presenter or msg["sender"],
                "now": now,
            }
            try:
                verdict = self._policy_fn(request)
            except _AATPError as e:
                verdict = {"decision": "deny", "rule_id": "AUT-004",
                           "code": e.code}
            except Exception:
                verdict = {"decision": "deny", "rule_id": "INTERNAL",
                           "code": "ERR_INTERNAL"}
        if not isinstance(verdict, dict) or verdict.get("decision") != "allow":
            code = "ERR_POLICY_DENIED"
            if isinstance(verdict, dict) and isinstance(verdict.get("code"), str):
                code = verdict["code"]
            rule = "AUT-006"
            if isinstance(verdict, dict) and isinstance(verdict.get("rule_id"), str):
                rule = verdict["rule_id"]
            self._audit("policy_decision", subject=msg["sender"],
                        action=self._policy_action,
                        resource=self._policy_resource,
                        decision="deny", rule_id=rule)
            return {"decision": "deny", "rule_id": rule, "code": code}
        self._audit("policy_decision", subject=msg["sender"],
                    action=self._policy_action, resource=self._policy_resource,
                    decision="allow", rule_id="POLICY-ALLOW")
        return verdict
```

Call it in `_handle_offer` right after the OFFER body/transfer_id checks pass and **before** manifest validation and any ACCEPT path:

```python
        if self._policy_fn is not None:
            verdict = self._policy_verdict(msg, body, now)
            if verdict["decision"] != "allow":
                return rej_tx(verdict["code"],
                              f"policy denied: {verdict['rule_id']}")
```

- [ ] **Step 5: Run the new tests**

Run: `.venv\Scripts\python -m pytest tests/test_policy_wiring.py -v`
Expected: 7 passed.

- [ ] **Step 6: Run the full suite for regressions**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all previous tests plus the new ones pass.

- [ ] **Step 7: Record the decisions and commit**

Append to `DECISIONS.md`:

```markdown
## D-044: Policy gate wiring in the OFFER path (post-M8)

- `TransferReceiver` takes `policy_fn`, `grant_leaf_env`, `grant_chain_envs`, `roots`, `policy_action`, `policy_resource`, `policy_presenter`, `revoked_grants`. All optional; `policy_fn=None` is an exact no-op, so the M0-M5/M6-M7 suites are unchanged.
- Fail closed: policy active + no grant leaf => deny `ERR_POLICY_DENIED` (rule AUT-006). Absent authorization is never treated as implicit allow.
- The receiver builds the request and passes `presenter` (default `msg["sender"]`) and `now` so a real `policy.evaluate` can be injected without the caller re-deriving them.
- Errors: an `AATPError` from the policy propagates its code into the REJECT; any other exception becomes `ERR_INTERNAL` (D-044) so the receiver still answers with a signed REJECT instead of raising.
- The gate runs before manifest validation, matching blueprint section 10.2 order (grant/authorization before artifact checks).
- No wire-format change, so the TypeScript M8 implementation needs no update.

## D-045: Audit emit is best-effort on I/O failure

- `audit_append` rejects forbidden fields before writing (AUD-001 stays fail-closed); that rejection raises `ERR_MALFORMED_MESSAGE` and nothing is written.
- I/O failure while appending (unwritable path, disk error) logs a warning and does NOT abort the transfer: the audit log is an observability artifact, not transactional state. A corrupt existing log starts a fresh chain instead of blocking the protocol.
- A corrupt/unreadable audit file is visible in the file itself (fresh `head` starting at `"00"*32`), never silently rewritten over.
```

```bash
git add aatp/transfer.py tests/test_policy_wiring.py DECISIONS.md
git commit -m "feat: policy gate AUT/SEC wired into OFFER path"
```

---

### Task P3: In-process pipeline test (grant → policy → transfer → audit)

**Files:**
- Create: `tests/test_pipeline_sim.py`
- Modify: none

**Interfaces:**
- Consumes: `TransferReceiver` from Tasks P1+P2, `aatp.grants.make_grant_envelope`-style grant building (built inline in the test), `aatp.node.make_node`, `aatp.quarantine.Quarantine`.
- Produces: a reusable in-process scenario builder `_scenario(tmp_path)` used by two tests (happy path + negative path).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_pipeline_sim.py
"""Coordinator -> Coder -> Reviewer pipeline, in-process (no HTTP).

Mirrors docs/superpowers/specs/2026-10-13-...-design.md section 3 with a
real attenuated grant chain and the real policy.evaluate.
"""
from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs
from aatp.dsse import PT_GRANT, PT_MESSAGE, make_envelope, verify_envelope
from aatp.policy import evaluate
from aatp.quarantine import Quarantine

from tests.test_audit_wiring import (_Agent, _offer_parts, _sealed, _world,
                                     _read_log)
from tests.test_policy_wiring import _grant
from aatp.transfer import TransferReceiver
from aatp.node import DagStore

NOW = "2026-10-02T00:00:00Z"


def _key(cards, aid):
    return b64u_dec(cards[aid]["signing_key"]["public_key"])


def _pipeline(tmp_path):
    """C issues G1 to A; A attenuates into G2 to B. Returns the pieces."""
    from aatp.grants import grant_id_of
    C, A, B, cards = _world3(tmp_path)
    g1_env, g1 = _grant(C, A, ["aatp.artifact.send", "aatp.grant.delegate",
                               "aatp.artifact.receive"],
                        "project:alpha/*", classification_max="INTERNAL")
    g2_env, g2 = _grant(A, B, ["aatp.artifact.receive"],
                        "project:alpha/src/*", classification_max="INTERNAL",
                        prf=[grant_id_of(g1)])
    return C, A, B, cards, g1_env, g1, g2_env


def _world3(tmp_path):
    from aatp.card import CardCache, verify_card
    C = _Agent(0xC3, "kc1", "ec1")
    A = _Agent(0xA1, "ka1", "ea1")
    B = _Agent(0xB2, "kb1", "eb1")
    cards = {C.agent_id: C.card, A.agent_id: A.card, B.agent_id: B.card}
    for name, a in (("c", C), ("a", A), ("b", B)):
        verify_card(a.card_env, a.agent_id,
                    CardCache(str(tmp_path / f"{name}-seq.json")), NOW)
    return C, A, B, cards


def test_pipeline_grant_policy_transfer_audit(tmp_path):
    C, A, B, cards, g1_env, g1, g2_env = _pipeline(tmp_path)
    files = [("src/app.py", b"print('halo')\n", False),
             ("src/util.py", b"def add(a, b):\n    return a + b\n", False),
             ("README.md", b"# demo project alpha\n", False)]
    parts = _offer_parts(A, B, files, tx_id="tx_pipe", chunk_size=16)

    def policy(req):
        return evaluate(req, roots={C.agent_id, A.agent_id},
                        key_resolver=lambda aid: _key(cards, aid),
                        presenter=req["presenter"], now=req["now"])

    recv = TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid], trusted={A.agent_id},
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / "replay.json"),
        store_path=str(tmp_path / "xfer.json"),
        audit_log_path=str(tmp_path / "audit.json"),
        policy_fn=policy, grant_leaf_env=g2_env, grant_chain_envs=[g1_env],
        roots={C.agent_id, A.agent_id},
        policy_action="aatp.artifact.receive",
        policy_resource="project:alpha/src/*")
    out = recv.receive_control(
        _sealed(A, B, "OFFER", parts["body"], corr={"transfer_id": "tx_pipe"}),
        now=NOW)
    acc = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert acc["type"] == "ACCEPT"
    for i in range(parts["total"]):
        recv.receive_chunk({"transfer_id": "tx_pipe", "index": i,
                            "data": b64u(parts["cts"][i])}, now=NOW)
    out = recv.receive_control(
        _sealed(A, B, "COMPLETE",
                {"transfer_id": "tx_pipe", "total_chunks": parts["total"]},
                corr={"transfer_id": "tx_pipe"}), now=NOW)
    rcpt = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rcpt["body"]["outcome"] == "accepted"
    assert rcpt["body"]["content_root"] == parts["cr"]
    assert recv.state_of("tx_pipe") == "COMPLETE"

    q = Quarantine()
    q.place(parts["cr"], parts["node_id"],
            [{"scanner_name": "demo", "scanner_version": "0.1",
              "verdict": "clean", "at": NOW}])
    assert q.state_of(parts["cr"])["state"] == "accepted"

    events = [e["entry"]["event"] for e in _read_log(tmp_path)["entries"]]
    for required in ("message_received", "transfer_state", "chunk_verified",
                     "artifact_verified", "policy_decision"):
        assert required in events, f"missing audit event: {required}"


def test_pipeline_negative_paths(tmp_path):
    C, A, B, cards, g1_env, g1, g2_env = _pipeline(tmp_path)

    def policy(req):
        return evaluate(req, roots={C.agent_id, A.agent_id},
                        key_resolver=lambda aid: _key(cards, aid),
                        presenter=req["presenter"], now=req["now"])

    # (a) OFFER with no grant at all -> REJECT ERR_POLICY_DENIED
    parts = _offer_parts(A, B, [("src/x.py", b"x = 1\n", False)],
                         tx_id="tx_nogrant", chunk_size=16)
    recv = TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid], trusted={A.agent_id},
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / "replay2.json"),
        store_path=str(tmp_path / "xfer2.json"),
        policy_fn=policy, grant_leaf_env=None,
        roots={C.agent_id, A.agent_id})
    out = recv.receive_control(
        _sealed(A, B, "OFFER", parts["body"],
                corr={"transfer_id": "tx_nogrant"}), now=NOW)
    rej = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej["type"] == "REJECT"
    assert rej["body"]["code"] == "ERR_POLICY_DENIED"

    # (b) grant max=PUBLIC but OFFER classification=RESTRICTED -> REJECT
    parts2 = _offer_parts(A, B, [("src/y.py", b"y = 2\n", False)],
                          tx_id="tx_class", chunk_size=16)
    parts2["body"]["classification"] = "RESTRICTED"
    from aatp.grants import grant_id_of
    weak_env, _ = _grant(A, B, ["aatp.artifact.receive"],
                         "project:alpha/src/*", classification_max="PUBLIC",
                         prf=[grant_id_of(g1)])
    recv2 = TransferReceiver(
        agent_id=B.agent_id, signer=B.signer, keystore=B.keystore,
        card_resolver=lambda aid: cards[aid], trusted={A.agent_id},
        own_card=B.card, dag=DagStore(parent_policy="lazy"),
        replay_path=str(tmp_path / "replay3.json"),
        store_path=str(tmp_path / "xfer3.json"),
        policy_fn=policy, grant_leaf_env=weak_env, grant_chain_envs=[g1_env],
        roots={C.agent_id, A.agent_id},
        policy_action="aatp.artifact.receive",
        policy_resource="project:alpha/src/*")
    out = recv2.receive_control(
        _sealed(A, B, "OFFER", parts2["body"],
                corr={"transfer_id": "tx_class"}), now=NOW)
    rej2 = verify_envelope(out[0], PT_MESSAGE, B.signer.public_key_raw())
    assert rej2["type"] == "REJECT"
    assert rej2["body"]["code"] == "ERR_POLICY_DENIED"
```

- [ ] **Step 2: Run the tests**

Run: `.venv\Scripts\python -m pytest tests/test_pipeline_sim.py -v`
Expected: PASS if Tasks P1+P2 landed correctly; FAIL with `ImportError`/`AttributeError` if `_audit` or `_policy_verdict` is missing. Fix the implementation, not the test, if it fails on a missing feature.

- [ ] **Step 3: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all tests green (411 + 6 + 7 + 2).

- [ ] **Step 4: Commit**

```bash
git add tests/test_pipeline_sim.py
git commit -m "test: in-process coordinator/coder/reviewer pipeline"
```

---

### Task P4: Demo tooling for the 4-agent HTTP simulation

**Files:**
- Create: `tools/README.md`, `tools/agent_cli.py`, `tools/relay_server.py`, `tools/simulate_pipeline.py`
- Modify: none in `aatp/` (this task is demo-only tooling)

**Interfaces:**
- Consumes: all `aatp/` modules plus the Task P1+P2 `TransferReceiver` parameters. `agent_cli.py` is the existing localhost CLI (currently at `C:\Users\ADMINI~1\AppData\Local\Temp\opencode\aatp-live\agent_cli.py`) moved here and extended with `grant` and `grant-load` subcommands plus `--policy`/`--audit` flags.
- Produces: `python tools/relay_server.py [port]` (single-instance via lock file), `python tools/agent_cli.py {init,publish,grant,grant-load,send,receive}`, `python tools/simulate_pipeline.py` (orchestrates all four agents over real HTTP and prints a timeline).

- [ ] **Step 1: Write the failing test for the tooling contract**

```python
# tests/test_tools_cli.py
"""Contract tests for tools/agent_cli.py helpers (TDD: written first)."""
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))


def test_tools_files_exist():
    for name in ("agent_cli.py", "relay_server.py", "simulate_pipeline.py",
                 "README.md"):
        assert (TOOLS / name).is_file(), f"missing tools/{name}"


def test_cli_exposes_grant_subcommands():
    import agent_cli
    assert callable(agent_cli.cmd_grant)
    assert callable(agent_cli.cmd_grant_load)


def test_cli_builds_allow_policy_callable():
    import agent_cli
    pol = agent_cli.make_policy(roots={"aatp:x"},
                                key_resolver=lambda a: None)
    verdict = pol({"action": "aatp.artifact.receive", "resource": "p",
                   "classification": "PUBLIC", "consumption_mode": "data_only",
                   "grant_leaf_env": None, "grant_chain_envs": [],
                   "revoked": set(), "manifest": None,
                   "presenter": "aatp:y", "now": "2026-10-02T00:00:00Z"})
    assert verdict["decision"] == "deny"
    assert verdict["code"] == "ERR_POLICY_DENIED"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_tools_cli.py -v`
Expected: FAIL — `tools/agent_cli.py` does not exist yet.

- [ ] **Step 3: Create `tools/`**

Move `C:\Users\ADMINI~1\AppData\Local\Temp\opencode\aatp-live\relay_server.py` and `agent_cli.py` into `D:\AATP-01\tools\` (copy, do not delete the temp copies). Change their hard-coded `sys.path.insert(0, "D:\\AATP-01")` to the repo-relative path so the tooling works from a clone:

```python
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
```

Add to `agent_cli.py`:

```python
def cmd_grant(args):
    """Coordinator issues a grant and stores it in <dir>/grants.json."""
    d = Path(args.dir)
    st = load_state(d)
    cache = {}
    peer = peer_info(st, args.audience, cache)
    issuer_id = args.issuer or st["agent_id"]
    body = {
        "v": "0.2", "iss": issuer_id, "aud": peer["agent_id"],
        "cap": [{"act": a, "res": args.res} for a in args.act],
        "nbf": args.nbf or shift_ts(now_ts(), -60),
        "exp": args.exp or shift_ts(now_ts(), 3600),
        "prf": [],
        "constraints": {"classification_max": args.classification_max,
                        "export": False},
    }
    env = make_envelope(PT_GRANT, jcs(body), st["signer"])
    path = d / "grants.json"
    db = json.loads(path.read_text()) if path.exists() else {}
    db[args.name] = {"env": env, "body": body}
    path.write_text(json.dumps(db, indent=2, sort_keys=True))
    print(f"grant {args.name}: iss={issuer_id} aud={peer['agent_id']}")


def cmd_grant_load(args):
    """Load grants from <dir>/grants.json and hand them to the receiver."""
    d = Path(args.dir)
    db = json.loads((d / "grants.json").read_text())
    leaf = db[args.leaf]["env"]
    chain = [db[n]["env"] for n in args.chain]
    print(json.dumps({"leaf": leaf, "chain": chain,
                      "roots": args.root}))


def make_policy(roots, key_resolver):
    from aatp.policy import evaluate
    from aatp.b64 import b64u_dec

    def policy(request):
        return evaluate(request, roots=roots, key_resolver=key_resolver,
                        presenter=request["presenter"], now=request["now"])
    return policy
```

Register the subcommands in `main()`:

```python
    p = sub.add_parser("grant")
    p.add_argument("--dir", required=True)
    p.add_argument("--audience", required=True)
    p.add_argument("--act", action="append", required=True)
    p.add_argument("--res", required=True)
    p.add_argument("--classification-max", default="INTERNAL")
    p.add_argument("--name", required=True)
    p.add_argument("--issuer", default=None)
    p.add_argument("--nbf", default=None)
    p.add_argument("--exp", default=None)
    p = sub.add_parser("grant-load")
    p.add_argument("--dir", required=True)
    p.add_argument("--leaf", required=True)
    p.add_argument("--chain", action="append", default=[])
    p.add_argument("--root", action="append", default=[])
```

and add them to the dispatch dict. In `cmd_receive`, load the grants when `--policy` is passed and forward them plus `--audit-log` into the `TransferReceiver(...)` call.

- [ ] **Step 4: Create `tools/simulate_pipeline.py`**

Orchestrate four agents (Coordinator, Coder, Reviewer, Deployer) over real HTTP. It must:

1. Start `relay_server.py` as a subprocess on a free port (default 8765) unless `--port` is given and the port is already serving.
2. `init` + `publish` the four agents into `run/<name>/`.
3. Coordinator issues `G1` (to Coder: `artifact.send` + `grant.delegate` + `artifact.receive` on `project:alpha/*`) and `G2` (Coder→Reviewer: `artifact.receive` on `project:alpha/src/*`, `prf=[grant_id(G1)]`).
4. Coder sends the 3-file source tree to Reviewer; deliberately **drops one chunk** mid-upload so the run exercises `STATUS have` + resume.
5. Reviewer verifies, materializes to `run/reviewer/received/<tx>/`, and runs the `Quarantine` stub scanner.
6. Reviewer sends a report back and issues a `HANDOFF_OFFER` to Coordinator; Coordinator answers `HANDOFF_RESPONSE{accept}` before the lease expires.
7. Prints a timeline, the four `agent_id`s, the received file listing, and re-verifies the audit chain with `hashlib.sha256(bytes.fromhex(prev) + jcs(entry))`.
8. Runs the four negative cases and prints their expected codes: no grant → `ERR_POLICY_DENIED`; classification too high → `ERR_POLICY_DENIED`; chunk reindexed → `ERR_CHUNK_AUTH_FAILED`; one byte flipped in a file → `ERR_ARTIFACT_HASH_MISMATCH`.

Reuse `agent_cli`'s helper functions by importing it as a module (`import agent_cli`), and reuse `HandoffStore` from `aatp.handoff`. Follow blueprint Appendix B for the handoff shape (`HandoffBody` fields: `handoff_id`, `task{task_id,title,objective}`, `input_node_ids`, `grant_env`, `expected_outputs`, `deadline`, `lease_expires_at`).

- [ ] **Step 5: Create `tools/README.md`**

Document: what the four agents are, the grant chain shape, the exact commands to run the simulation by hand, the relay port, and the caveat that TEST-ONLY deterministic seeds are used (never production keys) and that CRY-007 is still OPEN.

- [ ] **Step 6: Run the tests and the simulation**

Run: `.venv\Scripts\python -m pytest tests/test_tools_cli.py -v` → PASS.
Then run: `.venv\Scripts\python tools\simulate_pipeline.py --port 8765` → the timeline prints and the run ends with `AUDIT CHAIN OK` and `NEGATIVE CASES OK`.

- [ ] **Step 7: Commit**

```bash
git add tools tests/test_tools_cli.py
git commit -m "feat(tools): 4-agent HTTP pipeline simulation"
```

---

## Self-Review Notes

- Spec coverage: audit emit (§2.2, §3 step 6) → P1; policy wiring (§2.1, §3 steps 0–2) → P2; negative scenarios (§3) → P3; simulation + tooling (§6 files) → P4.
- No placeholders: every step has concrete code, commands, and expected results.
- Type consistency: `policy_fn(request: dict) -> {"decision","rule_id","code"}` is used identically in P2 tests, P3 tests, and the P4 tooling; `_audit(event: str, **fields)` keeps the same signature in P1 and P3.
- Backwards compatibility: every new constructor parameter is keyword-only with a `None`/empty default, so the 411 existing tests pass untouched.
