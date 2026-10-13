"""M5 transfer receiver: state machine, resume, durable stores (TRF-001..026).

Policy scope enforced here is M0-M5 only (blueprint section 10.2 steps
1,2,4,5 and 6-after-transfer): unseal -> trust admits sender -> size/entry
limits -> offer expiry + replay -> node signature + content_root check after
transfer. Grant chains, classification, SEC untrusted-content rules and
scanner verdicts are M6/M7 policy-engine scope and are NOT enforced here:
integrity pass yields ``RECEIPT{accepted}`` (quarantine deferred).

One exception, off by default: an injected ``policy_fn`` adds the M6
authorization gate (grant chain, classification, consumption mode) to the
OFFER path ahead of the artifact checks (D-044, blueprint section 10.2).
With ``policy_fn=None`` this receiver behaves exactly as before.

Wire flow per message (``receive_control``, blueprint section 5.3 steps 1-8):
packet.to match -> own enc-key window (ID-012) -> HPKE open -> JCS parse
(GEN-010/011) -> pinned trust (ID-003/004) -> signature + revocation check ->
recipient (MSG-002) -> time window (MSG-003) -> replay (MSG-004) -> dispatch
(MSG-006). Outbound responses are signed DSSE ``message+json`` envelopes;
sealing them for the wire is the transport binding (M7 scope) -- in-memory
callers pass envelopes directly.

Durable JSON stores (``write_bytes``, LF-terminated):
* replay cache ``{(sender, id) -> {expires_at, response}}`` kept until
  ``expires_at + skew`` and surviving restart (MSG-004). A repeat raises
  ``ERR_REPLAY_DETECTED`` carrying the previously produced response on the
  exception as ``previous_response`` (MSG-005 idempotency, N06).
* transfer state ``{transfer_id, content_root, cek, have_ranges, state, ...}``
  (TRF-020). The CEK is stored base64url in this file with mode ``0600``
  (test-only receiver; the production KeyStore is M7 scope). CEKs are never
  logged.

Chunk frames (TRF-010, data plane, no signature) look like
``{"transfer_id", "index", "data": b64url(ct)}``.
"""
import hashlib
import json
import os
import re
from datetime import timedelta
from pathlib import Path

from aatp import artifact as artifact_mod
from aatp import chunks as chunks_mod
from aatp import messages as msg_mod
from aatp import node as node_mod
from aatp import seal as seal_mod
from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.card import check_key_not_revoked
from aatp.dsse import PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import AATPError, err
from aatp.node import DagStore

SEND_WINDOW_CHUNKS = 16
MAX_CHUNK_FAILURES = 100
CHUNK_ACCEPT_STATES = ("ACCEPTED", "RECEIVING", "PAUSED")
CLASSIFICATIONS = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"})
CHUNK_SIZE_MAX = 16777216
TOTAL_CHUNKS_MAX = 4294967295

_HEX64_RE = re.compile(r"[0-9a-f]{64}")

# A grant failure code names the rule it belongs to (mirrors the mapping in
# aatp/policy.py); an unmapped code is an issuer-trust failure (AUT-001).
_POLICY_RULE_BY_CODE = {
    "ERR_POLICY_DENIED": "AUT-006",
    "ERR_GRANT_ATTENUATION": "AUT-002",
    "ERR_GRANT_INVALID": "AUT-004",
    "ERR_AUTH_FAILED": "AUT-001",
    "ERR_SIGNATURE_INVALID": "AUT-001",
}


def _replay_key(sender: str, msg_id: str) -> str:
    return sender + "\n" + msg_id


def _default_warn(text: str) -> None:
    print(f"aatp: audit warning: {text}")


def validate_have_ranges(have: object) -> list:
    """TRF-023: STATUS.have must be inclusive, sorted, non-overlapping ranges."""
    if not isinstance(have, list):
        raise err("ERR_RESUME_INVALID", "have must be a list")
    out = []
    for r in have:
        if (not isinstance(r, (list, tuple)) or len(r) != 2
                or not isinstance(r[0], int) or isinstance(r[0], bool)
                or not isinstance(r[1], int) or isinstance(r[1], bool)):
            raise err("ERR_RESUME_INVALID", "have range must be [lo, hi] ints")
        lo, hi = r
        if lo < 0 or hi < lo:
            raise err("ERR_RESUME_INVALID", "have range must satisfy 0 <= lo <= hi")
        out.append([lo, hi])
    for i in range(len(out) - 1):
        if not (out[i][0] < out[i + 1][0] and out[i][1] < out[i + 1][0]):
            raise err("ERR_RESUME_INVALID",
                      "have ranges must be sorted and non-overlapping")
    return out


def ranges_of(indices) -> list:
    """Compress a set of verified chunk indices into TRF-023 ranges."""
    out = []
    for i in sorted(indices):
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def sender_due_chunks(have: object, total: int, window: int = SEND_WINDOW_CHUNKS) -> list:
    """TRF-024 test helper: missing indices within the send window.

    At most ``window`` unacknowledged chunks beyond the highest contiguous
    ``have`` are due; the sender MUST send only these (TRF-021).
    """
    ranges = validate_have_ranges(have)
    if (not isinstance(total, int) or isinstance(total, bool) or total < 0):
        raise err("ERR_SEQUENCE_INVALID", "total must be an integer >= 0")
    contiguous = ranges[0][1] + 1 if ranges and ranges[0][0] == 0 else 0
    limit = contiguous + window - 1
    have_set = set()
    for lo, hi in ranges:
        have_set.update(range(lo, hi + 1))
    return [i for i in range(total) if i not in have_set and i <= limit]


class TransferReceiver:
    """Receiver-side endpoint: sealed packets and chunk frames in, signed
    envelopes out. States follow the blueprint section 8.4 receiver table."""

    def __init__(self, *, agent_id: str, signer, keystore, card_resolver,
                 trusted, own_card=None, dag=None, replay_path=None,
                 store_path=None, clock_skew_seconds: int = 120,
                 send_window_chunks: int = SEND_WINDOW_CHUNKS,
                 audit_log_path: str | None = None, warn=None,
                 policy_fn=None, grant_leaf_env=None, grant_chain_envs=None,
                 roots=None, policy_action: str = "aatp.artifact.receive",
                 policy_resource: str | None = None,
                 policy_presenter: str | None = None,
                 revoked_grants=None):
        self._agent_id = agent_id
        self._signer = signer
        self._keystore = keystore
        self._resolver = card_resolver
        self._trusted = set(trusted)
        self._own_card = own_card
        self._dag = dag if dag is not None else DagStore()
        self._replay_path = Path(replay_path) if replay_path else None
        self._store_path = Path(store_path) if store_path else None
        self._skew = clock_skew_seconds
        self._window = send_window_chunks
        self._replay = self._load_replay()
        self._store = self._load_store()
        self._audit_path = Path(audit_log_path) if audit_log_path else None
        self._warn = warn if warn is not None else _default_warn
        self._policy_fn = policy_fn
        self._grant_leaf_env = grant_leaf_env
        self._grant_chain_envs = list(grant_chain_envs or [])
        self._roots = set(roots) if roots else set()
        self._policy_action = policy_action
        self._policy_resource = policy_resource
        self._policy_presenter = policy_presenter
        self._revoked_grants = set(revoked_grants) if revoked_grants else set()

    # -- durable stores -------------------------------------------------

    @staticmethod
    def _write_json(path: Path, obj: dict, private: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(obj, sort_keys=True).encode("utf-8") + b"\n")
        if private:
            try:
                os.chmod(str(path), 0o600)
            except OSError:
                pass

    @staticmethod
    def _read_json(path: Path | None) -> dict | None:
        if path is None:
            return None
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            raise err("ERR_INTERNAL", "durable store unreadable") from None
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise err("ERR_INTERNAL", "durable store corrupt") from None
        if not isinstance(obj, dict):
            raise err("ERR_INTERNAL", "durable store corrupt")
        return obj

    def _load_replay(self) -> dict:
        obj = self._read_json(self._replay_path)
        if obj is None:
            return {}
        entries = obj.get("entries")
        if not isinstance(entries, dict):
            raise err("ERR_INTERNAL", "replay cache corrupt")
        return entries

    def _save_replay(self) -> None:
        if self._replay_path is not None:
            self._write_json(self._replay_path, {"v": "0.2", "entries": self._replay})

    def _load_store(self) -> dict:
        obj = self._read_json(self._store_path)
        if obj is None:
            return {}
        transfers = obj.get("transfers")
        if not isinstance(transfers, dict):
            raise err("ERR_INTERNAL", "transfer store corrupt")
        for rec in transfers.values():
            # RECEIVING | connection lost -> persist PAUSED (section 8.4).
            if isinstance(rec, dict) and rec.get("state") in ("ACCEPTED", "RECEIVING"):
                rec["state"] = "PAUSED"
        return transfers

    def _save_store(self) -> None:
        if self._store_path is not None:
            self._write_json(self._store_path,
                             {"v": "0.2", "transfers": self._store}, private=True)

    # -- audit (AUD-001/002) --------------------------------------------

    def _read_audit(self) -> dict:
        """Current ``{"entries": [...], "head": hex}`` chain state.

        A structurally invalid log (missing keys, a non-hex ``head``, a record
        without well-formed hashes) is discarded and a fresh chain is started
        from ``"00" * 32``: audit is best-effort, so corruption warns and the
        transfer keeps moving instead of aborting (D-045). The discarded
        entries are lost -- the next write overwrites the file with the new
        chain only.
        """
        empty = {"entries": [], "head": "00" * 32}
        obj = self._read_json(self._audit_path)
        if obj is None:  # no log yet: a fresh chain, not corruption
            return empty
        if (not isinstance(obj, dict) or not isinstance(obj.get("entries"), list)
                or not self._is_hex64(obj.get("head"))
                or not all(self._record_ok(rec) for rec in obj["entries"])):
            self._warn(f"audit log corrupt: discarded, new chain from "
                       f"{'00' * 32}")
            return empty
        return obj

    @staticmethod
    def _is_hex64(value: object) -> bool:
        return isinstance(value, str) and _HEX64_RE.fullmatch(value) is not None

    @classmethod
    def _record_ok(cls, rec: object) -> bool:
        return (isinstance(rec, dict) and isinstance(rec.get("entry"), dict)
                and cls._is_hex64(rec.get("prev_hash"))
                and cls._is_hex64(rec.get("entry_hash")))

    def _write_audit_json(self, obj: dict) -> None:
        """Atomic audit write (D-045): temp sibling then ``os.replace``, so a
        crash mid-write cannot leave a truncated log that disables auditing."""
        path = self._audit_path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_bytes(json.dumps(obj, sort_keys=True).encode("utf-8") + b"\n")
            os.replace(str(tmp), str(path))
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    def _audit(self, event: str, **fields) -> None:
        """Append one hash-chained entry (AUD-002). No path = no-op.

        A forbidden field is rejected by ``sec.audit_append`` before anything
        is written (AUD-001 fail-closed). Audit I/O failure only warns and
        never aborts the transfer (D-045).
        """
        if self._audit_path is None:
            return
        from aatp import sec as sec_mod
        entry = {"event": event}
        entry.update(fields)
        try:
            state = self._read_audit()
        except (OSError, AATPError) as e:
            self._warn(f"audit log unreadable: {e}")
            return
        log = state["entries"]
        new_hash = sec_mod.audit_append(log, entry, prev_hash=state["head"])
        try:
            self._write_audit_json({"entries": log, "head": new_hash})
        except OSError as e:
            self._warn(f"audit log not written: {e}")

    def _audit_verified(self, rec: dict, node_id: str) -> None:
        """Record the integrity pass outcome for a finished transfer."""
        try:
            ancestry = self._dag.ancestry_status(node_id)
        except AATPError:
            ancestry = "unknown"  # node never entered the DAG (rejected pass)
        self._audit("artifact_verified", content_root=rec["content_root"],
                    node_id=node_id, ancestry=ancestry)

    def _prune_replay(self, now_str: str) -> None:
        for key in list(self._replay.keys()):
            try:
                expired = msg_mod.parse_ts(self._replay[key]["expires_at"])
                now = msg_mod.parse_ts(now_str)
            except AATPError:
                del self._replay[key]
                continue
            if now > expired + timedelta(seconds=self._skew):
                del self._replay[key]

    # -- introspection (tests, operator status) --------------------------

    def state_of(self, transfer_id: str) -> str | None:
        rec = self._store.get(transfer_id)
        return rec.get("state") if isinstance(rec, dict) else None

    # -- outbound message signing ----------------------------------------

    def _sign_response(self, msg_type: str, recipient: str, body: dict, *,
                       now: str, transfer_id: str,
                       in_reply_to: str | None = None) -> dict:
        corr = {"transfer_id": transfer_id}
        if in_reply_to is not None:
            corr["in_reply_to"] = in_reply_to
        msg = msg_mod.build_message(msg_type, self._agent_id,
                                    self._signer.key_id(), recipient, body,
                                    now=now, lifetime=3600, corr=corr)
        return make_envelope(PT_MESSAGE, jcs(msg), self._signer)

    def _status_envelope(self, rec: dict, now: str,
                         in_reply_to: str | None = None) -> dict:
        verified = {int(k) for k in rec["chunks"].keys()}
        return self._sign_response(
            "STATUS", rec["sender"],
            {"transfer_id": rec["transfer_id"], "have": ranges_of(verified)},
            now=now, transfer_id=rec["transfer_id"], in_reply_to=in_reply_to)

    # -- receive_control (blueprint section 5.3 steps 1-8) ----------------

    def _check_own_key_window(self, key_id: object, now_str: str) -> None:
        if self._own_card is None:
            return
        try:
            enc = self._own_card["enc_key"]
            nb = msg_mod.parse_ts(enc["not_before"])
            na = msg_mod.parse_ts(enc["not_after"])
            own_kid = enc.get("key_id")
        except (KeyError, TypeError, AttributeError):
            raise err("ERR_INTERNAL", "own card malformed") from None
        if key_id != own_kid:
            return  # Unknown/alternate key ids fail closed in KeyStore.open.
        now = msg_mod.parse_ts(now_str)
        skew = timedelta(seconds=self._skew)
        if not (nb - skew <= now <= na + skew):
            raise err("ERR_KEY_EXPIRED", "recipient enc_key outside window")  # ID-012

    def _resolve_sender_card(self, sender: str) -> dict:
        try:
            card = self._resolver(sender)
        except AATPError:
            raise
        except Exception as e:
            raise err("ERR_AUTH_FAILED", "sender not admitted") from e
        if not isinstance(card, dict) or card.get("agent_id") != sender:
            raise err("ERR_AUTH_FAILED", "sender card mismatch")
        if sender not in self._trusted:  # ID-003/004 pinned trust.
            raise err("ERR_AUTH_FAILED", "sender not admitted by pinned trust")
        return card

    @staticmethod
    def _sender_signing_key(card: dict) -> tuple:
        sk = card.get("signing_key")
        if (not isinstance(sk, dict) or not isinstance(sk.get("key_id"), str)
                or not isinstance(sk.get("public_key"), str)):
            raise err("ERR_AUTH_FAILED", "sender card signing_key malformed")
        try:
            raw = b64u_dec(sk["public_key"])
        except AATPError:
            raise err("ERR_AUTH_FAILED", "sender signing key undecodable") from None
        if len(raw) != 32:
            raise err("ERR_AUTH_FAILED", "sender signing key must be 32 bytes")
        return sk["key_id"], raw

    def _check_sender_key_window(self, card: dict, created_at: str) -> None:
        try:
            nb = msg_mod.parse_ts(card["signing_key"]["not_before"])
            na = msg_mod.parse_ts(card["signing_key"]["not_after"])
        except (KeyError, TypeError):
            raise err("ERR_AUTH_FAILED", "sender key window malformed") from None
        created = msg_mod.parse_ts(created_at)
        skew = timedelta(seconds=self._skew)
        if not (nb - skew <= created <= na + skew):  # ID-014
            raise err("ERR_KEY_EXPIRED", "sender signing key outside window")

    def receive_control(self, packet: dict, *, now: str) -> list:
        """Unseal, authenticate and dispatch one sealed packet (5.3: 1-8)."""
        msg_mod.parse_ts(now)
        if not isinstance(packet, dict):
            raise err("ERR_MALFORMED_MESSAGE", "packet must be an object")
        if packet.get("to") != self._agent_id:
            raise err("ERR_RECIPIENT_MISMATCH", "packet not addressed to self")  # step 1
        self._check_own_key_window(packet.get("to_key_id"), now)  # step 2, ID-012
        env = seal_mod.open_packet(packet, self._keystore)  # step 3, ERR_DECRYPT_FAILED
        if len(jcs(env)) > seal_mod.MAX_MESSAGE_BYTES:  # MSG-013
            raise err("ERR_SIZE_LIMIT", "control message exceeds max_message_bytes")
        if env.get("payloadType") != PT_MESSAGE:  # SIG-003
            raise err("ERR_MALFORMED_MESSAGE", "payloadType mismatch")
        try:
            raw = b64u_dec(env["payload"])
        except AATPError:
            raise err("ERR_MALFORMED_MESSAGE", "payload not valid base64url") from None
        msg = parse_jcs(raw)  # step 4, GEN-010/011
        msg_mod.check_shape(msg)
        card = self._resolve_sender_card(msg["sender"])  # step 5, ID-003
        key_id, pub_raw = self._sender_signing_key(card)
        if msg["sender_key_id"] != key_id:
            raise err("ERR_SIGNATURE_INVALID", "unknown sender key id")
        verify_envelope(env, PT_MESSAGE, pub_raw,  # step 6
                        key_id=msg["sender_key_id"])
        check_key_not_revoked(card, msg["sender_key_id"], msg["created_at"])  # ID-024
        self._check_sender_key_window(card, msg["created_at"])  # ID-014
        if msg["recipient"] != self._agent_id:  # step 7, MSG-002
            raise err("ERR_RECIPIENT_MISMATCH", "message not addressed to self")
        msg_mod.check_time_window(msg, now, skew_seconds=self._skew)  # MSG-003
        self._prune_replay(now)
        key = _replay_key(msg["sender"], msg["id"])
        prior = self._replay.get(key)
        if isinstance(prior, dict) and "response" in prior:  # MSG-004/005
            exc = err("ERR_REPLAY_DETECTED", "duplicate message id")
            exc.previous_response = prior["response"]
            raise exc
        if msg["type"] == "OFFER":  # step 8, MSG-006
            out = self._handle_offer(msg, now)
        elif msg["type"] == "COMPLETE":
            out = self._handle_complete(msg, now)
        else:
            # Known-but-unexpected at the receiver (ACCEPT/STATUS/...) and
            # unknown types alike: unsupported here.
            raise err("ERR_UNSUPPORTED_MESSAGE",
                      f"unsupported message type {msg['type']!r}")
        self._replay[key] = {"expires_at": msg["expires_at"], "response": out}
        self._prune_replay(now)
        self._save_replay()
        return out

    def on_message(self, msg: dict, *, now: str) -> list:
        """Dispatch an already-authenticated message (pure state transition).

        ``receive_control`` performs steps 1-7 then calls this; tests may call
        it directly with a message that passed authentication.
        """
        msg_mod.parse_ts(now)
        msg_mod.check_shape(msg)
        if msg["type"] == "OFFER":
            return self._handle_offer(msg, now)
        if msg["type"] == "COMPLETE":
            return self._handle_complete(msg, now)
        raise err("ERR_UNSUPPORTED_MESSAGE",
                  f"unsupported message type {msg['type']!r}")

    # -- OFFER (TRF-001..005) ----------------------------------------------

    def _reject(self, sender: str, txid: str | None, code: str, detail: str, *,
                now: str, in_reply_to: str | None) -> list:
        shown = txid if txid is not None else "unknown"
        env = self._sign_response("REJECT", sender,
                                  {"transfer_id": shown, "code": code,
                                   "detail": detail},
                                  now=now, transfer_id=shown,
                                  in_reply_to=in_reply_to)
        if txid is not None and txid not in self._store:
            self._store[txid] = {"transfer_id": txid, "state": "REJECTED",
                                 "sender": sender, "chunks": {}, "have": [],
                                 "cek_b64u": "", "failures": 0}
            self._save_store()
        self._audit("transfer_state", transfer_id=shown, state="REJECTED",
                    sender=sender, recipient=self._agent_id, code=code)
        return [env]

    def _policy_verdict(self, msg: dict, body: dict, now: str) -> dict:
        """Run the injected policy callable before any ACCEPT (D-044).

        Fail closed three ways: an unconfigured ``policy_resource`` and a
        policy active with no grant leaf are both denies, never an
        allow-by-absence. An ``AATPError`` from the policy carries its own
        code into the REJECT and is labelled with the rule that code belongs
        to; any other exception becomes ``ERR_INTERNAL`` so the caller still
        gets a signed REJECT instead of a traceback.

        ``presenter`` defaults to this receiver, not the OFFER sender: the
        action being granted (``aatp.artifact.receive``) is the receiver's own
        and blueprint section 10.1 issues that leaf to ``aud`` = the receiving
        agent. The sender stays bound by pinned trust (ID-003) in
        ``receive_control``, before this gate runs. ``policy_presenter``
        overrides the default for a deployment whose grants are addressed to
        the sender.
        """
        txid = body["transfer_id"]
        if self._policy_resource is None:
            # No configured resource means no authorization can be expressed;
            # deny loudly instead of letting it surface as a res mismatch.
            self._audit("policy_decision", subject=msg["sender"],
                        action=self._policy_action, resource="unconfigured",
                        transfer_id=txid, decision="deny", rule_id="AUT-006")
            return {"decision": "deny", "rule_id": "AUT-006",
                    "code": "ERR_POLICY_DENIED",
                    "detail": "policy_resource must be configured"}
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
                "roots": set(self._roots),
                "revoked": set(self._revoked_grants),
                "manifest": body.get("manifest"),
                "presenter": self._policy_presenter or self._agent_id,
                "now": now,
            }
            try:
                verdict = self._policy_fn(request)
            except AATPError as e:
                verdict = {"decision": "deny",
                           "rule_id": _POLICY_RULE_BY_CODE.get(e.code, "AUT-001"),
                           "code": e.code}
            except Exception:
                verdict = {"decision": "deny", "rule_id": "INTERNAL",
                           "code": "ERR_INTERNAL"}
        if not isinstance(verdict, dict) or verdict.get("decision") != "allow":
            code = "ERR_POLICY_DENIED"
            rule = "AUT-006"
            if isinstance(verdict, dict):
                if isinstance(verdict.get("code"), str):
                    code = verdict["code"]
                if isinstance(verdict.get("rule_id"), str):
                    rule = verdict["rule_id"]
            self._audit("policy_decision", subject=msg["sender"],
                        action=self._policy_action,
                        resource=self._policy_resource,
                        transfer_id=txid, decision="deny", rule_id=rule)
            return {"decision": "deny", "rule_id": rule, "code": code}
        allow_rule = verdict.get("rule_id")
        self._audit("policy_decision", subject=msg["sender"],
                    action=self._policy_action, resource=self._policy_resource,
                    transfer_id=txid, decision="allow",
                    rule_id=allow_rule if isinstance(allow_rule, str)
                    else "POLICY-ALLOW")
        return verdict

    def _handle_offer(self, msg: dict, now: str) -> list:
        now_dt = msg_mod.parse_ts(now)
        sender = msg["sender"]
        body = msg["body"]
        reply_to = msg["id"]

        def rej(code, detail, tx=None):
            return self._reject(sender, tx, code, detail, now=now,
                                in_reply_to=reply_to)

        if not isinstance(body, dict):
            return rej("ERR_MALFORMED_MESSAGE", "OFFER body must be an object")
        try:
            msg_mod.check_id(body.get("transfer_id"), "transfer_id")
        except AATPError:
            return rej("ERR_MALFORMED_MESSAGE", "bad transfer_id")
        txid = body["transfer_id"]
        self._audit("message_received", msg_id=msg["id"], msg_type="OFFER",
                    sender=sender, recipient=self._agent_id, transfer_id=txid)

        def rej_tx(code, detail):
            return rej(code, detail, txid)

        if txid in self._store:
            # TRF-022: same tx+CEK resumes via chunks/STATUS; a fresh msg id
            # reusing a transfer_id is a new attempt, which MUST use a new
            # transfer_id (and CEK). Fail closed.
            raise err("ERR_TRANSFER_NOT_FOUND", "transfer_id already in use")
        if self._policy_fn is not None:
            # Blueprint 10.2: grant/authorization before artifact checks.
            verdict = self._policy_verdict(msg, body, now)
            if verdict["decision"] != "allow":
                return rej_tx(verdict["code"], verdict.get("detail") or
                              f"policy denied: {verdict['rule_id']}")
        if not isinstance(body.get("content_root"), str) or not \
                re.match(r"^sha256:[0-9a-f]{64}$", body["content_root"]):
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad content_root")
        chunk_size = body.get("chunk_size")
        if (not isinstance(chunk_size, int) or isinstance(chunk_size, bool)
                or not 1 <= chunk_size <= CHUNK_SIZE_MAX):
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad chunk_size")
        total = body.get("total_chunks")
        if (not isinstance(total, int) or isinstance(total, bool)
                or not 0 <= total <= TOTAL_CHUNKS_MAX):
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad total_chunks")
        stream_len = body.get("stream_len")
        if (not isinstance(stream_len, int) or isinstance(stream_len, bool)
                or stream_len < 0):
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad stream_len")
        if body.get("cipher") != "chacha20poly1305":
            # AES-256-GCM is OPTIONAL (blueprint section 3.1); M5 has no
            # negotiation, so anything else is an unsupported suite.
            return rej_tx("ERR_SUITE_UNSUPPORTED", "cipher must be chacha20poly1305")
        wraps = body.get("wraps")
        if not isinstance(wraps, list) or not wraps:
            return rej_tx("ERR_MALFORMED_MESSAGE", "wraps must be a non-empty list")
        if body.get("parent_policy") not in ("lazy", "require"):
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad parent_policy")
        if body.get("classification") not in CLASSIFICATIONS:
            # Shape enforced; grant-vs-classification policy is M6 scope.
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad classification")
        try:
            offer_exp = msg_mod.parse_ts(body.get("expires_at"))
        except AATPError:
            return rej_tx("ERR_MALFORMED_MESSAGE", "bad offer expires_at")
        if "manifest" in body and "sealed_manifest" in body:
            return rej_tx("ERR_MALFORMED_MESSAGE",
                       "manifest and sealed_manifest are exclusive")
        if "manifest" not in body:
            # TRF-004 sealed_manifest privacy profile: not implemented in M5.
            return rej_tx("ERR_UNSUPPORTED_EXTENSION", "sealed_manifest unsupported")
        if now_dt > offer_exp:  # TRF-005, strict: no skew grace on expiry.
            return rej_tx("ERR_MESSAGE_EXPIRED", "OFFER expired")
        manifest = body["manifest"]
        try:
            artifact_mod.validate_manifest(manifest)  # ART-001..007 + limits
        except AATPError as e:
            return rej_tx(e.code, e.detail or "")
        if sum(e["size"] for e in manifest["entries"]) != stream_len:  # TRF-002
            return rej_tx("ERR_MANIFEST_INVALID", "stream_len != sum(sizes)")
        expect = ((stream_len + chunk_size - 1) // chunk_size) if stream_len else 0
        if expect != total or (total == 0) != (stream_len == 0):  # ART-020
            return rej_tx("ERR_MANIFEST_INVALID", "total_chunks mismatch")
        node_env = body.get("node_env")
        if not isinstance(node_env, dict) or not isinstance(
                node_env.get("payload"), str):
            return rej_tx("ERR_MALFORMED_MESSAGE", "node_env must be a DSSE envelope")
        try:
            node_raw = b64u_dec(node_env["payload"])
            node_claim = parse_jcs(node_raw)
        except AATPError:
            return rej_tx("ERR_MALFORMED_MESSAGE", "node_env payload malformed")
        if not isinstance(node_claim, dict) or \
                node_claim.get("content_root") != body["content_root"]:  # TRF-001
            return rej_tx("ERR_ARTIFACT_HASH_MISMATCH",
                       "node content_root != OFFER content_root")
        entry = None
        for w in wraps:
            if (isinstance(w, dict) and w.get("agent_id") == self._agent_id
                    and isinstance(w.get("enc_key_id"), str)):
                entry = w
                break
        if entry is None:  # TRF-003
            return rej_tx("ERR_DECRYPT_FAILED", "no wrap for this recipient")
        try:
            cek = seal_mod.unwrap_cek(entry, body["content_root"], sender,
                                      txid, self._keystore)
        except AATPError as e:
            return rej_tx(e.code, e.detail or "")
        assert len(cek) == 32
        self._store[txid] = {
            "transfer_id": txid, "content_root": body["content_root"],
            "manifest": manifest, "node_env": node_env, "node": node_claim,
            "chunk_size": chunk_size, "total_chunks": total,
            "stream_len": stream_len, "cipher": body["cipher"],
            "sender": sender, "sender_key_id": msg["sender_key_id"],
            "offer_expires_at": body["expires_at"],
            "parent_policy": body["parent_policy"],
            "classification": body["classification"],
            "cek_b64u": b64u(cek), "chunks": {}, "have": [],
            "state": "ACCEPTED", "failures": 0, "node_id": "", "receipt": None,
        }
        self._save_store()
        self._audit("transfer_state", transfer_id=txid, state="ACCEPTED",
                    sender=sender, recipient=self._agent_id)
        accept = self._sign_response("ACCEPT", sender, {"transfer_id": txid},
                                     now=now, transfer_id=txid,
                                     in_reply_to=reply_to)
        return [accept]

    # -- CHUNK (TRF-010..014) ------------------------------------------------

    def _live_record(self, transfer_id: str, now: str) -> dict:
        rec = self._store.get(transfer_id)
        if not isinstance(rec, dict) or rec.get("state") not in CHUNK_ACCEPT_STATES:
            raise err("ERR_TRANSFER_NOT_FOUND", "unknown transfer")
        try:
            offer_exp = msg_mod.parse_ts(rec["offer_expires_at"])
        except (KeyError, TypeError, AATPError):
            raise err("ERR_INTERNAL", "transfer record corrupt") from None
        if msg_mod.parse_ts(now) > offer_exp:
            rec["state"] = "EXPIRED"
            self._save_store()
            raise err("ERR_TRANSFER_NOT_FOUND", "transfer expired")
        return rec

    def receive_chunk(self, frame: dict, *, now: str) -> list:
        """Store one data-plane chunk frame (TRF-010: no signature)."""
        msg_mod.parse_ts(now)
        if not isinstance(frame, dict) or \
                set(frame.keys()) != {"transfer_id", "index", "data"}:
            raise err("ERR_MALFORMED_MESSAGE",
                      "chunk needs exactly {transfer_id,index,data}")
        txid = frame["transfer_id"]
        if not isinstance(txid, str):
            raise err("ERR_MALFORMED_MESSAGE", "chunk transfer_id must be str")
        try:
            msg_mod.check_id(txid, "transfer_id")
        except AATPError:
            raise err("ERR_MALFORMED_MESSAGE", "bad chunk transfer_id") from None
        index = frame["index"]
        if (not isinstance(index, int) or isinstance(index, bool) or index < 0):
            raise err("ERR_SEQUENCE_INVALID", "chunk index must be >= 0")  # TRF-011
        rec = self._live_record(txid, now)
        total = rec["total_chunks"]
        if index >= total:  # TRF-011
            raise err("ERR_SEQUENCE_INVALID", "chunk index >= total_chunks")
        if str(index) in rec["chunks"]:
            return []  # TRF-012: duplicates are idempotent, not re-processed.
        verified = {int(k) for k in rec["chunks"].keys()}
        contiguous = 0
        while contiguous in verified:
            contiguous += 1
        if index > contiguous + self._window - 1:  # TRF-013
            raise err("ERR_SEQUENCE_INVALID", "chunk beyond receive window")
        if not isinstance(frame["data"], str):
            raise err("ERR_MALFORMED_MESSAGE", "chunk data must be a string")
        try:
            ct = b64u_dec(frame["data"])
        except AATPError:
            raise err("ERR_CHUNK_AUTH_FAILED", "chunk data undecodable") from None
        try:
            cek = b64u_dec(rec["cek_b64u"])
        except AATPError:
            raise err("ERR_INTERNAL", "stored CEK corrupt") from None
        try:  # TRF-014: verified only after AEAD open succeeds.
            pt = chunks_mod.decrypt_one(cek, index, total, rec["content_root"],
                                        txid, ct)
        except AATPError as e:
            rec["failures"] = rec.get("failures", 0) + 1
            if rec["failures"] > MAX_CHUNK_FAILURES:
                rec["state"] = "ABORTED"
            self._save_store()
            raise e
        rec["chunks"][str(index)] = b64u(pt)
        self._audit("chunk_verified", transfer_id=txid, index=index)
        rec["have"] = ranges_of({int(k) for k in rec["chunks"].keys()})
        rec["failures"] = 0
        was_paused = rec["state"] == "PAUSED"
        if rec["state"] == "ACCEPTED":
            rec["state"] = "RECEIVING"
        elif rec["state"] == "PAUSED":
            rec["state"] = "RECEIVING"
        self._save_store()  # TRF-020
        if was_paused:
            return [self._status_envelope(rec, now)]
        return []

    # -- COMPLETE / VERIFYING / RECEIPT (TRF-025/026, ART-021/022) -------------

    def _actor_key(self, actor: str) -> bytes:
        # Node actor keys resolve through the same card map as senders, but
        # actor trust is a policy (M6) question, not an authentication one:
        # the signature is still verified against the resolved key here.
        try:
            card = self._resolver(actor)
        except AATPError:
            raise
        except Exception as e:
            raise err("ERR_AUTH_FAILED", "actor key unresolvable") from e
        if not isinstance(card, dict) or card.get("agent_id") != actor:
            raise err("ERR_AUTH_FAILED", "actor card mismatch")
        _, raw = self._sender_signing_key(card)
        return raw

    def _handle_complete(self, msg: dict, now: str) -> list:
        body = msg["body"]
        if not isinstance(body, dict):
            raise err("ERR_MALFORMED_MESSAGE", "COMPLETE body must be an object")
        try:
            msg_mod.check_id(body.get("transfer_id"), "transfer_id")
        except AATPError:
            raise err("ERR_MALFORMED_MESSAGE", "bad COMPLETE transfer_id") from None
        txid = body["transfer_id"]
        if (not isinstance(body.get("total_chunks"), int)
                or isinstance(body.get("total_chunks"), bool)
                or body["total_chunks"] < 0):
            raise err("ERR_MALFORMED_MESSAGE", "bad COMPLETE total_chunks")
        rec = self._live_record(txid, now)
        if body["total_chunks"] != rec["total_chunks"]:
            raise err("ERR_SEQUENCE_INVALID", "COMPLETE total mismatch")
        total = rec["total_chunks"]
        verified = {int(k) for k in rec["chunks"].keys()}
        if verified != set(range(total)):
            # N16: chunks missing -> stay RECEIVING, STATUS with the gap.
            if rec["state"] == "PAUSED":
                rec["state"] = "RECEIVING"
            self._save_store()
            return [self._status_envelope(rec, now, in_reply_to=msg["id"])]
        # Phase marker only: the verification runs synchronously below, so the
        # store never holds a VERIFYING state (it would not be resumable via
        # CHUNK_ACCEPT_STATES). The record goes from its accept-state straight
        # to COMPLETE/REJECTED.
        self._audit("artifact_verification_started", transfer_id=txid,
                    phase="verification_started", sender=msg["sender"],
                    recipient=self._agent_id)
        return self._finish_verified(rec, msg, now)

    def _finish_verified(self, rec: dict, msg: dict, now: str) -> list:
        total = rec["total_chunks"]
        manifest = rec["manifest"]
        try:
            stream = b"".join(b64u_dec(rec["chunks"][str(i)]) for i in range(total))
            off = 0
            for e in manifest["entries"]:  # ART-021: per-file digests.
                piece = stream[off:off + e["size"]]
                if len(piece) != e["size"] or \
                        "sha256:" + hashlib.sha256(piece).hexdigest() != e["d"]:
                    raise err("ERR_ARTIFACT_HASH_MISMATCH",
                              f"digest mismatch {e['path']!r}")
                off += e["size"]
            if off != len(stream):
                raise err("ERR_ARTIFACT_HASH_MISMATCH", "stream length mismatch")
            root = "sha256:" + hashlib.sha256(
                artifact_mod.D_CONTENT + jcs(manifest)).hexdigest()
            if root != rec["content_root"]:  # ART-022
                raise err("ERR_ARTIFACT_HASH_MISMATCH", "content_root mismatch")
            node_id = self._dag.add(rec["node_env"], self._actor_key)
            if rec.get("parent_policy") == "require" and \
                    self._dag.ancestry_status(node_id) != "complete":  # PRV-010
                raise err("ERR_INVALID_PARENT", "unresolvable parent")
        except AATPError as e:
            try:
                node_id = node_mod.node_id_of(rec["node"])
            except AATPError:
                node_id = ""
            rec["state"] = "REJECTED"
            self._save_store()
            self._audit_verified(rec, node_id)
            self._audit("transfer_state", transfer_id=rec["transfer_id"],
                        state="REJECTED", outcome="rejected")
            receipt = self._sign_response(
                "RECEIPT", rec["sender"],
                {"transfer_id": rec["transfer_id"],
                 "content_root": rec["content_root"], "node_id": node_id,
                 "outcome": "rejected", "code": e.code},
                now=now, transfer_id=rec["transfer_id"], in_reply_to=msg["id"])
            rec["receipt"] = receipt
            self._save_store()
            return [receipt]
        rec["state"] = "COMPLETE"
        rec["node_id"] = node_id
        self._audit_verified(rec, node_id)
        self._audit("transfer_state", transfer_id=rec["transfer_id"],
                    state="COMPLETE", outcome="accepted")
        receipt = self._sign_response(
            "RECEIPT", rec["sender"],
            {"transfer_id": rec["transfer_id"],
             "content_root": rec["content_root"], "node_id": node_id,
             "outcome": "accepted"},  # TRF-026: signed; only delivery proof.
            now=now, transfer_id=rec["transfer_id"], in_reply_to=msg["id"])
        rec["receipt"] = receipt
        self._save_store()
        return [receipt]

    # -- STATUS ---------------------------------------------------------------

    def get_status(self, transfer_id: str, *, now: str) -> dict:
        """Current receiver-verified STATUS envelope (resume driver, TRF-021)."""
        msg_mod.parse_ts(now)
        rec = self._store.get(transfer_id)
        if not isinstance(rec, dict):
            raise err("ERR_TRANSFER_NOT_FOUND", "unknown transfer")
        if rec.get("state") in ("REJECTED", "EXPIRED", "ABORTED"):
            raise err("ERR_TRANSFER_NOT_FOUND", "transfer not resumable")
        try:
            offer_exp = msg_mod.parse_ts(rec["offer_expires_at"])
        except (KeyError, TypeError, AATPError):
            raise err("ERR_INTERNAL", "transfer record corrupt") from None
        if msg_mod.parse_ts(now) > offer_exp:
            rec["state"] = "EXPIRED"
            self._save_store()
            raise err("ERR_TRANSFER_NOT_FOUND", "transfer expired")
        return self._status_envelope(rec, now)
