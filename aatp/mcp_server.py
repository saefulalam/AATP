"""M7-3 MCP tool adapters (blueprint section 16) + stdio runner.

Orchestration only: combines artifact / node / seal / chunks / messages /
transfer / grants / handoff / policy / quarantine / sec / relay. Private keys
stay in the caller's Signer / KeyStore; Context holds object references
(signer, keystore, cards, dag, relay, quarantine, handoff store, policy
roots / key_resolver) -- never raw private key bytes.

Never logs keys / CEKs / plaintext.
"""
import hashlib
import json
import secrets
import sys
from dataclasses import dataclass, field

from aatp import artifact as artifact_mod
from aatp import chunks as chunks_mod
from aatp import node as node_mod
from aatp import seal as seal_mod
from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_MESSAGE, make_envelope
from aatp.errors import AATPError, err
from aatp.messages import build_message, check_id, shift_ts
from aatp.transfer import validate_have_ranges

CLASSIFICATIONS = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"})
CHUNK_SIZE_MAX = 16777216
_OFFER_LIFETIME = 3600


def _malformed(detail: str) -> AATPError:
    return err("ERR_MALFORMED_MESSAGE", detail)


@dataclass
class Context:
    """Caller-owned handles for the five tools.

    ``agent`` is a signer-holder object with ``.agent_id`` / ``.signer``
    (plus ``.enc_pub`` / ``.enc_key_id`` / ``.keystore`` / ``.card`` where
    the holder serves as a recipient). ``cards`` maps agent_id -> card dict
    (resolves bare-id recipients to enc keys). ``receiver`` is the
    TransferReceiver bound to ``agent`` (needed by aatp_fetch);
    ``artifact_db`` tracks offered ``content_root -> manifest/stream/node``
    (needed by aatp_verify).
    """

    agent: object
    cards: dict
    seq_dir: str
    dag: object
    relay: object
    quarantine: object = None
    handoff: object = None
    roots: set = field(default_factory=set)
    key_resolver: object = None
    trusted: set = field(default_factory=set)
    now: str = ""
    receiver: object = None
    artifact_db: dict = field(default_factory=dict)


def _resolve_recipient(ctx: Context, r) -> tuple:
    """Return ``(agent_id, enc_pub_raw, enc_key_id)`` for a holder or id."""
    if isinstance(r, str):
        try:
            card = ctx.cards[r]
            enc = card["enc_key"]
            kid = enc["key_id"]
            pub_s = enc["public_key"]
        except (KeyError, TypeError, AttributeError):
            raise err("ERR_AUTH_FAILED", "unknown recipient") from None
        if not isinstance(kid, str) or not isinstance(pub_s, str):
            raise err("ERR_AUTH_FAILED", "unknown recipient")
        try:
            pub = b64u_dec(pub_s)
        except AATPError:
            raise err("ERR_AUTH_FAILED",
                      "recipient enc key undecodable") from None
        if len(pub) != 32:
            raise err("ERR_AUTH_FAILED",
                      "recipient enc key must be 32 bytes")
        return r, pub, kid
    try:
        return r.agent_id, bytes(r.enc_pub), r.enc_key_id
    except AttributeError:
        raise _malformed(
            "recipient must be an agent holder or agent_id") from None
    except (TypeError, ValueError):
        raise _malformed("recipient enc_pub must be bytes") from None


def _check_files(files) -> list:
    if not isinstance(files, (list, tuple)) or not files:
        raise _malformed("files must be a non-empty list")
    out = []
    for f in files:
        if (not isinstance(f, (list, tuple)) or len(f) != 3
                or not isinstance(f[0], str)
                or not isinstance(f[1], (bytes, bytearray))
                or not isinstance(f[2], bool)):
            raise _malformed("files entries must be (path, bytes, x)")
        out.append((f[0], bytes(f[1]), f[2]))
    return out


def aatp_offer(ctx: Context, files, recipients, task_id: str, *,
               chunk_size: int = 8, classification: str = "INTERNAL",
               parent_policy: str = "lazy") -> dict:
    """Build + seal an OFFER for each recipient (ENC-020); return packet(s)."""
    file_list = _check_files(files)
    if not isinstance(recipients, (list, tuple)) or not recipients:
        raise _malformed("recipients must be a non-empty list")
    check_id(task_id, "task_id")
    if (not isinstance(chunk_size, int) or isinstance(chunk_size, bool)
            or not 1 <= chunk_size <= CHUNK_SIZE_MAX):
        raise _malformed("chunk_size must be within [1, 16777216]")
    if classification not in CLASSIFICATIONS:
        raise _malformed("bad classification")
    if parent_policy not in ("lazy", "require"):
        raise _malformed("bad parent_policy")
    dests = [_resolve_recipient(ctx, r) for r in recipients]
    sender = ctx.agent.agent_id
    manifest, stream, cr = artifact_mod.build(file_list)
    node, node_id = node_mod.make_node(
        cr, [], "create", sender, task_id,
        {"kind": "ai", "assurance": "self_asserted"}, ctx.now)
    node_env = node_mod.make_node_envelope(node, ctx.agent.signer)
    transfer_id = "tx_" + secrets.token_hex(8)
    total = ((len(stream) + chunk_size - 1) // chunk_size) if stream else 0
    cek = secrets.token_bytes(32)
    cts = chunks_mod.encrypt_chunks(
        cek, stream, chunk_size, cr, transfer_id) if total else []
    wraps = [seal_mod.wrap_cek(cek, cr, sender, rid, ekid, transfer_id,
                               epub) for rid, epub, ekid in dests]
    del cek
    body = {"transfer_id": transfer_id, "content_root": cr,
            "manifest": manifest, "node_env": node_env,
            "chunk_size": chunk_size, "total_chunks": total,
            "stream_len": len(stream), "cipher": "chacha20poly1305",
            "wraps": wraps, "parent_policy": parent_policy,
            "classification": classification,
            "expires_at": shift_ts(ctx.now, _OFFER_LIFETIME)}
    packets = {}
    for rid, epub, ekid in dests:
        msg = build_message("OFFER", sender, ctx.agent.signer.key_id(),
                            rid, body, now=ctx.now,
                            corr={"transfer_id": transfer_id})
        packets[rid] = seal_mod.seal_packet(
            rid, ekid, epub, make_envelope(PT_MESSAGE, jcs(msg),
                                           ctx.agent.signer))
    if ctx.artifact_db is None:
        ctx.artifact_db = {}
    ctx.artifact_db[cr] = {"manifest": manifest, "stream": bytes(stream),
                           "node": node, "node_id": node_id,
                           "transfer_id": transfer_id}
    first = dests[0][0]
    return {"packets": packets, "packet": packets[first],
            "chunks": [{"index": i, "data": b64u(ct)}
                       for i, ct in enumerate(cts)],
            "transfer_id": transfer_id, "content_root": cr,
            "node_id": node_id, "total_chunks": total}


def aatp_fetch(ctx: Context, transfer_id: str) -> dict:
    """STATUS have + missing indices for a tracked transfer (TRF-021/023)."""
    recv = ctx.receiver
    if recv is None:
        raise err("ERR_INTERNAL", "no receiver bound to context")
    env = recv.get_status(transfer_id, now=ctx.now)
    try:
        body = parse_jcs(b64u_dec(env["payload"]))["body"]
        have = validate_have_ranges(body["have"])
    except (KeyError, TypeError):
        raise _malformed("receiver STATUS malformed") from None
    try:
        total = recv._store[transfer_id]["total_chunks"]
    except (AttributeError, KeyError, TypeError):
        raise err("ERR_TRANSFER_NOT_FOUND", "unknown transfer") from None
    if (not isinstance(total, int) or isinstance(total, bool) or total < 0):
        raise err("ERR_INTERNAL", "transfer record corrupt")
    covered = set()
    for lo, hi in have:
        covered.update(range(lo, hi + 1))
    return {"have": have,
            "missing": [i for i in range(total) if i not in covered],
            "total": total}


def aatp_verify(ctx: Context, content_root: str) -> dict:
    """Recompute manifest digests + content_root from the tracked artifact."""
    entry = (ctx.artifact_db or {}).get(content_root)
    if entry is None:
        return {"ok": False, "code": "ERR_ARTIFACT_NOT_FOUND"}
    try:
        manifest = entry["manifest"]
        stream = entry["stream"]
        artifact_mod.validate_manifest(manifest)
        off = 0
        for e in manifest["entries"]:
            piece = stream[off:off + e["size"]]
            if (len(piece) != e["size"] or "sha256:" + hashlib.sha256(
                    piece).hexdigest() != e["d"]):
                raise err("ERR_ARTIFACT_HASH_MISMATCH",
                           f"digest mismatch {e['path']!r}")
            off += e["size"]
        if off != len(stream):
            raise err("ERR_ARTIFACT_HASH_MISMATCH", "stream length mismatch")
        root = "sha256:" + hashlib.sha256(
            artifact_mod.D_CONTENT + jcs(manifest)).hexdigest()
        if root != content_root:
            raise err("ERR_ARTIFACT_HASH_MISMATCH", "content_root mismatch")
    except AATPError as e:
        return {"ok": False, "code": e.code}
    return {"ok": True, "code": None}


def aatp_provenance(ctx: Context, node_id: str) -> dict:
    """Node + ancestry status from the shared DAG (PRV-011)."""
    try:
        node = ctx.dag.get(node_id)
        ancestry = ctx.dag.ancestry_status(node_id)
    except AATPError as e:
        return {"node": None, "ancestry": None, "code": e.code}
    return {"node": node, "ancestry": ancestry, "code": None}


def aatp_handoff(ctx: Context, task_id: str, agent, grant_env,
                 **fields) -> dict:
    """Offer a handoff to ``agent`` (HND-003/004); return id + state."""
    store = ctx.handoff
    if store is None:
        raise err("ERR_INTERNAL", "no handoff store bound to context")
    check_id(task_id, "task_id")
    rid = agent if isinstance(agent, str) else agent.agent_id
    hid = fields.get("handoff_id", f"handoff_{task_id}")
    if not isinstance(grant_env, dict):
        raise _malformed("grant_env must be an object")
    policy_context = fields.get("policy_context")
    if policy_context is None:
        policy_context = {"resource": fields.get("resource", task_id)}
    task = {"task_id": task_id,
            "title": fields.get("title", task_id),
            "objective": fields.get("objective", task_id)}
    if "constraints" in fields:
        task["constraints"] = fields["constraints"]
    body = {"handoff_id": hid, "task": task,
            "input_node_ids": list(fields.get("input_node_ids", [])),
            "grant_env": grant_env,
            "expected_outputs": list(fields.get("expected_outputs", [])),
            "deadline": fields.get("deadline", shift_ts(ctx.now, 86400)),
            "lease_expires_at": fields.get("lease_expires_at",
                                           shift_ts(ctx.now, 3600)),
            "policy_context": policy_context}
    store.offer(body, fields.get("grant_chain_envs", []), ctx.now,
                sender=ctx.agent.agent_id, recipient=rid,
                roots=ctx.roots, key_resolver=ctx.key_resolver)
    return {"handoff_id": hid, "state": store.state_of(hid)}


# --- stdio JSON-RPC-ish runner (stdlib sys/json only) ----------------------------

_TOOL_ALIASES = {
    "aatp_offer": "offer", "aatp.offer": "offer",
    "aatp_fetch": "fetch", "aatp.fetch": "fetch",
    "aatp_verify": "verify", "aatp.verify": "verify",
    "aatp_provenance": "provenance", "aatp.provenance": "provenance",
    "aatp_handoff": "handoff", "aatp.handoff": "handoff",
}


def _coerce_files(entries) -> list:
    """Accept ``[{path,text|data_b64,x}]`` or ``[[path, text, x]]``."""
    if not isinstance(entries, (list, tuple)):
        raise _malformed("files must be a list")
    out = []
    for f in entries:
        if isinstance(f, dict):
            path, x = f.get("path"), f.get("x", False)
            if not isinstance(path, str) or not isinstance(x, bool):
                raise _malformed("file needs {path, x}")
            if "data_b64" in f:
                try:
                    data = b64u_dec(f["data_b64"])
                except AATPError:
                    raise _malformed("file data_b64 undecodable") from None
            elif "text" in f:
                if not isinstance(f["text"], str):
                    raise _malformed("file text must be a string")
                data = f["text"].encode("utf-8")
            else:
                raise _malformed("file needs text or data_b64")
            out.append((path, data, x))
        elif isinstance(f, (list, tuple)) and len(f) == 3:
            path, data, x = f
            if not isinstance(path, str) or not isinstance(x, bool):
                raise _malformed("file needs [path, text, x]")
            if not isinstance(data, str):
                raise _malformed("file text must be a string")
            out.append((path, data.encode("utf-8"), x))
        else:
            raise _malformed("file needs {path, text|data_b64, x}")
    return out


def _dispatch(ctx: Context, tool: str, args: dict) -> dict:
    if tool == "offer":
        return aatp_offer(ctx, _coerce_files(args["files"]),
                          args["recipients"], args["task_id"],
                          chunk_size=args.get("chunk_size", 8),
                          classification=args.get("classification",
                                                  "INTERNAL"),
                          parent_policy=args.get("parent_policy", "lazy"))
    if tool == "fetch":
        return aatp_fetch(ctx, args["transfer_id"])
    if tool == "verify":
        return aatp_verify(ctx, args["content_root"])
    if tool == "provenance":
        return aatp_provenance(ctx, args["node_id"])
    if tool == "handoff":
        passthrough = {k: v for k, v in args.items()
                       if k not in ("task_id", "agent", "grant_env")}
        return aatp_handoff(ctx, args["task_id"], args["agent"],
                            args["grant_env"], **passthrough)
    raise err("ERR_UNSUPPORTED_MESSAGE", f"unknown tool {tool!r}")


def handle_line(ctx: Context, line: str) -> str:
    """Handle one ``{"tool", "args"}`` line; return the response line."""
    try:
        req = json.loads(line)
    except (ValueError, TypeError):
        return json.dumps({"ok": False, "code": "ERR_MALFORMED_MESSAGE"})
    if (not isinstance(req, dict) or not isinstance(req.get("tool"), str)):
        return json.dumps({"ok": False, "code": "ERR_MALFORMED_MESSAGE"})
    args = req.get("args", {})
    if not isinstance(args, dict):
        return json.dumps({"ok": False, "code": "ERR_MALFORMED_MESSAGE"})
    name = _TOOL_ALIASES.get(req["tool"])
    if name is None:
        return json.dumps({"ok": False, "code": "ERR_UNSUPPORTED_MESSAGE"})
    try:
        result = _dispatch(ctx, name, args)
    except AATPError as e:
        return json.dumps({"ok": False, "code": e.code})
    except (KeyError, TypeError, ValueError):
        return json.dumps({"ok": False, "code": "ERR_MALFORMED_MESSAGE"})
    except Exception:
        return json.dumps({"ok": False, "code": "ERR_INTERNAL"})
    return json.dumps({"ok": True, "result": result})


def run_stdio(ctx: Context) -> None:
    """Loop over stdin ``{"tool", "args"}`` lines; write result lines."""
    for raw in sys.stdin:
        if not raw.strip():
            continue
        sys.stdout.write(handle_line(ctx, raw) + "\n")
    sys.stdout.flush()
