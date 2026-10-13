"""Per-agent AATP CLI for the 4-agent HTTP demo (DEMO tooling, not the library).

Subcommands:

    init        create <dir>/state.json + card from a deterministic demo seed
    publish     PUT the agent card to the relay
    grant       issue a grant into <dir>/grants.json
    grant-load  print the leaf/chain/roots the receiver needs
    send        POST OFFER + upload chunks (+ --resume for STATUS-driven resume)
    receive     drain the mailbox, run the real TransferReceiver, verify,
                materialize and quarantine

The relay never opens anything: packets, chunks and cards move as opaque
bytes over localhost HTTP (``aatp.transport.http``).

All key material here is TEST-ONLY deterministic demo material -- see
tools/README.md. CRY-007 (cryptographic review) is still OPEN.
"""
import argparse
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aatp import artifact as artifact_mod
from aatp import chunks as chunks_mod
from aatp import node as node_mod
from aatp import seal as seal_mod
from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.card import CardCache, verify_card
from aatp.dsse import PT_CARD, PT_GRANT, PT_MESSAGE, make_envelope, verify_envelope
from aatp.errors import AATPError
from aatp.grants import grant_id_of
from aatp.ids import derive_agent_id
from aatp.messages import build_message, format_ts, shift_ts
from aatp.node import DagStore
from aatp.quarantine import Quarantine
from aatp.seal import KeyStore
from aatp.signer import SoftwareSigner
from aatp.transfer import TransferReceiver, sender_due_chunks

D_DEMO_SEED = b"AATP/0.2/DEMO-SEED\n"
RELAY_DEFAULT = "http://127.0.0.1:8765"
CARD_LAG_SECONDS = 60
CARD_TTL_SECONDS = 20 * 86400
ENC_TTL_SECONDS = 6 * 86400
SIGN_TTL_SECONDS = 365 * 86400
GRANT_TTL_SECONDS = 3600
DEFAULT_CHUNK_SIZE = 64
DEFAULT_POLICY_ACTION = "aatp.artifact.receive"
DEFAULT_CLASSIFICATION = "INTERNAL"
MAILBOX_PREFIX = "/aatp/v0.2/mailbox/"
SCANNER_NAME = "demo-scan"
SCANNER_VERSION = "0.1"


def now_ts() -> str:
    return format_ts(datetime.now(timezone.utc))


def demo_seed(name: str) -> bytes:
    """TEST-ONLY key material: deterministic per agent name, never a real key."""
    return hashlib.sha256(D_DEMO_SEED + name.encode("utf-8")).digest()


def _ts_offset(seconds: int) -> str:
    return now_ts() if seconds == 0 else shift_ts(now_ts(), seconds)


# -- relay HTTP client ---------------------------------------------------

def http(method: str, url: str, body: bytes | None = None,
         headers: dict | None = None) -> tuple:
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        raise SystemExit(f"relay unreachable at {url}: {e.reason}")


def relay_put_packet(base: str, packet: dict) -> tuple:
    return http("POST", f"{base}/aatp/v0.2/packets", jcs(packet),
                {"Content-Type": "application/json"})


def relay_put_chunk(base: str, transfer_id: str, index: int, data_b64: str) -> tuple:
    return http("PUT", f"{base}/aatp/v0.2/transfers/{transfer_id}/chunks/{index}",
                data_b64.encode("ascii"))


def relay_get_chunk(base: str, transfer_id: str, index: int):
    status, raw = http(
        "GET", f"{base}/aatp/v0.2/transfers/{transfer_id}/chunks/{index}")
    return raw.decode("ascii") if status == 200 else None


def relay_put_card(base: str, agent_id: str, card_env: dict) -> tuple:
    return http("PUT", f"{base}/aatp/v0.2/agents/{agent_id}/card",
                jcs(card_env), {"Content-Type": "application/json"})


def relay_get_card(base: str, agent_id: str):
    status, raw = http("GET", f"{base}/aatp/v0.2/agents/{agent_id}/card")
    if status != 200:
        return None
    return parse_jcs(b64u_dec(json.loads(raw)["payload"]))


def auth_header(signer, agent_id: str, path: str, created_at: str) -> str:
    payload = jcs({"method": "GET", "path": path,
                   "created_at": created_at, "agent_id": agent_id})
    return "DSSE " + b64u(jcs(make_envelope(PT_MESSAGE, payload, signer)))


def relay_mailbox(base: str, st: dict) -> list:
    """Drain our mailbox (GET + drain, DSSE-authenticated)."""
    path = f"{MAILBOX_PREFIX}{st['agent_id']}"
    status, raw = http("GET", f"{base}{path}", None,
                       {"Authorization": auth_header(st["signer"],
                                                    st["agent_id"], path,
                                                    now_ts())})
    if status != 200:
        raise SystemExit(f"mailbox GET failed: {status} {raw!r}")
    return json.loads(raw)


def send_envelope(base: str, st: dict, recipient: dict, msg_type: str, body: dict,
                  *, now: str, corr: dict | None = None,
                  lifetime: int = 3600) -> str:
    """Sign, seal and POST one control message; return its message id."""
    msg = build_message(msg_type, st["agent_id"], st["signer"].key_id(),
                        recipient["agent_id"], body, now=now,
                        lifetime=lifetime, corr=corr or {})
    env = make_envelope(PT_MESSAGE, jcs(msg), st["signer"])
    pkt = seal_mod.seal_packet(recipient["agent_id"], recipient["enc_key_id"],
                               recipient["enc_pub"], env)
    status, raw = relay_put_packet(base, pkt)
    if status != 202:
        raise SystemExit(f"relay rejected {msg_type}: {status} {raw!r}")
    return msg["id"]


def open_incoming(st: dict, packet: dict) -> tuple:
    """Open a sealed packet into ``(envelope, message)``."""
    env = seal_mod.open_packet(packet, st["keystore"])
    msg = parse_jcs(b64u_dec(env["payload"]))
    return env, msg


def verify_inbound(st: dict, env: dict, card: dict) -> dict:
    """Verify a signed envelope from a peer card (SIG-003 + ID-003)."""
    key_id = parse_jcs(b64u_dec(env["payload"]))["sender_key_id"]
    pub = b64u_dec(card["signing_key"]["public_key"])
    return verify_envelope(env, PT_MESSAGE, pub, key_id=key_id)


def own_envelope(st: dict, env: dict) -> dict:
    """Verify an envelope we signed ourselves (receiver responses)."""
    return verify_envelope(env, PT_MESSAGE, st["signer"].public_key_raw(),
                           key_id=st["signer"].key_id())


# -- durable agent state -------------------------------------------------

def state_path(directory) -> Path:
    return Path(directory) / "state.json"


def grants_path(directory) -> Path:
    return Path(directory) / "grants.json"


def read_json(path: Path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return default


def write_json(path: Path, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def load_state(directory) -> dict:
    """Rebuild signer/keystore/card from ``<dir>/state.json`` (restart-safe)."""
    raw = read_json(state_path(directory), None)
    if raw is None:
        raise SystemExit(f"no agent state in {directory}; run `init` first")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    signer = SoftwareSigner.from_seed(bytes.fromhex(raw["sign_seed"]),
                                      raw["sign_key_id"])
    enc_priv = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(raw["enc_seed"])).private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    card = read_json(Path(directory) / "card.json", raw["card_env"])
    return {"dir": Path(directory), "name": raw["name"],
            "agent_id": raw["agent_id"], "signer": signer,
            "keystore": KeyStore({raw["enc_key_id"]: enc_priv}),
            "card": card, "card_env": raw["card_env"],
            "sign_key_id": raw["sign_key_id"],
            "enc_key_id": raw["enc_key_id"],
            "enc_pub": b64u_dec(card["enc_key"]["public_key"])}


def build_card(agent_id: str, sign_key_id: str, sign_pub: bytes,
               enc_key_id: str, enc_pub: bytes) -> dict:
    return {
        "v": "0.2", "agent_id": agent_id,
        "genesis_public_key": b64u(sign_pub),
        "signing_key": {"key_id": sign_key_id, "public_key": b64u(sign_pub),
                        "not_before": _ts_offset(-CARD_LAG_SECONDS),
                        "not_after": _ts_offset(SIGN_TTL_SECONDS)},
        "enc_key": {"key_id": enc_key_id, "public_key": b64u(enc_pub),
                    "not_before": _ts_offset(-CARD_LAG_SECONDS),
                    "not_after": _ts_offset(ENC_TTL_SECONDS)},
        "key_history": [], "suites": ["AATP-S1"], "seq": 1,
        "issued_at": _ts_offset(-CARD_LAG_SECONDS),
        "expires_at": _ts_offset(CARD_TTL_SECONDS),
    }


def peer_info(st: dict, audience: str, cache: dict) -> dict:
    """Resolve a peer's card + enc key: cache, then ``peers.json``, then relay."""
    if audience in cache:
        return cache[audience]
    card = load_peers(st["dir"]).get(audience)
    if card is None:
        card = relay_get_card(st["relay"], audience)
    if card is None:
        raise SystemExit(f"peer {audience} has no published card on the relay")
    info = {"agent_id": audience, "card": card,
            "enc_key_id": card["enc_key"]["key_id"],
            "enc_pub": b64u_dec(card["enc_key"]["public_key"]),
            "sign_pub": b64u_dec(card["signing_key"]["public_key"])}
    cache[audience] = info
    return info


def load_peers(directory) -> dict:
    """Cards of known peers, written by ``publish`` (discovery is OPEN-10)."""
    return read_json(Path(directory) / "peers.json", {})


def transfer_records(directory) -> dict:
    """The receiver's own durable transfer store (no private attribute access)."""
    return read_json(Path(directory) / "xfer.json", {}).get("transfers", {})


# -- grants --------------------------------------------------------------

def make_policy(roots, key_resolver):
    """Policy callable for ``TransferReceiver`` backed by real policy.evaluate."""
    from aatp.policy import evaluate

    def policy(request):
        if request.get("grant_leaf_env") is None:
            # D-044: a policy with no grant leaf denies, never implicitly allows.
            # Mirrors TransferReceiver._policy_verdict, which short-circuits the
            # same way before calling the policy at all.
            return {"decision": "deny", "rule_id": "AUT-006",
                    "code": "ERR_POLICY_DENIED"}
        return evaluate(request, roots=roots, key_resolver=key_resolver,
                        presenter=request["presenter"], now=request["now"])
    return policy


def load_grants(args) -> dict:
    """Leaf + ancestor grant envelopes and roots for the receiver's policy."""
    db = read_json(grants_path(args.dir), {})
    if args.grants_file:
        db = read_json(Path(args.grants_file), db)
    leaf = None
    if args.grant_leaf:
        if args.grant_leaf not in db:
            raise SystemExit(f"grant {args.grant_leaf!r} not in the grants db")
        leaf = db[args.grant_leaf]["env"]
    chain = []
    for name in args.grant_chain or []:
        if name not in db:
            raise SystemExit(f"grant {name!r} not in the grants db")
        chain.append(db[name]["env"])
    return {"leaf": leaf, "chain": chain, "roots": list(args.root or []),
            "ids": {n: grant_id_of(db[n]["body"]) for n in db}}


# -- commands ------------------------------------------------------------

def cmd_init(args) -> int:
    d = Path(args.dir)
    d.mkdir(parents=True, exist_ok=True)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    seed = demo_seed(args.name)
    signer = SoftwareSigner.from_seed(seed, f"{args.name}-sig")
    agent_id = derive_agent_id(signer.public_key_raw())
    enc_kid = f"{args.name}-enc"
    enc_priv = X25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    enc_pub = X25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    card = build_card(agent_id, signer.key_id(), signer.public_key_raw(),
                      enc_kid, enc_pub)
    card_env = make_envelope(PT_CARD, jcs(card), signer)
    write_json(d / "card.json", card)
    write_json(d / "state.json", {
        "_test_only_keys": True,
        "note": "deterministic demo seeds; never production key material",
        "name": args.name, "agent_id": agent_id,
        "sign_key_id": signer.key_id(), "enc_key_id": enc_kid,
        "sign_seed": seed.hex(), "enc_seed": seed.hex(), "card_env": card_env})
    verify_card(card_env, agent_id, CardCache(str(d / "card-seq.json")), now_ts())
    print(f"init {args.name}: {agent_id}")
    return 0


def cmd_publish(args) -> int:
    st = load_state(args.dir)
    st["relay"] = args.relay
    status, raw = relay_put_card(args.relay, st["agent_id"], st["card_env"])
    if status != 204:
        raise SystemExit(f"card publish rejected: {status} {raw!r}")
    peers = load_peers(args.dir)
    peers[st["agent_id"]] = st["card"]
    for other in args.peer or []:
        card = relay_get_card(args.relay, other)
        if card is None:
            raise SystemExit(f"peer {other} has no card on the relay")
        peers[other] = card
    write_json(Path(args.dir) / "peers.json", peers)
    print(f"publish {st['name']}: {st['agent_id']} -> {args.relay} "
          f"({len(peers)} known cards)")
    return 0


def cmd_grant(args) -> int:
    """Coordinator issues a grant and stores it in <dir>/grants.json."""
    d = Path(args.dir)
    st = load_state(d)
    st["relay"] = args.relay
    cache = {}
    peer = peer_info(st, args.audience, cache)
    issuer_id = args.issuer or st["agent_id"]
    body = {
        "v": "0.2", "iss": issuer_id, "aud": peer["agent_id"],
        "cap": [{"act": a, "res": args.res} for a in args.act],
        "nbf": args.nbf or shift_ts(now_ts(), -60),
        "exp": args.exp or shift_ts(now_ts(), GRANT_TTL_SECONDS),
        "prf": list(args.prf or []),
        "constraints": {"classification_max": args.classification_max,
                        "export": False},
    }
    env = make_envelope(PT_GRANT, jcs(body), st["signer"])
    path = grants_path(d)
    db = read_json(path, {})
    db[args.name] = {"env": env, "body": body,
                     "grant_id": grant_id_of(body)}
    write_json(path, db)
    print(f"grant {args.name}: iss={issuer_id} aud={peer['agent_id']}")
    return 0


def cmd_grant_load(args) -> int:
    """Load grants from <dir>/grants.json and hand them to the receiver."""
    out = load_grants(args)
    if args.json:
        print(json.dumps({"leaf": out["leaf"], "chain": out["chain"],
                          "roots": out["roots"], "grant_ids": out["ids"]},
                         indent=2, sort_keys=True))
        return 0
    db = read_json(grants_path(args.dir), {})
    leaf = args.grant_leaf or "-"
    print(f"grant-load: leaf={leaf} "
          f"grant_id={out['ids'].get(leaf, 'none')}")
    if leaf in db:
        print(f"grant-load:   iss={db[leaf]['body']['iss']} "
              f"aud={db[leaf]['body']['aud']} "
              f"cap={json.dumps(db[leaf]['body']['cap'])}")
    print(f"grant-load: chain={[out['ids'].get(c) for c in args.grant_chain]} "
          f"({len(out['chain'])} envelope(s) loaded)")
    print(f"grant-load: roots={out['roots']}")
    print(f"grant-load: leaf envelope sha256="
          f"{hashlib.sha256(jcs(out['leaf'])).hexdigest() if out['leaf'] else '-'}")
    return 0


def collect_files(args) -> list:
    files = []
    for raw in args.file or []:
        p = Path(raw)
        files.append((p.as_posix(), p.read_bytes(), False))
    if args.src:
        root = Path(args.src)
        for p in sorted(root.rglob("*")):
            if p.is_file():
                files.append((p.relative_to(root).as_posix(),
                              p.read_bytes(), False))
    if not files:
        raise SystemExit("send needs --file or --src")
    return files


def build_offer(st: dict, peer: dict, files: list, *, transfer_id: str,
                chunk_size: int, task_id: str, classification: str,
                now: str, stream: bytes | None = None) -> dict:
    """Manifest + node + CEK + sealed chunks + the OFFER body."""
    manifest, plain, cr = artifact_mod.build(files)
    if stream is None:
        stream = plain
    node, node_id = node_mod.make_node(
        cr, [], "create", st["agent_id"], task_id,
        {"kind": "ai", "model": {"name": "aatp-demo"},
         "assurance": "self_asserted"}, now)
    node_env = node_mod.make_node_envelope(node, st["signer"])
    cek = secrets.token_bytes(32)
    cts = chunks_mod.encrypt_chunks(cek, stream, chunk_size, cr, transfer_id)
    wrap = seal_mod.wrap_cek(cek, cr, st["agent_id"], peer["agent_id"],
                             peer["enc_key_id"], transfer_id, peer["enc_pub"])
    body = {"transfer_id": transfer_id, "content_root": cr,
            "manifest": manifest, "node_env": node_env, "chunk_size": chunk_size,
            "total_chunks": len(cts), "stream_len": len(stream),
            "cipher": "chacha20poly1305", "wraps": [wrap],
            "parent_policy": "lazy", "classification": classification,
            "consumption_mode": "data_only",
            "expires_at": shift_ts(now, 3600)}
    return {"body": body, "cr": cr, "cts": cts, "node_id": node_id,
            "manifest": manifest, "stream": stream}


def outbox_path(directory, transfer_id: str) -> Path:
    return Path(directory) / "outbox" / f"{transfer_id}.json"


def cmd_send(args) -> int:
    d = Path(args.dir)
    st = load_state(d)
    st["relay"] = args.relay
    peer = peer_info(st, args.to, {})
    now = now_ts()
    if args.resume:
        return resume_send(args, st, peer)
    transfer_id = args.tx or f"tx_{args.name}_{transfer_tag()}"
    drop = set(args.drop_chunk or [])
    parts = build_offer(st, peer, collect_files(args), transfer_id=transfer_id,
                        chunk_size=args.chunk_size, task_id=args.task,
                        classification=args.classification, now=now)
    send_envelope(args.relay, st, peer, "OFFER", parts["body"], now=now,
                  corr={"transfer_id": transfer_id})
    sent = 0
    for i, ct in enumerate(parts["cts"]):
        if i in drop:
            print(f"send: deliberately dropping chunk {i} of "
                  f"{transfer_id} (resume demo)")
            continue
        status, raw = relay_put_chunk(args.relay, transfer_id, i, b64u(ct))
        if status != 204:
            raise SystemExit(f"chunk {i} rejected: {status} {raw!r}")
        sent += 1
    # The sender keeps what it sealed so ``--resume`` can re-upload a chunk
    # without re-deriving the CEK. Ciphertext only: no key material on disk.
    write_json(outbox_path(d, transfer_id),
               {"transfer_id": transfer_id, "chunks": [b64u(c) for c in parts["cts"]]})
    write_json(d / "pending.json",
               {"transfer_id": transfer_id, "to": peer["agent_id"],
                "content_root": parts["cr"], "chunk_size": args.chunk_size,
                "total_chunks": len(parts["cts"]), "task": args.task,
                "dropped": sorted(drop), "classification": args.classification,
                "expires_at": parts["body"]["expires_at"]})
    print(f"send: OFFER {transfer_id} -> {peer['agent_id']} "
          f"content_root={parts['cr'][:23]}... chunks={sent}/{len(parts['cts'])}")
    if not drop:
        # Nothing is missing, so the sender owns the COMPLETE right away. With a
        # dropped chunk it waits for the receiver's STATUS and `--resume` sends
        # both the missing chunk and COMPLETE (TRF-021).
        send_envelope(args.relay, st, peer, "COMPLETE",
                      {"transfer_id": transfer_id,
                       "total_chunks": len(parts["cts"])}, now=now,
                      corr={"transfer_id": transfer_id})
        print(f"send: COMPLETE {transfer_id}")
    return 0


def transfer_tag() -> str:
    return datetime.now(timezone.utc).strftime("%H%M%S")


def resume_send(args, st: dict, peer: dict) -> int:
    """TRF-021/024: read the receiver's STATUS, upload only what is missing."""
    pending = read_json(Path(args.dir) / "pending.json", None)
    if pending is None:
        raise SystemExit("nothing to resume; run `send` first")
    have = None
    for packet in relay_mailbox(args.relay, st):
        env, msg = open_incoming(st, packet)
        if msg["type"] != "STATUS":
            print(f"send: mailbox also carried {msg['type']}")
            continue
        verify_inbound(st, env, peer["card"])
        have = msg["body"]["have"]
        print(f"send: STATUS have={have}")
    if have is None:
        raise SystemExit("no STATUS in the mailbox; cannot resume")
    sealed = read_json(outbox_path(args.dir, pending["transfer_id"]), None)
    if sealed is None:
        raise SystemExit(f"no outbox for {pending['transfer_id']}; "
                         "run `send` and `send --resume` from the same directory")
    due = sender_due_chunks(have, pending["total_chunks"])
    for i in due:
        status, raw = relay_put_chunk(args.relay, pending["transfer_id"], i,
                                      sealed["chunks"][i])
        if status != 204:
            raise SystemExit(f"chunk {i} rejected: {status} {raw!r}")
    now = now_ts()
    send_envelope(args.relay, st, peer, "COMPLETE",
                  {"transfer_id": pending["transfer_id"],
                   "total_chunks": pending["total_chunks"]}, now=now,
                  corr={"transfer_id": pending["transfer_id"]})
    write_json(Path(args.dir) / "pending.json",
               dict(pending, resumed=due, completed_at=now))
    print(f"send: resumed chunks {due}, sent COMPLETE for "
          f"{pending['transfer_id']}")
    return 0


def cmd_receive(args) -> int:
    """Drain the mailbox up to ``--max-transfers`` passes and run the transfer."""
    d = Path(args.dir)
    st = load_state(d)
    st["relay"] = args.relay
    peers = load_peers(d)
    cache = {}
    for agent_id in peers:
        peer_info(st, agent_id, cache)
    cards = {a: v["card"] for a, v in cache.items()}
    cards[st["agent_id"]] = st["card"]

    receiver_kwargs = {}
    if args.policy:
        grants = load_grants(args)
        roots = set(grants["roots"])
        key_resolver = lambda aid: b64u_dec(  # noqa: E731
            cards[aid]["signing_key"]["public_key"])
        receiver_kwargs.update(
            policy_fn=make_policy(roots, key_resolver),
            grant_leaf_env=grants["leaf"],
            grant_chain_envs=grants["chain"], roots=roots,
            policy_action=args.policy_action,
            policy_resource=args.policy_resource,
            revoked_grants=set(args.revoked_grant or []))
        if args.policy_presenter:
            receiver_kwargs["policy_presenter"] = args.policy_presenter
        if args.audit_log:
            receiver_kwargs["audit_log_path"] = args.audit_log
    receiver = TransferReceiver(
        agent_id=st["agent_id"], signer=st["signer"], keystore=st["keystore"],
        card_resolver=lambda aid: cards[aid], trusted=set(cards),
        own_card=st["card"], dag=DagStore(parent_policy="lazy"),
        replay_path=str(d / "replay.json"), store_path=str(d / "xfer.json"),
        **receiver_kwargs)

    for _ in range(max(1, args.max_transfers)):
        packets = relay_mailbox(args.relay, st)
        if not packets:
            print("receive: mailbox empty")
            return 0
        for packet in packets:
            env, msg = open_incoming(st, packet)
            verify_inbound(st, env, cards[msg["sender"]])
            handle_incoming(args, st, msg, packet, receiver)
    return 0


def handle_incoming(args, st: dict, msg: dict, packet: dict,
                    receiver: TransferReceiver) -> None:
    now = now_ts()
    mtype = msg["type"]
    print(f"receive: {mtype} from {msg['sender']} id={msg['id']}")
    txid = msg["body"].get("transfer_id")
    if mtype == "COMPLETE" and txid in transfer_records(args.dir):
        # The control plane is sender-driven, so the receiver pulls the data
        # plane before it finalizes: whatever the sender already uploaded is
        # fetched and authenticated, and a real gap still surfaces as STATUS.
        pump_chunks(args, st, receiver, txid)
    try:
        responses = receiver.receive_control(packet, now=now)
    except AATPError as e:
        print(f"receive: {mtype} -> {e.code} ({e.detail})")
        return
    for env in responses:
        out = own_envelope(st, env)
        print(f"receive: <- {out['type']} body={_brief(out['body'])}")
        if out["type"] == "ACCEPT":
            txid = out["body"]["transfer_id"]
            pumped = pump_chunks(args, st, receiver, txid)
            if pumped["gaps"]:
                forward_resume_status(args, st, msg, receiver, txid)
        elif out["type"] == "STATUS":
            forward_status(args, st, msg, out)
        elif out["type"] == "REJECT":
            print(f"receive: REJECT code={out['body']['code']} "
                  f"detail={out['body'].get('detail')}")
        elif out["type"] == "RECEIPT":
            finish_receipt(args, st, out)


def _brief(body: dict) -> str:
    return json.dumps({k: v for k, v in body.items()
                       if k not in ("manifest", "node_env")},
                      sort_keys=True)[:160]


def forward_resume_status(args, st: dict, sender_msg: dict,
                          receiver: TransferReceiver, transfer_id: str) -> None:
    """Push the receiver's own STATUS view back to the sender (TRF-021).

    ``get_status`` is the authoritative source of ``have``; a transfer that is
    already closed raises, and then there is nothing to resume.
    """
    try:
        status = own_envelope(st, receiver.get_status(transfer_id, now=now_ts()))
    except AATPError as e:
        print(f"receive: no STATUS for {transfer_id}: {e.code}")
        return
    forward_status(args, st, sender_msg, status)


def forward_status(args, st: dict, sender_msg: dict, status: dict) -> None:
    """Seal the receiver's STATUS back to the sender so it can resume (TRF-021)."""
    peer = peer_info(st, sender_msg["sender"], {})
    send_envelope(args.relay, st, peer, "STATUS", status["body"],
                  now=now_ts(),
                  corr={"transfer_id": status["body"]["transfer_id"]})
    print(f"receive: forwarded STATUS have={status['body']['have']} -> "
          f"{peer['agent_id']}")


def pump_chunks(args, st: dict, receiver: TransferReceiver,
                transfer_id: str) -> dict:
    """Pull every chunk the relay has; a 404 is a gap, not an error."""
    rec = transfer_records(args.dir).get(transfer_id)
    if rec is None:
        raise SystemExit(f"no receiver record for {transfer_id}")
    if "total_chunks" not in rec:
        # A REJECTED transfer stores a stub record with no data plane (TRF-022).
        print(f"receive: {transfer_id} is {rec.get('state')}, nothing to pull")
        return {"have": [], "gaps": [], "record": rec}
    have, gaps = [], []
    for i in range(rec["total_chunks"]):
        data = relay_get_chunk(args.relay, transfer_id, i)
        if data is None:
            gaps.append(i)
            continue
        try:
            receiver.receive_chunk({"transfer_id": transfer_id, "index": i,
                                    "data": data}, now=now_ts())
        except AATPError as e:
            print(f"receive: chunk {i} -> {e.code} ({e.detail})")
            gaps.append(i)
            continue
        have.append(i)
    print(f"receive: chunks {len(have)}/{rec['total_chunks']} verified, "
          f"gaps={gaps}")
    return {"have": have, "gaps": gaps, "record": rec}


def finish_receipt(args, st: dict, receipt: dict) -> None:
    """On an accepted RECEIPT: materialize the tree and run the scanner."""
    body = receipt["body"]
    if body.get("outcome") != "accepted":
        print(f"receive: transfer rejected: outcome={body.get('outcome')} "
              f"code={body.get('code')}")
        return
    transfer_id = body["transfer_id"]
    rec = transfer_records(args.dir)[transfer_id]
    stream = b"".join(b64u_dec(rec["chunks"][str(i)])
                      for i in range(rec["total_chunks"]))
    root = Path(args.dest or (Path(args.dir) / "received"))
    dest = root / transfer_id
    if not dest.exists():
        artifact_mod.materialize(rec["manifest"], stream, dest)
    listing = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*")
                     if p.is_file())
    print(f"receive: materialized {transfer_id} -> {listing}")
    scan = Quarantine(trusted_scanners={SCANNER_NAME},
                      authorized_releasers={st["agent_id"]})
    state = scan.place(body["content_root"], body["node_id"],
                       [{"scanner_name": SCANNER_NAME,
                         "scanner_version": SCANNER_VERSION,
                         "verdict": "clean", "at": now_ts()}])
    print(f"receive: quarantine {body['content_root'][:23]}... -> "
          f"state={state['state']} "
          f"verdicts={scan.verdicts_of(body['content_root'])}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agent_cli", description=__doc__)
    sub = ap.add_subparsers(dest="command")

    def relay_arg(p):
        p.add_argument("--relay", default=RELAY_DEFAULT,
                       help=f"relay base URL (default {RELAY_DEFAULT})")

    def dir_arg(p):
        p.add_argument("--dir", required=True, help="agent state directory")

    p = sub.add_parser("init")
    p.set_defaults(func=cmd_init)
    dir_arg(p)
    p.add_argument("--name", required=True)

    p = sub.add_parser("publish")
    p.set_defaults(func=cmd_publish)
    dir_arg(p)
    relay_arg(p)
    p.add_argument("--peer", action="append", default=[])

    p = sub.add_parser("grant")
    p.set_defaults(func=cmd_grant)
    dir_arg(p)
    relay_arg(p)
    p.add_argument("--audience", required=True)
    p.add_argument("--act", action="append", required=True)
    p.add_argument("--res", required=True)
    p.add_argument("--classification-max", default=DEFAULT_CLASSIFICATION)
    p.add_argument("--name", required=True)
    p.add_argument("--issuer", default=None)
    p.add_argument("--nbf", default=None)
    p.add_argument("--exp", default=None)
    p.add_argument("--prf", action="append", default=[])

    p = sub.add_parser("grant-load")
    p.set_defaults(func=cmd_grant_load)
    dir_arg(p)
    p.add_argument("--leaf", dest="grant_leaf", default=None)
    p.add_argument("--chain", dest="grant_chain", action="append", default=[])
    p.add_argument("--root", action="append", default=[])
    p.add_argument("--grants-file", default=None)
    p.add_argument("--json", action="store_true",
                   help="print the full DSSE envelopes, not a summary")

    p = sub.add_parser("send")
    p.set_defaults(func=cmd_send)
    dir_arg(p)
    relay_arg(p)
    p.add_argument("--name", required=True, help="sending agent name")
    p.add_argument("--to", required=True)
    p.add_argument("--file", action="append", default=[])
    p.add_argument("--src", default=None)
    p.add_argument("--tx", default=None)
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    p.add_argument("--task", default="task_alpha")
    p.add_argument("--classification", default=DEFAULT_CLASSIFICATION)
    p.add_argument("--drop-chunk", action="append", type=int, default=[])
    p.add_argument("--resume", action="store_true")

    p = sub.add_parser("receive")
    dir_arg(p)
    relay_arg(p)
    p.add_argument("--max-transfers", type=int, default=1,
                   help="drain-and-process passes over the mailbox")
    p.add_argument("--policy", action="store_true",
                   help="gate the OFFER on the real aatp.policy.evaluate")
    p.add_argument("--grants-file", default=None)
    p.add_argument("--grant-leaf", default=None)
    p.add_argument("--grant-chain", action="append", default=[])
    p.add_argument("--root", action="append", default=[])
    p.add_argument("--policy-action", default=DEFAULT_POLICY_ACTION)
    p.add_argument("--policy-resource", default=None)
    p.add_argument("--policy-presenter", default=None)
    p.add_argument("--revoked-grant", action="append", default=[])
    p.add_argument("--audit-log", default=None)
    p.add_argument("--dest", default=None,
                   help="materialize root (default <dir>/received)")
    p.set_defaults(func=cmd_receive)
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())