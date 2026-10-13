"""Four-agent AATP work simulation over the real localhost HTTP relay.

    python tools/simulate_pipeline.py [--port 8765]

Coordinator -> Coder -> Reviewer -> Coordinator, plus a Deployer that is only
ever a trusted peer (ID-003). Every packet, chunk and card crosses real HTTP
through ``tools/relay_server.py``: sealed packets land in a mailbox, AEAD
chunks in a transfer store. The relay never opens any of it (NET-001/002).

Exercised, in order:
  * grant attenuation C -> A -> B (G1 root, G2 and G3 delegated by the Coder)
  * the real ``aatp.policy.evaluate`` gating the OFFER (no stub)
  * a deliberately dropped chunk mid-upload, then STATUS/have + resume
  * per-file digests and ``content_root`` verification (ART-021/022)
  * the quarantine stub scanner (SEC-007)
  * a HANDOFF_OFFER / HANDOFF_RESPONSE round trip inside the lease (HND-*)
  * a hash-chained audit log re-verified from scratch (AUD-002)

and four fail-closed negatives:
  no grant -> ERR_POLICY_DENIED, classification too high -> ERR_POLICY_DENIED,
  reindexed chunk -> ERR_CHUNK_AUTH_FAILED, flipped byte -> ERR_ARTIFACT_HASH_MISMATCH.

All key material is TEST-ONLY deterministic demo material (see README.md).
CRY-007 (cryptographic review) is still OPEN: this proves the plumbing works,
it is not a production-conformance claim.
"""
import argparse
import contextlib
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_cli  # noqa: E402
import relay_server  # noqa: E402
from aatp import node as node_mod  # noqa: E402
from aatp.canon import jcs  # noqa: E402
from aatp.dsse import PT_MESSAGE, make_envelope  # noqa: E402
from aatp.errors import AATPError  # noqa: E402
from aatp.grants import grant_id_of  # noqa: E402
from aatp.handoff import HandoffStore  # noqa: E402
from aatp.messages import parse_ts, shift_ts  # noqa: E402
from aatp.node import DagStore  # noqa: E402
from aatp.seal import seal_packet  # noqa: E402
from aatp.transfer import TransferReceiver  # noqa: E402

DEFAULT_PORT = 8765
DEFAULT_RUN = ROOT / "run"
AGENTS = ("coordinator", "coder", "reviewer", "deployer")
SEND_RES = "project:alpha/*"
RECV_RES = "project:alpha/src/*"
HANDOFF_RES = "project:alpha/review"
RECV_ACT = "aatp.artifact.receive"
HANDOFF_ACT = "aatp.task.handoff"
CHUNK_SIZE = 16
LEASE_SECONDS = 900
TXID = "tx_alpha_src"
REPORT_TXID = "tx_alpha_review"

SOURCE_FILES = [
    ("src/app.py", b"def main():\n    return 'aatp demo'\n", False),
    ("src/util.py", b"def add(a, b):\n    return a + b\n", False),
    ("README.md", b"# project alpha\n", False),
]

_CODE_RE = re.compile(r"code=(ERR_[A-Z_]+)")


def say(text: str) -> None:
    print(text, flush=True)


def step(n: int, text: str) -> None:
    say(f"\n[{n}] {text}")


def seconds_between(start: str, end: str) -> int:
    return int((parse_ts(end) - parse_ts(start)).total_seconds())


# -- relay lifecycle -----------------------------------------------------

def relay_serving(base: str) -> bool:
    try:
        status, _ = agent_cli.http("GET", f"{base}/aatp/v0.2/agents/probe/card")
    except SystemExit:
        return False
    return status in (200, 400, 404)


def start_relay(port: int):
    base = f"http://127.0.0.1:{port}"
    if relay_serving(base):
        say(f"relay: reusing the relay already serving {base}")
        return base, None
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "relay_server.py"), str(port)],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)
    for _ in range(100):
        time.sleep(0.1)
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise SystemExit(f"relay exited: {out.strip()}")
        if relay_serving(base):
            say(f"relay: started on {base} (pid {proc.pid}), "
                f"lock={relay_server.lock_path()}")
            return base, proc
    proc.terminate()
    raise SystemExit(f"relay did not come up on {base}")


# -- setup ---------------------------------------------------------------

def parse(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--run", default=str(DEFAULT_RUN),
                    help="run directory (default ./run)")
    ap.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    return ap.parse_args(argv)


def cli(*argv) -> None:
    rc = agent_cli.main(list(argv))
    if rc:
        raise SystemExit(f"agent_cli {argv[0]} exited {rc}")


def reset_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def bootstrap(run: Path, base: str) -> dict:
    step(0, "init + publish four agents (cards self-signed, "
            "trusted via peers.json)")
    for name in AGENTS:
        reset_dir(run / name)
        cli("init", "--dir", str(run / name), "--name", name)
    states = {n: agent_cli.load_state(run / n) for n in AGENTS}
    # Two passes: every card must be on the relay before any agent resolves a
    # peer's card, or the first publisher races the rest.
    for name in AGENTS:
        cli("publish", "--dir", str(run / name), "--relay", base)
    for name in AGENTS:
        argv = ["publish", "--dir", str(run / name), "--relay", base]
        for p in [p for p in AGENTS if p != name]:
            argv += ["--peer", states[p]["agent_id"]]
        cli(*argv)
    for name in AGENTS:
        say(f"    {name:<12} {states[name]['agent_id']}")
    return states


def issue_grants(run: Path, base: str, states: dict) -> dict:
    step(1, "Coordinator issues G1; the Coder attenuates it into G2 and G3")
    coordinator, coder = run / "coordinator", run / "coder"
    reviewer_id = states["reviewer"]["agent_id"]
    coordinator_id = states["coordinator"]["agent_id"]

    cli("grant", "--dir", str(coordinator), "--relay", base, "--audience",
        states["coder"]["agent_id"],
        "--act", "aatp.artifact.send", "--act", RECV_ACT,
        "--act", "aatp.grant.delegate", "--act", HANDOFF_ACT,
        "--res", SEND_RES,
        "--classification-max", "INTERNAL", "--name", "G1")
    g1 = agent_cli.read_json(coordinator / "grants.json", {})["G1"]
    g1_id = grant_id_of(g1["body"])
    # AUT-002 rejects a delegated grant whose window is wider than its parent's,
    # so the leaves inherit G1's exact nbf/exp instead of a fresh sliding hour.
    window = ["--nbf", g1["body"]["nbf"], "--exp", g1["body"]["exp"]]

    # G2: Coder -> Reviewer, narrower resource, no instruct cap (AUT-002/003).
    cli("grant", "--dir", str(coder), "--relay", base, "--audience",
        reviewer_id,
        "--act", RECV_ACT, "--res", RECV_RES,
        "--classification-max", "INTERNAL", "--name", "G2", "--prf", g1_id,
        *window)
    # G3: the same delegation edge carrying the handoff action. HandoffStore
    # binds the grant's presenter to the RECIPIENT (the party that answers), so
    # this leaf is addressed to the Coordinator for the reviewer's offer.
    cli("grant", "--dir", str(coder), "--relay", base, "--audience",
        coordinator_id,
        "--act", HANDOFF_ACT, "--res", HANDOFF_RES,
        "--classification-max", "INTERNAL", "--name", "G3", "--prf", g1_id,
        *window)

    roots = [coordinator_id, states["coder"]["agent_id"]]
    # Spec 2.3: the receiver's own state dir holds the grant envelopes it was
    # given, so `grant-load` and `receive --grant-leaf` read them from there.
    agent_cli.write_json(run / "reviewer" / "grants.json",
                         {"G1": g1, **{k: v for k, v in
                                        agent_cli.read_json(
                                            coder / "grants.json", {}).items()
                                        if k != "G1"}})
    cli("grant-load", "--dir", str(run / "reviewer"), "--leaf", "G2",
        "--chain", "G1", *sum([["--root", r] for r in roots], []))
    say(f"    roots={roots}")
    say(f"    G1  iss={coordinator_id} aud={states['coder']['agent_id']} "
        f"id={g1_id[:23]}...")
    for g in ("G2", "G3"):
        body = agent_cli.read_json(coder / "grants.json", {})[g]["body"]
        say(f"    {g:<6} iss={body['iss']} aud={body['aud']} "
            f"id={grant_id_of(body)[:23]}... cap={body['cap']}")
    return {"roots": roots, "g1_id": g1_id}


def stage_sources(run: Path) -> Path:
    src = run / "payload"
    if src.exists():
        shutil.rmtree(src)
    for path, data, _ in SOURCE_FILES:
        p = src / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return src


def policy_argv(state_dir: Path, base: str, roots: list, leaf: str,
                resource: str = RECV_RES) -> list:
    argv = ["receive", "--dir", str(state_dir), "--relay", base, "--policy",
            "--grant-leaf", leaf, "--grant-chain", "G1"]
    for r in roots:
        argv += ["--root", r]
    return argv + ["--policy-action", RECV_ACT, "--policy-resource", resource,
                   "--audit-log", str(state_dir / "audit.json"),
                   "--max-transfers", "1"]


# -- happy path ----------------------------------------------------------

def happy_path(run: Path, base: str, states: dict, grants: dict,
               chunk_size: int) -> dict:
    reviewer = run / "reviewer"
    step(2, "Coder OFFERs the 3-file tree to Reviewer, deliberately dropping "
            "chunk 2")
    cli("send", "--dir", str(run / "coder"), "--relay", base,
        "--name", "coder", "--to", states["reviewer"]["agent_id"],
        "--src", str(run / "payload"), "--tx", TXID,
        "--chunk-size", str(chunk_size), "--task", "task_alpha",
        "--drop-chunk", "2")

    step(3, "Reviewer receives: OFFER -> policy.evaluate -> ACCEPT, gap at 2, "
            "STATUS/have back to the Coder")
    cli(*policy_argv(reviewer, base, grants["roots"], "G2"))

    step(4, "Coder reads STATUS/have and resumes with chunk 2 + COMPLETE")
    cli("send", "--dir", str(run / "coder"), "--relay", base,
        "--name", "coder", "--to", states["reviewer"]["agent_id"], "--resume")

    step(5, "Reviewer receives COMPLETE: digests, content_root, scanner, "
            "materialize")
    cli(*policy_argv(reviewer, base, grants["roots"], "G2"))
    record = agent_cli.transfer_records(reviewer)[TXID]
    return {"txid": TXID, "record": record}


def handoff_round_trip(run: Path, base: str, states: dict, happy: dict) -> dict:
    reviewer_dir, coordinator_dir = run / "reviewer", run / "coordinator"
    reviewer, coordinator = states["reviewer"], states["coordinator"]

    step(6, "Reviewer sends its review report back to the Coordinator, then "
            "publishes a verify node over it")
    report_src = reset_dir(reviewer_dir / "report")
    (report_src / "review.md").write_bytes(
        b"# review\n\n3 files, digests verified.\n")
    (report_src / "findings.txt").write_bytes(b"no findings\n")
    cli("send", "--dir", str(reviewer_dir), "--relay", base, "--name", "reviewer",
        "--to", coordinator["agent_id"], "--src", str(report_src),
        "--tx", REPORT_TXID, "--task", "task_alpha")
    cli("receive", "--dir", str(coordinator_dir), "--relay", base,
        "--max-transfers", "2")
    got = agent_cli.transfer_records(coordinator_dir)[REPORT_TXID]
    now = agent_cli.now_ts()
    lease = shift_ts(now, LEASE_SECONDS)
    _verify_node, verify_id = node_mod.make_node(
        got["content_root"], [got["node_id"]], "verify", reviewer["agent_id"],
        "task_alpha", {"kind": "ai", "assurance": "self_asserted"}, now,
        annotations={"verification": {"outcome": "pass",
                                      "scope": "review report digests"}})
    say(f"    coordinator holds report node={got['node_id'][:23]}... "
        f"content_root={got['content_root'][:23]}...")
    say(f"    reviewer verify node={verify_id[:23]}... "
        f"parents={[got['node_id'][:23]]}")

    step(7, "Reviewer offers the handoff; the Coordinator answers "
            "HANDOFF_RESPONSE accept before the lease expires")
    db = agent_cli.read_json(run / "reviewer" / "grants.json", {})
    handoff = {"handoff_id": "ho_alpha_review",
               "task": {"task_id": "task_alpha",
                        "title": "ship project alpha",
                        "objective": "merge the reviewed source tree"},
               "input_node_ids": [happy["record"]["node_id"], got["node_id"],
                                  verify_id],
               "grant_env": db["G3"]["env"],
               "expected_outputs": ["release.tar.gz"],
               "deadline": shift_ts(now, 3600),
               "lease_expires_at": lease,
               "policy_context": {"resource": HANDOFF_RES}}
    roots = set(grants_of(run)["roots"])
    store = HandoffStore()
    store.offer(handoff, grant_chain_envs=[db["G1"]["env"]], now=now,
                sender=reviewer["agent_id"], recipient=coordinator["agent_id"],
                roots=roots, key_resolver=key_resolver_for(reviewer_dir))
    agent_cli.send_envelope(
        base, reviewer,
        agent_cli.peer_info(reviewer, coordinator["agent_id"], {}),
        "HANDOFF_OFFER", handoff, now=now, corr={"task_id": "task_alpha"})
    say(f"    HANDOFF_OFFER ho_alpha_review -> {coordinator['agent_id']}")
    say(f"    store state={store.state_of(handoff['handoff_id'], now)} "
        f"responsible={store.responsible(handoff['handoff_id'])} "
        f"lease_expires_at={lease}")

    decision = None
    for packet in agent_cli.relay_mailbox(base, coordinator):
        env, msg = agent_cli.open_incoming(coordinator, packet)
        if msg["type"] != "HANDOFF_OFFER":
            continue
        agent_cli.verify_inbound(coordinator, env, agent_cli.peer_info(
            coordinator, msg["sender"], {})["card"])
        accept_now = agent_cli.now_ts()
        coord_store = HandoffStore()
        coord_store.offer(msg["body"], grant_chain_envs=[db["G1"]["env"]],
                          now=accept_now, sender=msg["sender"],
                          recipient=msg["recipient"], roots=roots,
                          key_resolver=key_resolver_for(coordinator_dir))
        response = coord_store.respond(handoff["handoff_id"], "accept",
                                       accept_now,
                                       responder=coordinator["agent_id"],
                                       signer=coordinator["signer"])
        resp_msg = agent_cli.parse_jcs(agent_cli.b64u_dec(response["payload"]))
        say(f"    HANDOFF_RESPONSE decision={resp_msg['body']['decision']} "
            f"state={coord_store.state_of(handoff['handoff_id'])} "
            f"responsible={coord_store.responsible(handoff['handoff_id'])}")
        say(f"    handoff audit log (HND-006): "
            f"{coord_store.audit_log('task_alpha')}")
        say(f"    accepted {seconds_between(accept_now, lease)}s before "
            f"lease_expires_at={lease}")
        agent_cli.send_envelope(
            base, coordinator,
            agent_cli.peer_info(coordinator, msg["sender"], {}),
            "HANDOFF_RESPONSE", resp_msg["body"], now=accept_now,
            corr={"task_id": "task_alpha"})
        decision = resp_msg["body"]["decision"]
        break
    if decision is None:
        raise SystemExit("Coordinator never saw the HANDOFF_OFFER")

    verified = None
    for packet in agent_cli.relay_mailbox(base, reviewer):
        env, msg = agent_cli.open_incoming(reviewer, packet)
        if msg["type"] != "HANDOFF_RESPONSE":
            continue
        agent_cli.verify_inbound(reviewer, env, agent_cli.peer_info(
            reviewer, msg["sender"], {})["card"])
        verified = msg["body"]["decision"]
        say(f"    Reviewer verified the signed response: decision={verified} "
            f"store state={store.state_of(handoff['handoff_id'], agent_cli.now_ts())}")
    return {"decision": verified, "sent": decision, "handoff": handoff,
            "accepted_at": accept_now, "lease_expires_at": lease,
            "report_cr": got["content_root"], "verify_id": verify_id}


def grants_of(run: Path) -> dict:
    return {"roots": [agent_cli.read_json(run / n / "state.json", {})["agent_id"]
                      for n in ("coordinator", "coder")]}


def key_resolver_for(directory: Path):
    cards = agent_cli.load_peers(directory)
    return lambda aid: agent_cli.b64u_dec(cards[aid]["signing_key"]["public_key"])


# -- negatives -----------------------------------------------------------

def fresh_case_dir(run: Path, base: str, name: str, states: dict) -> Path:
    """A throwaway receiver with its own relay-published card and peer cache."""
    d = reset_dir(run / "negatives" / name)
    cli("init", "--dir", str(d), "--name", f"neg_{name.replace('-', '_')}")
    cli("publish", "--dir", str(d), "--relay", base,
        "--peer", states["coder"]["agent_id"],
        "--peer", states["coordinator"]["agent_id"])
    return d


def code_from(out: str) -> str:
    match = _CODE_RE.search(out)
    if match:
        return match.group(1)
    raise SystemExit(f"no error code in the receive output:\n{out}")


def verdict_line(out: str) -> str:
    """The receive line that carries an error code."""
    for line in out.strip().splitlines():
        if "code=" in line:
            return line.strip()
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    return lines[-1] if lines else out.strip()


def verdict(name: str, got: str, expect: str) -> str:
    if got != expect:
        raise SystemExit(f"negative case {name}: expected {expect}, got {got}")
    say(f"      {name}: expected {expect}, got {got}  [ok]")
    return got


def case_leaf(run: Path, base: str, case: Path, name: str,
              classification_max: str = "INTERNAL") -> dict:
    """A G1-derived leaf addressed to the throwaway case receiver.

    The leaf must name the receiver as ``aud`` (the OFFER-path policy presenter
    defaults to the receiving agent, D-044) and must narrow the parent's window:
    AUT-002 rejects a child whose ``exp`` is later than its parent's, so a
    delegated grant issued seconds later has to inherit G1's exact ``nbf``/``exp``
    rather than a fresh sliding hour.
    """
    g1 = agent_cli.read_json(run / "coordinator" / "grants.json", {})["G1"]
    cli("grant", "--dir", str(run / "coder"), "--relay", base,
        "--audience", _case_agent(case), "--act", RECV_ACT, "--res", RECV_RES,
        "--classification-max", classification_max, "--name", name,
        "--nbf", g1["body"]["nbf"], "--exp", g1["body"]["exp"],
        "--prf", grant_id_of(g1["body"]))
    return agent_cli.read_json(run / "coder" / "grants.json", {})[name]


def policy_negatives(run: Path, base: str, states: dict, grants: dict) -> list:
    """The two policy negatives, driven by the real ``receive`` CLI."""
    out = []
    g1 = agent_cli.read_json(run / "coordinator" / "grants.json", {})["G1"]
    say("\n    no-grant: policy active, OFFER arrives with no grant leaf")
    case = fresh_case_dir(run, base, "no-grant", states)
    cli("send", "--dir", str(run / "coder"), "--relay", base, "--name", "coder",
        "--to", _case_agent(case), "--file",
        str(run / "payload" / "README.md"), "--tx", "tx_neg_nogrant",
        "--task", "task_alpha")
    text = _receive_capturing(
        "receive", "--dir", str(case), "--relay", base, "--policy",
        "--policy-resource", RECV_RES, "--policy-action", RECV_ACT,
        "--audit-log", str(case / "audit.json"), "--max-transfers", "1")
    say(f"      {verdict_line(text)}")
    out.append(verdict("no-grant", code_from(text), "ERR_POLICY_DENIED"))

    say("\n    classification: leaf classification_max=PUBLIC, "
        "OFFER claims RESTRICTED")
    case = fresh_case_dir(run, base, "classification", states)
    weak = case_leaf(run, base, case, "Gnweak", "PUBLIC")
    agent_cli.write_json(case / "grants.json", {"G1": g1, "Gnweak": weak})
    cli("send", "--dir", str(run / "coder"), "--relay", base, "--name", "coder",
        "--to", _case_agent(case), "--file",
        str(run / "payload" / "README.md"), "--tx", "tx_neg_class",
        "--task", "task_alpha", "--classification", "RESTRICTED")
    text = _receive_capturing(
        "receive", "--dir", str(case), "--relay", base, "--policy",
        "--grants-file", str(case / "grants.json"), "--grant-leaf", "Gnweak",
        "--grant-chain", "G1",
        *sum([["--root", r] for r in grants["roots"]], []),
        "--policy-resource", RECV_RES, "--policy-action", RECV_ACT,
        "--audit-log", str(case / "audit.json"), "--max-transfers", "1")
    say(f"      {verdict_line(text)}")
    if "AUT-002" not in text:
        raise SystemExit(f"classification case should fail AUT-002:\n{text}")
    out.append(verdict("classification", code_from(text), "ERR_POLICY_DENIED"))
    return out


def _receive_capturing(*argv) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli(*argv)
    return buf.getvalue()


def _case_agent(case: Path) -> str:
    return agent_cli.read_json(case / "state.json", {})["agent_id"]


def transfer_negatives(run: Path, base: str, states: dict,
                       grants: dict) -> list:
    """Reindexed chunk + flipped byte. The misbehaviour has to happen at the
    sender, so these build the OFFER directly; transport is still real HTTP and
    the receiver is the real TransferReceiver, just not driven by the CLI."""
    out = []
    coder = agent_cli.load_state(run / "coder")
    coder["relay"] = base
    g1 = agent_cli.read_json(run / "coordinator" / "grants.json", {})["G1"]

    say("\n    reindexed-chunk: two chunk ciphertexts swapped before upload")
    case = fresh_case_dir(run, base, "reindexed-chunk", states)
    out.append(verdict(
        "reindexed-chunk",
        _transfer_negative(base, coder, g1, case_leaf(run, base, case,
                                                      "Gnchunk"),
                           case, grants, txid="tx_neg_reindex",
                           files=[("src/big.py", b"x" * 300, False)],
                           reindex=True),
        "ERR_CHUNK_AUTH_FAILED"))

    say("\n    flipped-byte: one byte of the delivered file flipped after "
        "digesting")
    case = fresh_case_dir(run, base, "flipped-byte", states)
    corrupt = bytearray(b"negative = True\n")
    corrupt[0] ^= 0x01
    out.append(verdict(
        "flipped-byte",
        _transfer_negative(base, coder, g1, case_leaf(run, base, case, "Gnflip"),
                           case, grants, txid="tx_neg_flipped",
                           files=[("src/neg.py", b"negative = True\n", False)],
                           stream=bytes(corrupt)),
        "ERR_ARTIFACT_HASH_MISMATCH"))
    return out


def _transfer_negative(base: str, coder: dict, g1: dict, leaf: dict,
                       case: Path, grants: dict, *,
                       txid: str, files: list, stream=None,
                       reindex: bool = False) -> str:
    now = agent_cli.now_ts()
    peer = agent_cli.peer_info(coder, _case_agent(case), {})
    parts = agent_cli.build_offer(coder, peer, files, transfer_id=txid,
                                  chunk_size=CHUNK_SIZE, task_id="task_alpha",
                                  classification="INTERNAL", now=now,
                                  stream=stream)
    if reindex:
        parts["cts"] = list(parts["cts"])
        parts["cts"][0], parts["cts"][1] = parts["cts"][1], parts["cts"][0]
    agent_cli.send_envelope(base, coder, peer, "OFFER", parts["body"], now=now,
                            corr={"transfer_id": txid})
    for i, ct in enumerate(parts["cts"]):
        agent_cli.relay_put_chunk(base, txid, i, agent_cli.b64u(ct))
    say(f"      uploaded {len(parts['cts'])} chunks over HTTP for {txid}")

    agent = agent_cli.load_state(case)
    cards = dict(agent_cli.load_peers(case))
    cards[agent["agent_id"]] = agent["card"]
    receiver = TransferReceiver(
        agent_id=agent["agent_id"], signer=agent["signer"],
        keystore=agent["keystore"], card_resolver=lambda a: cards[a],
        trusted={coder["agent_id"]}, own_card=agent["card"],
        dag=DagStore(parent_policy="lazy"),
        replay_path=str(case / "replay.json"), store_path=str(case / "xfer.json"),
        policy_fn=agent_cli.make_policy(set(grants["roots"]),
                                        key_resolver_for(case)),
        grant_leaf_env=leaf["env"], grant_chain_envs=[g1["env"]],
        roots=set(grants["roots"]), policy_action=RECV_ACT,
        policy_resource=RECV_RES, audit_log_path=str(case / "audit.json"))
    code = _run_negative_offer(receiver, agent, coder, parts["body"], txid,
                               now, base, case)
    if code is None:
        raise SystemExit(f"{txid}: negative case produced no verdict")
    return code


def _run_negative_offer(receiver, agent: dict, coder: dict, body: dict,
                        txid: str, now: str, base: str, case: Path):
    """OFFER over HTTP-pushed chunks, then COMPLETE; return the error code."""
    for env in receiver.receive_control(
            sealed(coder, agent, "OFFER", body, txid, now), now=now):
        out = agent_cli.own_envelope(agent, env)
        if out["type"] == "REJECT":
            say(f"      -> REJECT {out['body']['code']} "
                f"({out['body']['detail']})")
            return out["body"]["code"]
        if out["type"] != "ACCEPT":
            continue
        record = agent_cli.transfer_records(case)[txid]
        for i in range(record["total_chunks"]):
            data = agent_cli.relay_get_chunk(base, txid, i)
            if data is None:
                continue
            try:
                receiver.receive_chunk({"transfer_id": txid, "index": i,
                                        "data": data}, now=now)
            except AATPError as e:
                say(f"      -> chunk {i} {e.code} ({e.detail})")
                return e.code
        complete = sealed(coder, agent, "COMPLETE",
                          {"transfer_id": txid,
                           "total_chunks": record["total_chunks"]}, txid, now)
        for env in receiver.receive_control(complete, now=now):
            out = agent_cli.own_envelope(agent, env)
            if out["type"] == "RECEIPT":
                say(f"      -> RECEIPT {out['body']['outcome']} "
                    f"code={out['body'].get('code')}")
                return out["body"].get("code")
    return None


def sealed(sender: dict, recipient: dict, msg_type: str, body: dict,
           transfer_id: str, now: str) -> dict:
    msg = agent_cli.build_message(msg_type, sender["agent_id"],
                                  sender["signer"].key_id(),
                                  recipient["agent_id"], body, now=now,
                                  corr={"transfer_id": transfer_id})
    return seal_packet(recipient["agent_id"], recipient["enc_key_id"],
                       recipient["enc_pub"],
                       make_envelope(PT_MESSAGE, jcs(msg), sender["signer"]))


# -- audit verification --------------------------------------------------

def verify_audit(path: Path) -> tuple:
    """Re-derive the whole chain: head_n == SHA256(head_{n-1} || JCS(entry))."""
    log = json.loads(path.read_text(encoding="utf-8"))
    prev = "00" * 32
    for n, record in enumerate(log["entries"]):
        if record["prev_hash"] != prev:
            raise SystemExit(f"audit chain broken at entry {n}: prev_hash")
        want = hashlib.sha256(bytes.fromhex(prev) + jcs(record["entry"])).hexdigest()
        if record["entry_hash"] != want:
            raise SystemExit(f"audit chain broken at entry {n}: entry_hash")
        prev = want
    if log["head"] != prev:
        raise SystemExit("audit head does not match the last entry_hash")
    return len(log["entries"]), log["head"]


def report_audit(run: Path) -> None:
    step(9, "re-verify the hash-chained audit chain from scratch (AUD-002)")
    path = run / "reviewer" / "audit.json"
    count, head = verify_audit(path)
    entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
    events = [e["entry"]["event"] for e in entries]
    decisions = [(e["entry"]["decision"], e["entry"]["rule_id"])
                 for e in entries if e["entry"]["event"] == "policy_decision"]
    states = [e["entry"].get("state") for e in entries
              if e["entry"]["event"] == "transfer_state"]
    chunks = [e["entry"]["index"] for e in entries
              if e["entry"]["event"] == "chunk_verified"]
    say(f"    entries={count} head={head}")
    say(f"    events={events}")
    say(f"    chunk_verified indexes={chunks}")
    say(f"    policy_decision={decisions}")
    say(f"    transfer_state={states}")
    say("    AUDIT CHAIN OK")


# -- entry point ---------------------------------------------------------

def run_simulation(port: int = DEFAULT_PORT, run_dir: str = str(DEFAULT_RUN),
                   chunk_size: int = CHUNK_SIZE) -> int:
    """Drive the whole four-agent run; raises SystemExit on any failed check."""
    run = Path(run_dir)
    base, proc = start_relay(port)
    try:
        states = bootstrap(run, base)
        grants = issue_grants(run, base, states)
        stage_sources(run)
        happy = happy_path(run, base, states, grants, chunk_size)
        handoff = handoff_round_trip(run, base, states, happy)
        step(8, "four fail-closed negatives")
        cases = policy_negatives(run, base, states, grants)
        cases += transfer_negatives(run, base, states, grants)
        report_audit(run)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            # On Windows the venv launcher pid Popen reports is not the pid the
            # interpreter writes into the lock, and TerminateProcess skips the
            # relay's own cleanup. Drop the lock once its owner is gone.
            lock = relay_server.lock_path()
            try:
                owner = json.loads(lock.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                owner = {}
            if owner.get("port") == port and not relay_server.pid_alive(
                    owner.get("pid")):
                lock.unlink(missing_ok=True)
    dest = run / "reviewer" / "received" / happy["txid"]
    listing = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*")
                     if p.is_file())
    say(f"\nreceived tree {dest}:")
    for entry in listing:
        say(f"    {entry}")
    expected = sorted(path for path, _, _ in SOURCE_FILES)
    if listing != expected:
        raise SystemExit(f"received tree mismatch: {listing} != {expected}")
    if handoff["decision"] != "accept":
        raise SystemExit(f"handoff not accepted: {handoff['decision']}")
    if parse_ts(handoff["accepted_at"]) >= parse_ts(handoff["lease_expires_at"]):
        raise SystemExit("handoff accepted outside the lease: "
                         f"{handoff['accepted_at']} >= "
                         f"{handoff['lease_expires_at']}")
    say(f"\nagent_ids:")
    for name in AGENTS:
        say(f"    {name:<12} {states[name]['agent_id']}")
    say(f"\nnegative cases: {cases}")
    say("NEGATIVE CASES OK")
    say("PIPELINE OK")
    return 0


def main(argv=None) -> int:
    args = parse(argv)
    return run_simulation(args.port, args.run, args.chunk_size)


if __name__ == "__main__":
    sys.exit(main())
