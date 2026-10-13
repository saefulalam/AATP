"""Contract tests for tools/agent_cli.py helpers (TDD: written first).

``tools/`` is demo tooling, not part of the ``aatp`` package, so these are
contract tests over its CLI surface: the files exist, the ``grant`` family is
registered, ``make_policy`` fails closed through the real ``policy.evaluate``,
the relay lock is genuinely single-instance, and the README states the
TEST-ONLY-seed / CRY-007 caveats.
"""
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
ROOT = Path(__file__).resolve().parents[1]
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


def test_cli_resolves_repo_relative_root():
    """No hard-coded checkout path: the tooling must work from a clone."""
    import agent_cli
    import relay_server
    assert Path(agent_cli.ROOT) == ROOT
    assert Path(relay_server.ROOT) == ROOT
    for name in ("agent_cli.py", "relay_server.py", "simulate_pipeline.py"):
        src = (TOOLS / name).read_text(encoding="utf-8")
        assert "D:\\AATP-01" not in src, f"{name} hard-codes the checkout path"
        assert "D:/AATP-01" not in src, f"{name} hard-codes the checkout path"


def test_relay_lock_is_single_instance(tmp_path):
    """A live lock blocks a second relay; releasing it lets the next one in."""
    import relay_server
    lock = tmp_path / "relay.lock"
    held = relay_server.take_relay_lock(lock, 8765)
    assert held is not None, "the first relay must take the lock"
    assert relay_server.take_relay_lock(lock, 8765) is None
    assert json.loads(lock.read_text())["pid"] == held["pid"]
    relay_server.release_relay_lock(lock, held)
    assert not lock.exists()
    again = relay_server.take_relay_lock(lock, 8765)
    assert again is not None
    relay_server.release_relay_lock(lock, again)


def test_relay_lock_ignores_stale_owner(tmp_path):
    """A lock left by a dead process must not block the next relay forever."""
    import relay_server
    lock = tmp_path / "relay.lock"
    # PID 0 never resolves to a live process on Windows or POSIX.
    lock.write_text(json.dumps({"pid": 0, "port": 8765}), encoding="utf-8")
    assert relay_server.take_relay_lock(lock, 8765) is not None


def test_cli_parser_registers_grant_family():
    import agent_cli
    parser = agent_cli.build_parser()
    grant = parser.parse_args(
        ["grant", "--dir", "d", "--audience", "aatp:x", "--act", "a",
         "--res", "r", "--name", "G1"])
    assert grant.act == ["a"] and grant.name == "G1"
    load = parser.parse_args(["grant-load", "--dir", "d", "--leaf", "G2",
                              "--chain", "G1", "--root", "aatp:root"])
    assert load.grant_leaf == "G2" and load.grant_chain == ["G1"]
    assert load.root == ["aatp:root"]


def test_cli_parser_receive_exposes_policy_and_loop_flags():
    import agent_cli
    args = agent_cli.build_parser().parse_args(
        ["receive", "--dir", "d", "--relay", "http://127.0.0.1:8765"])
    assert args.max_transfers == 1
    assert args.policy is False
    assert args.grants_file is None
    assert args.audit_log is None
    on = agent_cli.build_parser().parse_args(
        ["receive", "--dir", "d", "--relay", "r", "--policy",
         "--grants-file", "g.json", "--grant-leaf", "G2",
         "--grant-chain", "G1", "--policy-resource", "project:alpha/src/*",
         "--audit-log", "a.json", "--max-transfers", "3"])
    assert on.max_transfers == 3 and on.policy is True
    assert on.grant_leaf == "G2" and on.grant_chain == ["G1"]
    assert on.policy_resource == "project:alpha/src/*"
    assert on.audit_log == "a.json"


def test_cli_grant_round_trip(tmp_path):
    """``grant`` stores a signed envelope that ``grant-load`` hands back."""
    import agent_cli
    from aatp.canon import parse_jcs
    from aatp.dsse import PT_GRANT, verify_envelope
    coord_dir, coder_dir = tmp_path / "coordinator", tmp_path / "coder"
    agent_cli.main(["init", "--dir", str(coord_dir), "--name", "coordinator"])
    agent_cli.main(["init", "--dir", str(coder_dir), "--name", "coder"])
    coder_id = json.loads((coder_dir / "state.json").read_text())["agent_id"]
    issuer = json.loads((coord_dir / "state.json").read_text())["agent_id"]
    # Discovery is OPEN-10; publish fills this cache in the real flow.
    agent_cli.write_json(coord_dir / "peers.json",
                         {coder_id: json.loads((coder_dir / "card.json").read_text())})

    agent_cli.main(["grant", "--dir", str(coord_dir), "--audience", coder_id,
                    "--act", "aatp.artifact.send", "--res", "project:alpha/*",
                    "--name", "G1"])
    db = json.loads((coord_dir / "grants.json").read_text())
    assert db["G1"]["body"]["iss"] == issuer
    assert db["G1"]["body"]["aud"] == coder_id
    assert db["G1"]["body"]["cap"] == [
        {"act": "aatp.artifact.send", "res": "project:alpha/*"}]
    signer = agent_cli.load_state(coord_dir)["signer"]
    signed = verify_envelope(db["G1"]["env"], PT_GRANT,
                             signer.public_key_raw(), key_id=signer.key_id())
    assert signed == db["G1"]["body"]

    loaded = agent_cli.build_parser().parse_args(
        ["grant-load", "--dir", str(coord_dir), "--leaf", "G1",
         "--root", "aatp:example-root"])
    out = agent_cli.load_grants(loaded)
    assert out["leaf"] == db["G1"]["env"]
    assert out["chain"] == []
    assert out["roots"] == ["aatp:example-root"]
    assert parse_jcs(
        agent_cli.b64u_dec(out["leaf"]["payload"]))["aud"] == coder_id


def test_simulate_pipeline_exposes_entrypoint():
    import simulate_pipeline
    assert callable(simulate_pipeline.main)
    assert callable(simulate_pipeline.run_simulation)


def test_audit_chain_reverification_accepts_and_rejects(tmp_path):
    """The demo re-derives head_n == SHA256(head_{n-1} || JCS(entry_n))."""
    import simulate_pipeline
    from aatp import sec
    log, head = [], "00" * 32
    for i in range(3):
        head = sec.audit_append(log, {"event": "message_received",
                                      "transfer_id": f"tx_{i}"}, prev_hash=head)
    path = tmp_path / "audit.json"
    path.write_text(json.dumps({"entries": log, "head": head}),
                    encoding="utf-8")
    count, verified_head = simulate_pipeline.verify_audit(path)
    assert (count, verified_head) == (3, head)

    broken = json.loads(path.read_text())
    broken["entries"][1]["entry"]["transfer_id"] = "tx_tampered"
    path.write_text(json.dumps(broken), encoding="utf-8")
    with pytest.raises(SystemExit):
        simulate_pipeline.verify_audit(path)


def test_cli_policy_allows_a_real_grant_chain(tmp_path):
    """``make_policy`` reaches the real evaluate and returns ALLOW."""
    import agent_cli
    from aatp.b64 import b64u_dec
    from aatp.messages import shift_ts
    coord_dir, coder_dir = tmp_path / "coordinator", tmp_path / "coder"
    agent_cli.main(["init", "--dir", str(coord_dir), "--name", "coordinator"])
    agent_cli.main(["init", "--dir", str(coder_dir), "--name", "coder"])
    coder_id = json.loads((coder_dir / "state.json").read_text())["agent_id"]
    issuer_id = json.loads((coord_dir / "state.json").read_text())["agent_id"]
    cards = {
        coder_id: json.loads((coder_dir / "card.json").read_text()),
        issuer_id: json.loads((coord_dir / "card.json").read_text())}
    agent_cli.write_json(coord_dir / "peers.json", {coder_id: cards[coder_id]})
    agent_cli.main(["grant", "--dir", str(coord_dir), "--audience", coder_id,
                    "--act", "aatp.artifact.send", "--res", "project:alpha/*",
                    "--name", "G1"])
    g1 = json.loads((coord_dir / "grants.json").read_text())["G1"]
    pol = agent_cli.make_policy(
        roots={issuer_id},
        key_resolver=lambda a: b64u_dec(cards[a]["signing_key"]["public_key"]))
    verdict = pol({"action": "aatp.artifact.send", "resource": "project:alpha/a.py",
                   "classification": "INTERNAL", "consumption_mode": "data_only",
                   "grant_leaf_env": g1["env"], "grant_chain_envs": [],
                   "revoked": set(), "manifest": None,
                   "presenter": coder_id,
                   "now": shift_ts(g1["body"]["nbf"], 30)})
    assert verdict == {"decision": "allow", "rule_id": "POLICY-ALLOW",
                       "code": None}
    # The same leaf presented by someone it is not addressed to denies.
    denied = pol({"action": "aatp.artifact.send",
                  "resource": "project:alpha/a.py",
                  "classification": "INTERNAL",
                  "consumption_mode": "data_only",
                  "grant_leaf_env": g1["env"], "grant_chain_envs": [],
                  "revoked": set(), "manifest": None,
                  "presenter": issuer_id,
                  "now": shift_ts(g1["body"]["nbf"], 30)})
    assert denied["decision"] == "deny"
    assert denied["code"] == "ERR_POLICY_DENIED"


def test_readme_states_demo_caveats():
    readme = (TOOLS / "README.md").read_text(encoding="utf-8")
    assert "TEST-ONLY" in readme
    assert "CRY-007" in readme
    assert "OPEN" in readme