# `tools/` — four-agent AATP demo

**Demo tooling. Not part of the `aatp` library package.** Nothing here is
imported by `aatp/`; the library is unchanged by this directory.

## What it is

| File | Role |
|---|---|
| `relay_server.py` | localhost relay over `aatp.transport.http`, single-instance via `relay.lock` |
| `agent_cli.py` | per-agent CLI: `init`, `publish`, `grant`, `grant-load`, `send`, `receive` |
| `simulate_pipeline.py` | orchestrates four agents over real HTTP and prints a timeline |
| `README.md` | this file |

Everything crosses **real HTTP** on `127.0.0.1:8765` (override with `--port`).
The relay is opaque: it never opens a sealed packet, a chunk or a card
(NET-001/002).

## The four agents

| Agent | Role in the run |
|---|---|
| **coordinator** | trust root; issues `G1`; accepts the handoff |
| **coder** | attenuates `G1` into `G2`/`G3`/`G4`; sends the source tree |
| **reviewer** | receives under `G2` behind the real `policy.evaluate`; scans; offers the handoff |
| **deployer** | published and pinned as a peer; takes part in no exchange (kept so the trust set is not a closed pair) |

## Grant chain shape

```
G1   iss=coordinator  aud=coder        aatp.artifact.send, aatp.artifact.receive,
                                     aatp.grant.delegate, aatp.task.handoff
                                     on  project:alpha/*
     |  prf: []                          classification_max=INTERNAL
G2   iss=coder        aud=reviewer     aatp.artifact.receive  on  project:alpha/src/*
     |  prf: [grant_id(G1)]               classification_max=INTERNAL
G3   iss=coder        aud=coordinator  aatp.task.handoff      on  project:alpha/review
     |  prf: [grant_id(G1)]               classification_max=INTERNAL
```

A `PUBLIC`-only leaf (`Gnweak`) is minted at run time for the classification
negative case.

AUT-002 rejects a delegated grant whose window is *wider* than its parent's, so
every leaf inherits G1's exact `nbf`/`exp` via `--nbf`/`--exp`. A leaf issued a
few seconds later with a fresh sliding hour is a legitimate `ERR_GRANT_ATTENUATION`.

`G2` and `G3` are delegated leaves, so AUT-001 (prf link), AUT-002
(attenuation) and AUT-003 (parent carries `aatp.grant.delegate` for the child's
resource) are all exercised on the way to a successful receive.

`G3` is addressed to the **coordinator**, not to the reviewer: `HandoffStore.offer`
verifies the grant chain with the handoff **recipient** as the presenter, so the
leaf has to name the party that answers the handoff.

Both leaves name the receiver as `aud`. The OFFER-path policy gate defaults
`presenter` to the receiving agent (`D-044`), because the action being granted
there — `aatp.artifact.receive` — is the receiver's own. Sender binding is
enforced separately by pinned trust (`ID-003`) before the gate runs. Override
with `--policy-presenter` if your grants are addressed to the sender.

## Run it

```powershell
# everything, one command
.venv\Scripts\python tools\simulate_pipeline.py --port 8765

# ... or by hand, one step at a time (run/ is created for you)
.venv\Scripts\python tools\relay_server.py 8765

.venv\Scripts\python tools\agent_cli.py init    --dir run\coordinator --name coordinator
.venv\Scripts\python tools\agent_cli.py init    --dir run\coder       --name coder
.venv\Scripts\python tools\agent_cli.py init    --dir run\reviewer    --name reviewer
.venv\Scripts\python tools\agent_cli.py init    --dir run\deployer    --name deployer

# publish: PUT each card, then cache every peer's card
.venv\Scripts\python tools\agent_cli.py publish --dir run\coordinator --relay http://127.0.0.1:8765 --peer <coder-id> --peer <reviewer-id> --peer <deployer-id>
# ... same for the other three (ids come from each `init` line)

# grants: root, then the Coder's delegations
.venv\Scripts\python tools\agent_cli.py grant --dir run\coordinator --relay http://127.0.0.1:8765 --audience <coder-id> --act aatp.artifact.send --act aatp.artifact.receive --act aatp.grant.delegate --act aatp.task.handoff --res "project:alpha/*" --name G1
.venv\Scripts\python tools\agent_cli.py grant --dir run\coder --relay http://127.0.0.1:8765 --audience <reviewer-id> --act aatp.artifact.receive --res "project:alpha/src/*" --name G2 --prf <grant_id(G1)> --nbf <G1.nbf> --exp <G1.exp>
.venv\Scripts\python tools\agent_cli.py grant-load --dir run\reviewer --leaf G2 --chain G1 --root <coordinator-id> --root <coder-id>

# transfer with a dropped chunk, STATUS/have, resume
.venv\Scripts\python tools\agent_cli.py send    --dir run\coder --relay http://127.0.0.1:8765 --name coder --to <reviewer-id> --src run\payload --tx tx_alpha_src --drop-chunk 2
.venv\Scripts\python tools\agent_cli.py receive --dir run\reviewer --relay http://127.0.0.1:8765 --policy --grant-leaf G2 --grant-chain G1 --root <coordinator-id> --root <coder-id> --policy-resource "project:alpha/src/*" --audit-log run\reviewer\audit.json
.venv\Scripts\python tools\agent_cli.py send    --dir run\coder --relay http://127.0.0.1:8765 --name coder --to <reviewer-id> --resume
.venv\Scripts\python tools\agent_cli.py receive --dir run\reviewer --relay http://127.0.0.1:8765 --policy --grant-leaf G2 --grant-chain G1 --root <coordinator-id> --root <coder-id> --policy-resource "project:alpha/src/*" --audit-log run\reviewer\audit.json
```

Port **8765** is the default for both tools. `relay_server.py` is
single-instance: a second copy finds a live `tools/relay.lock` and exits **2**
without fighting over the port -- exit 0 would report a running relay when none
is serving; a lock left behind by a dead process is taken over. If a relay is
already listening, `simulate_pipeline.py` reuses it instead of starting a
second one.

On Windows `TerminateProcess` skips the relay's own cleanup, so a killed relay
leaves its lock behind. That is exactly what the stale-lock branch is for: the
next start logs `stale lock from pid N, taking over`. `simulate_pipeline.py`
cleans the lock up for the relay it started once that owner is gone.

## State on disk

Everything lives under `--run` (default `./run`), one directory per agent:

| File | Contents |
|---|---|
| `state.json` | agent id, key ids, demo seeds, card envelope |
| `card.json` | the DSSE `card+json` envelope that gets published |
| `peers.json` | cached peer cards (discovery is OPEN-10 in the blueprint) |
| `grants.json` | `{name: {env, body, grant_id}}` |
| `replay.json` / `xfer.json` | the receiver's own durable stores |
| `audit.json` | the hash-chained audit log |
| `outbox/<tx>.json` | sealed chunk ciphertexts the sender kept so `--resume` can re-upload one. Ciphertext only — no key material. |
| `received/<tx>/` | the materialized tree after an accepted RECEIPT |
| `negatives/<case>/` | one throwaway receiver per negative case |

Delete `run/` to start clean.

## `receive` flags

`--policy` turns on the real authorization gate. `policy_resource` defaults to
`None`, which **fails closed** with `ERR_POLICY_DENIED` / `policy_resource must
be configured` (`D-044`) — so pass `--policy-resource` explicitly whenever you
pass `--policy`. Also available: `--policy-action`, `--policy-presenter`,
`--revoked-grant`, `--grants-file`, `--max-transfers` (drain-and-process passes
over the mailbox, default 1), `--audit-log`, `--dest`.

The receiver pulls the data plane on demand: once after an `ACCEPT`, and again
before it finalizes a `COMPLETE`, because the control plane is sender-driven.
A chunk the relay does not hold is a gap, not an error: the gap becomes
`have` in the `STATUS` the receiver sends back, and the sender resumes with
exactly what `sender_due_chunks` says is due.

## Caveats — read this before trusting anything here

* **All key material is TEST-ONLY.** `init` derives each agent's Ed25519 and
  X25519 keys deterministically from `SHA-256("AATP/0.2/DEMO-SEED\n" + name)`
  and stores the seed in `state.json` so the receiver can be rebuilt after a
  restart. These are throwaway demo keys. **Never production keys.**
* **CRY-007 (cryptographic review) is still OPEN**, and per D-020 the
  blueprint's V05/V06 hashes are UNVERIFIABLE. This is a functioning demo, not a
  production-conformance claim.
* `policy_fn` / the grant chain are rebuilt from `grants.json` on every
  `receive`, which is why the state dir is durable; the receiver itself never
  persists a grant.
* The quarantine scanner is a **stub** that always returns `clean`. It records
  a real `SEC-007` verdict with a name and version; it does not scan anything.
* The handoff body carries `policy_context` in addition to the fields the
  blueprint's appendix lists — `HandoffStore._check_body` requires exactly that
  field set.
* `tools/` is not packaged. Adding it to `pyproject.toml` would be a scope
  change; it stays out of `aatp/`.
