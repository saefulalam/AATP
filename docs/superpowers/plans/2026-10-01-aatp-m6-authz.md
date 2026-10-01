# AATP M6 Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement delegable authorization (grants with attenuation), task handoff with leases, and the policy evaluation pipeline for in-scope steps, per blueprint §10 plus SEC-002 gate.

**Architecture:** New package modules `aatp/grants.py` (chain verification), `aatp/handoff.py` (two-phase lease state), `aatp/policy.py` (ordered evaluation + consumption_mode). All grants are DSSE `grant+json` envelopes; all failures are `AATPError` with §14 codes; gaps go to `DECISIONS.md`.

**Tech Stack:** Python 3.12, existing `aatp/` modules (errors, canon, b64, dsse with `PT_GRANT`, signer). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-01-aatp-core-m0-m5-design.md`
**Blueprint:** `AATP_v0_2_Blueprint.md` §10 (lines ~492-540), §14 error table, §17.1 N19/N20/N22

## Global Constraints

- One rule ID = one test, named after the rule ID, failing-first (§18.4.1).
- Never log or print private keys, CEKs, or plaintext artifact bytes (§18.4.2).
- Fail closed on ambiguity; record in `DECISIONS.md` (§0.4, §18.4.3).
- No features outside the blueprint (§18.4.4).
- Timestamps exactly `YYYY-MM-DDTHH:MM:SSZ` UTC (GEN-004); reuse timestamp helpers by import, do not duplicate.
- Grant JSON fields exactly per §10.1: `v, iss, aud, cap[{act,res}], nbf, exp, prf[grant_id...], constraints{classification_max, export}`.
- `grant_id = "sha256:" + hex(SHA256(b"AATP/0.2/GRANT\n" + JCS(grant)))`.
- Action vocabulary exactly: `aatp.artifact.send`, `aatp.artifact.receive`, `aatp.artifact.derive`, `aatp.artifact.instruct`, `aatp.task.handoff`, `aatp.task.accept`, `aatp.grant.delegate`.
- `res_subset(child, parent) := child == parent OR (parent ends with "*" AND child startswith parent[:-1])`.
- Classification order: `PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`.
- Chain depth ≤ 8 (AUT-004); clock skew 120s (import single source, do not redefine).
- Branch `feat/core-m0-m5`; do NOT switch branches or change git config; tests via `.venv\Scripts\python -m pytest`; PowerShell 5.1.

---

### Task M6-1: `grants.py` — grant chain verification (AUT-001..006)

**Files:**
- Create: `aatp/grants.py`
- Test: `tests/test_grants.py`
- Modify: `DECISIONS.md` (new D-0xx entries), `reference_vectors.py` (none — no blueprint vectors for grants)

**Interfaces:**
- Consumes: `aatp.errors.err/AATPError`, `aatp.canon.jcs/parse_jcs`, `aatp.dsse.PT_GRANT/make_envelope/verify_envelope`.
- Produces: `grant_id_of(grant: dict) -> str`; `res_subset(child: str, parent: str) -> bool`; `make_grant_envelope(grant: dict, signer) -> dict`; `verify_chain(leaf_env: dict, chain_envs: list[dict], roots: set[str], now: str, action: str, resource: str, presenter: str, *, key_resolver) -> dict` (returns verified leaf grant; raises `AATPError`). `key_resolver(agent_id) -> bytes` returns current signing pubkey (same pattern as `DagStore`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_grants.py
import pytest
from aatp.errors import AATPError
from aatp.grants import grant_id_of, res_subset, verify_chain

def test_AUT002_grant_id_shape():
    g = {"v": "0.2", "iss": "aatp:x", "aud": "aatp:y",
         "cap": [{"act": "aatp.artifact.receive", "res": "project:alpha/*"}],
         "nbf": "2026-10-01T00:00:00Z", "exp": "2026-10-02T00:00:00Z",
         "prf": [], "constraints": {"classification_max": "INTERNAL", "export": False}}
    gid = grant_id_of(g)
    assert gid.startswith("sha256:") and len(gid) == 7 + 64

def test_AUT002_res_subset():
    assert res_subset("project:alpha/a", "project:alpha/*")
    assert res_subset("project:alpha/a", "project:alpha/a")
    assert not res_subset("project:beta/a", "project:alpha/*")
    assert not res_subset("project:alpha", "project:alpha/*")

def test_N19_child_widens_res_rejected():
    # parent res "project:alpha/*", child res "project:beta/*" -> ERR_GRANT_ATTENUATION
    ...
```

(Full test list in task: `test_AUT001_root_*`, `test_AUT002_attenuation_{iss,cap,nbf,exp,constraints}_*`, `test_AUT003_delegate_*`, `test_AUT004_depth/time_*`, `test_AUT005_revoked_*`, `test_AUT006_presenter_*`, `test_N19_*`. Implementer writes all of them first.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_grants.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aatp.grants'`

- [ ] **Step 3: Write minimal implementation**

```python
# aatp/grants.py
import hashlib
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_GRANT, make_envelope, verify_envelope
from aatp.errors import err

D_GRANT = b"AATP/0.2/GRANT\n"
CLASS_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
MAX_DEPTH = 8

def grant_id_of(grant: dict) -> str:
    return "sha256:" + hashlib.sha256(D_GRANT + jcs(grant)).hexdigest()

def res_subset(child: str, parent: str) -> bool:
    if child == parent:
        return True
    return parent.endswith("*") and child.startswith(parent[:-1])
```

Plus: `_check_grant_shape` (required fields, `v=="0.2"`, cap entries have known `act` + str `res`, `prf` list of `sha256:` digests, constraints shape; failures → `ERR_MALFORMED_MESSAGE`); `_constraints_cover(child_c, parent_c)` (child `classification_max` rank ≤ parent rank; child `export=True` only if parent `export=True`; missing keys treated as most-restrictive? NO — fail closed: missing `classification_max`/`export` → `ERR_MALFORMED_MESSAGE`; record in DECISIONS.md); `_attenuated(child, parent)` per AUT-002 (`child.iss == parent.aud`, every child cap covered, `child.nbf ≥ parent.nbf`, `child.exp ≤ parent.exp`, constraints cover; else `ERR_GRANT_ATTENUATION`); `verify_chain` (verify leaf envelope with issuer key via key_resolver; walk `prf` links through chain_envs matching `grant_id_of`; root `iss` in roots (AUT-001 else `ERR_GRANT_INVALID`); depth ≤ 8 (count leaf+chain, else `ERR_GRANT_INVALID`); each hop attenuation + delegation bit (AUT-003: non-root hop requires parent cap `aatp.grant.delegate` covering resource, else `ERR_GRANT_ATTENUATION`); time windows ± skew (AUT-004 else `ERR_GRANT_INVALID`); revocation set param `revoked: set[str]` (AUT-005: leaf or ancestor id in set → `ERR_GRANT_INVALID`); presenter `leaf.aud == presenter` (AUT-006 else `ERR_POLICY_DENIED`); action/resource coverage by leaf cap (else `ERR_POLICY_DENIED`)).

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_grants.py -v`
Expected: PASS. Then full suite: `.venv\Scripts\python -m pytest -q` → all green.

- [ ] **Step 5: Commit**

```bash
git add aatp/grants.py tests/test_grants.py DECISIONS.md
git commit -m "feat(M6): grant chain verify AUT-001..006"
```

---

### Task M6-2: `handoff.py` — two-phase handoff with lease (HND-001..006)

**Files:**
- Create: `aatp/handoff.py`
- Test: `tests/test_handoff.py`
- Modify: `DECISIONS.md`

**Interfaces:**
- Consumes: `aatp.grants.verify_chain/grant_id_of`, `aatp.errors`, `aatp.canon`, `aatp.messages.build_message/check_shape` (for HANDOFF_OFFER/HANDOFF_RESPONSE envelopes — reuse, do not rebuild).
- Produces: `HandoffStore` class: `offer(handoff: dict, grant_chain: dict, now: str) -> None` (validates + stores PENDING; raises); `respond(handoff_id: str, decision: str, now: str, *, signer_responder) -> dict` (returns signed HANDOFF_RESPONSE envelope dict; on accept past lease → raises `ERR_LEASE_EXPIRED` without state change); `state_of(handoff_id) -> str` (`PENDING|ACCEPTED|REJECTED|EXPIRED|VOID`); `audit_log(task_id) -> list[dict]` (HND-006: accepted handoff id + decision appended).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_handoff.py
def test_HND001_accept_before_lease_transfers():
    ...  # offer then respond accept before lease_expires_at -> ACCEPTED

def test_N20_accept_after_lease_rejected():
    ...  # respond accept with now > lease_expires_at -> ERR_LEASE_EXPIRED, state VOID

def test_HND003_grant_broader_than_sender_rejected():
    ...  # embedded grant AUT-002 vs sender authority fails -> ERR_GRANT_ATTENUATION

def test_HND004_input_not_covered_rejected():
    ...  # input_node_ids outside grant res -> ERR_POLICY_DENIED
```

(Full list: `test_HND001_*`, `test_HND002_late_accept_* + sender_still_responsible`, `test_HND003_*`, `test_HND004_*`, `test_HND005_conditional_*`, `test_HND006_audit_*`, `test_N20_*`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_handoff.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

`HandoffBody` shape check (required `handoff_id, task{task_id,title,objective}, input_node_ids, grant_env, expected_outputs, deadline, lease_expires_at`; `v=="0.2"` if present per M6 convention — blueprint A.6 has no `v`; do NOT require `v`, record in DECISIONS.md). Lease: `lease_expires_at > now` at offer else `ERR_MALFORMED_MESSAGE`; `respond("accept")` with `now > lease_expires_at` → `ERR_LEASE_EXPIRED`, mark VOID (HND-002; sender responsibility flag stays False→ sender remains responsible: expose `responsible(handoff_id) -> str` returning current responsible agent: sender until ACCEPTED). HND-003: run `grants.verify_chain` on embedded grant against sender's authority roots before storing. HND-004: every `input_node_ids` must be covered — node ids are digests, not resources: interpret as grant `res` must cover the task/resource string in `policy_context.resource` (record interpretation in DECISIONS.md; exact check: `policy_context.resource` covered by grant leaf cap for `aatp.task.handoff`, else `ERR_POLICY_DENIED`). HND-005: `constraints` in offer vs responder-declared conditions — accept with `conditions` param; unsatisfiable (caller-declared) → `ERR_POLICY_DENIED`. HND-006: on ACCEPTED append `{"handoff_id","task_id","decision":"accept","at":now}` to per-task audit list.

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_handoff.py -v` → PASS; full suite green.

- [ ] **Step 5: Commit**

```bash
git add aatp/handoff.py tests/test_handoff.py DECISIONS.md
git commit -m "feat(M6): handoff leases HND-001..006"
```

---

### Task M6-3: `policy.py` — evaluation order + consumption_mode gate (SEC-002, N22)

**Files:**
- Create: `aatp/policy.py`
- Test: `tests/test_policy.py`
- Modify: `DECISIONS.md`

**Interfaces:**
- Consumes: `aatp.grants.verify_chain`, `aatp.card.verify_card` (trust already done by callers — policy takes verified inputs), `aatp.artifact.validate_manifest`.
- Produces: `evaluate(request: dict, *, roots, key_resolver, presenter, now) -> dict` where request holds `{action, resource, classification, grant_leaf_env, grant_chain_envs, manifest?, consumption_mode?}`; returns `{"decision": "allow"|"deny", "rule_id": str, "code": str|None}`. Order per §10.2 M6-scope: grant chain valid → size/entry limits → offer expiry (if `expires_at` given) → classification vs grant `classification_max` → consumption_mode gate. Deny at first failure (fail closed).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_policy.py
def test_policy_allows_valid_receive():
    ...  # full valid chain + INTERNAL vs max CONFIDENTIAL -> allow

def test_policy_denies_widened_grant():
    ...  # N19-shaped chain -> deny, rule_id AUT-002, code ERR_GRANT_ATTENUATION

def test_N22_instructions_without_grant_denied():
    ...  # consumption_mode instructions_allowed, no aatp.artifact.instruct cap -> deny ERR_POLICY_DENIED
```

(Full list: allow-path, each deny step with `rule_id` assertion, `test_SEC002_data_only_default`, `test_SEC002_instruct_with_grant_allowed`, `test_N22_*`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_policy.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
# aatp/policy.py
from aatp import grants as grants_mod
from aatp.errors import err

def evaluate(request, *, roots, key_resolver, presenter, now):
    # 1. grant chain valid for action+resource (AUT-001..006)
    try:
        grants_mod.verify_chain(request["grant_leaf_env"], request.get("grant_chain_envs", []),
                                roots, now, request["action"], request["resource"],
                                presenter, key_resolver=key_resolver)
    except Exception as e:
        code = getattr(e, "code", "ERR_GRANT_INVALID")
        return {"decision": "deny", "rule_id": "AUT-002", "code": code}
    ...
```

Plus steps: manifest limits via `validate_manifest` (map error code through, `rule_id` from exception detail or `ART-006`); expiry (`expires_at < now` → deny `MSG-003`/`ERR_MESSAGE_EXPIRED`); classification rank (`CLASS_ORDER[classification] > CLASS_ORDER[leaf.constraints.classification_max]` → deny `AUT-002`/`ERR_POLICY_DENIED`); consumption_mode (`instructions_allowed` requires leaf cap `aatp.artifact.instruct` covering resource, else deny `SEC-002`/`ERR_POLICY_DENIED`; default `data_only` when key absent). Success → `{"decision": "allow", "rule_id": "POLICY-ALLOW", "code": None}` (record synthetic rule_id in DECISIONS.md).

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_policy.py -v` → PASS; full suite green.

- [ ] **Step 5: Commit**

```bash
git add aatp/policy.py tests/test_policy.py DECISIONS.md
git commit -m "feat(M6): policy pipeline + consumption gate"
```

---

## Self-Review Notes (controller fills after writing)

- Spec coverage: AUT-001..006 → M6-1; HND-001..006 → M6-2; §10.2 in-scope steps + SEC-002/N22 → M6-3; N19 → M6-1; N20 → M6-2.
- No placeholders: every step has concrete code/commands/expected output.
- Handoff message types (HANDOFF_OFFER/HANDOFF_RESPONSE) reuse `messages.build_message` registry — no new wire format invented.
