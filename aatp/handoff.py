"""M6 two-phase handoff with lease (blueprint section 10.3, HND-001..006, N20).

State only: this module never signs on its own. The responder's
``HANDOFF_RESPONSE`` envelope is built with ``messages.build_message`` and
signed inside :meth:`HandoffStore.respond` with the caller-supplied signer.

Never log keys.
"""
import copy
import re

from aatp.canon import jcs
from aatp.dsse import PT_MESSAGE, make_envelope
from aatp.errors import err
from aatp.grants import verify_chain
from aatp.messages import build_message, check_id, parse_ts

HANDOFF_ACT = "aatp.task.handoff"

_REQUIRED_FIELDS = frozenset({
    "handoff_id", "task", "input_node_ids", "grant_env",
    "expected_outputs", "deadline", "lease_expires_at", "policy_context"})
_TASK_FIELDS = frozenset({"task_id", "title", "objective", "constraints"})

_AGENT_RE = re.compile(r"^aatp:[a-z2-7]{52}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _malformed(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def _check_agent(v: object, what: str) -> str:
    if not isinstance(v, str) or not _AGENT_RE.match(v):
        raise _malformed(f"{what} must be an agent_id")
    return v


def _check_body(handoff: object) -> dict:
    if not isinstance(handoff, dict):
        raise _malformed("handoff must be an object")
    if set(handoff.keys()) != _REQUIRED_FIELDS:
        raise _malformed("handoff must carry exactly " + ",".join(
            sorted(_REQUIRED_FIELDS)))
    check_id(handoff["handoff_id"], "handoff_id")
    task = handoff["task"]
    if (not isinstance(task, dict)
            or not ({"task_id", "title", "objective"} <= set(task.keys()))
            or set(task.keys()) - _TASK_FIELDS):
        raise _malformed("task must carry task_id,title,objective"
                         " and optional constraints only")
    check_id(task["task_id"], "task.task_id")
    for f in ("title", "objective"):
        if not isinstance(task[f], str) or not task[f]:
            raise _malformed(f"task.{f} must be a non-empty string")
    constraints = task.get("constraints", {})
    if not isinstance(constraints, dict):
        raise _malformed("task.constraints must be an object")
    node_ids = handoff["input_node_ids"]
    if not isinstance(node_ids, list):
        raise _malformed("input_node_ids must be a list")
    for n in node_ids:
        if not isinstance(n, str) or not _DIGEST_RE.match(n):
            raise _malformed("input_node_ids entries must be sha256:<64 hex>")
    if not isinstance(handoff["grant_env"], dict):
        raise _malformed("grant_env must be an object")
    outputs = handoff["expected_outputs"]
    if not isinstance(outputs, list) or any(
            not isinstance(o, str) for o in outputs):
        raise _malformed("expected_outputs must be a list of strings")
    parse_ts(handoff["deadline"])
    parse_ts(handoff["lease_expires_at"])
    ctx = handoff["policy_context"]
    if not isinstance(ctx, dict):
        raise _malformed("policy_context must be an object")
    if not isinstance(ctx.get("resource"), str) or not ctx["resource"]:
        raise _malformed("policy_context.resource must be a non-empty string")
    return handoff


class HandoffStore:
    """Pending/terminal handoff states plus the per-task audit log."""

    def __init__(self):
        self._offers: dict[str, dict] = {}
        self._audit: dict[str, list] = {}

    def offer(self, handoff: dict, grant_chain_envs=None, now: str = "", *,
              sender: str, recipient: str, roots, key_resolver) -> None:
        """Validate a HANDOFF_OFFER body and store it PENDING."""
        body = _check_body(handoff)
        _check_agent(sender, "sender")
        _check_agent(recipient, "recipient")
        now_dt = parse_ts(now)
        lease_dt = parse_ts(body["lease_expires_at"])
        if lease_dt <= now_dt:
            raise _malformed("lease_expires_at must be after now")
        hid = body["handoff_id"]
        if hid in self._offers:
            raise err("ERR_POLICY_DENIED", "duplicate handoff_id")
        chain_envs = [] if grant_chain_envs is None else grant_chain_envs
        verify_chain(body["grant_env"], chain_envs, roots, now,
                     HANDOFF_ACT, body["policy_context"]["resource"],
                     recipient, key_resolver=key_resolver)
        self._offers[hid] = {
            "handoff_id": hid, "task_id": body["task"]["task_id"],
            "sender": sender, "recipient": recipient,
            "lease_expires_at": body["lease_expires_at"],
            "constraints": dict(body["task"].get("constraints", {})),
            "state": "PENDING", "response": None,
        }

    def respond(self, handoff_id: str, decision: str, now: str, *,
                responder: str, signer, conditions=None,
                code: str | None = None) -> dict:
        """Sign and return the HANDOFF_RESPONSE envelope for a PENDING offer."""
        rec = self._offers.get(handoff_id)
        if rec is None:
            raise err("ERR_POLICY_DENIED", "unknown handoff_id")
        if decision not in ("accept", "reject"):
            raise _malformed("decision must be accept or reject")
        if conditions is not None and not isinstance(conditions, dict):
            raise _malformed("conditions must be an object or null")
        if code is not None and not isinstance(code, str):
            raise _malformed("code must be a string or null")
        if rec["state"] in ("ACCEPTED", "REJECTED"):
            if ((rec["state"] == "ACCEPTED") == (decision == "accept")):
                return copy.deepcopy(rec["response"])
            raise err("ERR_POLICY_DENIED", "conflicting decision on closed handoff")
        if responder != rec["recipient"]:
            raise err("ERR_POLICY_DENIED", "only the designated recipient may respond")
        if parse_ts(now) > parse_ts(rec["lease_expires_at"]):
            rec["state"] = "VOID"
            raise err("ERR_LEASE_EXPIRED", "lease expired before response")
        if decision == "accept" and rec["constraints"] and conditions != rec["constraints"]:
            raise err("ERR_POLICY_DENIED", "offer constraints not satisfied")
        body = {"handoff_id": handoff_id, "decision": decision}
        if code is not None:
            body["code"] = code
        msg = build_message("HANDOFF_RESPONSE", sender=rec["recipient"],
                            sender_key_id=signer.key_id(),
                            recipient=rec["sender"], body=body, now=now,
                            corr={"task_id": rec["task_id"]})
        env = make_envelope(PT_MESSAGE, jcs(msg), signer)
        if decision == "accept":
            rec["state"] = "ACCEPTED"
            self._audit.setdefault(rec["task_id"], []).append(
                {"handoff_id": handoff_id, "task_id": rec["task_id"],
                 "decision": "accept", "at": now})
        else:
            rec["state"] = "REJECTED"
        rec["response"] = env
        return copy.deepcopy(env)

    def state_of(self, handoff_id: str, now: str | None = None) -> str:
        """Stored state; PENDING reads EXPIRED when ``now`` is past the lease."""
        rec = self._offers.get(handoff_id)
        if rec is None:
            raise err("ERR_POLICY_DENIED", "unknown handoff_id")
        if rec["state"] == "PENDING" and now is not None:
            if parse_ts(now) > parse_ts(rec["lease_expires_at"]):
                return "EXPIRED"
        return rec["state"]

    def responsible(self, handoff_id: str) -> str:
        """Sender until ACCEPTED, then the recipient (HND-001/002)."""
        rec = self._offers.get(handoff_id)
        if rec is None:
            raise err("ERR_POLICY_DENIED", "unknown handoff_id")
        return rec["recipient"] if rec["state"] == "ACCEPTED" else rec["sender"]

    def audit_log(self, task_id: str) -> list:
        """HND-006 accepted-handoff entries for a task (copies)."""
        return [dict(e) for e in self._audit.get(task_id, [])]
