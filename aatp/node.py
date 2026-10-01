"""M3 provenance nodes + DAG store (blueprint section 7, PRV-001..022).

node_id = "sha256:" + hex(SHA256(D_NODE + JCS(node))) (PRV-001).
Nodes are published as DSSE node+json envelopes signed by actor (PRV-002).
"""
import hashlib
import re
from datetime import datetime, timezone

from aatp.b64 import b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_NODE, make_envelope, verify_envelope
from aatp.errors import AATPError, err

D_NODE = b"AATP/0.2/NODE\n"
CLOCK_SKEW_SECONDS = 120

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_AGENT_RE = re.compile(r"^aatp:[a-z2-7]{52}$")
_TASK_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_OPERATIONS = ("create", "modify", "merge", "revert", "verify", "supersede")
_GENERATOR_KINDS = ("ai", "human", "tool", "mixed")
_ASSURANCES = ("self_asserted", "issuer_attested", "hardware_attested")
_RAW_PROMPT_KEYS = ("prompt", "prompt_text", "toolcalls")


def _malformed(detail: str) -> AATPError:
    return err("ERR_MALFORMED_MESSAGE", detail)


def _parse_ts(s: object) -> datetime:
    if not isinstance(s, str) or not _TS_RE.match(s):
        raise _malformed("timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise _malformed("invalid timestamp") from None


def _check_digest(v: object, what: str) -> None:
    if not isinstance(v, str) or not _DIGEST_RE.match(v):
        raise _malformed(f"{what} must be sha256:<64 hex>")


def _normalize_generator(gen):
    """PRV-020/021/022: self-asserted default, digests only, never raw prompts."""
    if gen is None:
        return None
    if not isinstance(gen, dict):
        raise _malformed("generator must be an object")
    for raw in _RAW_PROMPT_KEYS:
        if raw in gen:
            raise _malformed(f"generator must not embed raw {raw!r} (digests only)")
    kind = gen.get("kind")
    if kind not in _GENERATOR_KINDS:
        raise _malformed("generator.kind must be ai|human|tool|mixed")
    out = dict(gen)
    if out.get("assurance") is None:
        out["assurance"] = "self_asserted"  # PRV-021 default claim
    if out["assurance"] not in _ASSURANCES:
        raise _malformed("generator.assurance unknown")
    for f in ("prompt_digest", "toolcalls_digest"):
        if f in out and out[f] is not None:
            _check_digest(out[f], f"generator.{f}")
    if "human_approver" in out and out["human_approver"] is not None:
        if not isinstance(out["human_approver"], str) or not _AGENT_RE.match(
                out["human_approver"]):
            raise _malformed("generator.human_approver malformed")
    if "model" in out and out["model"] is not None and not isinstance(out["model"], dict):
        raise _malformed("generator.model must be an object")
    if "runtime" in out and out["runtime"] is not None and not isinstance(
            out["runtime"], dict):
        raise _malformed("generator.runtime must be an object")
    return out


def _check_annotations(operation: str, ann) -> None:
    if ann is None:
        if operation == "verify":
            raise _malformed("verify node needs annotations.verification")
        return
    if not isinstance(ann, dict):
        raise _malformed("annotations must be an object")
    if operation == "verify":  # PRV-012
        ver = ann.get("verification")
        if not isinstance(ver, dict):
            raise _malformed("verify node needs annotations.verification")
        if ver.get("outcome") not in ("pass", "fail"):
            raise _malformed("verification.outcome must be pass|fail")
        if not isinstance(ver.get("scope"), str):
            raise _malformed("verification.scope must be a string")


def _check_parents(parents: object) -> list:
    if not isinstance(parents, list):
        raise _malformed("parents must be a list")
    for p in parents:
        _check_digest(p, "parent")
    if len(set(parents)) != len(parents):
        raise _malformed("parents must not contain duplicates")  # PRV-001
    if list(parents) != sorted(parents):
        raise _malformed("parents must be sorted ascending")  # PRV-001
    return list(parents)


def _check_arity(operation: str, parents: list) -> None:
    n = len(parents)
    if operation == "create":
        if n != 0:
            raise err("ERR_INVALID_PARENT", "create requires 0 parents")
    elif operation == "merge":
        if n < 2:
            raise err("ERR_INVALID_PARENT", "merge requires >= 2 parents")
    elif operation in ("modify", "revert", "supersede", "verify"):
        if n < 1:
            raise err("ERR_INVALID_PARENT", f"{operation} requires >= 1 parent")
    else:
        raise _malformed("unknown operation")


def _build_node(content_root, parents, operation, actor, task_id,
                generator, now, annotations=None) -> dict:
    _check_digest(content_root, "content_root")
    clean_parents = _check_parents(parents)
    if operation not in _OPERATIONS:
        raise _malformed("unknown operation")
    _check_arity(operation, clean_parents)
    if not isinstance(actor, str) or not _AGENT_RE.match(actor):
        raise _malformed("actor malformed")
    if not isinstance(task_id, str) or not _TASK_RE.match(task_id):
        raise _malformed("task_id malformed")
    _parse_ts(now)
    gen = _normalize_generator(generator)
    _check_annotations(operation, annotations)
    node = {"v": "0.2", "content_root": content_root, "parents": clean_parents,
            "operation": operation, "actor": actor, "task_id": task_id,
            "created_at": now}
    if gen is not None:
        node["generator"] = gen
    if annotations is not None:
        node["annotations"] = annotations
    return node


def node_id_of(node: dict) -> str:
    return "sha256:" + hashlib.sha256(D_NODE + jcs(node)).hexdigest()


def make_node(content_root, parents, operation, actor, task_id,
              generator, now, annotations=None) -> tuple:
    """Create a node dict and its node_id (PRV-001/006, GEN-004)."""
    node = _build_node(content_root, parents, operation, actor, task_id,
                       generator, now, annotations)
    return node, node_id_of(node)


def make_node_envelope(node: dict, signer) -> dict:
    """Publish a node as a DSSE node+json envelope signed by actor (PRV-002)."""
    return make_envelope(PT_NODE, jcs(node), signer)


def validate_node(node: object) -> str:
    """Validate shape/arity/timestamps; return recomputed node_id."""
    if not isinstance(node, dict):
        raise _malformed("node must be an object")
    if node.get("v") != "0.2":
        raise err("ERR_PROTOCOL_VERSION", "node v must be 0.2")
    for f in ("content_root", "parents", "operation", "actor",
              "task_id", "created_at"):
        if f not in node:
            raise _malformed(f"node missing {f}")
    rebuilt = _build_node(node["content_root"], node["parents"],
                          node["operation"], node["actor"], node["task_id"],
                          node.get("generator"), node["created_at"],
                          node.get("annotations"))
    if "generator" not in node and "generator" in rebuilt:
        raise _malformed("node generator mismatch")
    return node_id_of(rebuilt)


class DagStore:
    """In-memory provenance DAG with lazy/require parent policy (PRV-010/011)."""

    def __init__(self, parent_policy: str = "lazy",
                 clock_skew_seconds: int = CLOCK_SKEW_SECONDS):
        if parent_policy not in ("lazy", "require"):
            raise _malformed("parent_policy must be lazy|require")
        self._policy = parent_policy
        self._skew = clock_skew_seconds
        self._nodes: dict = {}

    def _ensure_no_cycle(self, node_id: str, parents: list) -> None:
        """PRV-003: reject if node_id appears among its own ancestors."""
        if node_id in parents:
            raise err("ERR_DAG_CYCLE", "node lists itself as parent")
        seen = set()
        stack = list(parents)
        while stack:
            cur = stack.pop()
            if cur == node_id:
                raise err("ERR_DAG_CYCLE", "node among its own ancestors")
            if cur in seen:
                continue
            seen.add(cur)
            entry = self._nodes.get(cur)
            if entry is not None:
                stack.extend(entry[0].get("parents", []))
            if len(seen) > 100000:
                raise err("ERR_DAG_CYCLE", "ancestry too deep / cycle suspected")

    def _transitive(self, node_id: str) -> tuple:
        """Return (ancestors list, complete bool); raise ERR_DAG_CYCLE on loop."""
        if node_id not in self._nodes:
            raise err("ERR_ARTIFACT_NOT_FOUND", "unknown node")
        out: list = []
        seen: set = set()
        path: set = set()
        complete = True

        def visit(cur: str):
            nonlocal complete
            entry = self._nodes.get(cur)
            if entry is None:
                complete = False
                return
            for p in entry[0].get("parents", []):
                if p in path:
                    raise err("ERR_DAG_CYCLE", "cycle in stored ancestry")
                if p not in seen:
                    seen.add(p)
                    out.append(p)
                    if p not in self._nodes:
                        complete = False
                    else:
                        path.add(p)
                        visit(p)
                        path.discard(p)

        path.add(node_id)
        visit(node_id)
        path.discard(node_id)
        return out, complete

    def add(self, envelope: dict, key_resolver) -> str:
        """Verify envelope (PRV-002), validate node, enforce time/cycle/policy."""
        if not isinstance(envelope, dict) or not isinstance(
                envelope.get("payload"), str):
            raise _malformed("node envelope must carry a string payload")
        try:
            raw = b64u_dec(envelope["payload"])
        except AATPError:
            raise _malformed("node payload not valid base64url") from None
        peek = parse_jcs(raw)
        if not isinstance(peek, dict):
            raise _malformed("node payload must be a JSON object")
        actor = peek.get("actor")
        if not isinstance(actor, str) or not _AGENT_RE.match(actor):
            raise _malformed("node actor malformed")
        try:
            pubkey = key_resolver(actor)
        except AATPError:
            raise
        except Exception as e:
            raise err("ERR_AUTH_FAILED", "key resolution failed") from e
        if not isinstance(pubkey, bytes) or len(pubkey) != 32:
            raise err("ERR_AUTH_FAILED", "resolved key must be 32 bytes")
        node = verify_envelope(envelope, PT_NODE, pubkey)
        if not isinstance(node, dict):
            raise _malformed("node payload must be a JSON object")
        node_id = validate_node(node)
        if node_id in self._nodes:
            return node_id  # idempotent replay
        child_ts = _parse_ts(node["created_at"])
        unknown: list = []
        for p in node["parents"]:
            parent = self._nodes.get(p)
            if parent is None:
                unknown.append(p)
                continue
            parent_ts = _parse_ts(parent[0]["created_at"])
            if (child_ts - parent_ts).total_seconds() < -self._skew:  # PRV-005
                raise err("ERR_INVALID_PARENT", "created_at older than parent")
        if unknown and self._policy == "require":  # PRV-010
            raise err("ERR_INVALID_PARENT", "unresolvable parent")
        self._ensure_no_cycle(node_id, node["parents"])  # PRV-003
        self._nodes[node_id] = (node, envelope)
        return node_id

    def get(self, node_id: str) -> dict:
        try:
            return dict(self._nodes[node_id][0])
        except KeyError:
            raise err("ERR_ARTIFACT_NOT_FOUND", "unknown node") from None

    def ancestors(self, node_id: str) -> list:
        ancestors, _ = self._transitive(node_id)
        self._ensure_no_cycle(node_id, ancestors)
        return ancestors

    def ancestry_status(self, node_id: str) -> str:
        _, complete = self._transitive(node_id)
        return "complete" if complete else "partial"  # PRV-011
