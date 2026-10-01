"""M7 untrusted-content helpers (blueprint §11 SEC-001..005, §12 AUD-001/002).

Delimiting marks content as data; it never sanitizes. Tool calls are
re-authorized against the agent's own grants. Audit chaining is
``SHA256(prev_raw || JCS(entry))`` with a secret-key guard.

Never logs keys / CEKs / plaintext.
"""
import hashlib
import re
import shlex

from aatp.canon import jcs
from aatp.errors import AATPError, err
from aatp.policy import evaluate as policy_evaluate

_AGENT_RE = re.compile(r"^aatp:[a-z2-7]{52}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

FORBIDDEN_AUDIT_KEYS = frozenset(
    {"cek", "private_key", "plaintext", "payload", "plaintext_bytes"})


def _malformed(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def _audit_has_forbidden(obj) -> str | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN_AUDIT_KEYS:
                return k
            found = _audit_has_forbidden(v)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _audit_has_forbidden(v)
            if found is not None:
                return found
    return None


def delimit_for_model(text: str, source: str = "unknown") -> str:
    """SEC-001/003: fence artifact text as data (verbatim, never executed)."""
    if not isinstance(text, str):
        raise _malformed("text must be a string")
    if not isinstance(source, str):
        raise _malformed("source must be a string")
    if source != "unknown" and not _AGENT_RE.match(source):
        raise _malformed("source must be an agent_id or 'unknown'")
    return f"<<<AATP-DATA source={source}>>>\n{text}\n<<<END-AATP-DATA>>>"


def quote_filename(path: str) -> str:
    """SEC-005: shell-quote a manifest path."""
    if not isinstance(path, str):
        raise _malformed("path must be a string")
    return shlex.quote(path)


def tool_allowed(tool_action: str, resource: str, *, agent_chain=None,
                 roots=None, key_resolver=None, presenter=None, now=None,
                 leaf_env=None, chain_envs=None) -> bool:
    """SEC-004: re-authorize tool use against the agent's own grants.

    Accepts either an ``agent_chain`` dict ``{leaf_env, chain_envs}`` plus
    keyword ``roots/key_resolver/presenter/now``, or the same pieces as
    flat keywords. Deny (any ``AATPError``) returns False, never raises;
    programming errors propagate.
    """
    if isinstance(agent_chain, dict):
        leaf_env = agent_chain.get("leaf_env", leaf_env)
        chain_envs = agent_chain.get("chain_envs", chain_envs)
        roots = agent_chain.get("roots", roots)
        key_resolver = agent_chain.get("key_resolver", key_resolver)
        presenter = agent_chain.get("presenter", presenter)
        now = agent_chain.get("now", now)
    if chain_envs is None:
        chain_envs = []
    request = {"action": tool_action, "resource": resource,
               "grant_leaf_env": leaf_env, "grant_chain_envs": chain_envs,
               "consumption_mode": "data_only"}
    try:
        out = policy_evaluate(request, roots=roots,
                              key_resolver=key_resolver,
                              presenter=presenter, now=now)
    except AATPError:
        return False
    return isinstance(out, dict) and out.get("decision") == "allow"


def audit_append(log: list, entry: dict, *, prev_hash: str = "00" * 32) -> str:
    """AUD-001/002: guard secrets, append the chained record, return hash."""
    if not isinstance(log, list):
        raise _malformed("log must be a list")
    if not isinstance(entry, dict):
        raise _malformed("entry must be an object")
    if not isinstance(prev_hash, str) or not _HASH_RE.match(prev_hash):
        raise _malformed("prev_hash must be 64 lowercase hex")
    bad = _audit_has_forbidden(entry)
    if bad is not None:
        raise _malformed(f"audit entry must not carry {bad!r}")
    new_hash = hashlib.sha256(bytes.fromhex(prev_hash) + jcs(entry)).hexdigest()
    log.append({"entry": dict(entry), "prev_hash": prev_hash,
                "entry_hash": new_hash})
    return new_hash
