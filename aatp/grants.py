"""M6 grant chain verification (blueprint section 10.1, AUT-001..006, N19).

grant_id = "sha256:" + hex(SHA256(D_GRANT + JCS(grant))).
Grants travel as DSSE ``grant+json`` envelopes signed by the issuer.

Never log keys.
"""
import hashlib
import re
from datetime import timedelta

from aatp.b64 import b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_GRANT, make_envelope, verify_envelope
from aatp.errors import AATPError, err
from aatp.messages import CLOCK_SKEW_SECONDS, parse_ts

D_GRANT = b"AATP/0.2/GRANT\n"
MAX_DEPTH = 8

CLASS_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}

ACTION_VOCABULARY = frozenset({
    "aatp.artifact.send", "aatp.artifact.receive", "aatp.artifact.derive",
    "aatp.artifact.instruct", "aatp.task.handoff", "aatp.task.accept",
    "aatp.grant.delegate",
})
DELEGATE_ACT = "aatp.grant.delegate"

_GRANT_FIELDS = frozenset(
    {"v", "iss", "aud", "cap", "nbf", "exp", "prf", "constraints"})

_AGENT_RE = re.compile(r"^aatp:[a-z2-7]{52}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _malformed(detail: str) -> AATPError:
    return err("ERR_MALFORMED_MESSAGE", detail)


def grant_id_of(grant: dict) -> str:
    return "sha256:" + hashlib.sha256(D_GRANT + jcs(grant)).hexdigest()


def res_subset(child: str, parent: str) -> bool:
    if not isinstance(child, str) or not isinstance(parent, str):
        raise _malformed("res_subset needs string resources")
    if child == parent:
        return True
    return parent.endswith("*") and child.startswith(parent[:-1])


def _check_grant_shape(grant: object) -> dict:
    if not isinstance(grant, dict):
        raise _malformed("grant must be an object")
    if set(grant.keys()) != _GRANT_FIELDS:
        raise _malformed("grant must carry exactly v,iss,aud,cap,nbf,exp,prf,constraints")
    if grant["v"] != "0.2":
        raise _malformed("grant v must be 0.2")
    for f in ("iss", "aud"):
        if not isinstance(grant[f], str) or not _AGENT_RE.match(grant[f]):
            raise _malformed(f"grant.{f} must be an agent_id")
    cap = grant["cap"]
    if not isinstance(cap, list) or not cap:
        raise _malformed("grant.cap must be a non-empty list")
    for c in cap:
        if not isinstance(c, dict) or set(c.keys()) != {"act", "res"}:
            raise _malformed("grant.cap entries must be {act,res}")
        if c["act"] not in ACTION_VOCABULARY:
            raise _malformed("grant.cap.act not in vocabulary")
        if not isinstance(c["res"], str) or not c["res"]:
            raise _malformed("grant.cap.res must be a non-empty string")
    nbf = parse_ts(grant["nbf"])
    exp = parse_ts(grant["exp"])
    if nbf > exp:
        raise _malformed("grant.nbf must be <= grant.exp")
    prf = grant["prf"]
    if not isinstance(prf, list):
        raise _malformed("grant.prf must be a list")
    for p in prf:
        if not isinstance(p, str) or not _DIGEST_RE.match(p):
            raise _malformed("grant.prf entries must be sha256:<64 hex>")
    con = grant["constraints"]
    if not isinstance(con, dict) or set(con.keys()) != {"classification_max", "export"}:
        raise _malformed("grant.constraints must be {classification_max,export}")
    if con["classification_max"] not in CLASS_ORDER:
        raise _malformed("grant.constraints.classification_max unknown")
    if not isinstance(con["export"], bool):
        raise _malformed("grant.constraints.export must be a boolean")
    return grant


def _constraints_cover(child: dict, parent: dict) -> bool:
    cc, pc = child["constraints"], parent["constraints"]
    if CLASS_ORDER[cc["classification_max"]] > CLASS_ORDER[pc["classification_max"]]:
        return False
    if cc["export"] and not pc["export"]:
        return False
    return True


def _cap_covered(cap: dict, caps: list) -> bool:
    return any(p["act"] == cap["act"] and res_subset(cap["res"], p["res"])
               for p in caps)


def _attenuated(child: dict, parent: dict) -> None:
    """AUT-002: raise ERR_GRANT_ATTENUATION unless child narrows parent."""
    if child["iss"] != parent["aud"]:
        raise err("ERR_GRANT_ATTENUATION", "AUT-002: child.iss != parent.aud")
    for c in child["cap"]:
        if not _cap_covered(c, parent["cap"]):
            raise err("ERR_GRANT_ATTENUATION", "AUT-002: child cap not covered")
    if parse_ts(child["nbf"]) < parse_ts(parent["nbf"]):
        raise err("ERR_GRANT_ATTENUATION", "AUT-002: child.nbf older than parent")
    if parse_ts(child["exp"]) > parse_ts(parent["exp"]):
        raise err("ERR_GRANT_ATTENUATION", "AUT-002: child.exp later than parent")
    if not _constraints_cover(child, parent):
        raise err("ERR_GRANT_ATTENUATION", "AUT-002: constraints widened")


def _has_delegate(parent: dict, child: dict) -> None:
    """AUT-003: every delegated cap needs parent aatp.grant.delegate cover."""
    for c in child["cap"]:
        ok = any(p["act"] == DELEGATE_ACT and res_subset(c["res"], p["res"])
                 for p in parent["cap"])
        if not ok:
            raise err("ERR_GRANT_ATTENUATION",
                      "AUT-003: parent lacks aatp.grant.delegate for resource")


def _verify_grant_envelope(env: object, key_resolver) -> dict:
    if not isinstance(env, dict) or not isinstance(env.get("payload"), str):
        raise _malformed("grant envelope must carry a string payload")
    try:
        raw = b64u_dec(env["payload"])
    except AATPError:
        raise _malformed("grant payload not valid base64url") from None
    peek = parse_jcs(raw)
    if not isinstance(peek, dict):
        raise _malformed("grant payload must be a JSON object")
    _check_grant_shape(peek)
    try:
        pubkey = key_resolver(peek["iss"])
    except AATPError:
        raise
    except Exception as e:
        raise err("ERR_AUTH_FAILED", "key resolution failed") from e
    if not isinstance(pubkey, bytes) or len(pubkey) != 32:
        raise err("ERR_AUTH_FAILED", "resolved key must be 32 bytes")
    grant = verify_envelope(env, PT_GRANT, pubkey)
    if not isinstance(grant, dict):
        raise _malformed("grant payload must be a JSON object")
    _check_grant_shape(grant)
    return grant


def make_grant_envelope(grant: dict, signer) -> dict:
    """Sign a shape-checked grant as a DSSE grant+json envelope."""
    _check_grant_shape(grant)
    return make_envelope(PT_GRANT, jcs(grant), signer)


def verify_chain(leaf_env: dict, chain_envs: list, roots, now: str,
                 action: str, resource: str, presenter: str,
                 revoked=None, *, key_resolver) -> dict:
    """Verify a grant chain; return the leaf grant or raise AATPError."""
    if not isinstance(chain_envs, list):
        raise _malformed("chain_envs must be a list")
    if revoked is None:
        revoked_set = set()
    else:
        try:
            revoked_set = set(revoked)
        except TypeError:
            raise _malformed("revoked must be iterable") from None
    now_dt = parse_ts(now)
    leaf = _verify_grant_envelope(leaf_env, key_resolver)
    ancestors = [_verify_grant_envelope(e, key_resolver) for e in chain_envs]
    grants = [leaf] + ancestors
    if len(grants) > MAX_DEPTH:
        raise err("ERR_GRANT_INVALID", "AUT-004: chain depth exceeds 8")
    ids = [grant_id_of(g) for g in grants]
    n = len(grants)
    for i, g in enumerate(grants):
        if i < n - 1 and not g["prf"]:
            raise err("ERR_GRANT_INVALID", "AUT-001: chain gap before root")
        for t, entry in enumerate(g["prf"]):
            if i + 1 + t >= n or entry != ids[i + 1 + t]:
                raise err("ERR_GRANT_INVALID", "AUT-001: prf link mismatch")
    try:
        trusted = grants[-1]["iss"] in roots
    except TypeError:
        raise _malformed("roots must be a container of agent ids") from None
    if not trusted:
        raise err("ERR_GRANT_INVALID", "AUT-001: root iss not trusted")
    for i in range(n - 1):
        _attenuated(grants[i], grants[i + 1])
        _has_delegate(grants[i + 1], grants[i])
    skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
    for g in grants:
        if not (parse_ts(g["nbf"]) - skew <= now_dt <= parse_ts(g["exp"]) + skew):
            raise err("ERR_GRANT_INVALID", "AUT-004: grant outside validity window")
    for gid in ids:
        if gid in revoked_set:
            raise err("ERR_GRANT_INVALID", "AUT-005: grant revoked")
    if leaf["aud"] != presenter:
        raise err("ERR_POLICY_DENIED", "AUT-006: presenter is not leaf aud")
    if not isinstance(action, str) or not isinstance(resource, str):
        raise err("ERR_POLICY_DENIED", "action/resource must be strings")
    if not any(c["act"] == action and res_subset(resource, c["res"])
               for c in leaf["cap"]):
        raise err("ERR_POLICY_DENIED", "no leaf cap covers action+resource")
    return leaf
