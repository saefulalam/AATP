"""M6 policy evaluation pipeline (blueprint §10.2 M6-scope, SEC-002, N22).

Order (deny at first failure, fail closed):
  1. grant chain valid for action+resource (AUT-001..006 family)
  2. manifest size/entry limits (ART-006)
  3. offer expiry, when ``expires_at`` is given (MSG-003)
  4. classification vs leaf ``constraints.classification_max`` (AUT-002)
  5. consumption_mode gate (SEC-002)

Pure function: no transfer wiring (M7 scope). Never logs keys.
"""
from aatp import grants as grants_mod
from aatp.artifact import validate_manifest
from aatp.errors import AATPError
from aatp.grants import CLASS_ORDER, res_subset
from aatp.messages import parse_ts

INSTRUCT_ACT = "aatp.artifact.instruct"

_GRANT_RULE_BY_CODE = {
    "ERR_GRANT_ATTENUATION": "AUT-002",
    "ERR_GRANT_INVALID": "AUT-004",
    "ERR_POLICY_DENIED": "AUT-006",
    "ERR_MALFORMED_MESSAGE": "GEN-010",
}


def _deny(rule_id: str, code: str) -> dict:
    return {"decision": "deny", "rule_id": rule_id, "code": code}


def evaluate(request: dict, *, roots, key_resolver, presenter,
             now: str) -> dict:
    """Evaluate a request; return ``{"decision", "rule_id", "code"}``.

    ``request`` holds ``action``, ``resource``, ``grant_leaf_env`` plus
    optional ``grant_chain_envs`` (default ``[]``), ``revoked``,
    ``manifest``, ``limits``, ``expires_at``, ``classification``
    (default ``PUBLIC``) and ``consumption_mode`` (default ``data_only``).
    """
    action = request["action"]
    resource = request["resource"]
    # 1. grant chain valid for action+resource.
    try:
        leaf = grants_mod.verify_chain(
            request["grant_leaf_env"], request.get("grant_chain_envs", []),
            roots, now, action, resource, presenter,
            revoked=request.get("revoked"),
            key_resolver=key_resolver)
    except AATPError as e:
        return _deny(_GRANT_RULE_BY_CODE.get(e.code, "AUT-001"), e.code)
    # 2. manifest size/entry limits.
    manifest = request.get("manifest")
    if manifest is not None:
        try:
            validate_manifest(manifest, request.get("limits"))
        except AATPError as e:
            return _deny("ART-006", e.code)
    # 3. offer expiry (strict: expires_at < now denies; equality allows).
    expires_at = request.get("expires_at")
    if expires_at is not None:
        try:
            exp = parse_ts(expires_at)
        except AATPError as e:
            return _deny("GEN-010", e.code)
        if exp < parse_ts(now):
            return _deny("MSG-003", "ERR_MESSAGE_EXPIRED")
    # 4. classification vs leaf classification_max.
    classification = request.get("classification", "PUBLIC")
    try:
        rank = CLASS_ORDER[classification]
    except (KeyError, TypeError):
        return _deny("GEN-010", "ERR_MALFORMED_MESSAGE")
    if rank > CLASS_ORDER[leaf["constraints"]["classification_max"]]:
        return _deny("AUT-002", "ERR_POLICY_DENIED")
    # 5. consumption_mode gate (SEC-002, N22).
    mode = request.get("consumption_mode", "data_only")
    if mode == "data_only":
        pass
    elif mode == "instructions_allowed":
        if not any(c["act"] == INSTRUCT_ACT
                   and res_subset(resource, c["res"])
                   for c in leaf["cap"]):
            return _deny("SEC-002", "ERR_POLICY_DENIED")
    else:
        return _deny("SEC-002", "ERR_POLICY_DENIED")
    return {"decision": "allow", "rule_id": "POLICY-ALLOW", "code": None}
