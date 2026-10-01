"""M7 quarantine records (blueprint §8.4 RECEIPT vocabulary, §11 SEC-006/007/008).

States are ``accepted | rejected | quarantined`` only (SEC-006: never
"malicious"). Scanner verdicts are policy inputs recorded with
name/version (SEC-007), visible via ``verdicts_of``, never as states.

Never logs keys / CEKs / plaintext.
"""
import re

from aatp.errors import err
from aatp.messages import parse_ts

STATES = ("quarantined", "accepted", "rejected")
VERDICTS = ("clean", "suspicious", "malicious")

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERDICT_FIELDS = frozenset(
    {"scanner_name", "scanner_version", "verdict", "at"})


def _malformed(detail: str):
    return err("ERR_MALFORMED_MESSAGE", detail)


def _check_digest(v: object, what: str) -> str:
    if not isinstance(v, str) or not _DIGEST_RE.match(v):
        raise _malformed(f"{what} must be sha256:<64 hex>")
    return v


def _check_verdict(v: object) -> dict:
    if not isinstance(v, dict) or set(v.keys()) != _VERDICT_FIELDS:
        raise _malformed("verdict must carry exactly "
                         "scanner_name,scanner_version,verdict,at")
    for f in ("scanner_name", "scanner_version"):
        if not isinstance(v[f], str) or not v[f]:
            raise _malformed(f"verdict.{f} must be a non-empty string")
    if v["verdict"] not in VERDICTS:
        raise _malformed("verdict.verdict must be clean|suspicious|malicious")
    try:
        parse_ts(v["at"])
    except Exception:
        raise _malformed("verdict.at must be YYYY-MM-DDTHH:MM:SSZ") from None
    return {"scanner_name": v["scanner_name"],
            "scanner_version": v["scanner_version"],
            "verdict": v["verdict"], "at": v["at"]}


class Quarantine:
    """Local quarantine store (SEC-006/007/008)."""

    def __init__(self, *, trusted_scanners=None,
                 authorized_releasers=None,
                 quarantine_on_suspicious: bool = True):
        self._trusted = set(trusted_scanners) if trusted_scanners else set()
        self._releasers = (set(authorized_releasers)
                           if authorized_releasers else set())
        self._qos = bool(quarantine_on_suspicious)
        self._records: dict[str, dict] = {}

    def place(self, content_root: str, node_id: str,
              verdicts: list) -> dict:
        """Record scanner verdicts; return the state record (no verdicts)."""
        _check_digest(content_root, "content_root")
        _check_digest(node_id, "node_id")
        if not isinstance(verdicts, list):
            raise _malformed("verdicts must be a list")
        clean = [_check_verdict(v) for v in verdicts]
        if any(v["verdict"] == "malicious" and v["scanner_name"] in self._trusted
               for v in clean):
            state = "rejected"
        elif any(v["verdict"] == "malicious" for v in clean):
            state = "quarantined"
        elif any(v["verdict"] == "suspicious" for v in clean):
            state = "quarantined" if self._qos else "accepted"
        elif not clean:
            state = "quarantined"
        else:
            state = "accepted"
        self._records[content_root] = {
            "content_root": content_root, "node_id": node_id,
            "state": state, "verdicts": clean,
        }
        return self.state_of(content_root)

    def release(self, content_root: str, released_by: str,
                *, at: str) -> dict:
        """Trusted release of a quarantined record to accepted (SEC-007)."""
        rec = self._records.get(content_root)
        if rec is None:
            raise err("ERR_ARTIFACT_NOT_FOUND", "unknown content_root")
        try:
            parse_ts(at)
        except Exception:
            raise _malformed("at must be YYYY-MM-DDTHH:MM:SSZ") from None
        if not isinstance(released_by, str) or not released_by:
            raise _malformed("released_by must be a non-empty string")
        if rec["state"] != "quarantined":
            raise err("ERR_POLICY_DENIED", "only quarantined records release")
        if released_by not in self._releasers:
            raise err("ERR_POLICY_DENIED", "releaser not authorized")
        rec["state"] = "accepted"
        rec["released_by"] = released_by
        rec["at"] = at
        return self.state_of(content_root)

    def state_of(self, content_root: str):
        """Return ``{content_root, node_id, state, ...}`` — never verdicts."""
        rec = self._records.get(content_root)
        if rec is None:
            return None
        out = {"content_root": rec["content_root"], "node_id": rec["node_id"],
               "state": rec["state"]}
        if "released_by" in rec:
            out["released_by"] = rec["released_by"]
            out["at"] = rec["at"]
        return out

    def verdicts_of(self, content_root: str):
        """Return the recorded scanner verdicts (SEC-007), or None."""
        rec = self._records.get(content_root)
        if rec is None:
            return None
        return [dict(v) for v in rec["verdicts"]]

    def taint_annotations(self, node_ids: list) -> dict:
        """SEC-008: ``{"tainted_from": [...]}`` sorted, deduped."""
        if not isinstance(node_ids, list):
            raise _malformed("node_ids must be a list")
        for n in node_ids:
            _check_digest(n, "node_id")
        return {"tainted_from": sorted(set(node_ids))}
