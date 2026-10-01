"""M7 quarantine (blueprint §11 SEC-006/007/008, §8.4 RECEIPT vocabulary).

TDD RED: written before aatp/quarantine.py exists. One rule ID = one test.
"""
import hashlib

import pytest

from aatp.errors import AATPError

T_AT = "2026-10-01T12:00:00Z"


def _digest(tag: str) -> str:
    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


CR1 = _digest("content-1")
CR2 = _digest("content-2")
N1 = _digest("node-1")
N2 = _digest("node-2")
N3 = _digest("node-3")


def _verdict(name="scan", version="1.0", verdict="clean", at=T_AT):
    return {"scanner_name": name, "scanner_version": version,
            "verdict": verdict, "at": at}


def _q(**kw):
    from aatp.quarantine import Quarantine
    params = {"trusted_scanners": set(), "authorized_releasers": {"rel-1"}}
    params.update(kw)
    return Quarantine(**params)


# --- place outcomes (SEC-007 policy mapping) ---------------------------------

def test_quarantine_clean_accepted():
    q = _q()
    rec = q.place(CR1, N1, [_verdict(verdict="clean")])
    assert rec["state"] == "accepted"


def test_quarantine_suspicious_quarantined():
    q = _q()
    rec = q.place(CR1, N1, [_verdict(verdict="suspicious")])
    assert rec["state"] == "quarantined"


def test_quarantine_untrusted_malicious_quarantined():
    # Scanners are policy dependencies, not trusted subsystems: an
    # untrusted "malicious" verdict quarantines, never rejects.
    q = _q()
    rec = q.place(CR1, N1, [_verdict(verdict="malicious")])
    assert rec["state"] == "quarantined"


def test_quarantine_trusted_malicious_rejected():
    q = _q(trusted_scanners={"scan"})
    rec = q.place(CR1, N1, [_verdict(verdict="malicious")])
    assert rec["state"] == "rejected"


def test_quarantine_trusted_clean_suspicious_mix_quarantined():
    q = _q(trusted_scanners={"scan"})
    rec = q.place(CR1, N1, [_verdict("scan", "1.0", "clean"),
                            _verdict("other", "2.0", "suspicious")])
    assert rec["state"] == "quarantined"


def test_quarantine_empty_verdicts_quarantined():
    # Fail closed: no scan evidence -> quarantined, never accepted.
    q = _q()
    assert q.place(CR1, N1, [])["state"] == "quarantined"


def test_quarantine_suspicious_allowed_when_policy_off():
    q = _q(quarantine_on_suspicious=False)
    assert q.place(CR1, N1, [_verdict(verdict="suspicious")])["state"] == "accepted"


# --- SEC-006: state labels never "malicious" ----------------------------------

def test_SEC006_quarantined_not_malicious():
    from aatp.canon import jcs
    q = _q()
    q.place(CR1, N1, [_verdict(verdict="malicious")])  # untrusted scanner
    state = q.state_of(CR1)
    assert state["state"] in ("quarantined", "accepted", "rejected")
    assert state["state"] == "quarantined"
    assert "malicious" not in jcs(state).decode("utf-8")


def test_SEC007_verdict_record():
    q = _q()
    q.place(CR1, N1, [_verdict("scan", "3.1", "suspicious")])
    verdicts = q.verdicts_of(CR1)
    assert verdicts == [{"scanner_name": "scan", "scanner_version": "3.1",
                         "verdict": "suspicious", "at": T_AT}]


# --- SEC-008 taint ------------------------------------------------------------

def test_SEC008_tainted_from():
    q = _q()
    out = q.taint_annotations([N2, N1, N2])
    assert out == {"tainted_from": sorted([N1, N2])}


def test_SEC008_tainted_from_malformed():
    q = _q()
    with pytest.raises(AATPError) as e:
        q.taint_annotations(["not-a-digest"])
    assert e.value.code == "ERR_MALFORMED_MESSAGE"


# --- release -------------------------------------------------------------------

def test_quarantine_release_authorized():
    q = _q(authorized_releasers={"alice"})
    q.place(CR1, N1, [_verdict(verdict="suspicious")])
    rec = q.release(CR1, "alice", at=T_AT)
    assert rec["state"] == "accepted"
    assert rec["released_by"] == "alice"
    assert rec["at"] == T_AT


def test_quarantine_release_denied():
    q = _q(authorized_releasers={"alice"})
    q.place(CR1, N1, [_verdict(verdict="suspicious")])
    with pytest.raises(AATPError) as e:
        q.release(CR1, "mallory", at=T_AT)
    assert e.value.code == "ERR_POLICY_DENIED"
    assert q.state_of(CR1)["state"] == "quarantined"


def test_quarantine_release_unknown_content():
    q = _q(authorized_releasers={"alice"})
    with pytest.raises(AATPError) as e:
        q.release(CR2, "alice", at=T_AT)
    assert e.value.code == "ERR_ARTIFACT_NOT_FOUND"


def test_quarantine_release_rejected_not_releasable():
    q = _q(trusted_scanners={"scan"}, authorized_releasers={"alice"})
    q.place(CR1, N1, [_verdict(verdict="malicious")])
    with pytest.raises(AATPError) as e:
        q.release(CR1, "alice", at=T_AT)
    assert e.value.code == "ERR_POLICY_DENIED"


# --- malformed inputs (fail closed) ----------------------------------------------

def test_quarantine_malformed_digest():
    q = _q()
    with pytest.raises(AATPError) as e:
        q.place("nope", N1, [_verdict()])
    assert e.value.code == "ERR_MALFORMED_MESSAGE"


def test_quarantine_malformed_verdict():
    q = _q()
    with pytest.raises(AATPError) as e:
        q.place(CR1, N1, [{"scanner_name": "s", "scanner_version": "1",
                           "verdict": "evil", "at": T_AT}])
    assert e.value.code == "ERR_MALFORMED_MESSAGE"


def test_quarantine_malformed_verdict_ts():
    q = _q()
    with pytest.raises(AATPError) as e:
        q.place(CR1, N1, [_verdict(at="yesterday")])
    assert e.value.code == "ERR_MALFORMED_MESSAGE"


def test_quarantine_state_unknown_none():
    assert _q().state_of(CR2) is None
    assert _q().verdicts_of(CR2) is None
