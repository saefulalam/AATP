"""M3 provenance nodes + DAG store (blueprint section 7, PRV-001..022).

Fixtures are implementation-generated (NOT blueprint vectors):
actor is derived in-test via aatp.ids.derive_agent_id from a local seed;
task_id / timestamps are fixed in-test; CR1/CR2 are OUR artifact content_roots
from tests/test_artifact.py. No blueprint V05/V06 hash is asserted anywhere
(see DECISIONS.md D-020).
"""
import hashlib

import pytest

from aatp.canon import jcs
from aatp.dsse import PT_NODE, make_envelope, verify_envelope
from aatp.errors import AATPError
from aatp.ids import derive_agent_id
from aatp.signer import SoftwareSigner

# OUR artifact roots (tests/test_artifact.py): V04 manifest (hello 5B) and the
# hello-world (11B) variant from the Task-5 Step-0 probe (D-019 corroboration).
CR1 = "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf"
CR2 = "sha256:316dcfe880067987f2d83df8c040db75612d521f7df41ffe37a1847bed253bec"

SEED = bytes([0x77]) * 32
WRONG_SEED = bytes([0x88]) * 32
TASK = "task_local_m3_001"
T0 = "2026-10-01T00:00:00Z"
T1 = "2026-10-01T00:01:00Z"
T2 = "2026-10-01T00:02:00Z"


def _signer(seed=SEED, key_id="n0"):
    return SoftwareSigner.from_seed(seed, key_id)


def _actor(seed=SEED):
    return derive_agent_id(_signer(seed).public_key_raw())


def _resolver(signers):
    """Build actor->pubkey resolver from {actor: signer}."""
    pubs = {a: s.public_key_raw() for a, s in signers.items()}

    def resolve(actor):
        try:
            return pubs[actor]
        except KeyError:
            raise AATPError("ERR_AUTH_FAILED", 1102, "unknown actor") from None

    return resolve


def test_PRV001_determinism_same_inputs_same_id():
    from aatp.node import make_node
    actor = _actor()
    n1, id1 = make_node(CR1, [], "create", actor, TASK, None, T0)
    n2, id2 = make_node(CR1, [], "create", actor, TASK, None, T0)
    assert id1 == id2
    assert n1 == n2
    exp = "sha256:" + hashlib.sha256(b"AATP/0.2/NODE\n" + jcs(n1)).hexdigest()
    assert id1 == exp


def test_PRV001_unsorted_parents_rejected():
    from aatp.node import make_node
    actor = _actor()
    _, id_a = make_node(CR1, [], "create", actor, TASK, None, T0)
    _, id_b = make_node(CR1, [], "create", actor, TASK, None, T1)
    lo, hi = sorted([id_a, id_b])
    with pytest.raises(AATPError) as ei:
        make_node(CR1, [hi, lo], "merge", actor, TASK, None, T2)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_PRV001_dup_parents_rejected():
    from aatp.node import make_node
    actor = _actor()
    _, id_a = make_node(CR1, [], "create", actor, TASK, None, T0)
    with pytest.raises(AATPError) as ei:
        make_node(CR1, [id_a, id_a], "merge", actor, TASK, None, T1)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


def test_PRV006_arity():
    from aatp.node import make_node
    actor = _actor()
    fake = "sha256:" + "0" * 64
    with pytest.raises(AATPError) as ei:
        make_node(CR1, [fake], "create", actor, TASK, None, T0)
    assert ei.value.code == "ERR_INVALID_PARENT"
    with pytest.raises(AATPError):
        make_node(CR1, [], "modify", actor, TASK, None, T0)
    with pytest.raises(AATPError):
        make_node(CR1, [], "revert", actor, TASK, None, T0)
    with pytest.raises(AATPError):
        make_node(CR1, [], "supersede", actor, TASK, None, T0)
    with pytest.raises(AATPError):
        make_node(CR1, [], "verify", actor, TASK, None, T0)
    _, solo = make_node(CR1, [], "create", actor, TASK, None, T0)
    _ = solo
    _, m1 = make_node(CR1, [], "create", actor, TASK, None, T0)
    _ = m1
    with pytest.raises(AATPError) as ei2:
        make_node(CR1, [fake], "merge", actor, TASK, None, T1)
    assert ei2.value.code == "ERR_INVALID_PARENT"


def test_PRV004_revert_is_not_a_cycle():
    from aatp.node import DagStore, make_node, make_node_envelope
    actor = _actor()
    s = _signer()
    n1, id1 = make_node(CR1, [], "create", actor, TASK, None, T0)
    n2, id2 = make_node(CR2, [id1], "modify", actor, TASK, None, T1)
    n3, id3 = make_node(CR1, [id2], "revert", actor, TASK, None, T2)
    assert id3 != id1  # same content_root, distinct node_id
    store = DagStore()
    res = _resolver({actor: s})
    for n in (n1, n2, n3):
        store.add(make_node_envelope(n, s), res)  # must NOT raise ERR_DAG_CYCLE
    assert store.get(id3)["content_root"] == CR1
    assert store.ancestry_status(id3) == "complete"


def test_PRV003_self_ancestor_rejected():
    from aatp.node import DagStore
    from aatp.errors import err
    store = DagStore()
    # Synthetic cycle A<->B injected directly: honest hashes can never form a
    # loop (PRV-003 defense-in-depth), so the detector is proven on a fake graph.
    store._nodes["sha256:" + "a" * 64] = (
        {"v": "0.2", "content_root": CR1, "parents": ["sha256:" + "b" * 64],
         "operation": "modify", "actor": _actor(), "task_id": TASK,
         "created_at": T1}, None)
    store._nodes["sha256:" + "b" * 64] = (
        {"v": "0.2", "content_root": CR1, "parents": ["sha256:" + "a" * 64],
         "operation": "modify", "actor": _actor(), "task_id": TASK,
         "created_at": T1}, None)
    with pytest.raises(AATPError) as ei:
        store.ancestors("sha256:" + "a" * 64)
    assert ei.value.code == "ERR_DAG_CYCLE"
    # Direct self-parent is also rejected by the guard.
    with pytest.raises(AATPError) as ei2:
        store._ensure_no_cycle("sha256:" + "c" * 64, ["sha256:" + "c" * 64])
    assert ei2.value.code == "ERR_DAG_CYCLE"
    assert err("ERR_DAG_CYCLE").numeric == 1306


def test_PRV005_time_skew_violation():
    from aatp.node import DagStore, make_node, make_node_envelope
    actor = _actor()
    s = _signer()
    res = _resolver({actor: s})
    store = DagStore()
    n1, id1 = make_node(CR1, [], "create", actor, TASK, None, "2026-10-01T01:00:00Z")
    store.add(make_node_envelope(n1, s), res)
    # Child 121s older than parent (skew=120) -> ERR_INVALID_PARENT.
    n_old, _ = make_node(CR2, [id1], "modify", actor, TASK, None, "2026-10-01T00:57:59Z")
    with pytest.raises(AATPError) as ei:
        store.add(make_node_envelope(n_old, s), res)
    assert ei.value.code == "ERR_INVALID_PARENT"
    # Exactly 120s older is accepted.
    n_edge, id_edge = make_node(
        CR2, [id1], "modify", actor, TASK, None, "2026-10-01T00:58:00Z")
    assert store.add(make_node_envelope(n_edge, s), res) == id_edge


def test_PRV002_signed_by_actor():
    from aatp.node import DagStore, make_node, make_node_envelope
    actor = _actor()
    good = _signer()
    bad = _signer(WRONG_SEED, "n0")
    n1, _ = make_node(CR1, [], "create", actor, TASK, None, T0)
    store = DagStore()
    res = _resolver({actor: good})
    # Correct key verifies and returns the parsed node.
    env = make_node_envelope(n1, good)
    assert env["payloadType"] == PT_NODE
    assert verify_envelope(env, PT_NODE, good.public_key_raw()) == n1
    # Wrong key -> ERR_SIGNATURE_INVALID.
    bad_env = make_node_envelope(n1, bad)
    with pytest.raises(AATPError) as ei:
        store.add(bad_env, res)
    assert ei.value.code == "ERR_SIGNATURE_INVALID"


def test_PRV010_require_unknown_parent_rejected():
    from aatp.node import DagStore, make_node, make_node_envelope
    actor = _actor()
    s = _signer()
    res = _resolver({actor: s})
    store = DagStore(parent_policy="require")
    ghost = "sha256:" + "f" * 64
    n, _ = make_node(CR1, [ghost], "modify", actor, TASK, None, T0)
    with pytest.raises(AATPError) as ei:
        store.add(make_node_envelope(n, s), res)
    assert ei.value.code == "ERR_INVALID_PARENT"


def test_PRV011_lazy_partial_ancestry():
    from aatp.node import DagStore, make_node, make_node_envelope
    actor = _actor()
    s = _signer()
    res = _resolver({actor: s})
    store = DagStore()  # lazy default
    n1, id1 = make_node(CR1, [], "create", actor, TASK, None, T0)
    store.add(make_node_envelope(n1, s), res)
    assert store.ancestry_status(id1) == "complete"
    assert store.ancestors(id1) == []
    ghost = "sha256:" + "e" * 64
    n2, id2 = make_node(CR2, [id1, ghost], "merge", actor, TASK, None, T1)
    # merge needs >=2 parents: [id1, ghost] has 2 (sorted check below).
    assert n2["parents"] == sorted([id1, ghost])
    store.add(make_node_envelope(n2, s), res)  # lazy accepts
    assert store.ancestry_status(id2) == "partial"
    assert id1 in store.ancestors(id2)


def test_PRV012_verify_node():
    from aatp.node import DagStore, make_node, make_node_envelope
    actor = _actor()
    s = _signer()
    res = _resolver({actor: s})
    store = DagStore()
    n1, id1 = make_node(CR1, [], "create", actor, TASK, None, T0)
    store.add(make_node_envelope(n1, s), res)
    # verify without annotations.verification -> rejected.
    with pytest.raises(AATPError):
        make_node(CR1, [id1], "verify", actor, TASK, None, T1)
    good_ann = {"verification": {"outcome": "pass", "scope": "artifact"}}
    n_ok, id_ok = make_node(CR1, [id1], "verify", actor, TASK,
                            None, T1, annotations=good_ann)
    assert store.add(make_node_envelope(n_ok, s), res) == id_ok
    bad_ann = {"verification": {"outcome": "maybe", "scope": "artifact"}}
    with pytest.raises(AATPError):
        make_node(CR1, [id1], "verify", actor, TASK,
                          None, T1, annotations=bad_ann)


def test_PRV021_generator_defaults():
    from aatp.node import make_node
    actor = _actor()
    # None -> omitted.
    n, _ = make_node(CR1, [], "create", actor, TASK, None, T0)
    assert "generator" not in n
    # Missing assurance defaults to self_asserted.
    n2, _ = make_node(CR1, [], "create", actor, TASK,
                      {"kind": "ai"}, T0)
    assert n2["generator"]["assurance"] == "self_asserted"
    assert n2["generator"]["kind"] == "ai"
    # Bad kind rejected.
    with pytest.raises(AATPError):
        make_node(CR1, [], "create", actor, TASK, {"kind": "robot"}, T0)


def test_PRV022_no_raw_prompts():
    from aatp.node import make_node
    actor = _actor()
    with pytest.raises(AATPError):
        make_node(CR1, [], "create", actor, TASK,
                  {"kind": "ai", "prompt": "do evil"}, T0)
    # Digests-only accepted.
    d = "sha256:" + "1" * 64
    n, _ = make_node(CR1, [], "create", actor, TASK,
                    {"kind": "ai", "prompt_digest": d}, T0)
    assert n["generator"]["prompt_digest"] == d


def test_GEN004_strict_timestamp():
    from aatp.node import make_node
    actor = _actor()
    with pytest.raises(AATPError) as ei:
        make_node(CR1, [], "create", actor, TASK, None, "2026-10-01T00:00:00.000Z")
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
    with pytest.raises(AATPError):
        make_node(CR1, [], "create", actor, TASK, None, "not-a-time")
