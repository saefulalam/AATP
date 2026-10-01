"""Task 9 conformance gate: vectors regenerate byte-identical + impl matches JSON + N01-N16 green.

Per D-020 (binding human decision): blueprint V05 node_ids / V06 signature are
UNVERIFIABLE (vectors file absent). This file MUST NOT assert any blueprint
node/signature strings. It asserts instead:
  (a) committed tests/vectors/aatp_v0_2_vectors.json regenerates byte-identical
      via reference_vectors.main() into a temp comparison (write_bytes LF);
  (b) V01/V02/V03/V04/V07/V08 implementation outputs equal the JSON values
      (implementation modules vs JSON, closing T0-1/T1-1 drift gap);
  (c) V05-STRUCTURE present and labeled implementation-generated;
  (d) N01-N16 each have at least one passing test (canonical test names are
      mapped in comments; N17/N18 run the test_node.py test ids directly).
"""
import hashlib
import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).parent / "vectors" / "aatp_v0_2_vectors.json"


def _load_vectors():
    return json.loads(VECTORS_PATH.read_bytes().decode("utf-8"))


# --- (a) regeneration ----------------------------------------------------------

def test_vectors_regenerate_byte_identical(tmp_path):
    import reference_vectors
    committed = VECTORS_PATH.read_bytes()
    tmp_out = tmp_path / "aatp_v0_2_vectors.json"
    orig_out = reference_vectors.OUT
    reference_vectors.OUT = tmp_out
    try:
        reference_vectors.main()
    finally:
        reference_vectors.OUT = orig_out
    regenerated = tmp_out.read_bytes()
    assert regenerated == committed
    assert b"\r" not in regenerated
    assert regenerated.endswith(b"\n")


# --- (b) implementation vs JSON -------------------------------------------------

def test_V01_implementation_matches_json():
    from aatp.canon import jcs
    vec = _load_vectors()["V01"]
    assert jcs({"b": 2, "a": 1}) == bytes.fromhex(vec["jcs_hex"])
    assert jcs({"b": 2, "a": 1}).hex() == vec["jcs_hex"]


def test_V02_implementation_matches_json():
    from aatp.b64 import b64u
    vec = _load_vectors()["V02"]
    assert hashlib.sha256(b"hello").hexdigest() == vec["sha256_hello"]
    assert b64u(b"hello") == vec["b64url_hello"]


def test_V03_implementation_matches_json():
    from aatp.ids import derive_agent_id
    vec = _load_vectors()["V03"]
    assert derive_agent_id(bytes.fromhex(vec["genesis_pub_hex"])) == vec["agent_id"]


def test_V04_implementation_matches_json():
    from aatp.artifact import build
    from aatp.canon import jcs
    vec = _load_vectors()["V04"]
    manifest, stream, cr = build(
        [("hello.txt", b"hello", False), ("bin/run.sh", b"echo hi\n", True)]
    )
    assert jcs(manifest).hex() == vec["manifest_jcs_hex"]
    assert jcs(manifest) == bytes.fromhex(vec["manifest_jcs_hex"])
    assert stream.hex() == vec["stream_hex"]
    assert cr == vec["content_root"]


def test_V07_implementation_matches_json():
    from aatp.chunks import decrypt_one, encrypt_chunks, nonce
    vec = _load_vectors()["V07"]
    cek = bytes.fromhex(vec["cek_hex"])
    stream = bytes.fromhex(vec["stream_hex"])
    cts = encrypt_chunks(cek, stream, vec["chunk_size"],
                         vec["content_root"], vec["transfer_id"])
    assert len(cts) == len(vec["chunks"])
    for i, ch in enumerate(vec["chunks"]):
        assert ch["i"] == i
        assert nonce(i).hex() == ch["nonce_hex"]
        assert cts[i].hex() == ch["ct_hex"]
    total = len(cts)
    assert decrypt_one(cek, 0, total, vec["content_root"],
                       vec["transfer_id"], cts[0]) == stream[:vec["chunk_size"]]
    assert decrypt_one(cek, 1, total, vec["content_root"],
                       vec["transfer_id"], cts[1]) == stream[vec["chunk_size"]:]


def test_V08_negative_expectations():
    from aatp.chunks import decrypt_one, encrypt_chunks
    from aatp.errors import AATPError
    vecs = _load_vectors()
    assert vecs["V08"]["expect"] == "ERR_CHUNK_AUTH_FAILED"
    v07 = vecs["V07"]
    cek = bytes.fromhex(v07["cek_hex"])
    stream = bytes.fromhex(v07["stream_hex"])
    cts = encrypt_chunks(cek, stream, v07["chunk_size"],
                         v07["content_root"], v07["transfer_id"])
    bad = bytearray(cts[0])
    bad[0] ^= 1
    with pytest.raises(AATPError) as ei:
        decrypt_one(cek, 0, 2, v07["content_root"], v07["transfer_id"], bytes(bad))
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
    with pytest.raises(AATPError) as ei:
        decrypt_one(cek, 1, 2, v07["content_root"], v07["transfer_id"], cts[0])
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_V09_negative_vector():
    from aatp.canon import parse_jcs
    from aatp.errors import AATPError
    vec = _load_vectors()["V09"]
    assert vec["expect"] == "ERR_MALFORMED_MESSAGE"
    with pytest.raises(AATPError) as ei:
        parse_jcs(vec["input"].encode("utf-8"))
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"


# --- (c) V05-STRUCTURE ----------------------------------------------------------

def test_V05_structure_present_and_labeled():
    from aatp.canon import jcs
    vec = _load_vectors().get("V05-STRUCTURE")
    assert vec is not None
    assert "implementation-generated" in vec["note"]
    assert "NOT a blueprint vector" in vec["note"]
    assert vec["node_id_grammar"] == "sha256:hex(SHA256(D_NODE + JCS(node)))"
    assert vec["D_NODE_ascii"] == "AATP/0.2/NODE\n"
    assert vec["required_fields"] == ["v", "content_root", "parents",
                                      "operation", "actor", "task_id", "created_at"]
    ids = vec["example_node_ids"]
    assert len(ids) == 3 and all(i.startswith("sha256:") for i in ids)
    assert len(set(ids)) == 3
    node1 = json.loads(bytes.fromhex(vec["example_node1_jcs_hex"]).decode("utf-8"))
    assert jcs(node1).hex() == vec["example_node1_jcs_hex"]
    exp_id = "sha256:" + hashlib.sha256(b"AATP/0.2/NODE\n" + jcs(node1)).hexdigest()
    assert exp_id == ids[0]


# --- (d) N01-N16 gate + N17/N18 via test_node.py --------------------------------
# Each test below runs its canonical implementation test. The canonical test
# name is mapped in the comment per the Task 9 binding decision.

def test_N01_altered_payload_rejected():
    # N01 -> tests/test_dsse.py::test_N01_tampered_payload_value
    from tests.test_dsse import test_N01_tampered_payload_value
    test_N01_tampered_payload_value()


def test_N02_float_rejected():
    # N02 -> tests/test_canon.py::test_V09_float_parse_rejected
    from tests.test_canon import test_V09_float_parse_rejected
    test_V09_float_parse_rejected()


def test_N03_noncanonical_payload_rejected():
    # N03 -> tests/test_dsse.py::test_SIG002_reject_noncanonical_payload
    from tests.test_dsse import test_SIG002_reject_noncanonical_payload
    test_SIG002_reject_noncanonical_payload()


def test_N04_recipient_mismatch(tmp_path):
    # N04 -> tests/test_transfer.py::test_MSG002_recipient_mismatch
    from tests.test_transfer import test_MSG002_recipient_mismatch
    test_MSG002_recipient_mismatch(tmp_path)


def test_N05_expired_message(tmp_path):
    # N05 -> tests/test_transfer.py::test_MSG003_expired_message
    from tests.test_transfer import test_MSG003_expired_message
    test_MSG003_expired_message(tmp_path)


def test_N06_replay_detected(tmp_path):
    # N06 -> tests/test_transfer.py::test_MSG004_replay_detected_persistent
    from tests.test_transfer import test_MSG004_replay_detected_persistent
    test_MSG004_replay_detected_persistent(tmp_path)


def test_N07_card_rollback(tmp_path):
    # N07 -> tests/test_card.py::test_ID011_card_rollback_rejected
    from tests.test_card import test_ID011_card_rollback_rejected
    test_ID011_card_rollback_rejected(tmp_path)


def test_N08_commitment_mismatch(tmp_path):
    # N08 -> tests/test_card.py::test_ID020_commitment_mismatch
    from tests.test_card import test_ID020_commitment_mismatch
    test_ID020_commitment_mismatch(tmp_path)


def test_N09_dotdot_path_rejected():
    # N09 -> tests/test_artifact.py::test_ART002_reject_dotdot
    from tests.test_artifact import test_ART002_reject_dotdot
    test_ART002_reject_dotdot()


def test_N10_casefold_collision_rejected():
    # N10 -> tests/test_artifact.py::test_ART004_reject_casefold_collision
    from tests.test_artifact import test_ART004_reject_casefold_collision
    test_ART004_reject_casefold_collision()


def test_N11_unsorted_manifest_rejected():
    # N11 -> tests/test_artifact.py::test_ART007_reject_unsorted_manifest
    from tests.test_artifact import test_ART007_reject_unsorted_manifest
    test_ART007_reject_unsorted_manifest()


def test_N12_digest_mismatch(tmp_path):
    # N12 -> tests/test_artifact.py::test_ART023_materialize_digest_mismatch
    from tests.test_artifact import test_ART023_materialize_digest_mismatch
    test_ART023_materialize_digest_mismatch(tmp_path)


def test_N13_flipped_ct_bit_rejected():
    # N13 -> tests/test_chunks.py::test_V08_tampered_chunk_rejected
    from tests.test_chunks import test_V08_tampered_chunk_rejected
    test_V08_tampered_chunk_rejected()


def test_N14_wrong_index_rejected():
    # N14 -> tests/test_chunks.py::test_V08_wrong_index_rejected
    from tests.test_chunks import test_V08_wrong_index_rejected
    test_V08_wrong_index_rejected()


def test_N15_wrong_transfer_rejected():
    # N15 -> tests/test_chunks.py::test_V08_wrong_transfer_rejected
    from tests.test_chunks import test_V08_wrong_transfer_rejected
    test_V08_wrong_transfer_rejected()


def test_N16_partial_complete_stays_receiving(tmp_path):
    # N16 -> tests/test_transfer.py::test_N16_partial_complete_stays_receiving
    from tests.test_transfer import test_N16_partial_complete_stays_receiving
    test_N16_partial_complete_stays_receiving(tmp_path)


def test_N17_revert_accepted():
    # N17 (revert accepted, not a cycle) -> tests/test_node.py::test_PRV004_revert_is_not_a_cycle
    from tests.test_node import test_PRV004_revert_is_not_a_cycle
    test_PRV004_revert_is_not_a_cycle()


def test_N18_own_ancestor_cycle():
    # N18 -> tests/test_node.py::test_PRV003_self_ancestor_rejected
    from tests.test_node import test_PRV003_self_ancestor_rejected
    test_PRV003_self_ancestor_rejected()
