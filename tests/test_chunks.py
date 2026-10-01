"""M4 chunk AEAD (blueprint section 9.1, ENC-001..007).

V07/V08 are blueprint vectors (App. C): CEK=bytes(range(32)),
chunk_size 8, transfer_id tx_demo1, content_root CR1 from V04,
stream hex 6563686f2068690a68656c6c6f (13 bytes -> 2 chunks).
"""
import pytest

from aatp.chunks import aad, decrypt_one, encrypt_chunks, manifest_nonce, nonce
from aatp.errors import AATPError

CEK = bytes(range(32))  # 00..1f
CR1 = "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf"
STREAM = bytes.fromhex("6563686f2068690a68656c6c6f")  # 13 bytes
TX = "tx_demo1"


def test_V07_chunk_encryption():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    assert len(cts) == 2
    assert nonce(0).hex() == "000000000000000000000000"
    assert nonce(1).hex() == "000000000000000000000001"
    assert cts[0].hex() == "7ddb2a5e8d8ecfdbdf23f165585271f9598a9ddaad072de1"
    assert cts[1].hex() == "013910b55eca493016312b9e709d27d9800b9cfe25"


def test_V07_decrypt_roundtrip():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    assert decrypt_one(CEK, 0, 2, CR1, TX, cts[0]) == STREAM[:8]
    assert decrypt_one(CEK, 1, 2, CR1, TX, cts[1]) == STREAM[8:]


def test_V08_tampered_chunk_rejected():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    bad = bytearray(cts[0])
    bad[0] ^= 1
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 0, 2, CR1, TX, bytes(bad))
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_V08_wrong_index_rejected():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 1, 2, CR1, TX, cts[0])
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_V08_wrong_transfer_rejected():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 0, 2, CR1, "tx_other", cts[0])
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_V08_wrong_content_root_rejected():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    other = "sha256:" + "0" * 64
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 0, 2, other, TX, cts[0])
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_ENC002_deterministic_resend():
    first = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    second = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    assert first == second


def test_ENC003_nonce_format():
    assert nonce(0) == b"\x00" * 12
    assert nonce(1) == b"\x00" * 4 + (1).to_bytes(8, "big")
    assert manifest_nonce() == b"\xff" * 12


def test_ENC004_aad_binds_position():
    assert aad(CR1, 0, 2, TX) != aad(CR1, 1, 2, TX)
    assert aad(CR1, 0, 2, TX) != aad(CR1, 0, 2, "tx_other")


def test_ENC006_index_ge_2_63_rejected():
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 2**63, 2**63 + 1, CR1, TX, b"x")
    assert ei.value.code == "ERR_SEQUENCE_INVALID"


def test_ENC006_encrypt_rejects_huge_chunk_count():
    with pytest.raises(AATPError) as ei:
        nonce(2**63)
    assert ei.value.code == "ERR_SEQUENCE_INVALID"


def test_decrypt_garbage_short_ct_fail_closed():
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 0, 2, CR1, TX, b"\x00" * 10)
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_decrypt_non_tag_failure_mapped():
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)

    def _boom(*args, **kwargs):
        raise ValueError("simulated backend failure")

    import aatp.chunks as chunks_mod

    orig = chunks_mod.ChaCha20Poly1305
    try:
        chunks_mod.ChaCha20Poly1305 = lambda *a, **k: type(
            "B", (), {"decrypt": _boom, "encrypt": orig(*a, **k).encrypt}
        )()
        with pytest.raises(AATPError) as ei:
            decrypt_one(CEK, 0, 2, CR1, TX, cts[0])
        assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
    finally:
        chunks_mod.ChaCha20Poly1305 = orig


def test_non_str_content_root_rejected():
    with pytest.raises(AATPError) as ei:
        aad(123, 0, 2, TX)
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
    with pytest.raises(AATPError) as ei:
        encrypt_chunks(CEK, STREAM, 8, 123, TX)
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 0, 2, 123, TX, cts[0])
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"


def test_none_transfer_id_rejected():
    with pytest.raises(AATPError) as ei:
        aad(CR1, 0, 2, None)
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
    with pytest.raises(AATPError) as ei:
        encrypt_chunks(CEK, STREAM, 8, CR1, None)
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
    cts = encrypt_chunks(CEK, STREAM, 8, CR1, TX)
    with pytest.raises(AATPError) as ei:
        decrypt_one(CEK, 0, 2, CR1, None, cts[0])
    assert ei.value.code == "ERR_CHUNK_AUTH_FAILED"
