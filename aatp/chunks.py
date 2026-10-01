"""M4 chunk AEAD (blueprint section 9.1, ENC-001..007)."""
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from aatp.canon import jcs
from aatp.errors import err

D_CHUNK = b"AATP/0.2/CHUNK\n"

_SEQ_LIMIT = 2**63


def _sequence_invalid(detail: str):
    return err("ERR_SEQUENCE_INVALID", detail)


def _auth_failed(detail: str):
    return err("ERR_CHUNK_AUTH_FAILED", detail)


def _check_index(i: int) -> None:
    if not isinstance(i, int) or isinstance(i, bool):
        raise _sequence_invalid("index must be an integer")
    if i < 0 or i >= _SEQ_LIMIT:
        raise _sequence_invalid("index >= 2^63")


def _check_cek(cek: bytes) -> None:
    if not isinstance(cek, (bytes, bytearray)) or len(cek) != 32:
        raise _auth_failed("CEK must be 32 bytes")


def nonce(i: int) -> bytes:
    """nonce(i) = 0x00000000 || uint64_be(i); reject i >= 2^63 (ENC-006)."""
    _check_index(i)
    return b"\x00" * 4 + i.to_bytes(8, "big")


def manifest_nonce() -> bytes:
    """Reserved manifest nonce, disjoint from all chunk nonces (ENC-006)."""
    return b"\xff" * 12


def aad(content_root: str, i: int, total: int, transfer_id: str) -> bytes:
    """AAD(i) = D_CHUNK || JCS({"cr","i","n","t"}) (ENC-004)."""
    _check_index(i)
    if not isinstance(total, int) or isinstance(total, bool):
        raise _sequence_invalid("total must be an integer")
    if total <= 0 or total > _SEQ_LIMIT:
        raise _sequence_invalid("total out of range")
    if i >= total:
        raise _sequence_invalid("index >= total")
    return D_CHUNK + jcs({"cr": content_root, "i": i, "n": total, "t": transfer_id})


def encrypt_chunks(
    cek: bytes, stream: bytes, chunk_size: int, content_root: str, transfer_id: str
) -> list[bytes]:
    """Split stream into chunk_size pieces and seal each (ENC-001..005)."""
    _check_cek(cek)
    if not isinstance(stream, (bytes, bytearray)):
        raise _auth_failed("stream must be bytes")
    stream = bytes(stream)
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise _sequence_invalid("chunk_size must be a positive integer")
    total = (len(stream) + chunk_size - 1) // chunk_size if stream else 0
    if total > _SEQ_LIMIT:
        raise _sequence_invalid("chunk count >= 2^63")
    aead = ChaCha20Poly1305(bytes(cek))
    out: list[bytes] = []
    for i in range(total):
        pt = stream[i * chunk_size:(i + 1) * chunk_size]
        out.append(aead.encrypt(nonce(i), pt, aad(content_root, i, total, transfer_id)))
    return out


def decrypt_one(
    cek: bytes, index: int, total: int, content_root: str, transfer_id: str, ct: bytes
) -> bytes:
    """Open one chunk; AEAD failure -> ERR_CHUNK_AUTH_FAILED, never ack (ENC-007)."""
    _check_cek(cek)
    _check_index(index)
    if not isinstance(total, int) or isinstance(total, bool):
        raise _sequence_invalid("total must be an integer")
    if total <= 0 or total > _SEQ_LIMIT:
        raise _sequence_invalid("total out of range")
    if index >= total:
        raise _sequence_invalid("index >= total")
    if not isinstance(ct, (bytes, bytearray)):
        raise _auth_failed("ciphertext must be bytes")
    aead = ChaCha20Poly1305(bytes(cek))
    try:
        return aead.decrypt(nonce(index), bytes(ct), aad(content_root, index, total, transfer_id))
    except InvalidTag:
        raise _auth_failed("chunk authentication failed") from None
