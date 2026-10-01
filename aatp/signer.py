"""SIG-001: the Signer holds the private key; callers only get signatures."""
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aatp.dsse import pae


class Signer(Protocol):
    def sign(self, payload_type: str, payload: bytes) -> bytes: ...
    def key_id(self) -> str: ...
    def public_key_raw(self) -> bytes: ...


class SoftwareSigner:
    """In-process Ed25519 signer. The private key is never returned or rendered."""

    __slots__ = ("_sk", "_key_id")

    def __init__(self, sk: Ed25519PrivateKey, key_id: str):
        self._sk = sk
        self._key_id = key_id

    @classmethod
    def from_seed(cls, seed32: bytes, key_id: str) -> "SoftwareSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(seed32), key_id)

    @classmethod
    def generate(cls, key_id: str) -> "SoftwareSigner":
        # CRY-006: OpenSSL draws from the OS CSPRNG.
        return cls(Ed25519PrivateKey.generate(), key_id)

    def key_id(self) -> str:
        return self._key_id

    def public_key_raw(self) -> bytes:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, payload_type: str, payload: bytes) -> bytes:
        # CRY-002: sign the PAE bytes directly, no pre-hash.
        return self._sk.sign(pae(payload_type, payload))

    def __repr__(self) -> str:
        return f"SoftwareSigner(key_id={self._key_id!r})"

    __str__ = __repr__
