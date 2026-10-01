"""Generates tests/vectors/aatp_v0_2_vectors.json. Source of truth = blueprint rules."""
import base64
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).parent / "tests" / "vectors" / "aatp_v0_2_vectors.json"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


VECTORS = {}


def main():
    VECTORS["V02"] = {"sha256_hello": sha256_hex(b"hello"), "b64url_hello": b64u(b"hello")}
    OUT.write_text(json.dumps(VECTORS, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
