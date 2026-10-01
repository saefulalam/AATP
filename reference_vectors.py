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


def jcs_minimal(obj) -> bytes:
    # Independent of aatp.canon so the vector is not derived from the code under test.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def main():
    v01_input = {"b": 2, "a": 1}
    VECTORS["V01"] = {"input": v01_input, "jcs_hex": jcs_minimal(v01_input).hex()}
    assert VECTORS["V01"]["jcs_hex"] == "7b2261223a312c2262223a327d"  # blueprint App. C
    VECTORS["V09"] = {"input": '{"a":1.5}', "expect": "ERR_MALFORMED_MESSAGE"}
    VECTORS["V02"] = {"sha256_hello": sha256_hex(b"hello"), "b64url_hello": b64u(b"hello")}
    v03_pub = bytes.fromhex("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
    v03_agent = "aatp:" + base64.b32encode(
        hashlib.sha256(b"AATP/0.2/AGENT-ID\n" + v03_pub).digest()).decode().lower().rstrip("=")
    assert v03_agent == "aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma"  # blueprint App. C
    VECTORS["V03"] = {"genesis_pub_hex": v03_pub.hex(), "agent_id": v03_agent}
    # write_bytes: avoid platform newline translation (vectors must be byte-exact).
    OUT.write_bytes(json.dumps(VECTORS, indent=2, sort_keys=True).encode("utf-8"))


if __name__ == "__main__":
    main()
