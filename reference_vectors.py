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
    # V04 content_root (independent of aatp.artifact; blueprint App. C).
    d_run = sha256_hex(b"echo hi\n")
    d_hello = sha256_hex(b"hello")
    assert d_hello == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert d_run == "ab08508fdf5ca4da5c4995987bc41c56c048aaa5eeb046417ae4049b7d40286e"
    v04_manifest = {"v": "0.2", "entries": [
        {"path": "bin/run.sh", "size": 8, "x": True, "d": "sha256:" + d_run},
        {"path": "hello.txt", "size": 5, "x": False, "d": "sha256:" + d_hello},
    ]}
    v04_jcs = jcs_minimal(v04_manifest)
    assert v04_jcs.decode("ascii") == (
        '{"entries":[{"d":"sha256:ab08508fdf5ca4da5c4995987bc41c56c048aaa5eeb046417ae4049b7d40286e",'
        '"path":"bin/run.sh","size":8,"x":true},'
        '{"d":"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",'
        '"path":"hello.txt","size":5,"x":false}],"v":"0.2"}'
    )
    v04_stream = b"echo hi\n" + b"hello"
    assert v04_stream.hex() == "6563686f2068690a68656c6c6f"
    v04_cr = "sha256:" + sha256_hex(b"AATP/0.2/CONTENT\n" + v04_jcs)
    assert v04_cr == "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf"
    VECTORS["V04"] = {"manifest_jcs_hex": v04_jcs.hex(),
                      "stream_hex": v04_stream.hex(), "content_root": v04_cr}
    # V05-STRUCTURE (implementation-generated example, NOT a blueprint vector).
    # Blueprint V05/V06 expected hashes are UNVERIFIABLE (vectors file absent,
    # node1 inputs under-specified per D-019/D-020); no 1f3ce1/96f802/cc88b1 or
    # V06 signature string is asserted anywhere. Mechanism grammar is normative
    # (blueprint section 7): node_id = sha256:hex(SHA256(D_NODE + JCS(node))).
    d_node = b"AATP/0.2/NODE\n"
    ex_actor = "aatp:" + "2" * 52  # synthetic local actor, clearly not V03
    ex_cr1 = v04_cr
    ex_cr2 = "sha256:316dcfe880067987f2d83df8c040db75612d521f7df41ffe37a1847bed253bec"
    ex_n1 = {"v": "0.2", "content_root": ex_cr1, "parents": [],
             "operation": "create", "actor": ex_actor,
             "task_id": "task_local_m3_001",
             "created_at": "2026-10-01T00:00:00Z"}
    ex_id1 = "sha256:" + sha256_hex(d_node + jcs_minimal(ex_n1))
    ex_n2 = {"v": "0.2", "content_root": ex_cr2, "parents": [ex_id1],
             "operation": "modify", "actor": ex_actor,
             "task_id": "task_local_m3_001",
             "created_at": "2026-10-01T00:01:00Z"}
    ex_id2 = "sha256:" + sha256_hex(d_node + jcs_minimal(ex_n2))
    ex_n3 = {"v": "0.2", "content_root": ex_cr1, "parents": [ex_id2],
             "operation": "revert", "actor": ex_actor,
             "task_id": "task_local_m3_001",
             "created_at": "2026-10-01T00:02:00Z"}
    ex_id3 = "sha256:" + sha256_hex(d_node + jcs_minimal(ex_n3))
    assert ex_id3 != ex_id1  # revert: same content_root, distinct node_id
    VECTORS["V05-STRUCTURE"] = {
        "note": ("implementation-generated example, NOT a blueprint vector; "
                 "blueprint V05/V06 hashes UNVERIFIABLE per D-020"),
        "node_id_grammar": "sha256:hex(SHA256(D_NODE + JCS(node)))",
        "D_NODE_ascii": "AATP/0.2/NODE\n",
        "required_fields": ["v", "content_root", "parents", "operation",
                            "actor", "task_id", "created_at"],
        "arity": {"create": 0, "merge": ">=2",
                  "modify/revert/supersede/verify": ">=1"},
        "example_actor": ex_actor,
        "example_node1_jcs_hex": jcs_minimal(ex_n1).hex(),
        "example_node_ids": [ex_id1, ex_id2, ex_id3],
    }
    # write_bytes: avoid platform newline translation (vectors must be byte-exact).
    OUT.write_bytes(json.dumps(VECTORS, indent=2, sort_keys=True).encode("utf-8") + b"\n")


if __name__ == "__main__":
    main()
