"""Generate the Python->TypeScript interop fixture (M8-4, run once).

Output (committed): ts/testdata/offer.json

TEST-ONLY throwaway keys (fixed seeds, never production keys; see
DECISIONS.md D-042): actor Ed25519 seed 0x11*32 (== V03 vector key),
recipient signing seed 0x22*32 (id only), recipient X25519 priv 0x44*32
(exported so TS can open/unwrap). The CEK is NEVER exported in clear;
TS recovers it via the HPKE wrap entry.

Run: .venv\\Scripts\\python tests/export_interop_fixtures.py
"""
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aatp.b64 import b64u
from aatp.chunks import encrypt_chunks
from aatp.dsse import PT_NODE
from aatp.ids import derive_agent_id
from aatp.node import make_node, make_node_envelope, node_id_of
from aatp.seal import KeyStore, open_packet, seal_packet, unwrap_cek, wrap_cek
from aatp.signer import SoftwareSigner

ROOT = Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "tests" / "vectors" / "aatp_v0_2_vectors.json").read_text())
OUT = ROOT / "ts" / "testdata" / "offer.json"

ACTOR_SEED = bytes([0x11]) * 32  # == V03 vector key (TEST-ONLY)
RECIP_SIGN_SEED = bytes([0x22]) * 32  # recipient agent id only (TEST-ONLY)
RECIP_ENC_PRIV = bytes([0x44]) * 32  # exported TEST-ONLY so TS can open
ENC_KEY_ID = "rk-test-py-1"
TRANSFER_ID = "tx_demo1"
CHUNK_SIZE = 8
TASK_ID = "task_interop_py"
CREATED_AT = "2026-10-01T00:00:00Z"


def main() -> None:
    v07 = VECTORS["V07"]
    content_root = v07["content_root"]
    stream = bytes.fromhex(v07["stream_hex"])
    cek = bytes.fromhex(v07["cek_hex"])  # V07 CEK 00..1f; never written to fixture

    actor = SoftwareSigner.from_seed(ACTOR_SEED, key_id="k-interop-py")
    actor_id = derive_agent_id(actor.public_key_raw())
    assert actor_id == VECTORS["V03"]["agent_id"], "actor must be the V03 id"
    recip_sign = SoftwareSigner.from_seed(RECIP_SIGN_SEED, key_id="k-recip")
    recipient_id = derive_agent_id(recip_sign.public_key_raw())
    enc_sk = X25519PrivateKey.from_private_bytes(RECIP_ENC_PRIV)
    enc_pub = enc_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    node, node_id = make_node(content_root, [], "create", actor_id,
                              TASK_ID, None, CREATED_AT)
    assert node_id_of(node) == node_id
    envelope = make_node_envelope(node, actor)

    packet = seal_packet(recipient_id, ENC_KEY_ID, enc_pub, envelope)
    cts = encrypt_chunks(cek, stream, CHUNK_SIZE, content_root, TRANSFER_ID)
    assert [c.hex() for c in cts] == [c["ct_hex"] for c in v07["chunks"]], \
        "fixture chunks must equal V07 vectors"
    wrap = wrap_cek(cek, content_root, actor_id, recipient_id,
                    ENC_KEY_ID, TRANSFER_ID, enc_pub)

    # Self-check with Python before committing the fixture.
    ks = KeyStore({ENC_KEY_ID: RECIP_ENC_PRIV})
    assert open_packet(packet, ks) == envelope
    assert unwrap_cek(wrap, content_root, actor_id, TRANSFER_ID, ks) == cek

    fixture = {
        "_test_only_keys": True,
        "note": ("TEST-ONLY throwaway keys. Never production keys. "
                 "See DECISIONS.md D-042."),
        "actor_id": actor_id,
        "actor_pub_hex": actor.public_key_raw().hex(),
        "recipient_agent_id": recipient_id,
        "recipient_enc_key_id": ENC_KEY_ID,
        "recipient_enc_priv_hex": RECIP_ENC_PRIV.hex(),
        "recipient_enc_pub_hex": enc_pub.hex(),
        "content_root": content_root,
        "transfer_id": TRANSFER_ID,
        "chunk_size": CHUNK_SIZE,
        "stream_hex": stream.hex(),
        "node_id": node_id,
        "payload_type": PT_NODE,
        "offer_packet": packet,
        "node_envelope": envelope,
        "wrap_entry": wrap,
        "chunks": [{"index": i, "data_b64": b64u(c)} for i, c in enumerate(cts)],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes((json.dumps(fixture, indent=2) + "\n").encode("utf-8"))
    print(f"wrote {OUT} node_id={node_id}")


if __name__ == "__main__":
    sys.exit(main())
