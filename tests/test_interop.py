"""M8-4 TS->Python interop: consume the TS-written fixture (TEST-ONLY keys)."""
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aatp.b64 import b64u_dec
from aatp.chunks import decrypt_one
from aatp.dsse import PT_NODE, verify_envelope
from aatp.node import DagStore, node_id_of

FIXTURE = Path(__file__).parent / "testdata-ts" / "ts_interop.json"


def _load():
    fx = json.loads(FIXTURE.read_bytes())
    assert fx["_test_only_keys"] is True
    return fx


def test_TS001_x25519_pub_agrees_with_ts():
    fx = _load()
    sk = X25519PrivateKey.from_private_bytes(bytes.fromhex(fx["ts_recipient_enc_priv_hex"]))
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert pub.hex() == fx["ts_recipient_enc_pub_hex"]


def test_TS002_open_ts_packet_verify_node_unwrap_decrypt():
    from aatp.seal import KeyStore, open_packet, unwrap_cek
    fx = _load()
    kid = fx["ts_recipient_enc_key_id"]
    ks = KeyStore({kid: bytes.fromhex(fx["ts_recipient_enc_priv_hex"])})
    actor_pub = bytes.fromhex(fx["ts_actor_pub_hex"])

    envelope = open_packet(fx["ts_packet"], ks)
    assert envelope == fx["ts_node_envelope"]
    node = verify_envelope(envelope, PT_NODE, actor_pub)
    assert node_id_of(node) == fx["node_id"]

    # Python accepts the TS node envelope into a DAG (lazy: unknown parents ok).
    store = DagStore()
    assert store.add(fx["ts_node_envelope"], lambda a: actor_pub) == fx["node_id"]

    # CEK arrives only via HPKE wrap, never in clear in the fixture.
    assert "cek_hex" not in fx and "ts_cek_hex" not in fx
    cek = unwrap_cek(fx["ts_wrap_entry"], fx["content_root"],
                     fx["ts_actor_id"], fx["transfer_id"], ks)
    parts = []
    for c in fx["ts_chunks"]:
        ct = b64u_dec(c["data_b64"])
        parts.append(decrypt_one(cek, c["index"], len(fx["ts_chunks"]),
                                 fx["content_root"], fx["transfer_id"], ct))
    assert b"".join(parts).hex() == fx["stream_hex"]
