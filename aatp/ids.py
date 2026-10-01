"""ID-001: self-certifying agent_id (blueprint §4.1)."""
import base64
import hashlib

from aatp.errors import err

D_AGENT = b"AATP/0.2/AGENT-ID\n"


def derive_agent_id(genesis_public_key_raw32: bytes) -> str:
    if not isinstance(genesis_public_key_raw32, bytes) or len(genesis_public_key_raw32) != 32:
        raise err("ERR_MALFORMED_MESSAGE", "genesis public key must be 32 bytes")
    h = hashlib.sha256(D_AGENT + genesis_public_key_raw32).digest()
    return "aatp:" + base64.b32encode(h).decode("ascii").lower().rstrip("=")
