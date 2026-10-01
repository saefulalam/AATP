"""M7-2 in-memory relay: store-and-forward mailbox + chunk/card store.

The relay NEVER opens sealed packets (opaque store, NET-001/002).
Pure in-memory, no I/O. Thread-safe for ThreadingHTTPServer use.
"""
import copy
import hashlib
import re
import threading

from aatp.b64 import b64u_dec
from aatp.canon import jcs
from aatp.errors import AATPError, err

PACKET_KEYS = frozenset({"aatp", "to", "to_key_id", "enc", "ct"})

DEFAULT_MAX_STORED_PACKETS = 10000
DEFAULT_MAX_CHUNK_BYTES = 16777216 + 16

_TX_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def _malformed(detail: str) -> AATPError:
    return err("ERR_MALFORMED_MESSAGE", detail)


class Relay:
    """Opaque packet mailbox keyed by ``to`` plus chunk and card stores."""

    def __init__(self, *, max_stored_packets: int = DEFAULT_MAX_STORED_PACKETS,
                 max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES):
        if (not isinstance(max_stored_packets, int) or isinstance(max_stored_packets, bool)
                or max_stored_packets < 0):
            raise _malformed("max_stored_packets must be an integer >= 0")
        if (not isinstance(max_chunk_bytes, int) or isinstance(max_chunk_bytes, bool)
                or max_chunk_bytes < 0):
            raise _malformed("max_chunk_bytes must be an integer >= 0")
        self._max_stored = max_stored_packets
        self._max_chunk = max_chunk_bytes
        self._lock = threading.Lock()
        self._mailbox: dict[str, list[dict]] = {}
        self._by_id: dict[str, dict] = {}
        self._chunks: dict[tuple[str, int], str] = {}
        self._cards: dict[str, dict] = {}

    def put_packet(self, packet: dict) -> str:
        if not isinstance(packet, dict):
            raise _malformed("packet must be an object")
        if set(packet.keys()) != PACKET_KEYS:
            raise _malformed("packet must have exactly {aatp,to,to_key_id,enc,ct}")
        if packet.get("aatp") != "0.2":
            raise _malformed("unsupported packet version")
        if not isinstance(packet.get("to"), str):
            raise _malformed("packet to must be a string")
        try:
            raw = jcs(packet)
        except AATPError:
            raise
        except Exception:
            raise _malformed("packet not canonical") from None
        if len(raw) > self._max_chunk:
            raise err("ERR_SIZE_LIMIT", "packet exceeds size limit")
        pid = hashlib.sha256(raw).hexdigest()
        with self._lock:
            if pid in self._by_id:
                return pid
            if len(self._by_id) >= self._max_stored:
                raise err("ERR_RATE_LIMIT", "mailbox full")
            stored = dict(packet)
            self._by_id[pid] = stored
            self._mailbox.setdefault(packet["to"], []).append(stored)
            return pid

    def take_packets(self, agent_id: str) -> list[dict]:
        with self._lock:
            lst = self._mailbox.pop(agent_id, [])
            for p in lst:
                try:
                    pid = hashlib.sha256(jcs(p)).hexdigest()
                except AATPError:
                    continue
                self._by_id.pop(pid, None)
            return [dict(p) for p in lst]

    def put_chunk(self, transfer_id: str, index: int, data_b64: str) -> None:
        if not isinstance(transfer_id, str) or not _TX_RE.match(transfer_id):
            raise _malformed("transfer_id must match [A-Za-z0-9_.:-]{1,128}")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise _malformed("chunk index must be an integer >= 0")
        if not isinstance(data_b64, str):
            raise _malformed("chunk data must be a base64url string")
        try:
            raw = b64u_dec(data_b64)
        except AATPError:
            raise
        except Exception:
            raise _malformed("chunk data not valid base64url") from None
        if len(raw) > self._max_chunk:
            raise err("ERR_SIZE_LIMIT", "chunk exceeds size limit")
        with self._lock:
            self._chunks[(transfer_id, index)] = data_b64

    def get_chunk(self, transfer_id: str, index: int) -> str | None:
        with self._lock:
            return self._chunks.get((transfer_id, index))

    def put_card(self, agent_id: str, card_env: dict) -> None:
        if not isinstance(agent_id, str):
            raise _malformed("agent_id must be a string")
        if not isinstance(card_env, dict):
            raise _malformed("card envelope must be an object")
        if "payloadType" not in card_env or "signatures" not in card_env:
            raise _malformed("card envelope needs payloadType and signatures")
        with self._lock:
            self._cards[agent_id] = copy.deepcopy(card_env)

    def get_card(self, agent_id: str) -> dict | None:
        with self._lock:
            found = self._cards.get(agent_id)
            return copy.deepcopy(found) if found is not None else None
