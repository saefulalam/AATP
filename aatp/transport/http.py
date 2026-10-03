"""M7-2 reference HTTP transport (blueprint section 13, stdlib only).

Routes exactly:
  POST /aatp/v0.2/packets -> 202 {id} (idempotent by content hash)
  PUT /aatp/v0.2/transfers/{tx}/chunks/{i} -> 204 (idempotent)
  GET /aatp/v0.2/transfers/{tx}/chunks/{i} -> 200 octet-stream / 404
  PUT /aatp/v0.2/agents/{agent_id}/card -> 204 (self-signed card publish)
  GET /aatp/v0.2/agents/{agent_id}/card -> 200 card / 404 ERR_ARTIFACT_NOT_FOUND
  GET /aatp/v0.2/mailbox/{agent_id} -> 200 [packets] + drain (DSSE auth)
"""
import json
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_CARD, PT_MESSAGE, verify_envelope
from aatp.errors import AATPError, err
from aatp.messages import parse_ts

_PACKETS_PATH = "/aatp/v0.2/packets"
_TRANSFERS_RE = re.compile(r"^/aatp/v0\.2/transfers/([^/]+)/chunks/([^/]+)$")
_AGENTS_PREFIX = "/aatp/v0.2/agents/"
_MAILBOX_PREFIX = "/aatp/v0.2/mailbox/"
_TX_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_INDEX_RE = re.compile(r"^[0-9]+$")

AUTH_SKEW_SECONDS = 120


def _err_body(code: str, detail: str | None = None) -> dict:
    body: dict = {"code": code}
    if detail is not None:
        body["detail"] = detail
    return body


def serve(relay, *, host: str = "127.0.0.1", port: int = 0,
          card_resolver=None) -> ThreadingHTTPServer:
    relay_ref = relay
    resolver_ref = card_resolver

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _path_only(self) -> str:
            return urlsplit(self.path).path

        def _send_json(self, status: int, obj) -> None:
            try:
                raw = jcs(obj)
            except AATPError:
                raw = json.dumps(obj, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send_bytes(self, status: int, raw: bytes,
                        content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _agent_card_path(self) -> str | None:
            path = self._path_only()
            if not (path.startswith(_AGENTS_PREFIX)
                    and path.endswith("/card")):
                return None
            middle = path[len(_AGENTS_PREFIX):-len("/card")]
            if not middle or "/" in middle:
                return None
            return unquote(middle)

        def _read_body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _relay_error(self, e: AATPError) -> None:
            if e.code == "ERR_SIZE_LIMIT":
                self._send_json(413, _err_body(e.code, e.detail))
            elif e.code == "ERR_RATE_LIMIT":
                self._send_json(429, _err_body(e.code, e.detail))
            else:
                self._send_json(400, _err_body(e.code, e.detail))

        # -- POST /packets ------------------------------------------
        def do_POST(self):
            if self._path_only() != _PACKETS_PATH:
                self._send_json(404, _err_body("ERR_MALFORMED_MESSAGE", "not found"))
                return
            raw = self._read_body()
            try:
                text = raw.decode("utf-8")
                obj = json.loads(text) if text else None
            except (UnicodeDecodeError, ValueError):
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE", "bad JSON"))
                return
            try:
                pid = relay_ref.put_packet(obj)
            except AATPError as e:
                self._relay_error(e)
                return
            except Exception:
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE", "bad packet"))
                return
            self._send_json(202, {"id": pid})

        # -- PUT /transfers/{tx}/chunks/{i}  +  PUT .../agents/{id}/card
        def do_PUT(self):
            aid = self._agent_card_path()
            if aid is not None:
                self._handle_put_card(aid)
                return
            m = _TRANSFERS_RE.match(self._path_only())
            if not m:
                self._send_json(404, _err_body("ERR_MALFORMED_MESSAGE", "not found"))
                return
            tx = unquote(m.group(1))
            i_str = unquote(m.group(2))
            if not _TX_RE.match(tx):
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE", "bad transfer_id"))
                return
            if not _INDEX_RE.match(i_str):
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE", "bad chunk index"))
                return
            index = int(i_str)
            raw = self._read_body()
            try:
                relay_ref.put_chunk(tx, index, b64u(raw))
            except AATPError as e:
                self._relay_error(e)
                return
            except Exception:
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE", "bad chunk"))
                return
            self._send_empty(204)

        def _handle_put_card(self, aid: str) -> None:
            raw = self._read_body()
            try:
                text = raw.decode("utf-8")
                env = json.loads(text) if text else None
            except (UnicodeDecodeError, ValueError):
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                               "bad JSON"))
                return
            if not isinstance(env, dict):
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                               "bad card envelope"))
                return
            try:
                card = parse_jcs(b64u_dec(env["payload"]))
            except AATPError as e:
                self._send_json(400, _err_body(e.code, e.detail))
                return
            except Exception:
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                               "bad card payload"))
                return
            if not isinstance(card, dict) or card.get("agent_id") != aid:
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                               "card agent_id != path"))
                return
            try:
                pub_raw = b64u_dec(card["signing_key"]["public_key"])
                if not isinstance(pub_raw, bytes) or len(pub_raw) != 32:
                    raise err("ERR_MALFORMED_MESSAGE", "bad signing key")
                verify_envelope(env, PT_CARD, pub_raw)
            except AATPError as e:
                self._send_json(400, _err_body(e.code, e.detail))
                return
            except Exception:
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                               "bad card"))
                return
            try:
                relay_ref.put_card(aid, env)
            except AATPError as e:
                self._relay_error(e)
                return
            except Exception:
                self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                               "bad card"))
                return
            self._send_empty(204)

        # -- GET card / mailbox / chunk -------------------------------
        def do_GET(self):
            path = self._path_only()
            if path.startswith(_AGENTS_PREFIX) and path.endswith("/card"):
                middle = path[len(_AGENTS_PREFIX):-len("/card")]
                if not middle or "/" in middle:
                    self._send_json(404, _err_body("ERR_MALFORMED_MESSAGE", "not found"))
                    return
                aid = unquote(middle)
                card = relay_ref.get_card(aid)
                if card is None:
                    self._send_json(404, _err_body("ERR_ARTIFACT_NOT_FOUND",
                                                  "card not found"))
                    return
                self._send_json(200, card)
                return
            if path.startswith(_MAILBOX_PREFIX):
                aid_enc = path[len(_MAILBOX_PREFIX):]
                if not aid_enc or "/" in aid_enc:
                    self._send_json(404, _err_body("ERR_MALFORMED_MESSAGE", "not found"))
                    return
                aid = unquote(aid_enc)
                self._handle_mailbox(aid, path)
                return
            m = _TRANSFERS_RE.match(path)
            if m:
                tx = unquote(m.group(1))
                i_str = unquote(m.group(2))
                if not _TX_RE.match(tx):
                    self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                                   "bad transfer_id"))
                    return
                if not _INDEX_RE.match(i_str):
                    self._send_json(400, _err_body("ERR_MALFORMED_MESSAGE",
                                                   "bad chunk index"))
                    return
                data_b64 = relay_ref.get_chunk(tx, int(i_str))
                if data_b64 is None:
                    self._send_json(404, _err_body("ERR_TRANSFER_NOT_FOUND",
                                                   "chunk not found"))
                    return
                try:
                    raw = b64u_dec(data_b64)
                except AATPError as e:
                    self._send_json(404, _err_body(e.code, e.detail))
                    return
                except Exception:
                    self._send_json(404, _err_body("ERR_TRANSFER_NOT_FOUND",
                                                   "chunk not found"))
                    return
                self._send_bytes(200, raw, "application/octet-stream")
                return
            self._send_json(404, _err_body("ERR_MALFORMED_MESSAGE", "not found"))

        def _handle_mailbox(self, aid: str, path: str) -> None:
            auth = self.headers.get("Authorization")
            if not auth or not auth.startswith("DSSE "):
                self._send_json(401, _err_body("ERR_AUTH_REQUIRED", "missing auth"))
                return
            token = auth[len("DSSE "):].strip()
            try:
                env_raw = b64u_dec(token)
                env = parse_jcs(env_raw)
            except AATPError as e:
                self._send_json(401, _err_body(e.code, e.detail))
                return
            except Exception:
                self._send_json(401, _err_body("ERR_AUTH_REQUIRED", "bad auth"))
                return
            if not isinstance(env, dict):
                self._send_json(401, _err_body("ERR_AUTH_FAILED", "bad envelope"))
                return
            try:
                payload_b64 = env.get("payload")
                if not isinstance(payload_b64, str):
                    raise err("ERR_AUTH_FAILED", "bad payload")
                payload = parse_jcs(b64u_dec(payload_b64))
            except AATPError as e:
                self._send_json(401, _err_body(e.code, e.detail))
                return
            except Exception:
                self._send_json(401, _err_body("ERR_AUTH_FAILED", "bad payload"))
                return
            if not isinstance(payload, dict):
                self._send_json(401, _err_body("ERR_AUTH_FAILED", "bad payload"))
                return
            method = payload.get("method")
            ppath = payload.get("path")
            created = payload.get("created_at")
            envelope_aid = payload.get("agent_id")
            if (method != "GET" or ppath != path
                    or not isinstance(created, str)
                    or not isinstance(envelope_aid, str)):
                self._send_json(401, _err_body("ERR_AUTH_FAILED", "bad request binding"))
                return
            try:
                if resolver_ref is None:
                    raise KeyError("no resolver")
                card = resolver_ref(envelope_aid)
                if card is None:
                    raise KeyError("unknown agent")
                if isinstance(card, dict) and "payload" in card and "payloadType" in card:
                    card_dict = parse_jcs(b64u_dec(card["payload"]))
                else:
                    card_dict = card
                pub_raw = b64u_dec(card_dict["signing_key"]["public_key"])
                if not isinstance(pub_raw, bytes) or len(pub_raw) != 32:
                    raise ValueError("bad key")
            except AATPError as e:
                self._send_json(401, _err_body(e.code, e.detail))
                return
            except Exception:
                self._send_json(401, _err_body("ERR_AUTH_FAILED", "unknown agent"))
                return
            try:
                verify_envelope(env, PT_MESSAGE, pub_raw)
            except AATPError as e:
                self._send_json(401, _err_body(e.code, e.detail))
                return
            except Exception:
                self._send_json(401, _err_body("ERR_AUTH_FAILED", "bad signature"))
                return
            try:
                created_dt = parse_ts(created)
            except AATPError as e:
                self._send_json(401, _err_body(e.code, e.detail))
                return
            now = datetime.now(timezone.utc)
            if abs((now - created_dt).total_seconds()) > AUTH_SKEW_SECONDS:
                self._send_json(401, _err_body("ERR_MESSAGE_EXPIRED", "stale request"))
                return
            if envelope_aid != aid:
                self._send_json(403, _err_body("ERR_AUTH_FAILED", "agent mismatch"))
                return
            packets = relay_ref.take_packets(aid)
            self._send_json(200, packets)

    return ThreadingHTTPServer((host, port), Handler)
