"""M7-2 transport: relay + reference HTTP server (NET-001..003, section 13).

TDD RED first: this file is written before aatp/transport exists.
Server runs in a daemon thread (helper here, not in http.py), client via urllib.
Never logs packet contents beyond sizes (asserts on hashes/ids only).
"""
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

from aatp.b64 import b64u, b64u_dec
from aatp.canon import jcs, parse_jcs
from aatp.dsse import PT_CARD, PT_MESSAGE, make_envelope
from aatp.ids import derive_agent_id
from aatp.messages import format_ts
from aatp.signer import SoftwareSigner


def _signer(seed_byte, key_id):
    return SoftwareSigner.from_seed(bytes([seed_byte]) * 32, key_id)


def _agent(seed_byte, sign_kid):
    s = _signer(seed_byte, sign_kid)
    return s, derive_agent_id(s.public_key_raw())


def _card_for(signer, agent_id, enc_pub_raw=None, enc_kid="e0"):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    if enc_pub_raw is None:
        sk = X25519PrivateKey.generate()
        enc_pub_raw = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    card = {
        "v": "0.2", "agent_id": agent_id,
        "genesis_public_key": b64u(signer.public_key_raw()),
        "signing_key": {"key_id": signer.key_id(),
                        "public_key": b64u(signer.public_key_raw()),
                        "not_before": "2026-10-01T00:00:00Z",
                        "not_after": "2027-10-01T00:00:00Z"},
        "enc_key": {"key_id": enc_kid, "public_key": b64u(enc_pub_raw),
                    "not_before": "2026-10-01T00:00:00Z",
                    "not_after": "2026-10-08T00:00:00Z"},
        "key_history": [], "suites": ["AATP-S1"], "seq": 1,
        "issued_at": "2026-10-01T00:00:00Z",
        "expires_at": "2026-10-08T00:00:00Z",
    }
    return make_envelope(PT_CARD, jcs(card), signer)


def _sealed_packet(to_agent, to_key_id, enc_pub_raw, signer, body_extra=None):
    from aatp.seal import seal_packet
    body = {"type": "OFFER", "transfer_id": "tx1",
            "content_root": "sha256:" + "0" * 64,
            "sender": "aatp:sender", "recipient": to_agent}
    if body_extra:
        body.update(body_extra)
    env = make_envelope(PT_MESSAGE, jcs(body), signer)
    return seal_packet(to_agent, to_key_id, enc_pub_raw, env)


def _run_server(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _base_url(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


def _http(method, url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _auth_header(signer, agent_id, path, created_at):
    payload = jcs({"method": "GET", "path": path,
                   "created_at": created_at, "agent_id": agent_id})
    env = make_envelope(PT_MESSAGE, payload, signer)
    return "DSSE " + b64u(jcs(env))


def _now_ts():
    return format_ts(datetime.now(timezone.utc))


def test_NET002_relay_never_alters():
    from aatp.transport.relay import Relay
    s, aid = _agent(0xA1, "k1")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    pkt = _sealed_packet(aid, "e1", pk, s)
    relay = Relay()
    pid = relay.put_packet(pkt)
    (got,) = relay.take_packets(aid)
    assert jcs(got) == jcs(pkt)
    import hashlib
    assert pid == hashlib.sha256(jcs(pkt)).hexdigest()


def test_packet_roundtrip_idempotent_redelivery():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xA2, "k1")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    pkt = _sealed_packet(aid, "e1", pk, s)
    relay = Relay()
    cards = {}
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: cards[a])
    _run_server(server)
    try:
        base = _base_url(server)
        body = jcs(pkt)
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets", body=body,
                           headers={"Content-Type": "application/json"})
        assert st == 202
        id1 = json.loads(raw.decode())["id"]
        st2, raw2, _ = _http("POST", base + "/aatp/v0.2/packets", body=body,
                             headers={"Content-Type": "application/json"})
        assert st2 == 202
        assert json.loads(raw2.decode())["id"] == id1
    finally:
        server.shutdown()


def test_http_mailbox_auth():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    sA, aidA = _agent(0xA3, "kA")
    sB, aidB = _agent(0xB3, "kB")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    pkt = _sealed_packet(aidA, "e1", pk, sB)
    relay = Relay()
    relay.put_packet(pkt)
    cardA = _card_for(sA, aidA)
    cardB = _card_for(sB, aidB)
    cards = {aidA: parse_jcs(b64u_dec(cardA["payload"])),
             aidB: parse_jcs(b64u_dec(cardB["payload"]))}
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: cards[a])
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aidA}"
        # no auth -> 401
        st, _, _ = _http("GET", base + path)
        assert st == 401
        # wrong agent (B signs for A's mailbox) -> 403
        bad = _auth_header(sB, aidB, path, _now_ts())
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": bad})
        assert st == 403
        # expired created_at -> 401
        old = _auth_header(sA, aidA, path, "2020-01-01T00:00:00Z")
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": old})
        assert st == 401
        # valid -> 200 + drained
        good = _auth_header(sA, aidA, path, _now_ts())
        st, raw, _ = _http("GET", base + path,
                           headers={"Authorization": good})
        assert st == 200
        got = json.loads(raw.decode())
        assert len(got) == 1
        assert jcs(got[0]) == jcs(pkt)
        good2 = _auth_header(sA, aidA, path, _now_ts())
        st2, raw2, _ = _http("GET", base + path,
                             headers={"Authorization": good2})
        assert st2 == 200
        assert json.loads(raw2.decode()) == []
    finally:
        server.shutdown()


def test_chunk_put_get_idempotent_and_bad_input():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        url = base + "/aatp/v0.2/transfers/tx_1/chunks/0"
        st, _, _ = _http("PUT", url, body=b"hello",
                         headers={"Content-Type": "application/octet-stream"})
        assert st == 204
        assert relay.get_chunk("tx_1", 0) == b64u(b"hello")
        st, _, _ = _http("PUT", url, body=b"hello",
                         headers={"Content-Type": "application/octet-stream"})
        assert st == 204
        # bad index
        st, _, _ = _http("PUT", base + "/aatp/v0.2/transfers/tx_1/chunks/abc",
                         body=b"x",
                         headers={"Content-Type": "application/octet-stream"})
        assert st == 400
        st, _, _ = _http("PUT", base + "/aatp/v0.2/transfers/tx_1/chunks/-1",
                         body=b"x",
                         headers={"Content-Type": "application/octet-stream"})
        assert st == 400
        # bad tx charset
        st, _, _ = _http("PUT", base + "/aatp/v0.2/transfers/bad!tx/chunks/0",
                         body=b"x",
                         headers={"Content-Type": "application/octet-stream"})
        assert st == 400
    finally:
        server.shutdown()


def test_card_200_404_exact_code():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xA4, "k1")
    card_env = _card_for(s, aid)
    relay = Relay()
    relay.put_card(aid, card_env)
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        st, raw, _ = _http("GET", base + f"/aatp/v0.2/agents/{aid}/card")
        assert st == 200
        assert json.loads(raw.decode()) == card_env
        st, raw, _ = _http("GET", base + "/aatp/v0.2/agents/aatp:" + "z" * 52 + "/card")
        assert st == 404
        assert json.loads(raw.decode())["code"] == "ERR_ARTIFACT_NOT_FOUND"
    finally:
        server.shutdown()


def test_oversize_packet_and_chunk_mapping():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    relay = Relay(max_stored_packets=10000, max_chunk_bytes=10)
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        s, aid = _agent(0xA5, "k1")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        sk = X25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
        pkt = _sealed_packet(aid, "e1", pk, s)
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets",
                           body=jcs(pkt),
                           headers={"Content-Type": "application/json"})
        assert st == 413
        assert json.loads(raw.decode())["code"] == "ERR_SIZE_LIMIT"
        st, raw, _ = _http("PUT", base + "/aatp/v0.2/transfers/tx1/chunks/0",
                           body=b"0123456789ABCDEF",
                           headers={"Content-Type": "application/octet-stream"})
        assert st == 413
        assert json.loads(raw.decode())["code"] == "ERR_SIZE_LIMIT"
    finally:
        server.shutdown()
    # rate limit: tiny mailbox cap
    from aatp.transport.relay import Relay as R2
    r = R2(max_stored_packets=1)
    s2, aid2 = _agent(0xA6, "k1")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as X2
    from cryptography.hazmat.primitives import serialization as se2
    sk1 = X2.generate()
    pk1 = sk1.public_key().public_bytes(se2.Encoding.Raw, se2.PublicFormat.Raw)
    p1 = _sealed_packet(aid2, "e1", pk1, s2,
                        body_extra={"transfer_id": "tx_r1"})
    p2 = _sealed_packet(aid2, "e1", pk1, s2,
                        body_extra={"transfer_id": "tx_r2"})
    r.put_packet(p1)
    try:
        r.put_packet(p2)
        assert False, "expected rate limit"
    except Exception as e:
        assert getattr(e, "code", "") == "ERR_RATE_LIMIT"


def test_mailbox_auth_unknown_agent_401():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xB1, "k1")
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aid}"
        auth = _auth_header(s, aid, path, _now_ts())
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": auth})
        assert st == 401
    finally:
        server.shutdown()


def test_mailbox_auth_tampered_sig_401():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xB2, "k1")
    card_env = _card_for(s, aid)
    cards = {aid: parse_jcs(b64u_dec(card_env["payload"]))}
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: cards[a])
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aid}"
        payload = jcs({"method": "GET", "path": path,
                       "created_at": _now_ts(), "agent_id": aid})
        env = make_envelope(PT_MESSAGE, payload, s)
        sig_raw = bytearray(b64u_dec(env["signatures"][0]["sig"]))
        assert len(sig_raw) == 64
        sig_raw[0] ^= 0xFF
        env["signatures"][0]["sig"] = b64u(bytes(sig_raw))
        auth = "DSSE " + b64u(jcs(env))
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": auth})
        assert st == 401
    finally:
        server.shutdown()


def test_mailbox_auth_malformed_token_401():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xB3, "k1")
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aid}"
        st, _, _ = _http("GET", base + path)
        assert st == 401
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": "DSSE not-base64!!!"})
        assert st == 401
    finally:
        server.shutdown()


def test_mailbox_auth_path_tamper_401():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xB4, "k1")
    card_env = _card_for(s, aid)
    cards = {aid: parse_jcs(b64u_dec(card_env["payload"]))}
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: cards[a])
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aid}"
        auth = _auth_header(s, aid, "/aatp/v0.2/mailbox/OTHER", _now_ts())
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": auth})
        # implementation returns 401 on path binding mismatch (not 403)
        assert st == 401
    finally:
        server.shutdown()


def test_mailbox_auth_wrong_payload_type_401():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xB5, "k1")
    card_env = _card_for(s, aid)
    cards = {aid: parse_jcs(b64u_dec(card_env["payload"]))}
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: cards[a])
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aid}"
        payload = jcs({"method": "GET", "path": path,
                       "created_at": _now_ts(), "agent_id": aid})
        env = make_envelope(PT_CARD, payload, s)
        auth = "DSSE " + b64u(jcs(env))
        st, _, _ = _http("GET", base + path,
                         headers={"Authorization": auth})
        assert st == 401
    finally:
        server.shutdown()


def test_post_relay_full_429():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    relay = Relay(max_stored_packets=1)
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        s, aid = _agent(0xC1, "k1")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        sk = X25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
        p1 = _sealed_packet(aid, "e1", pk, s,
                            body_extra={"transfer_id": "tx_full1"})
        p2 = _sealed_packet(aid, "e1", pk, s,
                            body_extra={"transfer_id": "tx_full2"})
        st, _, _ = _http("POST", base + "/aatp/v0.2/packets", body=jcs(p1),
                         headers={"Content-Type": "application/json"})
        assert st == 202
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets", body=jcs(p2),
                           headers={"Content-Type": "application/json"})
        assert st == 429
        assert json.loads(raw.decode())["code"] == "ERR_RATE_LIMIT"
    finally:
        server.shutdown()


def test_post_malformed_400():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets", body=jcs({}),
                           headers={"Content-Type": "application/json"})
        assert st == 400
        assert json.loads(raw.decode())["code"] == "ERR_MALFORMED_MESSAGE"
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets",
                           body=b"\x00\x01 not json",
                           headers={"Content-Type": "application/json"})
        assert st == 400
        assert json.loads(raw.decode())["code"] == "ERR_MALFORMED_MESSAGE"
    finally:
        server.shutdown()


def test_redelivery_drain_fifo():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    sS, _ = _agent(0xD1, "kS")
    sR, aidR = _agent(0xD2, "kR")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    relay = Relay()
    cardR = _card_for(sR, aidR)
    cards = {aidR: parse_jcs(b64u_dec(cardR["payload"]))}
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: cards[a])
    _run_server(server)
    try:
        base = _base_url(server)
        path = f"/aatp/v0.2/mailbox/{aidR}"
        pkt1 = _sealed_packet(aidR, "e1", pk, sS,
                              body_extra={"transfer_id": "tx_dup"})
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets",
                           body=jcs(pkt1),
                           headers={"Content-Type": "application/json"})
        assert st == 202
        id1 = json.loads(raw.decode())["id"]
        st, raw, _ = _http("POST", base + "/aatp/v0.2/packets",
                           body=jcs(pkt1),
                           headers={"Content-Type": "application/json"})
        assert st == 202
        assert json.loads(raw.decode())["id"] == id1
        auth = _auth_header(sR, aidR, path, _now_ts())
        st, raw, _ = _http("GET", base + path,
                           headers={"Authorization": auth})
        assert st == 200
        got = json.loads(raw.decode())
        assert len(got) == 1
        assert jcs(got[0]) == jcs(pkt1)
        pktA = _sealed_packet(aidR, "e1", pk, sS,
                              body_extra={"transfer_id": "tx_fifo1"})
        pktB = _sealed_packet(aidR, "e1", pk, sS,
                              body_extra={"transfer_id": "tx_fifo2"})
        for pkt in (pktA, pktB):
            st, _, _ = _http("POST", base + "/aatp/v0.2/packets",
                             body=jcs(pkt),
                             headers={"Content-Type": "application/json"})
            assert st == 202
        auth = _auth_header(sR, aidR, path, _now_ts())
        st, raw, _ = _http("GET", base + path,
                           headers={"Authorization": auth})
        assert st == 200
        got = json.loads(raw.decode())
        assert len(got) == 2
        assert jcs(got[0]) == jcs(pktA)
        assert jcs(got[1]) == jcs(pktB)
        st, _, _ = _http("POST", base + "/aatp/v0.2/packets",
                         body=jcs(pktA),
                         headers={"Content-Type": "application/json"})
        assert st == 202
        auth = _auth_header(sR, aidR, path, _now_ts())
        st, raw, _ = _http("GET", base + path,
                           headers={"Authorization": auth})
        assert st == 200
        got = json.loads(raw.decode())
        assert len(got) == 1
        assert jcs(got[0]) == jcs(pktA)
    finally:
        server.shutdown()


def test_card_negatives_relay():
    from aatp.transport.relay import Relay
    s, aid = _agent(0xE1, "k1")
    relay = Relay()
    try:
        relay.put_card(aid, {"signatures": []})
        assert False, "expected ERR_MALFORMED_MESSAGE"
    except Exception as e:
        assert getattr(e, "code", "") == "ERR_MALFORMED_MESSAGE"
    card_env = _card_for(s, aid)
    bad = dict(card_env)
    bad["signatures"] = [{"keyid": "k1", "sig": b64u(b"\x00" * 5)}]
    relay.put_card(aid, bad)
    assert jcs(relay.get_card(aid)) == jcs(bad)


def test_put_card_publish_and_get():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xF1, "k1")
    card_env = _card_for(s, aid)
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        st, _, _ = _http("PUT", base + f"/aatp/v0.2/agents/{aid}/card",
                         body=jcs(card_env),
                         headers={"Content-Type": "application/json"})
        assert st == 204
        st, raw, _ = _http("GET", base + f"/aatp/v0.2/agents/{aid}/card")
        assert st == 200
        assert jcs(json.loads(raw.decode())) == jcs(card_env)
    finally:
        server.shutdown()


def test_put_card_agent_mismatch_400():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xF2, "k1")
    _, other = _agent(0xF3, "k1")
    card_env = _card_for(s, aid)
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        st, raw, _ = _http("PUT", base + f"/aatp/v0.2/agents/{other}/card",
                           body=jcs(card_env),
                           headers={"Content-Type": "application/json"})
        assert st == 400
        assert json.loads(raw.decode())["code"] == "ERR_MALFORMED_MESSAGE"
        assert relay.get_card(other) is None
    finally:
        server.shutdown()


def test_put_card_bad_sig_400():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    s, aid = _agent(0xF4, "k1")
    card_env = _card_for(s, aid)
    bad = dict(card_env)
    bad_sig = bytearray(b64u_dec(bad["signatures"][0]["sig"]))
    bad_sig[0] ^= 1
    bad["signatures"] = [{"keyid": "k1", "sig": b64u(bytes(bad_sig))}]
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        st, raw, _ = _http("PUT", base + f"/aatp/v0.2/agents/{aid}/card",
                           body=jcs(bad),
                           headers={"Content-Type": "application/json"})
        assert st == 400
        assert json.loads(raw.decode())["code"] == "ERR_SIGNATURE_INVALID"
        assert relay.get_card(aid) is None
    finally:
        server.shutdown()


def test_get_chunk_roundtrip_404():
    from aatp.transport.relay import Relay
    from aatp.transport.http import serve
    relay = Relay()
    server = serve(relay, host="127.0.0.1", port=0,
                   card_resolver=lambda a: (_ for _ in ()).throw(KeyError(a)))
    _run_server(server)
    try:
        base = _base_url(server)
        payload = b"\x00\x01\x02chunk-bytes"
        st, _, _ = _http("PUT", base + "/aatp/v0.2/transfers/tx_c1/chunks/3",
                         body=payload,
                         headers={"Content-Type": "application/octet-stream"})
        assert st == 204
        st, raw, headers = _http("GET",
                                 base + "/aatp/v0.2/transfers/tx_c1/chunks/3")
        assert st == 200
        assert raw == payload
        assert headers.get("Content-Type") == "application/octet-stream"
        st, raw, _ = _http("GET",
                           base + "/aatp/v0.2/transfers/tx_c1/chunks/9")
        assert st == 404
        assert json.loads(raw.decode())["code"] == "ERR_TRANSFER_NOT_FOUND"
        st, _, _ = _http("GET", base + "/aatp/v0.2/transfers/bad!tx/chunks/0")
        assert st == 400
        st, _, _ = _http("GET", base + "/aatp/v0.2/transfers/tx_c1/chunks/x")
        assert st == 400
    finally:
        server.shutdown()


def test_NET001_no_tls_dependency_sealed_opaque():
    from aatp.transport.relay import Relay
    from aatp.seal import seal_packet
    s, aid = _agent(0xA7, "k1")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    marker_body = {"type": "OFFER", "transfer_id": "tx_m",
                   "content_root": "sha256:" + "1" * 64,
                   "sender": "aatp:x", "recipient": aid,
                   "note": "SECRET-MARKER-ABC123"}
    env = make_envelope(PT_MESSAGE, jcs(marker_body), s)
    pkt = seal_packet(aid, "e9", pk, env)
    assert b"SECRET-MARKER" in jcs(marker_body)
    relay = Relay()
    relay.put_packet(pkt)
    (stored,) = relay.take_packets(aid)
    assert b"SECRET-MARKER" not in jcs(stored)
    assert b"SECRET-MARKER" not in jcs(pkt)
