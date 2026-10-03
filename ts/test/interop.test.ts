import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { hexToBytes, hex, b64uDec } from "../src/b64.ts";
import { PT_NODE, verifyEnvelope } from "../src/dsse.ts";
import { decryptOne } from "../src/chunks.ts";
import { nodeIdOf, validateNode } from "../src/node.ts";
import { KeyStore, openPacket, unwrapCek } from "../src/seal.ts";

// Python-written fixture (tests/export_interop_fixtures.py, TEST-ONLY keys).
const fixture = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "testdata", "offer.json"),
    "utf8",
  ),
);

describe("interop Python -> TS", () => {
  it("fixture is TEST-ONLY labeled", () => {
    assert.equal(fixture._test_only_keys, true);
  });

  it("X25519 pub derivation agrees with Python", () => {
    const priv = hexToBytes(fixture.recipient_enc_priv_hex as string);
    const derived = new Uint8Array(x25519.getPublicKey(priv));
    assert.equal(hex(derived), fixture.recipient_enc_pub_hex);
  });

  it("open Python-sealed packet, verify DSSE, unwrap CEK, decrypt chunks", async () => {
    const kid = fixture.recipient_enc_key_id as string;
    const ks = new KeyStore({
      [kid]: hexToBytes(fixture.recipient_enc_priv_hex as string),
    });
    const actorPub = hexToBytes(fixture.actor_pub_hex as string);

    // Sealed plaintext is the node envelope: open then verify with actor pub.
    const envelope = (await openPacket(fixture.offer_packet, ks)) as Record<
      string,
      unknown
    >;
    assert.deepEqual(envelope, fixture.node_envelope);
    const node = verifyEnvelope(envelope, PT_NODE, actorPub) as Parameters<
      typeof nodeIdOf
    >[0];
    assert.equal(validateNode(node), fixture.node_id);
    assert.equal(nodeIdOf(node), fixture.node_id);
    assert.equal(
      (node as { content_root: string }).content_root,
      fixture.content_root,
    );

    // CEK arrives only via HPKE wrap, never in clear in the fixture.
    assert.equal("cek_hex" in fixture, false);
    const cek = await unwrapCek(
      fixture.wrap_entry,
      fixture.content_root,
      fixture.actor_id,
      fixture.transfer_id,
      ks,
    );
    const chunks = fixture.chunks as { index: number; data_b64: string }[];
    const total = chunks.length;
    const parts: Uint8Array[] = [];
    for (const c of chunks) {
      const ct = b64uDec(c.data_b64);
      parts.push(
        decryptOne(
          cek,
          c.index,
          total,
          fixture.content_root,
          fixture.transfer_id,
          ct,
        ),
      );
    }
    const out = Buffer.concat(parts.map((p) => Buffer.from(p)));
    assert.equal(out.toString("hex"), fixture.stream_hex);
  });
});
