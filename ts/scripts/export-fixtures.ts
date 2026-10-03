// Generate the TypeScript->Python interop fixture (M8-4, run once).
// Output (committed): tests/testdata-ts/ts_interop.json
//
// TEST-ONLY throwaway keys (fixed seeds, never production keys; see
// DECISIONS.md D-042): actor Ed25519 seed 0x55*32, recipient signing seed
// 0x77*32 (id only), recipient X25519 priv 0x66*32 (exported so Python can
// open). The CEK is NEVER exported in clear; Python recovers it via the wrap.
//
// Run from repo root: node ts/scripts/export-fixtures.ts

import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { b64u, hex } from "../src/b64.ts";
import { build } from "../src/artifact.ts";
import { jcs } from "../src/canon.ts";
import { decryptOne, encryptChunks } from "../src/chunks.ts";
import { PT_NODE, verifyEnvelope } from "../src/dsse.ts";
import { deriveAgentId } from "../src/ids.ts";
import { SoftwareSigner } from "../src/signer.ts";
import { makeNode, makeNodeEnvelope, nodeIdOf } from "../src/node.ts";
import { KeyStore, openPacket, sealPacket, unwrapCek, wrapCek } from "../src/seal.ts";

const ACTOR_SEED = new Uint8Array(32).fill(0x55); // TEST-ONLY
const RECIP_SIGN_SEED = new Uint8Array(32).fill(0x77); // id only, TEST-ONLY
const RECIP_ENC_PRIV = new Uint8Array(32).fill(0x66); // exported TEST-ONLY
const ENC_KEY_ID = "rk-test-ts-1";
const TRANSFER_ID = "tx_demo_ts";
const CHUNK_SIZE = 5;
const TASK_ID = "task_interop_ts";
const CREATED_AT = "2026-10-01T00:00:00Z";
// Fixed TEST-ONLY CEK 0x20..0x3f; never written to the fixture in clear.
const CEK = new Uint8Array(32).map((_, i) => 0x20 + i);

const enc = new TextEncoder();

async function main(): Promise<void> {
  const actor = SoftwareSigner.fromSeed(ACTOR_SEED, "k-interop-ts");
  const actorId = deriveAgentId(actor.publicKeyRaw());
  const recipSigner = SoftwareSigner.fromSeed(RECIP_SIGN_SEED, "k-recip-ts");
  const recipientId = deriveAgentId(recipSigner.publicKeyRaw());
  const recipPub = new Uint8Array(x25519.getPublicKey(RECIP_ENC_PRIV));

  const { stream, contentRoot } = build([
    { path: "ts_hello.txt", data: enc.encode("hello from ts"), x: false },
  ]);
  const { node } = makeNode(
    contentRoot,
    [],
    "create",
    actorId,
    TASK_ID,
    null,
    CREATED_AT,
  );
  const nodeId = nodeIdOf(node);
  const envelope = makeNodeEnvelope(node, actor);

  const packet = await sealPacket(recipientId, ENC_KEY_ID, recipPub, envelope);
  const cts = encryptChunks(CEK, stream, CHUNK_SIZE, contentRoot, TRANSFER_ID);
  const wrap = await wrapCek(
    CEK,
    contentRoot,
    actorId,
    recipientId,
    ENC_KEY_ID,
    TRANSFER_ID,
    recipPub,
  );

  // Self-check with TS before committing the fixture.
  const ks = new KeyStore({ [ENC_KEY_ID]: RECIP_ENC_PRIV });
  const opened = await openPacket(packet, ks);
  assertDeepEqual(opened, envelope, "packet round-trip");
  const verifiedNode = verifyEnvelope(envelope, PT_NODE, actor.publicKeyRaw());
  assertDeepEqual(verifiedNode, node, "node envelope verify");
  const cekBack = await unwrapCek(
    wrap,
    contentRoot,
    actorId,
    TRANSFER_ID,
    ks,
  );
  assertDeepEqual(cekBack, CEK, "wrap round-trip");
  for (let i = 0; i < cts.length; i++) {
    const pt = decryptOne(CEK, i, cts.length, contentRoot, TRANSFER_ID, cts[i]);
    const want = stream.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    assertDeepEqual(pt, want, `chunk ${i}`);
  }

  const fixture = {
    _test_only_keys: true,
    note: "TEST-ONLY throwaway keys. Never production keys. See DECISIONS.md D-042.",
    ts_actor_id: actorId,
    ts_actor_pub_hex: hex(actor.publicKeyRaw()),
    ts_recipient_agent_id: recipientId,
    ts_recipient_enc_key_id: ENC_KEY_ID,
    ts_recipient_enc_priv_hex: hex(RECIP_ENC_PRIV),
    ts_recipient_enc_pub_hex: hex(recipPub),
    content_root: contentRoot,
    transfer_id: TRANSFER_ID,
    chunk_size: CHUNK_SIZE,
    stream_hex: Buffer.from(stream).toString("hex"),
    node_id: nodeId,
    payload_type: PT_NODE,
    ts_packet: packet,
    ts_node_envelope: envelope,
    ts_wrap_entry: wrap,
    ts_chunks: cts.map((c, i) => ({ index: i, data_b64: b64u(c) })),
  };
  const out = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "tests",
    "testdata-ts",
    "ts_interop.json",
  );
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(fixture, null, 2) + "\n");
  console.log(`wrote ${out} node_id=${nodeId}`);
}

function assertDeepEqual(a: unknown, b: unknown, what: string): void {
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    if (a.length === b.length && a.every((v, i) => v === b[i])) {
      return;
    }
    throw new Error(`self-check failed: ${what}`);
  }
  // Order-insensitive: canonical JCS sorts object keys.
  const sa = Buffer.from(jcs(a as Record<string, unknown>)).toString();
  const sb = Buffer.from(jcs(b as Record<string, unknown>)).toString();
  if (sa !== sb) {
    throw new Error(`self-check failed: ${what}`);
  }
}

await main();
