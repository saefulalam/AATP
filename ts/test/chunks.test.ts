import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  aad,
  decryptOne,
  encryptChunks,
  manifestNonce,
  nonce,
} from "../src/chunks.ts";
import { hexToBytes } from "../src/b64.ts";

const vectors = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "tests",
      "vectors",
      "aatp_v0_2_vectors.json",
    ),
    "utf8",
  ),
);
const V07 = vectors.V07;
const CR1 = V07.content_root as string;
const TX = V07.transfer_id as string;
const CEK = hexToBytes(V07.cek_hex as string);
const STREAM = hexToBytes(V07.stream_hex as string);
const CHUNK_SIZE = V07.chunk_size as number;

function chunkAuthFailed(fn: () => unknown, msg: string): void {
  assert.throws(
    fn,
    (e: unknown) =>
      typeof e === "object" &&
      e !== null &&
      (e as { code: string }).code === "ERR_CHUNK_AUTH_FAILED" &&
      (e as { numeric: number }).numeric === 1303,
    msg,
  );
}

function sequenceInvalid(fn: () => unknown, msg: string): void {
  assert.throws(
    fn,
    (e: unknown) =>
      typeof e === "object" &&
      e !== null &&
      (e as { code: string }).code === "ERR_SEQUENCE_INVALID" &&
      (e as { numeric: number }).numeric === 1402,
    msg,
  );
}

describe("chunks V07 byte-exact", () => {
  it("V07 nonces byte-exact", () => {
    const vchunks = V07.chunks as { i: number; nonce_hex: string }[];
    for (const c of vchunks) {
      assert.equal(Buffer.from(nonce(c.i)).toString("hex"), c.nonce_hex);
    }
  });

  it("V07 ciphertexts byte-exact (CEK 00..1f, chunk_size 8, tx_demo1, CR1)", () => {
    const cts = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    assert.equal(cts.length, 2);
    const vchunks = V07.chunks as { i: number; ct_hex: string }[];
    for (let i = 0; i < 2; i++) {
      assert.equal(Buffer.from(cts[i]).toString("hex"), vchunks[i].ct_hex);
    }
  });

  it("V07 deterministic resend identical", () => {
    const a = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    const b = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    assert.equal(a.length, b.length);
    for (let i = 0; i < a.length; i++) {
      assert.deepEqual(a[i], b[i]);
    }
  });

  it("V07 decrypt round-trip reassembles stream", () => {
    const cts = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    const parts: Uint8Array[] = [];
    for (let i = 0; i < cts.length; i++) {
      parts.push(decryptOne(CEK, i, cts.length, CR1, TX, cts[i]));
    }
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    assert.equal(Buffer.from(out).toString("hex"), V07.stream_hex);
  });

  it("manifestNonce is 0xff x12, disjoint from chunk nonces", () => {
    assert.equal(Buffer.from(manifestNonce()).toString("hex"), "ff".repeat(12));
    assert.notDeepEqual(manifestNonce(), nonce(0));
  });

  it("aad binds cr/i/n/t", () => {
    const a0 = aad(CR1, 0, 2, TX);
    const a1 = aad(CR1, 1, 2, TX);
    assert.notDeepEqual(a0, a1);
    assert.ok(Buffer.from(a0).toString().startsWith("AATP/0.2/CHUNK\n"));
  });
});

describe("chunks V08 tamper behavior", () => {
  it("V08 tampered chunk fails with ERR_CHUNK_AUTH_FAILED", () => {
    const cts = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    const bad = new Uint8Array(cts[0]);
    bad[0] ^= 1;
    chunkAuthFailed(
      () => decryptOne(CEK, 0, 2, CR1, TX, bad),
      "tampered ct must fail closed",
    );
  });

  it("V08 chunk 0 presented as index 1 fails with ERR_CHUNK_AUTH_FAILED", () => {
    const cts = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    chunkAuthFailed(
      () => decryptOne(CEK, 1, 2, CR1, TX, cts[0]),
      "reindexed chunk must fail (AAD binds index)",
    );
  });

  it("wrong CEK fails with ERR_CHUNK_AUTH_FAILED", () => {
    const cts = encryptChunks(CEK, STREAM, CHUNK_SIZE, CR1, TX);
    const wrong = new Uint8Array(CEK);
    wrong[0] ^= 1;
    chunkAuthFailed(
      () => decryptOne(wrong, 0, 2, CR1, TX, cts[0]),
      "wrong CEK must fail closed",
    );
  });

  it("index >= 2^63 rejected with ERR_SEQUENCE_INVALID", () => {
    sequenceInvalid(() => nonce(2 ** 63), "nonce(2^63)");
    sequenceInvalid(
      () => decryptOne(CEK, 2 ** 63, 2 ** 63 + 1, CR1, TX, new Uint8Array(0)),
      "decryptOne index 2^63",
    );
  });

  it("empty stream encrypts to zero chunks", () => {
    assert.deepEqual(encryptChunks(CEK, new Uint8Array(0), 8, CR1, TX), []);
  });
});
