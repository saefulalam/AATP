// Chunk AEAD (blueprint section 9.1, ENC-001..007). Fresh logic; constants,
// nonce/AAD formulas and error mapping copied from aatp/chunks.py.
// ChaCha20-Poly1305 via @noble/ciphers (CRY-001: no hand-rolled primitives).

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { jcs } from "./canon.ts";
import { err } from "./errors.ts";

// Domain constant copied verbatim from aatp/chunks.py (byte-exact ASCII + \n).
export const D_CHUNK: Uint8Array = new TextEncoder().encode("AATP/0.2/CHUNK\n");

// ENC-006 sequence space: indices valid in [0, 2^63). Kept as a float-free
// integer literal; comparisons use >= so any out-of-range value fails closed.
export const SEQ_LIMIT = 2 ** 63;

function sequenceInvalid(detail: string): never {
  throw err("ERR_SEQUENCE_INVALID", detail);
}

function authFailed(detail: string): never {
  throw err("ERR_CHUNK_AUTH_FAILED", detail);
}

function checkIndex(i: unknown): asserts i is number {
  if (typeof i !== "number" || !Number.isInteger(i) || i < 0 || i >= SEQ_LIMIT) {
    sequenceInvalid("index >= 2^63");
  }
}

function checkTotal(n: unknown): asserts n is number {
  if (
    typeof n !== "number" ||
    !Number.isInteger(n) ||
    n <= 0 ||
    n > SEQ_LIMIT
  ) {
    sequenceInvalid("total out of range");
  }
}

function checkCek(cek: unknown): asserts cek is Uint8Array {
  if (!(cek instanceof Uint8Array) || cek.length !== 32) {
    authFailed("CEK must be 32 bytes");
  }
}

// D-022 posture (mirrors Python): non-string ids fail closed as auth failures,
// never as schema errors, so type errors are indistinguishable from forgeries.
function checkIds(contentRoot: unknown, transferId: unknown): void {
  if (typeof contentRoot !== "string") {
    authFailed("content_root must be str");
  }
  if (typeof transferId !== "string") {
    authFailed("transfer_id must be str");
  }
}

export function nonce(i: number): Uint8Array {
  // nonce(i) = 0x00000000 || uint64_be(i); reject i >= 2^63 (ENC-006).
  checkIndex(i);
  const out = new Uint8Array(12);
  new DataView(out.buffer).setBigUint64(4, BigInt(i));
  return out;
}

export function manifestNonce(): Uint8Array {
  // Reserved manifest nonce, disjoint from all chunk nonces (ENC-006).
  return new Uint8Array(12).fill(0xff);
}

export function aad(
  contentRoot: string,
  i: number,
  total: number,
  transferId: string,
): Uint8Array {
  // AAD(i) = D_CHUNK || JCS({"cr","i","n","t"}) (ENC-004).
  checkIndex(i);
  checkTotal(total);
  if (i >= (total as number)) {
    sequenceInvalid("index >= total");
  }
  checkIds(contentRoot, transferId);
  const body = jcs({ cr: contentRoot, i, n: total, t: transferId });
  const out = new Uint8Array(D_CHUNK.length + body.length);
  out.set(D_CHUNK, 0);
  out.set(body, D_CHUNK.length);
  return out;
}

export function encryptChunks(
  cek: Uint8Array,
  stream: Uint8Array,
  chunkSize: number,
  contentRoot: string,
  transferId: string,
): Uint8Array[] {
  // Split stream into chunkSize pieces and seal each (ENC-001..005).
  checkCek(cek);
  if (!(stream instanceof Uint8Array)) {
    authFailed("stream must be bytes");
  }
  if (
    typeof chunkSize !== "number" ||
    !Number.isInteger(chunkSize) ||
    chunkSize <= 0
  ) {
    sequenceInvalid("chunk_size must be a positive integer");
  }
  checkIds(contentRoot, transferId);
  const total =
    stream.length === 0 ? 0 : Math.floor((stream.length + chunkSize - 1) / chunkSize);
  if (total > SEQ_LIMIT) {
    sequenceInvalid("chunk count >= 2^63");
  }
  const key = new Uint8Array(cek);
  const out: Uint8Array[] = [];
  for (let i = 0; i < total; i++) {
    const pt = stream.slice(i * chunkSize, (i + 1) * chunkSize);
    out.push(
      new Uint8Array(
        chacha20poly1305(key, nonce(i), aad(contentRoot, i, total, transferId)).encrypt(pt),
      ),
    );
  }
  return out;
}

export function decryptOne(
  cek: Uint8Array,
  index: number,
  total: number,
  contentRoot: string,
  transferId: string,
  ct: Uint8Array,
): Uint8Array {
  // Open one chunk; AEAD failure -> ERR_CHUNK_AUTH_FAILED, never ack (ENC-007).
  // All validation runs BEFORE the try so ERR_SEQUENCE_INVALID is never
  // swallowed by the fail-closed broad catch.
  checkCek(cek);
  checkIndex(index);
  checkTotal(total);
  if (index >= (total as number)) {
    sequenceInvalid("index >= total");
  }
  if (!(ct instanceof Uint8Array)) {
    authFailed("ciphertext must be bytes");
  }
  checkIds(contentRoot, transferId);
  try {
    return new Uint8Array(
      chacha20poly1305(
        new Uint8Array(cek),
        nonce(index),
        aad(contentRoot, index, total, transferId),
      ).decrypt(new Uint8Array(ct)),
    );
  } catch {
    authFailed("chunk authentication failed");
  }
}
