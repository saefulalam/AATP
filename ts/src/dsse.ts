// DSSE v1 envelopes over Ed25519 (blueprint §3.4, SIG-002/003, CRY-002/003).
// Mirrors aatp/dsse.py: PAE grammar and check order are identical, only the
// backend differs (noble instead of cryptography/OpenSSL).
//
// PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body with
// LEN the ASCII decimal byte length (no leading zeros possible: numbers are
// formatted, never parsed). The type is embedded as raw UTF-8 bytes and the
// body as raw bytes — the whole preimage is byte-exact.

import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u, b64uDec } from "./b64.ts";
import { parseJcs } from "./canon.ts";
import { err } from "./errors.ts";

// Payload-type strings copied verbatim from aatp/dsse.py (blueprint §3.3).
export const PT_MESSAGE = "application/vnd.aatp.message+json";
export const PT_NODE = "application/vnd.aatp.node+json";
export const PT_CARD = "application/vnd.aatp.card+json";
export const PT_GRANT = "application/vnd.aatp.grant+json";
export const PT_ROTATION = "application/vnd.aatp.rotation+json";

// Ed25519 group order, copied verbatim from aatp/dsse.py (CRY-003).
export const ED25519_L =
  2n ** 252n + 27742317777372353535851937790883648493n;

export interface DsSeSignature {
  keyid: string;
  sig: string;
}

export interface DsseEnvelope {
  payloadType: string;
  payload: string;
  signatures: DsSeSignature[];
}

export interface EnvelopeSigner {
  sign(payloadType: string, payload: Uint8Array): Uint8Array;
  keyId(): string;
}

export function pae(payloadType: string, payload: Uint8Array): Uint8Array {
  if (typeof payloadType !== "string") {
    throw err("ERR_MALFORMED_MESSAGE", "payloadType must be a string");
  }
  if (!(payload instanceof Uint8Array)) {
    throw err("ERR_MALFORMED_MESSAGE", "payload must be bytes");
  }
  const t = new TextEncoder().encode(payloadType);
  const prefix = new TextEncoder().encode(`DSSEv1 ${t.length} `);
  const middle = new TextEncoder().encode(` ${payload.length} `);
  const out = new Uint8Array(
    prefix.length + t.length + middle.length + payload.length,
  );
  out.set(prefix, 0);
  out.set(t, prefix.length);
  out.set(middle, prefix.length + t.length);
  out.set(payload, prefix.length + t.length + middle.length);
  return out;
}

export function makeEnvelope(
  payloadType: string,
  payload: Uint8Array,
  signer: EnvelopeSigner,
): DsseEnvelope {
  const sig = signer.sign(payloadType, payload);
  return {
    payloadType,
    payload: b64u(payload),
    signatures: [{ keyid: signer.keyId(), sig: b64u(sig) }],
  };
}

function malformed(detail: string): never {
  throw err("ERR_MALFORMED_MESSAGE", detail);
}

function selectSignature(
  sigs: unknown,
  keyId: string | null,
): { keyid: string; sig: string } {
  if (!Array.isArray(sigs) || sigs.length === 0) {
    malformed("signatures must be a non-empty list");
  }
  for (const s of sigs as unknown[]) {
    if (
      typeof s !== "object" ||
      s === null ||
      Array.isArray(s) ||
      typeof (s as Record<string, unknown>)["keyid"] !== "string" ||
      typeof (s as Record<string, unknown>)["sig"] !== "string"
    ) {
      malformed("signature entry needs string keyid and sig");
    }
  }
  const entries = sigs as { keyid: string; sig: string }[];
  if (keyId === null || keyId === undefined) {
    return entries[0];
  }
  for (const s of entries) {
    if (s.keyid === keyId) {
      return s;
    }
  }
  throw err("ERR_SIGNATURE_INVALID", "no signature for key_id");
}

function scalarLE(bytes: Uint8Array, start: number, end: number): bigint {
  let v = 0n;
  for (let i = end - 1; i >= start; i--) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

export function verifyEnvelope(
  env: unknown,
  expectedPayloadType: string,
  publicKeyRaw: unknown,
  keyId: string | null = null,
): unknown {
  // SIG-003: the type comparison runs before the payload is touched.
  if (typeof env !== "object" || env === null || Array.isArray(env)) {
    malformed("envelope must be an object");
  }
  const rec = env as Record<string, unknown>;
  const pt = rec["payloadType"];
  if (typeof pt !== "string" || typeof rec["payload"] !== "string") {
    malformed("payloadType and payload must be strings");
  }
  if (pt !== expectedPayloadType) {
    malformed("payloadType mismatch");
  }
  const entry = selectSignature(rec["signatures"], keyId);
  const payload = b64uDec(rec["payload"] as string);
  const sig = b64uDec(entry.sig);
  // SIG-002: rejects unless jcs(parsed) == payload byte-exact.
  const obj = parseJcs(payload);
  if (sig.length !== 64) {
    throw err("ERR_SIGNATURE_INVALID", "signature must be 64 bytes");
  }
  if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.length !== 32) {
    throw err("ERR_SIGNATURE_INVALID", "public key must be 32 bytes");
  }
  // CRY-003, backend-independent: explicit S < L before verify.
  if (scalarLE(sig, 32, 64) >= ED25519_L) {
    throw err("ERR_SIGNATURE_INVALID", "non-canonical signature (S >= L)");
  }
  let ok = false;
  try {
    ok = ed25519.verify(sig, pae(pt, payload), publicKeyRaw);
  } catch {
    ok = false;
  }
  if (!ok) {
    throw err("ERR_SIGNATURE_INVALID", "signature verification failed");
  }
  return obj;
}
