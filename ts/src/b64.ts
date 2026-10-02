// GEN-003: base64url without padding (RFC 4648 §5), strict decoding.
// Mirrors aatp/b64.py. Buffer is a Node built-in (not a crypto primitive),
// used only for the alphabet conversion; all strictness checks are explicit.

import { err } from "./errors.ts";

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function b64u(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

export function b64uDec(s: string): Uint8Array {
  // Reject padding, non-alphabet chars and impossible lengths first.
  if (typeof s !== "string" || !B64U_RE.test(s) || s.length % 4 === 1) {
    throw err("ERR_MALFORMED_MESSAGE", "invalid base64url");
  }
  const out = Buffer.from(s, "base64url");
  // Re-encode must reproduce the input byte-exact: rejects non-zero
  // trailing bits (non-canonical encodings of the same bytes).
  if (out.toString("base64url") !== s) {
    throw err("ERR_MALFORMED_MESSAGE", "non-canonical base64url");
  }
  return new Uint8Array(out);
}

// Lowercase hex helpers (test tooling; e.g. comparing against *_hex vectors).
export function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

export function hexToBytes(h: string): Uint8Array {
  if (
    typeof h !== "string" ||
    h.length % 2 !== 0 ||
    !/^[0-9a-f]*$/.test(h)
  ) {
    throw err("ERR_MALFORMED_MESSAGE", "invalid hex");
  }
  return new Uint8Array(Buffer.from(h, "hex"));
}
