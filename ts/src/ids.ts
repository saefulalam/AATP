// ID-001: self-certifying agent_id (blueprint §4.1). Mirrors aatp/ids.py.
// agent_id = "aatp:" + lowercase-no-pad base32(SHA-256(D_AGENT + genesis_pub)).

import { sha256 } from "@noble/hashes/sha2.js";
import { err } from "./errors.ts";

// Domain constant copied verbatim from aatp/ids.py (byte-exact ASCII + \n).
export const D_AGENT: Uint8Array = new TextEncoder().encode(
  "AATP/0.2/AGENT-ID\n",
);

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bitsLeft = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      out += B32_ALPHABET[(buffer >>> (bitsLeft - 5)) & 31];
      bitsLeft -= 5;
    }
    // Keep only the unconsumed bits so `buffer` never exceeds 13 bits.
    buffer &= (1 << bitsLeft) - 1;
  }
  if (bitsLeft > 0) {
    out += B32_ALPHABET[(buffer << (5 - bitsLeft)) & 31];
  }
  while (out.length % 8 !== 0) {
    out += "=";
  }
  return out;
}

export function deriveAgentId(genesisPublicKeyRaw32: Uint8Array): string {
  if (
    !(genesisPublicKeyRaw32 instanceof Uint8Array) ||
    genesisPublicKeyRaw32.length !== 32
  ) {
    throw err(
      "ERR_MALFORMED_MESSAGE",
      "genesis public key must be 32 bytes",
    );
  }
  const preimage = new Uint8Array(D_AGENT.length + 32);
  preimage.set(D_AGENT, 0);
  preimage.set(genesisPublicKeyRaw32, D_AGENT.length);
  const digest = sha256(preimage);
  return "aatp:" + base32Encode(digest).toLowerCase().replace(/=+$/, "");
}
