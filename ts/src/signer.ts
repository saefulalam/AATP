// SIG-001: the Signer holds the private key; callers only get signatures.
// Mirrors aatp/signer.py. The seed/secret lives in #private fields, which
// JSON.stringify never serializes, so stringifying a signer leaks nothing.

import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "node:crypto";
import { pae } from "./dsse.ts";
import { err } from "./errors.ts";

export class SoftwareSigner {
  #secret: Uint8Array;
  #keyId: string;

  private constructor(secret: Uint8Array, keyId: string) {
    this.#secret = secret;
    this.#keyId = keyId;
  }

  static fromSeed(seed: Uint8Array, keyId: string): SoftwareSigner {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) {
      throw err("ERR_MALFORMED_MESSAGE", "seed must be 32 bytes");
    }
    if (typeof keyId !== "string") {
      throw err("ERR_MALFORMED_MESSAGE", "keyId must be a string");
    }
    return new SoftwareSigner(new Uint8Array(seed), keyId);
  }

  static generate(keyId: string): SoftwareSigner {
    if (typeof keyId !== "string") {
      throw err("ERR_MALFORMED_MESSAGE", "keyId must be a string");
    }
    // CRY-006: node:crypto draws from the OS CSPRNG.
    return new SoftwareSigner(new Uint8Array(randomBytes(32)), keyId);
  }

  keyId(): string {
    return this.#keyId;
  }

  publicKeyRaw(): Uint8Array {
    return new Uint8Array(ed25519.getPublicKey(this.#secret));
  }

  sign(payloadType: string, payload: Uint8Array): Uint8Array {
    // CRY-002: sign the PAE bytes directly, no pre-hash.
    return new Uint8Array(ed25519.sign(pae(payloadType, payload), this.#secret));
  }
}
