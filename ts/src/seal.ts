// HPKE sealed packets + CEK wraps (blueprint 5.2, 9.2; MSG-010..013,
// ENC-020..023). Fresh logic; packet/wrap shapes, info constructions and the
// MSG-013 limit copied from aatp/seal.py.
//
// Suite: HPKE Base mode, KEM 0x0020 (DHKEM X25519 HKDF-SHA256) / KDF 0x0001
// (HKDF-SHA256) / AEAD 0x0003 (ChaCha20Poly1305) via @hpke/core +
// @hpke/chacha20poly1305 (CRY-001: never hand-roll HPKE). The @hpke/* API is
// Promise-based (WebCrypto), so seal/open/wrap/unwrap are async. Key contexts
// mirror Python: createSenderContext / createRecipientContext with aad == b""
// throughout; any recipient-open failure maps fail-closed to
// ERR_DECRYPT_FAILED.
//
// Never log keys / CEKs / plaintext.

import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { b64u, b64uDec } from "./b64.ts";
import { jcs, parseJcs } from "./canon.ts";
import { AATPError, err } from "./errors.ts";

// Domain constants copied verbatim from aatp/seal.py (byte-exact ASCII + \n).
export const D_PACKET: Uint8Array = new TextEncoder().encode(
  "AATP/0.2/PACKET\n",
);
export const D_CEKWRAP: Uint8Array = new TextEncoder().encode(
  "AATP/0.2/CEK-WRAP\n",
);

// MSG-013: measured on JCS(envelope) plaintext bytes, copied from aatp/seal.py.
export const MAX_MESSAGE_BYTES = 262144;

// Single suite for all seal/wrap operations (KEM 0x0020 / KDF 0x0001 /
// AEAD 0x0003). The ChaCha20Poly1305 AEAD lives in the companion package
// @hpke/chacha20poly1305 (see D-042); @hpke/core 1.9.0 ships AES-GCM only.
const SUITE = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

const EMPTY_AAD = new Uint8Array(0);

const PACKET_KEYS: readonly string[] = ["aatp", "ct", "enc", "to", "to_key_id"];
const WRAP_KEYS: readonly string[] = [
  "agent_id",
  "ct",
  "enc",
  "enc_key_id",
];

function malformed(detail: string): never {
  throw err("ERR_MALFORMED_MESSAGE", detail);
}

function decryptFailed(detail: string): never {
  throw err("ERR_DECRYPT_FAILED", detail);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return false;
  }
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function checkStr(v: unknown, name: string): asserts v is string {
  if (typeof v !== "string") {
    malformed(`${name} must be str`);
  }
}

function utf8(s: string, name: string): Uint8Array {
  checkStr(s, name);
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
      if (next < 0xdc00 || next > 0xdfff) {
        malformed(`${name} must be valid UTF-8`);
      }
      i++;
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      malformed(`${name} must be valid UTF-8`);
    }
  }
  return new TextEncoder().encode(s);
}

function exactKeys(obj: Record<string, unknown>, want: readonly string[], what: string): void {
  const got = Object.keys(obj).sort();
  if (got.length !== want.length || got.some((k, i) => k !== want[i])) {
    malformed(`${what} must have exactly {${want.join(",")}}`);
  }
}

export class KeyStore {
  // Minimal in-memory recipient X25519 key store. Holds raw 32-byte private
  // keys by enc_key_id; open maps ANY failure to ERR_DECRYPT_FAILED.
  private keys: Map<string, Uint8Array>;

  constructor(keys?: Record<string, Uint8Array>) {
    this.keys = new Map();
    if (keys !== undefined) {
      if (typeof keys !== "object" || keys === null || Array.isArray(keys)) {
        malformed("keys must be a mapping");
      }
      for (const [k, v] of Object.entries(keys)) {
        this.add(k, v);
      }
    }
  }

  add(encKeyId: string, privRaw: Uint8Array): void {
    if (typeof encKeyId !== "string") {
      malformed("enc_key_id must be str");
    }
    if (!(privRaw instanceof Uint8Array) || privRaw.length !== 32) {
      malformed("private key must be 32 bytes");
    }
    this.keys.set(encKeyId, new Uint8Array(privRaw));
  }

  async open(
    encKeyId: unknown,
    enc: unknown,
    ct: unknown,
    info: unknown,
  ): Promise<Uint8Array> {
    // HPKE open inside the store. ANY failure -> ERR_DECRYPT_FAILED.
    try {
      if (typeof encKeyId !== "string") {
        decryptFailed("unknown key");
      }
      const skRaw = this.keys.get(encKeyId);
      if (skRaw === undefined) {
        decryptFailed("unknown key id");
      }
      if (!(enc instanceof Uint8Array) || !(ct instanceof Uint8Array)) {
        decryptFailed("bad enc/ct");
      }
      if (!(info instanceof Uint8Array)) {
        decryptFailed("bad info");
      }
      const skr = await SUITE.kem.deserializePrivateKey(skRaw);
      const ctx = await SUITE.createRecipientContext({
        recipientKey: skr,
        enc,
        info,
      });
      return new Uint8Array(await ctx.open(ct, EMPTY_AAD));
    } catch (e) {
      if (e instanceof AATPError && e.code === "ERR_DECRYPT_FAILED") {
        throw e;
      }
      decryptFailed("open failed");
    }
  }
}

async function seal(
  pkRaw: unknown,
  info: Uint8Array,
  pt: Uint8Array,
): Promise<{ enc: Uint8Array; ct: Uint8Array }> {
  if (!(pkRaw instanceof Uint8Array) || pkRaw.length !== 32) {
    malformed("recipient public key must be 32 bytes");
  }
  if (!(info instanceof Uint8Array)) {
    malformed("info must be bytes");
  }
  if (!(pt instanceof Uint8Array)) {
    malformed("plaintext must be bytes");
  }
  let pkr: CryptoKey;
  try {
    pkr = await SUITE.kem.deserializePublicKey(pkRaw);
  } catch {
    malformed("invalid recipient public key");
  }
  try {
    const ctx = await SUITE.createSenderContext({
      recipientPublicKey: pkr,
      info,
    });
    const ct = new Uint8Array(await ctx.seal(pt, EMPTY_AAD));
    return { enc: new Uint8Array(ctx.enc), ct };
  } catch {
    throw err("ERR_INTERNAL", "hpke seal failed");
  }
}

export function packetInfo(to: string, toKeyId: string): Uint8Array {
  const a = utf8(to, "to");
  const b = utf8(toKeyId, "to_key_id");
  const out = new Uint8Array(D_PACKET.length + a.length + 1 + b.length);
  out.set(D_PACKET, 0);
  out.set(a, D_PACKET.length);
  out[D_PACKET.length + a.length] = 0x0a;
  out.set(b, D_PACKET.length + a.length + 1);
  return out;
}

export function wrapInfo(
  contentRoot: string,
  sender: string,
  recipient: string,
  transferId: string,
  encKeyId: string,
): Uint8Array {
  const body = jcs({ cr: contentRoot, s: sender, r: recipient, t: transferId, k: encKeyId });
  const out = new Uint8Array(D_CEKWRAP.length + body.length);
  out.set(D_CEKWRAP, 0);
  out.set(body, D_CEKWRAP.length);
  return out;
}

export async function sealPacket(
  recipientAgentId: unknown,
  toKeyId: unknown,
  recipientEncPubRaw: unknown,
  envelope: unknown,
): Promise<Record<string, string>> {
  checkStr(recipientAgentId, "to");
  checkStr(toKeyId, "to_key_id");
  if (!isPlainObject(envelope)) {
    malformed("envelope must be an object");
  }
  const pt = jcs(envelope);
  if (pt.length > MAX_MESSAGE_BYTES) {
    throw err("ERR_SIZE_LIMIT", "plaintext envelope exceeds max_message_bytes");
  }
  const info = packetInfo(recipientAgentId, toKeyId);
  const { enc, ct } = await seal(recipientEncPubRaw, info, pt);
  return {
    aatp: "0.2",
    to: recipientAgentId,
    to_key_id: toKeyId,
    enc: b64u(enc),
    ct: b64u(ct),
  };
}

export async function openPacket(
  packet: unknown,
  keystore: KeyStore,
): Promise<Record<string, unknown>> {
  if (!isPlainObject(packet)) {
    malformed("packet must be an object");
  }
  exactKeys(packet, PACKET_KEYS, "packet");
  if (packet["aatp"] !== "0.2") {
    malformed("unsupported packet version");
  }
  const to = packet["to"];
  const kid = packet["to_key_id"];
  const encS = packet["enc"];
  const ctS = packet["ct"];
  checkStr(to, "to");
  checkStr(kid, "to_key_id");
  if (typeof encS !== "string" || typeof ctS !== "string") {
    malformed("enc/ct must be strings");
  }
  const enc = b64uDec(encS);
  const ct = b64uDec(ctS);
  // Rebuild info from PACKET fields, never the inner message (MSG-011/012).
  const info = packetInfo(to, kid);
  const pt = await keystore.open(kid, enc, ct, info);
  const obj = parseJcs(pt);
  if (!isPlainObject(obj)) {
    malformed("packet plaintext must be an object");
  }
  return obj;
}

export async function wrapCek(
  cek: unknown,
  contentRoot: unknown,
  senderAgentId: unknown,
  recipientAgentId: unknown,
  encKeyId: unknown,
  transferId: unknown,
  recipientEncPubRaw: unknown,
): Promise<Record<string, string>> {
  if (!(cek instanceof Uint8Array) || cek.length !== 32) {
    malformed("CEK must be 32 bytes");
  }
  checkStr(contentRoot, "content_root");
  checkStr(senderAgentId, "sender");
  checkStr(recipientAgentId, "recipient");
  checkStr(encKeyId, "enc_key_id");
  checkStr(transferId, "transfer_id");
  const info = wrapInfo(contentRoot, senderAgentId, recipientAgentId, transferId, encKeyId);
  const { enc, ct } = await seal(recipientEncPubRaw, info, new Uint8Array(cek));
  return {
    agent_id: recipientAgentId,
    enc_key_id: encKeyId,
    enc: b64u(enc),
    ct: b64u(ct),
  };
}

export async function unwrapCek(
  entry: unknown,
  contentRoot: unknown,
  senderAgentId: unknown,
  transferId: unknown,
  keystore: KeyStore,
): Promise<Uint8Array> {
  if (!isPlainObject(entry)) {
    malformed("wrap entry must be an object");
  }
  exactKeys(entry, WRAP_KEYS, "wrap entry");
  const rid = entry["agent_id"];
  const kid = entry["enc_key_id"];
  const encS = entry["enc"];
  const ctS = entry["ct"];
  checkStr(rid, "agent_id");
  checkStr(kid, "enc_key_id");
  if (typeof encS !== "string" || typeof ctS !== "string") {
    malformed("enc/ct must be strings");
  }
  checkStr(contentRoot, "content_root");
  checkStr(senderAgentId, "sender");
  checkStr(transferId, "transfer_id");
  const enc = b64uDec(encS);
  const ct = b64uDec(ctS);
  const info = wrapInfo(contentRoot, senderAgentId, rid, transferId, kid);
  const cek = await keystore.open(kid, enc, ct, info);
  if (cek.length !== 32) {
    decryptFailed("bad CEK length");
  }
  return cek;
}
