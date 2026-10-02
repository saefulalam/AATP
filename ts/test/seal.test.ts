import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import { b64u } from "../src/b64.ts";
import { jcs } from "../src/canon.ts";
import {
  KeyStore,
  MAX_MESSAGE_BYTES,
  openPacket,
  packetInfo,
  sealPacket,
  unwrapCek,
  wrapCek,
  wrapInfo,
} from "../src/seal.ts";

const KID = "e-test-1";

function keypair(seed?: Uint8Array): { priv: Uint8Array; pub: Uint8Array } {
  const priv = seed ? new Uint8Array(seed) : new Uint8Array(randomBytes(32));
  return { priv, pub: new Uint8Array(x25519.getPublicKey(priv)) };
}

function storeFor(kid: string, priv: Uint8Array): KeyStore {
  return new KeyStore({ [kid]: priv });
}

function decryptFailed(p: Promise<unknown>, msg: string): Promise<void> {
  return assert.rejects(
    p,
    (e: unknown) =>
      typeof e === "object" &&
      e !== null &&
      (e as { code: string }).code === "ERR_DECRYPT_FAILED" &&
      (e as { numeric: number }).numeric === 1111,
    msg,
  );
}

describe("seal packet round-trip", () => {
  it("seal/open round-trip preserves envelope", async () => {
    const { priv, pub } = keypair();
    const env = { hello: "world", n: 1 };
    const pkt = await sealPacket("aatp:recv1", KID, pub, env);
    const out = await openPacket(pkt, storeFor(KID, priv));
    assert.deepEqual(out, env);
  });

  it("packet has exactly {aatp,to,to_key_id,enc,ct}", async () => {
    const { pub } = keypair();
    const pkt = await sealPacket("aatp:recv1", KID, pub, { a: 1 });
    assert.deepEqual(Object.keys(pkt).sort(), [
      "aatp",
      "ct",
      "enc",
      "to",
      "to_key_id",
    ]);
    assert.equal(pkt["aatp"], "0.2");
  });

  it("tampered ct fails with ERR_DECRYPT_FAILED", async () => {
    const { priv, pub } = keypair();
    const pkt = await sealPacket("aatp:recv1", KID, pub, { a: 1 });
    const raw = Uint8Array.from(Buffer.from(pkt["ct"] as string, "base64url"));
    raw[0] ^= 1;
    const bad = { ...pkt, ct: b64u(raw) };
    await decryptFailed(
      openPacket(bad, storeFor(KID, priv)),
      "tampered ct must fail closed",
    );
  });

  it("tampered enc fails with ERR_DECRYPT_FAILED", async () => {
    const { priv, pub } = keypair();
    const pkt = await sealPacket("aatp:recv1", KID, pub, { a: 1 });
    const raw = Uint8Array.from(Buffer.from(pkt["enc"] as string, "base64url"));
    raw[0] ^= 1;
    const bad = { ...pkt, enc: b64u(raw) };
    await decryptFailed(
      openPacket(bad, storeFor(KID, priv)),
      "tampered enc must fail closed",
    );
  });

  it("unknown key id fails with ERR_DECRYPT_FAILED", async () => {
    const { pub } = keypair();
    const pkt = await sealPacket("aatp:recv1", KID, pub, { a: 1 });
    await decryptFailed(
      openPacket(pkt, storeFor("other-kid", new Uint8Array(32).fill(9))),
      "unknown key id must fail closed",
    );
  });

  it("wrong info (retargeted to) fails with ERR_DECRYPT_FAILED", async () => {
    const { priv, pub } = keypair();
    const pkt = await sealPacket("aatp:recv1", KID, pub, { a: 1 });
    const bad = { ...pkt, to: "aatp:attacker" };
    await decryptFailed(
      openPacket(bad, storeFor(KID, priv)),
      "retargeted packet must fail (info binds to/key_id)",
    );
  });

  it("malformed packet shapes fail with ERR_MALFORMED_MESSAGE", async () => {
    const { priv, pub } = keypair();
    const pkt = await sealPacket("aatp:recv1", KID, pub, { a: 1 });
    const ks = storeFor(KID, priv);
    const cases: { name: string; pkt: unknown }[] = [
      { name: "extra key", pkt: { ...pkt, extra: 1 } },
      { name: "missing key", pkt: { aatp: "0.2", to: "x" } },
      { name: "bad version", pkt: { ...pkt, aatp: "0.3" } },
      { name: "bad b64", pkt: { ...pkt, ct: "!!!" } },
    ];
    for (const c of cases) {
      await assert.rejects(
        openPacket(c.pkt, ks),
        (e: unknown) =>
          typeof e === "object" &&
          e !== null &&
          (e as { code: string }).code === "ERR_MALFORMED_MESSAGE",
        c.name,
      );
    }
  });

  it("oversize envelope (>262144 plaintext bytes) fails with ERR_SIZE_LIMIT", async () => {
    const { pub } = keypair();
    const big = { pad: "A".repeat(MAX_MESSAGE_BYTES + 1) };
    await assert.rejects(
      sealPacket("aatp:recv1", KID, pub, big),
      (e: unknown) =>
        typeof e === "object" &&
        e !== null &&
        (e as { code: string }).code === "ERR_SIZE_LIMIT" &&
        (e as { numeric: number }).numeric === 1006,
      "oversize must be rejected before sealing",
    );
  });

  it("packet info grammar is D_PACKET + to + LF + key_id", () => {
    const info = packetInfo("aatp:recv1", KID);
    assert.equal(
      Buffer.from(info).toString("utf8"),
      "AATP/0.2/PACKET\n" + "aatp:recv1\n" + KID,
    );
  });
});

describe("seal cek wrap round-trip", () => {
  it("wrap/unwrap round-trip preserves 32B CEK", async () => {
    const { priv, pub } = keypair();
    const cek = new Uint8Array(32).map((_, i) => i);
    const entry = await wrapCek(
      cek,
      "sha256:" + "ab".repeat(32),
      "aatp:sender",
      "aatp:recv1",
      KID,
      "tx1",
      pub,
    );
    assert.deepEqual(Object.keys(entry).sort(), [
      "agent_id",
      "ct",
      "enc",
      "enc_key_id",
    ]);
    const out = await unwrapCek(
      entry,
      "sha256:" + "ab".repeat(32),
      "aatp:sender",
      "tx1",
      storeFor(KID, priv),
    );
    assert.deepEqual(out, cek);
  });

  it("tampered wrap ct fails with ERR_DECRYPT_FAILED", async () => {
    const { priv, pub } = keypair();
    const cek = new Uint8Array(32).fill(7);
    const entry = await wrapCek(
      cek,
      "sha256:" + "ab".repeat(32),
      "aatp:s",
      "aatp:r",
      KID,
      "tx1",
      pub,
    );
    const raw = Uint8Array.from(
      Buffer.from(entry["ct"] as string, "base64url"),
    );
    raw[raw.length - 1] ^= 1;
    await decryptFailed(
      unwrapCek(
        { ...entry, ct: b64u(raw) },
        "sha256:" + "ab".repeat(32),
        "aatp:s",
        "tx1",
        storeFor(KID, priv),
      ),
      "tampered wrap must fail closed",
    );
  });

  it("wrap info binds cr/s/r/t/k", () => {
    const info = wrapInfo("cr", "s", "r", "t", "k");
    const jcsPart = Buffer.from(info).toString("utf8").replace(
      "AATP/0.2/CEK-WRAP\n",
      "",
    );
    assert.equal(jcsPart, Buffer.from(jcs({ cr: "cr", s: "s", r: "r", t: "t", k: "k" })).toString());
  });
});
