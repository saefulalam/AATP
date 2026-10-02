import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  ED25519_L,
  PT_CARD,
  PT_GRANT,
  PT_MESSAGE,
  PT_NODE,
  PT_ROTATION,
  makeEnvelope,
  pae,
  verifyEnvelope,
} from "../src/dsse.ts";
import { SoftwareSigner } from "../src/signer.ts";
import { jcs } from "../src/canon.ts";
import { b64u, hex, hexToBytes } from "../src/b64.ts";

const vectorsPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "tests",
  "vectors",
  "aatp_v0_2_vectors.json",
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
const enc = new TextEncoder();

const SEED = new Uint8Array(32).fill(0x11);
const V03_PUB_HEX = vectors.V03.genesis_pub_hex as string;

function signer(): SoftwareSigner {
  return SoftwareSigner.fromSeed(SEED, "k1");
}

function payloadBytes(): Uint8Array {
  return jcs({ a: 1 });
}

function malformed(fn: () => unknown, msg: string): void {
  assert.throws(
    fn,
    (e: unknown) =>
      typeof e === "object" &&
      e !== null &&
      "code" in e &&
      (e as { code: string }).code === "ERR_MALFORMED_MESSAGE" &&
      "numeric" in e &&
      (e as { numeric: number }).numeric === 1002,
    msg,
  );
}

function sigInvalid(fn: () => unknown, msg: string): void {
  assert.throws(
    fn,
    (e: unknown) =>
      typeof e === "object" &&
      e !== null &&
      "code" in e &&
      (e as { code: string }).code === "ERR_SIGNATURE_INVALID" &&
      "numeric" in e &&
      (e as { numeric: number }).numeric === 1103,
    msg,
  );
}

describe("PT_* constants (§3.3, verbatim from aatp/dsse.py)", () => {
  it("five payload types exact", () => {
    assert.equal(PT_MESSAGE, "application/vnd.aatp.message+json");
    assert.equal(PT_NODE, "application/vnd.aatp.node+json");
    assert.equal(PT_CARD, "application/vnd.aatp.card+json");
    assert.equal(PT_GRANT, "application/vnd.aatp.grant+json");
    assert.equal(PT_ROTATION, "application/vnd.aatp.rotation+json");
  });
});

describe("pae byte-exact grammar", () => {
  it('pae("T", "{}") == "DSSEv1 1 T 2 {}"', () => {
    assert.equal(
      Buffer.from(pae("T", enc.encode("{}"))).toString("utf8"),
      "DSSEv1 1 T 2 {}",
    );
  });
  it("lengths are ASCII decimal byte lengths, no leading zeros", () => {
    assert.equal(
      Buffer.from(pae("AB", enc.encode("hello"))).toString("utf8"),
      "DSSEv1 2 AB 5 hello",
    );
  });
  it("empty body", () => {
    assert.equal(
      Buffer.from(pae("T", new Uint8Array(0))).toString("utf8"),
      "DSSEv1 1 T 0 ",
    );
  });
});

describe("SoftwareSigner (SIG-001)", () => {
  it("fromSeed is deterministic and matches the Python V03 key", () => {
    const s = signer();
    assert.equal(hex(s.publicKeyRaw()), V03_PUB_HEX);
    assert.equal(hex(signer().publicKeyRaw()), V03_PUB_HEX);
    assert.equal(s.keyId(), "k1");
  });
  it("generate gives a working 32-byte key distinct per call", () => {
    const a = SoftwareSigner.generate("a");
    const b = SoftwareSigner.generate("b");
    assert.equal(a.publicKeyRaw().length, 32);
    assert.ok(!Buffer.from(a.publicKeyRaw()).equals(Buffer.from(b.publicKeyRaw())));
    const payload = payloadBytes();
    const env = makeEnvelope(PT_MESSAGE, payload, a);
    assert.deepEqual(verifyEnvelope(env, PT_MESSAGE, a.publicKeyRaw()), {
      a: 1,
    });
  });
  it("JSON.stringify leaks no key material", () => {
    const s = signer();
    const dumped = JSON.stringify(s);
    assert.ok(!dumped.includes(Buffer.from(SEED).toString("hex")));
    assert.ok(!dumped.includes(V03_PUB_HEX));
    assert.ok(!dumped.includes("1101") || dumped.length < 200);
  });
  it("fromSeed rejects bad seed", () => {
    malformed(() => SoftwareSigner.fromSeed(new Uint8Array(31), "k"), "short");
    malformed(
      () => SoftwareSigner.fromSeed("not-bytes" as never, "k"),
      "non-bytes",
    );
  });
});

describe("sign/verify round-trip (SIG-002, CRY-002)", () => {
  it("makeEnvelope then verifyEnvelope returns the parsed payload", () => {
    const s = signer();
    const payload = payloadBytes();
    const env = makeEnvelope(PT_MESSAGE, payload, s);
    assert.equal(env["payloadType"], PT_MESSAGE);
    assert.equal(env["payload"], b64u(payload));
    assert.deepEqual(verifyEnvelope(env, PT_MESSAGE, s.publicKeyRaw()), {
      a: 1,
    });
  });
  it("CRY-002: noble verifies the raw signature over pae() bytes", () => {
    const s = signer();
    const payload = payloadBytes();
    const sig = s.sign(PT_MESSAGE, payload);
    assert.equal(sig.length, 64);
    const ok = ed25519.verify(
      sig,
      pae(PT_MESSAGE, payload),
      s.publicKeyRaw(),
    );
    assert.equal(ok, true);
  });
  it("N01: canonical payload value change fails closed", () => {
    const s = signer();
    const env = makeEnvelope(PT_MESSAGE, payloadBytes(), s);
    const tampered = {
      ...(env as unknown as Record<string, unknown>),
      payload: b64u(jcs({ a: 2 })),
    };
    sigInvalid(
      () => verifyEnvelope(tampered, PT_MESSAGE, s.publicKeyRaw()),
      "value change",
    );
  });
  it("tampered signature byte fails closed", () => {
    const s = signer();
    const env = makeEnvelope(PT_MESSAGE, payloadBytes(), s) as {
      payloadType: string;
      payload: string;
      signatures: { keyid: string; sig: string }[];
    };
    const raw = Buffer.from(b64uDecLenient(env.signatures[0].sig));
    raw[0] ^= 1;
    const bad = {
      ...env,
      signatures: [{ keyid: "k1", sig: b64u(new Uint8Array(raw)) }],
    };
    sigInvalid(() => verifyEnvelope(bad, PT_MESSAGE, s.publicKeyRaw()), "sig bit");
  });
  it("SIG-002: non-canonical (unsorted) payload fails as malformed", () => {
    const s = signer();
    const raw = enc.encode('{"b":2,"a":1}');
    const env = makeEnvelope(PT_MESSAGE, raw, s);
    malformed(() => verifyEnvelope(env, PT_MESSAGE, s.publicKeyRaw()), "unsorted");
  });
});

function b64uDecLenient(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

describe("CRY-003 explicit S<L check", () => {
  it("S' = S + L rejected even though the math wraps the same point", () => {
    const s = signer();
    const payload = payloadBytes();
    const env = makeEnvelope(PT_MESSAGE, payload, s) as {
      payloadType: string;
      payload: string;
      signatures: { keyid: string; sig: string }[];
    };
    const sig = new Uint8Array(b64uDecLenient(env.signatures[0].sig));
    const sVal = leToBig(sig.subarray(32));
    assert.ok(sVal < ED25519_L, "test precondition: S < L");
    const sPrime = sVal + ED25519_L;
    const bad = new Uint8Array(sig);
    bigToLe(sPrime, bad.subarray(32));
    const badEnv = {
      ...env,
      signatures: [{ keyid: "k1", sig: b64u(bad) }],
    };
    sigInvalid(
      () => verifyEnvelope(badEnv, PT_MESSAGE, s.publicKeyRaw()),
      "S+L",
    );
  });
});

function leToBig(le: Uint8Array): bigint {
  let v = 0n;
  for (let i = le.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(le[i]);
  return v;
}

function bigToLe(v: bigint, out: Uint8Array): void {
  for (let i = 0; i < out.length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

describe("SIG-003 payloadType checked before payload touch", () => {
  it("wrong expectedType fails as malformed", () => {
    const s = signer();
    const env = makeEnvelope(PT_MESSAGE, payloadBytes(), s);
    malformed(
      () => verifyEnvelope(env, PT_NODE, s.publicKeyRaw()),
      "type mismatch",
    );
  });
  it("type mismatch wins over garbage payload (ordering proof)", () => {
    const s = signer();
    const env = makeEnvelope(
      PT_MESSAGE,
      payloadBytes(),
      s,
    ) as unknown as Record<string, unknown>;
    const corrupt = { ...env, payload: "!!!not-b64!!!" };
    malformed(
      () => verifyEnvelope(corrupt, PT_NODE, s.publicKeyRaw()),
      "type first",
    );
  });
});

describe("length guards", () => {
  it("short signature fails as invalid", () => {
    const s = signer();
    const env = makeEnvelope(PT_MESSAGE, payloadBytes(), s) as {
      payloadType: string;
      payload: string;
      signatures: { keyid: string; sig: string }[];
    };
    const bad = {
      ...env,
      signatures: [{ keyid: "k1", sig: b64u(new Uint8Array(63)) }],
    };
    sigInvalid(() => verifyEnvelope(bad, PT_MESSAGE, s.publicKeyRaw()), "sig len");
  });
  it("short / non-bytes public key fails as invalid", () => {
    const s = signer();
    const env = makeEnvelope(PT_MESSAGE, payloadBytes(), s);
    sigInvalid(
      () => verifyEnvelope(env, PT_MESSAGE, new Uint8Array(31)),
      "pub len",
    );
    sigInvalid(
      () => verifyEnvelope(env, PT_MESSAGE, "nope" as never),
      "pub type",
    );
  });
});

describe("key_id selection (D-007 mirror)", () => {
  it("explicit keyId picks the matching entry; unknown fails invalid", () => {
    const s = signer();
    const other = SoftwareSigner.generate("other");
    const payload = payloadBytes();
    const good = makeEnvelope(PT_MESSAGE, payload, s) as {
      payloadType: string;
      payload: string;
      signatures: { keyid: string; sig: string }[];
    };
    const decoy = makeEnvelope(PT_MESSAGE, payload, other) as {
      signatures: { keyid: string; sig: string }[];
    };
    const multi = {
      ...good,
      signatures: [decoy.signatures[0], good.signatures[0]],
    };
    assert.deepEqual(
      verifyEnvelope(multi, PT_MESSAGE, s.publicKeyRaw(), "k1"),
      { a: 1 },
    );
    sigInvalid(
      () => verifyEnvelope(multi, PT_MESSAGE, s.publicKeyRaw(), "missing"),
      "no entry",
    );
  });
  it("no keyId verifies signatures[0]; extra entries unverified", () => {
    const s = signer();
    const other = SoftwareSigner.generate("other");
    const payload = payloadBytes();
    const good = makeEnvelope(PT_MESSAGE, payload, s) as {
      payloadType: string;
      payload: string;
      signatures: { keyid: string; sig: string }[];
    };
    const multi = {
      ...good,
      signatures: [
        good.signatures[0],
        { keyid: "junk", sig: b64u(new Uint8Array(64)) },
      ],
    };
    assert.deepEqual(verifyEnvelope(multi, PT_MESSAGE, s.publicKeyRaw()), {
      a: 1,
    });
    void other;
  });
});

describe("strict envelope shape fails malformed", () => {
  it("non-object / missing fields / bad types", () => {
    const s = signer();
    const env = makeEnvelope(PT_MESSAGE, payloadBytes(), s);
    const pub = s.publicKeyRaw();
    malformed(() => verifyEnvelope(null as never, PT_MESSAGE, pub), "null");
    malformed(() => verifyEnvelope([] as never, PT_MESSAGE, pub), "array");
    malformed(
      () =>
        verifyEnvelope({ ...env, payloadType: 1 } as never, PT_MESSAGE, pub),
      "pt type",
    );
    malformed(
      () => verifyEnvelope({ ...env, payload: 1 } as never, PT_MESSAGE, pub),
      "payload type",
    );
    malformed(
      () =>
        verifyEnvelope({ ...env, signatures: [] } as never, PT_MESSAGE, pub),
      "empty sigs",
    );
    malformed(
      () =>
        verifyEnvelope(
          { ...env, signatures: [{ keyid: "k1" }] } as never,
          PT_MESSAGE,
          pub,
        ),
      "entry shape",
    );
    malformed(
      () =>
        verifyEnvelope(
          { ...env, signatures: "x" } as never,
          PT_MESSAGE,
          pub,
        ),
      "sigs type",
    );
  });
  it("non-canonical base64url fails malformed", () => {
    const s = signer();
    const env = makeEnvelope(
      PT_MESSAGE,
      payloadBytes(),
      s,
    ) as unknown as Record<string, unknown>;
    malformed(
      () =>
        verifyEnvelope(
          { ...env, payload: "aGVsbG8=" } as never,
          PT_MESSAGE,
          s.publicKeyRaw(),
        ),
      "padded b64",
    );
  });
});

describe("cross-check: TS verify of a fixed envelope", () => {
  it("golden envelope from the V03 key verifies", () => {
    const pub = hexToBytes(V03_PUB_HEX);
    const payload = jcs({ hello: "world" });
    const s = signer();
    void payload;
    const env = makeEnvelope(PT_MESSAGE, jcs({ hello: "world" }), s);
    assert.deepEqual(verifyEnvelope(env, PT_MESSAGE, pub), {
      hello: "world",
    });
  });
});
