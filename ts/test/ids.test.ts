import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { deriveAgentId } from "../src/ids.ts";
import { hexToBytes } from "../src/b64.ts";

const vectorsPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "tests",
  "vectors",
  "aatp_v0_2_vectors.json",
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

describe("V03 agent_id (ID-001)", () => {
  it("pub d04ab232... derives the committed agent_id", () => {
    const pub = hexToBytes(vectors.V03.genesis_pub_hex as string);
    assert.equal(
      deriveAgentId(pub),
      "aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma",
    );
  });
  it("matches the vectors file value", () => {
    const pub = hexToBytes(vectors.V03.genesis_pub_hex as string);
    assert.equal(deriveAgentId(pub), vectors.V03.agent_id);
  });
  it("shape is aatp: + 52 lowercase base32 chars", () => {
    const pub = hexToBytes(vectors.V03.genesis_pub_hex as string);
    assert.match(deriveAgentId(pub), /^aatp:[a-z2-7]{52}$/);
  });
  it("deterministic and key-sensitive", () => {
    const pub = hexToBytes(vectors.V03.genesis_pub_hex as string);
    assert.equal(deriveAgentId(pub), deriveAgentId(pub));
    const other = new Uint8Array(pub);
    other[0] ^= 1;
    assert.notEqual(deriveAgentId(pub), deriveAgentId(other));
  });
  it("bad key fails malformed", () => {
    assert.throws(
      () => deriveAgentId(new Uint8Array(31)),
      (e: unknown) =>
        typeof e === "object" &&
        e !== null &&
        "code" in e &&
        (e as { code: string }).code === "ERR_MALFORMED_MESSAGE",
      "short",
    );
    assert.throws(
      () => deriveAgentId(new Uint8Array(33)),
      (e: unknown) =>
        typeof e === "object" &&
        e !== null &&
        "code" in e &&
        (e as { code: string }).code === "ERR_MALFORMED_MESSAGE",
      "long",
    );
    assert.throws(
      () => deriveAgentId("nope" as never),
      (e: unknown) =>
        typeof e === "object" &&
        e !== null &&
        "code" in e &&
        (e as { code: string }).code === "ERR_MALFORMED_MESSAGE",
      "non-bytes",
    );
  });
});
