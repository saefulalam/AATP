import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { jcs, parseJcs } from "../src/canon.ts";
import { hex } from "../src/b64.ts";

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

function nest(depth: number): unknown {
  const root: Record<string, unknown> = {};
  let cur = root;
  for (let i = 0; i < depth; i++) {
    const next: Record<string, unknown> = {};
    cur["x"] = next;
    cur = next;
  }
  return root;
}

describe("V01", () => {
  it("sorts keys byte-exact", () => {
    assert.equal(hex(jcs({ b: 2, a: 1 })), "7b2261223a312c2262223a327d");
  });
  it("matches committed vectors file", () => {
    assert.equal(hex(jcs(vectors.V01.input)), vectors.V01.jcs_hex);
  });
});

describe("V04 manifest cross-check (Python-computed hex)", () => {
  it("jcs of hand-built manifest equals manifest_jcs_hex", () => {
    const manifest = {
      entries: [
        {
          d: "sha256:ab08508fdf5ca4da5c4995987bc41c56c048aaa5eeb046417ae4049b7d40286e",
          path: "bin/run.sh",
          size: 8,
          x: true,
        },
        {
          d: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
          path: "hello.txt",
          size: 5,
          x: false,
        },
      ],
      v: "0.2",
    };
    assert.equal(hex(jcs(manifest)), vectors.V04.manifest_jcs_hex);
  });
  it("vectors manifest bytes parse back to the same object", () => {
    const raw = Buffer.from(vectors.V04.manifest_jcs_hex, "hex");
    const parsed = parseJcs(new Uint8Array(raw)) as {
      entries: unknown[];
      v: string;
    };
    assert.equal(parsed.v, "0.2");
    assert.equal(parsed.entries.length, 2);
    assert.equal(hex(jcs(parsed)), vectors.V04.manifest_jcs_hex);
  });
});

describe("GEN-010 serialize rejects", () => {
  it("V09 float", () => malformed(() => jcs({ a: 1.5 }), "float"));
  it("NaN", () => malformed(() => jcs({ a: NaN }), "NaN"));
  it("Infinity", () => malformed(() => jcs({ a: Infinity }), "Infinity"));
  it("-Infinity", () => malformed(() => jcs({ a: -Infinity }), "-Infinity"));
  it("bigint", () => malformed(() => jcs(10n), "bigint"));
  it("undefined", () => malformed(() => jcs({ a: undefined }), "undefined"));
  it("function", () => malformed(() => jcs({ a: () => 1 }), "function"));
  it("symbol", () => malformed(() => jcs({ a: Symbol("s") }), "symbol"));
  it("symbol key", () =>
    malformed(() => jcs({ [Symbol("k")]: 1 }), "symbol key"));
  it("non-ASCII key", () => malformed(() => jcs({ é: 1 }), "non-ASCII key"));
  it("lone surrogate", () => malformed(() => jcs({ a: "\ud800" }), "lone surrogate"));
  it("int > 2^53-1", () =>
    malformed(() => jcs({ a: 9007199254740992 }), "too big"));
  it("int < -(2^53-1)", () =>
    malformed(() => jcs({ a: -9007199254740992 }), "too small"));
  it("depth > 16 rejected, exactly 16 accepted", () => {
    assert.deepEqual(parseJcs(jcs(nest(16))), nest(16));
    malformed(() => jcs(nest(17)), "depth 17");
  });
  it("scalar inside 16th container rejected", () => {
    const root = nest(16) as Record<string, unknown>;
    let cur = root;
    for (let i = 0; i < 16; i++) cur = cur["x"] as Record<string, unknown>;
    cur["y"] = 1;
    malformed(() => jcs(root), "scalar at depth 17");
  });
});

describe("GEN-011 parse rejects non-canonical", () => {
  it("V09 float text", () =>
    malformed(() => parseJcs(enc.encode('{"a":1.5}')), "V09"));
  it("whitespace", () =>
    malformed(() => parseJcs(enc.encode('{ "a": 1 }')), "whitespace"));
  it("trailing newline", () =>
    malformed(() => parseJcs(enc.encode('{"a":1}\n')), "newline"));
  it("unsorted keys", () =>
    malformed(() => parseJcs(enc.encode('{"b":2,"a":1}')), "unsorted"));
  it("\\u0041 escape", () =>
    malformed(() => parseJcs(enc.encode('{"\\u0041":1}')), "escape"));
  it("escaped slash", () =>
    malformed(() => parseJcs(enc.encode('{"a":"\\/"}')), "slash escape"));
  it("duplicate keys same value", () =>
    malformed(() => parseJcs(enc.encode('{"a":1,"a":1}')), "dup same"));
  it("duplicate keys different value", () =>
    malformed(() => parseJcs(enc.encode('{"a":1,"a":2}')), "dup diff"));
  it("-0", () => malformed(() => parseJcs(enc.encode("-0")), "-0"));
  it("1.0", () => malformed(() => parseJcs(enc.encode('{"a":1.0}')), "1.0"));
  it("exponent", () =>
    malformed(() => parseJcs(enc.encode('{"a":1e2}')), "exponent"));
  it("lone surrogate escape", () =>
    malformed(() => parseJcs(enc.encode('{"a":"\\ud800"}')), "surrogate"));
  it("invalid UTF-8", () =>
    malformed(() => parseJcs(new Uint8Array([0xff])), "bad utf8"));
  it("not JSON", () =>
    malformed(() => parseJcs(enc.encode("nope")), "not json"));
  it("deep nesting rejected", () => {
    const ok = '{"x":'.repeat(16) + "{}" + "}".repeat(16);
    assert.deepEqual(parseJcs(enc.encode(ok)), nest(16));
    const bad = '{"x":'.repeat(17) + "{}" + "}".repeat(17);
    malformed(() => parseJcs(enc.encode(bad)), "parse depth 17");
  });
});

describe("JCS string escaping (RFC 8785 subset)", () => {
  it("short escapes and lowercase \\u00xx", () => {
    assert.equal(
      Buffer.from(jcs({ a: '"\\\b\f\n\r\t\x00\x1f/' })).toString("utf8"),
      '{"a":"\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f/"}',
    );
  });
  it("U+2028/2029 raw (JSON.stringify would escape)", () => {
    assert.equal(hex(jcs({ a: " " })), hex(enc.encode('{"a":" "}')));
    assert.equal(hex(jcs({ a: " " })), hex(enc.encode('{"a":" "}')));
    assert.ok(!hex(jcs({ a: " " })).includes("32303238"));
  });
  it("-0 serializes as 0", () => {
    assert.equal(Buffer.from(jcs(-0)).toString("utf8"), "0");
    assert.equal(Buffer.from(jcs({ a: -0 })).toString("utf8"), '{"a":0}');
  });
  it("scalars round-trip", () => {
    assert.equal(Buffer.from(jcs(null)).toString("utf8"), "null");
    assert.equal(Buffer.from(jcs(true)).toString("utf8"), "true");
    assert.equal(
      Buffer.from(jcs(9007199254740991)).toString("utf8"),
      "9007199254740991",
    );
    assert.deepEqual(parseJcs(jcs([1, "a", null, true, {}])), [
      1,
      "a",
      null,
      true,
      {},
    ]);
  });
});
