import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { jcs } from "../src/canon.ts";
import { hex } from "../src/b64.ts";
import {
  build,
  validateManifest,
  validatePath,
  D_CONTENT,
} from "../src/artifact.ts";

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
const b = (s: string): Uint8Array => enc.encode(s);

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.equal(typeof e, "object");
    assert.notEqual(e, null);
    return (e as { code: string }).code;
  }
  assert.fail("expected throw");
}

function numericOf(fn: () => unknown): number {
  try {
    fn();
  } catch (e) {
    return (e as { numeric: number }).numeric;
  }
  assert.fail("expected throw");
}

describe("ART-001..003 validatePath", () => {
  it("accepts simple relative paths", () => {
    validatePath("hello.txt");
    validatePath("bin/run.sh");
    validatePath("a.b/c d/e_f-g.h");
  });
  it("rejects empty, leading/trailing slash, backslash", () => {
    assert.equal(codeOf(() => validatePath("")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("/a")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("a/")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("a\\b")), "ERR_PATH_INVALID");
  });
  it("rejects empty segments, dot and dotdot", () => {
    for (const p of ["a//b", "a/./b", "a/../b", ".", "..", "a/.", "a/.."]) {
      assert.equal(codeOf(() => validatePath(p)), "ERR_PATH_INVALID", p);
    }
  });
  it("rejects NUL, C0 controls and DEL", () => {
    assert.equal(codeOf(() => validatePath("a\x00b")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("a\x01b")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("a\x1fb")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("a\x7fb")), "ERR_PATH_INVALID");
  });
  it("rejects non-NFC, accepts NFC", () => {
    assert.equal(codeOf(() => validatePath("é")), "ERR_PATH_INVALID");
    validatePath("é");
  });
  it("rejects trailing space/dot segments, allows interior", () => {
    assert.equal(codeOf(() => validatePath("dir /f")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("dir/f ")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("dir/f.")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath("dir./f")), "ERR_PATH_INVALID");
    validatePath("a.b/c d/e");
  });
  it("rejects Windows reserved names case-insensitive with extension", () => {
    for (const p of ["CON", "con", "con.txt", "PRN", "AUX", "NUL.json", "COM1", "com9.log", "Lpt9", "sub/CON", "sub/com1/x"]) {
      assert.equal(codeOf(() => validatePath(p)), "ERR_PATH_INVALID", p);
    }
    validatePath("console");
    validatePath("contact.txt");
    validatePath("com10");
  });
  it("rejects lone surrogates and non-strings", () => {
    assert.equal(codeOf(() => validatePath("\ud800")), "ERR_PATH_INVALID");
    assert.equal(codeOf(() => validatePath(7 as never)), "ERR_PATH_INVALID");
  });
  it("ERR_PATH_INVALID numeric is 1307", () => {
    assert.equal(numericOf(() => validatePath("")), 1307);
  });
});

describe("V04 byte-exact (ART-007/010/011/012)", () => {
  const files = [
    { path: "hello.txt", data: b("hello"), x: false },
    { path: "bin/run.sh", data: b("echo hi\n"), x: true },
  ];
  it("D_CONTENT is byte-exact ASCII", () => {
    assert.equal(Buffer.from(D_CONTENT).toString("hex"), Buffer.from("AATP/0.2/CONTENT\n").toString("hex"));
  });
  it("stream hex matches vectors (bin/run.sh first)", () => {
    const { stream } = build(files);
    assert.equal(hex(stream), vectors.V04.stream_hex);
    assert.equal(hex(stream), "6563686f2068690a68656c6c6f");
  });
  it("manifest JCS matches vectors hex byte-exact", () => {
    const { manifest } = build(files);
    assert.equal(hex(jcs(manifest)), vectors.V04.manifest_jcs_hex);
  });
  it("manifest deep-equals the vectors manifest", () => {
    const { manifest } = build(files);
    const expected = JSON.parse(
      Buffer.from(vectors.V04.manifest_jcs_hex as string, "hex").toString("utf8"),
    );
    assert.deepEqual(manifest, expected);
  });
  it("content_root matches vectors", () => {
    const { contentRoot } = build(files);
    assert.equal(contentRoot, vectors.V04.content_root);
    assert.equal(contentRoot, "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf");
  });
  it("content_root recomputes independently (D_CONTENT + JCS)", () => {
    const { manifest, contentRoot } = build(files);
    const pre = new Uint8Array([...D_CONTENT, ...jcs(manifest)]);
    assert.equal("sha256:" + hex(sha256(pre)), contentRoot);
  });
  it("input order does not matter; entries sorted bytewise", () => {
    const { manifest } = build([...files].reverse());
    assert.deepEqual(
      (manifest as { entries: { path: string }[] }).entries.map((e) => e.path),
      ["bin/run.sh", "hello.txt"],
    );
  });
  it("d digests and sizes are exact", () => {
    const { manifest } = build(files);
    const m = manifest as {
      entries: { path: string; size: number; x: boolean; d: string }[];
    };
    const hello = m.entries.find((e) => e.path === "hello.txt");
    assert.equal(hello?.size, 5);
    assert.equal(hello?.x, false);
    assert.equal(hello?.d, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
});

describe("ART-004..007 validateManifest + build negatives", () => {
  function goodManifest(): { v: string; entries: { path: string; size: number; x: boolean; d: string }[] } {
    return {
      v: "0.2",
      entries: [
        { path: "bin/run.sh", size: 8, x: true, d: "sha256:" + "0".repeat(64) },
        { path: "hello.txt", size: 5, x: false, d: "sha256:" + "1".repeat(64) },
      ],
    };
  }
  it("accepts a well-formed sorted manifest", () => {
    validateManifest(goodManifest());
  });
  it("rejects unsorted entries", () => {
    const m = goodManifest();
    m.entries.reverse();
    assert.equal(codeOf(() => validateManifest(m)), "ERR_MANIFEST_INVALID");
  });
  it("rejects exact duplicates", () => {
    const m = goodManifest();
    m.entries = [m.entries[0], m.entries[0]];
    assert.equal(codeOf(() => validateManifest(m)), "ERR_MANIFEST_INVALID");
    assert.equal(
      codeOf(() => build([
        { path: "x", data: b("a"), x: false },
        { path: "x", data: b("b"), x: false },
      ])),
      "ERR_MANIFEST_INVALID",
    );
  });
  it("rejects casefold collisions incl. Strasse pair", () => {
    const m = goodManifest();
    (m as { entries: { path: string; size: number; x: boolean; d: string }[] }).entries = [
      { path: "a.txt", size: 1, x: false, d: "sha256:" + "0".repeat(64) },
      { path: "A.TXT", size: 1, x: false, d: "sha256:" + "1".repeat(64) },
    ];
    assert.equal(codeOf(() => validateManifest(m)), "ERR_PATH_INVALID");
    assert.equal(
      codeOf(() => build([
        { path: "Straße", data: b("a"), x: false },
        { path: "STRASSE", data: b("b"), x: false },
      ])),
      "ERR_PATH_INVALID",
    );
  });
  it("rejects file/dir prefix collisions", () => {
    assert.equal(
      codeOf(() => build([
        { path: "a", data: b("x"), x: false },
        { path: "a/b", data: b("y"), x: false },
      ])),
      "ERR_MANIFEST_INVALID",
    );
  });
  it("rejects dotdot through build", () => {
    assert.equal(
      codeOf(() => build([{ path: "a/../b", data: b("x"), x: false }])),
      "ERR_PATH_INVALID",
    );
  });
  it("rejects bad shape, v, entry keys, d, size, x", () => {
    assert.equal(codeOf(() => validateManifest("nope" as never)), "ERR_MANIFEST_INVALID");
    assert.equal(codeOf(() => validateManifest({ v: "0.2" } as never)), "ERR_MANIFEST_INVALID");
    assert.equal(codeOf(() => validateManifest({ v: "0.3", entries: [] } as never)), "ERR_MANIFEST_INVALID");
    assert.equal(codeOf(() => validateManifest({ v: "0.2", entries: {} } as never)), "ERR_MANIFEST_INVALID");
    const m = goodManifest();
    (m.entries[0] as Record<string, unknown>)["extra"] = 1;
    assert.equal(codeOf(() => validateManifest(m)), "ERR_MANIFEST_INVALID");
    const m2 = goodManifest();
    m2.entries[0].d = "sha256:xyz";
    assert.equal(codeOf(() => validateManifest(m2)), "ERR_MANIFEST_INVALID");
    const m3 = goodManifest();
    m3.entries[0].size = -1;
    assert.equal(codeOf(() => validateManifest(m3)), "ERR_MANIFEST_INVALID");
    const m4 = goodManifest();
    (m4.entries[0] as unknown as Record<string, unknown>).x = 1;
    assert.equal(codeOf(() => validateManifest(m4)), "ERR_MANIFEST_INVALID");
    assert.equal(
      codeOf(() => build([{ path: "x", data: b("a"), x: 1 as never }])),
      "ERR_MANIFEST_INVALID",
    );
  });
  it("rejects build entries with extra keys", () => {
    assert.equal(
      codeOf(() => build([{ path: "a.txt", data: b("x"), x: false, extra: 1 }] as never)),
      "ERR_MANIFEST_INVALID",
    );
  });
  it("rejects overlong paths and too many entries", () => {
    assert.equal(
      codeOf(() => build([{ path: "a".repeat(1025), data: b("x"), x: false }])),
      "ERR_MANIFEST_INVALID",
    );
    const many = Array.from({ length: 10001 }, (_, i) => ({
      path: `f${i}`,
      data: b("x"),
      x: false as boolean,
    }));
    assert.equal(codeOf(() => build(many)), "ERR_MANIFEST_INVALID");
  });
  it("rejects total bytes over a custom limit", () => {
    const m = goodManifest();
    assert.equal(
      codeOf(() => validateManifest(m, { max_total_artifact_bytes: 5 })),
      "ERR_MANIFEST_INVALID",
    );
  });
  it("ERR_MANIFEST_INVALID numeric is 1308", () => {
    assert.equal(numericOf(() => validateManifest("nope" as never)), 1308);
  });
});
