import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, b64uDec, hex } from "../src/b64.ts";

const vectors = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "tests",
      "vectors",
      "aatp_v0_2_vectors.json",
    ),
    "utf8",
  ),
);
const enc = new TextEncoder();

describe("b64u", () => {
  it("V02 hello", () => {
    assert.equal(b64u(enc.encode("hello")), "aGVsbG8");
    assert.equal(b64u(enc.encode("hello")), vectors.V02.b64url_hello);
  });
  it("V02 sha256(hello) via noble", () => {
    assert.equal(hex(sha256(enc.encode("hello"))), vectors.V02.sha256_hello);
  });
  it("round-trips incl. empty", () => {
    assert.deepEqual(b64uDec(""), new Uint8Array(0));
    assert.deepEqual(
      b64uDec(b64u(new Uint8Array([0, 1, 2, 250, 255]))),
      new Uint8Array([0, 1, 2, 250, 255]),
    );
  });
  it("rejects padding", () => {
    assert.throws(() => b64uDec("aGVsbG8="), /MALFORMED/);
  });
  it("rejects length % 4 == 1", () => {
    assert.throws(() => b64uDec("a"), /MALFORMED/);
    assert.throws(() => b64uDec("abcde"), /MALFORMED/);
  });
  it("rejects non-alphabet", () => {
    for (const s of ["a b", "a+b", "a/b", "a=b", "é"]) {
      assert.throws(() => b64uDec(s), /MALFORMED/, JSON.stringify(s));
    }
  });
  it("rejects non-zero trailing bits", () => {
    assert.throws(() => b64uDec("AB"), /MALFORMED/);
    assert.deepEqual(b64uDec("AA"), new Uint8Array([0]));
  });
  it("rejects non-string", () => {
    assert.throws(() => b64uDec(42 as unknown as string), /MALFORMED/);
  });
});

describe("hex", () => {
  it("hello", () => {
    assert.equal(hex(enc.encode("hello")), "68656c6c6f");
  });
});
