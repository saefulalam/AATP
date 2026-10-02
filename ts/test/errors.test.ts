import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AATPError, ERROR_REGISTRY, err } from "../src/errors.ts";

describe("errors", () => {
  it("registry numbers match Python aatp/errors.py", () => {
    assert.equal(ERROR_REGISTRY["ERR_MALFORMED_MESSAGE"], 1002);
    assert.equal(ERROR_REGISTRY["ERR_PROTOCOL_VERSION"], 1001);
    assert.equal(ERROR_REGISTRY["ERR_SIGNATURE_INVALID"], 1103);
    assert.equal(ERROR_REGISTRY["ERR_DECRYPT_FAILED"], 1111);
    assert.equal(ERROR_REGISTRY["ERR_CHUNK_AUTH_FAILED"], 1303);
    assert.equal(ERROR_REGISTRY["ERR_INTERNAL"], 9000);
  });
  it("AATPError shape", () => {
    const e = err("ERR_MALFORMED_MESSAGE", "detail here");
    assert.ok(e instanceof Error);
    assert.ok(e instanceof AATPError);
    assert.equal(e.code, "ERR_MALFORMED_MESSAGE");
    assert.equal(e.numeric, 1002);
    assert.equal(e.detail, "detail here");
    assert.match(e.message, /ERR_MALFORMED_MESSAGE/);
  });
  it("unknown code falls back to ERR_INTERNAL", () => {
    const e = err("ERR_NOPE");
    assert.equal(e.code, "ERR_NOPE");
    assert.equal(e.numeric, 9000);
    assert.equal(e.detail, undefined);
  });
});
