// Canonical JSON (GEN-010/011/012): RFC 8785 JCS restricted subset.
// Mirrors aatp/canon.py: ASCII-only object keys, integers only with
// |n| <= 2^53-1 (no floats), max nesting depth 16 (root is depth 0).
// Every failure raises AATPError(ERR_MALFORMED_MESSAGE).
//
// Custom serializer (JSON.stringify is unsuitable: it does not sort keys and
// escapes U+2028/U+2029, neither of which is JCS). Keys are validated ASCII
// BEFORE sorting, so UTF-16 code-unit order equals code-point order.
//
// Parsing never repairs: input must equal jcs(parsed) byte-for-byte
// (GEN-011). This single round-trip byte check rejects ALL non-canonical
// forms without special-case code, including:
//   whitespace / trailing newline / BOM, unsorted keys, unnecessary escapes
//   (\u0041, \/, escaped surrogate pairs), -0, 1.0 / 1e2 / any
//   fraction-or-exponent number, NaN / Infinity (invalid JSON), and
//   DUPLICATE KEYS: JSON.parse collapses dupes silently, but the collapsed
//   object re-serializes to fewer bytes than the dupe-carrying input, so the
//   byte compare always differs. No reviver or tokenizer is needed.

import { AATPError, err } from "./errors.ts";

export const MAX_DEPTH = 16;
export const MAX_SAFE_INT = 2 ** 53 - 1;

const ASCII_RE = /^[\x00-\x7f]*$/;

function bad(detail: string): AATPError {
  return err("ERR_MALFORMED_MESSAGE", detail);
}

function isAscii(s: string): boolean {
  return ASCII_RE.test(s);
}

// TextEncoder replaces lone surrogates with U+FFFD instead of failing, so
// scan UTF-16 code units explicitly (matches Python's UTF-8 encode check).
function checkStr(s: string, what: string): void {
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
      if (next < 0xdc00 || next > 0xdfff) {
        throw bad(`${what} not encodable as UTF-8 (lone surrogate)`);
      }
      i++;
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      throw bad(`${what} not encodable as UTF-8 (lone surrogate)`);
    }
  }
}

function typeName(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  const t = typeof v;
  if (t === "object") {
    return (v as object).constructor?.name ?? "object";
  }
  return t;
}

function validate(obj: unknown, depth = 0): void {
  if (depth > MAX_DEPTH) {
    throw bad(`nesting depth > ${MAX_DEPTH}`);
  }
  if (obj === null || typeof obj === "boolean") {
    return;
  }
  if (typeof obj === "number") {
    // One check covers floats, NaN, ±Infinity and unsafe magnitudes:
    // none of them are safe integers. -0 IS a safe integer and serializes
    // as "0"; a "-0" parse is still rejected by the round-trip compare.
    if (!Number.isSafeInteger(obj)) {
      throw bad(
        Number.isInteger(obj)
          ? "integer magnitude exceeds 2^53-1"
          : "floating-point numbers forbidden",
      );
    }
    return;
  }
  if (typeof obj === "string") {
    checkStr(obj, "string");
    return;
  }
  if (Array.isArray(obj)) {
    for (const v of obj) {
      validate(v, depth + 1);
    }
    return;
  }
  if (typeof obj === "object") {
    const proto = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
      throw bad(`unsupported type ${typeName(obj)}`);
    }
    // Reflect.ownKeys (not Object.keys) so symbol keys are seen and rejected:
    // JSON has no symbol keys and silently dropping them would be repair.
    for (const k of Reflect.ownKeys(obj)) {
      if (typeof k !== "string") {
        throw bad(`object key must be str, got ${typeof k}`);
      }
      if (!isAscii(k)) {
        throw bad("non-ASCII object key");
      }
      checkStr(k, "object key");
      validate((obj as Record<string, unknown>)[k], depth + 1);
    }
    return;
  }
  // bigint, undefined, function, symbol: JSON has no such values.
  throw bad(`unsupported type ${typeName(obj)}`);
}

// Escape set exactly: '"' '\\' \b \f \n \r \t, other C0 controls as \u00xx
// lowercase; raw characters otherwise. No '/' escaping, no U+2028/2029
// escaping. Surrogate pairs pass through as raw units (lone surrogates were
// already rejected by validate, so TextEncoder will encode them correctly).
function escapeStr(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu === 0x22) {
      out += '\\"';
    } else if (cu === 0x5c) {
      out += "\\\\";
    } else if (cu === 0x08) {
      out += "\\b";
    } else if (cu === 0x0c) {
      out += "\\f";
    } else if (cu === 0x0a) {
      out += "\\n";
    } else if (cu === 0x0d) {
      out += "\\r";
    } else if (cu === 0x09) {
      out += "\\t";
    } else if (cu < 0x20) {
      out += "\\u00" + (cu < 16 ? "0" : "") + cu.toString(16);
    } else {
      out += s[i];
    }
  }
  return out + '"';
}

function serialize(obj: unknown): string {
  if (obj === null) {
    return "null";
  }
  if (obj === true) {
    return "true";
  }
  if (obj === false) {
    return "false";
  }
  if (typeof obj === "number") {
    // Validated safe integer; String(-0) === "0" (JCS has no -0).
    return String(obj);
  }
  if (typeof obj === "string") {
    return escapeStr(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(serialize).join(",") + "]";
  }
  const rec = obj as Record<string, unknown>;
  // ASCII-only keys enforced by validate before this default UTF-16 sort.
  const keys = Object.keys(rec).sort();
  return (
    "{" +
    keys.map((k) => escapeStr(k) + ":" + serialize(rec[k])).join(",") +
    "}"
  );
}

function depthGuard(e: unknown): never {
  if (e instanceof AATPError) {
    throw e;
  }
  // Hostile nesting can overflow the call stack instead of reaching the
  // depth counter (mirrors Python mapping RecursionError -> MALFORMED).
  if (e instanceof RangeError) {
    throw bad(`nesting depth > ${MAX_DEPTH}`);
  }
  throw e;
}

export function jcs(obj: unknown): Uint8Array {
  try {
    validate(obj);
    return new TextEncoder().encode(serialize(obj));
  } catch (e) {
    throw depthGuard(e);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

export function parseJcs(data: Uint8Array): unknown {
  if (!(data instanceof Uint8Array)) {
    throw bad(`expected bytes, got ${typeName(data)}`);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    throw bad("invalid UTF-8");
  }
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    if (e instanceof RangeError) {
      throw bad(`nesting depth > ${MAX_DEPTH}`);
    }
    throw bad(
      `invalid JSON: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  try {
    validate(obj);
  } catch (e) {
    throw depthGuard(e);
  }
  if (!bytesEqual(jcs(obj), data)) {
    throw bad("not in canonical form");
  }
  return obj;
}
