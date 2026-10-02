// Artifact model: paths, manifest, content_root, stream (blueprint §6,
// ART-001..007 subset). Fresh logic; constants and grammar copied from
// aatp/artifact.py. Scope: validate + build + stream only (no filesystem
// materialize in TS; see DECISIONS.md).

import { sha256 } from "@noble/hashes/sha2.js";
import { jcs } from "./canon.ts";
import { hex } from "./b64.ts";
import { err } from "./errors.ts";

// Domain constant copied verbatim from aatp/artifact.py (byte-exact ASCII).
export const D_CONTENT: Uint8Array = new TextEncoder().encode(
  "AATP/0.2/CONTENT\n",
);

// ART-006 default limits, copied verbatim from aatp/artifact.py.
export const MAX_PATH_BYTES = 1024;
export const MAX_MANIFEST_ENTRIES = 10000;
export const MAX_TOTAL_ARTIFACT_BYTES = 4294967296;

export interface ManifestEntry {
  path: string;
  size: number;
  x: boolean;
  d: string;
}

export interface Manifest {
  v: string;
  entries: ManifestEntry[];
}

export interface FileInput {
  path: string;
  data: Uint8Array;
  x: boolean;
}

export interface BuildResult {
  manifest: Manifest;
  stream: Uint8Array;
  contentRoot: string;
}

export interface ManifestLimits {
  max_path_bytes?: number;
  max_manifest_entries?: number;
  max_total_artifact_bytes?: number;
}

// Windows reserved basenames, copied verbatim from aatp/artifact.py.
const RESERVED: ReadonlySet<string> = new Set([
  "CON",
  "PRN",
  "AUX",
  "NUL",
  "COM1",
  "COM2",
  "COM3",
  "COM4",
  "COM5",
  "COM6",
  "COM7",
  "COM8",
  "COM9",
  "LPT1",
  "LPT2",
  "LPT3",
  "LPT4",
  "LPT5",
  "LPT6",
  "LPT7",
  "LPT8",
  "LPT9",
]);

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

const enc = new TextEncoder();

function pathInvalid(detail: string): never {
  throw err("ERR_PATH_INVALID", detail);
}

function manifestInvalid(detail: string): never {
  throw err("ERR_MANIFEST_INVALID", detail);
}

// Blueprint ART-004 casefold approximation (recorded in DECISIONS.md): Python
// str.casefold() has no JS equivalent; toLowerCase + ß→ss covers the tested
// pair (Straße/STRASSE). Locale-independent: no locale-sensitive mappings.
export function caseFold(s: string): string {
  return s.toLowerCase().replace(/ß/g, "ss");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  if (a.length === b.length) {
    return 0;
  }
  return a.length < b.length ? -1 : 1;
}

export function validatePath(path: unknown): void {
  // ART-001..003: syntax checks only (length/limits are manifest-level).
  if (typeof path !== "string") {
    pathInvalid("path must be a string");
  }
  const p = path as string;
  // Lone surrogates are not UTF-8 encodable (mirrors Python's encode check
  // plus its explicit surrogate rejection).
  for (let i = 0; i < p.length; i++) {
    const cu = p.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      const next = i + 1 < p.length ? p.charCodeAt(i + 1) : -1;
      if (next < 0xdc00 || next > 0xdfff) {
        pathInvalid("path contains surrogate");
      }
      i++;
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      pathInvalid("path contains surrogate");
    }
  }
  // ART-003: NFC required; reject-not-normalize.
  if (p.normalize("NFC") !== p) {
    pathInvalid("path not NFC-normalized");
  }
  if (p === "") {
    pathInvalid("path empty");
  }
  if (p.startsWith("/") || p.endsWith("/")) {
    pathInvalid("leading or trailing slash");
  }
  if (p.includes("\\")) {
    pathInvalid("backslash forbidden");
  }
  // ART-002 scope mirrors Python: C0 + DEL (U+0000-U+001F, U+007F).
  for (const ch of p) {
    const o = (ch as string).codePointAt(0) as number;
    if (o <= 0x1f || o === 0x7f) {
      pathInvalid("control character in path");
    }
  }
  for (const seg of p.split("/")) {
    if (seg === "" || seg === "." || seg === "..") {
      pathInvalid(`bad segment ${JSON.stringify(seg)}`);
    }
    if (seg.endsWith(" ") || seg.endsWith(".")) {
      pathInvalid("segment ends with space or dot");
    }
    const base = seg.split(".")[0].toUpperCase();
    if (RESERVED.has(base)) {
      pathInvalid(`windows reserved name ${JSON.stringify(seg)}`);
    }
  }
}

interface ResolvedLimits {
  max_path_bytes: number;
  max_manifest_entries: number;
  max_total_artifact_bytes: number;
}

function resolveLimits(limits: ManifestLimits | null | undefined): ResolvedLimits {
  const out: ResolvedLimits = {
    max_path_bytes: MAX_PATH_BYTES,
    max_manifest_entries: MAX_MANIFEST_ENTRIES,
    max_total_artifact_bytes: MAX_TOTAL_ARTIFACT_BYTES,
  };
  if (limits === null || limits === undefined) {
    return out;
  }
  if (typeof limits !== "object" || Array.isArray(limits)) {
    manifestInvalid("limits must be a mapping");
  }
  for (
    const k of [
      "max_path_bytes",
      "max_manifest_entries",
      "max_total_artifact_bytes",
    ] as const
  ) {
    const v = (limits as Record<string, unknown>)[k];
    if (v !== undefined) {
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
        manifestInvalid(`limit ${k} must be an integer >= 0`);
      }
      out[k] = v;
    }
  }
  return out;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return false;
  }
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

export function validateManifest(
  manifest: unknown,
  limits?: ManifestLimits | null,
): void {
  // ART-004..007: shape, path re-validation, collisions, order, limits.
  const lim = resolveLimits(limits);
  if (!isPlainObject(manifest)) {
    manifestInvalid("manifest must be an object");
  }
  const m = manifest as Record<string, unknown>;
  const keys = Object.keys(m);
  if (keys.length !== 2 || !keys.includes("v") || !keys.includes("entries")) {
    manifestInvalid("manifest needs exactly v and entries");
  }
  if (m["v"] !== "0.2") {
    manifestInvalid("manifest v must be 0.2");
  }
  const entries = m["entries"];
  if (!Array.isArray(entries)) {
    manifestInvalid("entries must be a list");
  }
  if (entries.length > lim.max_manifest_entries) {
    manifestInvalid("too many manifest entries");
  }
  const paths: string[] = [];
  let total = 0;
  for (const e of entries) {
    if (!isPlainObject(e)) {
      manifestInvalid("entry needs exactly path/size/x/d");
    }
    const ek = Object.keys(e);
    if (
      ek.length !== 4 || !ek.includes("path") || !ek.includes("size") ||
      !ek.includes("x") || !ek.includes("d")
    ) {
      manifestInvalid("entry needs exactly path/size/x/d");
    }
    const rec = e as Record<string, unknown>;
    const ep = rec["path"];
    if (typeof ep !== "string") {
      pathInvalid("entry path must be a string");
    }
    validatePath(ep);
    if (enc.encode(ep).length > lim.max_path_bytes) {
      manifestInvalid("path exceeds max_path_bytes");
    }
    const size = rec["size"];
    if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) {
      manifestInvalid("entry size must be an integer >= 0");
    }
    if (typeof rec["x"] !== "boolean") {
      manifestInvalid("entry x must be a boolean");
    }
    if (typeof rec["d"] !== "string" || !DIGEST_RE.test(rec["d"] as string)) {
      manifestInvalid("entry d must be sha256:<64 hex>");
    }
    paths.push(ep);
    total += size as number;
  }
  if (total > lim.max_total_artifact_bytes) {
    manifestInvalid("total artifact bytes exceed limit");
  }
  const exactSeen = new Set<string>();
  const foldSeen = new Map<string, string>();
  for (const p of paths) {
    if (exactSeen.has(p)) {
      manifestInvalid(`duplicate path ${JSON.stringify(p)}`);
    }
    const f = caseFold(p);
    const prev = foldSeen.get(f);
    if (prev !== undefined) {
      pathInvalid(`case-fold collision ${JSON.stringify(p)} vs ${JSON.stringify(prev)}`);
    }
    exactSeen.add(p);
    foldSeen.set(f, p);
  }
  const pathSet = new Set(paths);
  for (const p of paths) {
    const segs = p.split("/");
    for (let i = 1; i < segs.length; i++) {
      const prefix = segs.slice(0, i).join("/");
      if (pathSet.has(prefix)) {
        manifestInvalid(`file/dir collision ${JSON.stringify(prefix)} vs ${JSON.stringify(p)}`);
      }
    }
  }
  const raw = paths.map((p) => enc.encode(p));
  for (let i = 0; i + 1 < raw.length; i++) {
    if (compareBytes(raw[i], raw[i + 1]) >= 0) {
      manifestInvalid("entries not in bytewise UTF-8 order");
    }
  }
}

export function build(files: unknown): BuildResult {
  // ART-007/010/011/012: validate, sort bytewise, digest, concat, hash.
  if (!Array.isArray(files)) {
    manifestInvalid("files must be a list");
  }
  const items: { path: string; data: Uint8Array; x: boolean }[] = [];
  for (const item of files as unknown[]) {
    if (
      typeof item !== "object" || item === null || Array.isArray(item) ||
      !("path" in item) || !("data" in item) || !("x" in item)
    ) {
      manifestInvalid("file entry must be {path, data, x}");
    }
    const rec = item as Record<string, unknown>;
    const p = rec["path"];
    if (typeof p !== "string") {
      pathInvalid("path must be a string");
    }
    validatePath(p);
    const data = rec["data"];
    if (!(data instanceof Uint8Array)) {
      manifestInvalid("file data must be bytes");
    }
    if (typeof rec["x"] !== "boolean") {
      manifestInvalid("x must be a boolean");
    }
    items.push({ path: p, data: new Uint8Array(data), x: rec["x"] as boolean });
  }
  const paths = items.map((t) => t.path);
  const exactSeen = new Set<string>();
  const foldSeen = new Map<string, string>();
  for (const p of paths) {
    if (exactSeen.has(p)) {
      manifestInvalid(`duplicate path ${JSON.stringify(p)}`);
    }
    const f = caseFold(p);
    const prev = foldSeen.get(f);
    if (prev !== undefined) {
      pathInvalid(`case-fold collision ${JSON.stringify(p)} vs ${JSON.stringify(prev)}`);
    }
    exactSeen.add(p);
    foldSeen.set(f, p);
  }
  const pathSet = new Set(paths);
  for (const p of paths) {
    const segs = p.split("/");
    for (let i = 1; i < segs.length; i++) {
      if (pathSet.has(segs.slice(0, i).join("/"))) {
        manifestInvalid(`file/dir collision ${JSON.stringify(p)}`);
      }
    }
  }
  if (items.length > MAX_MANIFEST_ENTRIES) {
    manifestInvalid("too many manifest entries");
  }
  for (const t of items) {
    if (enc.encode(t.path).length > MAX_PATH_BYTES) {
      manifestInvalid("path exceeds max_path_bytes");
    }
  }
  if (items.reduce((n, t) => n + t.data.length, 0) > MAX_TOTAL_ARTIFACT_BYTES) {
    manifestInvalid("total artifact bytes exceed limit");
  }
  const keyed = items.map((t) => ({ item: t, raw: enc.encode(t.path) }));
  keyed.sort((a, b) => compareBytes(a.raw, b.raw));
  const ordered = keyed.map((k) => k.item);
  const entries: ManifestEntry[] = ordered.map((t) => ({
    path: t.path,
    size: t.data.length,
    x: t.x,
    d: "sha256:" + hex(sha256(t.data)),
  }));
  const manifest: Manifest = { v: "0.2", entries };
  validateManifest(manifest);
  const stream = concat(ordered.map((t) => t.data));
  const preimage = concat([D_CONTENT, jcs(manifest)]);
  const contentRoot = "sha256:" + hex(sha256(preimage));
  return { manifest, stream, contentRoot };
}

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) {
    n += p.length;
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
