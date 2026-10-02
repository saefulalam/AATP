# AATP M8 TypeScript Second Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Independent TypeScript implementation of the AATP v0.2 wire-critical path that reproduces the shared vectors byte-exact where specified and cross-interoperates with the Python implementation in both directions (blueprint §18.3 M8, freeze criteria minus CRY-007 review).

**Architecture:** Separate npm project in `ts/` (zero imports from `aatp/` Python — independence is the point; may only read `tests/vectors/aatp_v0_2_vectors.json` as test input). Modules mirror Python: `canon.ts`, `errors.ts`, `b64.ts`, `signer.ts`, `dsse.ts`, `ids.ts`, `artifact.ts`, `node.ts`, `chunks.ts`, `seal.ts`. Cross-interop via JSON fixture files in `ts/testdata/` (Python-written) and `tests/testdata-ts/` (TS-written, consumed by a Python test).

**Tech Stack:** Node 24 (native TS type-stripping, no build step; ESM only; no enums/namespaces/decorators in source), `node:test` + `node:assert/strict` (no test framework), pinned deps `@noble/curves`, `@noble/hashes`, `@hpke/core` (exact versions resolved at scaffold time from npm, recorded in `ts/package.json` + `DECISIONS.md`; CRY-001: no hand-rolled primitives).

**Spec:** `docs/superpowers/specs/2026-10-01-aatp-core-m0-m5-design.md`
**Blueprint:** `AATP_v0_2_Blueprint.md` §18.3 M8, App. C vectors

## Global Constraints

- Independence: no Python code, no shared source; only the committed vectors JSON and cross-fixture files cross the boundary.
- Byte-exact where specified: V01 (JCS hex), V02 (sha256/b64u hello), V03 (agent_id), V04 (manifest JCS + stream hex + content_root), V07 (nonces + cts). Behavioral: V06 (sign/verify mechanism + cross-verify), V08 (tamper/reindex fail), V09 (float reject). V05/V06 blueprint hashes UNVERIFIABLE per D-020 — mechanism only, both languages.
- All crypto via vetted libs (CRY-001): noble for Ed25519/SHA-256/ChaCha20-Poly1305/HKDF, `@hpke/core` for HPKE base KEM 0x0020/KDF 0x0001/AEAD 0x0003 (if `@hpke/core` API differs, adapt by inspection, never hand-roll; record in DECISIONS.md).
- Domain constants byte-exact ASCII + `\n`: D_CONTENT, D_NODE, D_AGENT, D_CHUNK, D_PACKET, D_CEKWRAP, D_GRANT (copy verbatim, never retype from memory — read Python `*_*.py` constants or blueprint §3.3).
- Fail closed + `AATPError(code, numeric, detail?)` mirroring Python numeric map (§14).
- Out of scope (recorded, not implemented): card chain verify, transfer state machine, grants/handoff/policy/quarantine/transport/MCP in TS. Rationale: M8 freeze criterion is vectors + wire interop; documented in DECISIONS.md.
- CRY-007 review still OPEN → v1.0 NOT frozen even after M8; no production claim.
- Branch `feat/core-m0-m5`; PowerShell 5.1; Node 24/npm 11; `node_modules/` git-ignored (add to `.gitignore`).

---

### Task M8-1: Scaffold + `canon.ts`/`errors.ts`/`b64.ts` (GEN-010/011, V01/V09)

**Files:**
- Create: `ts/package.json`, `ts/tsconfig.json` (check-only, `module: nodenext`, `strict: true`), `ts/src/canon.ts`, `ts/src/errors.ts`, `ts/src/b64.ts`, `ts/test/canon.test.ts`
- Modify: `.gitignore` (`node_modules/`, `ts/dist/` if used), `DECISIONS.md` (pinned versions)

**Interfaces:**
- Produces: `jcs(obj: unknown): Uint8Array` (throws `AATPError ERR_MALFORMED_MESSAGE`); `parseJcs(data: Uint8Array): unknown`; `AATPError extends Error { code: string; numeric: number; detail?: string }`; `b64u(bytes): string`, `b64uDec(s): Uint8Array` (strict: regex `^[A-Za-z0-9_-]*$`, reject `=` padding and bad trailing bits by re-encode compare).

- [ ] **Step 1: Scaffold + failing tests**

```bash
mkdir ts; npm init -y --prefix ts
npm install --prefix ts @noble/curves @noble/hashes @hpke/core
```

```ts
// ts/test/canon.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { jcs, parseJcs } from "../src/canon.ts";
import { hex } from "../src/b64.ts"; // or inline

describe("V01", () => {
  it("sorts keys byte-exact", () => {
    assert.equal(hex(jcs({ b: 2, a: 1 })), "7b2261223a312c2262223a327d");
  });
});
describe("GEN-010", () => {
  it("rejects float", () => assert.throws(() => jcs({ a: 1.5 }), /MALFORMED/));
});
```

(Full list: V01 hex, V09 float→MALFORMED, non-ASCII key, dup keys via parse, depth>16 + exactly-16 boundary, non-canonical whitespace/unsorted/`\u0041` escape, lone surrogate, |int|>2^53-1, NaN/Infinity.)

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ts/test/canon.test.ts`
Expected: FAIL (module not found)

- [ ] **Step 3: Write minimal implementation**

JCS: `JSON.stringify` with sorted-keys replacer? NO — `JSON.stringify` sorts nothing; implement canonical serializer: sort keys by UTF-16 code unit (ASCII-only keys enforced first, so code-point == code-unit order — validate ASCII before sorting, same argument as Python), `,`/`:` separators, string escaping per RFC 8785 (Python-compatible: `"` `\\` `\b\f\n\r\t`, other controls `\u00xx` lowercase; JS `JSON.stringify` escapes `/`? No, it doesn't; it escapes U+2028/2029 — MUST post-process or custom-escape to match JCS exactly; verify against V04 manifest JCS string from vectors JSON in tests). Numbers: only integers, reject non-integer/unsafe; depth: root 0, >16 reject.

- [ ] **Step 4: Run tests to verify pass**

Run: `node --test ts/test/`
Expected: PASS. Cross-check: TS `jcs` of V04 manifest (from vectors JSON) equals `manifest_jcs` hex in vectors file.

- [ ] **Step 5: Commit**

```bash
git add ts docs DECISIONS.md .gitignore
git commit -m "feat(M8): TS scaffold + JCS canon"
```

---

### Task M8-2: `signer.ts`/`dsse.ts`/`ids.ts` (SIG-001..003, CRY-002/003, ID-001, V03)

**Files:**
- Create: `ts/src/signer.ts`, `ts/src/dsse.ts`, `ts/src/ids.ts`, `ts/test/dsse.test.ts`, `ts/test/ids.test.ts`

**Interfaces:**
- Produces: `SoftwareSigner.fromSeed(seed32: Uint8Array, keyId: string)`, `sign(payloadType: string, payload: Uint8Array): Uint8Array` (signs PAE directly, CRY-002), `publicKeyRaw(): Uint8Array`, `keyId(): string` (private key never exposed, no toJSON leakage — test `JSON.stringify(signer)` contains no key material); `pae(t, b)`, `makeEnvelope(t, payload, signer)`, `verifyEnvelope(env, expectedType, pubRaw, keyId?)` (explicit S<L check before verify regardless of noble behavior, CRY-003 → ERR_SIGNATURE_INVALID); `deriveAgentId(genesisPub32): string`; five `PT_*` constants exact.

- [ ] **Step 1: Write the failing tests**

```ts
// V03: pub d04ab232... -> aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma
// CRY-003: S' = S + L must throw ERR_SIGNATURE_INVALID (L = 2n**252n + 27742317777372353535851937790883648493n)
// CRY-002: verify raw signature over pae() bytes with noble ed25519
// SIG-003: wrong payloadType → ERR_MALFORMED_MESSAGE; N01: canonical payload value change → ERR_SIGNATURE_INVALID
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ts/test/dsse.test.ts ts/test/ids.test.ts`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

noble `ed25519.sign`/`verify` (`@noble/curves/ed25519`); SHA-512 internal to noble, fine. Strict b64u decode shared from `b64.ts`.

- [ ] **Step 4: Run tests to verify pass**

Run: `node --test ts/test/` → PASS

- [ ] **Step 5: Commit**

```bash
git add ts/tests DECISIONS.md
git commit -m "feat(M8): TS DSSE + signer + ids"
```

---

### Task M8-3: `artifact.ts`/`node.ts` (ART-*, PRV-*, V04)

**Files:**
- Create: `ts/src/artifact.ts`, `ts/src/node.ts`, `ts/test/artifact.test.ts`, `ts/test/node.test.ts`

**Interfaces:**
- Produces: `build(files: Array<{path, data: Uint8Array, x: boolean}>) -> { manifest, stream: Uint8Array, contentRoot: string }`; `validateManifest(manifest) -> void`; `makeNode(contentRoot, parents, operation, actor, taskId, generator, now) -> { node, nodeId }`; `nodeIdOf(node)`, `makeNodeEnvelope`, `validateNode`, `class DagStore { add(envelope, keyResolver), ancestryStatus(id) }` (minimal: cycle vs revert, require/lazy, arity, time-skew 120s).

- [ ] **Step 1: Write the failing tests**

V04 byte-exact: files hello.txt/`hello` + bin/run.sh/`echo hi\n`(x) → stream hex `6563686f2068690a68656c6c6f`, content_root `sha256:9067a66c...c1cf`, manifest JCS equals vectors-file string. Path negatives N09–N11 equivalents (dotdot, casefold collision incl. Straße/STRASSE, unsorted manifest). Node: determinism, parents sorted/dedup, arity, revert-accepted vs self-ancestor-cycle (synthetic graph like Python), skew 120/121 boundary. NFC: reject NFD (use `"e\u0301".normalize("NFC")` comparison).

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ts/test/artifact.test.ts ts/test/node.test.ts`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

SHA-256 from `@noble/hashes/sha256`. NFC via `String.prototype.normalize`. Casefold: JS has no `casefold()` — implement blueprint ART-004 via `toLowerCase()` + explicit `ß→ss` mapping? Record approximation in DECISIONS.md: `caseFold(s) = s.toLowerCase().replace(/ß/g, "ss")` plus locale-independent note. Test the Straße pair through it.

- [ ] **Step 4: Run tests to verify pass**

Run: `node --test ts/test/` → PASS

- [ ] **Step 5: Commit**

```bash
git add ts DECISIONS.md
git commit -m "feat(M8): TS artifact + node"
```

---

### Task M8-4: `chunks.ts`/`seal.ts` + bidirectional interop (ENC-*, MSG-01x, V07/V08)

**Files:**
- Create: `ts/src/chunks.ts`, `ts/src/seal.ts`, `ts/test/chunks.test.ts`, `ts/test/seal.test.ts`, `ts/test/interop.test.ts`, `ts/testdata/` (Python-written fixtures, generated by a Python script), `tests/testdata-ts/` (TS-written fixtures), `tests/test_interop.py`
- Modify: `DECISIONS.md`

**Interfaces:**
- Produces: `nonce(i)`, `manifestNonce()`, `aad(cr,i,n,t)`, `encryptChunks(cek, stream, chunkSize, cr, tx): Uint8Array[]`, `decryptOne(cek, index, total, cr, tx, ct): Uint8Array`; `sealPacket(to, toKeyId, recipientPubRaw, envelope)`, `openPacket(packet, keystoreMap)`, `wrapCek(...)`, `unwrapCek(...)`; `KeyStore` minimal class (Map keyId→privKey, open→ERR_DECRYPT_FAILED incl. unknown id).
- Produces (Python): `scripts/export_interop_fixtures.py`? NO new top-level scripts outside plan — put generator as `tests/export_interop_fixtures.py` run manually once, output committed to `ts/testdata/`: `{ sealed_offer_packet, chunks[{index,data_b64}], signed_node_envelope_V03key, wrap_entry, ceK? NO — never export CEK in clear alongside ciphertext in a committed file? The wrap entry lets TS unwrap with the RECIPIENT private key — but then the recipient privkey must also be exported! Fail closed alternative: export fixtures where TS holds the recipient private key generated FRESH in TS? Then TS can't unwrap Python's wrap. Resolution: test-only keypair (fixed seeds, clearly labeled TEST-ONLY in file + DECISIONS.md) whose private keys live in the fixture; these keys are throwaway test vectors, never production. Record in DECISIONS.md. Same for TS→Python direction.

- [ ] **Step 1: Write the failing tests**

```ts
// chunks.test.ts: V07 byte-exact (nonces + both cts with CEK 00..1f, tx_demo1, CR1, 13B stream)
// seal.test.ts: round-trip packet + wrap; tamper → ERR_DECRYPT_FAILED; oversize (>262144) → ERR_SIZE_LIMIT; exact packet keys
// interop.test.ts: open Python-sealed OFFER (ts/testdata/offer.json) with TEST-ONLY recipient key → verify DSSE sig with Python actor pubkey; decrypt Python chunks → reassemble stream → content_root matches; verify Python node envelope signature + nodeId recompute
```

```python
# tests/test_interop.py: load tests/testdata-ts/*.json (written by a TS export step — implementer writes ts/scripts/export-fixtures.ts? Prefer: TS test writes fixtures to tests/testdata-ts/ when env UPDATE_FIXTURES=1, else reads. Simpler binding: TS script tests/export_fixtures.ts run once via node, output committed): open TS-sealed packet with Python KeyStore; verify TS signature with Python verify_envelope; decrypt TS chunks with Python decrypt_one.
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test ts/test/` and `.venv\Scripts\python -m pytest tests/test_interop.py -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

ChaCha20-Poly1305: noble `@noble/ciphers/chacha` (add dep; record). HPKE: `@hpke/core` — inspect API (likely `CipherSuite` + `createSenderContext`/`createRecipientContext` similar to pyhpke; adapt by inspection). Suite KEM DHKEM_X25519 / KDF HKDF_SHA256 / AEAD ChaCha20Poly1305.

- [ ] **Step 4: Run tests to verify pass**

Run: `node --test ts/test/` → PASS; `.venv\Scripts\python -m pytest -q` → all green.

- [ ] **Step 5: Commit**

```bash
git add ts tests DECISIONS.md .gitignore
git commit -m "feat(M8): TS chunks + seal + bidirectional interop"
```

---

## Self-Review Notes (controller fills after writing)

- Freeze criteria coverage: identical vectors (V01–V04, V07 byte-exact; V06/V08/V09 behavioral; V05 per D-020 mechanism) + cross-interop both directions → M8-4.
- No placeholders: versions resolved at scaffold from npm (record actual), API adaptation by inspection.
- TS out-of-scope recorded: card chain, transfer, grants/handoff/policy, quarantine, transport, MCP.
