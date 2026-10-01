# DECISIONS

Gaps, ambiguities and implementation choices (blueprint §0.4). One entry per decision.

## D-001: HPKE library = pyhpke 0.6.5 (RFC 9180 gate PASSED)

- Library: `pyhpke==0.6.5` (with `cryptography` 50.0.2). Suite: KEM 0x0020 / KDF 0x0001 / AEAD 0x0003, base mode.
- Gate vector: RFC 9180 Appendix A.2.1 (Base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305). The plan called it "A.1.1", but A.1.x is AES-128-GCM.
- Result: PASS (`tests/test_hpke_spike.py`).
  - Recipient: all 257 vector encryptions open to the vector plaintexts.
  - Sender KAT: with the ephemeral derived from `ikmE`, `enc` and `ct[0]` match the vector byte-exact.
  - Fresh random-ephemeral seal/open round-trip works.
- API constraint: in pyhpke 0.6.5, single-shot `CipherSuite.seal/open` raise `NotImplementedError`. M4 must use `create_sender_context` / `create_recipient_context` + `ctx.seal(pt, aad)` / `ctx.open(ct, aad)`.
- Vector file: `tests/vectors/rfc9180_hpke.json` contains only the filtered entry (mode 0, kem 32, kdf 1, aead 3) from the official set at
  `https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json` (full file 5.9 MB, sha256 `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`). The entry is unmodified.

## D-002: JCS nesting depth counting (GEN-010 "max nesting depth 16")

- The blueprint does not say how depth is counted. Convention: the top-level value is depth 0; each value directly inside an object/array is one deeper than its container. Any value (container or scalar) at depth > 16 is rejected with `ERR_MALFORMED_MESSAGE`.
- Effect: root object + 16 nested containers (`{"x":` ×16 around `{}`) is accepted; a 17th nested container, or a scalar inside the 16th nested container, is rejected.
- Parser: Python `RecursionError` from pathological nesting maps to `ERR_MALFORMED_MESSAGE` too.

## D-003: Strict JCS round-trip parsing (GEN-011)

- `parse_jcs` accepts input only if `jcs(parsed) == input` byte-for-byte. Rejects, among others: whitespace, trailing newline, BOM, unsorted keys, unnecessary escapes (`\u0041`, `\/`, escaped surrogate pairs), `-0`, any fraction/exponent number (incl. `1.0`), `NaN`/`Infinity`.
- Lone surrogate strings/keys (`"\ud800"`) cannot be encoded as UTF-8 and are rejected in both `jcs` and `parse_jcs`.
- Integer literals longer than 17 chars are rejected before `int()` so Python's int-string-length limit cannot surface as a raw exception.

## D-004: Ed25519 strict mode (CRY-003)

- `cryptography` 50.0.2 (OpenSSL) already rejects S' = S + L natively (probe: `test_CRY003_reject_noncanonical_signature` passed before any explicit check).
- To keep one strict mode independent of the backend, `verify_envelope` also checks `int.from_bytes(sig[32:], "little") < L` before calling verify. Failure: `ERR_SIGNATURE_INVALID`. All other checks (point decoding, small-order/non-canonical `R`/`A`) are whatever RFC 8032 verification `cryptography` performs; all AATP signature verification goes through `aatp.dsse.verify_envelope`.

## D-005: payloadType mismatch error code (SIG-003)

- The blueprint names no code for a wrong `payloadType`. Using `ERR_MALFORMED_MESSAGE` (closest match). The type is checked before the payload is decoded or parsed.

## D-006: Strict DSSE envelope parsing

- Any shape violation maps to `ERR_MALFORMED_MESSAGE`, never a raw Python exception: envelope not an object; `payloadType`/`payload` missing or not strings; `signatures` not a non-empty list; any signature entry not an object with string `keyid` and `sig`.
- base64url (GEN-003, `aatp/b64.py`): only `[A-Za-z0-9_-]`, no `=` padding, length mod 4 != 1, and the decoded bytes must re-encode to the same string (rejects non-zero trailing bits). Violations: `ERR_MALFORMED_MESSAGE`.
- Signature length != 64 bytes or public key not 32 bytes: `ERR_SIGNATURE_INVALID`.
- Check order: payloadType, envelope shape, base64url, JCS (SIG-002), lengths, S < L, Ed25519 verify.

## D-007: Signature selection

- `verify_envelope(env, expected_payload_type, public_key_raw, key_id=None)` verifies exactly one entry: the first with `keyid == key_id` (none: `ERR_SIGNATURE_INVALID`), or `signatures[0]` when `key_id` is None. Other entries are not verified here; multi-signature / counter-signatures are PRV-023 (M6+).

## D-008: Card verification error-code mapping (ID-*, Task 3)

- The blueprint names codes for rollback (`ERR_CARD_ROLLBACK`), commitment (`ERR_KEY_COMMITMENT_MISMATCH`), revoked keys (`ERR_KEY_REVOKED`) and suites (`ERR_SUITE_UNSUPPORTED`), but not for the other `verify_card` failures. Mapping used: `v != "0.2"` (card/rotation/revocation) → `ERR_PROTOCOL_VERSION`; suites missing `AATP-S1` → `ERR_SUITE_UNSUPPORTED`; every shape/type/timestamp-format failure → `ERR_MALFORMED_MESSAGE`; `agent_id` ≠ derived-from-genesis (ID-001) or ≠ pin → `ERR_AUTH_FAILED`; rotation `from_key_id`/final-key chain breaks → `ERR_SIGNATURE_INVALID`; card validity length > 30d (ID-013) or `now` outside `[issued_at, expires_at]` ± skew → `ERR_MESSAGE_EXPIRED`; key windows (`not_before`/`not_after` ± skew, ID-014) and `enc_key` length > 7d / window miss (ID-012) → `ERR_KEY_EXPIRED`.
- `pinned_agent_id=None` → `ERR_AUTH_FAILED` (ID-004 deny-by-default; only `pinned` mode is implemented in M1, `org_attested`/`did` are M6+). Callers with another trust basis pass the expected id explicitly.

## D-009: Genesis key_id is inferred (ID-021, Task 3)

- The Card schema stores `genesis_public_key` but no genesis `key_id`. `verify_card` infers it as `key_history[0].from_key_id` when history is non-empty, else the current `signing_key.key_id`. The first hop's `from` check is therefore tautological; its security comes from the signature check against the genesis public key. A genesis card (empty history) additionally requires `signing_key.public_key == genesis_public_key`.

## D-010: Revocation by the next-commitment key (ID-023, Task 3)

- The blueprint does not say how the verifier obtains the next key's public key. `make_revocation` accepts optional `public_key_raw32` (emitted as `public_key` b64url, an allowed unknown-optional field per GEN-012) and `verify_card` uses it only on the second path: current-key verification is tried first (strict `key_id` binding); on `ERR_SIGNATURE_INVALID` it requires `sha256(public_key) == active commitment` and verifies `signatures[0]` with it. Without a matching `public_key` the second path fails closed with `ERR_SIGNATURE_INVALID`.
- Active commitment = `card.next_commitment` if present else the last rotation's `next_commitment` (no equality required between the two, so a card may publish fresh pre-rotation without a new history entry).

## D-011: Revocation envelope carries `v: "0.2"` (Task 3)

- Blueprint §4.4 shows rotation with `"v":"0.2"` but revocation without it (abbreviated shape). `make_revocation` includes `"v":"0.2"` and `verify_card` gates it with `ERR_PROTOCOL_VERSION`, consistent with rotation handling.

## D-012: Revocation timing checks (ID-024, Task 3)

- `verify_card` rejects a card whose *current* signing key is revoked with `effective_at <= now` (`ERR_KEY_REVOKED`). `check_key_not_revoked(card, key_id, created_at)` (for M5 message checks) raises `ERR_KEY_REVOKED` iff some entry matches `key_id` with `effective_at <= created_at`; it trusts `verify_card` output and does not re-verify revocation signatures — callers must pass verified cards. The "created before revocation but received after learning of it" policy exception is M5 policy scope; M1 implements the strict comparison.

## D-013: Task 2 follow-up confined to Task 3 (non-dict payloads)

- `verify_envelope` (Task 2) can return scalar payloads. `aatp/card.py` requires `dict` after every card/rotation/revocation verification (`ERR_MALFORMED_MESSAGE` otherwise). `aatp/dsse.py` is untouched; a global non-object rejection stays a Task 2 follow-up (ledger T2-2).

## D-014: Vectors in Task 3 (V03 now; node1/V06 deferred)

- `reference_vectors.py` now emits V03 (`genesis_pub_hex`, `agent_id`, asserted against Appendix C). The brief's Step 6 also mentions node1 JCS + V06, but those need M3 `node.make` output; they stay deferred to the Task 9 vector consolidation (with ledger T0-1/T1-1).

## D-015: CardCache failure mode (ID-011, Task 3)

- Missing file = empty cache. Corrupt JSON / wrong types / unreadable / unwritable file → `ERR_INTERNAL` (fail closed, never silently reset, so rollback protection cannot be bypassed by deleting semantics — note: deleting the file itself yields an empty cache, which operators must protect like any trust store).
