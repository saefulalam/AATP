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
- Active commitment: `card.next_commitment` if present else the last rotation's `next_commitment`. Per blueprint ID-020 ("if the previous statement (or Card) carried `next_commitment`, then `sha256(to_public_key)` MUST equal it"), when both are present they MUST be equal, else `ERR_KEY_COMMITMENT_MISMATCH` (strict equality, fail closed; a card may not publish a divergent fresh pre-rotation while old history is still present).

## D-011: Revocation envelope carries `v: "0.2"` (Task 3)

- Blueprint §4.4 shows rotation with `"v":"0.2"` but revocation without it (abbreviated shape). `make_revocation` includes `"v":"0.2"` and `verify_card` gates it with `ERR_PROTOCOL_VERSION`, consistent with rotation handling.

## D-012: Revocation timing checks (ID-024, Task 3)

- `verify_card` rejects a card whose *current* signing key is revoked with `effective_at <= now` (`ERR_KEY_REVOKED`). `check_key_not_revoked(card, key_id, created_at)` (for M5 message checks) raises `ERR_KEY_REVOKED` iff some entry matches `key_id` with `effective_at <= created_at`; it re-verifies every revocation envelope signature (current-key first with strict `key_id` binding, then commitment-key second path identical to `verify_card`, including strict `v == "0.2"` shape checks) and fails closed (`ERR_SIGNATURE_INVALID`/`ERR_MALFORMED_MESSAGE`/`ERR_KEY_COMMITMENT_MISMATCH`) on any forged/tampered/stripped entry — callers must still pass `verify_card` output directly, since wholesale removal of the `revoked` list itself is not detectable by the helper alone. The "created before revocation but received after learning of it" policy exception is M5 policy scope; M1 implements the strict comparison.

## D-013: Task 2 follow-up confined to Task 3 (non-dict payloads)

- `verify_envelope` (Task 2) can return scalar payloads. `aatp/card.py` requires `dict` after every card/rotation/revocation verification (`ERR_MALFORMED_MESSAGE` otherwise). `aatp/dsse.py` is untouched; a global non-object rejection stays a Task 2 follow-up (ledger T2-2).

## D-014: Vectors in Task 3 (V03 now; node1/V06 deferred)

- `reference_vectors.py` now emits V03 (`genesis_pub_hex`, `agent_id`, asserted against Appendix C). The brief's Step 6 also mentions node1 JCS + V06, but those need M3 `node.make` output; they stay deferred to the Task 9 vector consolidation (with ledger T0-1/T1-1).

## D-015: CardCache failure mode (ID-011, Task 3)

- Missing file = empty cache. Corrupt JSON / wrong types / unreadable / unwritable file → `ERR_INTERNAL` (fail closed, never silently reset, so rollback protection cannot be bypassed by deleting semantics — note: deleting the file itself yields an empty cache, which operators must protect like any trust store).

## D-016: Artifact limit and shape error-code mapping (ART-001..024, Task 4)

- The blueprint names `ERR_PATH_INVALID` only for ART-004 and `ERR_MANIFEST_INVALID` for ART-007; no codes for ART-006 limits, manifest shape/version, prefix collisions, or stream length.
- Mapping used: path syntax (ART-001/002/003) and case-fold collision (ART-004) → `ERR_PATH_INVALID`; everything else manifest-level (bad `v`/shape/types/`d` format, exact duplicate, unsorted order, file/dir prefix collision ART-005, all three ART-006 limits, stream length ≠ sum(sizes)) → `ERR_MANIFEST_INVALID`; per-file digest mismatch on split/materialize → `ERR_ARTIFACT_HASH_MISMATCH`; quarantine/I-O failures → `ERR_INTERNAL`.

## D-017: Windows O_NOFOLLOW/O_EXCL equivalent and symlink refusal (ART-023, Task 4)

- POSIX: `os.open` with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`. Windows has no `O_NOFOLLOW`, so there flags are `O_WRONLY|O_CREAT|O_EXCL` (+`O_BINARY` where present) and symlink safety comes from pre-write checks: `dest_root` must not itself be a symlink; every existing parent prefix must satisfy `not islink` and `realpath(prefix) == join(realpath(root), prefix)`; the final parent's realpath must stay under `realpath(root)`; the final target must not already exist (`os.path.lexists`). Symlink detection failures → `ERR_PATH_INVALID`.
- Modes: `x=true` → `0o755` else `0o644` via best-effort `os.chmod` (limited semantics on Windows). Content is written, never executed.

## D-018: Materialize quarantine requires a fresh directory (ART-023, Task 4)

- `materialize(manifest, stream, dest_root)` writes only into a nonexistent path (created with parents) or an existing empty directory. A non-empty directory or a non-directory at `dest_root` → `ERR_INTERNAL`. Fail closed so one transfer can never overwrite operator data; callers allocate one quarantine dir per transfer and release it per policy.

## D-019: Task 5 Step-0 V05 node1 field-set reconstruction — NO MATCH (NEEDS_CONTEXT)

- Target (blueprint App. C V05): node1 (create, CR1=`sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf`) `node_id` = `sha256:1f3ce1c2654eee964b0b4c4365f5a909e0b11990dbc9f6478150efebb18b3253`. Method: `node_id = "sha256:"+hex(SHA256(D_NODE+JCS(candidate)))`, `D_NODE=b"AATP/0.2/NODE\n"`, JCS via `aatp.canon.jcs`. Cross-oracle V06: `sign(PAE(PT_NODE, JCS(node1)))` with the V03 test key (seed `11`×32 per blueprint App. C) must equal `5gLnkjsAGUvpED3PigH29W7M4mH3lkLf3zpq6-5cSMTuQQYmcgrzpaRhJ_qTXbs8iEcDPkw6AvyF7hgKhDRyBg`. Actor assumed = V03 `aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma` (PRV-002: node signed by actor's key; V06 signs with V03 key).
- Canonical trio (a)/(b)/(c) with `task_1` / `2026-10-01T00:00:00Z` — all MISS both oracles:
  - (a) minimal `{"actor":"<V03>","content_root":"<CR1>","created_at":"2026-10-01T00:00:00Z","operation":"create","parents":[],"task_id":"task_1","v":"0.2"}` → `sha256:767d9c7aad16d91e4927963cdbd7f6435f3480173f3ae08163471b51d958ca38`, sig `D3eFFYGk…` MISS.
  - (b) +`"annotations":{}` → `sha256:4a22e35940005556dc80ec1b7f1e10468dc0df48e99a4f594cdc765d46488d71`, sig `1dKig_Zq…` MISS.
  - (c) +`"generator":{"assurance":"self_asserted","kind":"ai"}` → `sha256:e895be30c692f40cd603e6311c2e23ffe937055bc22415475a3d1ad1a0ef0380`, sig `jYXMHtNj…` MISS.
  - (c)+annotations → `sha256:cacad76060731e7058dcba9773762847d44fd62e0207969a6dd69221af4270cc`, sig `Dtr7XoJC…` MISS.
- Extended sweep: 35 candidates total (8 task_id/timestamp bases × 4 field-set variants + 3 rich-generator variants), none matched either oracle. Bases: task_ids `task_1`, `task_demo1`, `task_demo`, `task_001`, `task_alpha`, `task_0199b2e2-9c2e-7b3a-9c2e-7b3a9c2e7b3a`, timestamps `2026-10-01T00:00:00Z`/`2026-10-01T00:01:00Z`/`2026-01-01T00:00:00Z`; generators: absent / `{"kind":"ai","assurance":"self_asserted"}` / `{"kind":"human","assurance":"self_asserted"}` / ai+model / ai+model+runtime+digests; annotations absent/`{}`. Result hashes (node_id):
  `e020666b…`, `c941d12c…`, `699ac80c…`, `2a50814e…`, `d76bd1f8…`, `3ad1c5a8…`, `3d9c2601…`, `18844a56…`, `15830fff…`, `95944f3d…`, `13d24416…`, `e5c38a1c…`, `17375ce1…`, `fb70ecd4…`, `a78bd0bc…`, `1b96e884…`, `520ece25…`, `a26a73b8…`, `4f06534e…`, `a5e26082…`, `0ebd3b96…`, `2e5a2236…`, `aa252542…`, `165d8b98…`, `e9dac05e…`, `0ccfe764…`, `54ad49ee…`, `c28bed76…`, `9317716b…`, `19dafcca…`, `180abb6b…` (full label→JCS→hash→sig table in `.superpowers/sdd/task-5-report.md`). V06 sig oracle missed for all 35.
- Corroborating finding (not blocking): CR2=`sha256:316dcf…` reproduces exactly as the V04 two-file manifest with `hello.txt`=`hello world` (11 B) instead of `hello` (5 B); stream/content_root grammar confirmed.
- Consequence: field set (actor/task_id/created_at/generator/annotations exact values) under-constrained by blueprint §7.1 + App. C alone; per brief Step 0, NO implementation on a guessed schema. `aatp/node.py` NOT created, `reference_vectors.py` untouched, no commit. Awaiting authoritative node1 JCS (vectors file with V05/V06 or exact field values).

## D-020: Blueprint V05/V06 expected hashes UNVERIFIABLE — mechanism verified by round-trip instead (binding human decision)

- Blueprint App. C says "Full node1 JCS is in the JSON vectors file" but that file was never provided, so V05 node_ids / V06 sig are unreproducible in principle (35-candidate Step-0 sweep in D-019 matched neither oracle).
- Decision: implement STRICTLY per rules (§7.1 schema + PRV-001..022 + node_id grammar), using OUR OWN test fixtures (actor = a V03-style agent_id derived in-test via `aatp.ids.derive_agent_id` from a local seed, task_id/timestamps fixed in-test). No test asserts the blueprint's `1f3ce1…`/`96f802…`/`cc88b1…`/`5gLnkj…` strings anywhere.
- Mechanism verified instead: `node_id = sha256 hex of SHA256(D_NODE + JCS(node))`, `D_NODE=b"AATP/0.2/NODE\n"` (determinism + independent recomputation in `test_PRV001_determinism_same_inputs_same_id`); V06-style signing `PAE(PT_NODE, JCS(node))` with the seed-`11`*32 key verified by DSSE round-trip (`test_PRV002_signed_by_actor` uses `verify_envelope`), not by blueprint hash equality.
- `reference_vectors.py` emits `V05-STRUCTURE` only (field schema + arity + implementation-generated example node_ids with a synthetic `aatp:222…` actor, clearly labeled NOT blueprint vectors); V01–V04 untouched, `write_bytes` LF.

## D-021: Node/DAG error-code mapping (PRV-*, Task 5)

- Blueprint §14 names `ERR_INVALID_PARENT` ("Parent invalid/missing/time-inconsistent"), `ERR_DAG_CYCLE` and `ERR_ARTIFACT_HASH_MISMATCH` but no code for PRV-001 shape or PRV-006 arity. Mapping used: node shape failures (bad digest/actor/task/timestamp/operation/generator/annotations, unsorted or duplicate parents, unknown `parent_policy`, non-object payload) → `ERR_MALFORMED_MESSAGE` (closest: "violates schema/GEN-010"); `v != "0.2"` → `ERR_PROTOCOL_VERSION`; arity violations (PRV-006), time-skew violations (PRV-005) and `require`-policy unknown parents (PRV-010) → `ERR_INVALID_PARENT`; own-`node_id` in ancestry → `ERR_DAG_CYCLE` (1306); signature failures propagate `ERR_SIGNATURE_INVALID` from `verify_envelope`; unresolvable actor key → `ERR_AUTH_FAILED`; unknown `node_id` in `get`/`ancestors`/`ancestry_status` → `ERR_ARTIFACT_NOT_FOUND`.
## D-022: Chunk fail-closed guards (M4 review fix wave)

- Non-`str` `content_root`/`transfer_id` in `aad()`/`encrypt_chunks()`/`decrypt_one()` → `ERR_CHUNK_AUTH_FAILED` (fail closed, avoids oracle distinguishing type errors from auth failures; `jcs` would otherwise accept ints/`None` or raise `ERR_MALFORMED_MESSAGE`).
- `decrypt_one` maps any `decrypt` failure to `ERR_CHUNK_AUTH_FAILED` (`except InvalidTag` kept, plus `except Exception` net); AAD/nonce validation runs before the `try` so `ERR_SEQUENCE_INVALID` is never swallowed.

## D-023: HPKE seal/wrap error mapping + KeyStore scope (MSG-010..013, ENC-020..023, Task 7)

- pyhpke 0.6.5 concrete open-failure type (ledger T0-2): `pyhpke.exceptions.OpenError("Failed to open.")` for all recipient-open failures probed (tampered `ct`, tampered `enc`, wrong `info`). `KeyStore.open` / `open_packet` / `unwrap_cek` map it (and any other exception) to `ERR_DECRYPT_FAILED`, fail closed. `cryptography.exceptions.InvalidTag` is the inner cause one layer down.
- `KeyStore` here is a minimal in-memory map `enc_key_id -> raw 32-byte X25519 private key` with `open(enc_key_id, enc, ct, info) -> bytes`; unknown key id (and any type/shape failure inside `open`) → `ERR_DECRYPT_FAILED`, never `KeyError`/raw. Full OS/file-backed keystore with ID-012 validity windows is M7+ scope.
- CRY-006: test recipient keys use `cryptography` `X25519PrivateKey.generate()` (OpenSSL OS CSPRNG), same basis as `SoftwareSigner.generate()`; no fixed HPKE vectors per blueprint §9 (RFC 9180 A.2.1 already gated in Task 0).
- MSG-013 scope: `max_message_bytes=262144` measured on `JCS(dsse_envelope)` plaintext bytes; `seal_packet` rejects oversize with `ERR_SIZE_LIMIT` before sealing.
- Wrap `pt` is the raw 32-byte CEK (not JCS); `wrap_cek` signature carries `transfer_id` explicitly since `info_r` binds it (`cr/s/r/t/k` short keys per §9.2). `open_packet` rebuilds `info` from packet `to`/`to_key_id` only, never inner message.
- Packet `aatp != "0.2"` → `ERR_MALFORMED_MESSAGE` (not `ERR_PROTOCOL_VERSION`): packet `aatp` is a relay-routing version tag, distinct from the envelope/node `v` protocol-version convention.
