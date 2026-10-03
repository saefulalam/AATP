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

## D-023: HPKE seal/wrap error mapping + KeyStore scope (MSG-010..013, ENC-020..023, Task 7)- pyhpke 0.6.5 concrete open-failure type (ledger T0-2): `pyhpke.exceptions.OpenError("Failed to open.")` for all recipient-open failures probed (tampered `ct`, tampered `enc`, wrong `info`). `KeyStore.open` / `open_packet` / `unwrap_cek` map it (and any other exception) to `ERR_DECRYPT_FAILED`, fail closed. `cryptography.exceptions.InvalidTag` is the inner cause one layer down.
- `KeyStore` here is a minimal in-memory map `enc_key_id -> raw 32-byte X25519 private key` with `open(enc_key_id, enc, ct, info) -> bytes`; unknown key id (and any type/shape failure inside `open`) → `ERR_DECRYPT_FAILED`, never `KeyError`/raw. Full OS/file-backed keystore with ID-012 validity windows is M7+ scope.
- CRY-006: test recipient keys use `cryptography` `X25519PrivateKey.generate()` (OpenSSL OS CSPRNG), same basis as `SoftwareSigner.generate()`; no fixed HPKE vectors per blueprint §9 (RFC 9180 A.2.1 already gated in Task 0).
- MSG-013 scope: `max_message_bytes=262144` measured on `JCS(dsse_envelope)` plaintext bytes; `seal_packet` rejects oversize with `ERR_SIZE_LIMIT` before sealing.
- Wrap `pt` is the raw 32-byte CEK (not JCS); `wrap_cek` signature carries `transfer_id` explicitly since `info_r` binds it (`cr/s/r/t/k` short keys per §9.2). `open_packet` rebuilds `info` from packet `to`/`to_key_id` only, never inner message.
- Packet `aatp != "0.2"` → `ERR_MALFORMED_MESSAGE` (not `ERR_PROTOCOL_VERSION`): packet `aatp` is a relay-routing version tag, distinct from the envelope/node `v` protocol-version convention.

## D-024: CEK persisted in the transfer store file (TRF-020, Task 8)

- The receiver transfer store (`store_path` JSON) keeps the unwrapped CEK base64url-encoded alongside `{transfer_id, content_root, have_ranges, state}` (TRF-020). The file is written with `write_bytes` (LF) and `chmod 0600` (best effort on Windows).
- Rationale: resume-after-restart must decrypt with the *same* CEK (TRF-022); a test-only receiver has no M7 KeyStore to hold it. Production deployments MUST use the M7 KeyStore (`cek_ref` handle) instead of this file.
- Never logged: no code path in `aatp/messages.py` / `aatp/transfer.py` prints keys, CEKs, or plaintext.

## D-025: Replay = raise + previous response attached (MSG-004/005, Task 8)

- Every authenticated control message id is cached as `(sender, id) -> {expires_at, response}` until `expires_at + skew` in a durable JSON file (survives restart; pruned on each receive).
- A repeat raises `ERR_REPLAY_DETECTED` (N06) with the previously produced outbound envelopes attached as `exc.previous_response` (MSG-005 idempotency: retransmit returns the same ACCEPT/STATUS/RECEIPT instead of re-executing).
- The cache covers all control types, a fail-closed superset of the "side-effecting (OFFER/ACCEPT/COMPLETE)" minimum.

## D-026: OFFER validation failures return REJECT (TRF-001/002/005, Task 8)

- Per the §8.4 receiver table (OFFER invalid → REJECT, state REJECTED), pre-accept validation failures produce a signed REJECT envelope whose `body.code` carries the specific error; authentication/protocol failures (sig, trust, replay, ...) raise instead.
- Code mapping: node `content_root` ≠ OFFER `content_root` → `ERR_ARTIFACT_HASH_MISMATCH` (TRF-001, checked before unwrap so the specific code surfaces); `stream_len != sum(sizes)` or `total_chunks != ceil(stream_len/chunk_size)` (0 iff stream 0) → `ERR_MANIFEST_INVALID` (TRF-002/ART-020); OFFER past `expires_at` → `ERR_MESSAGE_EXPIRED` (TRF-005, strict, no skew grace); no wrap for self or unwrap failure → `ERR_DECRYPT_FAILED` (TRF-003); `cipher != chacha20poly1305` → `ERR_SUITE_UNSUPPORTED` (AES-256-GCM is OPTIONAL and unnegotiated in M5); `sealed_manifest`-only (TRF-004 privacy profile) → `ERR_UNSUPPORTED_EXTENSION` (unimplemented in M5); any non-empty `crit` → `ERR_UNSUPPORTED_EXTENSION` (GEN-012; M5 defines no extensions).
- Full node signature + ancestry verification is deferred to VERIFYING (policy step 6, after transfer); at OFFER time only the claimed `content_root` equality is checked.

## D-027: Receiver transport + dispatch boundaries (Task 8)

- Outbound ACCEPT/REJECT/STATUS/RECEIPT are signed DSSE envelopes; sealing them for the wire is the M7 transport binding. In-memory callers pass envelopes directly.
- The receiver dispatches OFFER and COMPLETE only; any other registry type received here (ACCEPT/STATUS/...) and any unknown type → `ERR_UNSUPPORTED_MESSAGE` (MSG-006).
- A fresh msg id reusing a known `transfer_id` → `ERR_TRANSFER_NOT_FOUND` ("transfer_id already in use"): TRF-022 requires a new attempt to use a new `transfer_id` **and** CEK; resume of the same attempt travels via chunks + STATUS, never a second OFFER.
- Beyond-window chunks (`index > contiguous + send_window_chunks - 1`, window 16) → `ERR_SEQUENCE_INVALID` (drop + error); duplicates → silent idempotent discard without re-processing (TRF-012, even with differing bytes); >100 consecutive AEAD failures → ABORTED.
- Restart demotes in-flight ACCEPTED/RECEIVING records to PAUSED (section 8.4 "connection lost" row); `sender_due_chunks(have, total)` sends at most 16 unacknowledged chunks beyond contiguous have (TRF-024).
- VERIFYING failure → signed RECEIPT `rejected` (+code), state REJECTED (node_id best-effort via `node_id_of`). Integrity pass → RECEIPT `accepted`; quarantine/scanner outcomes are M7 policy scope (always accept on integrity pass here).
- `parent_policy=require` over a lazy DagStore is enforced by a post-add `ancestry_status == complete` check (else `ERR_INVALID_PARENT`).
- M5 assumes `card_resolver` returns verified cards (rollback enforced at fetch via `verify_card`); per-message checks are pin trust + signature with the current key id + signing-key window (ID-014) + revocation (ID-024). Policy steps skipped entirely (no engine yet): grant chains, classification-vs-grant, SEC rules, scans (§10.2 steps 3,7,8,9).
- Generated message ids are `msg_` + UUIDv4 (opaque GEN-006 shape; UUIDv7 clock-seq generation deferred, no behavioral difference on the wire).

## D-029: Grant shape is fail-closed exact (AUT-002, Task M6-1)

- `aatp/grants.py:_check_grant_shape` requires exactly the §10.1 keys `{v,iss,aud,cap,nbf,exp,prf,constraints}` (no extras, none missing), cap entries exactly `{act,res}`, constraints exactly `{classification_max,export}` — mirrors the node rebuild-compare convention. Any deviation → `ERR_MALFORMED_MESSAGE`.
- `v != "0.2"` → `ERR_MALFORMED_MESSAGE` per the M6-1 brief verbatim (differs from node/card, which use `ERR_PROTOCOL_VERSION`).
- Missing `classification_max`/`export` is NOT treated as most-restrictive — it is `ERR_MALFORMED_MESSAGE` (fail closed, per brief). `cap.res` must be a non-empty string; `export` must be a real boolean; `nbf <= exp` required (backwards windows rejected at shape time); `prf` entries must match `sha256:<64 hex>`.
- `grant_id_of` stays a pure function (no shape validation) so ids remain computable for the brief's shape test with non-agent ids.

## D-030: Grant chain walk semantics (AUT-001..006, Task M6-1)

- Depth (AUT-004) counts envelopes: `1 + len(chain_envs) <= 8`; 9 total → `ERR_GRANT_INVALID`.
- `prf` linkage is positional: for every grant at index `i` (leaf = 0, parent-first order), each `prf[t]` must equal `grant_id_of` the envelope at `i+1+t`. This accepts single-parent chains (all `prf` len ≤ 1, only `[0]` links checked) and full-ancestry chains alike, and verifies every `prf` entry — nothing ignored. Non-last grant with empty `prf` (gap) or last grant with non-empty `prf` (dangling claim) → `ERR_GRANT_INVALID`.
- AUT-003 delegation bit is per delegated cap: for every child cap, the parent must carry `aatp.grant.delegate` with `res_subset(child.res, delegate.res)`, else `ERR_GRANT_ATTENUATION` (fail-closed reading of "for that resource").
- Time windows (AUT-004, skew imported from `aatp.messages.CLOCK_SKEW_SECONDS`, timestamps via `aatp.messages.parse_ts` — no local copies) are enforced for EVERY envelope in the chain, not just the leaf.
- `verify_chain(..., revoked=None, *, key_resolver)`: `revoked` defaults to empty; key resolution follows the `DagStore.add` pattern (`AATPError` propagates, other failures → `ERR_AUTH_FAILED`, non-32B key → `ERR_AUTH_FAILED`).

## D-031: Handoff lease state semantics (HND-001..006, N20, Task M6-2)

- No `v` field required on `HandoffBody`: blueprint A.6 lists no `v` (unlike grants/nodes); shape requires exactly the 8 keys `{handoff_id,task,input_node_ids,grant_env,expected_outputs,deadline,lease_expires_at,policy_context}`. Any deviation (missing/extra top-level key, bad `task` fields beyond `task_id,title,objective,optional constraints`, non-`sha256:<64 hex>` `input_node_ids`, bad GEN-004 `deadline`/`lease_expires_at`) → `ERR_MALFORMED_MESSAGE`. `policy_context` extras beyond `resource` are allowed (open-ended context bag per A.6); `policy_context.resource` itself is a required non-empty string, else `ERR_MALFORMED_MESSAGE`.
- Timestamps reuse `aatp.messages.parse_ts` (no local copies). Offer with `lease_expires_at <= now` → `ERR_MALFORMED_MESSAGE`. Agent ids (`sender`/`recipient` params, not part of A.6) checked against a local copy of the `^aatp:[a-z2-7]{52}$` pattern (`grants`/`messages` keep theirs private).
- HND-003+HND-004 via one `grants.verify_chain` call before storing PENDING: leaf = embedded `grant_env`, chain = `grant_chain_envs` (default `[]`), `roots` passed at offer time, `action = aatp.task.handoff`, `resource = policy_context.resource`, `presenter = recipient` (leaf `aud` must be the recipient). Node digests are content addresses, not resources, so HND-004 "transferable under a grant whose `res` covers them" is interpreted as the leaf cap covering `(aatp.task.handoff, policy_context.resource)`; uncovered → `ERR_POLICY_DENIED` from `verify_chain`. `input_node_ids` themselves are only shape-checked.
- HND-005 strict equality on accept only: offer constraints live at `task.constraints` (default `{}`); if non-empty and `decision == "accept"`, `respond(..., conditions)` must equal them exactly (dict `==`), else `ERR_POLICY_DENIED` with no state change. `reject` never checks constraints (`conditions=None` succeeds). Empty offer constraints accept any `conditions`. Binding: `offer(handoff, grant_chain_envs, now, *, sender, recipient, roots, key_resolver)`.
- `respond` builds and signs the `HANDOFF_RESPONSE` envelope itself with the caller-supplied responder `signer` (`build_message` + `make_envelope(PT_MESSAGE, jcs(msg), signer)`, `corr = {task_id}`); only the designated `recipient` may respond (`responder != recipient` → `ERR_POLICY_DENIED`). `decision` outside `{accept,reject}` → `ERR_MALFORMED_MESSAGE`.
- Late response (either decision) with `now > lease_expires_at` → `ERR_LEASE_EXPIRED`, stored state VOID, no audit entry (HND-002; uniform treatment — blueprint only mandates the accept case). `now == lease` is on time. `EXPIRED` is the lazy read: `state_of(id, now)` returns `EXPIRED` for a still-PENDING offer past lease without mutating; VOID is only set by an attempted late response.
- Replay/idempotency: same decision twice → the stored envelope bytes verbatim (deep copy, JCS-identical); conflicting decision on ACCEPTED/REJECTED → `ERR_POLICY_DENIED` (blueprint silent, fail closed). Duplicate `offer` id and unknown `handoff_id` (`state_of`/`responsible`/`respond`) → `ERR_POLICY_DENIED`.
- HND-006 audit only on accept: `{"handoff_id","task_id","decision":"accept","at":now}` per task; `audit_log` returns copies. `responsible(id)` = sender until ACCEPTED, then recipient.

## D-032: Policy evaluation rule_id mapping + gate semantics (M6-3)

- `aatp/policy.py:evaluate` is pure (no transfer wiring): steps are grant chain → manifest limits → `expires_at` → classification → consumption_mode; deny at first failure. Transfer integration (node/content_root checks, scans, quarantine) is M7 scope.
- Step-1 `verify_chain` failures are mapped code → rule_id: `ERR_GRANT_ATTENUATION` → `AUT-002`, `ERR_GRANT_INVALID` → `AUT-004`, `ERR_POLICY_DENIED` (presenter/action-resource) → `AUT-006`, `ERR_MALFORMED_MESSAGE` → `GEN-010`; any other `AATPError` code (e.g. `ERR_AUTH_FAILED`/`ERR_SIGNATURE_INVALID` from key resolution/signature) → `AUT-001` (issuer trust failure). Only `AATPError` is caught; programming errors raise.
- Step-2 manifest failures map to rule `ART-006` with the `validate_manifest` code passed through (`ERR_MANIFEST_INVALID` or `ERR_PATH_INVALID`).
- Step-3 expiry is strict with no skew grace (`expires_at < now` denies with `MSG-003`/`ERR_MESSAGE_EXPIRED`; equality allows). Malformed `expires_at` → deny `GEN-010`/`ERR_MALFORMED_MESSAGE` (request data, fail closed); a malformed `now` raises (caller error).
- Step-4 unknown/non-string `classification` → deny `GEN-010`/`ERR_MALFORMED_MESSAGE`; rank above leaf `constraints.classification_max` → deny `AUT-002`/`ERR_POLICY_DENIED`.
- Step-5 `consumption_mode` absent defaults to `data_only` (skip); unknown values → deny `SEC-002`/`ERR_POLICY_DENIED` (fail closed at the gate). `instructions_allowed` requires a verified-leaf cap `{act: aatp.artifact.instruct, res_subset(resource, cap.res)}` (N22), else `SEC-002`/`ERR_POLICY_DENIED`.
- Success returns the synthetic rule_id `POLICY-ALLOW` with `code None` (no blueprint rule id exists for the allow path).

## D-033: M7-1 quarantine verdict mapping (SEC-006/007, Task M7-1)

- `Quarantine.place` default: all-clean → `accepted` (blueprint §8.4: VERIFYING + scan clean + policy allow → RECEIPT accepted); any `suspicious` → `quarantined` (default `quarantine_on_suspicious=True`; `False` → `accepted`, gates suspicious only); any `malicious` from a scanner in `trusted_scanners` (default empty set) → `rejected` (regardless of flag); untrusted `malicious` → `quarantined` always (fail closed; scanners are policy dependencies, never trusted subsystems); empty verdict list → `quarantined` (fail closed, no scan evidence).
- SEC-006: `state_of` returns only `{content_root, node_id, state, released_by?, at?}` — verdicts are excluded so the word "malicious" can never appear in state output; scanner detail lives in `verdicts_of` (SEC-007, exact `{scanner_name, scanner_version, verdict, at}` with GEN-004 `at` via `messages.parse_ts`).
- `release` only transitions `quarantined → accepted`, requires `released_by ∈ authorized_releasers` else `ERR_POLICY_DENIED`, records `released_by + at` (GEN-004); unknown root → `ERR_ARTIFACT_NOT_FOUND`; releasing `accepted`/`rejected` → `ERR_POLICY_DENIED`.

## D-034: M7-1 sec/audit semantics (SEC-003/004/005, AUD-001/002, Task M7-1)

- `delimit_for_model(text, source)` emits `<<<AATP-DATA source=<source>>>\n{text}\n<<<END-AATP-DATA>>>` with `text` embedded verbatim. Delimiting ≠ sanitizing: hostile text (even a forged end-fence) is carried unchanged, only marked data-only (SEC-001/003). `source` must be an `agent_id` or `"unknown"`, else `ERR_MALFORMED_MESSAGE`.
- `quote_filename` is `shlex.quote` verbatim (SEC-005).
- `tool_allowed` re-authorizes with `policy.evaluate(action=tool_action, resource=resource, consumption_mode="data_only", ...)` against the agent's own grant chain (SEC-004, N21 groundwork: full tool test in M7-3; here unit-level False without cap). Returns bool; catches `AATPError` → `False` (deny never raises); programming errors propagate.
- AUD-001 guard rejects keys `{"cek", "private_key", "plaintext", "payload", "plaintext_bytes"}` at any depth (recursive walk of dicts/lists) with `ERR_MALFORMED_MESSAGE` (fail closed; log untouched on reject).
- AUD-002: `entry_hash = SHA256(bytes.fromhex(prev_hash) + JCS(entry))` (raw 32-byte prev hash, not ASCII hex); `prev_hash` must be 64 lowercase hex (default `"00"*32`); `audit_append` appends `{"entry", "prev_hash", "entry_hash"}` and returns the new hash.

## D-028: Task 9 conformance gate — Core M0-M5 green, no production claim

- Full suite: 261 passed (`234` pre-existing + `27` gate in `tests/test_vectors.py`) via `.venv\Scripts\python -m pytest`. No `aatp/*.py` change in Task 9 (no drift found; generator untouched, JSON diff empty).
- Regeneration: committed `tests/vectors/aatp_v0_2_vectors.json` regenerates byte-identical via `reference_vectors.main()` into a temp comparison (`write_bytes` LF, no CR, trailing newline; `.gitattributes` keeps `tests/vectors/*.json -text`). Closes ledger T0-1/T1-1 (vector-file-vs-implementation drift): V01/V02/V03/V04/V07/V08 implementation outputs assert equal to the JSON values (implementation modules vs JSON, not generator vs itself); V09 negative; V05-STRUCTURE present, labeled implementation-generated, grammar recomputed (`D_NODE + JCS(node1)` == `example_node_ids[0]`).
- Per binding D-020: `tests/test_vectors.py` asserts NO blueprint V05/V06 strings anywhere; V05/V06 remain UNVERIFIABLE (vectors file absent).
- Negatives: N01–N16 each green via their canonical tests (test-name → N-code map in `tests/test_vectors.py` comments); N17 revert-accepted + N18 cycle run the `test_node.py` ids `test_PRV004_revert_is_not_a_cycle` / `test_PRV003_self_ancestor_rejected` directly, not reimplemented.
- Per blueprint §18.4 rule 6 (do not claim conformance until Core green AND CRY-007 review done) + §17 levels: Core M0-M5 is green BUT V05/V06-unverifiable and CRY-007 composition review stays OPEN → NO production conformance claim. Reference implementation only.

## D-035: M7-2 transport binding (NET-001..003, §13)

- Relay (`aatp/transport/relay.py`, pure in-memory, no I/O, thread-safe): `put_packet(packet) -> str` shape-checks exact keys `{aatp,to,to_key_id,enc,ct}` plus `aatp == "0.2"` (types: `to` must be `str`), else `ERR_MALFORMED_MESSAGE` (never raw; JCS failures propagate as `ERR_MALFORMED_MESSAGE`). Id `= hex(SHA256(JCS(packet)))`; duplicate content returns the same id without double-storing. `take_packets(agent_id)` drains FIFO and returns copies. `put_chunk(tx,index,data_b64)` requires `tx` matching `[A-Za-z0-9_.:-]{1,128}`, `index` an integer `>= 0`, `data_b64` valid b64u (strict `b64u_dec`, non-canonical rejected) else `ERR_MALFORMED_MESSAGE`; idempotent overwrite. `get_chunk` returns the stored b64u string or `None`. `put_card(agent_id,card_env)` requires a dict with `payloadType`/`signatures` keys else `ERR_MALFORMED_MESSAGE` — signature verification is the receiver's job, never the relay's. Relay never opens sealed packets (opaque store); `stored JCS == retrieved JCS` is asserted in tests (NET-002).
- Limits (NET-002): `max_stored_packets` (default 10000) counts currently stored packets; exceeding → `ERR_RATE_LIMIT`. `max_chunk_bytes` (default 16777216 + 16 tag) caps both `len(JCS(packet))` and decoded chunk bytes; exceeding → `ERR_SIZE_LIMIT`. Draining frees the rate-limit slots so redelivery after drain re-stores.
- HTTP (`aatp/transport/http.py`, stdlib `ThreadingHTTPServer` only, no new deps): `serve(relay, *, host="127.0.0.1", port=0, card_resolver) -> HTTPServer`. `POST /aatp/v0.2/packets` (JSON body → `202 {"id"}`; duplicate → `202` same id; malformed → `400`); `PUT /aatp/v0.2/transfers/{tx}/chunks/{i}` (raw octet-stream → stored as b64u → `204`; `tx` charset `[A-Za-z0-9_.:-]{1,128}`, `i` decimal `>= 0`, else `400`; idempotent); `GET /aatp/v0.2/agents/{agent_id}/card` → `200` card JSON / `404 {"code":"ERR_ARTIFACT_NOT_FOUND","detail":"card not found"}` (blueprint names no card-missing code; `ERR_ARTIFACT_NOT_FOUND` chosen as the closest existing code, consistent with `DagStore.get` unknown-node mapping in D-021); `GET /aatp/v0.2/mailbox/{agent_id}` → `200 [packets]` + drain.
- Mailbox auth exact format (§13 leaves bytes unspecified): `Authorization: DSSE <b64u(JCS(envelope))>` where the envelope is DSSE with `payloadType == "application/vnd.aatp.message+json"` and `payload == b64u(JCS({"method":"GET","path":<path-without-query>,"created_at":<GEN-004>,"agent_id":<id>}))`. Verified with `verify_envelope` against the signing pubkey from `card_resolver(agent_id)` (resolver returns the card dict; envelope-form cards also accepted). Status map: missing/malformed auth, bad signature, unknown agent, or `created_at` outside `±120s` of server now → `401` (codes `ERR_AUTH_REQUIRED` / `ERR_AUTH_FAILED` / `ERR_MESSAGE_EXPIRED` respectively); envelope `agent_id !=` path `agent_id` → `403 {"code":"ERR_AUTH_FAILED"}`. Error mapping for relay failures: `ERR_SIZE_LIMIT` → `413`, `ERR_RATE_LIMIT` → `429`, else `400`.
- NET-001: no TLS locally; all security assertions hold without it (HPKE + DSSE, `test_NET001_no_tls_dependency_sealed_opaque` proves the relay store never sees plaintext). TLS is defense-in-depth per blueprint; production deployments terminate TLS in front of this reference server.
- No new dependencies: transport + tests use stdlib only (`http.server`, `urllib`, `json`, `threading`).

## D-036: M7-3 MCP Context shape + offer semantics (§16, Task M7-3)

- `Context` (dataclass, `aatp/mcp_server.py`) holds object references only — never raw private key bytes: `{agent, cards, seq_dir, dag, relay, quarantine, handoff, roots, key_resolver, trusted, now}` plus two operational extras with defaults: `receiver` (the `TransferReceiver` bound to `agent`, needed by `aatp_fetch`) and `artifact_db` (`content_root -> {manifest, stream, node, node_id, transfer_id}`, needed by `aatp_verify`). `seq_dir` is carried for operator tooling; no tool reads it yet.
- `agent` is a duck-typed signer-holder (`.agent_id` / `.signer`; `.enc_pub` / `.enc_key_id` when acting as a recipient). `recipients` accepts holder objects OR bare agent-id strings; bare ids resolve via `ctx.cards[aid]["enc_key"]` (`key_id` + b64u `public_key`, 32-byte checked), unknown id → `ERR_AUTH_FAILED`. One CEK wrap per recipient (ENC-020).
- `aatp_offer` returns the brief's keys verbatim (`packet`, `chunks: [{index, data-b64u}]`, `transfer_id`, `content_root`, `node_id`, `total_chunks`) plus a `packets` map (`agent_id -> sealed packet`) for multi-recipient callers; `packet` is always the first recipient's sealed packet. The CEK is generated once per offer, used for chunks + wraps, then deleted from locals; it is never stored (sender needs it no further) and never logged. Offer does NOT touch the relay — callers `put_packet`/`put_chunk` explicitly (proves relay opacity in the demo).
- `aatp_fetch` reads `have` from the public `get_status` envelope (TRF-021 surface, `validate_have_ranges`-checked) and `total` from the receiver store record; unknown/non-resumable → `ERR_TRANSFER_NOT_FOUND` propagates. `aatp_verify` recomputes per-file digests + `content_root` from `artifact_db`; unknown root → `{"ok": False, "code": "ERR_ARTIFACT_NOT_FOUND"}`. `aatp_provenance` returns `{"node", "ancestry", "code"}` via `dag.get` / `ancestry_status`; unknown → `ERR_ARTIFACT_NOT_FOUND`. `aatp_handoff` builds the HND body from `(task_id, agent, grant_env)` plus `**fields` defaults (`handoff_id=handoff_<task>`, `deadline=+86400s`, `lease=+3600s`, `policy_context.resource=task_id`) and returns `{"handoff_id", "state"}`.

## D-037: M7-3 stdio protocol (stdlib `sys`/`json` only, no MCP SDK)

- Minimal JSON-RPC-ish line protocol: stdin lines `{"tool": name, "args": {...}}` → stdout lines `{"ok": True, "result": ...}` or `{"ok": False, "code": ...}` (no `detail` key, to match the brief verbatim and avoid leaking internals). Unknown tool → `ERR_UNSUPPORTED_MESSAGE`; unparsable/non-object lines and non-dict `args` → `ERR_MALFORMED_MESSAGE`; `AATPError` → its code; unexpected exceptions → `ERR_INTERNAL` (fail closed). Both `aatp_offer` and `aatp.offer` spellings dispatch (alias table); `run_stdio(ctx)` skips blank lines and flushes per line. Deterministic tests call `handle_line(ctx, line) -> str` directly; one subprocess smoke test pipes an unknown-tool line through `run_stdio` in a child interpreter.
- `files` over stdio coerce via `_coerce_files`: `[{path, text|x}]`, `[{path, data_b64|x}]`, or `[[path, text, x]]` (bare strings are UTF-8 text; binary must use `data_b64`). `recipients` over stdio are bare agent ids (holders cannot cross JSON) resolved via `ctx.cards`.

## D-038: Appendix B demo deviations (frozen modules win over shorthand)

- Step 0: G2 is issued Backend→Security with `prf=[id(G1)]` (true delegation chain C→A→B), not Coordinator→Security: `verify_chain` (frozen, AUT-002) requires `child.iss == parent.aud`, so a coordinator-issued G2 citing G1 as parent is rejected. Authority still derives from G1's delegate cap.
- Step 11: the report node N2 uses operation `modify` (parents `[N1]`), not `create`: frozen PRV-006 arity requires `create` → 0 parents; `modify` is the closest valid operation for a derived report.
- Step 12: the offer runs Security→Coordinator and the coordinator accepts before lease (App. B verbatim). Per frozen HND-001 semantics (`responsible` = sender while PENDING, recipient once ACCEPTED) the test asserts `responsible == security` pre-accept and `responsible == coordinator` post-accept; the brief's trailing "`responsible==security`" holds only for the pre-accept state.

## D-039: M8 TypeScript scaffold + JCS canon (Task M8-1)

- Separate npm project in `ts/` (`aatp-ts@0.2.0`, `"type": "module"`, ESM only). Zero imports from `aatp/` Python; only `tests/vectors/aatp_v0_2_vectors.json` is read, as test input.
- Pinned at scaffold time (exact resolved versions in `ts/package.json`): `@noble/curves 2.4.0`, `@noble/hashes 2.4.0`, `@hpke/core 1.9.0`, `@noble/ciphers 2.4.0` (ciphers needed M8-4; installed now to pin once). Dev: `typescript 7.0.2`, `@types/node 26.6.4`.
- `tsconfig.json` is check-only (`noEmit: true`; Node 24 strips types at runtime, no build step): `module/moduleResolution nodenext`, `strict true`, `target es2022`, plus `allowImportingTsExtensions` (tests import `../src/canon.ts` verbatim) and `types: ["node"]` (required — without it `tsc` reports TS2591 on `Buffer` and `node:*` imports despite `@types/node` being installed).
- `node --test ts/test/` (directory form) does NOT discover `.test.ts` files on Node v24.15.0 (falls back to loading the directory as a module → MODULE_NOT_FOUND); the suite runs via glob `node --test test/*.test.ts` (`npm test` in `ts/`). Same 50 tests either way once discovered.
- `@noble/hashes` 2.x exports `sha256` from `./sha2.js`, not `./sha256` (test import adjusted; recorded for M8-4+ authors).
- JCS (`ts/src/canon.ts`, fresh logic, constants/grammar copied from `aatp/canon.py`): custom serializer (no `JSON.stringify` for output — it neither sorts keys nor matches JCS escaping); ASCII keys validated BEFORE the default UTF-16 sort; escape set exactly `" \\ \b \f \n \r \t` + other C0 as `\u00xx` lowercase, raw otherwise (no `/`, no U+2028/2029); integers only via `Number.isSafeInteger` (one check rejects float/NaN/±Infinity/unsafe); `-0` serializes as `"0"`, so a `"-0"` parse dies on the round-trip compare; depth root 0, `>16` reject; `bigint`/`undefined`/`function`/`symbol`/non-plain objects rejected; symbol keys rejected via `Reflect.ownKeys`; lone surrogates rejected by explicit UTF-16 scan (TextEncoder would silently emit U+FFFD); JS `RangeError` (stack overflow on hostile nesting) maps to `ERR_MALFORMED_MESSAGE`, mirroring Python's `RecursionError` mapping.
- Duplicate-key detection needs no tokenizer: `parseJcs` requires `jcs(parsed) === input` byte-exact, and `JSON.parse` collapses dupes, so any duplicate key shrinks the re-serialization and the byte compare always differs (same-value dupes included). Documented in the `canon.ts` header comment.
- `Buffer` (Node built-in, not a crypto primitive) used only for base64url/hex alphabet conversion in `ts/src/b64.ts`; strictness (regex, no `=`, `len % 4 != 1`, re-encode compare for trailing bits) is explicit, mirroring `aatp/b64.py`.
- `ERROR_REGISTRY` numerics copied verbatim from `aatp/errors.py`; `err()` falls back to `ERR_INTERNAL` (9000) on unknown codes like Python.
## D-040: M8 TypeScript DSSE + signer + ids (Task M8-2)

- Fresh modules `ts/src/signer.ts`, `ts/src/dsse.ts`, `ts/src/ids.ts` (zero TS imports from Python; constants/grammars copied verbatim from `aatp/dsse.py`, `aatp/signer.py`, `aatp/ids.py`): five `PT_*` strings, `ED25519_L`, `D_AGENT=b"AATP/0.2/AGENT-ID\n"`, PAE grammar, verify check order (payloadType → envelope shape → b64u → JCS → lengths → S<L → verify), D-007 single-signature selection.
- CRY-002: `sign()` signs PAE bytes directly via noble `ed25519.sign`; test verifies the raw signature over `pae()` with noble `ed25519.verify`.
- CRY-003: explicit `S < L` BigInt check before verify (backend-independent, mirrors D-004). Probe: noble 2.4.0 already rejects `S+L` natively (`ed25519.verify` returns false), so the explicit check is belt-and-suspenders, identical posture to Python.
- SIG-003 code: `ERR_MALFORMED_MESSAGE` for payloadType mismatch (mirrors D-005); type compared before the payload is touched (ordering proved by a test with corrupt payload + wrong type).
- `verifyEnvelope` fails closed beyond Python: noble `verify` exceptions (e.g. invalid-point 32-byte keys, which Python leaks as raw `ValueError`) map to `ERR_SIGNATURE_INVALID`.
- SIG-001: secret in `#private` fields, so `JSON.stringify(signer)` is `{}` (tested to contain no key material). `fromSeed` requires 32-byte `Uint8Array` (else `ERR_MALFORMED_MESSAGE`); `generate()` uses `node:crypto` `randomBytes` = OS CSPRNG (CRY-006 basis, mirrors D-023/D-004 notes).
- `deriveAgentId`: noble `sha256` from `@noble/hashes/sha2.js` (same import path as the M8-1 b64 test); hand-written RFC4648 base32 encoder in `ids.ts` (no dep; masked accumulator so `buffer` never exceeds 13 bits). V03 byte-exact: seed `0x11`×32 → pub `d04ab232…9778737` (matches Python `SoftwareSigner.from_seed`, asserted in-test) → `aatp:ikee37…fkqadma`.
- Extra signature entries are unverified (PRV-023 multi-signature is M6+ scope, N/A to TS per brief).
- No dependency changes: pins from D-039 unchanged (`@noble/curves 2.4.0`, `@noble/hashes 2.4.0`, `@hpke/core 1.9.0`, `@noble/ciphers 2.4.0`; dev `typescript 7.0.2`, `@types/node 26.6.4`).
- Cross-interop probed both directions (ephemeral fixtures, not committed): TS-signed envelope verifies under Python `verify_envelope`, Python-signed under TS `verifyEnvelope`.
## D-041: M8 TypeScript artifact + node (Task M8-3)

- Fresh modules `ts/src/artifact.ts`, `ts/src/node.ts` (zero TS imports from Python; constants/grammars copied verbatim from `aatp/artifact.py`, `aatp/node.py`): `D_CONTENT=b"AATP/0.2/CONTENT\n"`, `D_NODE=b"AATP/0.2/NODE\n"`, ART-006 limits (1024 / 10000 / 2^32), reserved-name set, digest/agent/task/timestamp grammars, `CLOCK_SKEW_SECONDS=120`, node field order, D-021 error-code mapping (incl. case-fold collision → `ERR_PATH_INVALID`, prefix collision → `ERR_MANIFEST_INVALID`).
- `build(files: Array<{path, data: Uint8Array, x: boolean}>)` accepts object entries (not Python 3-tuples — the tuple shape has no TS idiom; digest/size/sort/stream/contentRoot semantics identical). `x` strictly boolean; sizes safe integers; byte-sort via `TextEncoder` compare.
- V04 byte-exact FIRST TRY: stream hex, manifest JCS hex, and content_root all equal the vectors file on the first green run (no fix wave).
- Casefold approximation: `caseFold(s) = s.toLowerCase().replace(/ß/g, "ss")` (JS has no `casefold()`); covers the Straße/STRASSE pair in-test. Other Unicode special-casing (e.g. Turkish İ, Greek sigma edge cases where Python casefold and lower differ) may diverge — fail-closed direction unknown, recorded as approximation, not equivalence.
- ART-002 control scope mirrors Python exactly (U+0000–U+001F + U+007F only; C1 U+0080–U+009F NOT rejected — same boundary as ledger T4-3).
- No-materialize scope: TS has no `materialize` (no filesystem writes); validate + build + stream only. Cross-transfer reassembly is M8-4+ scope.
- `DagStore` fields use TS `private` (not `#`) so tests can inject synthetic A↔B graphs exactly like Python tests write `store._nodes` directly (PRV-003 defense-in-depth proof; honest hashes cannot cycle).
- `validateNode` canonical-form check compares `jcs(rebuilt)` vs `jcs(input)` bytes (equivalent to Python dict `==` for validated canonical values; also enforces the assurance-default normalization).
- Cross-interop probed both directions (ephemeral fixtures, not committed): TS V04 manifest validates under Python `validate_manifest` and is byte-identical (manifest/stream/content_root); TS node envelope accepted by Python `DagStore.add`; Python node envelope accepted by TS `DagStore.add` (partial ancestry in a fresh store, correct lazy semantics).
- No blueprint-hash asserts per D-020: determinism + independent recompute (`D_NODE + JCS` in-test) + revert-distinct (same contentRoot, different parents → different ids, accepted).
- Out of scope (unchanged): rest of M8 (`chunks/seal`), card chain, transfers, grants/handoff/policy/quarantine/transport/MCP in TS; CRY-007 review still OPEN.

## D-042: M8 TypeScript chunks + seal + bidirectional interop (Task M8-4)

- Fresh modules `ts/src/chunks.ts`, `ts/src/seal.ts` (zero TS imports from Python; constants/grammars copied verbatim from `aatp/chunks.py`, `aatp/seal.py`): `D_CHUNK`, `D_PACKET`, `D_CEKWRAP`, `SEQ_LIMIT = 2^63`, `MAX_MESSAGE_BYTES = 262144`, packet exact keys `{aatp,to,to_key_id,enc,ct}`, wrap exact keys `{agent_id,enc_key_id,enc,ct}`, wrap info JCS `{cr,s,r,t,k}`, wrap pt = raw 32B CEK, D-022 non-string-id fail-closed mapping, D-023 error mapping (oversize -> `ERR_SIZE_LIMIT`, strict parse -> `ERR_MALFORMED_MESSAGE`, any open failure incl. unknown key id -> `ERR_DECRYPT_FAILED`; chunk decrypt any-failure -> `ERR_CHUNK_AUTH_FAILED` with validation ordered before the broad catch so `ERR_SEQUENCE_INVALID` is never swallowed).
- ChaCha20-Poly1305 via `@noble/ciphers/chacha.js` (`chacha20poly1305(key, nonce, aad).encrypt(pt)` / `.decrypt(ct)` — AAD is a construction parameter, not a per-call argument; tag appended to ct by the lib). V07 byte-exact FIRST TRY (both cts + nonces with CEK 00..1f, chunk_size 8, tx_demo1, CR1, 13B stream); deterministic resend identical.
- `@hpke/core` 1.9.0 API as found by inspection (recorded verbatim, never hand-rolled per CRY-001): exports `CipherSuite, DhkemX25519HkdfSha256, DhkemX448HkdfSha512, HkdfSha256/384/512, Aes128Gcm, Aes256Gcm, ExportOnly` (+ `KemId/KdfId/AeadId` enums: X25519 = 32, HKDF-SHA256 = 1, ChaCha20Poly1305 = 3); **no ChaCha20Poly1305 AEAD in core** (AES-GCM + ExportOnly only), so the suite AEAD is `Chacha20Poly1305` from companion package `@hpke/chacha20poly1305@1.8.0` (new pinned dep in `ts/package.json`; depends on the same `@hpke/common ^1.10.0`, interface-compatible). Suite construction: `new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Chacha20Poly1305() })`. Key contexts like Python: `suite.kem.deserializePublicKey(raw32)` / `deserializePrivateKey(raw32)` yield `CryptoKey`; `createSenderContext({ recipientPublicKey, info })` yields `{ enc: ArrayBuffer, seal(data, aad) }`; `createRecipientContext({ recipientKey, enc, info })` yields `{ open(data, aad) }`; aad is `b""` throughout. All methods are Promise-based (WebCrypto), hence the TS `sealPacket/openPacket/wrapCek/unwrapCek/KeyStore.open` surface is `async` while Python stays sync — wire shapes identical, call convention differs by runtime.
- X25519 test-key derivation uses noble `x25519.getPublicKey(privRaw)` and agrees byte-exact with Python `cryptography` in both directions (asserted in both interop tests). Note: `@hpke` `deriveKeyPair(ikm)` is an RFC HKDF-Derive construction and does NOT equal raw-scalar X25519 derivation — raw priv bytes go to `deserializePrivateKey` / noble directly, never through `deriveKeyPair`.
- Interop design: the sealed packet plaintext IS the DSSE node envelope (sealed node announcement), so one flow proves open -> DSSE-verify -> nodeId-recompute -> unwrap -> chunk-decrypt -> stream match. Fixture schemas: `ts/testdata/offer.json` (Python-written, chunks assert-equal to V07 vectors at generation) and `tests/testdata-ts/ts_interop.json` (TS-written, `ts_`-prefixed keys per brief). Generators `tests/export_interop_fixtures.py` + `ts/scripts/export-fixtures.ts` (run once; outputs committed; both self-check round-trip before writing; `tsconfig.json` include extended to `scripts/**/*.ts` so `npm run check` covers the exporter).
- TEST-ONLY committed private keys (`_test_only_keys: true` in both fixtures + here): Py->TS actor Ed25519 seed `0x11`x32 (== V03 vector key, actor = V03 agent_id), recipient id seed `0x22`x32, recipient X25519 priv `0x44`x32 (`rk-test-py-1`); TS->Py actor seed `0x55`x32, recipient id seed `0x77`x32, recipient X25519 priv `0x66`x32 (`rk-test-ts-1`), CEK `0x20..0x3f`. Throwaway vectors, never production keys. No CEK in clear in either committed fixture (verified by grep; CEK travels only inside HPKE wraps).
- Out of scope (unchanged): card chain, transfer, grants/handoff/policy, quarantine, transport, MCP in TS; CRY-007 review still OPEN.

## D-043: Local-test routes PUT card + GET chunk (post-M8)

- Blueprint section 13 lists only POST packets / PUT chunks / GET card / GET mailbox. Card distribution is OPEN-10 (unresolved). For local multi-session testing, this implementation adds two companion routes:
  - `PUT /aatp/v0.2/agents/{agent_id}/card` -> 204. Body must be a DSSE `card+json` envelope whose payload `agent_id` equals the path id AND whose signature verifies against the card's own `signing_key` (self-published, proves key-holder authorship). Mismatch/tamper -> 400 (`ERR_MALFORMED_MESSAGE` / `ERR_SIGNATURE_INVALID`).
  - `GET /aatp/v0.2/transfers/{tx}/chunks/{i}` -> 200 `application/octet-stream` / 404 `ERR_TRANSFER_NOT_FOUND` (chunk absent). No auth: chunks are opaque AEAD ciphertext; confidentiality comes from the CEK, not the relay (NET-001/003).
- The relay itself is unchanged (still opaque, never opens packets).
