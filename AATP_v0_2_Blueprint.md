---
spec_id: AATP
title: Autonomous Agent Transfer Protocol
version: 0.2.0-draft
supersedes: 0.1.0
status: DRAFT - NOT CRYPTOGRAPHICALLY REVIEWED - DO NOT DEPLOY TO PRODUCTION
date: 2026-10-01
audience: [AI coding agents, protocol engineers, security reviewers]
precedence: [normative_rules, schemas, byte_grammars, pseudocode, test_vectors, examples]
vectors_file: aatp_v0_2_vectors.json
vectors_generator: reference_vectors.py
---

# AATP v0.2 — Machine-Readable Protocol Blueprint

## 0. How an AI agent must read this document

1. **Rule IDs are atomic.** Every normative statement has an ID like `ART-007`. Implement each rule as one testable unit. Cite the ID in code comments and test names.
2. **Keywords** MUST, MUST NOT, SHOULD, MAY follow RFC 2119. Only lines with a rule ID are normative. Prose is explanatory.
3. **Precedence** when sources disagree: rules > schemas > byte grammars > pseudocode > vectors > examples. If `reference_vectors.py` disagrees with a rule, the rule wins and the script has a bug — report it, do not silently "fix" the rule.
4. **Silence = fail closed.** If this spec does not define a behavior, reject the message with the closest `ERR_*` code, and record the gap in `DECISIONS.md`. Never invent cryptography or guess byte layouts.
5. **Private keys never enter an LLM context.** Signing and decryption run inside a `Signer`/`KeyStore` component; the model only receives results (`SIG-001`).
6. Items marked `[[OPEN-n]]` are unresolved (Section 20). Do not implement them as if decided.

### 0.1 What changed from v0.1 (and why)

| # | v0.1 defect | v0.2 fix | Rules |
|---|---|---|---|
| 1 | `artifact_root` hashed content only; a revert (A→B→A′) produced identical hashes and was misreported as a DAG cycle | Split **content_root** (what the bytes are) from **node_id** (provenance event, hash-linked to parents). Cycles become impossible by construction | ART-020..025, PRV-001..012 |
| 2 | Hash grammar ambiguous (`MERKLE_OR_SHA256`), manifest lacked per-file digests, zip is non-deterministic | One frozen grammar; per-file digests; no archive format — artifact = sorted file tree streamed as raw bytes | ART-001..030 |
| 3 | Hand-rolled handshake, transcript binding only `SHOULD`, no identity binding, pre-hashed Ed25519 | Handshake removed from core. Stateless signed messages (DSSE) + HPKE (RFC 9180). Ed25519 signs PAE directly | CRY-001..010, MSG-001..020 |
| 4 | Chunk nonce/AAD undefined; resume across sessions broken | Per-transfer random CEK; nonce = chunk index; AAD binds content_root, index, total, transfer_id | ENC-001..012 |
| 5 | Trust anchor undefined ("configured trust mechanism") | Self-certifying `agent_id`, pinned trust mode, signed key rotation with pre-rotation commitment | ID-001..020 |
| 6 | Pairwise/synchronous only | Store-and-forward + N recipients via per-recipient HPKE key wrap | ENC-020..025 |
| 7 | Authorization was local policy only | Delegable capability **Grants** with cryptographic attenuation; handoff carries a grant | AUT-001..020, HND-001..012 |
| 8 | No AI-specific threats | Untrusted-content doctrine, `instruct` capability, AI `generator` provenance block | SEC-001..012, PRV-020..024 |
| 9 | Namespace typo `aapt`, leaked editorial text | Single namespace `aatp.*`; editorial cleanup | GEN-005 |

## 1. Purpose, positioning, non-goals

- **Purpose:** exchange *artifacts* (file trees produced by agents) between agents across trust boundaries with: verifiable sender identity, end-to-end confidentiality, content addressing, hash-linked provenance, delegable authorization, and task handoff.
- **Positioning:** complementary to A2A (task/messaging) and MCP (tools). AATP does not claim that "encrypted agent file transfer" is novel (existing: AgentDrop, AEX variants, etc.). Differentiators: hash-linked **AI provenance**, **untrusted-content doctrine**, **attenuable grants**, **handoff with leases**.
- **Non-goals:** defining models; new cryptographic primitives; replacing Git/S3/CI; guaranteeing semantic correctness of artifacts; malware detection as a cryptographic property.

## 2. Conventions

| ID | Rule |
|---|---|
| GEN-001 | Wire format is UTF-8 JSON. Signed/hashed JSON MUST be canonicalized per GEN-010. |
| GEN-002 | Digests are strings `sha256:<64 lowercase hex>`. Only SHA-256 is defined in v0.2. |
| GEN-003 | Binary-in-JSON uses base64url without padding (RFC 4648 §5). |
| GEN-004 | Timestamps are exactly `YYYY-MM-DDTHH:MM:SSZ` (UTC, seconds, no fraction). |
| GEN-005 | The only identifier namespace prefix is `aatp`. Capability IDs `aatp.<area>.<name>`; HTTP paths `/aatp/v0.2/...`. |
| GEN-006 | Message/transfer/task IDs: `msg_`, `tx_`, `task_` + UUIDv7 (lowercase, hyphenated) unless the application supplies its own opaque string (≤128 chars, `[A-Za-z0-9_.:-]`). |
| GEN-010 | **Canonical JSON = RFC 8785 (JCS) restricted subset:** object keys ASCII only; **no floating-point numbers** (integers only, \|n\| ≤ 2^53−1); no duplicate keys; max nesting depth 16; UTF-8 output; no insignificant whitespace; keys sorted by code unit; strings escaped per JCS. |
| GEN-011 | A parser MUST reject (not repair) any signed object violating GEN-010 with `ERR_MALFORMED_MESSAGE`. |
| GEN-012 | Unknown *optional* fields MUST be ignored but MUST be preserved byte-for-byte when re-serializing signed objects. Unknown fields listed in `crit` MUST cause `ERR_UNSUPPORTED_EXTENSION`. |

### 2.1 Default limits (configurable, but every limit MUST exist — GEN-020)

| Limit | Default |
|---|---|
| `max_message_bytes` (control message, pre-seal) | 262144 |
| `max_manifest_entries` | 10000 |
| `max_path_bytes` | 1024 |
| `max_total_artifact_bytes` | 4294967296 (4 GiB) |
| `chunk_size` default / max | 1048576 / 16777216 |
| `total_chunks` max | 4294967295 |
| `send_window_chunks` | 16 |
| `clock_skew_seconds` | 120 |
| `message_lifetime_max_seconds` | 86400 |
| `offer_lifetime_default_seconds` | 3600 |

## 3. Cryptographic suite `AATP-S1`

### 3.1 Primitives

| Purpose | Primitive | Requirement |
|---|---|---|
| Identity signatures | Ed25519 (RFC 8032) | REQUIRED |
| Signed-envelope framing | DSSE v1 PAE | REQUIRED |
| Key encapsulation / message sealing | HPKE base mode (RFC 9180): KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003` ChaCha20-Poly1305 | REQUIRED |
| Bulk chunk AEAD | ChaCha20-Poly1305 (RFC 8439) | REQUIRED |
| Bulk chunk AEAD (alt) | AES-256-GCM | OPTIONAL (`aatp.crypto.aes256gcm`) |
| Digest | SHA-256 | REQUIRED |

| ID | Rule |
|---|---|
| CRY-001 | Implementations MUST use a vetted library for every primitive. Hand-written HPKE/AEAD/Ed25519 is forbidden. |
| CRY-002 | Ed25519 signs the DSSE PAE bytes directly. It MUST NOT sign a pre-hash. |
| CRY-003 | Verifiers MUST reject non-canonical Ed25519 signatures (S ≥ L) and MUST use one consistent strict verification mode across the implementation. |
| CRY-004 | Identity (signing) keys MUST NOT be used for encryption. Encryption uses a separate X25519 key (`enc_key`). |
| CRY-005 | Algorithm agility is by suite ID only (`AATP-S1`). No per-primitive negotiation. A peer advertising an unknown suite gets `ERR_SUITE_UNSUPPORTED`; silent downgrade is forbidden. |
| CRY-006 | Randomness MUST come from the OS CSPRNG. |
| CRY-007 | This suite is a composition of standard primitives, but the composition has **not** been reviewed. A qualified cryptographer MUST review before any production use (`[[OPEN-1]]`). |

### 3.2 Forward secrecy note (honest limitation)

HPKE base mode gives no forward secrecy against later compromise of the recipient's `enc_key`. Mitigation: `enc_key` MUST be short-lived (ID-012) and destroyed after expiry. True per-session FS is an optional "live session" extension (Noise_XX, `[[OPEN-2]]`), not part of core.

### 3.3 Domain-separation constants (byte-exact ASCII, trailing `\n` included)

```
D_CONTENT  = "AATP/0.2/CONTENT\n"
D_NODE     = "AATP/0.2/NODE\n"
D_AGENT    = "AATP/0.2/AGENT-ID\n"
D_CHUNK    = "AATP/0.2/CHUNK\n"
D_PACKET   = "AATP/0.2/PACKET\n"
D_CEKWRAP  = "AATP/0.2/CEK-WRAP\n"
```

| DSSE payloadType | Used for |
|---|---|
| `application/vnd.aatp.message+json` | Protocol messages |
| `application/vnd.aatp.node+json` | Provenance nodes |
| `application/vnd.aatp.card+json` | Agent Cards |
| `application/vnd.aatp.grant+json` | Grants |
| `application/vnd.aatp.rotation+json` | Key rotation / revocation statements |

### 3.4 Signing grammar

```
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
   LEN(x) = ASCII decimal byte length, no leading zeros
signature = Ed25519.Sign(sk, PAE(payloadType, JCS(object)))
envelope  = { "payloadType": T, "payload": b64url(JCS(object)),
              "signatures": [ { "keyid": K, "sig": b64url(signature) } ] }
```

| ID | Rule |
|---|---|
| SIG-001 | Signing MUST be performed by a `Signer` interface holding the key; callers pass `(payloadType, bytes)` and receive a signature. The private key MUST NOT be exposed to application code or LLM context. |
| SIG-002 | A verifier MUST recompute JCS of the decoded payload and require byte equality with the received payload bytes (reject if re-canonicalization differs). |
| SIG-003 | A verifier MUST check `payloadType` matches the expected object kind before parsing the payload. |

## 4. Agent identity (fixes trust-anchor gap)

### 4.1 Self-certifying `agent_id`

```
agent_id = "aatp:" + lowercase(base32_rfc4648_nopad( SHA256( D_AGENT || genesis_public_key_raw32 ) ))   # 52 chars after prefix
```

| ID | Rule |
|---|---|
| ID-001 | `agent_id` MUST be derived exactly as above from the agent's **genesis** Ed25519 public key. It never changes across rotations. |
| ID-002 | Human-readable aliases are non-authoritative labels and MUST NOT be used for trust decisions. |

### 4.2 Trust modes

| Mode | Meaning | Requirement |
|---|---|---|
| `pinned` | Receiver obtained `agent_id` out-of-band (config, QR, prior contact). | REQUIRED support |
| `org_attested` | Card carries an attestation signed by an org key the receiver trusts. | OPTIONAL |
| `did` | Alias via DID method resolving to the same genesis key. | OPTIONAL extension |

| ID | Rule |
|---|---|
| ID-003 | A receiver MUST NOT deliver or accept protected artifacts from an `agent_id` not admitted by a configured trust mode (`ERR_AUTH_FAILED`). |
| ID-004 | First-contact of an unknown `agent_id` MUST be handled by policy (deny by default), never by implicit trust-on-first-use unless explicitly configured. |

### 4.3 Agent Card

Schema: `AgentCard` (Appendix A.3). Key fields: `agent_id`, `genesis_public_key`, `signing_key{key_id,public_key,not_before,not_after}`, `enc_key{key_id,public_key,not_before,not_after}`, `key_history[]` (rotation statements), `next_commitment?`, `revoked[]`, `endpoints[]`, `capabilities[]`, `suites[]`, `seq`, `issued_at`, `expires_at`.

| ID | Rule |
|---|---|
| ID-010 | The Card MUST be a DSSE envelope signed by `signing_key`. |
| ID-011 | `seq` is a monotonically increasing integer. Receivers MUST cache the highest verified `seq` per `agent_id` and reject lower values (`ERR_CARD_ROLLBACK`). |
| ID-012 | `enc_key` validity window MUST be ≤ 7 days by default. Senders MUST NOT wrap to an expired `enc_key`. |
| ID-013 | Card validity (`expires_at − issued_at`) MUST be ≤ 30 days. |
| ID-014 | `not_before`/`not_after` of every key MUST be enforced with `clock_skew_seconds` tolerance. |

### 4.4 Rotation, pre-rotation, revocation

Rotation statement (DSSE `rotation+json`), signed by the **old** signing key:

```json
{"v":"0.2","type":"rotate","agent_id":"aatp:...","from_key_id":"k1","to_key_id":"k2",
 "to_public_key":"<b64url>","effective_at":"2026-10-01T00:00:00Z","next_commitment":"sha256:<digest of the NEXT-next key>"}
```

| ID | Rule |
|---|---|
| ID-020 | If the previous statement (or Card) carried `next_commitment`, then `sha256(to_public_key_raw32)` MUST equal it, else `ERR_KEY_COMMITMENT_MISMATCH`. |
| ID-021 | Every Card MUST include the full `key_history` from genesis to the current signing key. Verifiers MUST walk it (Algorithm 4.5). |
| ID-022 | Agents SHOULD publish `next_commitment` (pre-rotation). It lets the holder of the *next* key recover after compromise of the current key. |
| ID-023 | Revocation statement `{"type":"revoke","agent_id","key_id","effective_at","reason"}` MUST be signed by the current signing key **or** by the key matching the active `next_commitment`. |
| ID-024 | Verifiers MUST reject any message signed by a key revoked with `effective_at` ≤ message `created_at`. Messages created before revocation remain valid only if received before the verifier learned of revocation **and** policy allows (`ERR_KEY_REVOKED` otherwise). |

### 4.5 Algorithm: `verify_card(card_env, pinned_agent_id, cache, now)`

```
1. env = parse_dsse(card_env); require payloadType == card+json   # SIG-003
2. card = parse_jcs(env.payload)                                   # SIG-002
3. require card.agent_id == pinned_agent_id (or trust-mode admits it)
4. require derive_agent_id(card.genesis_public_key) == card.agent_id          # ID-001
5. key = genesis; commitment = None
6. for stmt in card.key_history (in order):
     require verify(stmt_env, key.public_key)
     require stmt.from_key_id == key.key_id
     if commitment and sha256(stmt.to_public_key) != commitment: fail ERR_KEY_COMMITMENT_MISMATCH
     key = {key_id: stmt.to_key_id, public_key: stmt.to_public_key}
     commitment = stmt.next_commitment
7. require key.key_id == card.signing_key.key_id and key.public_key == card.signing_key.public_key
8. require verify(env, card.signing_key.public_key)                # ID-010
9. require now within [issued_at - skew, expires_at + skew]; key windows valid   # ID-013/014
10. require card.seq >= cache.highest_seq(agent_id)                 # ID-011
11. require no applicable revocation                                # ID-024
12. cache.highest_seq(agent_id) = card.seq; return card
```

## 5. Signed messages and sealed packets

### 5.1 Message (inside DSSE `message+json`)

```json
{
  "v": "0.2", "type": "OFFER", "id": "msg_0199...",
  "sender": "aatp:...", "sender_key_id": "k2", "recipient": "aatp:...",
  "created_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-01T01:00:00Z",
  "corr": { "transfer_id": "tx_...", "task_id": "task_...", "in_reply_to": "msg_..." },
  "crit": [],
  "body": { }
}
```

| ID | Rule |
|---|---|
| MSG-001 | Every control message MUST be a DSSE envelope signed by `sender`'s current signing key and MUST contain `recipient`. |
| MSG-002 | A receiver MUST reject a message whose `recipient` ≠ its own `agent_id` (`ERR_RECIPIENT_MISMATCH`). This prevents surreptitious forwarding of sign-then-encrypt messages. |
| MSG-003 | `expires_at − created_at` MUST be ≤ `message_lifetime_max_seconds`; receivers reject expired or future-dated (beyond skew) messages with `ERR_MESSAGE_EXPIRED`. |
| MSG-004 | Receivers MUST persist `(sender, id)` until `expires_at + skew` and reject repeats of side-effecting messages with `ERR_REPLAY_DETECTED`. The replay cache MUST survive process restart. |
| MSG-005 | Retransmission of the *same* signed message returns the previously produced response (idempotency) rather than re-executing. |
| MSG-006 | Message `type` MUST be in the registry (Section 8.1). Unknown type → `ERR_UNSUPPORTED_MESSAGE`. |

### 5.2 Sealed packet (what a relay sees)

```json
{ "aatp": "0.2", "to": "aatp:...", "to_key_id": "e5", "enc": "<b64url>", "ct": "<b64url>" }
```

```
info = D_PACKET || to || "\n" || to_key_id
(enc, ct) = HPKE.SealBase(pkR = recipient.enc_key, info = info, aad = "", pt = JCS(dsse_envelope))
```

| ID | Rule |
|---|---|
| MSG-010 | All messages carrying file names, hashes, grants, or key wraps (OFFER, HANDOFF_*, RECEIPT, TASK_UPDATE) MUST be sealed. Card fetch and liveness MAY be clear. |
| MSG-011 | Order is **sign, then seal**. The receiver unseals, then verifies the signature and `recipient` (MSG-002). |
| MSG-012 | A relay sees only `to`, `to_key_id`, size and timing. Relays MUST NOT need any other field. |
| MSG-013 | `max_message_bytes` applies to the plaintext DSSE envelope; oversize → `ERR_SIZE_LIMIT`. |

### 5.3 Algorithm: `receive_control(packet)`

```
1. if packet.to != self.agent_id: drop (ERR_RECIPIENT_MISMATCH)
2. key = self.enc_keys[packet.to_key_id]; require key valid now (ID-012)
3. env_bytes = HPKE.OpenBase(enc, key, info, "", ct);  on failure -> ERR_DECRYPT_FAILED
4. env = parse_dsse(env_bytes); msg = parse_jcs(env.payload)       # GEN-010/011, SIG-002
5. card = resolve_card(msg.sender); require trust admits sender     # ID-003
6. require verify(env, card.signing_key(msg.sender_key_id))        # ERR_SIGNATURE_INVALID
7. check recipient (MSG-002), time window (MSG-003), replay (MSG-004)
8. dispatch by msg.type through the state machine (Section 9)
```

## 6. Artifact model (fixes hash ambiguity)

An artifact is an **ordered tree of regular files**. There is no archive format in the protocol. Symlinks, hardlinks, devices, and directories-as-entries are not representable.

### 6.1 Path rules

| ID | Rule |
|---|---|
| ART-001 | Path is UTF-8, `/`-separated, relative, NFC-normalized. Non-NFC input MUST be rejected, not normalized. |
| ART-002 | Reject empty segments, `.`, `..`, leading `/`, trailing `/`, backslash, NUL, and any control character (U+0000–U+001F, U+007F). |
| ART-003 | Reject segments ending in space or `.`; reject Windows reserved names (`CON PRN AUX NUL COM1-9 LPT1-9`, case-insensitive, with or without extension). |
| ART-004 | Reject a manifest where two paths are equal under Unicode case-folding (`ERR_PATH_INVALID`). |
| ART-005 | Reject a manifest where one path is a proper directory-prefix of another file path (file/dir collision). |
| ART-006 | Path byte length ≤ `max_path_bytes`; entry count ≤ `max_manifest_entries`; sum of sizes ≤ `max_total_artifact_bytes`. |
| ART-007 | Entries are sorted ascending by **bytewise UTF-8** path. Unsorted or duplicated paths → `ERR_MANIFEST_INVALID`. |

### 6.2 Manifest and `content_root`

```json
{"v":"0.2","entries":[
  {"path":"bin/run.sh","size":8,"x":true, "d":"sha256:<sha256 of file bytes>"},
  {"path":"hello.txt", "size":5,"x":false,"d":"sha256:<sha256 of file bytes>"}
]}
```

```
manifest_bytes = JCS(manifest)
content_root   = "sha256:" + hex( SHA256( D_CONTENT || manifest_bytes ) )
```

| ID | Rule |
|---|---|
| ART-010 | `x` is the only mode bit carried (`false`=0644, `true`=0755). Receivers MUST NOT apply any other mode. |
| ART-011 | `d` is SHA-256 of the raw file bytes. `size` is the exact byte length. |
| ART-012 | `content_root` MUST be computed exactly as above. There is no Merkle/SHA-256 alternative in v0.2 (`[[OPEN-3]]` for large-file trees). |
| ART-013 | An empty artifact (zero entries) is valid; its `content_root` is computed the same way. |

### 6.3 The AATP stream

```
stream = concat( file_bytes(e) for e in manifest.entries in order )      # no separators, no padding
len(stream) = sum(e.size)
```

| ID | Rule |
|---|---|
| ART-020 | Chunks are fixed-size slices of `stream`; the last chunk may be shorter. `total_chunks = ceil(len(stream)/chunk_size)`; zero-length stream ⇒ `total_chunks = 0`. |
| ART-021 | The receiver splits the reassembled stream by manifest sizes and MUST verify each file's `d` as that file completes. A mismatch → `ERR_ARTIFACT_HASH_MISMATCH`. |
| ART-022 | After all files verify, the receiver MUST recompute `content_root` from the manifest and compare to the signed value. |
| ART-023 | Materialization to disk MUST: join paths under a fresh sandbox root, refuse to follow symlinks (`O_NOFOLLOW`/`O_EXCL`), never execute content, apply only `x` (ART-010), and finish in a quarantine directory until policy releases it. |
| ART-024 | Archive handling (zip/tar) is out of scope. If a file inside an artifact *is* an archive, it is opaque data; unpacking it is an application decision under SEC rules. |

Reference vectors: V04 (Appendix C).

## 7. Provenance nodes and the DAG (fixes the revert/cycle defect)

### 7.1 Node

```json
{
  "v": "0.2",
  "content_root": "sha256:...",
  "parents": ["sha256:<node_id>", "..."],
  "operation": "create|modify|merge|revert|verify|supersede",
  "actor": "aatp:...",
  "task_id": "task_...",
  "created_at": "2026-10-01T00:00:00Z",
  "generator": {
    "kind": "ai|human|tool|mixed",
    "model": { "provider": "...", "name": "...", "version": "..." },
    "runtime": { "name": "...", "version": "..." },
    "prompt_digest": "sha256:...",
    "toolcalls_digest": "sha256:...",
    "human_approver": "aatp:...",
    "assurance": "self_asserted|issuer_attested|hardware_attested"
  },
  "annotations": {}
}
```

```
node_id = "sha256:" + hex( SHA256( D_NODE || JCS(node) ) )
```

| ID | Rule |
|---|---|
| PRV-001 | `node_id` MUST be computed exactly as above. `parents` MUST hold `node_id`s, sorted ascending, without duplicates. |
| PRV-002 | A node MUST be published as a DSSE envelope (`node+json`) signed by `actor`'s signing key. |
| PRV-003 | Because a node commits to its parents' hashes, a cycle is impossible. Implementations MUST still reject any node whose `node_id` appears among its own ancestors (`ERR_DAG_CYCLE`) as a defense against a broken hash function or implementation bug. |
| PRV-004 | Two nodes with equal `content_root` but different `node_id` are **distinct events** (e.g., revert). This is valid and MUST NOT be reported as a cycle. |
| PRV-005 | `created_at` of a node MUST be ≥ each resolved parent's `created_at` minus `clock_skew_seconds`. Violation → `ERR_INVALID_PARENT`. |
| PRV-006 | `operation=merge` requires ≥ 2 parents; `create` requires 0; `modify`, `revert`, `supersede` require ≥ 1. |
| PRV-010 | **Parent availability policy** (`parent_policy` in OFFER): `require` (all ancestors resolvable, else `ERR_INVALID_PARENT`) or `lazy` (accept with `ancestry: "partial"`; unresolved parent IDs are kept as opaque hashes). Default: `lazy`. |
| PRV-011 | Receivers MUST mark each accepted node `ancestry: complete|partial` and expose it to policy. |
| PRV-012 | `verify` nodes MUST reference the verified artifact's node as parent and record outcome in `annotations.verification` (`pass|fail`, `scope`). |

**AI-specific provenance**

| ID | Rule |
|---|---|
| PRV-020 | When `generator.kind` is `ai` or `mixed`, `generator.model.{provider,name,version}` SHOULD be present. |
| PRV-021 | `generator` fields are **claims by the actor**. Unless `assurance` ≥ `issuer_attested` backed by a verifiable attestation, receivers MUST treat them as self-asserted. |
| PRV-022 | `prompt_digest`/`toolcalls_digest` are hashes only. Raw prompts MUST NOT be embedded by default (confidentiality). |
| PRV-023 | If policy requires human approval, the node MUST carry `human_approver` and that agent/person's counter-signature as an additional entry in `signatures[]`. |
| PRV-024 | `[[OPEN-4]]` Standardize attestation formats (in-toto/SLSA predicate mapping) for `issuer_attested` and `hardware_attested`. |

Reference vectors: V05, V06 (Appendix C). **V05 demonstrates the revert case.**

## 8. Messages and transfer

### 8.1 Message registry

| Type | Direction | Sealed | Body (schema ref) | Purpose |
|---|---|---|---|---|
| `OFFER` | S→R | yes | `OfferBody` A.4 | Announce artifact, manifest, node, key wraps |
| `ACCEPT` | R→S | yes | `{transfer_id}` | Policy allows transfer |
| `REJECT` | R→S | yes | `{transfer_id, code, detail?}` | Policy/limits deny |
| `STATUS` | R→S | yes | `{transfer_id, have:[[lo,hi],...]}` | Progress + resume state (receiver-verified) |
| `COMPLETE` | S→R | yes | `{transfer_id, total_chunks}` | All chunks sent |
| `RECEIPT` | R→S | yes | `{transfer_id, content_root, node_id, outcome: accepted\|rejected\|quarantined, code?}` | Signed outcome |
| `HANDOFF_OFFER` | A→B | yes | `HandoffBody` A.6 | Propose responsibility transfer |
| `HANDOFF_RESPONSE` | B→A | yes | `{handoff_id, decision: accept\|reject, code?}` | Decision (signed) |
| `TASK_UPDATE` | any | yes | `{task_id, status, detail?}` | Status: `ASSIGNED,ACCEPTED,IN_PROGRESS,BLOCKED,COMPLETED,FAILED,CANCELLED` |
| `ERROR` | any | yes | `{code, numeric, detail?, corr_id?}` | Machine-readable failure |
| `CHUNK` | S→R | no (AEAD) | see 8.3 | Data plane, not a signed message |

### 8.2 OFFER semantics

`OfferBody`: `{transfer_id, content_root, manifest | sealed_manifest, node_env, chunk_size, total_chunks, stream_len, cipher ("chacha20poly1305"), wraps[], parent_policy, classification, expires_at}`.

| ID | Rule |
|---|---|
| TRF-001 | OFFER MUST contain `node_env` (DSSE node) whose `content_root` equals the OFFER's `content_root`, else `ERR_ARTIFACT_HASH_MISMATCH`. |
| TRF-002 | Receiver MUST validate manifest (ART-001..007), limits, `stream_len == sum(size)`, `total_chunks` per ART-020 **before** replying ACCEPT. |
| TRF-003 | `wraps[]` has one entry per recipient (Section 9, ENC-020). A receiver finds its entry by `agent_id`+`enc_key_id`. |
| TRF-004 | `sealed_manifest` (optional privacy profile): manifest AEAD-encrypted under CEK with nonce `ff*12`, AAD = `D_CHUNK \|\| "manifest"`. `content_root` remains visible only inside the sealed OFFER. |
| TRF-005 | OFFER MUST be rejected after `expires_at` (`ERR_MESSAGE_EXPIRED`). Transfers expire no later than the OFFER. |

### 8.3 CHUNK (data plane)

```
CHUNK = { "transfer_id": "tx_...", "index": 7, "data": b64url(ciphertext) }     # or raw binary on binary bindings
```

| ID | Rule |
|---|---|
| TRF-010 | CHUNK carries no signature; authenticity comes from AEAD under the transfer CEK plus the final signed `content_root` check. |
| TRF-011 | Receiver MUST reject `index ≥ total_chunks` (`ERR_SEQUENCE_INVALID`) and chunks for unknown/expired transfers (`ERR_TRANSFER_NOT_FOUND`). |
| TRF-012 | Duplicate chunks MUST be idempotent: if already verified, discard; do not re-process. |
| TRF-013 | Out-of-order chunks are allowed within the send window; receivers MAY buffer up to `send_window_chunks` ahead of the highest contiguous verified index. |
| TRF-014 | A chunk is "verified" only after AEAD open succeeds with the exact nonce/AAD in ENC-003/004. |

### 8.4 Transfer state machine (receiver view)

| From | Event | Guard | Action | To |
|---|---|---|---|---|
| — | OFFER received | valid & policy allow | send ACCEPT | ACCEPTED |
| — | OFFER received | invalid or policy deny | send REJECT | REJECTED |
| ACCEPTED | first CHUNK | AEAD ok | store | RECEIVING |
| ACCEPTED | offer expired | — | discard | EXPIRED |
| RECEIVING | CHUNK | AEAD ok, in window | store; periodically send STATUS | RECEIVING |
| RECEIVING | CHUNK | AEAD fail | drop; count failures | RECEIVING (abort at N failures → ABORTED) |
| RECEIVING | connection lost | — | persist state | PAUSED |
| PAUSED | any valid CHUNK or sender reconnect | transfer not expired | send STATUS | RECEIVING |
| RECEIVING | COMPLETE | all chunks verified | — | VERIFYING |
| RECEIVING | COMPLETE | chunks missing | send STATUS with `have` | RECEIVING |
| VERIFYING | file digests + content_root + node signature pass; scan clean | policy allow | send RECEIPT accepted | COMPLETE |
| VERIFYING | checks pass; scan suspicious or policy=quarantine | — | send RECEIPT quarantined | QUARANTINED |
| VERIFYING | any integrity/signature failure | — | send RECEIPT rejected (+code) | REJECTED |
| QUARANTINED | trusted release (human/authorized subsystem) | — | send RECEIPT accepted | COMPLETE |
| any | fatal protocol error | — | send ERROR | ABORTED |

| ID | Rule |
|---|---|
| TRF-020 | Receiver MUST persist `{transfer_id, content_root, cek_ref, have_ranges, state}` durably if resume is offered. |
| TRF-021 | **Resume is driven by receiver-verified state.** Sender MUST send only chunks not in the latest STATUS `have`, and MUST NOT assume earlier sends arrived. |
| TRF-022 | Resume uses the same `transfer_id` and same CEK. A *new* transfer attempt MUST use a new `transfer_id` **and** new CEK (ENC-005). |
| TRF-023 | `STATUS.have` ranges are inclusive, sorted, non-overlapping. Invalid → `ERR_RESUME_INVALID`. |
| TRF-024 | Sender window: at most `send_window_chunks` unacknowledged chunks beyond the highest contiguous `have`. |
| TRF-025 | Transfer MUST NOT reach COMPLETE on chunk arrival alone; ART-021/022 and node signature checks are mandatory. |
| TRF-026 | RECEIPT MUST be signed. A sender MUST treat only a valid signed RECEIPT as proof of delivery. |

## 9. Encryption of artifact bytes

### 9.1 Key schedule

```
CEK             = random 32 bytes, fresh per (transfer_id)                          # ENC-005
nonce(i)        = 0x00000000 || uint64_be(i)                                        # 12 bytes
nonce(manifest) = 0xff * 12
AAD(i)          = D_CHUNK || JCS({"cr": content_root, "i": i, "n": total_chunks, "t": transfer_id})
ciphertext(i)   = ChaCha20Poly1305.Seal(CEK, nonce(i), AAD(i), plaintext_chunk(i))   # len = pt + 16
```

| ID | Rule |
|---|---|
| ENC-001 | A CEK MUST NOT encrypt any plaintext other than the exact chunk at its index for one `(content_root, transfer_id)`. |
| ENC-002 | Re-sending chunk `i` MUST reproduce identical ciphertext (deterministic), never re-encrypt different data under the same `(CEK, nonce)`. |
| ENC-003 | Nonce is exactly as above; random nonces are forbidden for chunks. |
| ENC-004 | AAD is exactly as above; this binds each chunk to its artifact, position, total length and transfer (prevents reorder, truncation, transplant). |
| ENC-005 | Every new transfer attempt generates a new CEK (prevents cross-transfer nonce reuse). |
| ENC-006 | Receivers MUST reject `index ≥ 2^63` (keeps `nonce(manifest)` disjoint). |
| ENC-007 | AEAD failure → `ERR_CHUNK_AUTH_FAILED`; the chunk is discarded and MUST NOT be acknowledged. |

### 9.2 Key wrapping (store-and-forward and N recipients)

```
for each recipient r:
    info_r = D_CEKWRAP || JCS({"cr":content_root,"s":sender_agent_id,"r":r.agent_id,"t":transfer_id,"k":r.enc_key_id})
    (enc_r, ct_r) = HPKE.SealBase(pkR = r.enc_key, info = info_r, aad = "", pt = CEK)
    wraps.append({"agent_id": r.agent_id, "enc_key_id": r.enc_key_id, "enc": b64u(enc_r), "ct": b64u(ct_r)})
```

| ID | Rule |
|---|---|
| ENC-020 | One wrap per recipient; the same CEK and ciphertext chunks serve all recipients (group transfer). |
| ENC-021 | The wrap `info` MUST bind content_root, sender, recipient, transfer_id and key id. |
| ENC-022 | Recipients can decrypt the artifact later (store-and-forward): chunks MAY be held by a relay or object store as opaque ciphertext. |
| ENC-023 | **Group caveat:** because all recipients share the CEK, any recipient could forge chunks for another. Authenticity for each recipient still holds via the sender-signed `node`/`content_root` check (ART-022). |

Reference vectors: V07, V08 (Appendix C). HPKE is not given a fixed vector: test with library round-trip + the RFC 9180 official vectors (`CRY-001`).

## 10. Authorization: Grants and handoff

### 10.1 Grant (DSSE `grant+json`)

```json
{
  "v": "0.2", "iss": "aatp:owner...", "aud": "aatp:agentB...",
  "cap": [ { "act": "aatp.artifact.receive", "res": "project:alpha/*" } ],
  "nbf": "2026-10-01T00:00:00Z", "exp": "2026-10-02T00:00:00Z",
  "prf": [ "sha256:<grant_id of parent>" ],
  "constraints": { "classification_max": "INTERNAL", "export": false }
}
grant_id = "sha256:" + hex(SHA256("AATP/0.2/GRANT\n" || JCS(grant)))
```

Action vocabulary: `aatp.artifact.send`, `aatp.artifact.receive`, `aatp.artifact.derive`, `aatp.artifact.instruct`, `aatp.task.handoff`, `aatp.task.accept`, `aatp.grant.delegate`.

Resources are opaque URN-ish strings; a trailing `*` means prefix match. `res_subset(child, parent) := child == parent OR (parent ends with "*" AND child starts with parent[:-1])`.

| ID | Rule |
|---|---|
| AUT-001 | A chain is valid only if the root grant's `iss` is a configured policy root for the resource (owner). |
| AUT-002 | **Attenuation:** for every child grant `g` with parent `p`: `g.iss == p.aud`; every `g.cap` entry is covered by some `p.cap` entry (same `act`, `res_subset`); `g.nbf ≥ p.nbf`; `g.exp ≤ p.exp`; `g.constraints` are at least as restrictive. Violation → `ERR_GRANT_ATTENUATION`. |
| AUT-003 | Delegation requires the parent to include `aatp.grant.delegate` for that resource. |
| AUT-004 | Chain depth ≤ 8. Grants past `exp` or before `nbf` (± skew) are invalid (`ERR_GRANT_INVALID`). |
| AUT-005 | Revoked grants are listed by `grant_id` in a signed revocation list from the issuer; verifiers with fresh-list policy MUST reject revoked IDs. |
| AUT-006 | Verifiers MUST pass the *presenter* check: `chain.leaf.aud == message.sender`. |

### 10.2 Policy evaluation order (fail closed at first deny)

```
1 unseal+verify packet (5.3)             6 verify node + content_root          (after transfer)
2 trust admits sender (ID-003)           7 classification vs grant constraints
3 grant chain valid for action+resource  8 untrusted-content rules (SEC-001..)
4 size/entry limits                      9 scan -> accept | quarantine | reject
5 offer expiry & replay
```

### 10.3 Handoff (two-phase with lease)

`HandoffBody`: `{handoff_id, task, input_node_ids[], grant_env, expected_outputs[], deadline, lease_expires_at, policy_context}`.

| ID | Rule |
|---|---|
| HND-001 | Responsibility transfers **only** when the sender holds a valid signed `HANDOFF_RESPONSE{accept}` received before `lease_expires_at`. |
| HND-002 | Until then, the sender remains responsible. On lease expiry without response, the handoff is void; a late accept MUST be answered with `ERR_LEASE_EXPIRED`. |
| HND-003 | A handoff MUST NOT broaden permissions: the embedded grant MUST satisfy AUT-002 relative to the sender's own authority. |
| HND-004 | Input artifacts referenced by `input_node_ids` MUST be transferable under a grant whose `res` covers them; otherwise `ERR_POLICY_DENIED`. |
| HND-005 | Acceptance MAY be conditional via `constraints`; conditions not satisfiable → reject with `ERR_POLICY_DENIED`. |
| HND-006 | The accepted handoff id + decision are appended to the task's audit log (Section 12). |

## 11. Untrusted-content doctrine (AI-specific security)

A valid signature proves **who sent** an artifact, never that its content is **safe to obey**.

| ID | Rule |
|---|---|
| SEC-001 | Artifact content (text, code, metadata, filenames) MUST be treated as **data**, never as instructions, by any LLM/agent component, regardless of sender authentication. |
| SEC-002 | Every accepted artifact carries `consumption_mode`: `data_only` (default) or `instructions_allowed`. `instructions_allowed` requires a valid grant with `aatp.artifact.instruct` for that resource. |
| SEC-003 | Agent runtimes MUST place artifact content in a clearly delimited, lower-privilege channel, separate from system/developer instructions, and MUST NOT allow such content to alter grants, policies, tool allow-lists, or key operations. |
| SEC-004 | Tools invoked *because of* artifact content MUST be re-authorized against the agent's own grants, not the artifact's claims. |
| SEC-005 | Filenames and manifest strings MUST be escaped/quoted before being shown to a model or shell. |
| SEC-006 | A `quarantined` artifact is a local state. It MUST NOT be described to third parties as "malicious" unless a trusted subsystem established that (carried over from v0.1). |
| SEC-007 | Scanners (malware, secrets, prompt-injection heuristics) are policy dependencies, not cryptographic guarantees; their verdict is recorded with scanner name/version. |
| SEC-008 | Artifacts derived from `rejected` or `quarantined` inputs MUST carry `annotations.tainted_from` listing those `node_id`s. |

## 12. Audit and observability

| ID | Rule |
|---|---|
| AUD-001 | Log the events below with the listed fields. Logs MUST NOT contain plaintext payloads, CEKs, or private keys (`SIG-001`). |
| AUD-002 | Audit logs SHOULD be hash-chained (`entry_hash = SHA256(prev_hash || JCS(entry))`). |

| Event | Minimum fields |
|---|---|
| `message_received` | id, type, sender, verdict, code? |
| `transfer_state` | transfer_id, from, to, content_root |
| `chunk_verified` | transfer_id, index |
| `artifact_verified` | content_root, node_id, ancestry |
| `policy_decision` | subject, action, resource, decision, rule_id |
| `key_event` | agent_id, key_id, rotate/revoke |
| `handoff` | handoff_id, task_id, decision |

## 13. Transport bindings (non-normative except packet format)

| Item | Definition |
|---|---|
| Packet | Section 5.2 JSON. Any transport that delivers bytes can carry it. |
| HTTP (reference) | `POST /aatp/v0.2/packets` → `202` (idempotent by packet hash). `PUT /aatp/v0.2/transfers/{tx}/chunks/{i}` with `application/octet-stream` body, `204` on store, idempotent. `GET /aatp/v0.2/agents/{agent_id}/card` → signed Card. `GET /aatp/v0.2/mailbox/{agent_id}` authenticated by a signed request (DSSE over method+path+created_at). |
| WebSocket / QUIC / P2P | Carry the same packets and chunk frames. |
| Relay | Store-and-forward mailbox keyed by `to`. |

| ID | Rule |
|---|---|
| NET-001 | TLS is defense in depth; AATP security MUST NOT depend on it. |
| NET-002 | Relays MUST enforce size, rate and concurrency limits and MAY require their own auth; they MUST NOT alter packets (MSG-012). |
| NET-003 | Metadata exposed to relays (to, size, timing, transfer_id, chunk index) is an accepted limitation; padding/mixing are extensions (`[[OPEN-5]]`). |

## 14. Error model

Numeric ranges: 10xx envelope/version, 11xx identity/auth, 12xx policy/grants, 13xx artifact, 14xx transfer, 15xx quarantine, 8xxx vendor, 9000 internal.

| Code | Num | Meaning |
|---|---|---|
| ERR_PROTOCOL_VERSION | 1001 | Unsupported version |
| ERR_MALFORMED_MESSAGE | 1002 | Violates schema/GEN-010 |
| ERR_UNSUPPORTED_MESSAGE | 1003 | Unknown message type |
| ERR_UNSUPPORTED_EXTENSION | 1004 | Unknown critical extension |
| ERR_SUITE_UNSUPPORTED | 1005 | Crypto suite not supported |
| ERR_SIZE_LIMIT | 1006 | Exceeds configured limit |
| ERR_AUTH_REQUIRED | 1101 | Authentication required |
| ERR_AUTH_FAILED | 1102 | Sender not admitted/verified |
| ERR_SIGNATURE_INVALID | 1103 | Signature invalid |
| ERR_KEY_EXPIRED | 1104 | Key outside validity window |
| ERR_KEY_REVOKED | 1105 | Key revoked |
| ERR_REPLAY_DETECTED | 1106 | Duplicate side-effecting message |
| ERR_KEY_COMMITMENT_MISMATCH | 1107 | Rotation violates pre-rotation commitment |
| ERR_CARD_ROLLBACK | 1108 | Card `seq` lower than cached |
| ERR_RECIPIENT_MISMATCH | 1109 | Message not addressed to this agent |
| ERR_MESSAGE_EXPIRED | 1110 | Outside time window |
| ERR_DECRYPT_FAILED | 1111 | HPKE open failed |
| ERR_POLICY_DENIED | 1201 | Policy denied |
| ERR_GRANT_INVALID | 1202 | Grant expired/invalid/revoked |
| ERR_GRANT_ATTENUATION | 1203 | Delegation broadens authority |
| ERR_LEASE_EXPIRED | 1204 | Handoff lease expired |
| ERR_ARTIFACT_NOT_FOUND | 1301 | Unavailable |
| ERR_ARTIFACT_HASH_MISMATCH | 1302 | File digest or content_root mismatch |
| ERR_CHUNK_AUTH_FAILED | 1303 | AEAD failed on chunk |
| ERR_INVALID_PARENT | 1305 | Parent invalid/missing/time-inconsistent |
| ERR_DAG_CYCLE | 1306 | Node among own ancestors |
| ERR_PATH_INVALID | 1307 | Violates ART-001..005 |
| ERR_MANIFEST_INVALID | 1308 | Unsorted/duplicate/size mismatch |
| ERR_TRANSFER_NOT_FOUND | 1401 | Unknown transfer |
| ERR_SEQUENCE_INVALID | 1402 | Bad chunk index |
| ERR_RESUME_INVALID | 1403 | Bad resume ranges |
| ERR_RATE_LIMIT | 1405 | Rate/concurrency limit |
| ERR_QUARANTINED | 1501 | Placed in quarantine |
| ERR_SCAN_REQUIRED | 1502 | Policy requires scan |
| ERR_INTERNAL | 9000 | Implementation failure |

## 15. Threat model (updated)

| Threat | Mitigation (rules) | Residual |
|---|---|---|
| Impersonation | Self-certifying ID, DSSE signatures (ID-001, MSG-001) | Compromised signing key; recover via pre-rotation (ID-022) |
| Forwarding/re-sealing a signed message | `recipient` inside signature (MSG-002) | — |
| Replay | Expiry + persistent id cache (MSG-003/004) | Cache loss |
| Chunk reorder/truncate/transplant | AAD binds cr, i, n, t (ENC-004) | — |
| Nonce reuse | Index-derived nonce + fresh CEK (ENC-003/005) | Implementation bugs → V07/V08 tests |
| Wrong-bytes-same-hash confusion | Per-file digests + frozen grammar (ART-011/012) | SHA-256 break |
| Revert misdetected as cycle | content_root vs node_id split (PRV-004) | — |
| Path traversal / collisions | ART-001..007, ART-023 | Filesystem quirks |
| Zip bomb | No archive format; size limits (ART-006, ART-024) | App-level unpacking |
| Prompt injection via signed artifact | SEC-001..005 | Agent-runtime quality |
| Over-broad delegation | Attenuation (AUT-002, HND-003) | Policy misconfiguration |
| Stale/zombie handoff | Leases (HND-001/002) | Clock skew |
| Downgrade | Single suite ID (CRY-005) | — |
| Relay compromise | E2E (MSG-010/012, ENC) | Traffic analysis (NET-003) |
| Recipient `enc_key` compromise | Short-lived keys (ID-012) | No per-session FS (3.2) |
| Malicious insider recipient (group) | Final signed root check (ENC-023) | Can forge for peers until verification |

## 16. Interoperability

| With | Mapping |
|---|---|
| A2A | A2A Task ↔ AATP `task_id`. A2A Artifact ↔ AATP `node_id` + `content_root`. Use A2A for discovery and task messages; use AATP when secure transfer + provenance are required. AATP MUST NOT redefine A2A task state. |
| MCP | Expose AATP as tools. Minimum: `aatp_offer(paths, recipients, task_id)`, `aatp_fetch(transfer_id)`, `aatp_verify(content_root)`, `aatp_provenance(node_id)`, `aatp_handoff(task_id, agent, grant)`. Tools return **results only**; keys stay in the `Signer` (SIG-001). Tool outputs containing artifact text are untrusted content (SEC-001). |
| Git | An artifact may contain a repo snapshot; Git stays version control. |
| Object stores | Hold ciphertext chunks only (ENC-022). |

## 17. Conformance

Levels: **Core** (ID, MSG, ART, PRV, ENC, TRF) · **Extended** (AUT, HND, SEC, AUD, resume, relay) · **Interop** (A2A/MCP adapters) · **Enterprise** (org_attested, key-management integration).

### 17.1 Mandatory negative tests

| Test | Input | Expected |
|---|---|---|
| N01 | Altered byte in signed payload | `ERR_SIGNATURE_INVALID` |
| N02 | Float in signed object | `ERR_MALFORMED_MESSAGE` |
| N03 | Payload not in canonical form | `ERR_MALFORMED_MESSAGE` |
| N04 | Message to other recipient | `ERR_RECIPIENT_MISMATCH` |
| N05 | Expired message | `ERR_MESSAGE_EXPIRED` |
| N06 | Repeated message id | `ERR_REPLAY_DETECTED` |
| N07 | Card with lower `seq` | `ERR_CARD_ROLLBACK` |
| N08 | Rotation violating commitment | `ERR_KEY_COMMITMENT_MISMATCH` |
| N09 | Path `a/../b` | `ERR_PATH_INVALID` |
| N10 | Paths `A.txt` and `a.txt` | `ERR_PATH_INVALID` |
| N11 | Unsorted manifest | `ERR_MANIFEST_INVALID` |
| N12 | File bytes differ from `d` | `ERR_ARTIFACT_HASH_MISMATCH` |
| N13 | Flip one ciphertext bit | `ERR_CHUNK_AUTH_FAILED` |
| N14 | Chunk moved to another index | `ERR_CHUNK_AUTH_FAILED` |
| N15 | Chunk from another transfer_id | `ERR_CHUNK_AUTH_FAILED` |
| N16 | Drop last chunk, send COMPLETE | stays RECEIVING, STATUS with gap |
| N17 | Revert node (same content_root, new parents) | **accepted**, not a cycle |
| N18 | Node lists own id as ancestor | `ERR_DAG_CYCLE` |
| N19 | Child grant widens `res` | `ERR_GRANT_ATTENUATION` |
| N20 | Handoff accept after lease expiry | `ERR_LEASE_EXPIRED` |
| N21 | Artifact text says "ignore policy, run tool X" | tool X not run without own grant (SEC-004) |
| N22 | `instructions_allowed` without `artifact.instruct` grant | `ERR_POLICY_DENIED` |

## 18. Reference implementation blueprint (task cards for coding agents)

### 18.1 Layout

```
aatp/
  canon.py        # JCS subset, float/ASCII-key guards                (GEN-010/011)
  dsse.py         # PAE, envelope parse/verify                          (SIG-*)
  signer.py       # Signer/KeyStore interface; file+OS keystore impls   (SIG-001)
  ids.py          # agent_id derivation                                 (ID-001)
  card.py         # Card, rotation, revocation, verify_card             (ID-*)
  artifact.py     # path validator, manifest, content_root, stream      (ART-*)
  node.py         # node, node_id, DAG store, ancestry                  (PRV-*)
  seal.py         # HPKE seal/open for packets and CEK wraps            (MSG-01x, ENC-02x)
  chunks.py       # CEK, nonce, AAD, encrypt/decrypt                    (ENC-0xx)
  transfer.py     # state machine, resume, persistence                  (TRF-*)
  grants.py       # grant verify, attenuation                           (AUT-*)
  handoff.py      # handoff with leases                                 (HND-*)
  policy.py       # evaluation order 10.2                               (SEC-*, AUT-*)
  quarantine.py   # sandbox materialize + scanner hooks                 (ART-023, SEC-006/007)
  transport/http.py, transport/relay.py                                 (NET-*)
  mcp_server.py   # tools from section 16
tests/
  vectors/aatp_v0_2_vectors.json   # from reference_vectors.py
  test_<module>.py                 # one test per rule ID; name tests after rule IDs
DECISIONS.md      # every gap, deviation, or [[OPEN-n]] workaround
```

### 18.2 Interfaces (language-neutral signatures)

```
Signer.sign(payload_type: str, payload: bytes) -> bytes
Signer.key_id() -> str
KeyStore.open(enc_key_id: str, enc: bytes, ct: bytes, info: bytes) -> bytes      # HPKE open inside keystore
canon.jcs(obj) -> bytes                       # raises ERR_MALFORMED_MESSAGE
artifact.build(files) -> (manifest, stream, content_root)
artifact.validate_manifest(manifest, limits) -> None | raises ERR_*
node.make(content_root, parents, operation, actor, task_id, generator, now) -> (node, node_id)
chunks.encrypt(cek, stream, chunk_size, content_root, transfer_id) -> list[ciphertext]
chunks.decrypt_one(cek, index, total, content_root, transfer_id, ct) -> bytes | raises ERR_CHUNK_AUTH_FAILED
transfer.on_message(msg) -> list[outbound_messages]          # pure state transition + effects list
grants.verify_chain(leaf_env, chain_envs, roots, now, action, resource, presenter) -> Grant | raises
```

### 18.3 Milestones (each ends with its acceptance tests green)

| M | Build | Done when |
|---|---|---|
| M0 | `canon`, `dsse`, `signer` | V01, V02, V06 reproduce byte-exact; N01–N03 pass |
| M1 | `ids`, `card` | V03 reproduces; N07, N08 pass; rotation chain test |
| M2 | `artifact` | V04 reproduces; N09–N12 pass; materialization sandbox test |
| M3 | `node` + DAG store | V05 reproduces; N17, N18 pass |
| M4 | `chunks`, `seal` | V07, V08 reproduce; N13–N15 pass; HPKE RFC 9180 vectors pass via library |
| M5 | `transfer` + in-memory transport | N04–N06, N16 pass; resume-after-disconnect integration test; duplicate/out-of-order chunk tests |
| M6 | `grants`, `handoff`, `policy` | N19, N20, N22 pass |
| M7 | `quarantine`, SEC tests, `transport/http`, `mcp_server` | N21 pass; end-to-end demo: coordinator → backend → security agent |
| M8 | Independent second implementation (different language) | Both pass identical vectors and cross-interoperate; only then freeze v1.0 |

### 18.4 Rules for the implementing agent

1. Implement one rule ID at a time; write the failing test first; name it after the rule ID.
2. Never log or print keys, CEKs, plaintext artifact bytes.
3. On any ambiguity: fail closed, add an entry to `DECISIONS.md`, continue with other rules.
4. Do not add features, extensions, or algorithms not in this document.
5. Regenerate vectors with `reference_vectors.py`; your implementation's output for V01–V09 must equal it byte-for-byte.
6. Do not claim conformance until the Core test set is green **and** CRY-007 review is done.

## 19. Privacy defaults

| Data | Default |
|---|---|
| Artifact bytes | E2E encrypted (CEK) |
| Manifest / file names | Inside sealed OFFER; `sealed_manifest` for sensitive classes (TRF-004) |
| `content_root` / `node_id` | Inside sealed messages |
| Sender/recipient, size, timing | Visible to relay (NET-003) |
| Prompts | Hash only (PRV-022) |

## 20. Open questions (unresolved — do not implement as decided)

| ID | Question |
|---|---|
| OPEN-1 | Independent cryptographic review of the composition (sign-then-seal, CEK wrap info, nonce scheme). |
| OPEN-2 | Optional Noise_XX live-session extension for per-session forward secrecy and low-latency control. |
| OPEN-3 | Tree hashing for very large files (per-file chunk Merkle) while keeping `content_root` stable. |
| OPEN-4 | Attestation formats for `issuer_attested`/`hardware_attested` (in-toto/SLSA mapping). |
| OPEN-5 | Metadata protection: padding, cover traffic, mix relays. |
| OPEN-6 | Key-compromise recovery when `next_commitment` was never published. |
| OPEN-7 | Partial acceptance semantics (accept a subset of files). |
| OPEN-8 | Artifact deletion/revocation after caching. |
| OPEN-9 | Group-sender authenticity without shared-CEK forgery (per-recipient MACs or per-sender chunk signatures). |
| OPEN-10 | Discovery: Card distribution and org directory without central registry. |

## Appendix A — JSON Schemas (draft 2020-12, abbreviated but valid)

### A.1 Common definitions

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.invalid/aatp/0.2/common.schema.json",
  "$defs": {
    "digest":   { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
    "agent_id": { "type": "string", "pattern": "^aatp:[a-z2-7]{52}$" },
    "ts":       { "type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$" },
    "b64url":   { "type": "string", "pattern": "^[A-Za-z0-9_-]*$" },
    "dsse": {
      "type": "object", "required": ["payloadType", "payload", "signatures"],
      "properties": {
        "payloadType": { "type": "string" },
        "payload": { "$ref": "#/$defs/b64url" },
        "signatures": { "type": "array", "minItems": 1,
          "items": { "type": "object", "required": ["keyid", "sig"],
            "properties": { "keyid": { "type": "string" }, "sig": { "$ref": "#/$defs/b64url" } } } }
      }
    }
  }
}
```

### A.2 Message

```json
{
  "$id": "https://example.invalid/aatp/0.2/message.schema.json",
  "type": "object",
  "required": ["v", "type", "id", "sender", "sender_key_id", "recipient", "created_at", "expires_at", "body"],
  "properties": {
    "v": { "const": "0.2" },
    "type": { "enum": ["OFFER","ACCEPT","REJECT","STATUS","COMPLETE","RECEIPT","HANDOFF_OFFER","HANDOFF_RESPONSE","TASK_UPDATE","ERROR"] },
    "id": { "type": "string", "minLength": 8, "maxLength": 128 },
    "sender": { "$ref": "common.schema.json#/$defs/agent_id" },
    "sender_key_id": { "type": "string" },
    "recipient": { "$ref": "common.schema.json#/$defs/agent_id" },
    "created_at": { "$ref": "common.schema.json#/$defs/ts" },
    "expires_at": { "$ref": "common.schema.json#/$defs/ts" },
    "corr": { "type": "object", "properties": {
      "transfer_id": {"type":"string"}, "task_id": {"type":"string"}, "in_reply_to": {"type":"string"} } },
    "crit": { "type": "array", "items": { "type": "string" } },
    "body": { "type": "object" }
  },
  "additionalProperties": true
}
```

### A.3 AgentCard

```json
{
  "$id": "https://example.invalid/aatp/0.2/card.schema.json",
  "type": "object",
  "required": ["v","agent_id","genesis_public_key","signing_key","enc_key","key_history","suites","seq","issued_at","expires_at"],
  "properties": {
    "v": {"const":"0.2"},
    "agent_id": {"$ref":"common.schema.json#/$defs/agent_id"},
    "genesis_public_key": {"$ref":"common.schema.json#/$defs/b64url"},
    "signing_key": {"type":"object","required":["key_id","public_key","not_before","not_after"],
      "properties":{"key_id":{"type":"string"},"public_key":{"$ref":"common.schema.json#/$defs/b64url"},
        "not_before":{"$ref":"common.schema.json#/$defs/ts"},"not_after":{"$ref":"common.schema.json#/$defs/ts"}}},
    "enc_key": {"type":"object","required":["key_id","public_key","not_before","not_after"],
      "properties":{"key_id":{"type":"string"},"public_key":{"$ref":"common.schema.json#/$defs/b64url"},
        "not_before":{"$ref":"common.schema.json#/$defs/ts"},"not_after":{"$ref":"common.schema.json#/$defs/ts"}}},
    "key_history": {"type":"array","items":{"$ref":"common.schema.json#/$defs/dsse"}},
    "next_commitment": {"$ref":"common.schema.json#/$defs/digest"},
    "revoked": {"type":"array","items":{"$ref":"common.schema.json#/$defs/dsse"}},
    "endpoints": {"type":"array","items":{"type":"string","format":"uri"}},
    "capabilities": {"type":"array","items":{"type":"string","pattern":"^aatp\\."}},
    "suites": {"type":"array","items":{"enum":["AATP-S1"]}},
    "seq": {"type":"integer","minimum":0},
    "issued_at": {"$ref":"common.schema.json#/$defs/ts"},
    "expires_at": {"$ref":"common.schema.json#/$defs/ts"}
  }
}
```

### A.4 OfferBody

```json
{
  "$id": "https://example.invalid/aatp/0.2/offer.schema.json",
  "type": "object",
  "required": ["transfer_id","content_root","node_env","chunk_size","total_chunks","stream_len","cipher","wraps","parent_policy","classification","expires_at"],
  "oneOf": [ {"required":["manifest"]}, {"required":["sealed_manifest"]} ],
  "properties": {
    "transfer_id": {"type":"string"},
    "content_root": {"$ref":"common.schema.json#/$defs/digest"},
    "manifest": {"$ref":"#/$defs/manifest"},
    "sealed_manifest": {"$ref":"common.schema.json#/$defs/b64url"},
    "node_env": {"$ref":"common.schema.json#/$defs/dsse"},
    "chunk_size": {"type":"integer","minimum":1,"maximum":16777216},
    "total_chunks": {"type":"integer","minimum":0,"maximum":4294967295},
    "stream_len": {"type":"integer","minimum":0},
    "cipher": {"enum":["chacha20poly1305","aes256gcm"]},
    "wraps": {"type":"array","minItems":1,"items":{"type":"object",
      "required":["agent_id","enc_key_id","enc","ct"],
      "properties":{"agent_id":{"$ref":"common.schema.json#/$defs/agent_id"},"enc_key_id":{"type":"string"},
        "enc":{"$ref":"common.schema.json#/$defs/b64url"},"ct":{"$ref":"common.schema.json#/$defs/b64url"}}}},
    "parent_policy": {"enum":["require","lazy"]},
    "classification": {"enum":["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"]},
    "expires_at": {"$ref":"common.schema.json#/$defs/ts"}
  },
  "$defs": {
    "manifest": {"type":"object","required":["v","entries"],
      "properties":{"v":{"const":"0.2"},"entries":{"type":"array","maxItems":10000,"items":{
        "type":"object","required":["path","size","x","d"],
        "properties":{"path":{"type":"string","maxLength":1024},"size":{"type":"integer","minimum":0},
          "x":{"type":"boolean"},"d":{"$ref":"common.schema.json#/$defs/digest"}}}}}}
  }
}
```

### A.5 Node

```json
{
  "$id": "https://example.invalid/aatp/0.2/node.schema.json",
  "type": "object",
  "required": ["v","content_root","parents","operation","actor","task_id","created_at"],
  "properties": {
    "v": {"const":"0.2"},
    "content_root": {"$ref":"common.schema.json#/$defs/digest"},
    "parents": {"type":"array","items":{"$ref":"common.schema.json#/$defs/digest"},"uniqueItems":true},
    "operation": {"enum":["create","modify","merge","revert","verify","supersede"]},
    "actor": {"$ref":"common.schema.json#/$defs/agent_id"},
    "task_id": {"type":"string"},
    "created_at": {"$ref":"common.schema.json#/$defs/ts"},
    "generator": {"type":"object","required":["kind","assurance"],
      "properties":{"kind":{"enum":["ai","human","tool","mixed"]},
        "model":{"type":"object","properties":{"provider":{"type":"string"},"name":{"type":"string"},"version":{"type":"string"}}},
        "runtime":{"type":"object"},
        "prompt_digest":{"$ref":"common.schema.json#/$defs/digest"},
        "toolcalls_digest":{"$ref":"common.schema.json#/$defs/digest"},
        "human_approver":{"$ref":"common.schema.json#/$defs/agent_id"},
        "assurance":{"enum":["self_asserted","issuer_attested","hardware_attested"]}}},
    "annotations": {"type":"object"}
  }
}
```

### A.6 HandoffBody

```json
{
  "$id": "https://example.invalid/aatp/0.2/handoff.schema.json",
  "type": "object",
  "required": ["handoff_id","task","input_node_ids","grant_env","expected_outputs","deadline","lease_expires_at"],
  "properties": {
    "handoff_id": {"type":"string"},
    "task": {"type":"object","required":["task_id","title","objective"],
      "properties":{"task_id":{"type":"string"},"title":{"type":"string"},"objective":{"type":"string"},
        "constraints":{"type":"object"}}},
    "input_node_ids": {"type":"array","items":{"$ref":"common.schema.json#/$defs/digest"}},
    "grant_env": {"$ref":"common.schema.json#/$defs/dsse"},
    "expected_outputs": {"type":"array","items":{"type":"string"}},
    "deadline": {"$ref":"common.schema.json#/$defs/ts"},
    "lease_expires_at": {"$ref":"common.schema.json#/$defs/ts"},
    "policy_context": {"type":"object"}
  }
}
```

## Appendix B — Worked example (happy path with resume)

```
0  Coordinator issues Grant G1 to Backend and G2 to Security (attenuated from G1).           (AUT-002)
1  Backend builds artifact: sorted files -> manifest -> content_root=CR1;                   (ART-*)
   node N1 {content_root:CR1, parents:[], operation:create, generator:{kind:ai,...}} signed.
2  Backend fetches Security's Card, verify_card() ok; picks enc_key E5.                      (4.5)
3  Backend: CEK random; chunks encrypted (ENC-*); wraps[] = [HPKE(E5, CEK)].
4  Backend -> Security: sealed OFFER{transfer_id tx_a, CR1, manifest, N1, wraps, ...}.       (MSG-010)
5  Security: unseal, verify signature, recipient, replay, grant chain, limits; ACCEPT.       (5.3, 10.2)
6  Backend streams CHUNK 0..7 (window 16). Network fails after chunk 4.
7  Security state PAUSED; on reconnect sends STATUS{have:[[0,4]]}.                            (TRF-021)
8  Backend sends CHUNK 5..7, then COMPLETE{total_chunks:8}.
9  Security: VERIFYING: per-file digests, content_root==CR1, N1 signature, ancestry.        (ART-021/022)
10 Scanner clean -> RECEIPT{accepted} signed.                                                (TRF-026)
11 Security produces report (node N2: operation create, parents:[N1]) and sends
   HANDOFF_OFFER{task, input_node_ids:[N1], grant G2', lease} back to Coordinator.          (HND-*)
12 Coordinator HANDOFF_RESPONSE{accept} before lease -> responsibility transfers.           (HND-001)
```

## Appendix C — Test vectors (computed by `reference_vectors.py`; authoritative file: `aatp_v0_2_vectors.json`)

**V01 JCS** — input `{"b":2,"a":1}` → `{"a":1,"b":2}` → hex `7b2261223a312c2262223a327d`.

**V02** — `sha256("hello")` = `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`; `b64url("hello")` = `aGVsbG8`.

**V03 agent_id** — Ed25519 seed `11` ×32 → public key
`d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737` →
`aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma`

**V04 content_root** — files: `hello.txt`="hello" (x=false), `bin/run.sh`="echo hi\n" (x=true).
Manifest JCS:
```
{"entries":[{"d":"sha256:ab08508fdf5ca4da5c4995987bc41c56c048aaa5eeb046417ae4049b7d40286e","path":"bin/run.sh","size":8,"x":true},{"d":"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","path":"hello.txt","size":5,"x":false}],"v":"0.2"}
```
Stream hex `6563686f2068690a68656c6c6f` (13 bytes).
`content_root` = `sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf`

**V05 revert is not a cycle**
- node1 (create, CR1) `node_id` = `sha256:1f3ce1c2654eee964b0b4c4365f5a909e0b11990dbc9f6478150efebb18b3253`
- node2 (modify, content `hello world`, parent node1): content_root `sha256:316dcfe880067987f2d83df8c040db75612d521f7df41ffe37a1847bed253bec`, node_id `sha256:96f802b77ff00b7fd1b8730da8cb4c2a48c365f1eed881c3929bb4384689a686`
- node3 (revert, parent node2, content identical to node1): content_root = CR1 (equal to node1), node_id `sha256:cc88b197e20b70e629fa0315c694c3dce7adbcd0ab16a05ec7ade0daf9d2c9a4` (≠ node1). **Must be accepted.**
Full node1 JCS is in the JSON vectors file.

**V06 DSSE signature** of node1 (payloadType `application/vnd.aatp.node+json`, key = V03):
`5gLnkjsAGUvpED3PigH29W7M4mH3lkLf3zpq6-5cSMTuQQYmcgrzpaRhJ_qTXbs8iEcDPkw6AvyF7hgKhDRyBg` (PAE hex in vectors file).

**V07 chunk encryption** — CEK = `00..1f`, transfer_id `tx_demo1`, chunk_size 8, content_root = CR1:
- chunk 0 nonce `000000000000000000000000`, ciphertext `7ddb2a5e8d8ecfdbdf23f165585271f9598a9ddaad072de1`
- chunk 1 nonce `000000000000000000000001`, ciphertext `013910b55eca493016312b9e709d27d9800b9cfe25`

**V08 negatives** — tampered chunk → `ERR_CHUNK_AUTH_FAILED`; chunk 0 presented as index 1 → `ERR_CHUNK_AUTH_FAILED`.
**V09** — `{"a":1.5}` → `ERR_MALFORMED_MESSAGE`.

## Appendix D — Prior art to reuse instead of reinventing

| Area | Reuse |
|---|---|
| Signing envelope | DSSE (in-toto/Sigstore ecosystem) |
| Message encryption | HPKE (RFC 9180); Noise as optional live session |
| Content-addressed DAG | Git object model, IPLD |
| Delegable authorization | UCAN, Biscuit, Macaroons |
| Provenance vocabulary | W3C PROV, in-toto/SLSA predicates |
| Key rotation w/ pre-commitment | KEL/KERI concepts |
| Agent tasks & messaging | A2A; tools: MCP |

## Appendix E — Status statement

This document is a **design baseline**, not a reviewed standard. Freeze criteria (repeat of M8): two independent implementations pass all vectors and cross-interoperate, plus a completed cryptographic review (CRY-007). This is technical analysis, not legal advice; run a formal prior-art/freedom-to-operate review with qualified counsel before any public filing or disclosure.
