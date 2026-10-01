# AATP Core M0–M5 — Design Spec

- Date: 2026-10-01
- Source: `AATP_v0_2_Blueprint.md` v0.2.0-draft (1019 lines, status DRAFT - NOT CRYPTOGRAPHICALLY REVIEWED)
- Scope: Full Core M0–M5, Python, Strict spec-compliant
- Approach: Sequential M0→M5 TDD
- Precedence: rules > schemas > byte grammars > pseudocode > vectors > examples (blueprint §0)

## 1. Tujuan & Non-tujuan

Tujuan: implementasi referensi Python untuk Core (ID, MSG, ART, PRV, ENC, TRF) sampai transfer + resume in-memory, lolos V01–V08 byte-exact dan N01–N16, dengan fail-closed + `DECISIONS.md`.

Non-tujuan (deferred, bukan dihapus):
- M6 grants/handoff/policy (`AUT-*`, `HND-*`), M7 quarantine/SEC/transport/MCP, M8 second implementation + interop freeze.
- OPEN-1..OPEN-10 tidak diimplementasikan sebagai decided (§20).
- Tidak ada fitur/algoritma di luar dokumen (§18.4.4).

## 2. Arsitektur

Layout ikut blueprint §18.1:

```
aatp/
  canon.py        # JCS subset GEN-010/011
  dsse.py         # PAE, envelope parse/verify SIG-*
  signer.py       # Signer/KeyStore isolasi key SIG-001
  ids.py          # agent_id derivation ID-001
  card.py         # Card, rotation, revocation, verify_card ID-*
  artifact.py     # path validator, manifest, content_root, stream ART-*
  node.py         # node, node_id, DAG store, ancestry PRV-*
  seal.py         # HPKE seal/open MSG-01x, ENC-02x
  chunks.py       # CEK, nonce, AAD, encrypt/decrypt ENC-0xx
  transfer.py     # state machine, resume, persistence TRF-*
tests/
  vectors/aatp_v0_2_vectors.json  # dari reference_vectors.py
  test_<module>.py                 # satu test per rule ID
DECISIONS.md
reference_vectors.py
```

Dependencies:
- Python 3.11+, OS CSPRNG (`secrets`), `cryptography` vetted untuk Ed25519/X25519/ChaCha20-Poly1305/HKDF-SHA256.
- HPKE base mode (KEM 0x0020, KDF 0x0001, AEAD 0x0003) WAJIB via vetted lib, dibuktikan dengan RFC 9180 official vectors. Jika tidak ada lib vetted yang tersedia, catat di `DECISIONS.md` dan fail-closed (CRY-001 melarang hand-roll HPKE/AEAD/Ed25519).
- Hand-rolled hanya untuk non-crypto: JCS canonicalizer, PAE framing, path/manifest validator, DAG store, state machine.

Interfaces (ikuti §18.2):
`Signer.sign(payload_type, bytes)->bytes`, `KeyStore.open(enc_key_id, enc, ct, info)->bytes`, `canon.jcs(obj)->bytes`, `artifact.build/validate_manifest`, `node.make`, `chunks.encrypt/decrypt_one`, `transfer.on_message`. `grants.verify_chain` tidak diimplementasikan pada M0–M5; jika distub, harus raise (fail-closed), jangan return OK.

Signer/KeyStore: private key tidak pernah masuk application code / LLM context. Caller hanya terima signature/hasil open.

## 3. Data Flow M0–M5

1. Build artifact: file diurut bytewise UTF-8 → `manifest_bytes=JCS(manifest)` → `content_root=sha256(D_CONTENT||manifest_bytes)`, `stream=concat(file_bytes)` (§6).
2. Make node: `node_id=sha256(D_NODE||JCS(node))`, parents sorted ascending, no-dup. `create`=0 parents (§7).
3. Fetch + `verify_card` penerima (alg §4.5, 12 langkah), pilih `enc_key` valid ≤7 hari.
4. `CEK=random32` fresh per transfer (ENC-005). Chunks: `nonce(i)=0x00000000||u64be(i)`, `nonce(manifest)=ff*12`, `AAD(i)=D_CHUNK||JCS({cr,i,n,t})`, `ct=ChaCha20Seal(CEK,nonce,AAD,pt)` (§9.1).
5. Wrap CEK per-recipient: `info_r=D_CEKWRAP||JCS({"cr":content_root,"s":sender_agent_id,"r":recipient_agent_id,"t":transfer_id,"k":enc_key_id})`, `HPKE.SealBase(pkR,info_r,"",CEK)` (§9.2).
6. Sealed OFFER (`sign then seal`, MSG-011): `info=D_PACKET||to||\n||to_key_id`, `pt=JCS(dsse_envelope)`.
7. Receiver `receive_control` (§5.3, 8 langkah): unseal dengan `info` yang dibangun dari **packet** (`D_PACKET||packet.to||"\n"||packet.to_key_id`, bukan field message dalam) → parse JCS → resolve card + trust (ID-003) → verify sig → recipient (MSG-002) → time window (MSG-003) → replay (MSG-004) → dispatch state machine (§8.4).
8. Streaming CHUNK: tolak `index>=total` / unknown tx, idempotent dup, buffer out-of-order ≤ `send_window_chunks=16`, verified hanya jika AEAD open dengan nonce/AAD eksak (TRF-010..014).
9. COMPLETE → VERIFYING: per-file `d` saat file complete (ART-021), recompute `content_root` (ART-022), verifikasi node signature + ancestry (`lazy` default, `require` jika diminta, PRV-010/011).
10. Signed RECEIPT (`accepted/rejected/quarantined`) — satu-satunya proof of delivery (TRF-026).
11. Resume: persist `{transfer_id, content_root, cek_ref, have_ranges, state}` (TRF-020). Receiver-driven: sender hanya kirim missing dari STATUS `have` terakhir (TRF-021). Resume pakai tx+CEK sama; attempt baru wajib tx+CEK baru (TRF-022). `STATUS.have` inclusive sorted non-overlapping (TRF-023). Window max 16 unacked beyond contiguous (TRF-024). COMPLETE tidak boleh hanya dari chunk arrival (TRF-025).

## 4. Error Handling (fail-closed)

- Silence = fail closed + catat gap di `DECISIONS.md` (§0.4).
- GEN-010/011: tolak float, dup keys, depth>16, non-ASCII keys, non-canonical → `ERR_MALFORMED_MESSAGE` (N02, N03, V09).
- GEN-012: unknown optional fields di-ignore tapi dipertahankan byte-for-byte saat re-serialize object bertanda tangan; unknown field yang masuk `crit` → `ERR_UNSUPPORTED_EXTENSION`.
- CRY-002: Ed25519 menandatangani PAE langsung, tidak pre-hash. CRY-003: tolak signature non-kanonik (S ≥ L) + satu mode strict konsisten.
- SIG-002 byte-equality re-canonicalization, SIG-003 payloadType check (N01 → `ERR_SIGNATURE_INVALID`).
- MSG-001: tiap control message DSSE-signed oleh `sender` current signing key dan wajib berisi `recipient` (missing recipient → malformed). MSG-002 recipient mismatch (N04), MSG-003 expiry/skew120s/lifetime≤86400 (N05), MSG-004 replay cache persist restart + idempotency MSG-005 (N06), MSG-006 unknown type, MSG-013 oversize.
- MSG-010: semua control messages M5 (OFFER, ACCEPT, REJECT, STATUS, COMPLETE, RECEIPT, ERROR; §8.1) sealed. MSG-012: relay hanya melihat `aatp,to,to_key_id,enc,ct` + size/timing.
- ID-003 trust pinned default-deny (ID-004), ID-011 rollback (N07), ID-012 enc ≤7d, ID-013 card ≤30d, ID-014 windows + skew, ID-020 commitment (N08), ID-023 revocation bisa ditandatangani current key ATAU key yang cocok `next_commitment`, ID-024 tolak message dari key yang revoked `effective_at ≤ created_at` (dengan exception timing §4.4).
- ART-001..007 path/manifest (N09, N10 → `ERR_PATH_INVALID`; N11 → `ERR_MANIFEST_INVALID`), ART-006 limits (GEN-020 defaults), ART-021/022 digest+root (N12), ART-023 quarantine-dir + O_NOFOLLOW, ART-013 empty artifact valid (`total_chunks=0`).
- ENC-007 chunk AEAD fail (N13–N15 → `ERR_CHUNK_AUTH_FAILED`), ENC-006 index≥2^63 reject.
- TRF-001: `node_env.content_root` wajib == OFFER `content_root`, else `ERR_ARTIFACT_HASH_MISMATCH`. TRF-002: validasi manifest/limits/`stream_len==sum(size)`/`total_chunks=ceil(len/chunk)` SEBELUM ACCEPT. TRF-023 bad ranges → `ERR_RESUME_INVALID`, N16 parsial COMPLETE tetap RECEIVING + STATUS gap.
- PRV-001 parents sorted ascending tanpa duplikat, PRV-002 node wajib DSSE `node+json` oleh actor, PRV-003 cycle defense (N18 → `ERR_DAG_CYCLE`), PRV-004 revert distinct event diterima (N17), PRV-005 time, PRV-006 arity, PRV-010/011 ancestry complete/partial, PRV-021 generator claims self-asserted by default, PRV-022 prompts hash-only tidak pernah embed raw.
- Semua fatal → `ERROR{code,numeric,corr_id}` (§14). Numeric ranges: 10xx envelope, 11xx identity/auth, 12xx policy, 13xx artifact, 14xx transfer, 15xx quarantine, 9000 internal. Kode untuk modul deferred (NET/quarantine) cukup didefinisikan sebagai enum, tidak diimplementasikan.
- Audit (§12): `message_received, transfer_state, chunk_verified, artifact_verified, policy_decision, key_event` (event `handoff` untuk M6) tanpa plaintext/CEK/private key, SHOULD hash-chained. Log SEC-006: quarantined ≠ malicious.

## 5. Testing (strict TDD)

Aturan §18.4: 1 rule = 1 test (nama = rule ID, mis. `test_GEN010_reject_float`), failing-first, tidak log keys/CEK/plaintext, tidak tambah fitur, regenerate vectors via `reference_vectors.py`, klaim conformance hanya jika Core green DAN CRY-007 review selesai (review tetap OPEN → tidak klaim production).

- M0 `canon,dsse,signer`: V01 (JCS `{"b":2,"a":1}`→`7b2261223a31...`), V02 sha256/b64url hello, V06 DSSE node1 sig `5gLnkj...` (juga bukti CRY-002 sign-PAE-direct), V09 float→ERR_MALFORMED (negative vector, bukan byte-exact); N01–N03. Plus `test_CRY003_reject_noncanonical_S`, `test_GEN012_unknown_field_preserved`, `test_GEN012_crit_unknown_unsupported`, `test_MSG001_missing_recipient_rejected`.
- M1 `ids,card`: V03 seed `11`*32 → pub `d04ab2...` → `aatp:ikee37...`; N07 rollback, N08 commitment + rotation chain genesis→current. Plus tests ID-012..014 windows, ID-023 dua jalur signature revoke, ID-024 revocation-vs-created_at.
- M2 `artifact`: V04 manifest JCS + stream hex `6563686f...` (13B) + `content_root 9067a6...`; N09–N12 + sandbox materialization test. Plus `test_ART013_empty_artifact`.
- M3 `node+DAG`: V05 node1 `1f3ce1...`, node2 `96f802...` (CR `316dcf...`), node3 revert CR=CR1 tapi node_id `cc88b1...` ≠ node1 → accepted (N17); N18 self-ancestor → cycle. Plus `test_PRV001_unsorted_parents_rejected`, `test_PRV002_node_dsse_signed`.
- M4 `chunks,seal`: V07 CEK `00..1f` tx_demo1 chunk_size 8 → ct0 `7ddb2a...`, ct1 `013910...`; V08 tamper/reindex → AUTH_FAILED; N13–N15 + RFC 9180 vectors via lib.
- M5 `transfer+in-mem transport`: N04–N06, N16 + resume-after-disconnect, dup/out-of-order, window16, `transfer.on_message` pure transition + effects list. Plus `test_TRF001_node_root_mismatch`, `test_TRF002_stream_len_mismatch`, `test_ART020_zero_chunks_complete`. Replay cache (MSG-004), transfer state (TRF-020), dan seq cache (ID-011) harus durable (file/SQLite) walau transport in-memory; in-memory hanya untuk transport.

Out-of-scope M0–M5 (dicatat, bukan diuji penuh): N19–N22 (grants/handoff/SEC, untuk M6–M7).

### Rule-coverage table (M0–M5)

| Area | Rules in scope | Milestone |
|---|---|---|
| GEN | 001–006, 010–012, 020 | M0–M5 |
| CRY | 001–006 | M0/M4 |
| SIG | 001–003 | M0 |
| ID | 001–004, 010–014, 020–024 | M1 |
| MSG | 001–006, 010–013 | M0/M5 |
| ART | 001–007, 010–013, 020–024 | M2 |
| PRV | 001–006, 010–012, 020–022 | M3 |
| ENC | 001–007, 020–023 | M4 |
| TRF | 001–005, 010–014, 020–026 | M5 |

Setiap baris di atas wajib punya test bernama rule ID sebelum milestone dinyatakan green.

## 6. Milestone Acceptance

Tiap milestone green sebelum lanjut. Urutan wajib M0→M5 karena dependensi (canon→dsse→card→artifact→node→chunks→transfer). M8 (second implementation beda bahasa + cross-interop) ditunda setelah M7.

## 7. Risiko & Keputusan

- HPKE vetted-lib availability adalah risiko terbesar (CRY-001). Mitigasi: spike task SEBELUM M0 sign-off untuk memilih lib (`hpke`/`pyhpke` di PyPI vs `cryptography`), gate = RFC 9180 official vectors KEM 0x0020/KDF 0x0001/AEAD 0x0003. Jika tidak ada yang lolos, M4 diblokir → DECISIONS.md + fail-closed; tidak hand-roll diam-diam.
- Crypto composition belum direview (CRY-007/OPEN-1) → DRAFT, DO NOT DEPLOY.
- Relay melihat to/size/timing (NET-003 accepted), no per-session FS ( §3.2, OPEN-2), group-CEK forgery ditahan oleh signed root check (ENC-023, OPEN-9).
- Batas default §2.1 semuanya harus ada dan configurable (GEN-020).
- Keputusan yang perlu dicatat di DECISIONS.md saat implementasi: (a) chunk out-of-window di-drop, kode terdekat `ERR_SEQUENCE_INVALID` (§0.4); (b) GEN-006 id format divalidasi untuk id yang kita mint; peer-supplied opaque id diperlakukan opaque ≤128 `[A-Za-z0-9_.:-]`; (c) ID-011 seq cache dibuat durable; (d) ART-023 materialization minimal M2 (quarantine dir + O_NOFOLLOW + mode `x`), subsystem quarantine penuh M7.
