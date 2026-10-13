# AATP Policy Wiring + Audit Emit + 4-Agent Simulation — Design Spec

- Date: 2026-10-13
- Source: `AATP_v0_2_Blueprint.md` v0.2.0-draft; prior spec `docs/superpowers/specs/2026-10-01-aatp-core-m0-m5-design.md`
- Scope: close two real integration gaps, then build a 4-agent work simulation over the existing localhost HTTP relay
- Status: DRAFT — CRY-007 (cryptographic review) still OPEN, V05/V06 still UNVERIFIABLE per D-020. Not production.

## 1. Tujuan

Tiga bagian:

1. **Wire `policy.evaluate` ke jalur transfer** — `aatp/grants.py`, `aatp/policy.py`, `aatp/handoff.py` sudah ada dan dites, tapi `aatp/transfer.py` tidak pernah memanggilnya. Grant & consumption gate hanya hidup di atas kertas.
2. **Emit audit events** — `aatp/sec.py` punya `audit_append` (AUD-001/002) tapi tidak ada modul yang memanggilnya. Jejak audit harus benar-benar ditulis pada transisi state.
3. **Simulasi kerja nyata 4 agen** lewat relay HTTP localhost yang sudah ada (`relay_server.py` + `agent_cli.py`), membuktikan grant → policy → quarantine → handoff → audit bekerja sebagai satu alur.

Di luar scope: relay durable (dib愿景 pisahkan), CRY-007, discovery (OPEN-10), perbaikan minor (UUIDv7, non-object payload, akses `_store` privat).

## 2. Arsitektur

Tiga perubahan, semuanya di dalam `aatp/`, tanpa mengubah format wire:

### 2.1 Policy wiring

`TransferReceiver.__init__` mendapat tiga parameter baru opsional:

```
policy_fn: callable | None = None   # (request: dict) -> {"decision","rule_id","code"}
grant_chain_envs: list[dict] = []   # DSSE grant+json envelopes (ancestors)
roots: set[str] | None = None       # policy roots untuk AUT-001
```

Default `policy_fn=None` → perilaku persis seperti sekarang (backwards-compatible, 411 test lama harus tetap hijau).

Di `_handle_offer`, **sebelum** cek validitas manifest dan sebelum ACCEPT:

```
if self._policy_fn is not None:
    request = {
        "action": "aatp.artifact.receive",
        "resource": body.get("resource") or OFFER-level default,
        "classification": body.get("classification"),
        "consumption_mode": body.get("consumption_mode", "data_only"),
        "grant_leaf_env": <leaf grant envelope>,
        "grant_chain_envs": self._grant_chain_envs,
        "revoked": self._revoked,
        "manifest": body.get("manifest"),
        "limits": self._limits,
    }
    verdict = self._policy_fn(request)
    if verdict["decision"] != "allow":
        return self._reject(sender, tx, verdict["code"], verdict["rule_id"], now=now)
```

Grant leaf diambil dari parameter baru `grant_leaf_env` (juga opsional, default None). Bila `policy_fn` di-set tapi `grant_leaf_env` None → deny `ERR_POLICY_DENIED` (fail closed, tidak ada grant = tidak boleh terima).

Memakai `policy.evaluate` yang sudah ada. Kalau `policy_fn` melempar `AATPError` → REJECT dengan kode tersebut. Kalau melempar exception lain → REJECT `ERR_INTERNAL` (D-044).

### 2.2 Audit emit

`TransferReceiver.__init__` mendapat `audit_log_path: str | None = None`. Tanpa path → no-op.

Helper internal `_audit(event, **fields)` yang:
1. Bentuk entry `{"event": <name>, **fields}` (hanya field yang relevan, tanpa payload).
2. Baca entry terakhir dari file JSON untuk dapat `prev_hash` (default `"00"*32`).
3. Panggil `sec.audit_append(log, entry, prev_hash=prev_hash)` → hash baru.
4. Tulis ulang file JSON (`{"entries": [...], "head": <hash>}`).

Event yang di-emit (§12): `message_received`, `transfer_state`, `chunk_verified`, `artifact_verified`, `policy_decision`, `key_event`.

`audit_append` menolak entry dengan field terlarang (`cek`, `private_key`, `plaintext`, `payload`, `plaintext_bytes`) → `ERR_MALFORMED_MESSAGE`. Kegagalan append karena I/O → best-effort, print warning, **tidak** menggagalkan transfer (D-045). Penolakan karena field terlarang tetap fail-closed (entry tidak ditulis).

`_audit` dipanggil di: `_handle_offer` (accepted/rejected), `receive_chunk` (setiap chunk verified), `_handle_complete` (→ VERIFYING), `_finish_verified` (artifact_verified + RECEIPT), dan setiap kali policy menolak (`policy_decision`).

### 2.3 Reload-safe

Karena receiver hidup di session terpisah, state harus tahan restart: `policy_fn`/grant chain **rebuild** dari state dir saat receiver dibuat ulang (sama seperti `replay.json`/`xfer.json` sekarang). Grant envelopes disimpan di `<state-dir>/grants.json`.

## 3. Alur simulasi 4 agen

Semua lewat relay HTTP `127.0.0.1:8765`. Empat agen: **Coordinator**, **Coder**, **Reviewer**, **Deployer**.

| # | Langkah | Yang diuji |
|---|---|---|
| 0 | Coordinator publishes card + membuat G1 (`iss=C, aud=Coder`, cap `aatp.artifact.send`+`receive`, `res=project:alpha/*`, `classification_max=INTERNAL`) dan G2 (`iss=Coder, aud=Reviewer`, attenuated dari G1: hanya `aatp.artifact.receive`, `res=project:alpha/src/*`, tanpa `artifact.instruct`) | AUT-001..006 |
| 1 | Coder `publish` card, simpan G1/G2, kirim OFFER source tree 3 file ke Reviewer | TRF-001/002, ART-* |
| 2 | Reviewer `receive`: OFFER masuk → policy evaluate (G2 valid, consumption_mode `data_only`) → ACCEPT | policy wiring |
| 3 | Coder upload chunk; relay dropping 1 chunk di tengah; Reviewer sees gap → STATUS `have` → Coder kirim ulang yang hilang | TRF-021/023/024, resume |
| 4 | Reviewer decrypt, verify per-file digest + `content_root` + node signature; scanner stub verdict `clean` → RECEIPT `accepted`; materialize ke `received/<tx>/` | ART-021/022, SEC-007 |
| 5 | Reviewer buat laporan (node `modify`, parent `N1`) → kirim ke Coordinator → HANDOFF_OFFER → HANDOFF_RESPONSE `accept` sebelum lease | PRV-006, HND-001..006 |
| 6 | Audit chain diverifikasi: `head_n == SHA256(head_{n-1} \|\| JCS(entry_n))` untuk semua entry | AUD-002 |

**Skenario negatif yang wajib ditunjukkan** (bukti fail-closed, bukan happy path saja):
- OFFER tanpa grant (`policy_fn` aktif, `grant_leaf_env=None`) → REJECT `ERR_POLICY_DENIED`.
- OFFER dengan grant yang `classification_max=PUBLIC` tapi OFFER `classification=RESTRICTED` → REJECT.
- Chunk yang indeksnya dipindah → `ERR_CHUNK_AUTH_FAILED`, tidak masuk have-ranges.
- Artifact dengan satu byte diubah → `ERR_ARTIFACT_HASH_MISMATCH` → RECEIPT `rejected`.

Output simulasi: timeline log, daftar 4 `agent_id`, isi folder `received/`, dan hasil verifikasi audit chain.

## 4. Error handling

- Policy DENY → REJECT dengan `code` dari verdict (`ERR_POLICY_DENIED` / `ERR_GRANT_INVALID` / `ERR_GRANT_ATTENUATION`).
- `policy_fn` melempar non-`AATPError` → REJECT `ERR_INTERNAL` (D-044).
- Grant leaf hilang padahal `policy_fn` aktif → deny `ERR_POLICY_DENIED` (fail closed).
- Audit append gagal I/O → warning, transfer lanjut (D-045). Audit entry dengan field terlarang → `ERR_MALFORMED_MESSAGE`, entry tidak ditulis.
- Tidak ada state yang ditulis sebelum policy lolos: REJECT hanya绝世 memantulkan store entry dengan `state=REJECTED`.

## 5. Testing

TDD strict, nama test per rule ID:

| Test | Isi |
|---|---|
| `test_AUT_wired_offer_accepted_valid` | `policy_fn` return allow + grant leaf valid → ACCEPT |
| `test_AUT_wired_offer_denied_without_grant` | `policy_fn` aktif, `grant_leaf_env=None` → REJECT `ERR_POLICY_DENIED` |
| `test_AUT_wired_offer_denied_by_policy` | `policy_fn` return deny dengan code → REJECT memakai code itu |
| `test_AUT_wired_offer_policy_exception_internal` | `policy_fn` lempar `RuntimeError` → REJECT `ERR_INTERNAL` |
| `test_AUD001_offer_transition_logged` | OFFER diterima → entry `transfer_state` ada di log |
| `test_AUD002_chain_links` | 2 entry: `head_2 == SHA256(head_1 \|\| JCS(entry_2))` |
| `test_AUD001_forbidden_key_rejected` | entry dengan `cek` → tidak tertulis |
| `test_AUD001_no_secrets_in_audit_entry` | tidak ada plaintext/CEK di file log |
| `test_default_no_policy_unchanged` | `policy_fn=None` default → 411 test lama tetap hijau (regresi) |

Simulasi 4 agen bukan pytest; tapi **2 test pytest menjalankan subset in-process** (grant → policy → transfer → audit, tanpa HTTP) supaya regresi tertangkap suite. Script simulasi penuh (`simulate_pipeline.py`) memakai relay HTTP nyata dan di‐run manual.

Full suite harus tetap hijau: 411 (Python) + 155 (TS).

## 6. File yang akan dibuat/diubah

```
aatp/transfer.py         # +policy_fn, +grant_leaf_env, +grant_chain_envs, +roots,
                         # +audit_log_path, +_audit helper, wiring di 5 titik
aatp/sec.py              # tidak diubah (audit_append sudah ada)
tests/test_policy_wiring.py   # baru: 8 test policy + audit
tests/test_pipeline_sim.py    # baru: 2 test subset in-process
tools/simulate_pipeline.py    # baru: demo 4 agen lewat relay HTTP
tools/relay_server.py         # dipindah dari temp (opsional; kalau tidak, biarkan)
tools/agent_cli.py            # diperluas: grant publish + policy load
DECISIONS.md                 # +D-044 (policy wiring), +D-045 (audit best-effort)
```

`tools/` adalah skrip demo, bukan bagian paket library `aatp/`.

## 7. Risiko

- Policy wiring mengubah perilaku default kalau ada yang lupa set `policy_fn` — mitigasi: default None, 411 test lama jadi proof.
- Audit I/O di hot path bisa memperlambat — mitigasi: append-only file, best-effort.
- Simulasi 4 agen butuh 4 proses Python + 1 relay; kalau port 8765 dipakai proses lain, konflik — mitigasi: lock file sudah ada di `relay_server.py`.
- Tetap DRAFT: CRY-007 OPEN, V05/V06 UNVERIFIABLE. Simulasi adalah bukti berfungsi, **bukan** bukti aman untuk produksi.
