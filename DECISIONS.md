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
