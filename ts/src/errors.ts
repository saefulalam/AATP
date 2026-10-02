// AATP error registry (blueprint §14). Numbers copied verbatim from
// aatp/errors.py — the registry is a wire-visible contract, both
// implementations must use identical numerics.

export const ERROR_REGISTRY: Record<string, number> = {
  ERR_PROTOCOL_VERSION: 1001,
  ERR_MALFORMED_MESSAGE: 1002,
  ERR_UNSUPPORTED_MESSAGE: 1003,
  ERR_UNSUPPORTED_EXTENSION: 1004,
  ERR_SUITE_UNSUPPORTED: 1005,
  ERR_SIZE_LIMIT: 1006,
  ERR_AUTH_REQUIRED: 1101,
  ERR_AUTH_FAILED: 1102,
  ERR_SIGNATURE_INVALID: 1103,
  ERR_KEY_EXPIRED: 1104,
  ERR_KEY_REVOKED: 1105,
  ERR_REPLAY_DETECTED: 1106,
  ERR_KEY_COMMITMENT_MISMATCH: 1107,
  ERR_CARD_ROLLBACK: 1108,
  ERR_RECIPIENT_MISMATCH: 1109,
  ERR_MESSAGE_EXPIRED: 1110,
  ERR_DECRYPT_FAILED: 1111,
  ERR_POLICY_DENIED: 1201,
  ERR_GRANT_INVALID: 1202,
  ERR_GRANT_ATTENUATION: 1203,
  ERR_LEASE_EXPIRED: 1204,
  ERR_ARTIFACT_NOT_FOUND: 1301,
  ERR_ARTIFACT_HASH_MISMATCH: 1302,
  ERR_CHUNK_AUTH_FAILED: 1303,
  ERR_INVALID_PARENT: 1305,
  ERR_DAG_CYCLE: 1306,
  ERR_PATH_INVALID: 1307,
  ERR_MANIFEST_INVALID: 1308,
  ERR_TRANSFER_NOT_FOUND: 1401,
  ERR_SEQUENCE_INVALID: 1402,
  ERR_RESUME_INVALID: 1403,
  ERR_RATE_LIMIT: 1405,
  ERR_QUARANTINED: 1501,
  ERR_SCAN_REQUIRED: 1502,
  ERR_INTERNAL: 9000,
};

export class AATPError extends Error {
  code: string;
  numeric: number;
  detail?: string;

  constructor(code: string, numeric: number, detail?: string) {
    super(`${code}(${numeric}): ${detail ?? ""}`);
    this.name = "AATPError";
    this.code = code;
    this.numeric = numeric;
    if (detail !== undefined) {
      this.detail = detail;
    }
  }
}

export function err(code: string, detail?: string): AATPError {
  return new AATPError(
    code,
    ERROR_REGISTRY[code] ?? ERROR_REGISTRY["ERR_INTERNAL"],
    detail,
  );
}
