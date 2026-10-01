from aatp.errors import ERROR_REGISTRY, AATPError


def test_error_registry_has_core_codes():
    assert ERROR_REGISTRY["ERR_MALFORMED_MESSAGE"] == 1002
    assert ERROR_REGISTRY["ERR_CHUNK_AUTH_FAILED"] == 1303
    assert ERROR_REGISTRY["ERR_INTERNAL"] == 9000


def test_aatp_error_fields():
    e = AATPError("ERR_PATH_INVALID", 1307, "bad path")
    assert e.code == "ERR_PATH_INVALID" and e.numeric == 1307 and e.detail == "bad path"
