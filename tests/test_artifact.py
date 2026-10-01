import hashlib
import os

import pytest

from aatp.artifact import build, materialize, validate_manifest
from aatp.canon import jcs
from aatp.errors import AATPError

LIMITS = {"max_path_bytes": 1024, "max_manifest_entries": 10000,
          "max_total_artifact_bytes": 4294967296}

V04_MANIFEST_JCS = (
    '{"entries":[{"d":"sha256:ab08508fdf5ca4da5c4995987bc41c56c048aaa5eeb046417ae4049b7d40286e",'
    '"path":"bin/run.sh","size":8,"x":true},'
    '{"d":"sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",'
    '"path":"hello.txt","size":5,"x":false}],"v":"0.2"}'
)
V04_STREAM_HEX = "6563686f2068690a68656c6c6f"
V04_CONTENT_ROOT = "sha256:9067a66c672c42accf461d38069a837189e8e2fe0713f4edc6f8e5ec3ce9c1cf"


def test_V04_content_root():
    files = [("hello.txt", b"hello", False), ("bin/run.sh", b"echo hi\n", True)]
    manifest, stream, cr = build(files)
    assert stream.hex() == V04_STREAM_HEX
    assert cr == V04_CONTENT_ROOT


def test_V04_manifest_jcs_exact():
    files = [("hello.txt", b"hello", False), ("bin/run.sh", b"echo hi\n", True)]
    manifest, _, _ = build(files)
    assert jcs(manifest).decode("ascii") == V04_MANIFEST_JCS
    assert jcs(manifest).hex() == V04_MANIFEST_JCS.encode("ascii").hex()


def test_ART002_reject_dotdot():
    with pytest.raises(AATPError) as ei:
        build([("a/../b", b"x", False)])
    assert ei.value.code == "ERR_PATH_INVALID"


def test_ART004_reject_casefold_collision():
    with pytest.raises(AATPError) as ei:
        build([("A.txt", b"1", False), ("a.txt", b"2", False)])
    assert ei.value.code == "ERR_PATH_INVALID"


def test_ART004_reject_casefold_straesse():
    with pytest.raises(AATPError) as ei:
        build([("Stra\xdfe.txt", b"1", False), ("STRASSE.txt", b"2", False)])
    assert ei.value.code == "ERR_PATH_INVALID"


def test_ART007_reject_unsorted_manifest():
    m = {"v": "0.2", "entries": [
        {"path": "b.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64},
        {"path": "a.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64}]}
    with pytest.raises(AATPError) as ei:
        validate_manifest(m, LIMITS)
    assert ei.value.code == "ERR_MANIFEST_INVALID"


def test_ART013_empty_artifact():
    m, s, cr = build([])
    assert m["entries"] == [] and s == b"" and cr.startswith("sha256:")
    exp = "sha256:" + hashlib.sha256(
        b"AATP/0.2/CONTENT\n" + jcs({"v": "0.2", "entries": []})).hexdigest()
    assert cr == exp


def test_ART003_reject_windows_reserved():
    with pytest.raises(AATPError) as ei:
        build([("CON.txt", b"x", False)])
    assert ei.value.code == "ERR_PATH_INVALID"


def test_ART001_reject_non_nfc():
    # NFD e + combining acute; NFC form is \u00e9.txt
    with pytest.raises(AATPError) as ei:
        build([("e\u0301.txt", b"x", False)])
    assert ei.value.code == "ERR_PATH_INVALID"


def test_ART001_accept_nfc():
    m, s, _ = build([("caf\u00e9.txt", b"x", False)])
    assert m["entries"][0]["path"] == "caf\u00e9.txt"
    assert s == b"x"


def test_ART002_reject_trailing_slash():
    with pytest.raises(AATPError) as ei:
        build([("dir/", b"x", False)])
    assert ei.value.code == "ERR_PATH_INVALID"


def test_ART002_reject_syntax_cases():
    bad = ["", "/a", "a//b", "a\\b", "a/./b", ".", "..",
           "a/\x00b", "a/\x1fb", "a/\x7fb", "/leading", "a/b/"]
    for p in bad:
        with pytest.raises(AATPError) as ei:
            build([(p, b"x", False)])
        assert ei.value.code == "ERR_PATH_INVALID", p


def test_ART003_reject_trailing_space_dot():
    for p in ["a /b", "a./b", "a/b ", "a/b.", "a/..."]:
        with pytest.raises(AATPError) as ei:
            build([(p, b"x", False)])
        assert ei.value.code == "ERR_PATH_INVALID", p


def test_ART003_reject_reserved_variants():
    for p in ["con", "PRN", "aux.txt", "nul.bin", "COM1", "com9.txt",
              "LPT1", "lpt9.log", "AUX", "Con"]:
        with pytest.raises(AATPError) as ei:
            build([(p, b"x", False)])
        assert ei.value.code == "ERR_PATH_INVALID", p
    # COM10 / LPT10 are not reserved
    m, _, _ = build([("COM10.txt", b"x", False)])
    assert m["entries"][0]["path"] == "COM10.txt"


def test_ART005_reject_prefix_collision():
    with pytest.raises(AATPError) as ei:
        build([("a", b"1", False), ("a/b", b"2", False)])
    assert ei.value.code == "ERR_MANIFEST_INVALID"


def test_ART006_reject_path_too_long():
    long_path = "a" * 1025
    with pytest.raises(AATPError) as ei:
        build([(long_path, b"x", False)])
    assert ei.value.code == "ERR_MANIFEST_INVALID"


def test_ART006_reject_too_many_entries():
    m = {"v": "0.2", "entries": [
        {"path": "a.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64},
        {"path": "b.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64},
        {"path": "c.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64}]}
    with pytest.raises(AATPError) as ei:
        validate_manifest(m, {"max_path_bytes": 1024, "max_manifest_entries": 2,
                              "max_total_artifact_bytes": 4294967296})
    assert ei.value.code == "ERR_MANIFEST_INVALID"


def test_ART006_reject_total_too_large():
    m = {"v": "0.2", "entries": [
        {"path": "a.txt", "size": 5, "x": False, "d": "sha256:" + "0" * 64}]}
    with pytest.raises(AATPError) as ei:
        validate_manifest(m, {"max_path_bytes": 1024, "max_manifest_entries": 10000,
                              "max_total_artifact_bytes": 4})
    assert ei.value.code == "ERR_MANIFEST_INVALID"


def test_ART007_reject_duplicate():
    m = {"v": "0.2", "entries": [
        {"path": "a.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64},
        {"path": "a.txt", "size": 1, "x": False, "d": "sha256:" + "0" * 64}]}
    with pytest.raises(AATPError) as ei:
        validate_manifest(m, LIMITS)
    assert ei.value.code == "ERR_MANIFEST_INVALID"


def test_ART007_build_sorts_bytewise():
    manifest, stream, _ = build([("b.txt", b"B", False), ("a.txt", b"A", False)])
    assert [e["path"] for e in manifest["entries"]] == ["a.txt", "b.txt"]
    assert stream == b"AB"


def test_ART010_011_digest_and_size():
    manifest, _, _ = build([("hello.txt", b"hello", False)])
    e = manifest["entries"][0]
    assert e["size"] == 5
    assert e["x"] is False
    assert e["d"] == "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_ART012_content_root_formula():
    manifest, _, cr = build([("hello.txt", b"hello", False)])
    exp = "sha256:" + hashlib.sha256(b"AATP/0.2/CONTENT\n" + jcs(manifest)).hexdigest()
    assert cr == exp


def test_ART023_materialize_roundtrip(tmp_path):
    manifest, stream, _ = build(
        [("hello.txt", b"hello", False), ("bin/run.sh", b"echo hi\n", True)])
    dest = tmp_path / "out"
    materialize(manifest, stream, dest)
    assert (dest / "hello.txt").read_bytes() == b"hello"
    assert (dest / "bin" / "run.sh").read_bytes() == b"echo hi\n"


def test_ART023_materialize_digest_mismatch(tmp_path):
    manifest, stream, _ = build([("hello.txt", b"hello", False)])
    bad = b"X" + stream[1:]
    with pytest.raises(AATPError) as ei:
        materialize(manifest, bad, tmp_path / "out")
    assert ei.value.code == "ERR_ARTIFACT_HASH_MISMATCH"


def test_ART023_materialize_requires_fresh_dir(tmp_path):
    manifest, stream, _ = build([("hello.txt", b"hello", False)])
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "pre.txt").write_bytes(b"pre")
    with pytest.raises(AATPError) as ei:
        materialize(manifest, stream, dest)
    assert ei.value.code == "ERR_INTERNAL"


def test_ART023_materialize_refuses_symlink_parent(tmp_path):
    manifest, stream, _ = build([("sub/f.txt", b"hi", False)])
    dest = tmp_path / "out"
    dest.mkdir()
    try:
        os.symlink(str(tmp_path), str(dest / "sub"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(AATPError) as ei:
        materialize(manifest, stream, dest)
    assert ei.value.code in ("ERR_PATH_INVALID", "ERR_INTERNAL")
