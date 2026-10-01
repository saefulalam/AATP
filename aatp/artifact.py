"""M2 artifact model: paths, manifest, content_root, stream, materialize (blueprint §6, ART-001..024)."""
import hashlib
import os
import re
import unicodedata
from pathlib import Path

from aatp.canon import jcs
from aatp.errors import err

D_CONTENT = b"AATP/0.2/CONTENT\n"

DEFAULT_LIMITS = {
    "max_path_bytes": 1024,
    "max_manifest_entries": 10000,
    "max_total_artifact_bytes": 4294967296,
}

_RESERVED = {"CON", "PRN", "AUX", "NUL"}
_RESERVED |= {f"COM{i}" for i in range(1, 10)}
_RESERVED |= {f"LPT{i}" for i in range(1, 10)}

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _path_invalid(detail: str):
    return err("ERR_PATH_INVALID", detail)


def _manifest_invalid(detail: str):
    return err("ERR_MANIFEST_INVALID", detail)


def validate_path(path: str) -> None:
    """ART-001..003: syntax checks only (length/limits are manifest-level)."""
    if not isinstance(path, str):
        raise _path_invalid("path must be a string")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        raise _path_invalid("path not encodable as UTF-8") from None
    for ch in path:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise _path_invalid("path contains surrogate")
    if unicodedata.normalize("NFC", path) != path:
        raise _path_invalid("path not NFC-normalized")
    if path == "":
        raise _path_invalid("path empty")
    if path.startswith("/") or path.endswith("/"):
        raise _path_invalid("leading or trailing slash")
    if "\\" in path:
        raise _path_invalid("backslash forbidden")
    for ch in path:
        o = ord(ch)
        if o <= 0x1F or o == 0x7F:
            raise _path_invalid("control character in path")
    for seg in path.split("/"):
        if seg == "" or seg == "." or seg == "..":
            raise _path_invalid(f"bad segment {seg!r}")
        if seg.endswith(" ") or seg.endswith("."):
            raise _path_invalid("segment ends with space or dot")
        base = seg.split(".")[0].upper()
        if base in _RESERVED:
            raise _path_invalid(f"windows reserved name {seg!r}")


def _limits_or_default(limits: dict | None) -> dict:
    if limits is None:
        return dict(DEFAULT_LIMITS)
    if not isinstance(limits, dict):
        raise _manifest_invalid("limits must be a mapping")
    out = dict(DEFAULT_LIMITS)
    for k in ("max_path_bytes", "max_manifest_entries", "max_total_artifact_bytes"):
        if k in limits:
            v = limits[k]
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise _manifest_invalid(f"limit {k} must be an integer >= 0")
            out[k] = v
    return out


def validate_manifest(manifest: dict, limits: dict | None = None) -> None:
    """ART-004..007: shape, path re-validation, collisions, order, limits."""
    lim = _limits_or_default(limits)
    if not isinstance(manifest, dict):
        raise _manifest_invalid("manifest must be an object")
    if set(manifest.keys()) != {"v", "entries"}:
        raise _manifest_invalid("manifest needs exactly v and entries")
    if manifest["v"] != "0.2":
        raise _manifest_invalid("manifest v must be 0.2")
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise _manifest_invalid("entries must be a list")
    if len(entries) > lim["max_manifest_entries"]:
        raise _manifest_invalid("too many manifest entries")
    paths: list[str] = []
    total = 0
    for e in entries:
        if not isinstance(e, dict) or set(e.keys()) != {"path", "size", "x", "d"}:
            raise _manifest_invalid("entry needs exactly path/size/x/d")
        p, size, x, d = e["path"], e["size"], e["x"], e["d"]
        if not isinstance(p, str):
            raise _path_invalid("entry path must be a string")
        validate_path(p)
        if len(p.encode("utf-8")) > lim["max_path_bytes"]:
            raise _manifest_invalid("path exceeds max_path_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise _manifest_invalid("entry size must be an integer >= 0")
        if type(x) is not bool:
            raise _manifest_invalid("entry x must be a boolean")
        if not isinstance(d, str) or not _DIGEST_RE.match(d):
            raise _manifest_invalid("entry d must be sha256:<64 hex>")
        paths.append(p)
        total += size
    if total > lim["max_total_artifact_bytes"]:
        raise _manifest_invalid("total artifact bytes exceed limit")
    exact_seen: set[str] = set()
    fold_seen: dict[str, str] = {}
    for p in paths:
        if p in exact_seen:
            raise _manifest_invalid(f"duplicate path {p!r}")
        f = p.casefold()
        if f in fold_seen:
            raise _path_invalid(f"case-fold collision {p!r} vs {fold_seen[f]!r}")
        exact_seen.add(p)
        fold_seen[f] = p
    path_set = set(paths)
    for p in paths:
        segs = p.split("/")
        for i in range(1, len(segs)):
            prefix = "/".join(segs[:i])
            if prefix in path_set:
                raise _manifest_invalid(f"file/dir collision {prefix!r} vs {p!r}")
    raw = [p.encode("utf-8") for p in paths]
    for i in range(len(raw) - 1):
        if not raw[i] < raw[i + 1]:
            raise _manifest_invalid("entries not in bytewise UTF-8 order")


def build(files: list[tuple[str, bytes, bool]]) -> tuple[dict, bytes, str]:
    """ART-007/010/011/012: validate, sort bytewise, digest, concat, hash."""
    if not isinstance(files, list):
        raise _manifest_invalid("files must be a list")
    items: list[tuple[str, bytes, bool]] = []
    for item in files:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise _manifest_invalid("file entry must be (path, bytes, x)")
        p, data, x = item
        if not isinstance(p, str):
            raise _path_invalid("path must be a string")
        validate_path(p)
        if not isinstance(data, (bytes, bytearray)):
            raise _manifest_invalid("file data must be bytes")
        if type(x) is not bool:
            raise _manifest_invalid("x must be a boolean")
        items.append((p, bytes(data), x))
    paths = [p for p, _, _ in items]
    exact_seen: set[str] = set()
    fold_seen: dict[str, str] = {}
    for p in paths:
        if p in exact_seen:
            raise _manifest_invalid(f"duplicate path {p!r}")
        f = p.casefold()
        if f in fold_seen:
            raise _path_invalid(f"case-fold collision {p!r} vs {fold_seen[f]!r}")
        exact_seen.add(p)
        fold_seen[f] = p
    path_set = set(paths)
    for p in paths:
        segs = p.split("/")
        for i in range(1, len(segs)):
            if "/".join(segs[:i]) in path_set:
                raise _manifest_invalid(f"file/dir collision {p!r}")
    lim = DEFAULT_LIMITS
    if len(items) > lim["max_manifest_entries"]:
        raise _manifest_invalid("too many manifest entries")
    for p, data, _ in items:
        if len(p.encode("utf-8")) > lim["max_path_bytes"]:
            raise _manifest_invalid("path exceeds max_path_bytes")
    if sum(len(d) for _, d, _ in items) > lim["max_total_artifact_bytes"]:
        raise _manifest_invalid("total artifact bytes exceed limit")
    ordered = sorted(items, key=lambda t: t[0].encode("utf-8"))
    entries = []
    for p, data, x in ordered:
        entries.append({
            "path": p,
            "size": len(data),
            "x": x,
            "d": "sha256:" + hashlib.sha256(data).hexdigest(),
        })
    manifest = {"v": "0.2", "entries": entries}
    validate_manifest(manifest)
    stream = b"".join(d for _, d, _ in ordered)
    content_root = "sha256:" + hashlib.sha256(D_CONTENT + jcs(manifest)).hexdigest()
    return manifest, stream, content_root


def _refuse_symlink(path: Path, detail: str) -> None:
    raise err("ERR_PATH_INVALID", detail)


def materialize(manifest: dict, stream: bytes, dest_root) -> None:
    """ART-021/023: verify digests, write under fresh quarantine dir, no symlinks."""
    validate_manifest(manifest)
    if not isinstance(stream, (bytes, bytearray)):
        raise _manifest_invalid("stream must be bytes")
    stream = bytes(stream)
    entries = manifest["entries"]
    total = sum(e["size"] for e in entries)
    if len(stream) != total:
        raise _manifest_invalid("stream length != sum(sizes)")
    blobs: list[bytes] = []
    off = 0
    for e in entries:
        chunk = stream[off:off + e["size"]]
        if len(chunk) != e["size"]:
            raise _manifest_invalid("stream truncated")
        if "sha256:" + hashlib.sha256(chunk).hexdigest() != e["d"]:
            raise err("ERR_ARTIFACT_HASH_MISMATCH", f"digest mismatch {e['path']!r}")
        blobs.append(chunk)
        off += e["size"]
    dest = Path(dest_root)
    try:
        if dest.exists():
            if not dest.is_dir():
                raise err("ERR_INTERNAL", "dest exists and is not a directory")
            if any(dest.iterdir()):
                raise err("ERR_INTERNAL", "dest must be a fresh empty directory")
            if os.path.islink(dest):
                _refuse_symlink(dest, "dest is a symlink")
        else:
            dest.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise err("ERR_INTERNAL", "dest must be a fresh empty directory") from None
    except OSError:
        raise err("ERR_INTERNAL", "dest unavailable") from None
    try:
        real_root = os.path.realpath(str(dest))
    except OSError:
        raise err("ERR_INTERNAL", "dest unavailable") from None
    if os.path.islink(dest):
        _refuse_symlink(dest, "dest is a symlink")
    for e, blob in zip(entries, blobs):
        parts = e["path"].split("/")
        cur = dest
        for depth, seg in enumerate(parts[:-1], start=1):
            cur = cur / seg
            expected_real = os.path.join(real_root, *parts[:depth])
            if os.path.lexists(cur):
                if os.path.islink(cur):
                    _refuse_symlink(cur, f"symlink parent {cur}")
                if not cur.is_dir():
                    raise err("ERR_INTERNAL", f"parent blocks dir {cur}")
                if os.path.realpath(str(cur)) != expected_real:
                    _refuse_symlink(cur, f"parent escapes quarantine {cur}")
            else:
                try:
                    cur.mkdir(exist_ok=False)
                except FileExistsError:
                    if os.path.islink(cur):
                        _refuse_symlink(cur, f"symlink parent {cur}")
                    raise err("ERR_INTERNAL", f"parent race {cur}") from None
                except OSError:
                    raise err("ERR_INTERNAL", f"cannot create dir {cur}") from None
        target = dest.joinpath(*parts)
        if os.path.lexists(target):
            raise err("ERR_INTERNAL", f"target exists {e['path']!r}")
        parent_real = os.path.realpath(str(target.parent))
        if parent_real != real_root and not parent_real.startswith(real_root + os.sep):
            _refuse_symlink(target, f"parent escapes quarantine {e['path']!r}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        if getattr(os, "O_BINARY", 0):
            flags |= os.O_BINARY
        try:
            fd = os.open(str(target), flags, 0o644)
        except FileExistsError:
            raise err("ERR_INTERNAL", f"target exists {e['path']!r}") from None
        except OSError:
            raise err("ERR_INTERNAL", f"cannot create file {e['path']!r}") from None
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        try:
            os.chmod(str(target), 0o755 if e["x"] else 0o644)
        except OSError:
            pass
