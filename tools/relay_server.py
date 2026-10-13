"""localhost AATP relay, single-instance via a lock file (DEMO tooling).

Run: ``python tools/relay_server.py [port]`` (default 8765).

The relay is opaque: it stores sealed packets, AEAD chunks and published cards
and never opens any of them (``aatp.transport.relay.Relay``, NET-001/002). The
HTTP routes come from ``aatp.transport.http.serve`` unchanged -- this file only
adds process plumbing (lock file, port reuse, clean shutdown).

Single instance: exactly one relay per lock file. A second ``relay_server.py``
that finds a live lock prints the running pid/port and exits 2 rather than
fighting over the port -- exiting 0 would tell the caller a relay is serving
when none is. A lock left behind by a dead process is taken over.
"""
import json
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aatp.transport.http import serve  # noqa: E402
from aatp.transport.relay import Relay  # noqa: E402

DEFAULT_PORT = 8765
LOCK_NAME = "relay.lock"


def lock_path() -> Path:
    """Lock file next to this script, so a clone keeps its own instance."""
    return Path(__file__).resolve().parent / LOCK_NAME


def pid_alive(pid: int) -> bool:
    """Is ``pid`` a live process? Never signals it (Windows-safe)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not process:
            return False
        ctypes.windll.kernel32.CloseHandle(process)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def take_relay_lock(path: Path, port: int) -> dict | None:
    """Claim the relay lock; return the owner record, or None if held.

    This read-then-write is advisory: two processes can both pass it. What
    actually keeps one relay up is the ``serve`` bind in ``main``, which fails
    for the loser; the lock only makes the common case print a clear message.
    """
    path = Path(path)
    if path.exists():
        try:
            owner = json.loads(path.read_text(encoding="utf-8"))
            live = pid_alive(owner.get("pid"))
        except (OSError, ValueError):
            owner, live = {}, False
        if live:
            return None
        print(f"relay: stale lock from pid {owner.get('pid')!r}, taking over")
    record = {"pid": os.getpid(), "port": int(port),
              "started_at": datetime.now(timezone.utc).isoformat()}
    path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    return record


def release_relay_lock(path: Path, record: dict) -> None:
    """Drop the lock, but only if we still own it."""
    path = Path(path)
    try:
        owner = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if owner.get("pid") != record.get("pid"):
        return
    try:
        path.unlink()
    except OSError:
        pass


def port_in_use(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def relay_answers(host: str, port: int) -> bool:
    """Does something on this port actually speak the AATP relay routes?"""
    import urllib.error
    import urllib.request
    url = f"http://{host}:{port}/aatp/v0.2/agents/probe/card"
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status == 404
    except urllib.error.HTTPError as e:
        return e.status == 404
    except Exception:
        return False


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    port = int(argv[0]) if argv and argv[0].isdigit() else DEFAULT_PORT
    host = "127.0.0.1"
    lock = lock_path()

    if port_in_use(host, port):
        if relay_answers(host, port):
            print(f"relay: port {port} already serving an AATP relay; reusing it")
            return 0
        print(f"relay: port {port} is taken by something that is not an AATP "
              f"relay; refusing to start")
        return 2
    record = take_relay_lock(lock, port)
    if record is None:
        try:
            owner = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            owner = {}
        print(f"relay: already running as pid {owner.get('pid')} "
              f"on port {owner.get('port')}; not serving, exiting 2")
        return 2

    relay = Relay()
    server = serve(relay, host=host, port=port,
                   card_resolver=relay.get_card)
    actual = server.server_address[1]
    if actual != port:  # port 0 was requested
        record["port"] = actual
        lock.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    print(f"relay: listening on http://{host}:{actual} (pid {os.getpid()})")

    def shutdown(*_args):
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, shutdown)
        except (ValueError, OSError):
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("relay: stopping")
    finally:
        server.server_close()
        release_relay_lock(lock, record)
    return 0


if __name__ == "__main__":
    sys.exit(main())
