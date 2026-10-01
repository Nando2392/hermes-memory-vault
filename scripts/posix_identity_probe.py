"""Synthetic isolated-identity SQLite experiment, NOT a production broker.

Help/default are harmless on Windows. --run requires Linux root on a disposable
GitHub Actions runner supplied by the parent workflow. Never elevates itself,
creates users, installs software, or accepts paths/SQL from clients.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import signal
import socket
import sqlite3
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

SERVICE = 61001
ATTACKER = 61002
TIMEOUT = 15.0
NAMES = ("memory.db", "memory.db-wal", "memory.db-shm", "memory.db-journal")


def require(condition: bool, message: str) -> None:
    """Fail even when Python is invoked with optimization enabled."""
    if not condition:
        raise RuntimeError(message)


def identity() -> dict[str, Any]:
    """Capture real/effective/saved credentials, not just the requested IDs."""
    return {
        "uids": list(os.getresuid()),
        "gids": list(os.getresgid()),
        "groups": os.getgroups(),
    }


def send(channel: socket.socket, result: dict[str, Any]) -> None:
    """Send one bounded JSON frame over private harness IPC."""
    payload = json.dumps(result).encode()
    require(len(payload) < 65536, "oversized result")
    channel.sendall(len(payload).to_bytes(4, "big") + payload)


def receive(channel: socket.socket) -> dict[str, Any]:
    """Read exactly one bounded frame with an absolute deadline."""
    deadline = time.monotonic() + TIMEOUT

    def exact(size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "IPC deadline exceeded")
            channel.settimeout(remaining)
            chunk = channel.recv(size - len(chunks))
            require(bool(chunk), "child exited before result")
            chunks.extend(chunk)
        return bytes(chunks)

    size = int.from_bytes(exact(4), "big")
    require(0 < size < 65536, "invalid frame size")
    result = json.loads(exact(size))
    require(isinstance(result, dict) and "error" not in result, str(result))
    return result


def spawn(
    uid: int,
    work: Callable[[], dict[str, Any]],
    children: dict[int, socket.socket],
    hold: bool = False,
) -> tuple[int, socket.socket]:
    """Fork a synthetic worker; drop all supplementary and saved credentials."""
    parent, child = socket.socketpair()
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid == 0:
        parent.close()
        code = 0
        try:
            # No inherited store handles or parent IPC channels reach the worker.
            for name in os.listdir("/proc/self/fd"):
                fd = int(name)
                if fd > 2 and fd != child.fileno():
                    try:
                        os.close(fd)
                    except OSError as exc:
                        if exc.errno != errno.EBADF:
                            raise
            os.chdir("/")
            os.umask(0o077)
            os.setgroups([])
            os.setresgid(uid, uid, uid)
            os.setresuid(uid, uid, uid)
            actual = identity()
            require(
                actual == {"uids": [uid] * 3, "gids": [uid] * 3, "groups": []},
                "credential drop incomplete",
            )
            result = work()
            result["identity"] = actual
            send(child, result)
            if hold:
                child.settimeout(TIMEOUT * 4)
                child.recv(1)  # Parent forcibly kills service; never graceful close.
        except BaseException as exc:  # noqa: BLE001 - fork child must never resume parent code
            code = 2
            try:
                send(child, {"error": repr(exc)})
            except OSError:
                pass
        finally:
            child.close()
            os._exit(code)
    child.close()
    children[pid] = parent
    return pid, parent


def reap(pid: int, children: dict[int, socket.socket], kill: bool = False) -> int:
    """Bound cleanup, including workers stuck after sending their result."""
    if kill:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            children.pop(pid).close()
            return status
        time.sleep(0.01)
    if not kill:
        return reap(pid, children, kill=True)
    raise RuntimeError(f"child {pid} did not reap within SIGKILL deadline")


def once(
    uid: int, work: Callable[[], dict[str, Any]], children: dict[int, socket.socket]
) -> dict[str, Any]:
    """Execute one fixed experiment under a fully dropped identity."""
    pid, channel = spawn(uid, work, children)
    result = receive(channel)
    require(reap(pid, children) == 0, "worker failed or timed out")
    return result


def snapshot(paths: list[Path]) -> dict[str, list[int]]:
    """Record object identity/ownership, excluding legitimate content changes."""
    output = {}
    for path in paths:
        value = path.lstat()
        require(not stat.S_ISLNK(value.st_mode), f"unexpected link: {path}")
        output[path.name] = [
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
        ]
    return output


def mutations(store: Path, scratch: Path, sentinel: Path) -> dict[str, Any]:
    """Try each substitution independently; errors other than DAC denial fail."""
    results = {}
    for name in NAMES:
        target = store / name
        for operation in (
            "symlink",
            "hardlink",
            "symlink_create",
            "hardlink_create",
            "unlink",
            "rename",
            "write",
            "export_link",
        ):
            stage = scratch / ("stage-" + name + "-" + operation)
            try:
                if operation == "symlink_create":
                    target.symlink_to(sentinel)
                elif operation == "hardlink_create":
                    os.link(sentinel, target)
                elif operation == "symlink":
                    stage.symlink_to(sentinel)
                    os.replace(stage, target)
                elif operation == "hardlink":
                    # Source belongs to this identity: protected_hardlinks is not
                    # the explanation for a failed destination substitution.
                    os.link(sentinel, stage)
                    os.replace(stage, target)
                elif operation == "unlink":
                    target.unlink()
                elif operation == "rename":
                    os.rename(target, stage)
                elif operation == "write":
                    with target.open("wb") as stream:
                        stream.write(b"hostile")
                else:
                    os.link(target, stage)
                results[name + ":" + operation] = {"succeeded": True}
            except OSError as exc:
                results[name + ":" + operation] = {
                    "succeeded": False,
                    "errno": exc.errno,
                }
            finally:
                if stage.is_symlink() or stage.exists():
                    stage.unlink()
    for label, target in (("store", store), ("ancestor", store.parent)):
        replacement = scratch / ("replace-" + label)
        replacement.mkdir()
        for operation in ("rename", "replace"):
            try:
                if operation == "rename":
                    os.rename(target, scratch / ("stolen-" + label))
                else:
                    os.replace(replacement, target)
                results[label + ":" + operation] = {"succeeded": True}
            except OSError as exc:
                results[label + ":" + operation] = {
                    "succeeded": False,
                    "errno": exc.errno,
                }
    require(len(results) == len(NAMES) * 8 + 4, "incomplete attack matrix")
    require(
        all(
            not item["succeeded"] and item.get("errno") in (errno.EACCES, errno.EPERM)
            for item in results.values()
        ),
        f"namespace boundary failed: {results}",
    )
    return results


def scratch_control(directory: Path) -> dict[str, Any]:
    """Prove all namespace primitives work in this identity's own 0700 tree."""
    directory.mkdir(mode=0o700)
    a, b, c = (directory / name for name in ("a", "b", "c"))
    a.write_bytes(b"control")
    os.link(a, b)
    c.symlink_to(a)
    require(
        c.read_bytes() == b"control" and a.stat().st_ino == b.stat().st_ino,
        "scratch link controls failed",
    )
    os.replace(b, c)
    require(not c.is_symlink(), "scratch rename failed")
    a.unlink()
    c.unlink()
    moved = directory.with_name(directory.name + "-moved")
    directory.rename(moved)
    moved.rmdir()
    return {"write_link_symlink_replace_unlink_directory_rename": True}


def service_start(slot: Path, keepalive: list[sqlite3.Connection]) -> dict[str, Any]:
    """Own the store; hold native WAL connections open across adversarial work."""
    store = slot / "store"
    store.mkdir(mode=0o700)
    (slot / "peer-control").mkdir(mode=0o700)
    control = scratch_control(slot / "same-uid-control")
    connection = sqlite3.connect(store / "memory.db", timeout=3)
    keepalive.append(connection)
    require(
        connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal", "no WAL"
    )
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE records(id TEXT PRIMARY KEY)")
    connection.execute("INSERT INTO records VALUES ('service-committed')")
    connection.commit()
    # A second simultaneous native connection shares ordinary WAL/SHM paths.
    reader = sqlite3.connect(store / "memory.db", timeout=3)
    keepalive.append(reader)
    require(
        reader.execute("SELECT count(*) FROM records").fetchone()[0] == 1,
        "reader failed",
    )
    return {
        "same_uid_0700_control": control,
        "wal": True,
        "connections": 2,
        "journal_candidate": "absent; creation attempts still tested",
        "sqlite_compile_options": [
            row[0] for row in connection.execute("PRAGMA compile_options")
        ],
    }


def native_client(store: Path, recovery: bool = False) -> dict[str, Any]:
    """Run fixed SQL only; direct native client uses the trusted service UID."""
    connection = sqlite3.connect(store / "memory.db", timeout=3)
    try:
        require(
            connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal", "WAL lost"
        )
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        expected = ["service-committed"]
        if recovery:
            expected = ["client-committed", "service-committed"]
        rows = [
            row[0] for row in connection.execute("SELECT id FROM records ORDER BY id")
        ]
        require(rows == expected, f"unexpected committed rows: {rows}")
        if not recovery:
            connection.execute("INSERT INTO records VALUES ('client-committed')")
            connection.commit()
        require(
            connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
            "integrity failure",
        )
        return {
            "rows_before_operation": rows,
            "integrity_check": "ok",
            "recovery": recovery,
        }
    finally:
        connection.close()


def run() -> int:
    """Test Linux DAC isolation; privileged parent only provisions disposable paths."""
    results: dict[str, Any] = {}
    children: dict[int, socket.socket] = {}
    try:
        # /tmp is used rather than a checkout under an unprivileged writable
        # ancestor. Only root-owned non-writable or sticky ancestors are allowed.
        for ancestor in (Path("/"), Path("/tmp")):
            value = ancestor.stat()
            require(
                value.st_uid == 0
                and (not value.st_mode & 0o022 or bool(value.st_mode & stat.S_ISVTX)),
                "unprotected temp ancestor",
            )
        with tempfile.TemporaryDirectory(prefix="sqlite-identity-", dir="/tmp") as name:
            base = Path(name)
            base.chmod(0o755)
            slot, scratch = base / "service", base / "attacker"
            for path, uid in ((slot, SERVICE), (scratch, ATTACKER)):
                path.mkdir(mode=0o700)
                os.chown(path, uid, uid)
            # Deliberately writable by the service too: unchanged bytes must
            # result from namespace protection, not an inaccessible sentinel.
            sentinel = base / "outside-sentinel"
            sentinel.write_bytes(b"outside sentinel must stay unchanged\n")
            os.chown(sentinel, ATTACKER, ATTACKER)
            sentinel.chmod(0o666)
            before_sentinel = sentinel.read_bytes()
            sentinel_identity = snapshot([sentinel])
            store = slot / "store"
            try:
                keepalive: list[sqlite3.Connection] = []
                service_pid, channel = spawn(
                    SERVICE, lambda: service_start(slot, keepalive), children, hold=True
                )
                results["service"] = receive(channel)
                stable_paths = [base, slot, store] + [
                    store / item for item in NAMES[:3]
                ]
                baseline = snapshot(stable_paths)
                for path in stable_paths[1:]:
                    value = path.stat()
                    require(
                        value.st_uid == SERVICE
                        and value.st_gid == SERVICE
                        and not value.st_mode & 0o077,
                        "store ownership/privacy mismatch",
                    )
                results["same_uid_peer_control"] = once(
                    SERVICE,
                    lambda: scratch_control(slot / "peer-control" / "child"),
                    children,
                )
                results["attacker_scratch_control"] = once(
                    ATTACKER, lambda: scratch_control(scratch / "control"), children
                )
                results["attacks"] = once(
                    ATTACKER, lambda: mutations(store, scratch, sentinel), children
                )
                require(
                    snapshot(stable_paths) == baseline,
                    "namespace/ownership changed during attacks",
                )
                results["native_client"] = once(
                    SERVICE, lambda: native_client(store), children
                )
                require(
                    snapshot(stable_paths) == baseline, "native client split namespace"
                )
                require(
                    (store / "memory.db-wal").stat().st_size > 32,
                    "no recoverable WAL present",
                )
                status = reap(service_pid, children, kill=True)
                require(
                    os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
                    "service was not forcibly terminated",
                )
                results["forced_service_exit"] = (
                    "SIGKILL after committed records; not power-loss proof"
                )
                results["recovery"] = once(
                    SERVICE, lambda: native_client(store, recovery=True), children
                )
                require(
                    snapshot(stable_paths[:4])
                    == {
                        key: baseline[key]
                        for key in (base.name, slot.name, store.name, "memory.db")
                    },
                    "main identity changed on recovery",
                )
                # WAL/SHM may legitimately be deleted/recreated on last close.
                for path in store.iterdir():
                    value = path.lstat()
                    require(
                        stat.S_ISREG(value.st_mode)
                        and value.st_uid == SERVICE
                        and value.st_gid == SERVICE
                        and not value.st_mode & 0o077
                        and value.st_nlink == 1,
                        "unexpected recovered namespace entry",
                    )
                require(
                    sentinel.read_bytes() == before_sentinel
                    and snapshot([sentinel]) == sentinel_identity,
                    "outside sentinel changed",
                )
                results["outside_sentinel_unchanged"] = True
                results["stable_ownership_and_live_inode_identity"] = True
            finally:
                cleanup_errors = []
                for pid in list(children):
                    try:
                        reap(pid, children, kill=True)
                    except (OSError, RuntimeError) as exc:
                        cleanup_errors.append(repr(exc))
                require(not cleanup_errors, str(cleanup_errors))
        report = {"status": "isolated_identity_checks_passed", "results": results}
        code = 0
    except (OSError, RuntimeError, sqlite3.Error, ValueError) as exc:
        report = {"status": "failed", "error": repr(exc), "results": results}
        code = 1
    report.update(
        {
            "kernel": platform.release(),
            "sqlite_version": sqlite3.sqlite_version,
            "service_uid_gid": SERVICE,
            "attacker_uid_gid": ATTACKER,
            "limits": "Synthetic Linux identity experiment only; no production broker, "
            "Windows support, power-loss proof, hostile same-service-UID protection, "
            "privilege-free deployment, IPC authentication or arbitrary SQL interface.",
        }
    )
    print(json.dumps(report, indent=2))
    return code


def main() -> int:
    """Require explicit opt-in and the parent-controlled Linux CI environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run", action="store_true", help="run synthetic Linux CI experiment"
    )
    arguments = parser.parse_args()
    if not arguments.run:
        parser.print_help()
        return 0
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.environ.get("GITHUB_ACTIONS") != "true"
    ):
        print(
            json.dumps(
                {
                    "status": "unsupported",
                    "reason": "requires Linux root in parent-controlled GitHub Actions",
                }
            )
        )
        return 77
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
