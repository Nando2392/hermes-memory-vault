"""Landlock counterexample test, not a sandbox implementation.

All scratch data is created under this script's directory and removed afterwards.
Only --run on Linux executes experiments. No installs, network, or root needed.
A zero exit means counterexamples were reproduced, NOT that isolation is safe.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import platform
import signal
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def checked(result: int) -> int:
    """Raise with the kernel errno, without treating denial as success."""
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def restrict(libc: ctypes.CDLL, root_fd: int, abi: int) -> None:
    """Apply filesystem restrictions solely for the counterexample test."""
    handled = (1 << 13) - 1
    if abi >= 2:
        handled |= 1 << 13  # REFER: no grant, even though peer can link.
    if abi >= 3:
        handled |= 1 << 14  # TRUNCATE must be handled explicitly.
    rules = Ruleset(handled)
    rules_fd = checked(libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0))
    try:
        rule = PathRule(handled & ~1 & ~(1 << 13), root_fd)
        checked(libc.syscall(445, rules_fd, 1, ctypes.byref(rule), 0))
        checked(libc.prctl(38, 1, 0, 0, 0))  # PR_SET_NO_NEW_PRIVS
        checked(libc.prctl(4, 0, 0, 0, 0))  # PR_SET_DUMPABLE
        checked(libc.syscall(446, rules_fd, 0))
    finally:
        os.close(rules_fd)


def attempt_write(path: Path) -> dict[str, object]:
    """Record whether the kernel permits opening and writing this path."""
    try:
        descriptor = os.open(path, os.O_WRONLY)
        try:
            os.write(descriptor, b"changed")
        finally:
            os.close(descriptor)
        return {"write_succeeded": True}
    except OSError as exc:
        return {"write_succeeded": False, "errno": exc.errno}


def child_experiments(
    libc: ctypes.CDLL,
    root: Path,
    outside: Path,
    root_fd: int,
    inherited_fd: int,
) -> dict[str, object]:
    """Test path grants, inode aliases, inherited descriptors and stock SQLite."""
    results: dict[str, object] = {}
    for name, path in (
        ("outside_direct", outside / "direct"),
        ("outside_symlink", root / "symlink"),
        ("preexisting_hardlink", root / "preexisting"),
        ("late_hardlink", root / "late"),
    ):
        results[name] = attempt_write(path)
    os.write(inherited_fd, b"changed")
    results["inherited_descriptor"] = {"write_succeeded": True}
    # BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV do not reject hardlinks.
    how = OpenHow(os.O_WRONLY, 0, 0x08 | 0x04 | 0x02 | 0x01)
    descriptor = checked(
        libc.syscall(
            437,
            root_fd,
            ctypes.c_char_p(b"preexisting"),
            ctypes.byref(how),
            ctypes.sizeof(how),
        )
    )
    try:
        os.write(descriptor, b"openat2")
    finally:
        os.close(descriptor)
    results["openat2_hardlink"] = {"write_succeeded": True}
    for name in ("main", "wal", "shm"):
        connection = None
        try:
            connection = sqlite3.connect(root / name / "memory.db")
            mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE IF NOT EXISTS t(x)")
            connection.execute("INSERT INTO t VALUES (1)")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(FULL)").fetchall()
            results["sqlite_" + name] = {"operation_succeeded": True, "mode": mode}
        except sqlite3.Error as exc:
            results["sqlite_" + name] = {
                "operation_succeeded": False,
                "error": str(exc),
            }
        finally:
            if connection is not None:
                connection.close()
    return results


def run() -> int:
    """Run independent-process attacks against disposable sentinel files."""
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64"):
        print(
            json.dumps({"status": "unsupported", "reason": "Linux x86_64/aarch64 only"})
        )
        return 77
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 3:
        print(
            json.dumps(
                {
                    "status": "unsupported",
                    "landlock_abi": abi,
                    "errno": ctypes.get_errno(),
                }
            )
        )
        return 77
    with tempfile.TemporaryDirectory(
        prefix="research-h2-run-", dir=Path(__file__).parent
    ) as directory:
        base = Path(directory).resolve()
        root = base / "allowed"
        outside = base / "outside"
        root.mkdir(mode=0o700)
        outside.mkdir(mode=0o700)
        for name in (
            "direct",
            "preexisting",
            "late",
            "inherited",
            "main",
            "wal",
            "shm",
        ):
            (outside / name).write_bytes(b"")
        (root / "symlink").symlink_to(outside / "direct")
        os.link(outside / "preexisting", root / "preexisting")
        for name in ("main", "wal", "shm"):
            case = root / name
            case.mkdir()
            database = case / "memory.db"
            if name != "main":
                with sqlite3.connect(database) as connection:
                    connection.execute("CREATE TABLE t(x)")
                connection.close()
            attacked = database if name == "main" else case / ("memory.db-" + name)
            os.link(outside / name, attacked)
        root_fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
        inherited_fd = os.open(outside / "inherited", os.O_WRONLY)
        parent_socket, child_socket = socket.socketpair()
        parent_socket.settimeout(15)
        child_socket.settimeout(15)
        process = os.fork()
        if process == 0:
            parent_socket.close()
            exit_code = 0
            try:
                restrict(libc, root_fd, abi)
                child_socket.sendall(b"R")
                if child_socket.recv(1) != b"G":
                    raise RuntimeError("parent failed synchronization")
                result = child_experiments(libc, root, outside, root_fd, inherited_fd)
                child_socket.sendall(json.dumps(result).encode())
            except (OSError, RuntimeError, sqlite3.Error) as exc:
                exit_code = 2
                child_socket.sendall(json.dumps({"error": repr(exc)}).encode())
            finally:
                child_socket.close()
                os._exit(exit_code)
        child_socket.close()
        os.close(root_fd)
        os.close(inherited_fd)
        try:
            if parent_socket.recv(1) != b"R":
                raise RuntimeError("worker failed before sandbox-ready barrier")
            os.link(outside / "late", root / "late")
            parent_socket.sendall(b"G")
            chunks = []
            while chunk := parent_socket.recv(4096):
                chunks.append(chunk)
            results = json.loads(b"".join(chunks))
        finally:
            parent_socket.close()
            # Bounded teardown even if SQLite or kernel behavior stalls.
            try:
                os.kill(process, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(process, 0)
        assert "error" not in results, results
        for name in ("outside_direct", "outside_symlink"):
            assert results[name] == {"write_succeeded": False, "errno": errno.EACCES}, (
                results
            )
        for name in (
            "preexisting_hardlink",
            "late_hardlink",
            "openat2_hardlink",
            "inherited_descriptor",
        ):
            assert results[name]["write_succeeded"], results
        for name in ("preexisting", "late", "inherited"):
            assert (outside / name).read_bytes(), name
        results["sqlite_sentinel_changed"] = {
            name: bool((outside / name).read_bytes()) for name in ("main", "wal", "shm")
        }
        assert (outside / "direct").read_bytes() == b""
        print(
            json.dumps(
                {
                    "status": "counterexamples_reproduced",
                    "landlock_abi": abi,
                    "kernel": platform.release(),
                    "sqlite_version": sqlite3.sqlite_version,
                    "results": results,
                    "limits": "Not a production sandbox; SQLite substitution outcomes observational; no seccomp, ptrace, interop or crash proof.",
                },
                indent=2,
            )
        )
    return 0


def main() -> int:
    """Keep experiments opt-in and help safe on non-Linux hosts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run", action="store_true", help="run disposable Linux-only counterexamples"
    )
    arguments = parser.parse_args()
    if not arguments.run:
        parser.print_help()
        return 0
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
