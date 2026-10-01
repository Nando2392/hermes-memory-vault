"""Real broker synthetic CI probe. Never installs, elevates, or opens live stores."""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_FRAME = 8 * 1024 * 1024
TIMEOUT = 15.0


def wait_ready(
    poll: Callable[[], int | None],
    ready: Callable[[], bool],
    ping: Callable[[], Any],
    timeout: float = TIMEOUT,
    interval: float = 0.02,
) -> None:
    """Wait for final socket permissions, then require authenticated service I/O."""
    deadline = time.monotonic() + timeout
    while True:
        require(poll() is None, "broker exited before socket readiness")
        require(time.monotonic() < deadline, "socket readiness deadline exceeded")
        if ready():
            ping()
            return
        time.sleep(interval)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_reply(value: dict[str, Any], request_id: str, ok: bool) -> dict[str, Any]:
    require(
        type(value.get("protocol")) is int and value["protocol"] == 1,
        "wrong reply protocol",
    )
    require(value.get("request_id") == request_id, "uncorrelated reply")
    require(value.get("ok") is ok, f"unexpected outcome: {value}")
    result = value.get("result" if ok else "error")
    require(isinstance(result, dict), "missing typed result/error")
    if not ok:
        require(
            isinstance(result.get("code"), str) and bool(result["code"]),
            "missing error code",
        )
    return result


def make_report(
    checks: list[str], results: dict[str, Any], status: str, error: str | None = None
) -> dict[str, Any]:
    require(len(checks) == len(set(checks)), "duplicate check labels")
    return {
        "status": status,
        "completed_checks": list(checks),
        "completed_check_count": len(checks),
        "results": results,
        "error": error,
        "full_attack_matrix": False,
        "limits": "Synthetic Linux CI only. No 36-attack matrix, same-service-UID "
        "isolation, power-loss, export/plugin, migration, deployment, "
        "Windows isolation, concurrency stress or DoS proof. SIGKILL "
        "only after acknowledged commits. Timings include CLI startup; "
        "no direct-path performance comparator.",
    }


def encode_frame(value: dict[str, Any]) -> bytes:
    payload = json.dumps(value, allow_nan=False).encode("utf-8")
    require(0 < len(payload) <= MAX_FRAME, "invalid frame length")
    return len(payload).to_bytes(4, "big") + payload


def receive_frame(channel: socket.socket, timeout: float = TIMEOUT) -> dict[str, Any]:
    deadline = time.monotonic() + timeout

    def exact(size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "frame deadline exceeded")
            channel.settimeout(remaining)
            chunk = channel.recv(size - len(data))
            require(bool(chunk), "truncated frame")
            data.extend(chunk)
        return bytes(data)

    size = int.from_bytes(exact(4), "big")
    require(0 < size <= MAX_FRAME, "invalid frame length")
    value = json.loads(exact(size).decode("utf-8"))
    require(isinstance(value, dict), "frame must be an object")
    return value


def raw_frame_outcome(channel: socket.socket, frame: bytes) -> dict[str, Any]:
    """A peer may deny before reading even the first request byte."""
    channel.settimeout(TIMEOUT)
    try:
        channel.sendall(frame)
        channel.shutdown(socket.SHUT_WR)
        reply = receive_frame(channel)
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return {"denied": "closed"}
    except RuntimeError as exc:
        require(str(exc) == "truncated frame", str(exc))
        return {"denied": "closed"}
    require(
        reply.get("ok") is False
        and isinstance(reply.get("error", {}).get("code"), str),
        "malformed frame accepted",
    )
    return {"denied": reply["error"]["code"]}


def supported(platform: str, euid: int, actions: str | None) -> bool:
    return platform == "linux" and euid == 0 and actions == "true"


def run(binary: Path) -> int:
    """Exercise only a newly created fixture; never run on Windows locally."""
    import errno
    import importlib.util
    import os
    import shutil
    import signal
    import sqlite3
    import stat
    import subprocess
    import tempfile
    from pathlib import Path

    service, client, unauthorized = 61001, 61002, 61003
    checks: list[str] = []
    results: dict[str, Any] = {}
    children: dict[int, socket.socket] = {}
    processes: list[subprocess.Popen] = []
    spec = importlib.util.spec_from_file_location(
        "identity_probe", Path(__file__).with_name("posix_identity_probe.py")
    )
    require(spec is not None and spec.loader is not None, "identity helper missing")
    identity_probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity_probe)

    def drop(uid: int) -> None:
        os.umask(0o077)
        os.setgroups([])
        os.setresgid(uid, uid, uid)
        os.setresuid(uid, uid, uid)
        require(
            os.getresuid() == (uid,) * 3
            and os.getresgid() == (uid,) * 3
            and os.getgroups() == [],
            "incomplete credential drop",
        )

    def launch(uid: int, arguments: list[str], **kwargs: Any) -> subprocess.Popen:
        process = subprocess.Popen(
            arguments,
            cwd="/",
            close_fds=True,
            preexec_fn=lambda: drop(uid),  # noqa: PLW1509 - standalone, single-threaded harness
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            **kwargs,
        )
        processes.append(process)
        return process

    def stop(process: subprocess.Popen) -> None:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)

    try:
        for ancestor in (Path("/"), Path("/tmp")):
            info = ancestor.lstat()
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and (not info.st_mode & 0o022 or bool(info.st_mode & stat.S_ISVTX)),
                "unprotected temp ancestor",
            )
        require(binary.is_file(), "--binary must name a built broker executable")
        with tempfile.TemporaryDirectory(prefix="broker-probe-", dir="/tmp") as name:
            base = Path(name)
            base.chmod(0o755)
            store, runtime = base / "store", base / "runtime"
            executable = base / "broker"
            shutil.copyfile(binary, executable)
            executable.chmod(0o755)
            require(
                executable.stat().st_uid == 0 and executable.stat().st_nlink == 1,
                "executable not root-owned private copy",
            )
            for path, mode in ((store, 0o700), (runtime, 0o755)):
                path.mkdir(mode=mode)
                os.chown(path, service, service)
                path.chmod(mode)
            endpoint = runtime / "broker.sock"
            sequence = 0

            def request(
                op: str,
                body: dict[str, Any],
                *,
                uid: int = client,
                ok: bool = True,
                server_uid: int = service,
                extra: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                nonlocal sequence
                sequence += 1
                request_id = f"probe-{sequence}"
                envelope = {
                    "protocol": 1,
                    "request_id": request_id,
                    "op": op,
                    "body": body,
                    **(extra or {}),
                }
                process = launch(
                    uid,
                    [
                        str(executable),
                        "request",
                        "--socket",
                        str(endpoint),
                        "--server-uid",
                        str(server_uid),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    output, errors = process.communicate(
                        json.dumps(envelope).encode(), timeout=TIMEOUT
                    )
                except subprocess.TimeoutExpired:
                    stop(process)
                    raise RuntimeError("request process deadline exceeded") from None
                require(len(output) <= MAX_FRAME, "CLI reply exceeded frame budget")
                if ok:
                    require(process.returncode == 0, f"CLI failed: {errors[:500]!r}")
                return validate_reply(json.loads(output), request_id, ok)

            def start() -> subprocess.Popen:
                daemon = launch(
                    service,
                    [
                        str(executable),
                        "serve",
                        "--root",
                        str(store),
                        "--socket",
                        str(endpoint),
                        "--allowed-uid",
                        str(client),
                        "--workspace",
                        "sandbox",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                def ready() -> bool:
                    try:
                        info = endpoint.lstat()
                    except FileNotFoundError:
                        return False
                    require(
                        stat.S_ISSOCK(info.st_mode) and info.st_uid == service,
                        "socket must be service-owned",
                    )
                    mode = stat.S_IMODE(info.st_mode)
                    require(mode in (0o700, 0o666), "unexpected socket permissions")
                    return mode == 0o666

                wait_ready(daemon.poll, ready, lambda: request("ping", {}))
                return daemon

            def native_state() -> dict[str, Any]:
                connection = sqlite3.connect(store / "memory.db", timeout=3)
                try:
                    require(
                        connection.execute("PRAGMA integrity_check").fetchall()
                        == [("ok",)],
                        "native integrity check failed",
                    )
                    require(
                        connection.execute("PRAGMA journal_mode").fetchone()[0]
                        == "wal",
                        "broker did not use WAL",
                    )
                    tables = ("records", "snapshot_state", "snapshot_counters")
                    rows = {
                        table: sorted(
                            connection.execute(f"SELECT * FROM {table}").fetchall()
                        )
                        for table in tables
                    }
                    events = (store / "events.jsonl").read_text()
                    projected = [json.loads(line) for line in events.splitlines()]
                    require(
                        sorted(row["id"] for row in projected)
                        == sorted(row[0] for row in rows["records"]),
                        "JSONL does not project canonical IDs",
                    )
                    return {
                        "tables": rows,
                        "jsonl": events,
                        "sqlite_version": sqlite3.sqlite_version,
                        "sqlite_source_id": connection.execute(
                            "SELECT sqlite_source_id()"
                        ).fetchone()[0],
                        "compile_options": [
                            row[0]
                            for row in connection.execute("PRAGMA compile_options")
                        ],
                        "integrity_check": "ok",
                    }
                finally:
                    connection.close()

            def state() -> dict[str, Any]:
                return identity_probe.once(service, native_state, children)

            def malformed(frame: bytes) -> dict[str, Any]:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                    channel.settimeout(TIMEOUT)
                    channel.connect(str(endpoint))
                    return raw_frame_outcome(channel, frame)

            try:
                daemon = start()
                results["ping"] = request("ping", {})
                checks.append("allowed_ping")
                record = {
                    "id": "broker-fixture-event",
                    "session_id": "fixture",
                    "workspace": "sandbox",
                    "kind": "message",
                    "content": "brokertoken persistent event",
                    "timestamp": 1.0,
                    "metadata": {},
                }
                results["ingest"] = request("ingest", {"records": [record]})
                before_duplicate = state()
                require(
                    len(before_duplicate["tables"]["records"]) == 1,
                    "allowed ingest did not persist exactly one row",
                )
                checks.append("allowed_ingest")
                results["duplicate"] = request("ingest", {"records": [record]})
                require(state() == before_duplicate, "duplicate ingest mutated state")
                checks.append("duplicate_ingest_no_mutation")
                snapshot = {
                    "session_id": "snapshot-fixture",
                    "workspace": "sandbox",
                    "items": [
                        {
                            "kind": "message",
                            "content": "brokertoken snapshot",
                            "timestamp": 2.0,
                            "metadata": {},
                        }
                    ],
                }
                results["snapshot"] = request("snapshot", snapshot)
                baseline = state()
                require(
                    len(baseline["tables"]["records"]) == 2
                    and bool(baseline["tables"]["snapshot_state"])
                    and bool(baseline["tables"]["snapshot_counters"]),
                    "snapshot did not persist records and incremental state",
                )
                request("snapshot", snapshot)
                require(state() == baseline, "duplicate snapshot mutated state")
                checks.append("snapshot_incremental_duplicate")
                query = {
                    "query": "brokertoken",
                    "workspace": "sandbox",
                    "limit": 10,
                    "max_bytes": 4096,
                }
                hits = request("search", query)["hits"]
                require(
                    sorted(hit["id"] for hit in hits)
                    == sorted(row[0] for row in baseline["tables"]["records"]),
                    "search did not return both persisted records",
                )
                checks.append("allowed_search")
                for label, op, body, uid, extra in (
                    (
                        "scope_ingest",
                        "ingest",
                        {
                            "records": [
                                {**record, "id": "forbidden", "workspace": "other"}
                            ]
                        },
                        client,
                        None,
                    ),
                    (
                        "scope_search",
                        "search",
                        {**query, "workspace": "other"},
                        client,
                        None,
                    ),
                    (
                        "scope_snapshot",
                        "snapshot",
                        {**snapshot, "workspace": "other"},
                        client,
                        None,
                    ),
                    ("unknown_field", "ping", {}, client, {"root": "/tmp/untrusted"}),
                ):
                    results[label] = request(op, body, uid=uid, ok=False, extra=extra)
                    require(
                        state() == baseline,
                        f"{label} mutated canonical/projection state",
                    )
                    checks.append(label + "_denied_unchanged")

                # Unauthorized connections may close before an envelope is read.
                def unauthorized_request() -> dict[str, Any]:
                    return malformed(
                        encode_frame(
                            {
                                "protocol": 1,
                                "request_id": "unauthorized",
                                "op": "ingest",
                                "body": {"records": [{**record, "id": "unauthorized"}]},
                            }
                        )
                    )

                results["unauthorized"] = identity_probe.once(
                    unauthorized, unauthorized_request, children
                )
                require(state() == baseline, "unauthorized request mutated state")
                checks.append("unauthorized_peer_denied_unchanged")

                # A root-owned fake listener records that the real CLI sends no
                # request bytes when its expected server UID is wrong.
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as impostor:
                    fake = base / "wrong-server.sock"
                    impostor.bind(str(fake))
                    # Pass pathname ownership validation, but retain the root
                    # listener so SO_PEERCRED must reject before sending bytes.
                    os.chown(fake, service, service)
                    fake.chmod(0o666)
                    impostor.listen(1)
                    impostor.settimeout(TIMEOUT)
                    process = launch(
                        client,
                        [
                            str(executable),
                            "request",
                            "--socket",
                            str(fake),
                            "--server-uid",
                            str(service),
                        ],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    process.stdin.write(
                        json.dumps(
                            {
                                "protocol": 1,
                                "request_id": "secret",
                                "op": "ingest",
                                "body": {"records": [record]},
                            }
                        ).encode()
                    )
                    process.stdin.close()
                    process.stdin = None
                    channel, _ = impostor.accept()
                    with channel:
                        channel.settimeout(TIMEOUT)
                        require(
                            channel.recv(1) == b"",
                            "CLI leaked request before peer authentication",
                        )
                    process.communicate(timeout=TIMEOUT)
                    require(process.returncode != 0, "CLI accepted wrong server UID")
                require(state() == baseline, "wrong-server probe mutated store")
                checks.append("server_uid_mismatch_before_send")

                for label, frame in (
                    ("invalid_json", b"\x00\x00\x00\x01{"),
                    ("oversized", (MAX_FRAME + 1).to_bytes(4, "big")),
                    ("truncated", b"\x00\x00\x00\x10{}"),
                ):
                    results[label] = identity_probe.once(
                        client, lambda f=frame: malformed(f), children
                    )
                    request("ping", {})
                    require(state() == baseline, f"{label} mutated state")
                    checks.append(label + "_bounded_recovery_unchanged")

                def direct_denied() -> dict[str, Any]:
                    denied = []
                    for filename in (
                        "memory.db",
                        "memory.db-wal",
                        "memory.db-shm",
                        "memory.db-journal",
                    ):
                        for flags in (os.O_RDONLY, os.O_WRONLY):
                            try:
                                fd = os.open(store / filename, flags)
                            except OSError as exc:
                                require(
                                    exc.errno in (errno.EACCES, errno.EPERM),
                                    "direct denial was not DAC",
                                )
                                denied.append([filename, flags, exc.errno])
                            else:
                                os.close(fd)
                                raise RuntimeError("client obtained direct DB handle")
                    require(len(denied) == 8, "incomplete direct-access checks")
                    return {"attempts": denied, "denied_count": len(denied)}

                results["direct_access"] = identity_probe.once(
                    client, direct_denied, children
                )
                checks.append("eight_direct_open_denials")
                stale = endpoint.lstat()
                stop(daemon)
                require(daemon.returncode == -signal.SIGKILL, "service not SIGKILLed")
                current = endpoint.lstat()
                require(
                    endpoint.parent == runtime
                    and runtime.parent == base
                    and base.parent == Path("/tmp")
                    and base.name.startswith("broker-probe-")
                    and base.lstat().st_uid == 0
                    and not base.lstat().st_mode & 0o022
                    and runtime.lstat().st_uid == service
                    and not runtime.lstat().st_mode & 0o022
                    and stat.S_ISSOCK(current.st_mode)
                    and current.st_uid == service
                    and (current.st_dev, current.st_ino)
                    == (stale.st_dev, stale.st_ino),
                    "refuse unsafe stale-socket removal",
                )
                endpoint.unlink()  # Only our stopped instance inside this fresh fixture.
                daemon = start()
                require(
                    state() == baseline,
                    "SIGKILL restart lost rows, snapshot state or JSONL",
                )
                require(
                    sorted(hit["id"] for hit in request("search", query)["hits"])
                    == sorted(hit["id"] for hit in hits),
                    "restart lost FTS results",
                )
                results["trusted_native_sqlite"] = {
                    key: baseline[key]
                    for key in (
                        "sqlite_version",
                        "sqlite_source_id",
                        "compile_options",
                        "integrity_check",
                        "identity",
                    )
                }
                checks.append("sigkill_restart_persistence_native_integrity")
                samples: dict[str, list[float]] = {"ping": [], "search": []}
                for op, body in (("ping", {}), ("search", query)):
                    for _ in range(5):
                        started = time.monotonic_ns()
                        result = request(op, body)
                        if op == "search":
                            require(
                                sorted(hit["id"] for hit in result["hits"])
                                == sorted(hit["id"] for hit in hits),
                                "benchmark search mismatch",
                            )
                        samples[op].append((time.monotonic_ns() - started) / 1_000_000)
                results["benchmark"] = {
                    "clock": "monotonic_ns",
                    "unit": "ms",
                    "samples": samples,
                    "includes": "CLI process startup + IPC + operation",
                    "baseline_comparator": None,
                }
                checks.append("five_successful_ping_and_search_samples_each")
                require(state() == baseline, "read-only benchmark mutated state")
            finally:
                # Never use pkill/killpg: only handles/PIDs created and tracked here.
                cleanup_errors = []
                for process in processes:
                    try:
                        stop(process)
                    except (OSError, subprocess.SubprocessError) as exc:
                        cleanup_errors.append(repr(exc))
                for pid in list(children):
                    try:
                        identity_probe.reap(pid, children, kill=True)
                    except (OSError, RuntimeError) as exc:
                        cleanup_errors.append(repr(exc))
                require(not cleanup_errors, f"cleanup failed: {cleanup_errors}")
        report = make_report(checks, results, "real_broker_checks_passed")
        code = 0
    except (
        OSError,
        RuntimeError,
        ValueError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as exc:
        report = make_report(checks, results, "failed", repr(exc))
        code = 1
    print(json.dumps(report, indent=2))
    return code


def main() -> int:
    import argparse
    import os
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", type=Path, help="built broker copied into protected fixture"
    )
    parser.add_argument(
        "--run", action="store_true", help="run only in parent-controlled Linux root CI"
    )
    arguments = parser.parse_args()
    if not arguments.run:
        parser.print_help()
        return 0
    if not supported(
        sys.platform,
        os.geteuid() if hasattr(os, "geteuid") else -1,
        os.environ.get("GITHUB_ACTIONS"),
    ):
        print(
            json.dumps(
                {
                    "status": "unsupported",
                    "reason": "requires Linux root and GITHUB_ACTIONS=true",
                }
            )
        )
        return 77
    if arguments.binary is None:
        parser.error("--run requires --binary")
    return run(arguments.binary.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
