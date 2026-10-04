"""Bounded allowlisted evidence helper; no process/native operations.

Only disposable synthetic controller output is eligible. Never collect environment,
fixtures, binaries, profiles, or arbitrary caller-selected paths.
"""

from __future__ import annotations

import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
CAP = 65536
FILES = {
    "controller.log": ("drain-native-controller.log", CAP),
    "controller-status.json": ("drain-native-controller-status.json", 8192),
    "result.json": ("target/drain-native-evidence/result.json", CAP),
}


def write_json_evidence(path: Path, value: dict, cap: int) -> list[str]:
    """Finalize bounded evidence without letting secondary IO replace primary status."""
    errors = []
    try:
        payload = json.dumps(value, indent=2)
        if len(payload.encode("utf-8")) > cap:
            raise ValueError("evidence cap")
    except BaseException:
        return ["serialization"]
    try:
        stream = path.open("x", encoding="utf-8")
    except BaseException:
        return ["open"]
    try:
        try:
            if stream.write(payload) != len(payload):
                raise OSError("short evidence write")
        except BaseException:
            errors.append("write")
        try:
            stream.flush()
        except BaseException:
            errors.append("flush")
    finally:
        try:
            stream.close()
        except BaseException:
            errors.append("close")
    return errors


def report_evidence_failure(
    kind: str, state: str, primary: int | None, errors: list[str]
) -> None:
    """Fixed allowlisted fallback survives failed serialization; never emit exception text."""
    import sys

    kind = kind if kind in ("controller", "native_result") else "controller"
    state = state if state in ("exited", "timeout", "error") else "error"
    code = (
        str(primary) if type(primary) is int and -(2**31) <= primary < 2**32 else "null"
    )
    allowed = (
        "serialization",
        "open",
        "write",
        "flush",
        "close",
        "log_flush",
        "log_close",
    )
    labels = [label for label in allowed if label in errors]
    payload = (
        '{"schema_version":1,"kind":"'
        + kind
        + '","primary_state":"'
        + state
        + '","primary_exit_code":'
        + code
        + ',"evidence_errors":['
        + ",".join('"' + label + '"' for label in labels)
        + "]}\n"
    )
    try:
        sys.stderr.write(payload)
        sys.stderr.flush()
    except BaseException:
        pass  # No recursive fallback; original primary exit still returns.


def check_info(info, cap):
    if (
        not stat.S_ISREG(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 1024
        or info.st_nlink != 1
        or not 0 <= info.st_size <= cap
    ):
        raise ValueError("nonregular/reparse/multilink/oversize evidence")


def read_regular(path, cap):
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024:
            raise ValueError("reparse evidence path")
    check_info(path.lstat(), cap)
    with path.open("rb") as stream:
        check_info(os.fstat(stream.fileno()), cap)
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError("oversize evidence")
    return raw


def object_keys(value, required, optional=()):
    if (
        not isinstance(value, dict)
        or not set(required) <= value.keys()
        or set(value) - set(required) - set(optional)
    ):
        raise ValueError("unexpected evidence schema")


def text(value, cap=1024):
    if (
        not isinstance(value, str)
        or len(value) > cap
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("invalid evidence text")


def sha(value, width=64):
    if not isinstance(value, str) or not re.fullmatch(
        "[0-9a-f]{" + str(width) + "}", value
    ):
        raise ValueError("invalid evidence digest")


def integer(value):
    if type(value) is not int:
        raise ValueError("invalid evidence integer")


def boolean(value):
    if type(value) is not bool:
        raise ValueError("invalid evidence boolean")


def validate_status(value):
    object_keys(
        value,
        (
            "schema_version",
            "state",
            "exit_code",
            "deadline_seconds",
            "kill_wait_complete",
            "python_path",
            "python_version",
            "rustc_path",
            "rustc_version",
            "source_path",
            "workflow_path",
        ),
        ("evidence_errors",),
    )
    if (
        value["schema_version"] != 1
        or value["state"] not in ("exited", "timeout", "error")
        or value["deadline_seconds"] != 180
    ):
        raise ValueError("invalid controller state")
    if value["exit_code"] is not None:
        integer(value["exit_code"])
    boolean(value["kill_wait_complete"])
    if "evidence_errors" in value:
        errors = value["evidence_errors"]
        if (
            not isinstance(errors, list)
            or len(errors) > 7
            or any(
                e
                not in (
                    "serialization",
                    "open",
                    "write",
                    "flush",
                    "close",
                    "log_flush",
                    "log_close",
                )
                for e in errors
            )
        ):
            raise ValueError("invalid secondary evidence failures")
    for name in ("python_path", "rustc_path", "source_path", "workflow_path"):
        text(value[name])
        if not Path(value[name]).is_absolute():
            raise ValueError("expected selected absolute path")
    for name in ("python_version", "rustc_version"):
        text(value[name], 1024)


def image(value):
    object_keys(value, ("path", "identity", "sha256", "size"))
    text(value["path"])
    if not Path(value["path"]).is_absolute():
        raise ValueError("image path not absolute")
    if not isinstance(value["identity"], list) or len(value["identity"]) != 2:
        raise ValueError("invalid image identity")
    for item in value["identity"]:
        integer(item)
    integer(value["size"])
    if not 0 <= value["size"] <= 2097152:
        raise ValueError("image cap")
    sha(value["sha256"])


def ordinary_windows_path(value: str) -> str:
    """Check the primitive's local lexical contract without lookup or repair."""
    text(value)
    # Inspect raw components before PureWindowsPath can discard dot components.
    spelling = value.replace("/", "\\")
    if not re.match(r"^[A-Za-z]:\\", spelling):
        raise ValueError("ordinary local drive path required")
    components = spelling[3:].split("\\")
    if any(
        not part
        or part in (".", "..")
        or part.endswith((" ", "."))
        or any(c in part for c in ':<>"|?*')
        or PureWindowsPath(part).is_reserved()
        for part in components
    ):
        raise ValueError("unsupported Windows path spelling")
    return ntpath.normcase(value)


def validate_success_receipt(receipt: dict) -> None:
    """Require coherent renamed/copied image witnesses, not just success flags."""
    paths = receipt["paths"]
    if len({ordinary_windows_path(p) for p in paths.values()}) != 4:
        raise ValueError("receipt paths must be distinct")
    before, after, staged = receipt["before"], receipt["after"], receipt["staged"]
    if (
        any(before[n] is None for n in ("source", "active"))
        or any(after[n] is None for n in ("source", "active", "backup"))
        or staged is None
        or after["candidate"] is not None
        or receipt["errors"]
        or receipt["winerror"] is not None
    ):
        raise ValueError("missing/failed successful receipt witness")
    witnesses = [
        before["source"],
        before["active"],
        staged,
        *(after[name] for name in ("source", "active", "backup")),
    ]
    # Producer puts every image in one fresh nonreparse fixture directory.
    if len({observed["identity"][0] for observed in witnesses}) != 1:
        raise ValueError("native fixture volume contradiction")
    for observed in witnesses:
        ordinary_windows_path(observed["path"])
        # NativeLifecycle MAX_EXE_BYTES, not the primitive's larger generic cap.
        if not 0 < observed["size"] <= 2 * 1024 * 1024:
            raise ValueError("native executable size")
        # CPython 3.11+ Windows fstat: unsigned volume serial (up to 64 bits),
        # file index (64 bits on 3.11; FILE_ID_128 on 3.12+).
        if not (
            0 <= observed["identity"][0] < 2**64
            and 0 <= observed["identity"][1] < 2**128
        ):
            raise ValueError("native Windows identity range")
    for phase in (before, after):
        for name, observed in phase.items():
            if observed is not None and observed["path"] != paths[name]:
                raise ValueError("image/receipt path contradiction")
    if staged["path"] != paths["candidate"]:
        raise ValueError("staged path contradiction")
    if (
        before["source"]["sha256"] == before["active"]["sha256"]
        or len(
            {tuple(i["identity"]) for i in (before["source"], before["active"], staged)}
        )
        != 3
    ):
        raise ValueError("old/source/staged images must be distinct")
    for observed, expected in (
        (after["backup"], before["active"]),
        (after["active"], staged),
        (after["source"], before["source"]),
    ):
        if any(observed[k] != expected[k] for k in ("identity", "sha256", "size")):
            raise ValueError("renamed/preserved image contradiction")
    if any(staged[k] != before["source"][k] for k in ("sha256", "size")):
        raise ValueError("staged source contradiction")


def validate_result(value):
    optional = (
        "owned_fixture_removed",
        "children",
        "cleanup_errors",
        "receipt",
        "sharing_timeouts",
        "mismatch_cleanup_exclusive_reopen",
        "lease_delayed_close",
        "postrelease_open",
        "fresh_epoch_real_reacquisition",
        "authentication_established",
        "activation_approved",
    )
    object_keys(value, ("provenance", "tests_run", "pass"), optional)
    boolean(value["pass"])
    integer(value["tests_run"])
    if value["tests_run"] != 1:
        raise ValueError("unexpected native test count")
    provenance = value["provenance"]
    object_keys(
        provenance,
        ("commit", "inventory_sha256", "workflow_sha256", "authentication_established"),
    )
    sha(provenance["commit"], 40)
    sha(provenance["inventory_sha256"])
    sha(provenance["workflow_sha256"])
    if provenance["authentication_established"] is not False:
        raise ValueError("no native authentication claim allowed")
    for name in optional:
        if name in value and name not in (
            "children",
            "cleanup_errors",
            "receipt",
            "sharing_timeouts",
        ):
            boolean(value[name])
    for name in ("authentication_established", "activation_approved"):
        if value.get(name, False) is not False:
            raise ValueError("no activation/authentication claim allowed")
    if "children" in value:
        if not isinstance(value["children"], list) or len(value["children"]) > 3:
            raise ValueError("child cap")
        for child in value["children"]:
            object_keys(child, ("pid_observation_only", "exit_code", "forced"))
            integer(child["pid_observation_only"])
            integer(child["exit_code"])
            boolean(child["forced"])
    if "cleanup_errors" in value:
        if (
            not isinstance(value["cleanup_errors"], list)
            or len(value["cleanup_errors"]) > 8
        ):
            raise ValueError("cleanup error cap")
        for error in value["cleanup_errors"]:
            text(error)
    if "sharing_timeouts" in value:
        if (
            not isinstance(value["sharing_timeouts"], list)
            or len(value["sharing_timeouts"]) > 2
        ):
            raise ValueError("sharing evidence cap")
        for record in value["sharing_timeouts"]:
            object_keys(record, ("old_children", "before"), ("after", "winerror"))
            integer(record["old_children"])
            if record["old_children"] not in (1, 2):
                raise ValueError("unexpected old count")
            if "winerror" in record:
                integer(record["winerror"])
            for phase in ("before", "after"):
                if phase in record:
                    codes = record[phase]
                    if (
                        not isinstance(codes, list)
                        or len(codes) != record["old_children"]
                    ):
                        raise ValueError("liveness cardinality")
                    for code in codes:
                        if code is not None:
                            integer(code)
    if "receipt" in value:
        receipt = value["receipt"]
        object_keys(
            receipt,
            (
                "success",
                "state",
                "paths",
                "before",
                "staged",
                "after",
                "errors",
                "winerror",
            ),
        )
        boolean(receipt["success"])
        if receipt["state"] not in ("replaced", "unchanged", "partial", "unknown"):
            raise ValueError("receipt state")
        object_keys(receipt["paths"], ("source", "active", "candidate", "backup"))
        for path in receipt["paths"].values():
            text(path)
            if not Path(path).is_absolute():
                raise ValueError("receipt path")
        for phase in ("before", "after"):
            object_keys(
                receipt[phase],
                ("source", "active")
                if phase == "before"
                else ("source", "active", "candidate", "backup"),
            )
            for item in receipt[phase].values():
                if item is not None:
                    image(item)
        if receipt["staged"] is not None:
            image(receipt["staged"])
        if not isinstance(receipt["errors"], dict) or len(receipt["errors"]) > 8:
            raise ValueError("receipt error cap")
        for key, error in receipt["errors"].items():
            if key not in (
                "staging",
                "replace",
                "inspect:source",
                "inspect:active",
                "inspect:candidate",
                "inspect:backup",
            ):
                raise ValueError("receipt error key")
            text(error)
        if receipt["winerror"] is not None:
            integer(receipt["winerror"])
    if value["pass"]:
        if not set(optional) <= value.keys():
            raise ValueError("incomplete successful proof")
        if (
            value["cleanup_errors"]
            or not value["owned_fixture_removed"]
            or len(value["children"]) != 3
            or any(c["exit_code"] != 0 or c["forced"] for c in value["children"])
            or not value["receipt"]["success"]
            or value["receipt"]["state"] != "replaced"
            or len(value["sharing_timeouts"]) != 2
        ):
            raise ValueError("cleanup/lifecycle not proven")
        validate_success_receipt(value["receipt"])
        # PROCESS_INFORMATION.dwProcessId is a DWORD, never a signed PID policy.
        if any(not 0 < c["pid_observation_only"] < 2**32 for c in value["children"]):
            raise ValueError("native Windows process ID range")
        if len({c["pid_observation_only"] for c in value["children"]}) != 3:
            raise ValueError("distinct owned child observations required")
        for record, count in zip(value["sharing_timeouts"], (2, 1)):
            if record != {
                "old_children": count,
                "before": [None] * count,
                "after": [None] * count,
                "winerror": 32,
            }:
                raise ValueError("old child liveness not proven")
        for name in (
            "mismatch_cleanup_exclusive_reopen",
            "lease_delayed_close",
            "postrelease_open",
            "fresh_epoch_real_reacquisition",
        ):
            if value[name] is not True:
                raise ValueError("incomplete lifecycle proof")


def proof_pass(status, result):
    return bool(
        status
        and result
        and status["state"] == "exited"
        and status["exit_code"] == 0
        and status.get("kill_wait_complete") is True
        and not status.get("evidence_errors")
        and result.get("pass") is True
    )


def collect(root=ROOT, controller_outcome: str | None = None):
    # Fixed output directory, fresh per disposable checkout. Only validated copies upload.
    output = root / "target/drain-native-collected"
    # The child may fail during admission before creating target/evidence. Create
    # only this validated cooperative parent, never an arbitrary caller directory.
    for parent in (root, output.parent):
        if parent == output.parent:
            parent.mkdir(exist_ok=True)
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 1024
        ):
            raise ValueError("unsafe collector directory")
    output.mkdir(exist_ok=False)
    # A status close/flush may fail after valid bytes reach disk. Bind classification
    # to the independently observed workflow controller outcome as well as witnesses.
    if controller_outcome is None:
        controller_outcome = os.environ.get("CONTROLLER_OUTCOME", "missing")
    if controller_outcome not in ("success", "failure", "cancelled", "skipped"):
        controller_outcome = "missing"
    status = result = None
    accepted, refused = [], []
    for name, (relative, cap) in FILES.items():
        try:
            raw = read_regular(root / relative, cap)
            if name == "controller-status.json":
                parsed = json.loads(raw)
                validate_status(parsed)
                status = parsed
            elif name == "result.json":
                parsed = json.loads(raw)
                validate_result(parsed)
                result = parsed
            else:
                raw.decode("utf-8")
        except (OSError, ValueError, UnicodeError):
            refused.append(name)  # Names only, never exception/env/private data.
            continue
        # Output IO is not an input refusal: partial/failed copies cannot be uploaded.
        # Propagate before any fresh marker, even when other evidence was accepted.
        with (output / name).open("xb") as stream:
            if stream.write(raw) != len(raw):
                raise OSError("short collected evidence write")
            stream.flush()
        accepted.append(name)
    summary = {
        "schema_version": 1,
        "accepted": accepted,
        "refused": refused,
        "primary_state": status["state"] if status else "missing_or_invalid",
        "primary_exit_code": status["exit_code"] if status else None,
        "controller_outcome": controller_outcome,
        "proof_pass": controller_outcome == "success"
        and not refused
        and proof_pass(status, result),
    }
    if write_json_evidence(output / "collection.json", summary, 8192):
        raise ValueError("collector summary finalization failed")
    # GitHub step output is set only by this fresh collector after all writes close.
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
            stream.write("fresh=true\n")
    return 0 if summary["proof_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(collect())
