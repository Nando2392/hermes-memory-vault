"""Prospective Windows ordinary gates; never dispatches or installs into a real profile."""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import tomllib

from scripts import ci_test_shards as custody

HOST = "53fefae5d74312a534063e1b1ef932c0cf98e1e9"
PARENT = "9192b4c03bec9c41378f1e28fab82ddff6a5d28d"
MODULES = {
    "test_broker_sandbox_probe.py": 15,
    "test_build_release.py": 3,
    "test_installer.py": 19,
    "test_sqlite_concurrency.py": 3,
    "test_vault_provider.py": 25,
    "test_windows_broker_full8_validator.py": 25,
}
META = 4 * 1024 * 1024
MEMBER = 512 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def bounded(path, cap=META):
    custody.no_reparse(path)
    require(path.is_file() and path.stat().st_size <= cap, "Regular bounded input required")
    with path.open("rb") as stream:
        value = stream.read(cap + 1)
    require(len(value) <= cap, "Input grew beyond cap")
    return value


def pin(path, cap=MEMBER):
    custody.no_reparse(path)
    size = path.stat().st_size
    require(path.is_file() and 0 < size <= cap, "Bounded regular member required")
    total = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            require(total <= cap, "Member grew beyond cap")
            digest.update(chunk)
    require(total == size == path.stat().st_size, "Member size changed")
    return {"bytes": size, "sha256": digest.hexdigest()}


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(raw) <= META, "Metadata cap")
    with path.open("xb") as stream:
        stream.write(raw)


def execute_input(argv, output, name, seconds, input_path):
    """Retained direct child with a bounded file as stdin and bounded concurrent drains."""
    capture = {"stdout": bytearray(), "stderr": bytearray()}
    errors = []
    lock = threading.Lock()
    started = time.monotonic()
    with input_path.open("rb") as source:
        child = subprocess.Popen(argv, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def drain(stream_name):
        try:
            while chunk := getattr(child, stream_name).read1(16384):
                with lock:
                    remaining = custody.LOG - len(capture[stream_name])
                    capture[stream_name].extend(chunk[:remaining])
                    if len(chunk) > remaining and len(errors) < 16:
                        errors.append("capture overflow")
        except Exception as error:
            with lock:
                if len(errors) < 16:
                    errors.append(str(error)[:1024])

    threads = [threading.Thread(target=drain, args=(key,), daemon=True) for key in capture]
    for thread in threads:
        thread.start()
    timed_out = False
    while child.poll() is None:
        with lock:
            capture_error = bool(errors)
        if time.monotonic() - started >= seconds or capture_error:
            timed_out = time.monotonic() - started >= seconds
            try:
                child.kill()
            except OSError as error:
                with lock:
                    if len(errors) < 16:
                        errors.append("owned kill failed: " + str(error)[:1024])
            break
        time.sleep(0.02)
    end = time.monotonic() + 5
    settled = False
    try:
        child.wait(timeout=max(0, end - time.monotonic()))
        settled = True
    except subprocess.TimeoutExpired:
        with lock:
            if len(errors) < 16:
                errors.append("retained child did not settle")
    for thread in threads:
        thread.join(max(0, end - time.monotonic()))
    capture_complete = not any(thread.is_alive() for thread in threads)
    with lock:
        snapshots = {key: bytes(value) for key, value in capture.items()}
        saved_errors = list(errors[:16])
    for key, raw in snapshots.items():
        with (output / (name + "." + key)).open("xb") as stream:
            stream.write(raw)
    receipt = {"argv": argv, "pid": child.pid, "exit_code": child.returncode if settled else None,
               "timeout_limit_seconds": seconds, "timed_out": timed_out, "settled": settled,
               "capture_complete": capture_complete, "errors": saved_errors,
               "elapsed_seconds": time.monotonic() - started, "stdin": pin(input_path, META)}
    return receipt, snapshots["stdout"], snapshots["stderr"]


def command(argv, output, name, seconds, input_path=None):
    receipt, stdout, stderr = (custody.execute(argv, output, name, seconds) if input_path is None
                              else execute_input(argv, output, name, seconds, input_path))
    receipt["stdout"] = pin(output / (name + ".stdout"), cap=custody.LOG) if stdout else {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    receipt["stderr"] = pin(output / (name + ".stderr"), cap=custody.LOG) if stderr else {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    save(output / (name + ".json"), receipt)
    require(custody.success(receipt), "Command incomplete or failed: " + name)
    return receipt, stdout


def current_binding():
    require(os.name == "nt" and os.environ.get("RUNNER_OS") == "Windows", "Windows only")
    require(sys.version_info[:2] == (3, 11), "Reviewed Python 3.11 required")
    value = custody.binding("featureless")
    value["ordinary_helper_sha256"] = pin(Path(__file__), META)["sha256"]
    value["python_executable"] = sys.executable
    value["python_version"] = sys.version
    value["runner_temp"] = str(Path(os.environ["RUNNER_TEMP"]).absolute())
    require(not subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], timeout=15).returncode,
            "Tracked checkout differs from commit")
    cargo = tomllib.loads(bounded(Path("Cargo.toml")).decode())
    require(not cargo.get("features", {}).get("default"), "Default features changed")
    value["version"] = cargo["package"]["version"]
    extra_paths = [Path(name) for name in ("README.md", "LICENSE", "install-memory-vault.py")]
    for directory in ("plugin", "installer", "ci_evidence"):
        extra_paths.extend(path for path in Path(directory).rglob("*") if path.is_file()
                           and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"))
    value["package_and_reuse_inputs"] = [{"path": path.as_posix(), **pin(path, META)} for path in sorted(extra_paths)]
    value["package_and_reuse_inputs_sha256"] = custody.digest(value["package_and_reuse_inputs"])
    require(not os.environ.get("CARGO_TARGET_DIR"), "External target directory override")
    return value


def compatible(producer, current):
    fields = ("commit", "run_id", "run_attempt", "source_inventory_sha256", "os",
              "configuration", "ordinary_helper_sha256", "version", "package_and_reuse_inputs_sha256", "image_os")
    require(all(producer.get(key) == current.get(key) for key in fields), "Foreign or stale producer binding")


def restore(capsule, profile, current, target):
    value = json.loads(bounded(capsule / "capsule.json"))
    require(value.get("schema") == 1 and value.get("status") == "BUILT" and value.get("profile") == profile,
            "Wrong or incomplete capsule")
    compatible(value["binding"], current)
    member = capsule / "runtime" / "hermes-memory.exe"
    require(member.stat().st_nlink == 1, "Transport member alias")
    require(pin(member) == value["binary"], "Transport member drift")
    require(not target.exists(), "Restore destination must be new")
    target.parent.mkdir(parents=True, exist_ok=True)
    with member.open("rb") as source, target.open("xb") as dest:
        shutil.copyfileobj(source, dest, 1024 * 1024)
    require(target.stat().st_nlink == 1 and pin(target) == value["binary"], "Restored member drift")
    return value


def build(profile, output, binding):
    target = Path.cwd() / "target" / profile / "hermes-memory.exe"
    require(not target.exists(), "Build requires a fresh target")
    argv = ["cargo", "build", "--locked", "--bin", "hermes-memory", "--message-format=json-render-diagnostics"]
    if profile == "release":
        argv.append("--release")
    receipt, raw = command(argv, output, "cargo-build", 600)
    artifacts = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "hermes-memory" and item.get("target", {}).get("kind") == ["bin"]:
            artifacts.append(item)
    require(len(artifacts) == 1, "Missing or ambiguous ordinary compiler artifact")
    item = artifacts[0]
    require(item.get("features") == [] and item.get("profile", {}).get("test") is False,
            "Nondefault or test build")
    require(Path(item["executable"]).absolute() == target and item["target"]["src_path"] == str(Path.cwd() / "src" / "main.rs"),
            "Wrong binary identity")
    require(item["profile"]["opt_level"] == ("3" if profile == "release" else "0"), "Wrong compiler profile")
    binary = pin(target)
    staged = output / "runtime" / "hermes-memory.exe"
    staged.parent.mkdir()
    with target.open("rb") as source, staged.open("xb") as dest:
        shutil.copyfileobj(source, dest, 1024 * 1024)
    require(staged.stat().st_nlink == 1 and pin(staged) == binary, "Build staging drift")
    _, version = command([str(staged), "--version"], output, "version", 30)
    require(version.decode().strip() == "hermes-memory " + binding["version"], "Actual version mismatch")
    require(pin(target) == binary and pin(staged) == binary, "Build binary changed during version probe")
    compatible(binding, current_binding())
    return {"schema": 1, "status": "BUILT", "profile": profile, "binding": binding,
            "binary": binary, "compiler_artifact": item, "build_command": receipt, "staged_binary_path": str(staged)}


def bases():
    result = set()
    for filename, count in MODULES.items():
        module = ast.parse(bounded(Path("python_tests") / filename).decode())
        names = []
        for node in module.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                names.append(node.name)
            if isinstance(node, ast.ClassDef):
                names.extend(node.name + "::" + child.name for child in node.body
                             if isinstance(child, ast.FunctionDef) and child.name.startswith("test_"))
        require(len(names) == count, "Reviewed Python base inventory changed: " + filename)
        result.update("python_tests/" + filename + "::" + name for name in names)
    require(len(result) == 90, "Reviewed base inventory is not 90")
    return result


def validate_pytest(value, expected):
    collected = value.get("collected", [])
    require(collected and len(collected) == len(set(collected)), "Missing or duplicate collected nodeid")
    require({node.split("[", 1)[0] for node in collected} == set(expected), "Collected base inventory differs")
    require(value.get("deselected") == [] and value.get("collection_errors") == []
            and type(value.get("exitstatus")) is int and value["exitstatus"] == 0,
            "Deselected, collection failure or nonzero pytest terminal")
    reports = value.get("reports", [])
    require(len(reports) == 3 * len(collected), "Missing lifecycle reports")
    for node in collected:
        actual = [record for record in reports if record["nodeid"] == node]
        require(len(actual) == 3 and {record["when"] for record in actual} == {"setup", "call", "teardown"}
                and all(record["outcome"] == "passed" and not record["wasxfail"] for record in actual),
                "Skipped, failed, xfail or incomplete nodeid")
    return sorted(collected)


_pytest_record = {"collected": [], "deselected": [], "collection_errors": [], "reports": []}


def pytest_collection_modifyitems(items):
    _pytest_record["collected"] = [item.nodeid for item in items]


def pytest_deselected(items):
    _pytest_record["deselected"].extend(item.nodeid for item in items)


def pytest_collectreport(report):
    if report.failed:
        _pytest_record["collection_errors"].append(report.nodeid)


def pytest_runtest_logreport(report):
    _pytest_record["reports"].append({"nodeid": report.nodeid, "when": report.when,
                                      "outcome": report.outcome, "wasxfail": bool(getattr(report, "wasxfail", False))})
    require(len(_pytest_record["reports"]) <= 12000, "Pytest report cap")


def pytest_sessionfinish(exitstatus):
    _pytest_record["exitstatus"] = int(exitstatus)
    save(Path(os.environ["ORDINARY_PYTEST_REPORT"]), _pytest_record)


def reuse_controls_value():
    root = Path("ci_evidence/windows-helper-reuse")
    admission = json.loads(bounded(root / "homologation.json"))
    require(admission.get("schema") == 1 and admission.get("scope") == "Windows-local-13-reviewed-controls"
            and admission.get("tests_reexecuted") is False, "Missing explicit reuse admission")
    for name, expected in admission["receipt_sha256"].items():
        require(Path(name).name == name and pin(root / name, META)["sha256"] == expected, "Reuse receipt drift")
    for filename, count in (("helper-controls-01.json", 7), ("helper-controls-02.json", 2), ("helper-controls-03.json", 1)):
        actual = json.loads(bounded(root / filename))
        require(type(actual.get("actual_exit_code")) is int and actual["actual_exit_code"] == 0
                and actual.get("tests_run") == count, "Retained controls failed or incomplete")
    latest = json.loads(bounded(root / "new-controls-01.json"))
    require(type(latest.get("exit")) is int and latest["exit"] == 0
            and latest["pins"] == latest["pins_after"], "D5 new controls failed or source drift")
    for name, expected in admission["current_source_sha256"].items():
        require(name in ("scripts/ci_test_shards.py", "python_tests/test_ci_test_shards.py") and pin(Path(name), META)["sha256"] == expected,
                "Homologated source changed")
    require(len(admission["base_nodeids"]) == len(set(admission["base_nodeids"])) == 13,
            "Incomplete reuse base inventory")
    return admission


def reuse_controls(output):
    admission = reuse_controls_value()
    save(output / "reused-controls.json", admission)
    return admission


def python_gate(capsule, host, output, binding):
    require(host.resolve().is_relative_to(Path.cwd()), "Host checkout must be isolated in workspace")
    actual = subprocess.check_output(["git", "-C", str(host), "rev-parse", "HEAD"], text=True, timeout=15).strip()
    require(actual == HOST, "Hermes host commit mismatch")
    require(not subprocess.run(["git", "-C", str(host), "diff", "--quiet", "HEAD", "--"], timeout=15).returncode,
            "Hermes host tracked drift")
    target = Path.cwd() / "target" / "debug" / "hermes-memory.exe"
    prior = restore(capsule, "debug", binding, target)
    reused = reuse_controls(output)
    expected = bases()
    versions = {name: importlib.metadata.version(name) for name in ("pytest", "PyYAML", "ruamel.yaml")}
    require(versions == {"pytest": "8.4.2", "PyYAML": "6.0.2", "ruamel.yaml": "0.18.17"}, "Python dependency versions changed")
    command([sys.executable, "-m", "pip", "freeze"], output, "python-dependencies", 30)
    own_home = output / "disposable-python-hermes-home"
    own_home.mkdir()
    os.environ["HERMES_HOME"] = str(own_home)
    os.environ["PYTHONPATH"] = str(host.resolve()) + os.pathsep + str(Path.cwd())
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ["ORDINARY_PYTEST_REPORT"] = str(output / "pytest-report.json")
    require(not os.environ.get("HERMES_MEMORY_BIN"), "Inherited authoritative binary override")
    argv = [sys.executable, "-B", "-m", "pytest", "-p", "scripts.ci_windows_ordinary", "-q", "--strict-markers",
            "--basetemp", str(output / "pytest-temp"), *["python_tests/" + name for name in MODULES]]
    receipt, _ = command(argv, output, "pytest", 600)
    passed = validate_pytest(json.loads(bounded(output / "pytest-report.json")), expected)
    require(pin(target) == prior["binary"], "Debug binary changed during tests")
    compatible(binding, current_binding())
    return {"schema": 1, "status": "PYTHON_PASS", "binding": binding, "host_commit": HOST,
            "debug_capsule_sha256": pin(capsule / "capsule.json", META)["sha256"],
            "dependency_versions": versions, "hermes_home": str(own_home),
            "pending_base_nodeids": sorted(expected), "passed_full_nodeids": passed,
            "pytest_command": receipt, "reused_controls_sha256": custody.digest(reused)}


def package_child(output, reviewed_digest, binding):
    from installer.hermes_memory_vault_installer import install_bundle
    from scripts.build_release import build_release

    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True, timeout=15).strip()
    assets = build_release(repo=Path.cwd(), dist=output / "dist", version="v" + binding["version"],
                           platform="windows-x86_64", git_commit=binding["commit"], git_tree=tree,
                           reviewed_digest=reviewed_digest)
    home = output / "disposable-hermes-home"
    home.mkdir()
    sentinels = {"config.yaml": b"memory:\n  provider: preserved-ordinary-sentinel\n",
                 "unmanaged.txt": b"owned unmanaged preservation witness\n",
                 "memory-vault/preservation-sentinel.json": b'{"owned_sentinel":true}\n'}
    for relative, raw in sentinels.items():
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    before = {path.relative_to(home).as_posix(): pin(path, META) for path in home.rglob("*") if path.is_file()}
    os.environ.pop("HERMES_MEMORY_BIN", None)
    kwargs = {"bundle": assets.archive, "expected_sha256": pin(assets.archive)["sha256"],
              "release_manifest": assets.manifest, "home": home, "activate": False}
    dry = install_bundle(**kwargs, dry_run=True)
    after_dry = {path.relative_to(home).as_posix(): pin(path, META) for path in home.rglob("*") if path.is_file()}
    require(dry.get("dry_run") is True and dry.get("changed") is False and after_dry == before, "Dry run mutated home")
    installed = install_bundle(**kwargs)
    require(installed.get("changed") is True and installed.get("activated") is False, "Disposable install or no-activation contract")
    binary = home / "bin" / "hermes-memory.exe"
    require(pin(binary) == pin(Path("target/release/hermes-memory.exe")), "Installed release differs")
    require(all(bounded(home / relative) == raw for relative, raw in sentinels.items()), "Install changed unmanaged data or configuration")
    save(output / "installer.json", {"dry_run": dry, "install": installed, "home": str(home),
                                    "binary": pin(binary), "archive": pin(assets.archive), "manifest": pin(assets.manifest),
                                    "unmanaged_before": before, "dry_run_after": after_dry})


def package_gate(capsule, output, reviewed_digest, binding):
    if reviewed_digest is None:
        _, delta = command(["git", "diff", "--binary", "--no-ext-diff", "--no-color", PARENT, "HEAD"], output, "reviewed-delta", 30)
        require(delta, "Missing reviewed successor delta")
        reviewed_digest = hashlib.sha256(delta).hexdigest()
    require(len(reviewed_digest) == 64 and all(char in "0123456789abcdef" for char in reviewed_digest), "Reviewed digest shape")
    target = Path.cwd() / "target" / "release" / "hermes-memory.exe"
    prior = restore(capsule, "release", binding, target)
    command([sys.executable, "-B", "-m", "scripts.ci_windows_ordinary", "package-child", "--output", str(output),
             "--reviewed-digest", reviewed_digest], output, "package-install", 120)
    binary = output / "disposable-hermes-home" / "bin" / "hermes-memory.exe"
    _, version = command([str(binary), "--version"], output, "installed-version", 30)
    require(version.decode().strip() == "hermes-memory " + binding["version"], "Installed version")
    root = output / "disposable-hermes-home" / "memory-vault" / "synthetic-store"
    record = {"id": "ordinary-release-ingest", "session_id": "ordinary-release-session",
              "workspace": "ordinary-release-workspace", "kind": "user", "content": "release-witness-6417",
              "timestamp": 1.0, "metadata": {}}
    ingest = output / "synthetic-ingest.json"
    save(ingest, record)
    _, raw = command([str(binary), "ingest", "--root", str(root)], output, "installed-ingest", 30, ingest)
    require(json.loads(raw) == {"inserted": 1, "duplicates": 0}, "Installed ingest did not commit")
    snapshot = output / "synthetic-snapshot.json"
    save(snapshot, {"session_id": "ordinary-snapshot-session", "workspace": "ordinary-release-workspace",
                    "items": [{"kind": "assistant", "content": "snapshot-witness-7548", "timestamp": 2.0, "metadata": {}}]})
    _, raw = command([str(binary), "snapshot", "--root", str(root)], output, "installed-snapshot", 30, snapshot)
    require(json.loads(raw) == {"inserted": 1, "duplicates": 0}, "Installed snapshot did not commit")
    _, raw = command([str(binary), "search", "--root", str(root), "--query", "release-witness-6417",
                      "--workspace", "ordinary-release-workspace"], output, "installed-search", 30)
    hits = json.loads(raw)
    require(isinstance(hits, list) and any(hit.get("id") == record["id"] and hit.get("content") == record["content"] for hit in hits),
            "Installed search did not return the ingested record")
    vault = output / "disposable-hermes-home" / "synthetic-export"
    _, raw = command([str(binary), "export", "--root", str(root), "--vault", str(vault),
                      "--workspace", "ordinary-release-workspace"], output, "installed-export", 30)
    require(json.loads(raw) == {"sessions": 2}, "Installed export session count")
    exports = sorted(vault.rglob("*.md"))
    require(exports and all(path.is_relative_to(vault) for path in exports), "Missing own export files")
    exported = "\n".join(bounded(path).decode("utf-8") for path in exports)
    require(record["content"] in exported and "snapshot-witness-7548" in exported, "Installed export lost records")
    require(pin(binary) == prior["binary"] and pin(target) == prior["binary"], "Release binary changed during exercise")
    installer = json.loads(bounded(output / "installer.json"))
    require(all(pin(output / "disposable-hermes-home" / relative, META) == expected
                for relative, expected in installer["unmanaged_before"].items()), "Release exercise changed unmanaged sentinels")
    compatible(binding, current_binding())
    return {"schema": 1, "status": "PACKAGE_PASS", "binding": binding,
            "release_capsule_sha256": pin(capsule / "capsule.json", META)["sha256"],
            "release_binary": prior["binary"], "reviewed_digest": reviewed_digest,
            "activation_performed": False, "production_install_performed": False,
            "installed_commands": ["version", "ingest", "snapshot", "search", "export"],
            "installer_receipt_sha256": pin(output / "installer.json", META)["sha256"]}


def verify_record(directory, name, limit):
    actual = json.loads(bounded(directory / (name + ".json")))
    require(custody.success(actual) and type(actual.get("timeout_limit_seconds")) is int
            and 0 < actual["timeout_limit_seconds"] <= limit, "Command terminal or limit mismatch")
    for stream in ("stdout", "stderr"):
        raw = bounded(directory / (name + "." + stream), custody.LOG)
        require(actual[stream] == {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, "Command log drift")
    return actual, bounded(directory / (name + ".stdout"), custody.LOG)


def artifact_bounds(output, action):
    """Bound only the explicitly uploaded members, excluding test/installation scratch."""
    members = [path for path in output.iterdir() if path.is_file()
               and path.suffix in (".json", ".stdout", ".stderr")]
    if action == "build":
        members.append(output / "runtime" / "hermes-memory.exe")
    if action == "package":
        members.extend(path for path in (output / "dist").iterdir() if path.is_file())
    require(len(members) <= 64, "Artifact member count cap")
    total = 0
    for path in members:
        custody.no_reparse(path)
        require(path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= MEMBER, "Artifact member bound or alias")
        total += path.stat().st_size
    limit = {"build": 1024, "python": 128, "package": 256, "aggregate": 8}[action] * 1024 * 1024
    require(total + META <= limit, "Artifact total cap including final receipt reserve")
    return {"members_before_final_receipt": len(members), "bytes_before_final_receipt": total,
            "final_receipt_reserve_bytes": META, "total_limit_bytes": limit}


def aggregate(inputs, output, binding):
    expected_status = {"debug": "BUILT", "release": "BUILT", "python": "PYTHON_PASS", "package": "PACKAGE_PASS"}
    proofs = {}
    for role, status in expected_status.items():
        path = inputs / role / "result.json"
        value = json.loads(bounded(path))
        compatible(value["binding"], binding)
        require(value.get("schema") == 1 and value.get("status") == status and value.get("gate_pass") is True,
                "Missing or failed ordinary stage: " + role)
        if role in ("debug", "release"):
            require(value.get("profile") == role and custody.success(value["build_command"]), "Build terminal mismatch")
            build_receipt, raw = verify_record(inputs / role, "cargo-build", 600)
            expected_argv = ["cargo", "build", "--locked", "--bin", "hermes-memory", "--message-format=json-render-diagnostics"]
            if role == "release":
                expected_argv.append("--release")
            require(build_receipt == value["build_command"] and build_receipt["argv"] == expected_argv, "Build invocation drift")
            artifacts = [item for line in raw.decode("utf-8").splitlines()
                         if (item := json.loads(line)).get("reason") == "compiler-artifact"
                         and item.get("target", {}).get("name") == "hermes-memory" and item.get("target", {}).get("kind") == ["bin"]]
            require(artifacts == [value["compiler_artifact"]] and artifacts[0]["features"] == []
                    and artifacts[0]["profile"]["test"] is False
                    and artifacts[0]["profile"]["opt_level"] == ("3" if role == "release" else "0"), "Compiler artifact drift")
            member = inputs / role / "runtime" / "hermes-memory.exe"
            require(member.stat().st_nlink == 1 and pin(member) == value["binary"], "Built binary transport drift")
            capsule = json.loads(bounded(inputs / role / "capsule.json"))
            require(all(capsule.get(key) == value.get(key) for key in capsule), "Build capsule/result mismatch")
            version_receipt, version = verify_record(inputs / role, "version", 30)
            require(version_receipt["argv"] == [value["staged_binary_path"], "--version"]
                    and version.decode().strip() == "hermes-memory " + binding["version"], "Built version proof drift")
        if role == "python":
            passed = validate_pytest(json.loads(bounded(inputs / role / "pytest-report.json")), bases())
            require(passed == value["passed_full_nodeids"] and custody.success(value["pytest_command"]), "Pytest proof drift")
            require(value["host_commit"] == HOST, "Host proof drift")
            dependencies, raw = verify_record(inputs / role, "python-dependencies", 30)
            require(dependencies["argv"] == [value["binding"]["python_executable"], "-m", "pip", "freeze"], "Dependency inventory invocation")
            require(value["dependency_versions"] == {"pytest": "8.4.2", "PyYAML": "6.0.2", "ruamel.yaml": "0.18.17"}
                    and {"pytest==8.4.2", "pyyaml==6.0.2", "ruamel.yaml==0.18.17"}.issubset(set(raw.decode().casefold().splitlines())),
                    "Actual Python dependency inventory differs")
            actual, _ = verify_record(inputs / role, "pytest", 600)
            require(actual == value["pytest_command"], "Pytest receipt mismatch")
            argv = actual["argv"]
            require(argv[:8] == [value["binding"]["python_executable"], "-B", "-m", "pytest", "-p", "scripts.ci_windows_ordinary", "-q", "--strict-markers"]
                    and argv[8] == "--basetemp" and argv[10:] == ["python_tests/" + name for name in MODULES], "Pytest invocation drift")
            require(json.loads(bounded(inputs / role / "reused-controls.json")) == reuse_controls_value(), "Reuse proof drift")
        proofs[role] = {"result": value, "sha256": pin(path, META)["sha256"]}
    require(proofs["python"]["result"]["debug_capsule_sha256"] == pin(inputs / "debug" / "capsule.json", META)["sha256"],
            "Python used a different debug capsule")
    package = proofs["package"]["result"]
    require(package["release_capsule_sha256"] == pin(inputs / "release" / "capsule.json", META)["sha256"]
            and package["release_binary"] == proofs["release"]["result"]["binary"], "Package used a different release")
    require(package["activation_performed"] is False and package["production_install_performed"] is False,
            "Package installation scope")
    for name in ("package-install", "installed-version", "installed-ingest", "installed-snapshot", "installed-search", "installed-export"):
        actual, _ = verify_record(inputs / "package", name, 120 if name == "package-install" else 30)
        expected_operation = name.removeprefix("installed-")
        require((name == "package-install" and actual["argv"][:6] == [package["binding"]["python_executable"], "-B", "-m", "scripts.ci_windows_ordinary", "package-child", "--output"])
                or (name != "package-install" and actual["argv"][1] == ("--version" if expected_operation == "version" else expected_operation)),
                "Installed invocation drift")
    return {"schema": 1, "status": "WINDOWS_ORDINARY_DIAGNOSTIC_PASS", "binding": binding,
            "stage_proof_sha256": {key: value["sha256"] for key, value in proofs.items()},
            "production_install_performed": False, "release_approved": False,
            "historical_cause_proven": False, "host_commit": HOST}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("build", "python", "package", "package-child", "aggregate"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("debug", "release"))
    parser.add_argument("--capsule", type=Path)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--reviewed-digest")
    parser.add_argument("--inputs", type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    custody.no_reparse(output)
    require(output.is_relative_to(Path(os.environ["RUNNER_TEMP"]).absolute()), "Output must remain in runner scratch")
    if args.action != "package-child":
        require(not output.exists(), "New output directory required")
        output.mkdir(parents=True)
    value = {"schema": 1, "status": "INCOMPLETE", "action": args.action, "gate_pass": False}
    try:
        binding = current_binding()
        if args.action == "build":
            require(args.profile is not None, "Profile required")
            value = build(args.profile, output, binding)
            save(output / "capsule.json", value)
        elif args.action == "python":
            require(args.capsule is not None and args.host is not None, "Capsule and host required")
            value = python_gate(args.capsule, args.host, output, binding)
        elif args.action == "package":
            require(args.capsule is not None, "Capsule required")
            value = package_gate(args.capsule, output, args.reviewed_digest, binding)
        elif args.action == "aggregate":
            require(args.inputs is not None, "Stage proofs required")
            value = aggregate(args.inputs, output, binding)
        else:
            package_child(output, args.reviewed_digest, binding)
            return 0
        value["artifact_bounds"] = artifact_bounds(output, args.action)
        value["gate_pass"] = True
        save(output / "result.json", value)
        return 0
    except Exception as error:
        value["status"] = "INCOMPLETE"
        value["gate_pass"] = False
        value["error"] = str(error)[:2048]
        save(output / ("package-child-error.json" if args.action == "package-child" else "result.json"), value)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
