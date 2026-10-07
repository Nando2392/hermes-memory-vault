"""Bounded hosted test carrier. Workers execute pinned harnesses, never Cargo."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import threading
import time

META = 4 * 1024 * 1024
LOG = 16 * 1024 * 1024
MEMBER = 512 * 1024 * 1024
TOTAL = 2 * 1024 * 1024 * 1024
ISOLATED = ["full_native::tests::terminal_shared_eight_baseline_failures_keep_primary_and_no_retry",
            "full_native::tests::causal_coordinated_first_interior_final_all_ingresses"]
SLOW = {"cadence_review_balanced_omitted_failures_cannot_complete_or_publish",
        "cadence_review_omitted_real_failures_preserve_all_sample_summaries",
        "cadence_shared_fault_paths_retain_partial_without_ack_or_next_runner",
        "case_closure_actual_shared_partials_keep_primary_and_cleanup",
        "case_closure_all14_failure_conservation_crossproduct",
        "causal_exact_three_witnesses_all_four_ingresses",
        "operation_seal_relabelled_terminal_owners_all_ingresses",
        "review_fix_attempted_unretained_failure_is_not_completed_receipt",
        "review_fix_complete_requires_every_confirmed_ack",
        "review_fix_exact_frozen_malformed_witnesses_all_ingresses",
        "review_fix_retained_receipt_semantics_actual_collision",
        "shared_full64_orchestration_runs_real_store_and_retains_before_each_ack"}
EXAMPLE_REQUIRED = ["data::tests::owned_store_seed_preserves_records_source_and_namespace_reservation",
                    "full_native::tests::shared_full64_orchestration_runs_real_store_and_retains_before_each_ack",
                    "full_native::tests::shared_controller_invalid_after_done_receipt_withholds_ack_and_next_release",
                    "full_native::tests::shared_peer_unknown_real_commit_has_no_done_or_retry",
                    "full_oracles::tests::stopped_streaming_oracles_bind_same_count_fields_order_state_and_notes"]
WRITER = "concurrent_ingest_projects_complete_parseable_jsonl"
FIXTURE_TARGET = "example:windows_broker_benchmark:examples/windows_broker_benchmark.rs"
FIXTURE_SOURCES = {
    "examples/windows_broker_benchmark/contract.rs": "b178b99b81c5664e08bf0a04b662cbc43b3f6c317734482ec20d8baebb99ff37",
    "examples/windows_broker_benchmark/metrics_tests.rs": "4bb913d076e1ccb7c779c3dbae996a72580bbebb8d989f5a529f74e950daa610",
}
FIXTURE_NAMES = {
    "contract::tests::capture_sleeper",
    "contract::tests::capture_fixture",
    "contract::tests::capture_writer_holder",
    "contract::tests::descendant::direct_fixture",
    "contract::tests::descendant::descendant_fixture",
    "scm::metrics::tests::logical_io_child_payload",
}


def ordinary_inventory(inventory):
    return [item for item in inventory if not (item[0] == FIXTURE_TARGET and item[1] in FIXTURE_NAMES)]


def verify_fixture_sources(workspace):
    for name, expected in FIXTURE_SOURCES.items():
        path = workspace / name
        no_reparse(path)
        require(path.is_file() and path.stat().st_size <= META, "Fixture source type/size")
        require(sha(path.read_bytes()) == expected, "Fixture source drift")


def validate_ignored_listing(target, inventory_names, ignored_names):
    expected = sorted(set(inventory_names) & FIXTURE_NAMES) if target == FIXTURE_TARGET else []
    require(ignored_names == expected, "Unknown ignored test or fixture classification drift")
    return expected


def require(value, text):
    if not value:
        raise ValueError(text)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return sha(canonical(value))


def no_reparse(path):
    for part in (path.absolute(), *path.absolute().parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not (
                getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT), "Reparse path")


def relative(text):
    require(isinstance(text, str) and text and "\\" not in text and ":" not in text, "Unsafe member path")
    path = PurePosixPath(text)
    require(not path.is_absolute() and all(x not in ("", ".", "..") for x in text.split("/")), "Unsafe member path")
    require(path.parts[0] == "target", "Runtime member outside target")
    for component in path.parts:
        require(component[-1] not in ". " and not any(ord(c) < 32 or c in '<>"|?*' for c in component), "Unsafe Windows alias")
        require(component.split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL",
                *("COM" + str(i) for i in range(1, 10)), *("LPT" + str(i) for i in range(1, 10))}, "Reserved path")
    return path


def read_json(path):
    no_reparse(path)
    require(path.is_file() and path.stat().st_size <= META, "Metadata type/cap")
    with path.open("rb") as stream:
        raw = stream.read(META + 1)
    require(len(raw) <= META, "Metadata cap")
    return json.loads(raw)


def save(path, value):
    raw = canonical(value)
    require(len(raw) <= META, "Metadata cap")
    no_reparse(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def source_inputs(workspace):
    folders = {"src": None, "examples": None, "tests": None,
               "scripts": {".py"}, "python_tests": {".py"}, ".github/workflows": {".yml", ".yaml"}}
    paths = [workspace / p for p in ("Cargo.toml", "Cargo.lock")]
    for folder, suffixes in folders.items():
        for path in (workspace / folder).rglob("*"):
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
                continue
            no_reparse(path)
            if path.is_file() and (suffixes is None or path.suffix in suffixes):
                paths.append(path)
    return sorted(paths)


def verify_member(path, member, require_single_link=True):
    no_reparse(path)
    require(path.is_file() and path.stat().st_size == member["bytes"]
            and 0 < member["bytes"] <= MEMBER, "Runtime member type/size")
    if require_single_link:
        require(path.stat().st_nlink == 1, "Runtime hardlink alias")
    with path.open("rb") as stream:
        raw = stream.read(MEMBER + 1)
    require(len(raw) == member["bytes"] and sha(raw) == member["sha256"], "Runtime member drift")


def stage_member(source, destination, member):
    # Cargo may legitimately hardlink its outputs. Reading them cannot mutate aliases.
    verify_member(source, member, require_single_link=False)
    no_reparse(destination)
    require(not destination.exists(), "New staging member required")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("xb") as dest:
        remaining = member["bytes"]
        while True:
            chunk = src.read(min(1024 * 1024, remaining + 1))
            if not chunk:
                break
            require(len(chunk) <= remaining, "Source grew during staging")
            dest.write(chunk)
            remaining -= len(chunk)
        require(remaining == 0, "Source shrank during staging")
    verify_member(destination, member)


def binding(configuration, require_temp=True):
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).absolute()
    no_reparse(workspace)
    require(workspace == Path.cwd().absolute(), "Workspace mismatch")
    require(configuration in ("featureless", "all-features"), "Configuration")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Hosted required")
    commit = os.environ["GITHUB_SHA"]
    require(re.fullmatch("[0-9a-f]{40}", commit), "Commit shape")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=15).strip()
    require(actual == commit, "Checkout commit mismatch")
    if require_temp:
        runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
        for name in ("TMPDIR", "TEMP", "TMP"):
            own = Path(os.environ[name]).absolute()
            no_reparse(own)
            require(own.is_dir() and own.is_relative_to(runner_temp) and own != runner_temp, "Owned temp required")
    source_paths = source_inputs(workspace)
    source = []
    for path in source_paths:
        no_reparse(path)
        require(path.stat().st_size <= MEMBER, "Source cap")
        source.append({"path": path.relative_to(workspace).as_posix(), "sha256": sha(path.read_bytes())})
    return {"configuration": configuration, "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "source_inventory_sha256": digest(source),
            "commit": commit, "os": os.environ["RUNNER_OS"], "image_os": os.environ["ImageOS"],
            "workspace": str(workspace), "helper_sha256": sha(Path(__file__).read_bytes())}


def execute(argv, output, prefix, timeout):
    """Retained direct child, bounded capture, no process search or tree kill."""
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    errors = []
    capture_lock = threading.Lock()
    start = time.monotonic()
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def drain(name):
        try:
            while True:
                chunk = getattr(child, name).read1(16384)
                if not chunk:
                    return
                with capture_lock:
                    remaining = LOG - len(captures[name])
                    captures[name].extend(chunk[:remaining])
                    if len(chunk) > remaining and not errors:
                        errors.append("capture overflow")
        except Exception as error:
            with capture_lock:
                errors.append(str(error)[:1024])
    threads = [threading.Thread(target=drain, args=(name,), daemon=True) for name in captures]
    for thread in threads:
        thread.start()
    timed_out = False
    while child.poll() is None:
        if time.monotonic() - start >= timeout or errors:
            timed_out = time.monotonic() - start >= timeout
            try:
                child.kill()
            except OSError as error:
                errors.append("owned kill failed: " + str(error)[:1024])
            break
        time.sleep(0.02)
    settled = False
    end = time.monotonic() + 5
    try:
        child.wait(timeout=max(0, end - time.monotonic()))
        settled = True
    except subprocess.TimeoutExpired:
        errors.append("retained child did not settle")
    for thread in threads:
        thread.join(max(0, end - time.monotonic()))
    complete = not any(thread.is_alive() for thread in threads)
    with capture_lock:
        snapshots = {name: bytes(raw) for name, raw in captures.items()}
        retained_errors = list(errors)
    output.mkdir(parents=True, exist_ok=True)
    for name, raw in snapshots.items():
        with (output / (prefix + "." + name)).open("xb") as stream:
            stream.write(raw)
    receipt = {"argv": argv, "exit_code": child.returncode if settled else None,
               "timeout_limit_seconds": timeout,
               "timed_out": timed_out, "settled": settled, "capture_complete": complete,
               "errors": retained_errors, "elapsed_seconds": time.monotonic() - start}
    return receipt, snapshots["stdout"], snapshots["stderr"]


def listed(raw):
    names = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if line.endswith(": test"):
            names.append(line[:-6])
        elif line.strip():
            raise ValueError("Unsupported or ambiguous harness listing")
    require(len(names) == len(set(names)), "Duplicate test name within target")
    require(all(re.fullmatch("[A-Za-z0-9_:]+", name) for name in names), "Unsupported test filter name")
    return sorted(names)


def success(command):
    return type(command["exit_code"]) is int and command["exit_code"] == 0 and command["settled"] is True and command["capture_complete"] is True and command["timed_out"] is False and command["errors"] == []


def positive(raw, expected):
    text = raw.decode("utf-8", errors="strict")
    records = re.findall(r"^test (.+) \.\.\. (ok|FAILED|ignored)(?: .*)?$", text, re.MULTILINE)
    require(len(records) == len(expected) and len({name for name, _ in records}) == len(records), "Missing/duplicate runtime test")
    require(sorted(name for name, state in records if state == "ok") == sorted(expected), "Ignored, failed or unplanned runtime test")
    summary = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;.*?(\d+) filtered out", text)
    require(len(summary) == 1 and tuple(map(int, summary[0][:3])) == (len(expected), 0, 0), "Zero or ambiguous terminal summary")
    return sorted(expected)


def plan(inventory):
    require(len(inventory) == len(set(map(tuple, inventory))), "Duplicate inventory tuple")
    inventory = ordinary_inventory(inventory)
    shards, weights = [[] for _ in range(8)], [0] * 8
    isolated = set()
    for index, name in enumerate(ISOLATED):
        matches = [item for item in inventory if item[0].startswith("example:windows_broker_benchmark:") and item[1] == name]
        require(len(matches) <= 1, "Ambiguous isolated target")
        if matches:
            shards[index].append(matches[0])
            isolated.add(tuple(matches[0]))
    active = [i for i in range(8) if i >= 2 or not shards[i]]
    remainder = [item for item in inventory if tuple(item) not in isolated]
    for item in sorted(remainder, key=lambda x: (-64 if x[1].rsplit("::", 1)[-1] in SLOW else -1, x)):
        index = min(active, key=lambda i: (weights[i], i))
        shards[index].append(item)
        weights[index] += 64 if item[1].rsplit("::", 1)[-1] in SLOW else 1
    return [sorted(items) for items in shards]


def capsule(path, configuration, require_temp=True):
    value = read_json(path / "capsule.json")
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["binding"] == binding(configuration, require_temp), "Capsule identity mismatch")
    require(digest(value["inventory"]) == value["inventory_sha256"] and digest(value["plan"]) == value["plan_sha256"], "Inventory/plan drift")
    require(value["plan"] == plan(value["inventory"]), "Plan mismatch")
    verify_fixture_sources(Path(value["binding"]["workspace"]))
    expected_ignored = sorted(item for item in value["inventory"] if item not in ordinary_inventory(value["inventory"]))
    require(value.get("ignored_fixtures") == expected_ignored, "Fixture classification mismatch")
    members = value["members"]
    require(0 < len(members) <= 64 and sum(m["bytes"] for m in members) <= TOTAL, "Transport bounds")
    seen = set()
    for member in members:
        name = str(relative(member["path"]))
        require(name.casefold() not in seen and type(member["bytes"]) is int and 0 < member["bytes"] <= MEMBER
                and type(member["mode"]) is int and 0 <= member["mode"] <= 0o777
                and member["role"] in ("test", "companion", "library"), "Duplicate/member cap")
        seen.add(name.casefold())
        actual = path / "runtime" / name
        no_reparse(actual)
        verify_member(actual, member)
    actual_files = set()
    for actual in path.rglob("*"):
        no_reparse(actual)
        if actual.is_file():
            actual_files.add(actual.relative_to(path).as_posix())
    require(actual_files == {"capsule.json", *("runtime/" + m["path"] for m in members)}, "Undeclared capsule member")
    require(set(value["targets"].values()).issubset({m["path"] for m in members if m["role"] == "test"}), "Foreign target executable")
    require(all(target in value["targets"] and isinstance(name, str) and name for target, name in value["inventory"]), "Foreign inventory target")
    return value


def build(configuration, output):
    require(not output.exists(), "New build output required")
    identity = binding(configuration)
    output.mkdir(parents=True)
    proof = output.with_name(output.name + "-build-proof")
    require(not proof.exists(), "New build proof required")
    feature = "--no-default-features" if configuration == "featureless" else "--all-features"
    command, raw, _ = execute(["cargo", "test", "--locked", "--all-targets", "--no-run", "--message-format=json", feature], proof, "build", 780)
    save(proof / "build-command.json", command)
    require(success(command), "Build failed")
    workspace = Path(identity["workspace"])
    targets, members = {}, {}
    for line in raw.decode().splitlines():
        event = json.loads(line)
        if event.get("reason") != "compiler-artifact":
            continue
        target = event["target"]
        if "custom-build" in target["kind"] or "proc-macro" in target["kind"]:
            continue
        exe = event.get("executable")
        if exe:
            require(type(event["profile"]["test"]) is bool, "Ambiguous Cargo profile")
            require(event.get("features", []) == ([] if configuration == "featureless" else ["experimental-broker"]), "Compiled feature mismatch")
            require(event["profile"]["test"] or "bin" in target["kind"], "Unsupported executable companion")
            path = Path(exe).absolute()
            name = path.relative_to(workspace).as_posix()
            relative(name)
            members[name] = "test" if event["profile"]["test"] else "companion"
            if event["profile"]["test"]:
                key = "+".join(target["kind"]) + ":" + target["name"] + ":" + Path(target["src_path"]).relative_to(workspace).as_posix()
                require(key not in targets, "Duplicate Cargo test target")
                targets[key] = name
        for filename in event.get("filenames", []):
            path = Path(filename)
            if path.suffix.lower() in (".dll", ".so", ".dylib") and any(kind in target.get("crate_types", []) for kind in ("dylib", "cdylib")):
                name = path.absolute().relative_to(workspace).as_posix()
                relative(name)
                members[name] = "library"
    inventory = []
    ignored_fixtures = []
    verify_fixture_sources(workspace)
    for index, (key, name) in enumerate(sorted(targets.items())):
        receipt, stdout, _ = execute([str(workspace / name), "--list", "--format", "terse"], proof, "list-" + str(index), 30)
        require(success(receipt), "Inventory failed")
        names = listed(stdout)
        ignored_receipt, ignored_stdout, _ = execute([str(workspace / name), "--ignored", "--list", "--format", "terse"], proof, "ignored-list-" + str(index), 30)
        require(success(ignored_receipt), "Ignored inventory failed")
        save(proof / ("ignored-list-" + str(index) + ".json"), ignored_receipt)
        ignored_names = validate_ignored_listing(key, names, listed(ignored_stdout))
        inventory.extend([[key, test_name] for test_name in names])
        ignored_fixtures.extend([[key, test_name] for test_name in ignored_names])
    require(inventory, "Empty inventory")
    manifest = []
    for name, role in sorted(members.items()):
        source = workspace / name
        no_reparse(source)
        require(source.is_file() and 0 < source.stat().st_size <= MEMBER, "Member type/size")
        mode = stat.S_IMODE(source.stat().st_mode)
        data = source.read_bytes()
        manifest.append({"path": name, "role": role, "bytes": len(data), "sha256": sha(data), "mode": mode})
    require(len(manifest) <= 64 and sum(item["bytes"] for item in manifest) <= TOTAL, "Transport cap")
    for item in manifest:
        target = output / "runtime" / item["path"]
        stage_member(workspace / item["path"], target, item)
    save(output / "capsule.json", {"schema": 1, "binding": identity, "targets": targets,
         "producer_job": os.environ["GITHUB_JOB"], "build_command": command,
         "compiler_version": subprocess.check_output(["rustc", "--version"], text=True, timeout=15).strip(),
         "producer_image_version": os.environ.get("ImageVersion"),
         "members": manifest, "inventory": sorted(inventory), "inventory_sha256": digest(sorted(inventory)),
         "ignored_fixtures": sorted(ignored_fixtures),
         "plan": plan(sorted(inventory)), "plan_sha256": digest(plan(sorted(inventory)))})


def run(configuration, path, shard, output):
    require(0 <= shard < 8 and not output.exists(), "New shard output required")
    value = capsule(path, configuration)
    output.mkdir(parents=True)
    receipt = {"schema": 1, "binding": value["binding"], "shard": shard,
               "capsule_sha256": sha((path / "capsule.json").read_bytes()), "state": "INCOMPLETE", "positive": [], "commands": [], "executions": [], "error": None}
    try:
        run_started = time.monotonic()
        workspace = Path(value["binding"]["workspace"])
        for member in value["members"]:
            dest = workspace / member["path"]
            no_reparse(dest)
            if dest.exists():
                verify_member(dest, member)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                stage_member(path / "runtime" / member["path"], dest, member)
            if os.name != "nt":
                dest.chmod(member["mode"])
                require(stat.S_IMODE(dest.stat().st_mode) == member["mode"], "Mode restore failed")
        assigned = value["plan"][shard]
        case_failures = []
        def verify_runtime(executable):
            for member in value["members"]:
                if member["path"] == executable or member["role"] in ("companion", "library"):
                    actual = workspace / member["path"]
                    verify_member(actual, member)
        for index, (key, executable) in enumerate(sorted(value["targets"].items())):
            verify_runtime(executable)
            exe = str(workspace / executable)
            cmd, raw, _ = execute([exe, "--list", "--format", "terse"], output, f"shard{shard}-target{index}-list", 30)
            receipt["commands"].append(cmd)
            require(success(cmd) and listed(raw) == sorted(name for target, name in value["inventory"] if target == key), "Whole inventory drift")
            names = sorted(name for target, name in assigned if target == key)
            groups = [names]
            if value["binding"]["os"] == "Linux" and configuration == "all-features" and key.startswith("test:memory:") and WRITER in names:
                groups = [[WRITER], [name for name in names if name != WRITER]]
            for group_id, names in enumerate(groups):
                if not names:
                    continue
                prefix = f"shard{shard}-target{index}-group{group_id}"
                verify_runtime(executable)
                args = [exe, "--exact", *names]
                cmd, raw, _ = execute([*args, "--list", "--format", "terse"], output, prefix + "-selected", 30)
                receipt["commands"].append(cmd)
                require(success(cmd) and listed(raw) == names, "Selected inventory mismatch")
                verify_runtime(executable)
                limit = 30 if names == [WRITER] and key.startswith("test:memory:") else 780
                limit = min(limit, max(0, 780 - (time.monotonic() - run_started)))
                cmd, raw, _ = execute(args, output, prefix + "-run", limit)
                receipt["commands"].append(cmd)
                execution = {"target": key, "assigned_names": names, "command": cmd,
                             "stdout_file": prefix + "-run.stdout", "stdout_sha256": sha(raw),
                             "positive_actual": []}
                receipt["executions"].append(execution)
                if not cmd["settled"] or not cmd["capture_complete"] or cmd["errors"]:
                    raise ValueError("Unsafe or incomplete retained harness capture")
                try:
                    require(success(cmd), "Harness execution failed")
                    execution["positive_actual"] = positive(raw, names)
                    receipt["positive"].extend([[key, name] for name in execution["positive_actual"]])
                except ValueError as error:
                    case_failures.append({"target": key, "names": names, "error": str(error)})
                require(time.monotonic() - run_started < 780, "Shard wall deadline")
        require(not case_failures, "Ordinary harness failures: " + str(case_failures)[:3000])
        require(sorted(receipt["positive"]) == assigned, "Shard coverage mismatch")
        require(binding(configuration) == value["binding"], "Source drift during worker")
        receipt["state"] = "PASS"
    except Exception as error:
        receipt["error"] = str(error)[:4096]
    finally:
        save(output / f"shard-{shard}.json", receipt)
    require(receipt["state"] == "PASS", "Shard incomplete")


def validate_receipts(value, capsule_sha, receipts):
    require(len(receipts) == 8 and all(type(r["shard"]) is int for r in receipts)
            and {r["shard"] for r in receipts} == set(range(8)), "Missing/duplicate shard")
    covered = []
    for receipt in receipts:
        require(type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["binding"] == value["binding"] and receipt["capsule_sha256"] == capsule_sha, "Receipt identity mismatch")
        require(receipt["state"] == "PASS" and receipt["error"] is None, "Nonterminal/failed shard")
        expected = value["plan"][receipt["shard"]]
        require(sorted(receipt["positive"]) == expected, "Missing/duplicate/extra test")
        require(all(success(command) for command in receipt["commands"]), "False successful command")
        require(bool(receipt["commands"]) or not expected, "Fake nonempty coverage")
        actual_executions = []
        for execution in receipt["executions"]:
            target = execution["target"]
            names = execution["assigned_names"]
            command = execution["command"]
            require(target in value["targets"] and names and names == sorted(set(names)), "Execution target/names")
            exe = str(Path(value["binding"]["workspace"]) / value["targets"][target])
            require(command in receipt["commands"] and success(command)
                    and command["argv"] == [exe, "--exact", *names], "List-only or foreign execution")
            require(execution["positive_actual"] == names
                    and re.fullmatch("[0-9a-f]{64}", execution["stdout_sha256"]), "False positive execution")
            filename = execution["stdout_file"]
            require(isinstance(filename, str) and "/" not in filename and "\\" not in filename
                    and filename.startswith("shard" + str(receipt["shard"]) + "-")
                    and filename.endswith("-run.stdout"), "Foreign execution log")
            if value["binding"].get("os") == "Linux" and value["binding"]["configuration"] == "all-features" and target.startswith("test:memory:") and WRITER in names:
                require(names == [WRITER] and type(command["timeout_limit_seconds"]) in (int, float)
                        and 0 < command["timeout_limit_seconds"] <= 30, "Writer gate weakened")
            actual_executions.extend([[target, name] for name in names])
        require(sorted(actual_executions) == expected, "Missing, duplicate or fabricated execution coverage")
        covered.extend(receipt["positive"])
    require(sorted(covered) == ordinary_inventory(value["inventory"]) and len(covered) == len(set(map(tuple, covered))), "Union coverage mismatch")
    return covered


def required_witnesses(value, covered):
    if value.get("ignored_fixtures"):
        # All ordinary contract tests remain mandatory; this includes every
        # parent of the five contract payloads, not an arbitrary single witness.
        parents = [item for item in ordinary_inventory(value["inventory"])
                   if item[0] == FIXTURE_TARGET and item[1].startswith("contract::tests::")]
        require(parents and all(item in covered for item in parents), "Missing fixture parent coverage")
        metrics_parent = [FIXTURE_TARGET, "scm::metrics::tests::retained_ordinary_child_final_logical_io_includes_terminal_writes"]
        if [FIXTURE_TARGET, "scm::metrics::tests::logical_io_child_payload"] in value["ignored_fixtures"]:
            require(metrics_parent in covered, "Missing logical IO fixture parent")
    require(all(any(target.startswith("example:windows_broker_benchmark:") and name == required
                    for target, name in covered) for required in EXAMPLE_REQUIRED), "Missing original example witness")
    if value["binding"]["os"] != "Linux":
        return
    if value["binding"]["configuration"] == "featureless":
        for required in ("direct_posix_open_is_unsupported_without_io", "direct_posix_open_rejects_aliases_before_io",
                         "direct_posix_open_preserves_hardlinked_sentinels"):
            require(any(target.startswith("lib:") and name.rsplit("::", 1)[-1] == required
                        for target, name in covered), "Missing direct POSIX library witness")
        require(any(target.startswith("test:cli:") and name == "direct_posix_commands_are_unsupported_without_io"
                    for target, name in covered), "Missing direct POSIX CLI witness")
    else:
        for required in (WRITER, "broker_second_instance_rejected_without_mutation"):
            require(any(target.startswith("test:memory:") and name == required for target, name in covered), "Missing broker memory witness")
        require(any(target.startswith("lib:") and name.startswith("broker_store_tests::") for target, name in covered), "Missing broker library witnesses")
        require(any(target.startswith("test:broker_export:") for target, _ in covered), "Missing broker export target")


def aggregate(configuration, path, directory, output):
    value = capsule(path, configuration, require_temp=False)
    summary = {"schema": 1, "state": "INCOMPLETE", "error": None, "binding": value["binding"]}
    try:
        paths = sorted(directory.glob("shard-*.json"))
        receipts = [read_json(p) for p in paths]
        covered = validate_receipts(value, sha((path / "capsule.json").read_bytes()), receipts)
        for receipt in receipts:
            for execution in receipt["executions"]:
                logfile = directory / execution["stdout_file"]
                no_reparse(logfile)
                require(logfile.is_file() and logfile.stat().st_size <= LOG, "Execution log cap/type")
                with logfile.open("rb") as stream:
                    raw = stream.read(LOG + 1)
                require(len(raw) <= LOG and sha(raw) == execution["stdout_sha256"], "Execution log drift")
                require(positive(raw, execution["assigned_names"]) == execution["positive_actual"], "Execution transcript coverage mismatch")
        required_witnesses(value, covered)
        summary.update(state="PASS", tuples=len(covered), inventory_sha256=value["inventory_sha256"])
    except Exception as error:
        summary["error"] = str(error)[:4096]
    finally:
        save(output, summary)
    require(summary["state"] == "PASS", "Aggregate incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build", "run", "aggregate"))
    parser.add_argument("--configuration", required=True, choices=("featureless", "all-features"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capsule", type=Path)
    parser.add_argument("--receipts", type=Path)
    parser.add_argument("--shard", type=int)
    args = parser.parse_args()
    if args.command == "build":
        build(args.configuration, args.output)
    elif args.command == "run":
        require(args.capsule is not None and args.shard is not None, "Run arguments")
        run(args.configuration, args.capsule, args.shard, args.output)
    else:
        require(args.capsule is not None and args.receipts is not None, "Aggregate arguments")
        aggregate(args.configuration, args.capsule, args.receipts, args.output)


if __name__ == "__main__":
    main()
