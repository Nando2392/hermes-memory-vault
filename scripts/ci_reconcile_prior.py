"""Offline reconciliation of D4 evidence; never executes a test or changes its verdict."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import time

META = 4 * 1024 * 1024
LOG = 16 * 1024 * 1024
MEMBER = 512 * 1024 * 1024
TOTAL = 2 * 1024 * 1024 * 1024
OLD_HELPER = "9bbf9bcb39e3d97db6f379c8562da3663f46ee17148042fd4d5b7d32eb884e9d"
PRODUCER_COMMIT = "7a0803c71bb13b6317540411b0f85fb838726502"
PRODUCER_RUNS = {"Windows": "37550081788", "Linux": "37550081745"}
REPOSITORY = "Nando2392/hermes-memory-vault"
TARGET = "example:windows_broker_benchmark:examples/windows_broker_benchmark.rs"
SOURCE_PINS = {
    "examples/windows_broker_benchmark/contract.rs": "b178b99b81c5664e08bf0a04b662cbc43b3f6c317734482ec20d8baebb99ff37",
    "examples/windows_broker_benchmark/metrics_tests.rs": "4bb913d076e1ccb7c779c3dbae996a72580bbebb8d989f5a529f74e950daa610",
}
IGNORED = {
    "contract::tests::capture_sleeper": "subprocess fixture only; explicitly selected with --ignored --exact",
    "contract::tests::capture_fixture": "subprocess fixture only",
    "contract::tests::capture_writer_holder": "subprocess fixture only; outer harness owns and reaps this child",
    "contract::tests::descendant::direct_fixture": "ordinary owned direct fixture only",
    "contract::tests::descendant::descendant_fixture": "ordinary returned-handle descendant fixture only",
    "scm::metrics::tests::logical_io_child_payload": "ordinary subprocess payload; invoked explicitly by parent test",
}
WRITER = "concurrent_ingest_projects_complete_parseable_jsonl"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def no_alias(path):
    for current in (path, *path.parents):
        if current.exists() or current.is_symlink():
            info = current.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & 0x400, "Reparse/symlink input")


def relative(name):
    require(isinstance(name, str) and "\\" not in name and ":" not in name
            and not any(ord(ch) < 32 for ch in name), "Unsafe relative input")
    path = PurePosixPath(name)
    require(not path.is_absolute() and name == path.as_posix() and path.parts
            and all(part not in (".", "..") and not part.endswith((".", " ")) for part in path.parts), "Unsafe path components")
    return path


class Inputs:
    def __init__(self, root):
        self.root = Path(root)
        require(self.root.is_absolute(), "Absolute evidence root required")
        no_alias(self.root)
        require(self.root.is_dir(), "Evidence root missing")
        self.deadline = time.monotonic() + 60
        self.total = 0
        self.members = {}

    def check(self):
        require(time.monotonic() < self.deadline, "Offline reader 60-second deadline")

    def path(self, name):
        result = self.root / relative(name)
        no_alias(result)
        return result

    def read(self, path, cap, expected=None):
        self.check()
        no_alias(path)
        before = path.stat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= cap, "Input type, hardlink or size cap")
        with path.open("rb") as stream:
            raw = stream.read(cap + 1)
        after = path.stat()
        require(len(raw) == before.st_size and before.st_size == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns, "Input changed during read")
        actual = hashlib.sha256(raw).hexdigest()
        require(expected is None or actual == expected, "Input SHA mismatch")
        return raw

    def bound_json(self, binding):
        require(re.fullmatch("[0-9a-f]{64}", binding["sha256"]), "SHA shape")
        return json.loads(self.read(self.path(binding["path"]), META, binding["sha256"]))

    def verify_transport(self, manifest):
        require(type(manifest["schema"]) is int and manifest["schema"] == 1
                and 0 < len(manifest["members"]) <= 2048, "Transport manifest schema/count")
        for member in manifest["members"]:
            self.check()
            name = str(relative(member["path"]))
            require(name.casefold() not in self.members and type(member["bytes"]) is int
                    and 0 <= member["bytes"] <= MEMBER
                    and re.fullmatch("[0-9a-f]{64}", member["sha256"]), "Transport duplicate/size/hash")
            self.total += member["bytes"]
            require(self.total <= TOTAL, "Transport total cap")
            path = self.path(name)
            before = path.stat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_size == member["bytes"], "Transport type/size/alias")
            actual = hashlib.sha256()
            remaining = member["bytes"]
            with path.open("rb") as stream:
                while remaining:
                    self.check()
                    raw = stream.read(min(1024 * 1024, remaining))
                    require(raw, "Transport shrank")
                    remaining -= len(raw)
                    actual.update(raw)
                require(not stream.read(1), "Transport grew")
            after = path.stat()
            require(before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns
                    and actual.hexdigest() == member["sha256"], "Transport changed/hash")
            self.members[name.casefold()] = member

    def transported(self, name, cap):
        member = self.members.get(str(relative(name)).casefold())
        require(member is not None, "Unmanifested artifact input")
        return self.read(self.path(name), cap, member["sha256"])


def terminal(command):
    require(type(command["exit_code"]) is int and command["exit_code"] in (0, 101)
            and command["settled"] is True and command["capture_complete"] is True
            and command["timed_out"] is False and command["errors"] == [], "Nonterminal or incomplete command")


def transcript(raw, names, target, exit_code):
    text = raw.decode("utf-8", errors="strict")
    records = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored)(?:, ([^\r\n]+))?$", text, re.MULTILINE)
    require(len(records) == len(names) and sorted(name for name, _, _ in records) == names, "Missing/duplicate/unplanned runtime record")
    states = {state: sorted(name for name, current, _ in records if current == state)
              for state in ("ok", "FAILED", "ignored")}
    for name, state, reason in records:
        if state == "ignored":
            require(target == TARGET and name in IGNORED and reason == IGNORED[name], "Unapproved ignored payload/reason")
        else:
            require(not reason and not (target == TARGET and name in IGNORED), "Payload classification contradiction")
    summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; \d+ filtered out; finished in [0-9.]+s$", text, re.MULTILINE)
    require(len(summaries) == 1, "Missing/ambiguous harness terminal summary")
    status, passed, failed, ignored = summaries[0]
    require(tuple(map(int, (passed, failed, ignored))) == tuple(len(states[s]) for s in ("ok", "FAILED", "ignored")), "Terminal count mismatch")
    require((exit_code == 0 and status == "ok" and not states["FAILED"])
            or (exit_code == 101 and status == "FAILED" and states["FAILED"]), "Native exit/summary mismatch")
    return states


def source_manifest(root, os_name, reader):
    root = Path(root)
    require(root.is_absolute() and root.is_dir(), "Exact source checkout required")
    no_alias(root)
    files = [root / name for name in ("Cargo.toml", "Cargo.lock")]
    folders = {"src": None, "examples": None, "tests": None,
               "scripts": {".py"}, "python_tests": {".py"}, ".github/workflows": {".yml", ".yaml"}}
    for folder, suffixes in folders.items():
        for path in (root / folder).rglob("*"):
            reader.check()
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
                continue
            no_alias(path)
            if path.is_file() and (suffixes is None or path.suffix in suffixes):
                files.append(path)
    flavor = PureWindowsPath if os_name == "Windows" else PurePosixPath
    # D4 sorted native Path objects, which compare path components rather than
    # joined strings. Preserve that producer ordering across consumer platforms.
    def key(path):
        return flavor(path.relative_to(root).as_posix())
    result = []
    for path in sorted(files, key=key):
        raw = reader.read(path, META)
        result.append({"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()})
    require(len(result) <= 1024 and len({item["path"].casefold() for item in result}) == len(result), "Source count/collision")
    pins = {item["path"]: item["sha256"] for item in result}
    require(pins.get("scripts/ci_test_shards.py") == OLD_HELPER, "Producer helper drift")
    require(all(pins.get(name) == expected for name, expected in SOURCE_PINS.items()), "Payload source drift")
    return result


def reconcile(request):
    require(type(request["schema"]) is int and request["schema"] == 1, "Request schema")
    binding = request["binding"]
    require(binding["helper_sha256"] == OLD_HELPER and binding["commit"] == PRODUCER_COMMIT
            and binding["os"] in ("Windows", "Linux") and binding["configuration"] in ("featureless", "all-features")
            and binding["run_id"] == PRODUCER_RUNS[binding["os"]]
            and re.fullmatch("[1-9][0-9]*", binding["run_attempt"]), "Producer binding")
    reader = Inputs(request["evidence_root"])
    api_run = reader.bound_json(request["api_run"])
    require(api_run["id"] == int(binding["run_id"]) and api_run["run_attempt"] == int(binding["run_attempt"])
            and api_run["head_sha"] == binding["commit"] and api_run["status"] == "completed", "Producer API run identity/terminal")
    require(api_run["repository"]["full_name"] == REPOSITORY, "Producer repository")
    jobs = reader.bound_json(request["api_jobs"])["jobs"]
    require(len(jobs) <= 100 and len({job["id"] for job in jobs}) == len(jobs), "API jobs bounds/duplicates")
    jobs = {job["id"]: job for job in jobs}
    build = jobs[request["build_job_id"]]
    require(build["status"] == "completed" and build["conclusion"] == "success"
            and build["run_id"] == int(binding["run_id"]), "Build API custody")
    artifacts = reader.bound_json(request["api_artifacts"])["artifacts"]
    require(len(artifacts) <= 100 and len({artifact["id"] for artifact in artifacts}) == len(artifacts), "API artifact bounds/duplicates")
    artifacts = {artifact["id"]: artifact for artifact in artifacts}
    manifest = reader.bound_json(request["transport_manifest"])
    reader.verify_transport(manifest)
    source = source_manifest(request["source_root"], binding["os"], reader)
    require(digest(source) == binding["source_inventory_sha256"], "Exact producer source inventory mismatch")
    capsule_raw = reader.transported(request["capsule"]["path"], META)
    capsule_sha = hashlib.sha256(capsule_raw).hexdigest()
    require(capsule_sha == request["capsule"]["sha256"], "Capsule SHA")
    capsule = json.loads(capsule_raw)
    require(type(capsule["schema"]) is int and capsule["schema"] == 1 and capsule["binding"] == binding
            and digest(capsule["inventory"]) == capsule["inventory_sha256"]
            and digest(capsule["plan"]) == capsule["plan_sha256"], "Capsule identity/plan/inventory")
    inventory = capsule["inventory"]
    require(inventory == sorted(inventory) and len(inventory) == len(set(map(tuple, inventory)))
            and len(inventory) <= 10000 and len(capsule["plan"]) == 8
            and sorted(item for shard in capsule["plan"] for item in shard) == inventory, "Original full plan coverage")
    capsule_members = capsule["members"]
    require(0 < len(capsule_members) <= 64 and sum(member["bytes"] for member in capsule_members) <= TOTAL, "Capsule runtime member caps")
    capsule_dir = str(PurePosixPath(request["capsule"]["path"]).parent)
    expected_capsule_files = {request["capsule"]["path"]}
    for member in capsule_members:
        name = capsule_dir + "/runtime/" + str(relative(member["path"]))
        transport = reader.members.get(name.casefold())
        require(transport is not None and transport["bytes"] == member["bytes"]
                and transport["sha256"] == member["sha256"] and member["role"] in ("test", "companion", "library"), "Runtime transport/member mismatch")
        expected_capsule_files.add(name)
    actual_capsule_files = {item["path"] for item in manifest["members"] if item["path"].startswith(capsule_dir + "/")}
    require(actual_capsule_files == expected_capsule_files, "Unexpected capsule transport member")

    def download(binding_record, expected_name, directory):
        receipt = reader.bound_json(binding_record)
        artifact = receipt["artifact"]
        require(type(receipt["exit"]) is int and receipt["exit"] == 0
                and artifact == artifacts[artifact["id"]] and artifact["name"] == expected_name
                and artifact["expired"] is False
                and artifact["workflow_run"]["id"] == int(binding["run_id"])
                and artifact["workflow_run"]["head_sha"] == binding["commit"]
                and re.fullmatch("sha256:[0-9a-f]{64}", artifact["digest"]), "Artifact API/download custody")
        require(Path(receipt["path"]) == reader.path(directory), "Download extraction location")
        validate_download_command(receipt["command"], expected_name, reader.path(directory), binding["run_id"])
        return artifact["id"]

    prefix = f"{binding['os']}-{binding['configuration']}-{binding['run_id']}-{binding['run_attempt']}"
    capsule_directory = str(PurePosixPath(request["capsule"]["path"]).parent)
    download(request["capsule_download"], "test-capsule-" + prefix, capsule_directory)
    require(len(request["shards"]) == 8 and {item["shard"] for item in request["shards"]} == set(range(8)), "Eight distinct shards required")
    covered, failed, ignored, executions, used_jobs = [], [], [], [], set()
    for spec in sorted(request["shards"], key=lambda item: item["shard"]):
        shard = spec["shard"]
        require(type(shard) is int and spec["job_id"] not in used_jobs, "Shard/job duplicate or bool")
        used_jobs.add(spec["job_id"])
        job = jobs[spec["job_id"]]
        require(job["run_id"] == int(binding["run_id"]) and job["status"] == "completed"
                and job["conclusion"] in ("success", "failure"), "Shard API terminal custody")
        artifact_id = download(spec["download"], "test-receipt-" + prefix + "-" + str(shard), spec["directory"])
        name = spec["directory"] + f"/shard-{shard}.json"
        receipt = json.loads(reader.transported(name, META))
        require(type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["shard"] == shard
                and receipt["binding"] == binding and receipt["capsule_sha256"] == capsule_sha
                and receipt["state"] in ("PASS", "INCOMPLETE"), "Shard receipt identity")
        require((receipt["state"] == "PASS" and receipt["error"] is None and job["conclusion"] == "success")
                or (receipt["state"] == "INCOMPLETE" and isinstance(receipt["error"], str) and job["conclusion"] == "failure"), "Original verdict/API mismatch")
        for command in receipt["commands"]:
            terminal(command)
            if "--list" in command["argv"]:
                require(command["exit_code"] == 0, "Failed inventory command")
        actual = []
        shard_covered = []
        executed_commands = []
        for execution in receipt["executions"]:
            target, names, command = execution["target"], execution["assigned_names"], execution["command"]
            require(target in capsule["targets"] and names and names == sorted(set(names))
                    and command in receipt["commands"], "Foreign/duplicate execution")
            path_type = PureWindowsPath if binding["os"] == "Windows" else PurePosixPath
            exe = str(path_type(binding["workspace"]) / relative(capsule["targets"][target]))
            require(command["argv"] == [exe, "--exact", *names], "Foreign/list-only execution")
            terminal(command)
            executed_commands.append(command)
            if binding["os"] == "Linux" and binding["configuration"] == "all-features" and target.startswith("test:memory:") and WRITER in names:
                limit = command["timeout_limit_seconds"]
                require(names == [WRITER] and type(limit) in (int, float) and 0 < limit <= 30, "Writer timeout gate drift")
            filename = execution["stdout_file"]
            require(isinstance(filename, str) and "/" not in filename and "\\" not in filename
                    and filename.startswith(f"shard{shard}-") and filename.endswith("-run.stdout"), "Foreign stdout path")
            raw = reader.transported(spec["directory"] + "/" + filename, LOG)
            require(hashlib.sha256(raw).hexdigest() == execution["stdout_sha256"], "Execution stdout drift")
            states = transcript(raw, names, target, command["exit_code"])
            actual.extend([[target, name] for name in names])
            positives = [[target, name] for name in states["ok"]]
            shard_covered.extend(positives)
            covered.extend(positives)
            failed.extend([[target, name] for name in states["FAILED"]])
            ignored.extend([[target, name] for name in states["ignored"]])
            require(execution["positive_actual"] == states["ok"] or execution["positive_actual"] == [], "Fabricated receipt positive")
            executions.append({"shard": shard, "artifact_id": artifact_id, "target": target,
                               "exit_code": command["exit_code"], "stdout_sha256": execution["stdout_sha256"],
                               "covered": states["ok"], "failed": states["FAILED"], "ignored": states["ignored"]})
        require(sorted(actual) == capsule["plan"][shard], "Missing/extra execution or test")
        require(len(executed_commands) == len({canonical(command) for command in executed_commands})
                and sorted(canonical(command) for command in receipt["commands"] if "--list" not in command["argv"])
                == sorted(canonical(command) for command in executed_commands), "Unbound or duplicate execution command")
        for command in receipt["commands"]:
            if "--list" not in command["argv"]:
                continue
            argv = command["argv"]
            require(len(argv) >= 4 and argv[-3:] == ["--list", "--format", "terse"], "Foreign listing command")
            require(any(argv[0] == str((PureWindowsPath if binding["os"] == "Windows" else PurePosixPath)(binding["workspace"]) / relative(path))
                        for path in capsule["targets"].values()), "Foreign listing executable")
            require(len(argv) == 4 or (argv[1] == "--exact" and argv[2:-3]), "Unsupported listing selection")
        claimed = receipt["positive"]
        require(len(claimed) == len(set(map(tuple, claimed))) and all(item in shard_covered for item in claimed), "False original positive")
        if receipt["state"] == "PASS":
            require(sorted(claimed) == capsule["plan"][shard], "Original PASS missing coverage")
    require(len(covered + failed + ignored) == len(set(map(tuple, covered + failed + ignored))), "Duplicate outcome tuple")
    require(sorted(covered + failed + ignored) == inventory, "Outcome union mismatch")
    payloads = sorted(item for item in inventory if item[0] == TARGET and item[1] in IGNORED)
    require(sorted(ignored) == payloads, "Missing/extra ignored payload outcomes")
    parent_missing = []
    if payloads:
        parents = [item for item in inventory if item[0] == TARGET and item[1].startswith("contract::tests::") and item not in payloads]
        if [TARGET, "scm::metrics::tests::logical_io_child_payload"] in payloads:
            parents.append([TARGET, "scm::metrics::tests::retained_ordinary_child_final_logical_io_includes_terminal_writes"])
        parent_missing = sorted(item for item in parents if item not in covered)
    missing = sorted(item for item in inventory if item not in covered and item not in payloads)
    return {"schema": 1, "state": "RECONCILED", "gate_pass": False,
            "original_producer_verdict": api_run["conclusion"], "binding": binding,
            "capsule_sha256": capsule_sha, "inventory_sha256": capsule["inventory_sha256"],
            "source_manifest": source, "source_inventory_sha256": digest(source),
            "covered_positive_tuples": sorted(covered), "missing_tuples": missing,
            "failed_tuples": sorted(failed), "ignored_payload_tuples": payloads,
            "missing_parent_tuples": parent_missing, "executions": executions,
            "homologation_to_successor": "PENDING_SEPARATE_REVIEW_AND_NEW_CHANGED_TEST_EVIDENCE"}


def validate_download_command(command, artifact_name, directory, run_id):
    terminal(command)
    argv = command["argv"]
    require(command["exit_code"] == 0 and len(argv) == 10 and Path(argv[0]).name.lower() in ("gh", "gh.exe")
            and argv[1:4] == ["run", "download", run_id], "Real download command required")
    options = dict(zip(argv[4::2], argv[5::2], strict=True))
    require(len(options) == 3 and options == {"--repo": REPOSITORY, "--name": artifact_name, "--dir": str(directory)}, "Download command scope")


def write_new(path, value):
    raw = canonical(value)
    require(len(raw) <= META and not path.exists(), "Exclusive bounded output required")
    no_alias(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    no_alias(path)
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def prepare(args):
    reader = Inputs(args.evidence_root)
    args.output = args.output.absolute()
    require(args.os in PRODUCER_RUNS and args.run_id == PRODUCER_RUNS[args.os]
            and args.run_attempt == "1" and args.configuration in ("featureless", "all-features"), "Declared producer scope")

    def pin(name):
        raw = reader.read(reader.path(name), META)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    api = {name: pin("api-" + name + ".json") for name in ("run", "jobs", "artifacts")}
    run = reader.bound_json(api["run"])
    require(run["id"] == int(args.run_id) and run["run_attempt"] == 1 and run["head_sha"] == PRODUCER_COMMIT
            and run["repository"]["full_name"] == REPOSITORY and run["status"] == "completed", "Prepare producer API identity")
    artifacts = reader.bound_json(api["artifacts"])["artifacts"]
    require(len(artifacts) <= 100 and len({item["id"] for item in artifacts}) == len(artifacts), "Artifact API bounds")
    artifacts = {item["id"]: item for item in artifacts}
    jobs = reader.bound_json(api["jobs"])["jobs"]
    require(len(jobs) <= 100 and len({job["id"] for job in jobs}) == len(jobs), "Job API bounds")

    def job_id(kind, shard=None):
        if args.os == "Windows":
            name = kind if shard is None else kind + f" ({shard})"
        else:
            suffix = args.configuration if shard is None else args.configuration + f", {shard}"
            name = kind + " (" + suffix + ")"
        matches = [job for job in jobs if job["name"] == name and job["run_id"] == int(args.run_id)]
        require(len(matches) == 1, "Unique producer job required: " + name)
        return matches[0]["id"]

    prefix = f"{args.os}-{args.configuration}-{args.run_id}-1"
    directories = ["capsule", *(f"shards/{shard}" for shard in range(8))]
    downloads = []
    for index, directory in enumerate(directories):
        key = "capsule" if index == 0 else "shard-" + str(index - 1)
        record = pin("downloads/" + key + ".json")
        receipt = reader.bound_json(record)
        name = "test-capsule-" + prefix if index == 0 else "test-receipt-" + prefix + "-" + str(index - 1)
        artifact = receipt["artifact"]
        require(type(receipt["exit"]) is int and receipt["exit"] == 0 and artifact == artifacts[artifact["id"]]
                and artifact["name"] == name and artifact["expired"] is False
                and artifact["workflow_run"]["id"] == int(args.run_id)
                and artifact["workflow_run"]["head_sha"] == PRODUCER_COMMIT
                and Path(receipt["path"]) == reader.path(directory), "Prepare actual download custody")
        validate_download_command(receipt["command"], name, reader.path(directory), args.run_id)
        downloads.append(record)
    members = []
    total = 0
    for directory in directories:
        require(reader.path(directory).is_dir(), "Missing extracted artifact directory")
        for path in sorted(reader.path(directory).rglob("*")):
            reader.check()
            no_alias(path)
            if path.is_dir():
                continue
            before = path.stat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and 0 <= before.st_size <= MEMBER, "Prepared transport type/size/alias")
            total += before.st_size
            require(total <= TOTAL and len(members) < 2048, "Prepared transport aggregate cap")
            value = hashlib.sha256()
            remaining = before.st_size
            with path.open("rb") as stream:
                while remaining:
                    reader.check()
                    raw = stream.read(min(1024 * 1024, remaining))
                    require(raw, "Prepared transport shrank")
                    remaining -= len(raw)
                    value.update(raw)
                require(not stream.read(1), "Prepared transport grew")
            after = path.stat()
            require(before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns, "Prepared transport drift")
            members.append({"path": path.relative_to(reader.root).as_posix(), "bytes": before.st_size, "sha256": value.hexdigest()})
    manifest_name = "prepared-transport-manifest.json"
    manifest_sha = write_new(reader.path(manifest_name), {"schema": 1, "members": sorted(members, key=lambda item: item["path"])})
    capsule_pin = pin("capsule/capsule.json")
    binding = reader.bound_json(capsule_pin)["binding"]
    require(binding["commit"] == PRODUCER_COMMIT and binding["run_id"] == args.run_id
            and binding["run_attempt"] == "1" and binding["os"] == args.os
            and binding["configuration"] == args.configuration and binding["helper_sha256"] == OLD_HELPER, "Prepare capsule binding")
    request = {"schema": 1, "binding": binding, "evidence_root": str(reader.root),
               "source_root": str(Path(args.source_root).absolute()), "capsule": capsule_pin,
               "api_run": api["run"], "api_jobs": api["jobs"], "api_artifacts": api["artifacts"],
               "transport_manifest": {"path": manifest_name, "sha256": manifest_sha},
               "capsule_download": downloads[0], "build_job_id": job_id("correctness-build"),
               "shards": [{"shard": shard, "job_id": job_id("correctness-shards", shard),
                           "directory": f"shards/{shard}", "download": downloads[shard + 1]} for shard in range(8)]}
    require(not args.output.absolute().is_relative_to(Path(args.source_root).absolute()), "Preparation output inside source")
    request_sha = write_new(args.output, request)
    write_new(args.output.with_name(args.output.name + ".sha256.json"),
              {"schema": 1, "request": str(args.output.absolute()), "sha256": request_sha})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--request", type=Path)
    parser.add_argument("--request-sha256")
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--os", choices=("Windows", "Linux"))
    parser.add_argument("--configuration", choices=("featureless", "all-features"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.prepare:
        require(all(value is not None for value in (args.evidence_root, args.source_root, args.run_id,
                    args.run_attempt, args.os, args.configuration)), "Prepare arguments")
        prepare(args)
        return
    require(args.request is not None and args.request_sha256 is not None, "Consume request arguments")
    require(re.fullmatch("[0-9a-f]{64}", args.request_sha256), "Request SHA shape")
    require(not args.output.exists(), "Exclusive new output required")
    no_alias(args.output)
    bootstrap = Inputs(args.request.parent.absolute())
    request = json.loads(bootstrap.read(args.request.absolute(), META, args.request_sha256))
    require(not args.output.absolute().is_relative_to(Path(request["source_root"]).absolute()), "Output must stay outside source checkout")
    result = reconcile(request)
    result.update(request_sha256=args.request_sha256,
                  consumer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    raw = canonical(result)
    require(len(raw) <= META, "Output metadata cap")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    no_alias(args.output)
    with args.output.open("xb") as stream:
        stream.write(raw)


if __name__ == "__main__":
    main()
