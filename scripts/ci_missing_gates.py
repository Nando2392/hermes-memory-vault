"""Run only the new Windows owner fixture; no suite or deployment execution."""

import argparse
import json
import os
from pathlib import Path

import ci_test_shards as gate


TEST = "windows_enrollment::tests::user_owned_open_handle_is_rejected_without_acl_changes"
D4 = "7a0803c71bb13b6317540411b0f85fb838726502"
REPOSITORY = "Nando2392/hermes-memory-vault"
CHANGED_PINS = {
    "scripts/ci_test_shards.py": "7a652ff4c3b393738c9eadd35709e1751290ac5f8637106bdb3030e9e40a659b",
    "python_tests/test_ci_test_shards.py": "3d6e8a5ba3f2c507a5f06f8f95f2440704a51ed80a04ab019d0ddd99b54d154e",
    "src/windows_enrollment.rs": "67bb075e23690e7c06a171e93e2bcebc98a1e175b99b4a9232d689dbe8582346",
}


def bounded_bytes(path, cap, require_single_link=True):
    gate.no_reparse(path)
    gate.require(path.is_file() and path.stat().st_size <= cap, "Bounded regular input required")
    if require_single_link:
        gate.require(path.stat().st_nlink == 1, "Independent input required")
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    gate.require(len(raw) <= cap, "Input grew beyond cap")
    return raw


def verify_repair(repaired, repair):
    root = repaired.absolute().parent
    executable = Path(repair["executable"]["path"])
    gate.require(executable.is_absolute() and executable.is_relative_to(Path.cwd() / "target"), "Foreign fixture executable")
    specifications = [
        ("format-new-fixture", ["rustfmt", "--check", "--edition", "2021", "src/windows_enrollment.rs"], 30),
        ("compile-new-fixture", ["cargo", "test", "--locked", "--lib", "--all-features", "--no-run", "--message-format=json"], 360),
        ("list-new-fixture", [str(executable), TEST, "--exact", "--list", "--format", "terse"], 30),
        ("run-new-fixture", [str(executable), TEST, "--exact"], 30),
    ]
    commands, streams = [], {}
    for prefix, argv, limit in specifications:
        receipt_path = root / (prefix + ".json")
        gate.no_reparse(receipt_path)
        receipt = gate.read_json(receipt_path)
        gate.require(gate.success(receipt) and receipt["argv"] == argv
                     and receipt["timeout_limit_seconds"] == limit, "New fixture command identity/terminal mismatch")
        stdout_path = root / (prefix + ".stdout")
        raw = bounded_bytes(stdout_path, gate.LOG)
        gate.require(gate.sha(raw) == receipt["stdout_sha256"], "New fixture stdout changed")
        streams[prefix] = raw
        commands.append(receipt)
    gate.require(repair["commands"] == commands, "New fixture command ledger drift")
    gate.require(gate.listed(streams["list-new-fixture"]) == [TEST], "New fixture exact listing mismatch")
    gate.require(gate.positive(streams["run-new-fixture"], [TEST]) == repair["positive"], "New fixture actual positive mismatch")
    matches = []
    for line in streams["compile-new-fixture"].decode("utf-8", errors="strict").splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-artifact" and event.get("executable") == str(executable):
            matches.append(event)
    gate.require(len(matches) == 1 and matches[0]["target"]["kind"] == ["lib"]
                 and matches[0]["profile"]["test"] is True
                 and matches[0]["features"] == ["experimental-broker"]
                 and Path(matches[0]["target"]["src_path"]) == Path.cwd() / "src/lib.rs", "Fixture compiler artifact mismatch")
    proof = root / "fixture-harness.exe"
    gate.verify_member(proof, repair["executable"])


def consume(request, output):
    pin = gate.read_json(Path(str(request) + ".sha256.json"))
    gate.require(Path(pin["request"]).absolute() == request.absolute(), "Request pin path mismatch")
    gate.require(pin["sha256"] == gate.sha(bounded_bytes(request, gate.META)), "Request pin mismatch")
    logs = output.with_name(output.name + "-reader-proof")
    gate.require(not logs.exists() and not output.exists(), "Exclusive consumer output")
    receipt, _, _ = gate.execute(["python", str(Path(__file__).with_name("ci_reconcile_prior.py")),
                                 "--request", str(request), "--request-sha256", pin["sha256"],
                                 "--output", str(output)], logs, "reconcile", 120)
    gate.save(logs / "command.json", receipt)
    gate.require(gate.success(receipt), "Prior evidence reader failed")


def admit(prior, repaired, output):
    gate.require(not output.exists(), "Exclusive admission output")
    result = {"schema": 1, "scope": "D4-ordinary-correctness-plus-new-owner-fixture",
              "gate_pass": False, "release_ready": False, "inputs": []}
    keys = set()
    for path in prior:
        value = gate.read_json(path)
        gate.require(value["state"] == "RECONCILED" and value["gate_pass"] is False, "Reader is not a release gate")
        identity = value["binding"]
        key = (identity["os"], identity["configuration"])
        gate.require(key not in keys and identity["commit"] == D4 and identity["run_attempt"] == "1", "Prior identity mismatch")
        keys.add(key)
        gate.require(identity["run_id"] == ("37550081745" if identity["os"] == "Linux" else "37550081788"), "Producer run mismatch")
        reviewed_changes = set(CHANGED_PINS)
        workspace = Path.cwd()
        original_paths = {item["path"] for item in value["source_manifest"]}
        current_paths = {path.relative_to(workspace).as_posix() for path in gate.source_inputs(workspace)}
        gate.require(original_paths <= current_paths, "Removed original source input")
        gate.require(current_paths - original_paths <= {"scripts/ci_reconcile_prior.py", "scripts/ci_missing_gates.py",
                                                        ".github/workflows/controlled-followup.yml"}, "Unreviewed new source input")
        for item in value["source_manifest"]:
            if item["path"] not in reviewed_changes:
                source = workspace / item["path"]
                gate.no_reparse(source)
                gate.require(gate.sha(bounded_bytes(source, gate.MEMBER)) == item["sha256"], "Unchanged source drift")
        for name, expected in CHANGED_PINS.items():
            gate.require(gate.sha(bounded_bytes(workspace / name, gate.META)) == expected, "Reviewed changed source drift")
        gate.require(value["missing_parent_tuples"] == [], "Missing mandatory fixture parent")
        if key == ("Windows", "all-features"):
            missing = value["missing_tuples"]
            gate.require(len(missing) == 1 and missing[0][0].startswith("lib:") and missing[0][1] == TEST
                         and value["failed_tuples"] == missing, "Windows has unresolved failures beyond changed fixture")
        else:
            gate.require(value["original_producer_verdict"] == "success", "Linux producer did not succeed")
            gate.require(value["missing_tuples"] == [] and value["failed_tuples"] == [], "Prior configuration is incomplete")
        result["inputs"].append({"path": str(path.absolute()), "sha256": gate.sha(bounded_bytes(path, gate.META)), "binding": identity})
    gate.require(keys == {("Linux", "featureless"), ("Linux", "all-features"), ("Windows", "all-features")}, "Missing configuration")
    repair = gate.read_json(repaired)
    gate.require(repair["pass"] is True and repair["positive"] == [TEST]
                 and repair["binding"] == gate.binding("all-features"), "New fixture/source identity mismatch")
    verify_repair(repaired, repair)
    result["repair"] = {"path": str(repaired.absolute()), "sha256": gate.sha(bounded_bytes(repaired, gate.META)), "binding": repair["binding"]}
    result["trust_root"] = "Reviewed carrier manifest published at actual checkout Git HEAD/GITHUB_SHA; all current source files bound identically across phases"
    result["gate_pass"] = True
    gate.save(output, result)


def fetch_prior(output, platform, configuration):
    """Acquire original producer evidence without asserting its gates passed."""
    output = output.absolute()
    gate.no_reparse(output)
    gate.require(not output.exists(), "Exclusive evidence output required")
    gate.require(os.environ.get("GITHUB_ACTIONS") == "true"
                 and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "Hosted required")
    gate.require(platform in ("Linux", "Windows") and configuration in ("featureless", "all-features"), "Scope")
    gate.require(platform != "Windows" or configuration == "all-features", "No invented Windows featureless producer")
    run = "37550081745" if platform == "Linux" else "37550081788"
    output.mkdir(parents=True)
    downloads = output / "downloads"
    downloads.mkdir()
    try:
        apis = {}
        for name, suffix in (("run", ""), ("jobs", "/jobs?per_page=100"), ("artifacts", "/artifacts?per_page=100")):
            argv = ["gh", "api", "repos/" + REPOSITORY + "/actions/runs/" + run + suffix]
            receipt, stdout, _ = gate.execute(argv, output, "api-" + name, 30)
            gate.save(output / ("api-" + name + "-command.json"), receipt)
            gate.require(gate.success(receipt), "API acquisition incomplete")
            value = json.loads(stdout)
            (output / ("api-" + name + ".json")).write_bytes(stdout)
            apis[name] = value
        metadata = apis["run"]
        gate.require(str(metadata["id"]) == run and metadata["head_sha"] == D4
                     and metadata["run_attempt"] == 1 and metadata["status"] == "completed", "Original producer identity/terminal mismatch")
        for name, key in (("jobs", "jobs"), ("artifacts", "artifacts")):
            gate.require(apis[name]["total_count"] == len(apis[name][key]), "API pagination incomplete")
        prefix = platform + "-" + configuration + "-" + run + "-1"
        wanted = ["test-capsule-" + prefix] + ["test-receipt-" + prefix + "-" + str(i) for i in range(8)]
        items = [item for item in apis["artifacts"]["artifacts"] if item["name"] in wanted]
        gate.require(len(items) == 9 and len({item["name"] for item in items}) == 9, "Missing/duplicate producer artifacts")
        gate.require(all(not item["expired"] for item in items)
                     and sum(item["size_in_bytes"] for item in items) <= 6 * 1024**3, "Artifact availability/size cap")
        for index, item in enumerate(sorted(items, key=lambda entry: entry["name"])):
            is_capsule = item["name"].startswith("test-capsule-")
            shard = item["name"].rsplit("-", 1)[-1]
            directory = output / "capsule" if is_capsule else output / "shards" / shard
            argv = ["gh", "run", "download", run, "--repo", REPOSITORY, "--name", item["name"], "--dir", str(directory)]
            receipt, _, _ = gate.execute(argv, output, "download-" + str(index), 120)
            gate.save(downloads / ("capsule.json" if is_capsule else "shard-" + shard + ".json"),
                      {"artifact": item, "exit": receipt["exit_code"], "path": str(directory), "command": receipt})
            gate.require(gate.success(receipt), "Artifact download incomplete")
    finally:
        gate.save(output / "fetch-scope.json", {"schema": 1, "producer_commit": D4,
                  "run_id": run, "os": platform, "configuration": configuration,
                  "gate_pass": False})


def fixture(output):
    output = output.absolute()
    gate.no_reparse(output)
    gate.require(not output.exists(), "Exclusive output required")
    identity = gate.binding("all-features")
    gate.require(identity["os"] == "Windows" and identity["image_os"] == "win22", "Windows 2022 required")
    output.mkdir(parents=True)
    result = {"schema": 1, "scope": "single-new-owner-fixture", "binding": identity,
              "helper_sha256": gate.sha(bounded_bytes(Path(__file__), gate.META)), "commands": [],
              "pass": False, "release_ready": False}

    def command(argv, name, limit):
        receipt, stdout, _ = gate.execute(argv, output, name, limit)
        receipt["stdout_sha256"] = gate.sha(stdout)
        result["commands"].append(receipt)
        gate.save(output / (name + ".json"), receipt)
        gate.require(gate.success(receipt), name + " failed or incomplete")
        return stdout

    try:
        command(["rustfmt", "--check", "--edition", "2021", "src/windows_enrollment.rs"], "format-new-fixture", 30)
        # D4's production clippy gate passed. Only cfg(test) fixture changed;
        # the following exact library compile checks its native binding types.
        raw = command(["cargo", "test", "--locked", "--lib", "--all-features", "--no-run", "--message-format=json"], "compile-new-fixture", 360)
        workspace = Path(identity["workspace"])
        candidates = []
        for line in raw.decode("utf-8", errors="strict").splitlines():
            event = json.loads(line)
            if event.get("reason") != "compiler-artifact" or not event.get("executable"):
                continue
            target = event["target"]
            if target["kind"] == ["lib"] and event["profile"]["test"] is True:
                gate.require(event.get("features") == ["experimental-broker"], "Feature mismatch")
                source = Path(target["src_path"]).absolute()
                gate.require(source == workspace / "src/lib.rs", "Foreign library target")
                executable = Path(event["executable"]).absolute()
                gate.require(executable.is_relative_to(workspace / "target"), "Executable outside target")
                gate.no_reparse(executable)
                candidates.append(executable)
        gate.require(len(candidates) == 1, "Exactly one compiled library harness required")
        executable = candidates[0]
        gate.require(executable.stat().st_size <= gate.MEMBER, "Fixture executable cap")
        # Cargo may hardlink its public EXE and hashed dependency artifact.
        # Read/hash the original only; the retained proof copy is independent.
        executable_bytes = bounded_bytes(executable, gate.MEMBER, require_single_link=False)
        with (output / "fixture-harness.exe").open("xb") as stream:
            stream.write(executable_bytes)
        result["executable"] = {"path": str(executable), "sha256": gate.sha(executable_bytes), "bytes": len(executable_bytes)}
        gate.verify_member(executable, result["executable"], require_single_link=False)
        listing = command([str(executable), TEST, "--exact", "--list", "--format", "terse"], "list-new-fixture", 30)
        gate.require(gate.listed(listing) == [TEST], "Missing/ambiguous exact fixture")
        gate.verify_member(executable, result["executable"], require_single_link=False)
        positive = command([str(executable), TEST, "--exact"], "run-new-fixture", 30)
        gate.verify_member(executable, result["executable"], require_single_link=False)
        result["positive"] = gate.positive(positive, [TEST])
        gate.require(gate.binding("all-features") == identity, "Source/binding changed")
        result["pass"] = True
    except Exception as error:
        result["error"] = str(error)[:2048]
        raise
    finally:
        gate.save(output / "result.json", result)


def identity_probe(output, admission):
    output = output.absolute()
    gate.no_reparse(output)
    gate.require(not output.exists(), "Exclusive probe output")
    identity = gate.binding("all-features")
    admitted = gate.read_json(admission)
    gate.require(admitted["gate_pass"] is True and admitted["repair"]["binding"] == identity,
                 "Scoped correctness admission required")
    gate.require(identity["os"] == "Windows" and identity["image_os"] == "win22", "Disposable Windows 2022 required")
    output.mkdir(parents=True)
    result = {"schema": 1, "binding": identity, "pass": False, "release_ready": False}
    try:
        build, _, _ = gate.execute(["cargo", "build", "--locked", "--release", "--features", "experimental-broker",
                                    "--example", "windows-identity-probe", "--bin", "hermes-memory-broker",
                                    "--bin", "hermes-memory-client"], output, "build-distinct-identity-release", 600)
        gate.save(output / "build-command.json", build)
        gate.require(gate.success(build), "Identity release build failed")
        executable = Path.cwd() / "target/release/examples/windows-identity-probe.exe"
        gate.no_reparse(executable)
        executable_raw = bounded_bytes(executable, gate.MEMBER, require_single_link=False)
        executable_member = {"bytes": len(executable_raw), "sha256": gate.sha(executable_raw)}
        result["executable_sha256"] = executable_member["sha256"]
        acl_script = ('@("$env:SystemDrive\\", $env:ProgramData) | ForEach-Object { '
                      '$acl = Get-Acl -LiteralPath $_ -ErrorAction Stop; '
                      '[pscustomobject]@{path=$_;owner=$acl.Owner;sddl=$acl.Sddl} '
                      '} | ConvertTo-Json -Depth 4')
        acl, acl_raw, _ = gate.execute(["pwsh", "-NoProfile", "-NonInteractive", "-Command", acl_script],
                                       output, "windows-ancestor-acls", 30)
        gate.save(output / "ancestor-acls-command.json", acl)
        gate.require(gate.success(acl), "Ancestor ACL evidence unavailable")
        gate.require(len(json.loads(acl_raw)) == 2, "Ancestor ACL evidence incomplete")
        (output / "windows-ancestor-acls.json").write_bytes(acl_raw)
        gate.verify_member(executable, executable_member, require_single_link=False)
        receipt, raw, _ = gate.execute([str(executable), "--run", "--allow-disposable-services"], output, "identity", 180)
        gate.save(output / "probe-command.json", receipt)
        gate.verify_member(executable, executable_member, require_single_link=False)
        gate.require(gate.success(receipt), "Identity failed/incomplete; no cleanup success claimed")
        report = json.loads(raw)
        gate.require(report["report"]["status"] == "BOUNDED_SCOPE_COMPLETED" and report["cleanup_errors"] == [], "Identity or cleanup incomplete")
        gate.require(gate.binding("all-features") == identity, "Identity source changed")
        result["pass"] = True
    except Exception as error:
        result["error"] = str(error)[:2048]
        raise
    finally:
        gate.save(output / "result.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["windows-fixture", "fetch-prior", "consume", "admit", "identity"])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--os", choices=["Linux", "Windows"])
    parser.add_argument("--configuration", choices=["featureless", "all-features"])
    parser.add_argument("--request", type=Path)
    parser.add_argument("--prior", nargs="+", type=Path)
    parser.add_argument("--repaired", type=Path)
    parser.add_argument("--admission", type=Path)
    args = parser.parse_args()
    gate.require(os.environ.get("GITHUB_REF") == "refs/heads/test/full64-controlled-followup", "Reviewed branch required")
    if args.command == "fetch-prior":
        fetch_prior(args.output, args.os, args.configuration)
    elif args.command == "consume":
        consume(args.request, args.output)
    elif args.command == "admit":
        admit(args.prior, args.repaired, args.output)
    elif args.command == "identity":
        identity_probe(args.output, args.admission)
    else:
        fixture(args.output)


if __name__ == "__main__":
    main()
