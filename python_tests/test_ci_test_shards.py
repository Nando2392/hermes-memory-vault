"""New pure falsification controls for exact shard custody; no binaries invoked."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ci_test_shards as gate


class IgnoredFixtureAdmissionTests(unittest.TestCase):
    def test_new_exact_payload_classification_preserves_parent_and_foreign_target(self):
        payload = "contract::tests::capture_sleeper"
        parent = "contract::tests::measured_command_retains_real_child_io_and_memory_without_changing_legacy"
        inventory = sorted([[gate.FIXTURE_TARGET, payload], [gate.FIXTURE_TARGET, parent],
                            ["test:foreign:tests/foreign.rs", payload]])
        planned = sorted(item for shard in gate.plan(inventory) for item in shard)
        self.assertEqual(planned, sorted([[gate.FIXTURE_TARGET, parent],
                                         ["test:foreign:tests/foreign.rs", payload]]))
        self.assertEqual(gate.validate_ignored_listing(gate.FIXTURE_TARGET, [payload, parent], [payload]), [payload])
        for target, ignored in [(gate.FIXTURE_TARGET, []), (gate.FIXTURE_TARGET, ["unknown_ignored"]),
                                ("test:foreign:tests/foreign.rs", [payload])]:
            with self.assertRaises(ValueError):
                gate.validate_ignored_listing(target, [payload, parent], ignored)

    def test_new_runtime_ignored_is_still_rejected(self):
        raw = ("test parent ... ok\ntest payload ... ignored, fixture\n"
               "test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n").encode()
        with self.assertRaises(ValueError):
            gate.positive(raw, ["parent", "payload"])

    def test_new_missing_fixture_parent_is_not_a_positive(self):
        value = {"binding": {"os": "Windows", "configuration": "all-features"},
                 "inventory": [[gate.FIXTURE_TARGET, "contract::tests::capture_sleeper"],
                               [gate.FIXTURE_TARGET, "contract::tests::measured_command_retains_real_child_io_and_memory_without_changing_legacy"]],
                 "ignored_fixtures": [[gate.FIXTURE_TARGET, "contract::tests::capture_sleeper"]]}
        with self.assertRaisesRegex(ValueError, "Missing fixture parent"):
            gate.required_witnesses(value, [])


def fixture(inventory=None, configuration="featureless"):
    inventory = sorted(inventory or [["test:first:tests/first.rs", "same_name"],
                        ["test:second:tests/second.rs", "same_name"],
                        ["test:second:tests/second.rs", "other_name"]])
    value = {"binding": {"configuration": configuration, "commit": "a" * 40,
                         "workspace": "/synthetic-workspace", "os": "Linux"},
             "inventory": inventory, "plan": gate.plan(inventory),
             "targets": {target: "target/" + str(index) for index, target in enumerate(sorted({t for t, _ in inventory}))}}
    receipts = []
    for shard, assigned in enumerate(value["plan"]):
        commands, executions = [], []
        for index, target in enumerate(sorted({target for target, _ in assigned})):
            names = sorted(name for current, name in assigned if current == target)
            command = {"exit_code": 0, "settled": True, "capture_complete": True,
                       "timed_out": False, "errors": [], "timeout_limit_seconds": 30,
                       "argv": [str(gate.Path(value["binding"]["workspace"]) / value["targets"][target]), "--exact", *names]}
            commands.append(command)
            executions.append({"target": target, "assigned_names": names, "command": command,
                               "stdout_file": f"shard{shard}-target{index}-group0-run.stdout",
                               "stdout_sha256": "f" * 64, "positive_actual": names})
        receipts.append({"schema": 1, "binding": value["binding"], "shard": shard,
                         "capsule_sha256": "b" * 64, "state": "PASS", "error": None,
                         "positive": assigned, "commands": commands, "executions": executions})
    return value, receipts


class ShardGateTests(unittest.TestCase):
    def test_new_included_json_changes_source_fingerprint_and_fixture_alias_is_rejected(self):
        parent = Path(__file__).resolve().parents[2] / "proof/helper-transport-temp"
        parent.mkdir(exist_ok=True)
        gate.no_reparse(parent)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            fixture_path = root / "examples/tests/cadence/clock-oracle.json"
            fixture_path.parent.mkdir(parents=True)
            fixture_path.write_bytes(b'{"clock":1}')
            for name in ("Cargo.toml", "Cargo.lock"):
                (root / name).write_bytes(b"synthetic input")
            def fingerprint():
                return gate.digest([{ "path": p.relative_to(root).as_posix(), "sha256": gate.sha(p.read_bytes()) }
                                    for p in gate.source_inputs(root)])
            first = fingerprint()
            self.assertIn(fixture_path, gate.source_inputs(root))
            fixture_path.write_bytes(b'{"clock":2}')
            self.assertNotEqual(first, fingerprint())
            real = root / "own-alias-target"
            real.mkdir()
            alias = root / "examples/fixture-alias"
            if os.name == "nt":
                result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(real)],
                                        capture_output=True, check=False, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                try:
                    with self.assertRaises(ValueError):
                        gate.source_inputs(root)
                finally:
                    os.rmdir(alias)
            else:
                alias.symlink_to(real, target_is_directory=True)
                with self.assertRaises(ValueError):
                    gate.source_inputs(root)

    def test_new_transport_allows_readonly_source_alias_and_rejects_restored_alias(self):
        parent = Path(__file__).resolve().parents[2] / "proof/helper-transport-temp"
        parent.mkdir(exist_ok=True)
        gate.no_reparse(parent)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            source, alias, staged = (root / name for name in ("source", "source-alias", "staged"))
            raw = b"synthetic transport control; never executable"
            source.write_bytes(raw)
            os.link(source, alias)
            member = {"bytes": len(raw), "sha256": gate.sha(raw)}
            self.assertEqual(source.stat().st_nlink, 2)
            gate.stage_member(source, staged, member)
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(alias.read_bytes(), raw)
            self.assertEqual(staged.stat().st_nlink, 1)
            self.assertNotEqual(staged.stat().st_ino, source.stat().st_ino)
            gate.verify_member(staged, member)
            os.link(staged, root / "restored-alias")
            with self.assertRaises(ValueError):
                gate.verify_member(staged, member)

    def test_new_source_inventory_excludes_generated_cache_not_reviewed_inputs(self):
        parent = Path(__file__).resolve().parents[2] / "proof/helper-transport-temp"
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            cache = root / "scripts/__pycache__"
            cache.mkdir(parents=True)
            (cache / "generated.pyc").write_bytes(b"cache")
            (root / "scripts/input.py").write_bytes(b"# reviewed control input")
            paths = [path.relative_to(root).as_posix() for path in gate.source_inputs(root)]
            self.assertIn("scripts/input.py", paths)
            self.assertNotIn("scripts/__pycache__/generated.pyc", paths)

    def test_same_name_different_targets_remains_distinct_in_deterministic_union(self):
        value, receipts = fixture()
        self.assertEqual(value["plan"], gate.plan(list(reversed(value["inventory"]))))
        self.assertEqual(sorted(gate.validate_receipts(value, "b" * 64, receipts)), value["inventory"])
        self.assertEqual(sum(name == "same_name" for _, name in value["inventory"]), 2)

    def test_missing_duplicate_nonterminal_and_wrong_identity_receipts_rejected(self):
        value, receipts = fixture()
        variants = [receipts[:-1], receipts[:-1] + [receipts[0]]]
        for key, bad in (("state", "INCOMPLETE"), ("capsule_sha256", "c" * 64),
                         ("binding", {"configuration": "all-features", "commit": "a" * 40}),
                         ("binding", {"configuration": "featureless", "commit": "d" * 40}),
                         ("shard", True)):
            changed = copy.deepcopy(receipts)
            changed[0][key] = bad
            variants.append(changed)
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                gate.validate_receipts(value, "b" * 64, candidate)

    def test_missing_test_duplicate_test_and_fake_zero_coverage_rejected(self):
        value, receipts = fixture()
        index = next(i for i, receipt in enumerate(receipts) if receipt["positive"])
        for mode in ("missing", "duplicate", "no_commands", "wrong_target", "list_only"):
            changed = copy.deepcopy(receipts)
            current = changed[index]
            if mode == "missing":
                current["positive"] = []
            elif mode == "duplicate":
                current["positive"] += current["positive"]
            elif mode == "no_commands":
                current["commands"] = []
            elif mode == "wrong_target":
                current["positive"][0][0] = "test:foreign:tests/foreign.rs"
            else:
                current["commands"][0]["argv"] += ["--list"]
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                gate.validate_receipts(value, "b" * 64, changed)

    def test_runtime_requires_positive_exact_names_and_terminal_not_ignored(self):
        good = b"running 1 test\ntest exact_name ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out\n"
        self.assertEqual(gate.positive(good, ["exact_name"]), ["exact_name"])
        for raw in (good.replace(b"... ok", b"... ignored"), good.replace(b"exact_name", b"other_name"),
                    good.replace(b"1 passed", b"0 passed"), good.split(b"test result:")[0], good + good):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                gate.positive(raw, ["exact_name"])

    def test_false_terminal_timeout_bool_exit_and_wrong_path_rejected(self):
        value, receipts = fixture()
        index = next(i for i, receipt in enumerate(receipts) if receipt["positive"])
        for field, bad in (("exit_code", False), ("exit_code", 1), ("settled", False),
                           ("timed_out", True), ("capture_complete", False), ("errors", ["overflow"])):
            changed = copy.deepcopy(receipts)
            changed[index]["commands"][0][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                gate.validate_receipts(value, "b" * 64, changed)
        for path in ("../target/x", "target/../x", "/target/x", "target/x:ads", "target\\x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                gate.relative(path)

    def test_original_witness_absence_is_not_inherited_from_generic_green(self):
        value, receipts = fixture()
        value["binding"].update(os="Linux")
        with self.assertRaises(ValueError):
            gate.required_witnesses(value, gate.validate_receipts(value, "b" * 64, receipts))

    def test_writer_timeout_and_isolation_are_actual_execution_requirements(self):
        value, receipts = fixture([["test:memory:tests/memory.rs", gate.WRITER]], "all-features")
        gate.validate_receipts(value, "b" * 64, receipts)
        index = next(i for i, receipt in enumerate(receipts) if receipt["positive"])
        changed = copy.deepcopy(receipts)
        changed[index]["commands"][0]["timeout_limit_seconds"] = 31
        with self.assertRaises(ValueError):
            gate.validate_receipts(value, "b" * 64, changed)


if __name__ == "__main__":
    unittest.main()
