"""Ordinary producer controls and explicitly synthetic validator-only mutations."""

import copy
import json
from pathlib import Path
import unittest

from scripts import windows_broker_full8_validator as v

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "examples/windows_broker_benchmark/tests/cadence"


def load(name):
    return json.loads((CORPUS / name).read_bytes())


class Full8Tests(unittest.TestCase):
    def test_conditional_epoch_dependency_crossproduct(self):
        for name, report, accepted in epoch_dependency_cases():
            with self.subTest(synthetic_dependency=name):
                decoded = v.decode_report(json.dumps(report, ensure_ascii=True))
                original = copy.deepcopy(decoded)
                if accepted:
                    v.validate_structure(decoded)
                else:
                    with self.assertRaises((ValueError, UnicodeError)):
                        v.validate_structure(decoded)
                self.assertEqual(decoded, original)

    def test_epoch_correlation_encoded_caps_and_closed_scalars(self):
        control = load("case-closure/owner-control.json")
        for epoch in ("", "a" * 257, "é" * 129, "\0\n", "😀"):
            bad = copy.deepcopy(control)
            self.assertNotEqual(bad["case_epoch"], epoch)
            bad["case_epoch"] = epoch
            with self.assertRaises(ValueError):
                v.validate_structure(bad)
        for epoch in (17, True, 2.0, [], {}, "\ud800"):
            bad = load("manifest/pre-setup.json")
            bad["case_epoch"] = epoch
            with self.assertRaises((ValueError, UnicodeError)):
                v.validate_structure(v.decode_report(json.dumps(bad)))
        for character in ("a", "é", "\0"):
            for over in (0, 1):
                report = copy.deepcopy(control)
                cadence = report["operations"][0]["cadence"]
                cadence["case_epoch"] = ""
                budget = 32768 - len(v.encoded(cadence))
                width = len(v.encoded(character)) - 2
                epoch = character * (budget // width) + "a" * (budget % width + over)
                report["case_epoch"] = cadence["case_epoch"] = epoch
                self.assertEqual(len(v.encoded(cadence)), 32768 + over)
                if over:
                    with self.assertRaisesRegex(
                        ValueError, "Cadence interval byte cap"
                    ):
                        v.validate_structure(report)
                else:
                    v.validate_structure(report)

    def test_global_report_and_aggregate_cadence_caps_are_preserved(self):
        for over in (0, 1):
            report = load("manifest/pre-setup.json")
            report["diagnostics"]["synthetic_padding"] = ""
            budget = v.REPORT_LIMIT - len(v.encoded(report))
            report["diagnostics"]["synthetic_padding"] = "a" * (budget + over)
            raw = v.encoded(report)
            self.assertEqual(len(raw), v.REPORT_LIMIT + over)
            if over:
                with self.assertRaisesRegex(ValueError, "Report byte cap"):
                    v.decode_report(raw)
                with self.assertRaisesRegex(ValueError, "Report byte cap"):
                    v.validate_structure(report)
            else:
                v.validate_structure(v.decode_report(raw))
        # The aggregate bound is also implied by 64 individually bounded intervals.
        self.assertEqual(64 * 32768, 2097152)
        complete = load("seal/original_full64.json")
        self.assertLessEqual(
            sum(len(v.encoded(op["cadence"])) for op in complete["operations"]), 2097152
        )
        complete["operations"].append(copy.deepcopy(complete["operations"][-1]))
        with self.assertRaisesRegex(ValueError, "Operations bound"):
            v.validate_structure(complete)

    def test_native_epoch_admission_remains_independent_and_strict(self):
        report = load("seal/original_full64.json")
        report["native_handle_verified"] = True  # Synthetic admission-prefix only.
        pins = dict.fromkeys(("admin", "broker", "client"), "a" * 64)
        report["diagnostics"] = {
            "source_unchanged": True,
            "client_registration_deleted": True,
            "executable_sha256": pins,
            "fixture": {"root": "C:/synthetic", "client_service": "valid-1"},
            "plan": {},
        }
        # Valid admission reaches the NEXT prerequisite; this is not native success.
        for epoch in ("a", "a" * 256, "valid-1"):
            report["case_epoch"] = epoch
            report["diagnostics"]["fixture"]["client_service"] = epoch
            with self.assertRaises(KeyError) as next_prerequisite:
                v.validate_native_success(report, pins)
            self.assertEqual(next_prerequisite.exception.args, ("enrollment",))
        for epoch in (None, "", "a" * 257, "é", "\0\n", "😀", "a_b", "a/b", "a b"):
            report["case_epoch"] = epoch
            report["diagnostics"]["fixture"]["client_service"] = epoch
            with self.subTest(native_admission=repr(epoch)):
                with self.assertRaisesRegex(ValueError, "Full root/case epoch"):
                    v.validate_native_success(report, pins)
        report["case_epoch"] = "valid-2"
        report["diagnostics"]["fixture"]["client_service"] = "valid-1"
        with self.assertRaisesRegex(ValueError, "Full root/case epoch"):
            v.validate_native_success(report, pins)

    def test_workload_completion_requires_nonempty_correlated_epoch(self):
        control = load("seal/original_full64.json")
        for epoch in (None, "", "a" * 257, "é" * 129, "\0\n", "😀"):
            report = copy.deepcopy(control)
            report["case_epoch"] = epoch
            for operation in report["operations"]:
                operation["cadence"]["case_epoch"] = epoch
            with self.subTest(epoch=repr(epoch)):
                if epoch is None or epoch == "":
                    with self.assertRaises(ValueError):
                        v.validate_structure(report)
                else:
                    self.assertTrue(v.validate_structure(report)["correctness_pass"])

    def test_retained_prefix_comparison_requires_present_operations(self):
        # Retain actual intrinsic commands; remove only their optional owner evidence.
        for epoch in (None, "", "ordinary", "é" * 129, "\0\n"):
            report = load("manifest/post-generation.json")
            report["case_epoch"] = epoch
            report["controller_retained_commands"] = load(
                "case-closure/owner-control.json"
            )["controller_retained_commands"]
            original = copy.deepcopy(report)
            with self.subTest(epoch=repr(epoch)):
                self.assertFalse(v.validate_structure(report)["correctness_pass"])
                self.assertEqual(report, original)
                report["operations"] = []
                with self.assertRaises(ValueError):
                    v.validate_structure(report)
                report["operations"] = None
                report["controller_retained_commands"][0]["capture_complete"] = False
                with self.assertRaises(ValueError):
                    v.validate_structure(report)

    def test_structural_epoch_is_conditional_not_native_admission(self):
        epochs = (
            None,
            "",
            "a",
            "a" * 256,
            "a" * 257,
            "é" * 128,
            "é" * 129,
            "\0\n",
            "😀",
        )
        for name in (
            "manifest/pre-setup.json",
            "manifest/post-generation.json",
            "case-closure/owner-control.json",
            "seal/actual_genuine_retained_unknown_ack.json",
        ):
            for epoch in epochs:
                report = load(name)
                report["case_epoch"] = epoch
                if report["operations"] is not None:
                    for operation in report["operations"]:
                        operation["cadence"]["case_epoch"] = epoch
                raw = json.dumps(report, ensure_ascii=True).encode()
                with self.subTest(control=name, epoch=repr(epoch)):
                    decoded = v.decode_report(raw)
                    if epoch is None and report["operations"] is not None:
                        with self.assertRaises(ValueError):
                            v.validate_structure(decoded)
                    else:
                        original = copy.deepcopy(decoded)
                        self.assertFalse(
                            v.validate_structure(decoded)["correctness_pass"]
                        )
                        self.assertEqual(decoded, original)
        for epoch in ("", "a" * 257, "é" * 129, "\0\n", "😀"):
            report = load("manifest/post-generation.json")
            report.update(operations=[], case_epoch=epoch)
            self.assertFalse(v.validate_structure(report)["correctness_pass"])

    def test_retained_unknown_ack_cannot_erase_manifest_prerequisites(self):
        control = load("case-closure/owner-control.json")
        self.assertFalse(v.validate_structure(control)["correctness_pass"])
        expected = copy.deepcopy(control)
        expected["seed_records"] = expected["final_records"] = None
        witness = load("manifest/retained-seed-null.json")
        self.assertEqual(witness, expected)
        # Exact two-field genuine-negative witness, not a success-only gate.
        with self.assertRaisesRegex(ValueError, "Retained receipt manifest missing"):
            v.validate_structure(witness)

    def test_present_empty_operations_require_case_epoch(self):
        partial = load("manifest/post-generation.json")
        partial["operations"] = []
        with self.assertRaisesRegex(ValueError, "Cadence case epoch missing"):
            v.validate_structure(partial)

    def test_manifest_dependency_preserves_genuine_pre_setup_partials(self):
        for name in ("manifest/pre-setup.json", "manifest/post-generation.json"):
            control = load(name)
            self.assertFalse(v.validate_structure(control)["correctness_pass"])
            for retained in (None, []):
                partial = copy.deepcopy(control)
                partial["controller_retained_commands"] = retained
                partial["seed_records"] = partial["final_records"] = None
                self.assertFalse(v.validate_structure(partial)["correctness_pass"])
                # A present empty array still asks Rust to validate a manifest.
                partial["operations"] = []
                partial["case_epoch"] = "ordinary"
                with self.assertRaisesRegex(ValueError, "manifest seed missing"):
                    v.validate_structure(partial)
                partial["seed_records"], partial["final_records"] = 16, 5159
                self.assertFalse(v.validate_structure(partial)["correctness_pass"])

    def test_manifest_seed_final_partial_and_malformed_combinations(self):
        for name in (
            "manifest/pre-setup.json",
            "manifest/post-generation.json",
            "case-closure/owner-control.json",
        ):
            control = load(name)
            for seeds in (None, 16, 15, 400001, True, 16.0, "16", {}, []):
                for final in (None, 5159, 5158, True, 5159.0, "5159", {}, []):
                    report = copy.deepcopy(control)
                    report["seed_records"], report["final_records"] = seeds, final
                    expected = (
                        type(seeds) is int
                        and seeds == 16
                        and type(final) is int
                        and final == 5159
                    ) or (
                        seeds is None
                        and final is None
                        and report["operations"] is None
                        and not report["controller_retained_commands"]
                    )
                    with self.subTest(control=name, seeds=seeds, final=final):
                        if expected:
                            self.assertFalse(
                                v.validate_structure(report)["correctness_pass"]
                            )
                        else:
                            with self.assertRaises(ValueError):
                                v.validate_structure(report)

    def test_actual_ordinary_negative_controls_and_malformed_corpus(self):
        for name in (
            "seal/actual_genuine_retained_unknown_ack.json",
            "case-closure/owner-control.json",
            "case-closure/delete-control.json",
        ):
            with self.subTest(control=name):
                self.assertFalse(v.validate_structure(load(name))["correctness_pass"])
        for folder in ("seal", "case-closure"):
            for path in (CORPUS / folder).glob("*.json"):
                if path.name.startswith(
                    (
                        "cause-mutation",
                        "malformed",
                        "workload_complete",
                        "delete-erased",
                        "owner-contradiction",
                    )
                ):
                    with self.subTest(malformed=path.name):
                        with self.assertRaises(ValueError):
                            v.validate_structure(json.loads(path.read_bytes()))

    def test_synthetic_current_schema_complete_control(self):
        # Retained corpus rebased with synthetic case capsule: validator proof ONLY.
        self.assertTrue(
            v.validate_structure(load("seal/original_full64.json"))["correctness_pass"]
        )

    def test_closed_schema_and_ingress(self):
        control = load("case-closure/owner-control.json")
        for key in control:
            bad = copy.deepcopy(control)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                v.validate_structure(bad)
        with self.assertRaises(ValueError):
            v.decode_report('{"schema":8,"schema":8}')
        with self.assertRaises(ValueError):
            v.decode_report('{"schema":NaN}')
        with self.assertRaises(ValueError):
            v.decode_report(b" " * (v.REPORT_LIMIT + 1))

    def test_unretained_measurement_cannot_erase_live_coverage(self):
        command = load("case-closure/owner-control.json")[
            "controller_retained_commands"
        ][0]
        v.command_semantics(command, 0, False)
        command["measurement"]["memory"] = None
        with self.assertRaises(ValueError):
            v.command_semantics(command, 0, False)

    def test_numeric_overflow_float_is_not_json_evidence(self):
        with self.assertRaises(ValueError):
            v.decode_report('{"diagnostics": {"n": 1e999}}')

    def test_phase_reducer_seal_is_absorbing(self):
        st = v.new_phase_state()
        for stage in v.STAGES[1:]:
            v.phase_transition(st, "stage", stage)
            if stage == "Release":
                v.phase_transition(st, "release", "Confirmed")
            elif stage == "Done":
                v.phase_transition(st, "done", True)
            elif stage == "Append":
                v.phase_transition(st, "append", True)
            elif stage == "Receipt":
                v.phase_transition(st, "receipt", True)
            elif stage == "Retention":
                v.phase_transition(st, "retain", True)
            elif stage == "Ack":
                v.phase_transition(st, "ack", "Confirmed")
            elif stage == "PostAck":
                v.phase_transition(st, "post_ack", True)
        for event in (
            "done",
            "append",
            "receipt",
            "retain",
            "ack",
            "release",
            "post_ack",
            "stage",
        ):
            before = copy.deepcopy(st)
            with (
                self.subTest(synthetic_after_seal=event),
                self.assertRaises(ValueError),
            ):
                v.phase_transition(st, event, True)
            self.assertEqual(st, before)

    def test_first_interior_final_confirmed_post_ack_stop_controls(self):
        control = load("seal/original_full64.json")
        for op in (0, 31, 63):
            bad = copy.deepcopy(control)
            bad["operations"] = bad["operations"][: op + 1]
            bad["commands"] = bad["commands"][: op + 1]
            bad["controller_retained_commands"] = bad["controller_retained_commands"][
                : op + 1
            ]
            c = bad["operations"][-1]["cadence"]
            st = c["state"]
            primary = "synthetic postACK admission cancellation"
            st.update(
                stage="PostAck",
                sealed=False,
                post_ack_checked=False,
                primary_finalized=True,
                action={"Gate": "PostAck"},
                peer_consumption="NotObserved",
            )
            st["terminal"] = {
                "action": st["action"],
                "stage": "PostAck",
                "cause": "AdmissionStopped",
                "pair_count": st["pairs"],
                "pending_slot": None,
                "primary": primary,
            }
            c["failure"] = {
                "role": None,
                "kind": "controller",
                "os_code": None,
                "text": primary,
            }
            c["evidence_complete"] = c["cadence_target_met"] = False
            for key in (
                "pass",
                "correctness_complete",
                "workload_complete",
                "native_handle_verified",
            ):
                bad[key] = False
            bad["error"] = primary
            bad["case_actions"] = {
                "entered": None,
                "operation_failure": primary,
                "records": [
                    {"action": a, "error": None} for a in v.ACTIONS if a in v.CLEANUP
                ],
            }
            bad["case_stop"] = {
                "position": op,
                "acknowledged_prefix": op + 1,
                "cause": {"Operation": "PostAck"},
                "primary": primary,
            }
            self.assertFalse(v.validate_structure(bad)["correctness_pass"])
            for action in ({"Phase": "PostAck"}, {"Phase": "Ack"}):
                mutation = copy.deepcopy(bad)
                ms = mutation["operations"][-1]["cadence"]["state"]
                ms["action"] = ms["terminal"]["action"] = action
                self.assertNotEqual(mutation, bad)
                with (
                    self.subTest(synthetic_post_ack=(op, action)),
                    self.assertRaises(ValueError),
                ):
                    v.validate_structure(mutation)

    def test_retained_1000_clock_oracles_and_omitted_peak_mutation(self):
        template = load("seal/original_full64.json")["operations"][0]["cadence"]
        cases = load("clock-oracle.json")
        self.assertEqual(len(cases), 1000)
        for index, case in enumerate(cases):
            c = synthetic_clock_capsule(template, case)
            with self.subTest(synthetic_clock=index):
                v.cadence(c, "independent", 0)
            if index in (0, 499, 999):
                bad = copy.deepcopy(c)
                bad["supervisor"]["maxima"]["lifetime_peak_private_bytes"] += 1
                with self.assertRaises(ValueError):
                    v.cadence(bad, "independent", 0)

    def test_every_seal_including_final_operation(self):
        control = load("seal/original_full64.json")
        for op in range(64):
            bad = copy.deepcopy(control)
            bad["operations"][op]["cadence"]["state"]["sealed"] = False
            with self.subTest(synthetic_seal=op), self.assertRaises(ValueError):
                v.validate_structure(bad)

    def test_all14_failure_and_secondary_cleanup_owner_closure(self):
        control = load("seal/original_full64.json")
        for index, action in enumerate(v.ACTIONS):
            bad = copy.deepcopy(control)
            primary = "synthetic validator-only " + action
            records = [
                {"action": a, "error": primary if a == action else None}
                for a in v.ACTIONS[: index + 1]
            ]
            records += [
                {"action": a, "error": "synthetic secondary cleanup"}
                for a in v.ACTIONS[index + 1 :]
                if a in v.CLEANUP
            ]
            bad["case_actions"]["records"] = records
            bad["pass"] = bad["correctness_complete"] = False
            bad["error"] = primary
            bad["case_stop"] = {
                "position": 64,
                "acknowledged_prefix": 64,
                "cause": {"Action": action},
                "primary": primary,
            }
            self.assertFalse(v.validate_structure(bad)["correctness_pass"])
            bad["error"] = bad["case_stop"] = None
            with (
                self.subTest(synthetic_erased_action=action),
                self.assertRaises(ValueError),
            ):
                v.validate_structure(bad)

    def test_coordinated_unknown_ack_cause_and_primary_erasure(self):
        control = load("case-closure/owner-control.json")
        for mutation in ("confirmed", "erase", "foreign", "null", "frontier"):
            bad = copy.deepcopy(control)
            st = bad["operations"][0]["cadence"]["state"]
            if mutation == "confirmed":
                st["ack"] = "Confirmed"
                bad["case_stop"]["acknowledged_prefix"] = 1
            elif mutation == "erase":
                st["terminal"] = None
                st["primary_finalized"] = False
                bad["operations"][0]["cadence"]["failure"] = None
                bad["error"] = bad["case_stop"] = None
                bad["case_actions"]["operation_failure"] = None
            elif mutation in ("foreign", "null"):
                bad["case_actions"]["operation_failure"] = (
                    None if mutation == "null" else "synthetic foreign owner"
                )
            else:
                st["last_live"][0] += 1
            self.assertNotEqual(bad, control)
            with (
                self.subTest(synthetic_coordinated=mutation),
                self.assertRaises(ValueError),
            ):
                v.validate_structure(bad)

    def test_cadence_changed_value_mutations(self):
        control = load("case-closure/owner-control.json")
        paths = [
            ("schema",),
            ("operation_id",),
            ("accounted_slots",),
            ("missed_slots",),
            ("supervisor", "maxima", "private_bytes"),
            ("broker", "baseline_to_end_io", "read_bytes"),
            ("supervisor", "prefix", 0, "ordinal"),
            ("state", "last_pair", "ordinal"),
            ("state", "last_attempt", 1),
            ("state", "terminal", "pair_count"),
        ]
        for path in paths:
            bad = copy.deepcopy(control)
            target = bad["operations"][0]["cadence"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] += 1
            with self.subTest(synthetic_cadence=path), self.assertRaises(ValueError):
                v.validate_structure(bad)

    def test_nested_exact_types_missing_and_unknown_keys(self):
        control = load("case-closure/owner-control.json")

        def paths(value, path=()):
            if isinstance(value, dict):
                yield path, value
                for key, child in value.items():
                    yield from paths(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from paths(child, path + (index,))
            elif type(value) in (bool, int):
                yield path, value

        for path, value in paths(control):
            if path and path[0] == "diagnostics":
                continue  # Explicit opaque diagnostic payload, not structural authority.
            if isinstance(value, dict):
                mutations = [("extra", "synthetic_unknown", None)] + [
                    ("missing", key, None) for key in value
                ]
            else:
                mutations = [
                    (
                        "type",
                        path[-1],
                        int(value) if type(value) is bool else bool(value),
                    )
                ]
            for kind, key, replacement in mutations:
                bad = copy.deepcopy(control)
                target = bad
                for part in path if isinstance(value, dict) else path[:-1]:
                    target = target[part]
                if kind == "extra":
                    target[key] = replacement
                elif kind == "missing":
                    del target[key]
                else:
                    target[key] = replacement
                with (
                    self.subTest(synthetic_grammar=(path, kind, key)),
                    self.assertRaises((ValueError, TypeError, KeyError)),
                ):
                    v.validate_structure(bad)

    def test_actual_workflow_explicit_version_dispatch(self):
        namespace = workflow_functions()
        calls = []
        namespace["validate_full_report"] = lambda report, pins: calls.append(5)
        namespace["validate_full8_report"] = lambda report, pins: calls.append(8)
        for schema in (5, 8):
            namespace["validate_report"]({"schema": schema}, "representative-full6", {})
        self.assertEqual(calls, [5, 8])
        for schema in (True, 5.0, 7, 9, "8"):
            with self.assertRaises(RuntimeError):
                namespace["validate_report"](
                    {"schema": schema}, "representative-full6", {}
                )
        # The actual imported full8 wrapper must NOT treat ordinary controls as native.
        namespace = workflow_functions()
        with self.assertRaises((ValueError, KeyError)):
            namespace["validate_full8_report"](load("seal/original_full64.json"), {})


def epoch_dependency_cases():
    """Bounded synthetic structural masks; preserve genuine source fixture bytes."""
    command = load("case-closure/owner-control.json")["controller_retained_commands"]
    for epoch in (None, "", "ordinary"):
        for operations in ("absent", "null", "empty"):
            for retained in ("absent", "null", "empty", "valid", "malformed"):
                for manifest in (
                    "absent",
                    "null",
                    "valid",
                    "seed-only",
                    "final-only",
                    "wrong-equation",
                    "below",
                    "above",
                ):
                    report = load("manifest/post-generation.json")
                    report["case_epoch"] = epoch
                    if operations == "absent":
                        del report["operations"]
                    else:
                        report["operations"] = None if operations == "null" else []
                    if retained == "absent":
                        del report["controller_retained_commands"]
                    else:
                        report["controller_retained_commands"] = (
                            None
                            if retained == "null"
                            else []
                            if retained == "empty"
                            else copy.deepcopy(command)
                        )
                        if retained == "malformed":
                            report["controller_retained_commands"][0]["success"] = False
                    if manifest == "absent":
                        del report["seed_records"], report["final_records"]
                    else:
                        seed, final = {
                            "null": (None, None),
                            "valid": (16, 5159),
                            "seed-only": (16, None),
                            "final-only": (None, 5159),
                            "wrong-equation": (16, 5158),
                            "below": (15, 5158),
                            "above": (400001, 405144),
                        }[manifest]
                        report["seed_records"], report["final_records"] = seed, final
                    accepted = (
                        operations != "absent"
                        and retained != "absent"
                        and manifest in ("null", "valid")
                        and retained != "malformed"
                        and (manifest == "valid" or retained != "valid")
                        and (
                            operations == "null"
                            or epoch is not None
                            and manifest == "valid"
                            and retained != "valid"
                        )
                    )
                    name = (
                        repr(epoch) + ":" + operations + ":" + retained + ":" + manifest
                    )
                    yield name, report, accepted


def synthetic_clock_capsule(template, case):
    """Portable producer-derived clock corpus; synthetic validator proof only."""
    c = copy.deepcopy(template)
    times = case["times"]
    count = len(times)
    slots = [None] + [(t[0] - case["release"]) // 2000 for t in times[1:-1]] + [None]
    c.update(
        case_epoch="independent",
        release_begin_us=case["release"],
        release_end_us=case["release_end"],
        done_validated_us=case["done"],
        observation_envelope_end_us=case["envelope"],
        accounted_slots=case["requested"] + case["missed"],
        requested_samples=case["requested"],
        missed_slots=case["missed"],
        pair_attempts=count,
        both_live_pairs=count,
        max_pair_span_us=max(t[3] - t[0] for t in times),
        last_pair_end_us=times[-1][3],
        evidence_complete=True,
        cadence_target_met=False,
    )
    c["requested_coverage"] = {
        "pairs": count - 2,
        "supervisor_live": count - 2,
        "broker_live": count - 2,
        "both_live": count - 2,
        "supervisor_aborted": 0,
        "broker_aborted": 0,
    }
    for label, name, epoch, offset, key in (
        ("supervisor", "SupervisorB", 2, 0, "b"),
        ("broker", "BrokerC", 1, 2, "c"),
    ):
        r = c[label]
        points = []
        for i, t in enumerate(times):
            n = i + 1
            sample = {
                "logical_io": dict(zip(v.IO, [n, 2 * n, 3 * n, 5 * n, 7 * n, 11 * n])),
                "private_bytes": 900 if n == 14 else n,
                "working_set_bytes": 800 if n == 14 else 2 * n,
                "lifetime_peak_private_bytes": 1000 + n,
                "lifetime_peak_working_set_bytes": 1100 + n,
            }
            points.append(
                {
                    "ordinal": n,
                    "class": "Baseline"
                    if i == 0
                    else "End"
                    if n == count
                    else "Requested",
                    "sample_begin_us": t[offset],
                    "sample_end_us": t[offset + 1],
                    "requested_slot": slots[i],
                    "read": {"role": name, "epoch": epoch, "sample": sample},
                }
            )
        gap = max(
            b["sample_end_us"] - a["sample_end_us"] for a, b in zip(points, points[1:])
        )
        r.update(
            attempts=count,
            successful_live_samples=count,
            prefix=points[:12],
            omitted_points=count - 12,
            first_sample_us=points[0]["sample_end_us"],
            last=points[-1],
            baseline=points[0],
            end=points[-1],
            last_attempt_span={
                k: points[-1][k] for k in ("sample_begin_us", "sample_end_us")
            },
            max_attempt_span_us=max(
                p["sample_end_us"] - p["sample_begin_us"] for p in points
            ),
            max_acquisition_span_us=max(
                p["sample_end_us"] - p["sample_begin_us"] for p in points
            ),
            max_consecutive_gap_us=gap,
            observation_max_gap_us=case[key][0],
            operational_max_gap_us=case[key][1],
        )
        r["maxima"] = {k: max(p["read"]["sample"][k] for p in points) for k in v.MEM}
        r["maxima"]["logical_io"] = points[-1]["read"]["sample"]["logical_io"]
        r["baseline_to_end_io"] = v.delta(
            points[-1]["read"]["sample"]["logical_io"],
            points[0]["read"]["sample"]["logical_io"],
        )
    c["state"].update(
        stage="Finalize",
        action={"Phase": "Finalize"},
        sealed=False,
        post_ack_checked=False,
        append_verified=False,
        receipt_validated=False,
        command_retained=False,
        ack="NotStarted",
        peer_consumption="NotObserved",
        pairs=count,
        classes=[1, count - 2, 1],
        last_live=[count, count],
        last_attempt=[count, count],
        last_slot=slots[-2],
    )
    c["state"]["last_pair"] = {
        "ordinal": count,
        "class": "End",
        "slot": None,
        "spans": [times[-1][:2], times[-1][2:]],
        "outcomes": ["Live", "Live"],
        "abort_check_span": None,
    }
    return c


def workflow_functions():
    # Test-only AST extraction. No top-level hosted/native workflow code executed.
    import ast
    import hashlib
    import textwrap

    workflow = (ROOT / ".github/workflows/windows-broker-benchmark.yml").read_text()
    block = (
        workflow.split("      - name: Run selected disposable 6 MiB case")[1]
        .split("        run: |\n")[1]
        .split("\n      - name: Stage only")[0]
    )
    tree = ast.parse(textwrap.dedent(block))
    names = {
        "require",
        "selected_case",
        "exact_equal",
        "uint",
        "sha",
        "logical_io",
        "process_sample",
        "validate_measurement",
        "closed",
        "full_descriptor",
        "full_statistics",
        "strict_json",
        "validate_full_report",
        "validate_full8_report",
        "validate_report",
        "command_group",
        "warmup_record",
        "validate_two_warmup",
    }
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in nodes} == names
    namespace = {"json": json, "hashlib": hashlib}
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]),
            "actual-workflow-pure-functions",
            "exec",
        ),
        namespace,
    )
    return namespace


if __name__ == "__main__":
    unittest.main()
