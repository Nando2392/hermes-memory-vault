"""Portable helper tests; these do not execute or simulate a Linux broker."""

import importlib.util
import socket
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "broker_sandbox_probe.py"


class ProbeTests(unittest.TestCase):
    def test_readiness_retries_transition_and_ping_before_acceptance(self):
        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "wait_ready", None)), "readiness helper missing"
        )
        observations = iter([False, False, True])
        calls = []
        probe.wait_ready(
            lambda: None,
            lambda: next(observations),
            lambda: calls.append("ping"),
            timeout=1,
            interval=0,
        )
        self.assertEqual(calls, ["ping"])

    def test_readiness_rejects_dead_process_and_expires(self):
        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "wait_ready", None)), "readiness helper missing"
        )
        with self.assertRaisesRegex(RuntimeError, "exited"):
            probe.wait_ready(lambda: 1, lambda: True, lambda: None)
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            probe.wait_ready(lambda: None, lambda: False, lambda: None, timeout=0)

    def load(self):
        self.assertTrue(SCRIPT.exists(), "broker harness not implemented")
        spec = importlib.util.spec_from_file_location("broker_probe", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_projection_compares_every_persisted_field(self):
        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "validate_projection", None)),
            "full-field projection validator missing",
        )
        record = {
            "id": "event",
            "session_id": "session",
            "workspace": "sandbox",
            "kind": "message",
            "content": "Unicode café\nline",
            "timestamp": 1.25,
            "metadata": {"nested": [True, None, {"a": 1, "b": "é"}]},
        }
        row = (
            "event",
            "session",
            "sandbox",
            "message",
            "Unicode café\nline",
            1.25,
            '{"nested": [true, null, {"b": "é", "a": 1}]}',
        )
        self.assertEqual(probe.validate_projection([row], [record]), [record])
        for field, changed in (
            ("id", "other"),
            ("session_id", "other"),
            ("workspace", "other"),
            ("kind", "event"),
            ("content", "wrong"),
            ("timestamp", 2.0),
            ("metadata", {"nested": [False]}),
        ):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                probe.validate_projection([row], [{**record, field: changed}])
        other = {**record, "id": "another", "metadata": None}
        other_row = ("another", *row[1:6], "null")
        self.assertEqual(
            probe.validate_projection([row, other_row], [other, record]),
            [other, record],
        )
        for projected in (
            [],
            [record, record],
            [{**record, "extra": 1}],
            [{key: value for key, value in record.items() if key != "metadata"}],
            [{**record, "metadata": {"nested": [1, None, {"a": 1, "b": "é"}]}}],
        ):
            with self.subTest(projected=projected), self.assertRaises(RuntimeError):
                probe.validate_projection([row], projected)
        with self.assertRaises(RuntimeError):
            probe.validate_projection([row, row], [record])

    def test_concurrent_clients_launch_before_wait_and_validate_replies(self):
        import json
        import subprocess
        import sys
        import tempfile
        import threading

        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "concurrent_requests", None)),
            "bounded concurrent runner missing",
        )
        envelopes = [{"request_id": f"client-{i}"} for i in range(4)]
        processes = []
        with tempfile.TemporaryDirectory() as name:
            # Real portable child processes rendezvous: serial launch/wait fails.
            code = (
                "import json, pathlib, sys, time; "
                "value=json.load(sys.stdin); root=pathlib.Path(sys.argv[1]); "
                "(root/value['request_id']).touch(); end=time.monotonic()+5\n"
                "while len(list(root.iterdir())) < 4:\n"
                " if time.monotonic() >= end: sys.exit(2)\n"
                " time.sleep(0.01)\n"
                "print(json.dumps(dict(protocol=1, request_id=value['request_id'], "
                "ok=True, result=dict(received=value['request_id']))))"
            )

            def launch(**kwargs):
                self.assertIs(threading.current_thread(), threading.main_thread())
                process = subprocess.Popen([sys.executable, "-c", code, name], **kwargs)
                processes.append(process)
                return process

            replies = probe.concurrent_requests(launch, envelopes, timeout=8)
        self.assertEqual(replies, [{"received": e["request_id"]} for e in envelopes])
        self.assertTrue(all(p.returncode == 0 for p in processes))
        self.assertLess(len(json.dumps(envelopes)), 4096)

    def test_concurrent_deadline_reaps_entire_cohort(self):
        import subprocess
        import sys

        probe = self.load()
        processes = []

        def launch(**kwargs):
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"], **kwargs
            )
            processes.append(process)
            return process

        with self.assertRaisesRegex(RuntimeError, "deadline"):
            probe.concurrent_requests(
                launch, [{"request_id": str(i)} for i in range(4)], timeout=0.2
            )
        self.assertTrue(processes)
        self.assertTrue(all(process.poll() is not None for process in processes))

    def test_concurrent_bounds_and_bad_reply_fail_closed(self):
        import subprocess
        import sys

        probe = self.load()
        processes = []

        def launch(**kwargs):
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        'print(\'{"protocol":1,"request_id":"wrong",'
                        '"ok":true,"result":{}}\')'
                    ),
                ],
                **kwargs,
            )
            processes.append(process)
            return process

        for envelopes in ([], [{}] * 5, [{"request_id": "x", "body": "x" * 4096}]):
            with self.assertRaisesRegex(RuntimeError, "budget"):
                probe.concurrent_requests(launch, envelopes)
        self.assertEqual(processes, [])
        with self.assertRaisesRegex(RuntimeError, "uncorrelated"):
            probe.concurrent_requests(launch, [{"request_id": "expected"}])
        self.assertTrue(all(process.poll() is not None for process in processes))

    def test_frame_roundtrip(self):
        probe = self.load()
        value = {"protocol": 1, "request_id": "portable", "ok": True, "result": {}}
        frame = probe.encode_frame(value)
        self.assertEqual(int.from_bytes(frame[:4], "big"), len(frame[4:]))
        left, right = socket.socketpair()
        with left, right:
            left.sendall(frame)
            self.assertEqual(probe.receive_frame(right, timeout=0.2), value)

    def test_report_counts_only_completed_checks(self):
        probe = self.load()
        self.assertTrue(callable(getattr(probe, "make_report", None)), "report missing")
        report = probe.make_report(["allowed_ping", "scope_denied"], {}, "failed", "x")
        self.assertEqual(report["completed_check_count"], 2)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["full_attack_matrix"])
        self.assertNotIn("benchmark", report["results"])

    def test_reply_requires_correlation_and_typed_error(self):
        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "validate_reply", None)), "validator missing"
        )
        good = {"protocol": 1, "request_id": "x", "ok": True, "result": {}}
        self.assertEqual(probe.validate_reply(good, "x", True), {})
        for bad in (
            {**good, "request_id": "y"},
            {**good, "protocol": 2},
            {**good, "ok": False},
            {"protocol": 1, "request_id": "x", "ok": False, "error": {}},
        ):
            with self.assertRaises(RuntimeError):
                probe.validate_reply(bad, "x", True)
        self.assertEqual(
            probe.validate_reply(
                {
                    "protocol": 1,
                    "request_id": "x",
                    "ok": False,
                    "error": {"code": "unauthorized"},
                },
                "x",
                False,
            ),
            {"code": "unauthorized"},
        )

    def test_frame_rejects_bad_lengths_truncation_and_nonobjects(self):
        probe = self.load()
        for frame in (
            b"\x00\x00\x00\x00",
            (probe.MAX_FRAME + 1).to_bytes(4, "big"),
            b"\x00\x00\x00\x04{}",
            b"\x00\x00\x00\x02[]",
        ):
            left, right = socket.socketpair()
            with left, right:
                left.sendall(frame)
                left.shutdown(socket.SHUT_WR)
                with self.assertRaises(RuntimeError):
                    probe.receive_frame(right, timeout=0.2)

    def test_idle_frame_has_deadline(self):
        probe = self.load()
        left, right = socket.socketpair()
        with left, right, self.assertRaises((TimeoutError, RuntimeError)):
            probe.receive_frame(right, timeout=0.02)

    def test_peer_can_reject_before_request_write(self):
        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "raw_frame_outcome", None)), "raw helper missing"
        )
        left, right = socket.socketpair()
        right.close()
        with left:
            self.assertEqual(
                probe.raw_frame_outcome(left, b"request"), {"denied": "closed"}
            )

    def test_raw_frame_success_is_not_a_denial(self):
        probe = self.load()
        self.assertTrue(
            callable(getattr(probe, "raw_frame_outcome", None)), "raw helper missing"
        )
        left, right = socket.socketpair()
        with left, right:
            right.sendall(probe.encode_frame({"ok": True, "result": {}}))
            with self.assertRaises(RuntimeError):
                probe.raw_frame_outcome(left, b"bad")

    def test_entrypoint_is_harmless_without_opt_in(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--binary", result.stdout)
        self.assertIn("--run", result.stdout)

    def test_gate_rejects_every_missing_prerequisite(self):
        probe = self.load()
        self.assertTrue(callable(getattr(probe, "supported", None)), "gate missing")
        self.assertTrue(probe.supported("linux", 0, "true"))
        for args in (
            ("win32", 0, "true"),
            ("linux", 1, "true"),
            ("linux", 0, None),
            ("linux", 0, "True"),
        ):
            self.assertFalse(probe.supported(*args))


if __name__ == "__main__":
    unittest.main()
