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
