"""Dormant native candidate: explicit reviewed hosted invocation only.

Runner variables are consistency checks, NOT authentication. Authorization must
come from independently reviewed immutable source/workflow and authorized manual
hosted dispatch; no proposal-added environment provisioning is required.
Import/discovery never enables tests. No services, adapters or installed images.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import asdict, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD_SHA = "d2cbb40c2b1bebd6f5da66c0e112c6ab64de5c4af6d19132b6e207a97cd68ebe"
REF = "refs/heads/review/drain-guard-native-proof"
EXPECTED = (
    "installer/__init__.py",
    "installer/windows_image_cutover.py",
    "native_tests/drain_guard_lifecycle.py",
    "native_tests/evidence_safety.py",
    "native_tests/owned_image_child.rs",
)
ENABLED = False
OBSERVATIONS: dict[str, object] = {}
MAX_EXE_BYTES = 2 * 1024 * 1024


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def authorize(commit: str, inventory_sha: str, workflow_sha: str) -> dict:
    for value, width in ((commit, 40), (inventory_sha, 64), (workflow_sha, 64)):
        if not re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", value):
            raise ValueError("exact lowercase reviewed digest required")
    if os.name != "nt":
        raise ValueError("Windows required")
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows",
        "ImageOS": "win22",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": REF,
        "GITHUB_SHA": commit,
        "GITHUB_WORKFLOW_SHA": commit,
    }
    for name, value in expected.items():
        if os.environ.get(name) != value:
            raise ValueError(f"workflow consistency check rejected {name}")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository or workflow_ref != (
        repository + "/.github/workflows/windows-drain-guard-native-proof.yml@" + REF
    ):
        raise ValueError("unexpected workflow/ref")
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10
    ).strip()
    if head != commit:
        raise ValueError("checkout differs from reviewed commit")
    if (
        digest(ROOT / ".github/workflows/windows-drain-guard-native-proof.yml")
        != workflow_sha
    ):
        raise ValueError("workflow differs from independently reviewed bytes")
    manifest = ROOT / "native_tests/source_inventory.json"
    if digest(manifest) != inventory_sha:
        raise ValueError("inventory differs from independently reviewed bytes")
    inventory = json.loads(manifest.read_text(encoding="utf-8"))
    if (
        set(inventory) != {"schema_version", "scope", "files"}
        or type(inventory["schema_version"]) is not int
        or inventory["schema_version"] != 1
        or not isinstance(inventory["scope"], str)
        or not isinstance(inventory["files"], list)
        or len(inventory["files"]) != len(EXPECTED)
        or any(
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256"}
            or not isinstance(entry["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            for entry in inventory["files"]
        )
        or tuple(entry["path"] for entry in inventory["files"]) != EXPECTED
    ):
        raise ValueError("exact minimal execution inventory required")
    for entry in inventory["files"]:
        path = ROOT / entry["path"]
        if path.is_symlink() or digest(path) != entry["sha256"]:
            raise ValueError("source inventory mismatch: " + entry["path"])
    if digest(ROOT / "installer/windows_image_cutover.py") != GUARD_SHA:
        raise ValueError("reviewed guard changed")
    if not shutil.which("rustc"):
        raise ValueError("existing offline rustc required; no installation fallback")
    return {
        "commit": head,
        "inventory_sha256": inventory_sha,
        "workflow_sha256": workflow_sha,
        "authentication_established": False,
    }


class NativeLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        if not ENABLED:
            self.skipTest("explicit reviewed disposable workflow required")
        from installer import windows_image_cutover

        self.api = windows_image_cutover
        self.temp = tempfile.TemporaryDirectory(
            prefix="owned-drain-lifecycle-", dir=os.environ["RUNNER_TEMP"]
        )
        self.root = Path(self.temp.name)
        self.addCleanup(self.cleanup_fixture)
        self.children: list[subprocess.Popen] = []
        self.guards = []
        self.addCleanup(self.cleanup_owned)
        self.active, self.source, self.candidate, self.backup = [
            self.root / name
            for name in ("active.exe", "source.exe", "candidate.exe", "backup.exe")
        ]
        rustc = shutil.which("rustc")
        for label, output in (("old", self.active), ("new", self.source)):
            env = os.environ.copy()
            env["IMAGE_LABEL"] = label
            subprocess.run(
                [
                    rustc,
                    "--edition=2021",
                    "-C",
                    "debuginfo=0",
                    str(ROOT / "native_tests/owned_image_child.rs"),
                    "-o",
                    str(output),
                ],
                env=env,
                check=True,
                timeout=60,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertLessEqual(output.stat().st_size, MAX_EXE_BYTES)

    def cleanup_fixture(self) -> None:
        self.temp.cleanup()
        self.assertFalse(self.root.exists())
        OBSERVATIONS["owned_fixture_removed"] = True

    def stop(self, child: subprocess.Popen) -> None:
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        forced = False
        try:
            code = child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            forced = True
            child.kill()  # Retained owned direct-child handle, never PID enumeration.
            code = child.wait(timeout=2)
        finally:
            if child.stdout is not None:
                child.stdout.close()
        OBSERVATIONS.setdefault("children", []).append(
            {"pid_observation_only": child.pid, "exit_code": code, "forced": forced}
        )
        self.assertFalse(forced, "owned child did not exit gracefully")
        self.assertEqual(code, 0)

    def cleanup_owned(self) -> None:
        errors = []
        for guard in self.guards:
            try:
                guard.close()
            except BaseException as error:
                errors.append(repr(error))
        for child in self.children:
            if child.stdout is not None and not child.stdout.closed:
                try:
                    self.stop(child)
                except BaseException as error:
                    errors.append(repr(error))
        OBSERVATIONS["cleanup_errors"] = errors
        self.assertEqual(errors, [])

    def start(self, label: str) -> subprocess.Popen:
        self.assertLess(len(self.children), 3)
        child = subprocess.Popen(
            [str(self.active)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            cwd=self.root,
        )
        self.children.append(child)
        ready: queue.Queue = queue.Queue(maxsize=1)

        def read_ready() -> None:
            ready.put(child.stdout.readline(16))

        reader = threading.Thread(target=read_ready, daemon=True)
        reader.start()
        self.assertEqual(ready.get(timeout=3).rstrip(b"\r\n"), label.encode())
        reader.join(1)
        self.assertFalse(reader.is_alive())
        self.assertIsNone(child.poll())
        return child

    def blocked(self) -> None:
        with self.assertRaises(OSError) as caught:
            with self.backup.open("rb"):
                self.fail("retained native handle allowed ordinary open")
        self.assertEqual(caught.exception.winerror, 32)

    def sharing_timeout(self, expected, children, records) -> None:
        record = {"old_children": len(children), "before": [c.poll() for c in children]}
        records.append(record)
        OBSERVATIONS["sharing_timeouts"] = records
        self.assertEqual(
            record["before"], [None] * len(children), "old child expired before timeout"
        )
        try:
            with self.assertRaises(self.api.DrainTimeout) as caught:
                self.api.wait_for_drain(expected, timeout=0.05, poll_interval=0.01)
            record["winerror"] = caught.exception.winerror
            self.assertEqual(caught.exception.winerror, 32)
        finally:
            record["after"] = [c.poll() for c in children]
        self.assertEqual(
            record["after"], [None] * len(children), "old child expired during timeout"
        )

    def acquire(self, expected, epoch):
        guard = self.api.wait_for_drain(
            expected, timeout=1, poll_interval=0.01, acquisition_epoch=epoch
        )
        self.guards.append(guard)
        return guard

    def test_two_old_images_lease_close_mismatch_and_fresh_epoch(self) -> None:
        old_hash, new_hash = digest(self.active), digest(self.source)
        self.assertNotEqual(old_hash, new_hash)
        old1, old2 = self.start("old"), self.start("old")
        receipt = self.api.cutover(
            source=self.source,
            active=self.active,
            candidate=self.candidate,
            backup=self.backup,
            source_sha256=new_hash,
            active_sha256=old_hash,
            max_bytes=MAX_EXE_BYTES,
        )
        self.assertTrue(receipt.success, receipt)
        self.assertEqual(receipt.state, "replaced")
        expected = receipt.after["backup"]
        self.assertIsNotNone(expected)
        self.assertEqual(expected.identity, receipt.before["active"].identity)
        self.assertEqual(expected.sha256, old_hash)
        self.assertFalse(self.candidate.exists())
        new = self.start("new")
        timeouts = []
        for remaining, child in (((old1, old2), old1), ((old2,), old2)):
            self.sharing_timeout(expected, remaining, timeouts)
            self.stop(child)
        self.assertIsNone(new.poll())

        for mismatch in (
            replace(expected, sha256="0" * 64),
            replace(
                expected, identity=(expected.identity[0], expected.identity[1] + 1)
            ),
            replace(expected, size=expected.size + 1),
        ):
            with self.assertRaises(self.api.ValidationError):
                self.api.wait_for_drain(mismatch, timeout=0, acquisition_epoch=object())
            # A fresh real exclusive open proves the failed acquisition released custody.
            with self.api._Native().exclusive(self.backup):
                pass
            self.assertEqual(digest(self.backup), old_hash)

        epoch, fresh_epoch = object(), object()
        guard = self.acquire(expected, epoch)
        for image, token in (
            (expected, fresh_epoch),
            (replace(expected, sha256="0" * 64), epoch),
        ):
            with self.assertRaises(self.api.ValidationError):
                with guard.lease(image, acquisition_epoch=token):
                    self.fail("mismatched live lease qualified")
            self.assertFalse(guard.closed)
            self.blocked()
        attempted, finished = threading.Event(), threading.Event()
        errors = []
        mutex = guard._lock
        owner = threading.get_ident()

        class ObservedMutex:
            def __enter__(self):
                if threading.get_ident() != owner:
                    if mutex.acquire(blocking=False):
                        mutex.release()
                        raise AssertionError(
                            "original RLock did not contend: lease lock missing"
                        )
                    attempted.set()
                if not mutex.acquire(timeout=2):
                    raise AssertionError("bounded original RLock acquisition timed out")
                return self

            def __exit__(self, *args):
                mutex.release()

        # Observe entry to the original RLock; native stream and acquisition stay real.
        guard._lock = ObservedMutex()

        def close() -> None:
            try:
                guard.close()
            except BaseException as error:
                errors.append(repr(error))
            finally:
                finished.set()

        closer = threading.Thread(target=close, daemon=True)
        try:
            with guard.lease(expected, acquisition_epoch=epoch) as scope:
                self.assertEqual(scope.image, expected)
                closer.start()
                self.assertTrue(attempted.wait(2))
                self.assertFalse(finished.is_set())
                self.assertFalse(guard.closed)
                self.blocked()
                with self.assertRaises(self.api.DrainTimeout) as caught:
                    self.api.wait_for_drain(expected, timeout=0)
                self.assertEqual(caught.exception.winerror, 32)
                self.assertIsNone(new.poll())
        finally:
            if closer.ident is not None:
                closer.join(2)
        self.assertFalse(closer.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(finished.is_set())
        self.assertTrue(guard.closed)
        with self.assertRaises(self.api.ValidationError):
            _ = scope.image
        with self.backup.open("rb") as reader:
            self.assertEqual(
                hashlib.file_digest(reader, "sha256").hexdigest(), old_hash
            )
        for token in (epoch, fresh_epoch):
            with self.assertRaises(self.api.ValidationError):
                with guard.lease(expected, acquisition_epoch=token):
                    self.fail("closed guard qualified")
        fresh = self.acquire(expected, fresh_epoch)
        try:
            with self.assertRaises(self.api.ValidationError):
                with fresh.lease(expected, acquisition_epoch=epoch):
                    self.fail("fresh guard accepted stale epoch")
            with fresh.lease(expected, acquisition_epoch=fresh_epoch) as scope2:
                self.assertEqual(scope2.image, expected)
                self.blocked()
                self.assertIsNone(new.poll())
        finally:
            fresh.close()
        self.assertEqual(digest(self.backup), old_hash)
        self.assertEqual(digest(self.active), new_hash)
        self.assertEqual(digest(self.source), new_hash)
        self.stop(new)
        OBSERVATIONS.update(
            {
                "receipt": asdict(receipt),
                "sharing_timeouts": timeouts,
                "mismatch_cleanup_exclusive_reopen": True,
                "lease_delayed_close": True,
                "postrelease_open": True,
                "fresh_epoch_real_reacquisition": True,
                "authentication_established": False,
                "activation_approved": False,
            }
        )


def main() -> int:
    global ENABLED
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--reviewed-commit", required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--workflow-sha256", required=True)
    args = parser.parse_args()
    provenance = authorize(
        args.reviewed_commit, args.inventory_sha256, args.workflow_sha256
    )
    # Fixed owned evidence path, no arbitrary external result/path selection.
    evidence = ROOT / "target/drain-native-evidence"
    evidence.mkdir(parents=True, exist_ok=False)
    ENABLED = True
    sys.path.insert(0, str(ROOT))
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeLifecycle)
    )
    OBSERVATIONS.update(
        {
            "provenance": provenance,
            "tests_run": result.testsRun,
            "pass": result.wasSuccessful() and not result.skipped,
        }
    )
    primary = 0 if OBSERVATIONS["pass"] else 1
    from native_tests.evidence_safety import (
        write_json_evidence,
        report_evidence_failure,
    )

    errors = write_json_evidence(evidence / "result.json", OBSERVATIONS, 65536)
    if errors:
        OBSERVATIONS["pass"] = False
        report_evidence_failure("native_result", "exited", primary, errors)
    return primary or int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
