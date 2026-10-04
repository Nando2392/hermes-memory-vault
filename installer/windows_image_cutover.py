"""Explicit user-plane executable replacement, not installer activation.

Operational draining of managed client images is NOT authentication or defense
against a compromised same-user installer. Callers must serialize cooperating
writers and own the supplied local paths. No PID enumeration, process stopping,
services, profile discovery, database access, or automatic rollback occurs here.
Replacing a filename does not establish canonical activation. After a broker
might have served mutations, rolling code back is a separate caller decision.
Source and old backup data are retained; only the staged candidate name is
consumed by ReplaceFileW. Receipts describe observations, not crash durability
or a transactional snapshot against hostile/concurrent namespace changes.
"""

from __future__ import annotations

import ctypes
import hashlib
import math
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from collections.abc import Iterator
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

MAX_IMAGE_BYTES = 128 * 1024 * 1024


class ValidationError(ValueError):
    """No intentional mutation occurred when preflight raises this error."""


def _windows() -> bool:
    return os.name == "nt"


def _check_platform() -> None:
    if not _windows():
        raise ValidationError("Windows is required")


def _check_path(path: Path, *, absent: bool = False) -> None:
    # Deliberately restrict to ordinary absolute local drive paths, no ADS,
    # device/UNC namespaces, dot components, trailing-dot aliases, or reparses.
    if (
        not path.is_absolute()
        or str(path).startswith("\\\\")
        or any(
            part in (".", "..")
            or part.endswith((" ", "."))
            or ":" in part
            or any(c in part for c in '<>"|?*')
            or any(ord(c) < 32 for c in part)
            for part in path.parts[1:]
        )
        or path.is_reserved()
    ):
        raise ValidationError(f"unsupported path: {path}")
    for parent in reversed(path.parents):
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValidationError(f"non-directory/reparse ancestor: {parent}")
    if absent:
        if os.path.lexists(path):
            raise ValidationError(f"no-clobber conflict: {path}")
        return
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or getattr(info, "st_file_attributes", 0) & (0x400 | 0x1)
    ):
        raise ValidationError(
            f"nonregular, hardlinked, readonly or reparse image: {path}"
        )


def _preflight(
    paths: dict[str, Path], hashes: dict[str, str], max_bytes: int
) -> dict[str, Image]:
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_IMAGE_BYTES:
        raise ValidationError("invalid bounded image size")
    if any(not re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in hashes.values()):
        raise ValidationError("expected SHA256 must be 64 hex characters")
    if len({os.path.normcase(str(p)) for p in paths.values()}) != len(paths):
        raise ValidationError("source/target path alias")
    try:
        for name, path in paths.items():
            _check_path(path, absent=name in ("candidate", "backup"))
        if (
            len(
                {
                    paths[n].parent.stat().st_dev
                    for n in ("active", "candidate", "backup")
                }
            )
            != 1
        ):
            raise ValidationError("replacement paths must share a volume")
        for name in hashes:
            if paths[name].stat().st_size > max_bytes:
                raise ValidationError("image exceeds byte limit")
        before = {name: _inspect(paths[name]) for name in hashes}
        if len({image.identity for image in before.values()}) != len(before):
            raise ValidationError("source/target identity alias")
        for name, image in before.items():
            if image.sha256 != hashes[name].lower():
                raise ValidationError(f"wrong {name} SHA256")
        return before
    except OSError as error:
        raise ValidationError(str(error)) from error


@dataclass(frozen=True)
class Image:
    path: str
    identity: tuple[int, int]
    sha256: str
    size: int


def _validate_drain_image(image: Image) -> None:
    """Require inert fields before equality; preserve their exact spelling."""
    if (
        type(image) is not Image
        or type(image.path) is not str
        or type(image.sha256) is not str
        or type(image.identity) is not tuple
        or len(image.identity) != 2
        or any(type(part) is not int for part in image.identity)
        or type(image.size) is not int
        or not 0 <= image.size <= MAX_IMAGE_BYTES
    ):
        raise ValidationError("invalid bounded expected image size/type")


@dataclass(frozen=True)
class Receipt:
    """Observed recovery state; serializable with dataclasses.asdict.

    ``unchanged`` means the original active and source identities/hashes remain,
    not that staging did not write a candidate. ``replaced`` requires verified
    source, active, and backup identities/hashes and a consumed candidate.
    ``partial`` requires caller reconciliation; ``unknown`` has inspection
    errors. Neither implies rollback. Even ``replaced`` can have success=False
    when Win32 reported failure: inspect errors/winerror before proceeding.
    """

    success: bool
    state: str
    paths: dict[str, str]
    before: dict[str, Image]
    staged: Image | None
    after: dict[str, Image | None]
    errors: dict[str, str]
    winerror: int | None = None


def _hash(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    total = 0
    while chunk := stream.read(min(1024 * 1024, MAX_IMAGE_BYTES - total + 1)):
        total += len(chunk)
        if total > MAX_IMAGE_BYTES:
            raise ValidationError("image exceeds bounded hash limit")
        digest.update(chunk)
    return digest.hexdigest()


def _inspect(path: Path) -> Image:
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        return Image(str(path), (info.st_dev, info.st_ino), _hash(stream), info.st_size)


class _Native:
    """Small stdlib-only Win32 boundary; injected only by tests."""

    def __init__(self) -> None:
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.ReplaceFileW.argtypes = [wintypes.LPCWSTR] * 3 + [
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPVOID,
        ]
        self.api.ReplaceFileW.restype = wintypes.BOOL

    def exclusive(self, path: Path) -> BinaryIO:
        """Open for read/write sharing exclusion, NEVER write file data."""
        import msvcrt

        self.api.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.api.CreateFileW.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        handle = self.api.CreateFileW(
            str(path), 0xC0000000, 0, None, 3, 0x00200000, None
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except OSError:
            self.api.CloseHandle(handle)
            raise
        try:
            return os.fdopen(descriptor, "r+b")
        except OSError:
            os.close(descriptor)
            raise

    def replace(self, active: Path, candidate: Path, backup: Path) -> None:
        if not self.api.ReplaceFileW(
            str(active), str(candidate), str(backup), 0, None, None
        ):
            raise ctypes.WinError(ctypes.get_last_error())


class DrainTimeout(TimeoutError):
    """Exclusive old-image access did not become available before the deadline."""

    def __init__(self, image: Image, winerror: int | None) -> None:
        super().__init__(f"old image did not drain: {image.path}")
        self.image = image
        self.winerror = winerror


class LeaseConflictError(RuntimeError):
    """A same-thread operation conflicts with the active consumer lease."""


class _DrainLease:
    """Thread-bound live scope, never portable evidence or activation authority."""

    __slots__ = ("_guard",)

    def __init__(self, guard: DrainGuard) -> None:
        self._guard = guard

    @property
    def image(self) -> Image:
        guard = self._guard
        with guard._lock:
            if (
                guard._active_lease is not self
                or guard._lease_owner != threading.get_ident()
            ):
                raise ValidationError("inactive lease scope")
            return guard._image

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("live drain leases cannot serialize")


class DrainGuard:
    """Retain an exclusive old-image handle until close/context exit.

    Epoch-qualified leases hold this guard's mutex across consumer work. They
    establish only cooperative in-process ownership, not external attestation
    or activation. Only wait_for_drain's private factory records verification;
    the public two-argument constructor remains observation-only. Native kernel
    sharing exclusion still requires separate disposable Windows verification.

    All cooperating releases must use close(). Stream aliases, private-field
    mutation and adversarial Python introspection bypass this contract. Ordinary
    new opens of the retained file are excluded by the native handle, not by the
    Python lock; copied images elsewhere are not covered. No data is written.
    """

    def __init__(self, stream: BinaryIO, image: Image) -> None:
        self._lock = threading.RLock()
        self._lease_owner: int | None = None
        self._active_lease: _DrainLease | None = None
        self._closed = False
        self._stream = stream
        self._image = image
        self._acquisition_epoch: object | None = None
        self._acquired_stream: BinaryIO | None = None

    @classmethod
    def _from_verified_handle(
        cls, stream: BinaryIO, image: Image, acquisition_epoch: object | None
    ) -> Self:
        """Internal factory after retained-handle checks, not a trust boundary."""
        guard = cls(stream, image)
        with guard._lock:
            guard._acquisition_epoch = acquisition_epoch
            guard._acquired_stream = stream
        return guard

    def _refuse_lease_conflict(self) -> None:
        if self._lease_owner == threading.get_ident():
            raise LeaseConflictError("operation conflicts with active lease")

    @contextmanager
    def lease(
        self, expected: Image, *, acquisition_epoch: object
    ) -> Iterator[_DrainLease]:
        """Revalidate exact image/token, retaining the mutex until scope exit.

        Close, context exit, image assignment and nested lease on this thread
        raise LeaseConflictError before mutation. Other threads wait. Exceptions
        revoke the scope and release the mutex; each later lease revalidates.
        The scope is thread-bound and nonserializable; its immutable Image is
        only metadata and cannot carry lifetime authority beyond this context.
        """
        with self._lock:
            self._refuse_lease_conflict()
            _validate_drain_image(expected)
            _validate_drain_image(self._image)
            if (
                acquisition_epoch is None
                or acquisition_epoch is not self._acquisition_epoch
                or self._stream is not self._acquired_stream
                or self._image != expected
            ):
                raise ValidationError("guard is not qualified for this image/epoch")
            # Stream.closed (including its truth conversion) may call back.
            # Reserve ownership before that read and clear it on every failure.
            self._lease_owner = threading.get_ident()
            try:
                if self.closed:
                    raise ValidationError("guard is not qualified for this image/epoch")
                scope = _DrainLease(self)
                self._active_lease = scope
                yield scope
            finally:
                self._active_lease = None
                self._lease_owner = None

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("live drain guards cannot serialize")

    @property
    def acquisition_epoch(self) -> object | None:
        """Original caller token; not an external acquisition attestation."""
        with self._lock:
            return self._acquisition_epoch

    @property
    def image(self) -> Image:
        with self._lock:
            return self._image

    @image.setter
    def image(self, value: Image) -> None:
        """Preserve legacy writes, revoking verification even for equal values."""
        with self._lock:
            self._refuse_lease_conflict()
            self._image = value
            self._acquired_stream = None

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed or self._stream.closed

    def close(self) -> None:
        """Irrevocably revoke, closing once; propagate the first close failure.

        closed denotes unusable custody even if the underlying close raises;
        it does not claim successful native release in that error case.
        """
        with self._lock:
            self._refuse_lease_conflict()
            if self._closed:
                return
            # Revoke first, even if stream.close raises or calls back into us.
            self._closed = True
            self._acquired_stream = None
            self._stream.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def wait_for_drain(
    expected: Image,
    *,
    timeout: float,
    poll_interval: float = 0.05,
    acquisition_epoch: object | None = None,
) -> DrainGuard:
    """Acquire and retain exclusive access to a verified preserved old image.

    Only ERROR_SHARING_VIOLATION (32) and ERROR_LOCK_VIOLATION (33) retry.
    A zero timeout permits exactly one immediate attempt. The monotonic deadline
    bounds retries, not synchronous kernel/filesystem call latency. An open
    alone is insufficient: identity and SHA256 are checked through that handle.
    An optional live opaque epoch token is stamped by identity only after those
    checks. None preserves legacy acquisition but cannot qualify a lease. Value
    scalars/containers are refused as tokens; serialization never restores a
    guard or scope. This bookkeeping is not authenticated acquisition evidence.
    """
    _check_platform()
    if acquisition_epoch is not None and isinstance(
        acquisition_epoch,
        (
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            bytearray,
            dict,
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        raise ValidationError("acquisition epoch must be a live opaque identity token")
    if (
        not math.isfinite(timeout)
        or not 0 <= timeout <= 3600
        or not math.isfinite(poll_interval)
        or not 0 < poll_interval <= 1
    ):
        raise ValidationError("invalid bounded drain timing")
    _validate_drain_image(expected)
    deadline = time.monotonic() + timeout
    path = Path(expected.path)
    native = _Native()
    last_error = None
    first = True
    while True:
        if not first and time.monotonic() >= deadline:
            raise DrainTimeout(expected, last_error)
        first = False
        _check_path(path)
        try:
            stream = native.exclusive(path)
        except OSError as error:
            code = getattr(error, "winerror", None)
            if code not in (32, 33):
                raise
            last_error = code
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DrainTimeout(expected, code) from error
            time.sleep(min(poll_interval, remaining))
            continue
        try:
            info = os.fstat(stream.fileno())
            image = Image(
                str(path), (info.st_dev, info.st_ino), _hash(stream), info.st_size
            )
            _validate_drain_image(image)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or image != expected
            ):
                raise ValidationError("old-image identity/hash changed before drain")
            return DrainGuard._from_verified_handle(stream, image, acquisition_epoch)
        except BaseException:
            # Resource cleanup only: never suppress or retry arbitrary failures.
            stream.close()
            raise


def cutover(
    *,
    source: Path,
    active: Path,
    candidate: Path,
    backup: Path,
    source_sha256: str,
    active_sha256: str,
    max_bytes: int = MAX_IMAGE_BYTES,
) -> Receipt:
    """Stage a verified source copy, then replace an explicit active filename.

    All paths must be absolute local paths. Candidate and backup must not exist;
    candidate/active/backup must share a volume. The source is never consumed.
    Supply externally trusted SHA256 values for source and current active image.
    Preflight errors raise ValidationError without staging. Once staging starts,
    filesystem/validation failures return receipts and keep recovery artifacts.
    ReplaceFileW is called at most once, never retried or automatically undone.
    Successful replacement is not activation: drain the receipt's backup Image
    separately and retain its guard across the caller's operational boundary.
    """
    _check_platform()
    paths = {
        "source": Path(source),
        "active": Path(active),
        "candidate": Path(candidate),
        "backup": Path(backup),
    }
    before = _preflight(
        paths, {"source": source_sha256, "active": active_sha256}, max_bytes
    )
    source, active, candidate, backup = (
        paths[n] for n in ("source", "active", "candidate", "backup")
    )
    staged = None
    errors: dict[str, str] = {}
    winerror = None
    phase = "staging"
    try:
        with source.open("rb") as reader, candidate.open("xb") as writer:
            total = 0
            while chunk := reader.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ValidationError("source grew beyond byte limit")
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        staged = _inspect(candidate)
        if staged.sha256 != before["source"].sha256:
            raise ValidationError("candidate hash differs from verified source")
        # Recheck immediately before the sole native mutation. This is not a
        # same-user adversary boundary; cooperating callers must serialize.
        for name in ("source", "active"):
            _check_path(paths[name])
            if _inspect(paths[name]) != before[name]:
                raise ValidationError(f"{name} changed while staging")
        _check_path(candidate)
        _check_path(backup, absent=True)
        phase = "replace"
        _Native().replace(active, candidate, backup)
    except (OSError, ValidationError) as error:
        errors[phase] = str(error)
        winerror = getattr(error, "winerror", None)
    after: dict[str, Image | None] = {}
    for name, path in paths.items():
        try:
            _check_path(path)
            after[name] = _inspect(path)
        except FileNotFoundError:
            after[name] = None
        except (OSError, ValidationError) as error:
            after[name] = None
            errors[f"inspect:{name}"] = str(error)

    def same(left: Image | None, right: Image | None) -> bool:
        return (
            left is not None
            and right is not None
            and (left.identity, left.sha256, left.size)
            == (right.identity, right.sha256, right.size)
        )

    if any(key.startswith("inspect:") for key in errors):
        state = "unknown"
    elif (
        same(after["active"], staged)
        and same(after["backup"], before["active"])
        and same(after["source"], before["source"])
        and after["candidate"] is None
    ):
        state = "replaced"
    elif (
        same(after["active"], before["active"])
        and after["backup"] is None
        and same(after["source"], before["source"])
    ):
        state = "unchanged"
    else:
        state = "partial"
    return Receipt(
        not errors and state == "replaced",
        state,
        {name: str(path) for name, path in paths.items()},
        before,
        staged,
        after,
        errors,
        winerror,
    )
