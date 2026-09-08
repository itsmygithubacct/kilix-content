"""Owned immutable model bytes bound to the accepted packaged receipt authority."""

from __future__ import annotations

import fcntl
import ctypes
import hashlib
import math
import os
from pathlib import PurePosixPath
import stat
import threading
import time
from collections.abc import Callable

from .install import InstallError
from .model import AssetFileSpec, AssetSpec
from .receipt import ArtifactBinding, ReceiptStore, ReleaseContext, VerifiedReceipt


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_SOURCE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
# Linux UAPI values also cover Python builds whose fcntl module omits these
# names. The actual kernel operations and resulting seals are still required.
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
_SEALS = 0x000F  # SEAL | SHRINK | GROW | WRITE
_MAX_BYTES = 8 * 1024**3
_MAX_MEMBERS = 256
_MAX_DIRECTORIES = 256
_TOKEN = object()


class InstalledAssetError(InstallError):
    """An installed population could not be authorized and snapshotted exactly."""


def _create_memfd() -> int:
    # Some supported Python builds omit the Linux wrapper even though libc and
    # the kernel provide it. Both routes require CLOEXEC and ALLOW_SEALING.
    creator = getattr(os, "memfd_create", None)
    if creator is not None:
        return creator("kilix-content-asset", 0x0003)
    try:
        creator = ctypes.CDLL(None, use_errno=True).memfd_create
    except AttributeError as exc:
        raise InstalledAssetError("the runtime cannot create sealed installed snapshots") from exc
    creator.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    creator.restype = ctypes.c_int
    descriptor = creator(b"kilix-content-asset", 0x0003)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


class InstalledAsset:
    """Context-managed snapshot; each duplicate() result belongs to its caller.

    These release, asset and receipt identities describe the accepted packaged
    authority checked at opening. They are not hardware admission, an install
    transaction receipt, or a replacement for a provider's actual-byte checks.
    No source pathname or writable descriptor is handed to consumers.
    """

    __slots__ = ("_descriptors", "_pid", "_binding", "_release", "_receipts", "_files", "_lock")

    def __init__(self, token: object, descriptors: dict[str, int], spec: AssetSpec,
                 release: ReleaseContext, receipts: tuple[VerifiedReceipt, ...]):
        if token is not _TOKEN:
            raise InstalledAssetError("installed snapshots must be opened by the installer")
        self._descriptors = descriptors
        self._pid = os.getpid()
        self._binding = ArtifactBinding.from_spec(spec)
        self._release = release
        self._receipts = receipts
        self._files = spec.files
        self._lock = threading.Lock()

    @property
    def binding(self) -> ArtifactBinding:
        return self._binding

    @property
    def release(self) -> ReleaseContext:
        return self._release

    @property
    def receipts(self) -> tuple[VerifiedReceipt, ...]:
        return self._receipts

    @property
    def files(self) -> tuple[AssetFileSpec, ...]:
        return self._files

    def duplicate(self, path: str) -> int:
        """Return an owned read-only sealed descriptor with an independent offset."""
        if self._pid != os.getpid():
            raise InstalledAssetError("installed snapshot is closed or belongs to another process")
        with self._lock:
            if self._descriptors is None:
                raise InstalledAssetError("installed snapshot is closed")
            if not isinstance(path, str) or path not in self._descriptors:
                raise InstalledAssetError("installed snapshot has no such member")
            try:
                return os.open(f"/proc/self/fd/{self._descriptors[path]}", os.O_RDONLY | os.O_CLOEXEC)
            except OSError as exc:
                raise InstalledAssetError("could not duplicate the installed member") from exc

    def close(self) -> None:
        if self._pid != os.getpid():
            raise InstalledAssetError("installed snapshot belongs to another process")
        with self._lock:
            descriptors, self._descriptors = self._descriptors, None
            if descriptors is not None:
                for descriptor in descriptors.values():
                    os.close(descriptor)

    def __enter__(self) -> InstalledAsset:
        if self._pid != os.getpid() or self._descriptors is None:
            raise InstalledAssetError("installed snapshot is closed or belongs to another process")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __reduce__(self):
        raise TypeError("installed snapshots cannot be serialized or copied")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe_directory(info: os.stat_result, *, asset: bool) -> None:
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or (asset and info.st_uid != os.geteuid())
            or (info.st_mode & 0o022 and not (
                not asset and info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
        raise InstalledAssetError("installed asset has an unsafe directory chain")


class _Directories:
    """Keep both ends of every directory link until the snapshot is complete."""

    def __init__(self):
        self.descriptors: list[int] = []
        self.links: list[tuple[int, str, int, int, int, bool]] = []

    def open(self, parent: int, name: str, *, asset: bool) -> int:
        descriptor = os.open(name, _DIRECTORY, dir_fd=parent)
        self.descriptors.append(descriptor)
        info = os.fstat(descriptor)
        _safe_directory(info, asset=asset)
        self.links.append((parent, name, descriptor, info.st_dev, info.st_ino, asset))
        return descriptor

    def root(self, path: str) -> int:
        parts = PurePosixPath(path).parts
        if not parts or parts[0] != "/" or ".." in parts or len(parts) > 129:
            raise InstalledAssetError("installed asset location must be absolute and canonical")
        descriptor = os.open("/", _DIRECTORY)
        self.descriptors.append(descriptor)
        _safe_directory(os.fstat(descriptor), asset=False)
        for index, name in enumerate(parts[1:]):
            descriptor = self.open(descriptor, name, asset=index == len(parts) - 2)
        return descriptor

    def check(self) -> None:
        for parent, name, descriptor, device, inode, asset in self.links:
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            pinned = os.fstat(descriptor)
            _safe_directory(linked, asset=asset)
            _safe_directory(pinned, asset=asset)
            if (linked.st_dev, linked.st_ino) != (device, inode) or (
                    pinned.st_dev, pinned.st_ino) != (device, inode):
                raise InstalledAssetError("installed asset directory identity changed")

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


def _member(parent: int, item: AssetFileSpec, check: Callable[[], None]) -> tuple[int, tuple[int, ...]]:
    source = os.open(PurePosixPath(item.path).name, _SOURCE, dir_fd=parent)
    snapshot = readonly = -1
    try:
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_mode & 0o133
                or before.st_size != item.bytes):
            raise InstalledAssetError("installed asset member metadata does not match")
        snapshot = _create_memfd()
        os.fchmod(snapshot, 0o600)
        remaining = item.bytes
        digest = hashlib.sha256()
        while remaining:
            check()
            data = os.read(source, min(remaining, 1024 * 1024))
            if not data:
                raise InstalledAssetError("installed asset member ended early")
            remaining -= len(data)
            digest.update(data)
            pending = memoryview(data)
            while pending:
                written = os.write(snapshot, pending)
                if written <= 0:
                    raise InstalledAssetError("could not snapshot installed member bytes")
                pending = pending[written:]
        check()
        if os.read(source, 1) or _identity(os.fstat(source)) != _identity(before):
            raise InstalledAssetError("installed asset member changed during snapshot")
        if digest.hexdigest() != item.sha256:
            raise InstalledAssetError("installed asset member digest does not match")
        fcntl.fcntl(snapshot, _F_ADD_SEALS, _SEALS)
        readonly = os.open(f"/proc/self/fd/{snapshot}", os.O_RDONLY | os.O_CLOEXEC)
        if ((os.fstat(readonly).st_dev, os.fstat(readonly).st_ino)
                != (os.fstat(snapshot).st_dev, os.fstat(snapshot).st_ino)
                or fcntl.fcntl(readonly, _F_GET_SEALS) & _SEALS != _SEALS):
            raise InstalledAssetError("installed member snapshot identity is invalid")
        result, readonly = readonly, -1
        return result, _identity(before)
    finally:
        os.close(source)
        if snapshot >= 0:
            os.close(snapshot)
        if readonly >= 0:
            os.close(readonly)


def _open_installed_asset(selected: str, spec: AssetSpec, store: ReceiptStore,
                          release: ReleaseContext, *, maximum_bytes: int,
                          timeout: float, cancelled: Callable[[], bool] | None) -> InstalledAsset:
    if (type(maximum_bytes) is not int or not 0 < maximum_bytes <= _MAX_BYTES
            or spec.installed_bytes > maximum_bytes or len(spec.files) > _MAX_MEMBERS):
        raise InstalledAssetError("installed asset exceeds the caller's snapshot budget")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 3600
            or (cancelled is not None and not callable(cancelled))):
        raise InstalledAssetError("installed snapshot requires a bounded timeout and cancellation hook")
    if type(store) is not ReceiptStore:
        raise InstalledAssetError("installed snapshots require the production receipt store")
    receipts = store.require_asset(spec, release)
    expected: dict[str, dict[str, bool]] = {"": {}}
    for item in spec.files:
        parts = PurePosixPath(item.path).parts
        if len(parts) > 32:
            raise InstalledAssetError("installed asset directory depth exceeds its bound")
        for index, name in enumerate(parts):
            parent = "/".join(parts[:index])
            directory = index != len(parts) - 1
            members = expected.setdefault(parent, {})
            if name in members and members[name] != directory:
                raise InstalledAssetError("installed asset has conflicting member paths")
            members[name] = directory
    if len(expected) > _MAX_DIRECTORIES:
        raise InstalledAssetError("installed asset directory count exceeds its bound")
    deadline = time.monotonic() + timeout

    def check() -> None:
        if cancelled is not None and cancelled():
            raise InstalledAssetError("installed asset snapshot was cancelled")
        if time.monotonic() >= deadline:
            raise InstalledAssetError("installed asset snapshot deadline exceeded")

    directories = _Directories()
    descriptors: dict[str, int] = {}
    try:
        check()
        opened = {"": directories.root(selected)}
        for relative in sorted(expected, key=lambda value: (value.count("/"), value)):
            check()
            if relative:
                path = PurePosixPath(relative)
                parent = "" if str(path.parent) == "." else str(path.parent)
                opened[relative] = directories.open(opened[parent], path.name, asset=True)

        def population() -> None:
            directories.check()
            for relative, descriptor in opened.items():
                seen: set[str] = set()
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        check()
                        if entry.name not in expected[relative]:
                            raise InstalledAssetError("installed asset has an unexpected member")
                        info = entry.stat(follow_symlinks=False)
                        wanted_directory = expected[relative][entry.name]
                        if (wanted_directory and not stat.S_ISDIR(info.st_mode)) or (
                                not wanted_directory and not stat.S_ISREG(info.st_mode)):
                            raise InstalledAssetError("installed asset has an invalid member type")
                        seen.add(entry.name)
                if seen != expected[relative].keys():
                    raise InstalledAssetError("installed asset is missing a declared member")

        population()
        identities = {}
        for item in spec.files:
            parent = str(PurePosixPath(item.path).parent)
            parent_descriptor = opened["" if parent == "." else parent]
            descriptor, identity = _member(parent_descriptor, item, check)
            descriptors[item.path] = descriptor
            identities[item.path] = (parent_descriptor, identity)
        population()
        for path, (parent_descriptor, identity) in identities.items():
            check()
            if _identity(os.stat(PurePosixPath(path).name, dir_fd=parent_descriptor,
                                 follow_symlinks=False)) != identity:
                raise InstalledAssetError("installed asset selection changed during snapshot")
        if store.require_asset(spec, release) != receipts:
            raise InstalledAssetError("installed asset authorization changed during snapshot")
        check()
        result = InstalledAsset(_TOKEN, descriptors, spec, release, receipts)
        descriptors = {}
        return result
    except (OSError, ValueError) as exc:
        raise InstalledAssetError("could not snapshot the exact installed asset") from exc
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)
        directories.close()
