"""Explicit offline installation of an exact, already-authorized tar archive."""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import time
import uuid
from collections.abc import Callable

from .install import InstallError
from .installed import _Directories, _DIRECTORY, _SOURCE, _identity
from .model import AssetSpec
from .receipt import ReceiptStore, ReleaseContext


_MAX_BYTES = 8 * 1024**3
_MAX_FILES = 256


def _select(source: int, parent: int, name: str) -> None:
    """Select a new version without replacing even an empty existing entry."""
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise InstallError("atomic archive selection is unavailable") from exc
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source, b"content", parent, os.fsencode(name), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _write(descriptor: int, data: bytes, check: Callable[[], None]) -> None:
    pending = memoryview(data)
    while pending:
        check()
        count = os.write(descriptor, pending)
        if count <= 0:
            raise InstallError("local archive write made no progress")
        pending = pending[count:]


def _copy_archive(path: str, parent: int, expected_size: int, expected_hash: str,
                  check: Callable[[], None]) -> int:
    """Copy one pinned input to a private unlinked file; never reopen its path."""
    source = writer = reader = -1
    directories = _Directories()
    name = ".archive-" + uuid.uuid4().hex
    try:
        location = Path(os.fspath(path))
        if not location.is_absolute() or ".." in location.parts:
            raise InstallError("local archive path must be absolute and canonical")
        input_parent = directories.root(str(location.parent))
        source = os.open(location.name, _SOURCE, dir_fd=input_parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_mode & 0o133
                or before.st_size != expected_size):
            raise InstallError("local archive metadata does not match the expected input")
        writer = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=parent)
        os.unlink(name, dir_fd=parent)
        remaining = expected_size
        digest = hashlib.sha256()
        while remaining:
            check()
            block = os.read(source, min(remaining, 1024 * 1024))
            if not block:
                raise InstallError("local archive ended before its declared size")
            remaining -= len(block)
            digest.update(block)
            _write(writer, block, check)
        check()
        if os.read(source, 1) or _identity(os.fstat(source)) != _identity(before):
            raise InstallError("local archive changed during its verified copy")
        directories.check()
        linked = os.stat(location.name, dir_fd=input_parent, follow_symlinks=False)
        if _identity(linked) != _identity(before) or digest.hexdigest() != expected_hash:
            raise InstallError("local archive identity or digest does not match")
        os.fsync(writer)
        reader = os.open(f"/proc/self/fd/{writer}", os.O_RDONLY | os.O_CLOEXEC)
        if _identity(os.fstat(reader)) != _identity(os.fstat(writer)):
            raise InstallError("private archive snapshot identity changed")
        result, reader = reader, -1
        return result
    finally:
        for descriptor in (source, writer, reader):
            if descriptor >= 0:
                os.close(descriptor)
        directories.close()


def _extract(archive_fd: int, output: int, spec: AssetSpec,
             check: Callable[[], None]) -> dict[str, tuple[int, ...]]:
    """Materialize only exact declared members, with private modes and FD paths."""
    expected = {item.path: item for item in spec.files}
    names: set[str] = set()
    for item in spec.files:
        path = PurePosixPath(item.path)
        if len(path.parts) > 32:
            raise InstallError("local archive member depth exceeds its bound")
        names.update(str(parent) for parent in path.parents if str(parent) != ".")
    if len(names) > _MAX_FILES or names.intersection(expected):
        raise InstallError("local archive directory population is invalid")
    opened = {"": output}
    identities: dict[str, tuple[int, ...]] = {}
    try:
        for name in sorted(names, key=lambda value: (value.count("/"), value)):
            check()
            path = PurePosixPath(name)
            parent = "" if str(path.parent) == "." else str(path.parent)
            os.mkdir(path.name, 0o700, dir_fd=opened[parent])
            opened[name] = os.open(path.name, _DIRECTORY, dir_fd=opened[parent])
        seen: set[str] = set()
        seen_directories: set[str] = set()
        with os.fdopen(os.dup(archive_fd), "rb") as source:
            # Offline import intentionally supports uncompressed tar only.
            # It does not auto-detect a converter or launch any archive program.
            with tarfile.open(fileobj=source, mode="r:") as archive:
                for member in archive:
                    check()
                    if member.isdir():
                        name = member.name.rstrip("/")
                        if name not in names or name in seen_directories:
                            raise InstallError("local archive has an undeclared or duplicate directory")
                        seen_directories.add(name)
                        continue
                    if (not member.isfile() or member.sparse is not None
                            or member.name not in expected or member.name in seen):
                        raise InstallError("local archive has an undeclared, duplicate or special member")
                    item = expected[member.name]
                    if member.size != item.bytes or member.mode & 0o111:
                        raise InstallError("local archive member size or executable mode is invalid")
                    path = PurePosixPath(item.path)
                    parent = "" if str(path.parent) == "." else str(path.parent)
                    descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                         dir_fd=opened[parent])
                    try:
                        digest = hashlib.sha256()
                        remaining = item.bytes
                        contents = archive.extractfile(member)
                        if contents is None:
                            raise InstallError("local archive member cannot be read")
                        with contents:
                            while remaining:
                                check()
                                block = contents.read(min(remaining, 1024 * 1024))
                                if not block:
                                    raise InstallError("local archive member ended early")
                                remaining -= len(block)
                                digest.update(block)
                                _write(descriptor, block, check)
                            if contents.read(1) or digest.hexdigest() != item.sha256:
                                raise InstallError("local archive member digest does not match")
                        os.fsync(descriptor)
                        identities[item.path] = _identity(os.fstat(descriptor))
                    finally:
                        os.close(descriptor)
                    seen.add(item.path)
        if seen != expected.keys():
            raise InstallError("local archive is missing a declared member")
        for descriptor in reversed(list(opened.values())):
            os.fsync(descriptor)
        identities.update((name, _identity(os.fstat(descriptor)))
                          for name, descriptor in opened.items())
        return identities
    finally:
        for name, descriptor in opened.items():
            if name:
                os.close(descriptor)


def _check_population(output: int, identities: dict[str, tuple[int, ...]],
                      check: Callable[[], None]) -> None:
    opened = {"": output}
    try:
        for name in sorted(identities, key=lambda value: (value.count("/"), value)):
            check()
            if not name:
                if _identity(os.fstat(output)) != identities[name]:
                    raise InstallError("local archive output directory changed")
                continue
            path = PurePosixPath(name)
            parent = "" if str(path.parent) == "." else str(path.parent)
            observed = os.stat(path.name, dir_fd=opened[parent], follow_symlinks=False)
            if _identity(observed) != identities[name]:
                raise InstallError("local archive member changed before selection")
            if stat.S_ISDIR(observed.st_mode):
                opened[name] = os.open(path.name, _DIRECTORY, dir_fd=opened[parent])
                if _identity(os.fstat(opened[name])) != identities[name]:
                    raise InstallError("local archive directory changed before selection")
        for name, descriptor in opened.items():
            check()
            expected = {PurePosixPath(item).name for item in identities if item
                        and ("" if str(PurePosixPath(item).parent) == "."
                             else str(PurePosixPath(item).parent)) == name}
            if set(os.listdir(descriptor)) != expected:
                raise InstallError("local archive output population changed before selection")
    finally:
        for name, descriptor in opened.items():
            if name:
                os.close(descriptor)


def _import_asset_archive(root: str, spec: AssetSpec, store: ReceiptStore,
                          release: ReleaseContext, path: str, *, maximum_bytes: int,
                          timeout: float, cancelled: Callable[[], bool] | None) -> tuple[str, ...]:
    if spec.source_mode in {"mirrored", "multipart-mirrored"}:
        size, digest = spec.download_bytes, spec.archive_sha256
    elif spec.source_mode == "user-supplied" and not spec.conversion_argv:
        size, digest = spec.input_bytes, spec.input_sha256
    else:
        raise InstallError("this asset does not support explicit local archive import")
    if (type(maximum_bytes) is not int or not 0 < size <= maximum_bytes <= _MAX_BYTES
            or not 0 < len(spec.files) <= _MAX_FILES
            or spec.temporary_bytes < size + spec.installed_bytes):
        raise InstallError("local archive exceeds its byte, member or temporary-space budget")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 3600 or not math.isfinite(timeout)
            or (cancelled is not None and not callable(cancelled))):
        raise InstallError("local archive import requires a bounded deadline and cancellation hook")
    if type(store) is not ReceiptStore:
        raise InstallError("local archive import requires the production receipt store")
    deadline = time.monotonic() + timeout

    def check() -> None:
        if cancelled is not None and cancelled():
            raise InstallError("local archive import was cancelled")
        if time.monotonic() >= deadline:
            raise InstallError("local archive import deadline exceeded")

    check()
    receipts = store.require_asset(spec, release, check=check)
    directories = _Directories()
    lock = stage = output = archive_fd = -1
    parent = -1
    stage_name = ""
    stage_identity = None
    try:
        check()
        root_fd = directories.root(root)
        try:
            os.mkdir(spec.asset_id, 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        parent = directories.open(root_fd, spec.asset_id, asset=True)
        token = hashlib.sha256(f"{spec.asset_id}\x00{spec.version}".encode()).hexdigest()
        lock_name = f".install-{token}.lock"
        lock = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=parent)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise InstallError("local archive install lock has unsafe metadata")
        while True:
            check()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        check()
        if store.require_asset(spec, release, check=check) != receipts:
            raise InstallError("local archive authorization changed while waiting")
        try:
            os.stat(spec.version, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise InstallError("refusing to replace an existing asset selection")
        directories.check()
        free = os.fstatvfs(parent)
        if free.f_bavail * free.f_frsize < spec.temporary_bytes:
            raise InstallError("insufficient available space for archive staging")
        stage_name = ".asset-import-" + uuid.uuid4().hex
        os.mkdir(stage_name, 0o700, dir_fd=parent)
        stage = os.open(stage_name, _DIRECTORY, dir_fd=parent)
        stage_identity = (os.fstat(stage).st_dev, os.fstat(stage).st_ino)
        os.mkdir("content", 0o700, dir_fd=stage)
        output = os.open("content", _DIRECTORY, dir_fd=stage)
        archive_fd = _copy_archive(path, stage, size, digest, check)
        identities = _extract(archive_fd, output, spec, check)
        check()
        if store.require_asset(spec, release, check=check) != receipts:
            raise InstallError("local archive authorization changed before selection")
        directories.check()
        _check_population(output, identities, check)
        linked_output = os.stat("content", dir_fd=stage, follow_symlinks=False)
        if _identity(linked_output) != identities[""]:
            raise InstallError("local archive output selection link changed")
        if _identity(os.stat(lock_name, dir_fd=parent, follow_symlinks=False)) != _identity(info):
            raise InstallError("local archive install lock identity changed")
        check()
        _select(stage, parent, spec.version)
        os.fsync(parent)
        return tuple(os.path.join(root, spec.asset_id, spec.version, item.path)
                     for item in spec.files)
    except (OSError, ValueError, TypeError, tarfile.TarError) as exc:
        raise InstallError("local archive import failed without replacing an existing selection") from exc
    finally:
        cleanup_error = None
        for descriptor in (archive_fd, output):
            if descriptor >= 0:
                os.close(descriptor)
        if stage >= 0:
            try:
                linked = os.stat(stage_name, dir_fd=parent, follow_symlinks=False)
                if (linked.st_dev, linked.st_ino) == stage_identity:
                    # The parent descriptor stays pinned even if an ancestor
                    # is renamed. This form also supports Python 3.10.
                    shutil.rmtree(f"/proc/self/fd/{parent}/{stage_name}")
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = exc
            finally:
                os.close(stage)
        if lock >= 0:
            os.close(lock)
        directories.close()
        if cleanup_error is not None:
            raise InstallError("local archive staging cleanup failed") from cleanup_error
