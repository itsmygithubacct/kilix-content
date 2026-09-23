"""Unprivileged, immutable content installation primitives."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import math
import os
import selectors
import shutil
import signal
import stat

# Child processes always receive an argv array and never invoke a shell.
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
import json
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from kilix_license.coverage import AssetRef, require as require_license
from kilix_license.records import RecordIndex
from kilix_license.store import ReceiptStore
from kilix_license.texts import TextStore

from .fetch import (
    DownloadError,
    Progress,
    _HTTPSPartRedirects,
    _RESUME_MIN_BYTES,
    fetch_exact,
)
from .model import AssetSpec, Catalog, ContentSpec, source_objects_sha256

Report = Callable[[str], None]

_AT_FDCWD = -100
_RENAME_EXCHANGE = 2
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
_SAFE_GIT_PROTOCOLS = frozenset(("file", "git", "http", "https", "ssh"))


class InstallError(RuntimeError):
    """A content install failed without selecting a partial result."""


class SuppliedFile:
    """One exact file the user already holds, held open across verification.

    Restores the F100 `VerifiedInput` discipline for asset/v3 (OD-BO). The
    path is opened **once**, with `O_NOFOLLOW` so a symlinked leaf is refused
    and `O_NONBLOCK` so a FIFO cannot block the open, and it is never reopened
    by name: the size and digest are read through that descriptor, the staged
    copy is written from it, and `revalidate()` re-reads it afterwards. A file
    that is truncated or rewritten in place between the check and the copy
    therefore fails, and a path swapped for a different file cannot change
    what was copied -- neither of which reopening by name can tell you.

    Two ways in, and they are not the same guard:

    * `open(path)` guards the **leaf only**. `O_NOFOLLOW` applies to the last
      component; a symlinked *directory* anywhere above it is followed.
    * `open_beneath(root, relative)` is what the supplied install uses. It
      walks every component below `root` with `dir_fd` and `O_NOFOLLOW`, so
      no symlink beneath the nominated directory is followed at any depth,
      and `..`, empty and absolute components are refused outright.
    """

    def __init__(
        self, path: str, descriptor: int, info: os.stat_result, digest: str
    ) -> None:
        self.path = path
        self._descriptor = descriptor
        self._device = info.st_dev
        self._inode = info.st_ino
        self.bytes = info.st_size
        self.sha256 = digest

    _LEAF_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    _WALK_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> SuppliedFile:
        """Open one file by path. **Guards the leaf only** -- see the class note.

        A symlinked directory above the leaf is followed. The supplied install
        does not use this; it uses `open_beneath`.
        """
        try:
            resolved = os.path.abspath(os.fspath(path))
            descriptor = os.open(resolved, cls._LEAF_FLAGS)
        except (OSError, TypeError, ValueError) as exc:
            raise InstallError(f"could not open supplied file: {path}") from exc
        return cls._held(resolved, descriptor)

    @classmethod
    def open_beneath(
        cls, root: str | os.PathLike[str], relative: str
    ) -> SuppliedFile:
        """Open `root/relative` without following a symlink at any depth below `root`.

        The documented boundary of a supplied install is "a directory holding
        the asset's installed files". `open()` enforced it for the leaf only:
        an intermediate directory symlink was followed and bytes were read from
        outside that directory (C-V3-FIX F6). The digest still had to match, so
        nothing unverified was installed -- but the boundary was stated and not
        enforced.

        `root` itself is opened by path and **may** be reached through a
        symlink: the operator nominated it. Every component beneath it is then
        opened with `dir_fd` relative to its parent and `O_NOFOLLOW`
        (`O_DIRECTORY` for the intermediate ones), and the leaf with the same
        flags as `open()`. `..`, empty and absolute components are refused
        before anything is opened. Pure `os.open` with `dir_fd`: no `ctypes`,
        no `openat2`.
        """
        base = os.path.abspath(os.fspath(root))
        shown = os.path.join(base, relative)
        parts = relative.split("/")
        if os.path.isabs(relative) or any(part in ("", "..") for part in parts):
            raise InstallError(
                f"supplied path is not a plain path beneath the supplied directory: {relative!r}"
            )
        walked: list[int] = []
        try:
            try:
                parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                walked.append(parent)
                for part in parts[:-1]:
                    parent = os.open(part, cls._WALK_FLAGS, dir_fd=parent)
                    walked.append(parent)
                descriptor = os.open(parts[-1], cls._LEAF_FLAGS, dir_fd=parent)
            except (OSError, TypeError, ValueError) as exc:
                raise InstallError(f"could not open supplied file: {shown}") from exc
        finally:
            for handle in walked:
                os.close(handle)
        return cls._held(shown, descriptor)

    @classmethod
    def _held(cls, path: str, descriptor: int) -> SuppliedFile:
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise InstallError(f"supplied file is not a regular file: {path}")
            return cls(path, descriptor, info, cls._digest(descriptor))
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _digest(descriptor: int) -> str:
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            try:
                block = os.read(descriptor, 1024 * 1024)
            except InterruptedError:
                continue
            if not block:
                break
            digest.update(block)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return digest.hexdigest()

    def revalidate(self) -> None:
        try:
            info = os.fstat(self._descriptor)
        except OSError as exc:
            raise InstallError("supplied file is no longer open") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_dev != self._device
            or info.st_ino != self._inode
            or info.st_size != self.bytes
            or self._digest(self._descriptor) != self.sha256
        ):
            raise InstallError(f"supplied file changed after it was opened: {self.path}")

    def copy_to(self, target: str) -> None:
        """Write the held bytes to a new private file, from the descriptor."""
        os.lseek(self._descriptor, 0, os.SEEK_SET)
        handle = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
        try:
            while True:
                try:
                    block = os.read(self._descriptor, 1024 * 1024)
                except InterruptedError:
                    continue
                if not block:
                    break
                offset = 0
                while offset < len(block):
                    offset += os.write(handle, block[offset:])
        finally:
            os.close(handle)
        os.lseek(self._descriptor, 0, os.SEEK_SET)

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, -1
        if descriptor >= 0:
            os.close(descriptor)

    def __enter__(self) -> SuppliedFile:  # noqa: PYI034 -- Python 3.10 support
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


_held_install_locks = threading.local()


def _acquire_install_lock(lock_path: str) -> int:
    """Open and exclusively lock the live inode at lock_path.

    A finished installation unlinks its lock file while still holding the
    lock, so an acquired descriptor is only valid while it still names the
    path; otherwise the wait is repeated on the recreated file.
    """
    try:
        while True:
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                try:
                    current = os.stat(lock_path)
                except FileNotFoundError:
                    current = None
                owned = os.fstat(descriptor)
                if current is not None and (
                    (current.st_dev, current.st_ino)
                    == (owned.st_dev, owned.st_ino)
                ):
                    return descriptor
            except OSError:
                os.close(descriptor)
                raise
            os.close(descriptor)
    except OSError as exc:
        raise InstallError(f"could not lock installation: {lock_path}") from exc


def _rename_exchange(first: str, second: str) -> None:
    """Atomically exchange two filesystem entries using Linux renameat2."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            _AT_FDCWD,
            os.fsencode(first),
            _AT_FDCWD,
            os.fsencode(second),
            _RENAME_EXCHANGE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), first, second)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_member_path(root: str, member_name: str) -> str:
    if not member_name or "\x00" in member_name or os.path.isabs(member_name):
        raise InstallError(f"archive contains unsafe path: {member_name!r}")
    target = os.path.realpath(os.path.join(root, member_name))
    if target != root and not target.startswith(root + os.sep):
        raise InstallError(f"archive contains unsafe path: {member_name!r}")
    return target


def _check_archive_budget(
    sizes: Iterable[int], count: int, max_members: int, max_bytes: int
) -> None:
    if count > max_members:
        raise InstallError(f"archive contains more than {max_members} members")
    total = 0
    for size in sizes:
        if size < 0 or size > max_bytes - total:
            raise InstallError(
                f"archive expands beyond the {max_bytes}-byte safety limit"
            )
        total += size


def safe_extract_tar(
    archive: tarfile.TarFile,
    destination: str,
    *,
    max_members: int = _MAX_ARCHIVE_MEMBERS,
    max_bytes: int = _MAX_ARCHIVE_BYTES,
) -> None:
    """Extract bounded regular files/directories, rejecting links and escapes."""
    members = archive.getmembers()
    _check_archive_budget(
        (member.size for member in members if member.isfile()),
        len(members),
        max_members,
        max_bytes,
    )
    root = os.path.realpath(destination)
    for member in members:
        _safe_member_path(root, member.name)
        if not (member.isdir() or member.isfile()):
            raise InstallError(f"archive contains unsupported member: {member.name!r}")
    try:
        # Every member's type, path, and expanded size was prevalidated above.
        archive.extractall(  # nosec B202
            destination, members=members
        )
    except (OSError, tarfile.TarError) as exc:
        raise InstallError(f"could not safely extract tar archive: {exc}") from exc


def safe_extract_zip(
    archive: zipfile.ZipFile,
    destination: str,
    *,
    max_members: int = _MAX_ARCHIVE_MEMBERS,
    max_bytes: int = _MAX_ARCHIVE_BYTES,
) -> None:
    """Extract bounded files/directories, rejecting paths and special files."""
    members = archive.infolist()
    _check_archive_budget(
        (member.file_size for member in members if not member.is_dir()),
        len(members),
        max_members,
        max_bytes,
    )
    root = os.path.realpath(destination)
    for member in members:
        _safe_member_path(root, member.filename)
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise InstallError(
                f"archive contains unsupported symlink: {member.filename!r}"
            )
        file_type = stat.S_IFMT(mode)
        if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise InstallError(
                f"archive contains unsupported member: {member.filename!r}"
            )
    try:
        # Every member's type, path, and expanded size was prevalidated above.
        archive.extractall(  # nosec B202
            destination, members=members
        )
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise InstallError(f"could not safely extract ZIP archive: {exc}") from exc


def download(
    urls: str | Iterable[str],
    destination: str,
    report: Report = lambda _message: None,
    expected_sha256: str = "",
) -> str:
    """Atomically download the first working URL and validate its digest."""
    candidates = (urls,) if isinstance(urls, str) else tuple(urls)
    if not candidates:
        raise InstallError("content download has no candidate URLs")
    last_error: Exception | None = None
    for url in candidates:
        temporary = ""
        try:
            report(f"downloading {url.rsplit('/', 1)[-1]} …")
            request = urllib.request.Request(
                url, headers={"User-Agent": "kilix-content/0.3"}
            )
            destination_dir = os.path.dirname(os.path.abspath(destination))
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{os.path.basename(destination)}.download-",
                dir=destination_dir,
            )
            digest = hashlib.sha256()
            with (
                os.fdopen(descriptor, "wb") as output,
                # Local file URLs are intentional and still require exact digests.
                urllib.request.urlopen(request, timeout=60) as response,  # nosec B310
            ):
                while block := response.read(1024 * 1024):
                    output.write(block)
                    if expected_sha256:
                        digest.update(block)
            if expected_sha256:
                actual = digest.hexdigest()
                if actual != expected_sha256:
                    raise InstallError(
                        f"sha256 mismatch for {url}: expected {expected_sha256}, got {actual}"
                    )
            os.replace(temporary, destination)
            temporary = ""
            return destination
        except Exception as exc:  # noqa: BLE001 -- any mirror failure advances to the next
            last_error = exc
        finally:
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
    raise InstallError(f"all content downloads failed: {last_error}")


def _run(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        timeout=timeout,
    )  # nosec B603


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    process.wait()


def _run_with_tail(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    tail_bytes: int = 16 * 1024,
    timeout: float | None = None,
) -> tuple[int, str]:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )  # nosec B603
    tail = bytearray()
    output = process.stdout
    if output is None:
        process.kill()
        process.wait()
        raise RuntimeError("could not capture build output")

    def decoded() -> str:
        return tail.decode("utf-8", errors="replace").strip()

    def timed_out() -> InstallError:
        _kill_process_group(process)
        detail = decoded()
        suffix = f": {detail}" if detail else ""
        return InstallError(
            f"{argv[0]} timed out after {timeout:g} seconds{suffix}"
        )

    descriptor = output.fileno()

    def absorb() -> bool:
        """Move one ready block into the bounded tail; report False at EOF."""
        block = os.read(descriptor, 64 * 1024)
        if not block:
            return False
        tail.extend(block)
        if len(tail) > tail_bytes:
            del tail[:-tail_bytes]
        return True

    deadline = None if timeout is None else time.monotonic() + timeout
    with output, selectors.DefaultSelector() as poller:
        poller.register(descriptor, selectors.EVENT_READ)
        while True:
            if deadline is None:
                interval = 1.0
            else:
                interval = min(1.0, deadline - time.monotonic())
                if interval <= 0:
                    raise timed_out()
            if poller.select(interval):
                if not absorb():
                    break  # Every writer closed the pipe: output is complete.
            elif process.poll() is not None:
                # The command has exited but a child it started still holds
                # the pipe open. Keep what has arrived and stop waiting.
                while poller.select(0) and absorb():
                    pass
                break
    try:
        remaining = (
            None if deadline is None else max(0.0, deadline - time.monotonic())
        )
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        raise timed_out() from None
    return returncode, decoded()


def _git_environment(env: dict[str, str] | None = None) -> dict[str, str]:
    result = dict(os.environ if env is None else env)
    configured_protocols = result.get("GIT_ALLOW_PROTOCOL", "")
    for key in tuple(result):
        if key.startswith("GIT_") or key in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"):
            result.pop(key, None)
    if isinstance(configured_protocols, str):
        protocols = tuple(
            protocol
            for protocol in configured_protocols.split(":")
            if protocol in _SAFE_GIT_PROTOCOLS
        )
        if protocols:
            result["GIT_ALLOW_PROTOCOL"] = ":".join(protocols)
    result.update(
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_KEY_1": "credential.helper",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_VALUE_1": "",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "SSH_ASKPASS_REQUIRE": "never",
        }
    )
    return result


def _require_managed_git_directory(directory: str) -> None:
    git_directory = os.path.join(directory, ".git")
    if (
        os.path.islink(directory)
        or os.path.islink(git_directory)
        or not os.path.isdir(git_directory)
    ):
        raise InstallError(f"not a managed Git checkout: {directory}")


def _git_status(directory: str, env: dict[str, str]) -> tuple[str, bool, bool]:
    try:
        result = _run(
            [
                "git",
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=no",
                "--ignore-submodules=none",
            ],
            cwd=directory,
            env=env,
        )
    except OSError as exc:
        raise InstallError(f"could not verify managed checkout: {directory}") from exc
    if result.returncode != 0:
        raise InstallError(f"could not verify managed checkout: {directory}")
    head = ""
    branch = ""
    dirty = False
    for line in result.stdout.splitlines():
        if line.startswith("# branch.oid "):
            head = line.removeprefix("# branch.oid ")
        elif line.startswith("# branch.head "):
            branch = line.removeprefix("# branch.head ")
        elif not line.startswith("# "):
            dirty = True
    if not head or not branch:
        raise InstallError(f"could not verify managed checkout: {directory}")
    return head, branch == "(detached)", dirty


def _git_origin(
    directory: str, env: dict[str, str], *, allow_missing: bool = False
) -> str | None:
    try:
        result = _run(
            ["git", "config", "--get", "remote.origin.url"], cwd=directory, env=env
        )
    except OSError as exc:
        raise InstallError(f"could not verify managed checkout: {directory}") from exc
    if allow_missing and result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode != 0:
        raise InstallError(f"could not verify managed checkout: {directory}")
    return result.stdout.strip()


def _verify_submodules(directory: str, env: dict[str, str]) -> None:
    if not os.path.isfile(os.path.join(directory, ".gitmodules")):
        return
    try:
        result = _run(
            ["git", "submodule", "status", "--recursive"], cwd=directory, env=env
        )
    except OSError as exc:
        raise InstallError(f"could not verify managed checkout: {directory}") from exc
    if result.returncode != 0:
        raise InstallError(f"could not verify managed checkout: {directory}")
    for line in result.stdout.splitlines():
        if line[:1] in ("-", "+", "U"):
            raise InstallError(
                f"managed checkout has an invalid submodule state: {directory}"
            )


def verify_git_checkout(
    repository: str, ref: str, directory: str, *, env: dict[str, str] | None = None
) -> None:
    """Require the configured origin, exact HEAD, clean tracked files, and initialized submodules."""
    if not _valid_git_identity(repository, ref):
        raise InstallError("managed checkout identity is invalid")
    _require_managed_git_directory(directory)
    git_env = _git_environment(env)
    head, detached, dirty = _git_status(directory, git_env)
    if _git_origin(directory, git_env) != repository:
        raise InstallError(f"managed checkout has an unexpected origin: {directory}")
    if head != ref:
        raise InstallError(f"managed checkout is not at its pinned commit: {directory}")
    if not detached:
        raise InstallError(f"managed checkout is not detached: {directory}")
    if dirty:
        raise InstallError(f"refusing modified managed checkout: {directory}")
    _verify_submodules(directory, git_env)


def _valid_git_identity(repository: object, ref: object) -> bool:
    if not (
        isinstance(repository, str)
        and repository
        and "\x00" not in repository
        and isinstance(ref, str)
        and len(ref) == 40
        and all(character in "0123456789abcdef" for character in ref)
    ):
        return False
    try:
        os.fsencode(repository)
    except (TypeError, UnicodeError):
        return False
    return True


class Installer:
    """Install catalog entries below one caller-owned data directory.

    Every fetch and build command an installation spawns is bounded by
    ``command_timeout`` seconds so a stalled network peer or wedged build
    cannot block ``ensure()`` forever. The generous default accommodates
    long legitimate builds; pass ``None`` to wait without bound.
    """

    def __init__(
        self,
        root: str,
        *,
        env: dict[str, str] | None = None,
        command_timeout: float | None = 3600.0,
    ):
        try:
            root = os.fspath(root)
        except TypeError as exc:
            raise InstallError("content root must be a filesystem path") from exc
        if not isinstance(root, str) or "\x00" in root or not os.path.isabs(root):
            raise InstallError("content root must be an absolute path")
        if command_timeout is not None and (
            isinstance(command_timeout, bool)
            or not isinstance(command_timeout, (int, float))
            or not math.isfinite(command_timeout)
            or command_timeout <= 0
        ):
            raise InstallError(
                "command timeout must be a positive number of seconds or None"
            )
        self.root = os.path.normpath(root)
        self.env = dict(os.environ if env is None else env)
        self.command_timeout = (
            None if command_timeout is None else float(command_timeout)
        )
        self._ensure_root()

    def _ensure_root(self) -> None:
        if os.path.lexists(self.root) and os.path.islink(self.root):
            raise InstallError(f"content root must not be a symlink: {self.root}")
        try:
            os.makedirs(self.root, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise InstallError(f"could not create content root: {self.root}") from exc
        if not os.path.isdir(self.root):
            raise InstallError(f"content root is not a directory: {self.root}")

    def destination(self, spec: ContentSpec) -> str:
        install_id = spec.install_id
        try:
            destination = os.path.abspath(os.path.join(self.root, install_id))
        except (TypeError, ValueError) as exc:
            raise InstallError("install id is not a safe path component") from exc
        if destination == self.root or os.path.dirname(destination) != self.root:
            raise InstallError(
                f"install id is not a safe path component: {install_id!r}"
            )
        return destination

    def executable(self, spec: ContentSpec, directory: str | None = None) -> str:
        selected = os.path.abspath(directory or self.destination(spec))
        try:
            executable = os.path.abspath(os.path.join(selected, spec.binary))
            inside = os.path.commonpath((selected, executable)) == selected
        except (TypeError, ValueError) as exc:
            raise InstallError("content binary is not a safe relative path") from exc
        if executable == selected or not inside:
            raise InstallError(
                f"content binary is not a safe relative path: {spec.binary!r}"
            )
        return executable

    @staticmethod
    def _executable_stays_within(selected: str, executable: str) -> bool:
        try:
            root = os.path.realpath(selected)
            target = os.path.realpath(executable)
            return target != root and os.path.commonpath((root, target)) == root
        except (OSError, ValueError):
            return False

    def ready(self, spec: ContentSpec, directory: str | None = None) -> str | None:
        return self.ready_provided((spec,), directory=directory).get(spec.content_id)

    def ready_provided(
        self,
        specs: Iterable[ContentSpec],
        *,
        directory: str | None = None,
    ) -> dict[str, str | None]:
        """Check several entries from one package with one source verification.

        Every binary is still checked independently. The expensive immutable
        checkout/submodule verification is shared only when every flattened
        spec declares the exact same installation identity.
        """
        provided = tuple(specs)
        if not provided:
            return {}
        first = provided[0]
        identity = (
            first.install_id,
            first.source_type,
            first.repository,
            first.ref,
            first.urls,
            first.sha256,
            first.build,
        )
        seen: set[str] = set()
        for spec in provided:
            candidate_identity = (
                spec.install_id,
                spec.source_type,
                spec.repository,
                spec.ref,
                spec.urls,
                spec.sha256,
                spec.build,
            )
            if candidate_identity != identity:
                raise InstallError(
                    "provided readiness requires one shared installation identity"
                )
            if spec.content_id in seen:
                raise InstallError(
                    f"duplicate provided content id: {spec.content_id}"
                )
            seen.add(spec.content_id)

        selected = os.path.abspath(
            os.path.normpath(directory or self.destination(first))
        )
        results: dict[str, str | None] = {
            spec.content_id: None for spec in provided
        }
        if os.path.islink(selected):
            return results
        candidates: dict[str, str] = {}
        for spec in provided:
            try:
                executable = self.executable(spec, selected)
            except InstallError:
                continue
            if not self._executable_stays_within(selected, executable):
                continue
            try:
                file_stat = os.stat(executable, follow_symlinks=False)
            except (OSError, ValueError):
                continue
            if stat.S_ISREG(file_stat.st_mode) and os.access(executable, os.X_OK):
                candidates[spec.content_id] = executable
        if not candidates:
            return results
        if first.source_type == "git":
            try:
                managed_destination = self.destination(first)
                managed_selection = os.path.realpath(selected) == os.path.realpath(
                    managed_destination
                ) or os.path.lexists(os.path.join(selected, ".git"))
            except (InstallError, OSError, ValueError):
                return results
            if managed_selection:
                try:
                    verify_git_checkout(
                        first.repository, first.ref, selected, env=self.env
                    )
                except InstallError:
                    return results
        results.update(candidates)
        return results

    def ensure(self, spec: ContentSpec, report: Report = lambda _message: None) -> str:
        self._ensure_root()
        ready = self.ready(spec)
        if ready:
            return ready
        if spec.source_type not in ("git", "archive"):
            raise InstallError(
                f"{spec.content_id} uses a non-installable {spec.source_type} source"
            )
        self.destination(spec)
        with self._install_lock(spec.install_id):
            # Another process may have completed this same installation while
            # this one waited for the lock; adopt its selected result instead
            # of duplicating the fetch and build.
            ready = self.ready(spec)
            if ready:
                return ready
            if spec.source_type == "git":
                return self._ensure_git(spec, report)
            return self._ensure_archive(spec, report)

    @contextmanager
    def _install_lock(self, install_id: str) -> Iterator[None]:
        """Serialize one installation identity across processes and threads.

        The lock is re-entrant within a thread, so a nested ``ensure()`` for
        the same identity (for example from a report callback) can never
        deadlock against its own caller.
        """
        key = (self.root, install_id)
        held = getattr(_held_install_locks, "keys", None)
        if held is None:
            held = _held_install_locks.keys = set()
        if key in held:
            yield
            return
        lock_path = os.path.join(self.root, f".{install_id}.lock")
        descriptor = _acquire_install_lock(lock_path)
        held.add(key)
        try:
            yield
        finally:
            held.discard(key)
            # Remove the lock file while its lock is still held; a waiter
            # that acquires the orphaned inode detects the mismatch below
            # and retries on the fresh path.
            try:
                os.unlink(lock_path)
            except OSError:
                pass
            os.close(descriptor)

    def _create_stage(self, spec: ContentSpec) -> str:
        try:
            return tempfile.mkdtemp(
                prefix=f".{spec.install_id}.install-", dir=self.root
            )
        except OSError as exc:
            raise InstallError(
                f"could not create staging directory in {self.root}"
            ) from exc

    @staticmethod
    def _harden_git_stage(stage: str) -> None:
        """Remove group/other write bits created by a permissive umask.

        Build tools may validate every source ancestor before reading pinned
        inputs. Git honors the caller's umask when it creates checkout paths,
        so an otherwise private managed stage can contain group-writable
        directories and files. Preserve owner and executable bits while
        making the fetched tree safe for those tools.
        """
        for directory, names, files in os.walk(stage, followlinks=False):
            entries = (os.path.join(directory, name) for name in names + files)
            for path in (directory, *entries):
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    continue
                mode = stat.S_IMODE(info.st_mode)
                if mode & 0o022:
                    os.chmod(path, mode & ~0o022)

    def _replace_stage(self, stage: str, destination: str) -> None:
        if not os.path.lexists(destination):
            try:
                os.rename(stage, destination)
                return
            except OSError as exc:
                if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                    raise InstallError(
                        f"could not atomically select content path: {destination}"
                    ) from exc
                # A concurrent installer selected the destination between the
                # existence check and the rename; exchange with the freshly
                # selected tree instead of failing.
        if os.path.islink(destination) or not os.path.isdir(destination):
            raise InstallError(
                f"refusing to replace non-directory content path: {destination}"
            )
        try:
            _rename_exchange(stage, destination)
        except OSError as exc:
            raise InstallError(
                f"could not atomically replace content path: {destination}"
            ) from exc
        # The destination is never absent: stage now names the superseded
        # tree, which can be removed after the atomic exchange.
        try:
            shutil.rmtree(stage)
        except OSError as exc:
            raise InstallError(
                f"selected content but could not remove its superseded tree: {stage}"
            ) from exc

    def _existing_git_is_replaceable(self, spec: ContentSpec, destination: str) -> None:
        if not os.path.lexists(destination):
            return
        try:
            _require_managed_git_directory(destination)
        except InstallError as exc:
            raise InstallError(
                f"refusing to replace unmanaged content path: {destination}"
            ) from exc
        git_env = _git_environment(self.env)
        head, detached, dirty = _git_status(destination, git_env)
        if dirty:
            raise InstallError(f"refusing modified managed checkout: {destination}")
        origin = _git_origin(destination, git_env, allow_missing=True)
        if head == "(initial)":
            # An interrupted first-time `git init` has no selected source and
            # is safe to replace when it is otherwise empty.  A configured
            # origin, if present, must still be the catalog origin.
            if any(entry != ".git" for entry in os.listdir(destination)):
                raise InstallError(
                    f"refusing untracked files in interrupted checkout: {destination}"
                )
            if origin is not None and origin != spec.repository:
                raise InstallError(
                    f"refusing checkout with an unexpected origin: {destination}"
                )
            return
        if not detached:
            raise InstallError(f"refusing attached managed checkout: {destination}")
        if origin != spec.repository:
            raise InstallError(
                f"refusing checkout with an unexpected origin: {destination}"
            )
        _verify_submodules(destination, git_env)

    def _ensure_git(self, spec: ContentSpec, report: Report) -> str:
        if not _valid_git_identity(spec.repository, spec.ref):
            raise InstallError("managed checkout identity is invalid")
        destination = self.destination(spec)
        self._existing_git_is_replaceable(spec, destination)
        stage = self._create_stage(spec)
        try:
            commands = (
                ["git", "init", "--quiet"],
                ["git", "remote", "add", "origin", spec.repository],
                ["git", "fetch", "--quiet", "--depth", "1", "origin", spec.ref],
                ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
                [
                    "git",
                    "submodule",
                    "update",
                    "--quiet",
                    "--init",
                    "--recursive",
                    "--depth",
                    "1",
                ],
            )
            report(f"fetching pinned source {spec.ref[:12]} from {spec.repository} …")
            git_env = _git_environment(self.env)
            for argv in commands:
                try:
                    result = _run(
                        argv, cwd=stage, env=git_env, timeout=self.command_timeout
                    )
                except OSError as exc:
                    raise InstallError(
                        f"source setup could not start {' '.join(argv[:3])}"
                    ) from exc
                except subprocess.TimeoutExpired as exc:
                    raise InstallError(
                        f"source setup timed out ({' '.join(argv[:3])})"
                    ) from exc
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout).strip()[-600:]
                    raise InstallError(
                        f"source setup failed ({' '.join(argv[:3])}): {detail}"
                    )
            verify_git_checkout(spec.repository, spec.ref, stage, env=self.env)
            try:
                self._harden_git_stage(stage)
            except OSError as exc:
                raise InstallError("could not harden fetched source permissions") from exc
            self._build(spec, stage, report)
            # A build may create untracked outputs, but it must never rewrite
            # pinned source or move a dependency. Re-check the tracked tree
            # before it can become the selected installation.
            verify_git_checkout(spec.repository, spec.ref, stage, env=self.env)
            try:
                self._harden_git_stage(stage)
            except OSError as exc:
                raise InstallError("could not harden built source permissions") from exc
            self._replace_stage(stage, destination)
            stage = ""
        finally:
            if stage:
                shutil.rmtree(stage, ignore_errors=True)
        ready = self.ready(spec)
        if not ready:
            raise InstallError(f"installed content has no runnable {spec.binary}")
        return ready

    def _ensure_archive(self, spec: ContentSpec, report: Report) -> str:
        destination = self.destination(spec)
        if os.path.lexists(destination):
            raise InstallError(
                f"refusing to replace existing archive content: {destination}"
            )
        stage = self._create_stage(spec)
        archive_path = os.path.join(stage, ".download")
        extracted = os.path.join(stage, "content")
        try:
            os.mkdir(extracted)
            download(spec.urls, archive_path, report, spec.sha256)
            try:
                with tarfile.open(archive_path, "r:*") as archive:
                    safe_extract_tar(archive, extracted)
            except tarfile.ReadError:
                try:
                    with zipfile.ZipFile(archive_path) as archive:
                        safe_extract_zip(archive, extracted)
                except zipfile.BadZipFile as exc:
                    raise InstallError(
                        "download is neither a supported tar nor ZIP archive"
                    ) from exc
            try:
                os.unlink(archive_path)
            except OSError as exc:
                raise InstallError(
                    "could not remove verified archive staging file"
                ) from exc
            self._build(spec, extracted, report)
            self._replace_stage(extracted, destination)
            extracted = ""
        except InstallError:
            raise
        except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as exc:
            raise InstallError(f"archive installation failed: {exc}") from exc
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        ready = self.ready(spec)
        if not ready:
            raise InstallError(f"installed content has no runnable {spec.binary}")
        return ready

    def _build(self, spec: ContentSpec, directory: str, report: Report) -> None:
        detail = ""
        if spec.build:
            report(f"building {spec.label} …")
            try:
                # Build tools may reject a shared or otherwise permissive
                # inherited cache. Give each build a private temporary cache
                # and remove it on both success and failure.
                with tempfile.TemporaryDirectory(
                    prefix=".build-cache-", dir=self.root
                ) as cache:
                    os.chmod(cache, 0o700)
                    build_env = dict(self.env)
                    build_env["XDG_CACHE_HOME"] = cache
                    returncode, detail = _run_with_tail(
                        list(spec.build),
                        cwd=directory,
                        env=build_env,
                        timeout=self.command_timeout,
                    )
            except (OSError, ValueError) as exc:
                hint = f" ({spec.dependency_hint})" if spec.dependency_hint else ""
                raise InstallError(
                    f"build command could not start{hint}: {exc}"
                ) from exc
            detail = detail[-1000:]
            if returncode != 0:
                hint = f" ({spec.dependency_hint})" if spec.dependency_hint else ""
                raise InstallError(f"build failed{hint}: {detail}")
        try:
            executable = self.executable(spec, directory)
        except InstallError as exc:
            raise InstallError(
                f"build declared an unsafe binary path: {spec.binary!r}"
            ) from exc
        detail_suffix = f": {detail}" if detail else ""
        try:
            info = os.stat(executable, follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise InstallError(
                f"build produced no {spec.binary}{detail_suffix}"
            ) from exc
        if (
            not self._executable_stays_within(directory, executable)
            or not stat.S_ISREG(info.st_mode)
            or not os.access(executable, os.X_OK)
        ):
            raise InstallError(
                f"build produced no runnable {spec.binary}{detail_suffix}"
            )

    def asset_destination(self, spec: AssetSpec) -> str:
        asset_id = spec.asset_id
        parent = os.path.join(self.root, "assets")
        destination = os.path.abspath(os.path.join(parent, asset_id))
        if os.path.dirname(destination) != os.path.abspath(parent):
            raise InstallError(f"asset id is not a safe path component: {asset_id!r}")
        return destination

    def _ensure_asset_parent(self, spec: AssetSpec) -> str:
        parent = os.path.dirname(self.asset_destination(spec))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        return parent

    def _verify_asset_directory(self, spec: AssetSpec, directory: str) -> str | None:
        root = os.path.realpath(directory)
        if not os.path.isdir(root):
            return None
        seen: set[str] = set()
        for item in spec.files:
            target = os.path.join(root, item.path)
            if not os.path.isfile(target):
                return None
            try:
                info = os.stat(target, follow_symlinks=False)
            except OSError:
                return None
            if info.st_size != item.bytes or sha256_file(target) != item.sha256:
                return None
            seen.add(item.path)
        for dirpath, dirnames, filenames in os.walk(root):
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                if rel not in seen:
                    return None
        return directory

    def _asset_integrity_ready(self, spec: AssetSpec) -> tuple[str, ...] | None:
        destination = self.asset_destination(spec)
        if os.path.islink(destination):
            return None
        verified = self._verify_asset_directory(spec, destination)
        if verified is None:
            return None
        return (verified,)

    def _write_notices(self, spec: AssetSpec, output: str, notices: TextStore) -> None:
        for item in spec.files:
            if not item.path.startswith("notices/"):
                continue
            payload = notices.get(item.sha256, label=item.path)
            if len(payload) != item.bytes:
                raise InstallError("notice text does not match the manifest size")
            target = os.path.join(output, item.path)
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)

    def _strip_archive_root(self, extracted: str, root: str) -> str:
        entries = [name for name in os.listdir(extracted) if name not in {".", ".."}]
        if entries != [root]:
            raise InstallError("archive root does not match the declared directory")
        source = os.path.join(extracted, root)
        if not os.path.isdir(source):
            raise InstallError("archive root is not a directory")
        content = os.path.join(os.path.dirname(extracted), "content")
        os.rename(source, content)
        shutil.rmtree(extracted, ignore_errors=True)
        return content

    def _populate_upstream_asset(
        self,
        spec: AssetSpec,
        stage: str,
        report: Report,
        notices: TextStore,
        *,
        store: ReceiptStore,
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
        progress: Callable[[Progress], None] | None = None,
    ) -> str:
        extract = os.path.join(stage, "x")
        os.makedirs(extract, mode=0o700, exist_ok=True)
        partial_dir = os.path.join(os.path.dirname(self.asset_destination(spec)), ".partial", spec.digest)
        if spec.source_mode == "upstream-archive":
            archive_path = os.path.join(stage, ".download")
            report(f"fetching {spec.asset_id} …")
            fetch_exact(
                spec.url,
                archive_path,
                expected_bytes=spec.archive_bytes,
                expected_sha256=spec.archive_sha256,
                deadline=deadline,
                cancelled=cancelled,
                progress=progress,
                partial_dir=partial_dir,
                installed_bytes=spec.installed_bytes,
            )
            if spec.archive_format == "zip":
                with zipfile.ZipFile(archive_path) as archive:
                    safe_extract_zip(archive, extract)
            else:
                with tarfile.open(archive_path, "r:*") as archive:
                    safe_extract_tar(archive, extract)
            try:
                os.unlink(archive_path)
            except OSError as exc:
                raise InstallError("could not remove verified archive staging file") from exc
            output = self._strip_archive_root(extract, spec.root)
        elif spec.source_mode == "upstream-files":
            output = os.path.join(stage, "content")
            os.makedirs(output, mode=0o700, exist_ok=True)
            by_path = {item.path: item for item in spec.files}
            for index, item in enumerate(spec.fetch):
                listed = by_path[item.path]
                target = os.path.join(output, item.path)
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                fetch_exact(
                    item.url,
                    target,
                    expected_bytes=listed.bytes,
                    expected_sha256=listed.sha256,
                    deadline=deadline,
                    cancelled=cancelled,
                    progress=progress,
                    partial_dir=os.path.join(partial_dir, str(index)),
                )
        elif spec.source_mode == "upstream-convert":
            output = os.path.join(stage, "content")
            os.makedirs(output, mode=0o700, exist_ok=True)
            # With extra inputs the converter reads a private input directory
            # and writes the installed tree itself, so the inputs are staged
            # outside `output` and `output` is still empty at the conversion.
            input_directory = bool(spec.convert_inputs)
            source_layout = bool(spec.convert_input_path) and not input_directory
            if source_layout:
                staged_input = os.path.join(output, spec.convert_input_path)
                os.makedirs(os.path.dirname(staged_input), mode=0o700, exist_ok=True)
            elif input_directory:
                staged_input = os.path.join(stage, "input")
                os.makedirs(staged_input, mode=0o700, exist_ok=True)
            else:
                staged_input = os.path.join(stage, "input")
            primary = (
                os.path.join(staged_input, spec.convert_input_path)
                if input_directory
                else staged_input
            )
            fetch_exact(
                spec.convert_url,
                primary,
                expected_bytes=spec.convert_bytes,
                expected_sha256=spec.convert_sha256,
                deadline=deadline,
                cancelled=cancelled,
                progress=progress,
                partial_dir=partial_dir,
            )
            for index, item in enumerate(spec.convert_inputs):
                fetch_exact(
                    item.url,
                    os.path.join(staged_input, item.path),
                    expected_bytes=item.bytes,
                    expected_sha256=item.sha256,
                    deadline=deadline,
                    cancelled=cancelled,
                    progress=progress,
                    partial_dir=os.path.join(partial_dir, f"input-{index}"),
                )
            by_path = {item.path: item for item in spec.files}
            for index, item in enumerate(spec.fetch):
                listed = by_path[item.path]
                target = os.path.join(output, item.path)
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                fetch_exact(
                    item.url,
                    target,
                    expected_bytes=listed.bytes,
                    expected_sha256=listed.sha256,
                    deadline=deadline,
                    cancelled=cancelled,
                    progress=progress,
                    partial_dir=os.path.join(partial_dir, f"convert-{index}"),
                )
            derived = os.path.join(stage, "derived") if source_layout else output
            os.makedirs(derived, mode=0o700, exist_ok=True)
            # E1-VERIFY F7: the converter's licence gate binds whatever manifest
            # digest the caller asserts, so the caller must assert the real one.
            # Both are the values the licence screen bound into the receipt that
            # `ensure_upstream_asset` has already required.
            argv = [
                argument.replace("{input}", staged_input)
                .replace("{output}", derived)
                .replace("{sources}", output)
                .replace("{receipt_store}", os.fspath(store.root))
                .replace("{manifest_digest}", spec.manifest_digest)
                for argument in spec.convert_argv
            ]
            report(f"converting {spec.label} …")
            returncode, detail = _run_with_tail(
                argv, cwd=stage, env=self.env, timeout=self.command_timeout
            )
            if returncode != 0:
                raise InstallError(f"asset conversion failed with status {returncode}: {detail}")
        elif spec.source_mode == "registry-manifest":
            output = os.path.join(stage, "content")
            os.makedirs(output, mode=0o700, exist_ok=True)
            manifest_path = os.path.join(stage, "manifest.json")
            fetch_exact(
                spec.manifest_url,
                manifest_path,
                expected_bytes=spec.download_bytes,
                expected_sha256=spec.manifest_sha256,
                deadline=deadline,
                cancelled=cancelled,
                progress=progress,
                partial_dir=partial_dir,
            )
            # download_bytes for registry-manifest is the manifest size; blobs follow.
            by_path = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
            for index, item in enumerate(spec.blobs):
                listed = by_path[item.path]
                target = os.path.join(output, item.path)
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                fetch_exact(
                    item.url,
                    target,
                    expected_bytes=listed.bytes,
                    expected_sha256=listed.sha256,
                    deadline=deadline,
                    cancelled=cancelled,
                    progress=progress,
                    partial_dir=os.path.join(partial_dir, f"blob-{index}"),
                )
        else:
            raise InstallError("asset source mode is unsupported")
        self._write_notices(spec, output, notices)
        return output

    def _populate_supplied_asset(
        self,
        spec: AssetSpec,
        stage: str,
        report: Report,
        notices: TextStore,
        *,
        supplied: str | os.PathLike[str],
    ) -> str:
        """Stage the asset from bytes the user already holds (OD-BO).

        Every installed file except the licence notices is read from
        `<supplied>/<path>`, where `path` is exactly the manifest path -- the
        same layout an installed asset has, so a tree copied from another
        machine can be supplied unchanged. Each file is opened once and
        verified against the manifest's own size and digest before and after
        it is copied (`SuppliedFile.open_beneath`, which follows no symlink
        at any depth below `supplied`), and the staged tree is then verified
        again as a whole by the caller. Notices are written from the packaged
        licence authority, never from the supplied directory, so a supplier
        cannot substitute the licence text.
        """
        source = os.path.abspath(os.fspath(supplied))
        if not os.path.isdir(source):
            raise InstallError(f"supplied directory does not exist: {source}")
        output = os.path.join(stage, "content")
        os.makedirs(output, mode=0o700, exist_ok=True)
        wanted = [
            item for item in spec.files if not item.path.startswith("notices/")
        ]
        if not wanted:
            raise InstallError("this asset has no files that can be supplied")
        report(f"reading {len(wanted)} supplied file(s) for {spec.asset_id} …")
        for item in wanted:
            with SuppliedFile.open_beneath(source, item.path) as handle:
                if handle.bytes != item.bytes or handle.sha256 != item.sha256:
                    raise InstallError(
                        f"supplied file does not match the manifest: {item.path}"
                    )
                target = os.path.join(output, item.path)
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                handle.copy_to(target)
                # The bytes were read from the held descriptor, so this proves
                # the file was not rewritten underneath the copy.
                handle.revalidate()
        self._write_notices(spec, output, notices)
        return output

    @contextmanager
    def _asset_lock(
        self,
        spec: AssetSpec,
        parent: str,
        *,
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
        progress: Callable[[Progress], None] | None = None,
    ) -> Iterator[None]:
        lock_path = os.path.join(parent, f".{spec.asset_id}.lock")
        owner_path = os.path.join(parent, f".install-{spec.asset_id}.owner")
        last_wait = 0.0
        while True:
            if cancelled is not None and cancelled():
                raise DownloadError("cancelled")
            if deadline is not None and time.monotonic() >= deadline:
                raise DownloadError("deadline")
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
                now = time.monotonic()
                if progress is not None and now - last_wait >= 1.0:
                    last_wait = now
                    progress(
                        Progress(
                            phase="waiting",
                            host="",
                            owner_pid=os.getpid(),
                            started=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        )
                    )
                time.sleep(0.1)
                continue
            try:
                payload = json.dumps(
                    {
                        "host": "",
                        "pid": os.getpid(),
                        "started_utc": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                tmp = owner_path + ".tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
                try:
                    os.write(fd, payload)
                finally:
                    os.close(fd)
                os.replace(tmp, owner_path)
                yield
            finally:
                try:
                    os.unlink(owner_path)
                except OSError:
                    pass
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass
                os.close(descriptor)
            return  # pragma: no cover

    def _select_asset(
        self,
        spec: AssetSpec,
        populate: Callable[[str], str],
        *,
        store: ReceiptStore,
        records: RecordIndex,
        report: Report,
        cancelled: Callable[[], bool] | None,
        deadline: float | None,
        progress: Callable[[Progress], None] | None,
        installed_by_other: list[bool] | None,
        covered_message: str,
    ) -> tuple[str, ...]:
        """Licence, lock, stage, verify, select -- whatever produced the bytes.

        `populate(stage)` is the only difference between an upstream download
        and a user-supplied install (OD-BO), so both get the same discipline by
        construction rather than by two implementations that agree today: a
        covering receipt is required before staging, again under the lock,
        and again after the staged tree has been verified against the
        manifest, and a tree that does not match its manifest is never
        selected.

        Each of those three checks has a test of its own that no other check
        can satisfy, because each is distinguished by what had already
        happened when it refused (`tests/test_supplied_install.py`). They were
        stated as discipline before any test held them, and all three could be
        deleted one at a time with the suite green.

        The final verification runs **under the lock** and withdraws the
        selection before refusing, so a refusal never leaves non-matching
        bytes at the installed path.
        """
        self._ensure_root()
        asset = AssetRef(
            id=spec.asset_id,
            record_digest=spec.licenses[0].record_digest,
            manifest_digest=spec.manifest_digest,
        )
        require_license(asset, records=records, store=store)
        ready = self._asset_integrity_ready(spec)
        if ready is not None:
            if installed_by_other is not None:
                installed_by_other.append(True)
            return ready
        destination = self.asset_destination(spec)
        parent = self._ensure_asset_parent(spec)
        with self._asset_lock(
            spec, parent, cancelled=cancelled, deadline=deadline, progress=progress
        ):
            require_license(asset, records=records, store=store)
            ready = self._asset_integrity_ready(spec)
            if ready is not None:
                if installed_by_other is not None:
                    installed_by_other.append(True)
                report(covered_message)
                return ready
            if os.path.lexists(destination):
                raise InstallError("refusing to replace an unverified asset selection")
            stage = tempfile.mkdtemp(prefix=".asset-install-", dir=parent)
            try:
                output = populate(stage)
                if self._verify_asset_directory(spec, output) is None:
                    raise InstallError("staged asset tree does not match its manifest")
                require_license(asset, records=records, store=store)
                self._replace_stage(output, destination)
                # Still under the lock, so the tree at `destination` is the one
                # this call just selected and nobody else's -- which is what
                # makes withdrawing it safe.
                selected = self._asset_integrity_ready(spec)
                if selected is None:
                    self._withdraw_selection(destination)
                    raise InstallError("installed asset failed final verification")
            except (InstallError, DownloadError):
                raise
            except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as exc:
                raise InstallError("asset installation failed") from exc
            finally:
                shutil.rmtree(stage, ignore_errors=True)
        return selected

    def _withdraw_selection(self, destination: str) -> None:
        """Undo a selection that failed its final verification.

        A refusal must not leave bytes that do not match the manifest at the
        installed path. The staged-tree check above is what normally makes
        that impossible -- but when it was made a no-op, the corrupt tree was
        **published and then refused**, and it stayed there
        (C-V3-EXTEND-VERIFY F4; the same shape C-MIGRATE-KILIX-VERIFY V3
        recorded for kilix). Two guards covering each other's blind spots is
        luck; a refusal that leaves nothing behind is the property.

        Called only under the asset lock, on a destination this call created
        after finding it absent, so nothing here removes another installer's
        tree.
        """
        try:
            if os.path.islink(destination) or not os.path.isdir(destination):
                os.unlink(destination)
                return
            shutil.rmtree(destination)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise InstallError(
                "installed asset failed final verification and could not be "
                f"withdrawn: {destination}"
            ) from exc

    def ensure_upstream_asset(
        self,
        spec: AssetSpec,
        *,
        store: ReceiptStore,
        records: RecordIndex,
        notices: TextStore,
        report: Report = lambda _message: None,
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
        progress: Callable[[Progress], None] | None = None,
        installed_by_other: list[bool] | None = None,
    ) -> tuple[str, ...]:
        """Install one exact upstream asset after a covering licence receipt exists."""
        return self._select_asset(
            spec,
            lambda stage: self._populate_upstream_asset(
                spec,
                stage,
                report,
                notices,
                store=store,
                cancelled=cancelled,
                deadline=deadline,
                progress=progress,
            ),
            store=store,
            records=records,
            report=report,
            cancelled=cancelled,
            deadline=deadline,
            progress=progress,
            installed_by_other=installed_by_other,
            covered_message="Installed by another process; nothing downloaded",
        )

    def ensure_supplied_asset(
        self,
        spec: AssetSpec,
        *,
        supplied: str | os.PathLike[str],
        store: ReceiptStore,
        records: RecordIndex,
        notices: TextStore,
        report: Report = lambda _message: None,
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
        progress: Callable[[Progress], None] | None = None,
        installed_by_other: list[bool] | None = None,
    ) -> tuple[str, ...]:
        """Install one exact asset from bytes the user already holds (OD-BO).

        The air-gapped and metered-connection path: `supplied` is a directory
        holding the asset's installed files at their manifest paths, and this
        makes **no network request of any kind** -- no fetch, no name lookup,
        no connection. Everything else is the upstream path's discipline,
        unchanged: the same covering receipt is required at the same three
        points, every file is verified against the manifest by size and digest
        through a descriptor that is never reopened, the licence notices are
        written from the packaged authority rather than from the supplied
        directory, and the staged tree must match the manifest exactly -- an
        extra file in it is refused -- before it is selected.

        It is available for every source mode, because at asset/v3 the
        manifest, not the mode, is what determines the installed tree. For an
        `upstream-convert` record the supplied tree is the conversion's output;
        the converter's own gate binds the same record and manifest digests
        this call requires, so nothing is skipped by supplying them.
        """
        return self._select_asset(
            spec,
            lambda stage: self._populate_supplied_asset(
                spec, stage, report, notices, supplied=supplied
            ),
            store=store,
            records=records,
            report=report,
            cancelled=cancelled,
            deadline=deadline,
            progress=progress,
            installed_by_other=installed_by_other,
            covered_message="Installed by another process; nothing was read",
        )

    def ensure_asset(
        self,
        spec: AssetSpec,
        store: ReceiptStore,
        records: RecordIndex,
        notices: TextStore,
        report: Report = lambda _message: None,
        *,
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
        progress: Callable[[Progress], None] | None = None,
    ) -> tuple[str, ...]:
        return self.ensure_upstream_asset(
            spec,
            store=store,
            records=records,
            notices=notices,
            report=report,
            cancelled=cancelled,
            deadline=deadline,
            progress=progress,
        )
