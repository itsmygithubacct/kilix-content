"""Unprivileged, immutable content installation primitives."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Callable, Iterable
import urllib.request
import zipfile

from .model import ContentSpec


Report = Callable[[str], None]

_AT_FDCWD = -100
_RENAME_EXCHANGE = 2


class InstallError(RuntimeError):
    """A content install failed without selecting a partial result."""


def _rename_exchange(first: str, second: str) -> None:
    """Atomically exchange two filesystem entries using Linux renameat2."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable") from exc
    renameat2.argtypes = [
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(_AT_FDCWD, os.fsencode(first),
                 _AT_FDCWD, os.fsencode(second),
                 _RENAME_EXCHANGE) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), first, second)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_member_path(destination: str, member_name: str) -> str:
    if not member_name or "\x00" in member_name or os.path.isabs(member_name):
        raise InstallError(f"archive contains unsafe path: {member_name!r}")
    target = os.path.realpath(os.path.join(destination, member_name))
    root = os.path.realpath(destination)
    if target != root and not target.startswith(root + os.sep):
        raise InstallError(f"archive contains unsafe path: {member_name!r}")
    return target


def safe_extract_tar(archive: tarfile.TarFile, destination: str) -> None:
    """Extract regular files/directories while rejecting links and escapes."""
    members = archive.getmembers()
    for member in members:
        _safe_member_path(destination, member.name)
        if not (member.isdir() or member.isfile()):
            raise InstallError(f"archive contains unsupported member: {member.name!r}")
    archive.extractall(destination, members=members)


def safe_extract_zip(archive: zipfile.ZipFile, destination: str) -> None:
    """Extract files/directories while rejecting paths and Unix symlinks."""
    for member in archive.infolist():
        _safe_member_path(destination, member.filename)
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise InstallError(f"archive contains unsupported symlink: {member.filename!r}")
    archive.extractall(destination)


def download(urls: str | Iterable[str], destination: str, report: Report = lambda _message: None,
             expected_sha256: str = "") -> str:
    """Download the first working URL and validate its exact digest."""
    candidates = (urls,) if isinstance(urls, str) else tuple(urls)
    last_error: Exception | None = None
    for url in candidates:
        try:
            report(f"downloading {url.rsplit('/', 1)[-1]} …")
            request = urllib.request.Request(url, headers={"User-Agent": "kilix-content/0.1"})
            with urllib.request.urlopen(request, timeout=60) as response, open(destination, "wb") as output:
                while block := response.read(64 * 1024):
                    output.write(block)
            if expected_sha256:
                actual = sha256_file(destination)
                if actual != expected_sha256:
                    raise InstallError(
                        f"sha256 mismatch for {url}: expected {expected_sha256}, got {actual}")
            return destination
        except Exception as exc:
            last_error = exc
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass
    raise InstallError(f"all content downloads failed: {last_error}")


def _run(argv: list[str], *, cwd: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)


def verify_git_checkout(repository: str, ref: str, directory: str) -> None:
    """Require the configured origin, exact HEAD, clean tracked files, and initialized submodules."""
    if os.path.islink(directory) or not os.path.isdir(os.path.join(directory, ".git")):
        raise InstallError(f"not a managed Git checkout: {directory}")
    checks = {
        "origin": ["git", "config", "--get", "remote.origin.url"],
        "head": ["git", "rev-parse", "HEAD"],
        "status": ["git", "status", "--porcelain", "--untracked-files=no"],
        "submodules": ["git", "submodule", "status", "--recursive"],
    }
    results = {name: _run(argv, cwd=directory) for name, argv in checks.items()}
    if any(result.returncode != 0 for result in results.values()):
        raise InstallError(f"could not verify managed checkout: {directory}")
    if results["origin"].stdout.strip() != repository:
        raise InstallError(f"managed checkout has an unexpected origin: {directory}")
    if results["head"].stdout.strip() != ref:
        raise InstallError(f"managed checkout is not at its pinned commit: {directory}")
    if results["status"].stdout.strip():
        raise InstallError(f"refusing modified managed checkout: {directory}")
    for line in results["submodules"].stdout.splitlines():
        if line[:1] in ("-", "+", "U"):
            raise InstallError(f"managed checkout has an invalid submodule state: {directory}")


class Installer:
    """Install catalog entries below one caller-owned data directory."""

    def __init__(self, root: str, *, env: dict[str, str] | None = None):
        if not os.path.isabs(root):
            raise InstallError("content root must be an absolute path")
        self.root = os.path.normpath(root)
        self.env = dict(os.environ if env is None else env)
        self._ensure_root()

    def _ensure_root(self) -> None:
        if os.path.lexists(self.root) and os.path.islink(self.root):
            raise InstallError(f"content root must not be a symlink: {self.root}")
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        if not os.path.isdir(self.root):
            raise InstallError(f"content root is not a directory: {self.root}")

    def destination(self, spec: ContentSpec) -> str:
        return os.path.join(self.root, spec.content_id)

    def executable(self, spec: ContentSpec, directory: str | None = None) -> str:
        return os.path.join(directory or self.destination(spec), spec.binary)

    def ready(self, spec: ContentSpec, directory: str | None = None) -> str | None:
        selected = os.path.normpath(directory or self.destination(spec))
        executable = self.executable(spec, selected)
        try:
            file_stat = os.stat(executable, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(file_stat.st_mode) or not os.access(executable, os.X_OK):
            return None
        if spec.source_type == "git" and selected == self.destination(spec):
            try:
                verify_git_checkout(spec.repository, spec.ref, selected)
            except InstallError:
                return None
        return executable

    def ensure(self, spec: ContentSpec, report: Report = lambda _message: None) -> str:
        ready = self.ready(spec)
        if ready:
            return ready
        if spec.source_type == "git":
            return self._ensure_git(spec, report)
        if spec.source_type == "archive":
            return self._ensure_archive(spec, report)
        raise InstallError(f"{spec.content_id} uses a non-installable {spec.source_type} source")

    def _replace_stage(self, stage: str, destination: str) -> None:
        if os.path.lexists(destination):
            if os.path.islink(destination) or not os.path.isdir(destination):
                raise InstallError(f"refusing to replace non-directory content path: {destination}")
            try:
                _rename_exchange(stage, destination)
            except OSError as exc:
                raise InstallError(
                    f"could not atomically replace content path: {destination}"
                ) from exc
            # The destination is never absent: stage now names the superseded
            # tree, which can be removed after the atomic exchange.
            shutil.rmtree(stage)
        else:
            os.rename(stage, destination)

    def _existing_git_is_replaceable(self, spec: ContentSpec, destination: str) -> None:
        if not os.path.exists(destination):
            return
        if os.path.islink(destination) or not os.path.isdir(os.path.join(destination, ".git")):
            raise InstallError(f"refusing to replace unmanaged content path: {destination}")
        status = _run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=destination)
        if status.returncode != 0 or status.stdout.strip():
            raise InstallError(f"refusing modified managed checkout: {destination}")
        origin = _run(["git", "config", "--get", "remote.origin.url"], cwd=destination)
        head = _run(["git", "rev-parse", "--verify", "HEAD"], cwd=destination)
        if head.returncode != 0:
            # An interrupted first-time `git init` has no selected source and
            # is safe to replace when it is otherwise empty.  A configured
            # origin, if present, must still be the catalog origin.
            if origin.returncode == 0 and origin.stdout.strip() != spec.repository:
                raise InstallError(f"refusing checkout with an unexpected origin: {destination}")
            return
        if origin.returncode != 0 or origin.stdout.strip() != spec.repository:
            raise InstallError(f"refusing checkout with an unexpected origin: {destination}")

    def _ensure_git(self, spec: ContentSpec, report: Report) -> str:
        destination = self.destination(spec)
        self._existing_git_is_replaceable(spec, destination)
        stage = tempfile.mkdtemp(prefix=f".{spec.content_id}.install-", dir=self.root)
        try:
            commands = (
                ["git", "init", "--quiet"],
                ["git", "remote", "add", "origin", spec.repository],
                ["git", "fetch", "--depth", "1", "origin", spec.ref],
                ["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
                ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"],
            )
            report(f"fetching pinned source {spec.ref[:12]} from {spec.repository} …")
            for argv in commands:
                result = _run(argv, cwd=stage, env=self.env)
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout).strip()[-600:]
                    raise InstallError(f"source setup failed ({' '.join(argv[:3])}): {detail}")
            verify_git_checkout(spec.repository, spec.ref, stage)
            self._build(spec, stage, report)
            # A build may create untracked outputs, but it must never rewrite
            # pinned source or move a dependency. Re-check the tracked tree
            # before it can become the selected installation.
            verify_git_checkout(spec.repository, spec.ref, stage)
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
            raise InstallError(f"refusing to replace existing archive content: {destination}")
        stage = tempfile.mkdtemp(prefix=f".{spec.content_id}.install-", dir=self.root)
        archive_path = os.path.join(stage, ".download")
        extracted = os.path.join(stage, "content")
        os.mkdir(extracted)
        try:
            download(spec.urls, archive_path, report, spec.sha256)
            try:
                with tarfile.open(archive_path, "r:*") as archive:
                    safe_extract_tar(archive, extracted)
            except tarfile.ReadError:
                try:
                    with zipfile.ZipFile(archive_path) as archive:
                        safe_extract_zip(archive, extracted)
                except zipfile.BadZipFile as exc:
                    raise InstallError("download is neither a supported tar nor ZIP archive") from exc
            os.unlink(archive_path)
            self._build(spec, extracted, report)
            self._replace_stage(extracted, destination)
            extracted = ""
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        ready = self.ready(spec)
        if not ready:
            raise InstallError(f"installed content has no runnable {spec.binary}")
        return ready

    def _build(self, spec: ContentSpec, directory: str, report: Report) -> None:
        if spec.build:
            report(f"building {spec.label} …")
            result = _run(list(spec.build), cwd=directory, env=self.env)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()[-1000:]
                hint = f" ({spec.dependency_hint})" if spec.dependency_hint else ""
                raise InstallError(f"build failed{hint}: {detail}")
        executable = self.executable(spec, directory)
        try:
            info = os.stat(executable, follow_symlinks=False)
        except OSError as exc:
            raise InstallError(f"build produced no {spec.binary}") from exc
        if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
            raise InstallError(f"build produced no runnable {spec.binary}")
