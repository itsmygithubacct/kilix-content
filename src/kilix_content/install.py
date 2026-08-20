"""Unprivileged, immutable content installation primitives."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import shutil
import stat

# Child processes always receive an argv array and never invoke a shell.
import subprocess  # nosec B404
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from .model import AssetSpec, ContentSpec
from .receipt import ReceiptError, ReceiptStore, ReleaseContext

Report = Callable[[str], None]

_AT_FDCWD = -100
_RENAME_EXCHANGE = 2
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
_SAFE_GIT_PROTOCOLS = frozenset(("file", "git", "http", "https", "ssh"))


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
            try:
                parsed = urlsplit(url)
                display_name = os.path.basename(parsed.path.rstrip("/")) or "content"
            except (TypeError, ValueError):
                display_name = "content"
            if (
                len(display_name) > 128
                or not isinstance(display_name, str)
                or not display_name.isprintable()
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in display_name
                )
            ):
                display_name = "content"
            report(f"downloading {display_name} …")
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
                        "downloaded content failed SHA-256 verification"
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
    error_type = type(last_error).__name__ if last_error is not None else "unknown"
    raise InstallError(
        f"all {len(candidates)} content download candidates failed ({error_type})"
    )


def _run(
    argv: list[str], *, cwd: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )  # nosec B603


def _run_with_tail(
    argv: list[str], *, cwd: str, env: dict[str, str], tail_bytes: int = 16 * 1024
) -> tuple[int, str]:
    process = subprocess.Popen(
        argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )  # nosec B603
    tail = bytearray()
    output = process.stdout
    if output is None:
        process.kill()
        process.wait()
        raise RuntimeError("could not capture build output")
    with output:
        while block := output.read(64 * 1024):
            tail.extend(block)
            if len(tail) > tail_bytes:
                del tail[:-tail_bytes]
    return process.wait(), tail.decode("utf-8", errors="replace").strip()


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
    """Install catalog entries below one caller-owned data directory."""

    def __init__(self, root: str, *, env: dict[str, str] | None = None):
        try:
            root = os.fspath(root)
        except TypeError as exc:
            raise InstallError("content root must be a filesystem path") from exc
        if not isinstance(root, str) or "\x00" in root or not os.path.isabs(root):
            raise InstallError("content root must be an absolute path")
        self.root = os.path.normpath(root)
        self.env = dict(os.environ if env is None else env)
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

    def asset_destination(self, spec: AssetSpec) -> str:
        """Return the version-qualified selection directory for an asset."""
        try:
            destination = os.path.abspath(
                os.path.join(self.root, spec.asset_id, spec.version)
            )
            parent = os.path.abspath(os.path.join(self.root, spec.asset_id))
        except (TypeError, ValueError) as exc:
            raise InstallError("asset identity is not a safe path") from exc
        if (
            parent == self.root
            or os.path.dirname(parent) != self.root
            or destination == parent
            or os.path.dirname(destination) != parent
        ):
            raise InstallError("asset identity is not a safe path")
        return destination

    def asset_ready(
        self, spec: AssetSpec, store: ReceiptStore, release: ReleaseContext
    ) -> tuple[str, ...] | None:
        """Return exact paths only after license authorization and integrity checks."""
        store.require_asset(spec, release)
        return self._asset_integrity_ready(spec)

    def _asset_integrity_ready(self, spec: AssetSpec) -> tuple[str, ...] | None:
        """Probe exact bytes without creating a usable, authorization-bypassing API."""
        selected = self.asset_destination(spec)
        return self._verify_asset_directory(spec, selected)

    def _verify_asset_directory(
        self, spec: AssetSpec, selected: str
    ) -> tuple[str, ...] | None:
        if os.path.islink(selected) or not os.path.isdir(selected):
            return None
        expected = {item.path: item for item in spec.files}
        observed: set[str] = set()
        try:
            for directory, names, files in os.walk(selected, followlinks=False):
                for name in names:
                    if os.path.islink(os.path.join(directory, name)):
                        return None
                for name in files:
                    path = os.path.join(directory, name)
                    relative = os.path.relpath(path, selected).replace(os.sep, "/")
                    item = expected.get(relative)
                    if item is None or os.path.islink(path):
                        return None
                    info = os.stat(path, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_mode & 0o111
                        or info.st_size != item.bytes
                        or sha256_file(path) != item.sha256
                    ):
                        return None
                    observed.add(relative)
        except (OSError, ValueError):
            return None
        if observed != set(expected):
            return None
        return tuple(os.path.join(selected, item.path) for item in spec.files)

    def ensure_asset(
        self,
        spec: AssetSpec,
        store: ReceiptStore,
        release: ReleaseContext,
        report: Report = lambda _message: None,
    ) -> tuple[str, ...]:
        """Install one exact mirrored asset after every license is authorized."""
        self._ensure_root()
        store.require_asset(spec, release)
        ready = self._asset_integrity_ready(spec)
        if ready is not None:
            return ready
        if spec.source_mode != "mirrored":
            raise InstallError(
                f"{spec.asset_id} requires user-supplied acquisition support"
            )
        destination = self.asset_destination(spec)
        if os.path.lexists(destination):
            raise InstallError(
                f"refusing to replace an unverified asset selection: {destination}"
            )
        parent = os.path.dirname(destination)
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise InstallError(f"could not create asset root: {parent}") from exc
        stage = tempfile.mkdtemp(prefix=f".{spec.version}.install-", dir=parent)
        archive_path = os.path.join(stage, ".download")
        extracted = os.path.join(stage, "content")
        os.mkdir(extracted)
        try:
            download(
                spec.mirrors,
                archive_path,
                report,
                spec.archive_sha256,
            )
            try:
                with tarfile.open(archive_path, "r:*") as archive:
                    safe_extract_tar(archive, extracted)
            except tarfile.ReadError:
                try:
                    with zipfile.ZipFile(archive_path) as archive:
                        safe_extract_zip(archive, extracted)
                except zipfile.BadZipFile as exc:
                    raise InstallError(
                        "asset download is neither a supported tar nor ZIP archive"
                    ) from exc
            if self._verify_asset_directory(spec, extracted) is None:
                raise InstallError(
                    f"{spec.asset_id} extracted tree does not match its manifest"
                )
            # Authorization can be removed or corrupted during a long download.
            # Recheck the same exact bindings immediately before selection.
            store.require_asset(spec, release)
            self._replace_stage(extracted, destination)
            extracted = ""
        except (InstallError, ReceiptError):
            raise
        except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as exc:
            raise InstallError(f"asset installation failed: {exc}") from exc
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        selected = self.asset_ready(spec, store, release)
        if selected is None:
            raise InstallError(f"installed asset failed final verification: {spec.asset_id}")
        return selected

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
        if spec.source_type == "git":
            return self._ensure_git(spec, report)
        if spec.source_type == "archive":
            return self._ensure_archive(spec, report)
        raise InstallError(
            f"{spec.content_id} uses a non-installable {spec.source_type} source"
        )

    def _replace_stage(self, stage: str, destination: str) -> None:
        if os.path.lexists(destination):
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
        else:
            try:
                os.rename(stage, destination)
            except OSError as exc:
                raise InstallError(
                    f"could not atomically select content path: {destination}"
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
        stage = tempfile.mkdtemp(prefix=f".{spec.install_id}.install-", dir=self.root)
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
                    result = _run(argv, cwd=stage, env=git_env)
                except OSError as exc:
                    raise InstallError(
                        f"source setup could not start {' '.join(argv[:3])}"
                    ) from exc
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout).strip()[-600:]
                    raise InstallError(
                        f"source setup failed ({' '.join(argv[:3])}): {detail}"
                    )
            verify_git_checkout(spec.repository, spec.ref, stage, env=self.env)
            self._build(spec, stage, report)
            # A build may create untracked outputs, but it must never rewrite
            # pinned source or move a dependency. Re-check the tracked tree
            # before it can become the selected installation.
            verify_git_checkout(spec.repository, spec.ref, stage, env=self.env)
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
        stage = tempfile.mkdtemp(prefix=f".{spec.install_id}.install-", dir=self.root)
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
                returncode, detail = _run_with_tail(
                    list(spec.build), cwd=directory, env=self.env
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
