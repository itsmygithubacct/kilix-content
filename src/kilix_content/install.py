"""Unprivileged, immutable content installation primitives."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import selectors
import shutil
import signal
import stat
import unicodedata

# Child processes always receive an argv array and never invoke a shell.
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

from .model import AssetSpec, Catalog, CatalogError, ContentSpec
from .receipt import (
    BindingMismatch,
    ReceiptError,
    ReceiptStore,
    ReleaseContext,
    VerifiedInput,
)

Report = Callable[[str], None]

_AT_FDCWD = -100
_RENAME_EXCHANGE = 2
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
_SAFE_GIT_PROTOCOLS = frozenset(("file", "git", "http", "https", "ssh"))
_CONVERTER_TAIL_BYTES = 16 * 1024
_CONVERTER_TIMEOUT_SECONDS = 15 * 60.0
_CONVERTER_TERMINATE_GRACE_SECONDS = 2.0
_CONVERTER_ATTESTATION_BYTES = 512
_CONVERTER_ATTESTATION_SCHEMA = "kilix.content.converter-attestation/v1"


class InstallError(RuntimeError):
    """A content install failed without selecting a partial result."""


class _CleanupRefusal(InstallError):
    """Group cleanup ran to completion and could not prove the group empty.

    Deliberately distinct from every other ``InstallError``. A refusal is a
    *finished* cleanup with a negative result, so the caller must propagate it
    without cleaning or reaping again. Any other error raised while cleaning --
    an unreadable ``/proc``, say -- means cleanup did *not* complete, and the
    caller's fallback must still run. A single boolean set from a broad
    ``except InstallError`` would confuse the two.

    Private: callers outside this module see it as ``InstallError``.
    """


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


@dataclass(frozen=True)
class AcquisitionRequired:
    """Trusted catalog facts a UI needs to request user-supplied bytes."""

    asset_id: str
    official_url: str
    reason: str
    input_bytes: int
    input_sha256: str
    conversion_required: bool
    conversion_tool_asset_id: str


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
    # The last mirror's failure is identified by its sanitized class name only.
    # The raw exception is deliberately not chained: a rendered traceback prints
    # chained causes, which would re-expose URL and query tokens.
    raise InstallError(
        f"all {len(candidates)} content download candidates failed ({error_type})"
    ) from None


_CHILD_COMMAND_LABEL = "child command"
_BUILD_COMMAND_LABEL = "build command"
# Post-exit drain bounds. Only a bounded diagnostic tail is ever retained, so
# there is nothing to gain from draining exhaustively -- and a descendant that
# writes without gaps can keep a descriptor ready indefinitely, which would
# turn an exhaustive drain into an unbounded loop that never reaches group
# teardown or its own deadline.
_POST_EXIT_DRAIN_BLOCKS = 64
_POST_EXIT_DRAIN_SECONDS = 0.5


def _drain_pending(
    poller: selectors.BaseSelector,
    absorb: Callable[[], bool],
    *,
    blocks: int = _POST_EXIT_DRAIN_BLOCKS,
    seconds: float = _POST_EXIT_DRAIN_SECONDS,
) -> None:
    """Absorb what is already buffered, under a hard block and time bound.

    The leader has exited and the group is about to be torn down, so this is
    only about keeping the last of the diagnostic tail. It must never wait on
    a still-writing descendant.
    """
    deadline = time.monotonic() + seconds
    for _block in range(blocks):
        if time.monotonic() >= deadline:
            return
        if not poller.select(0):
            return
        if not absorb():
            return


def _drain_stream(
    stream: object, sink: bytearray, failures: list[BaseException]
) -> None:
    """Move one child stream into memory so no pipe can wedge the caller.

    A read that fails part-way leaves ``sink`` holding a prefix of the real
    output. Swallowing that error would let the caller hand back a silently
    truncated result, so the failure is recorded for the caller to refuse on.
    """
    try:
        with stream:  # type: ignore[attr-defined]
            while block := stream.read(64 * 1024):  # type: ignore[attr-defined]
                sink.extend(block)
    except (OSError, ValueError) as exc:
        failures.append(exc)


def _group_is_settled(process: subprocess.Popen[bytes], *, label: str) -> bool:
    """True when the leader has exited and no other group member is live."""
    if not _wait_without_reaping(process, 0, label=label):
        return False
    return not _live_process_group_members(process, label=label)


def _teardown_process_group(
    process: subprocess.Popen[bytes],
    *,
    label: str,
    grace: float = _CONVERTER_TERMINATE_GRACE_SECONDS,
) -> bool:
    """Bring down a whole group -- leader included -- in bounded steps.

    One discipline for every forced path: ``SIGTERM``, a bounded grace window,
    then ``SIGKILL`` and a second bounded window, then prove the group is
    empty. Reporting ``False`` means cleanup could not be proven; the caller
    must refuse rather than present a result.

    The leader is never reaped here. While it stays an unreaped zombie the
    kernel cannot recycle its PID/PGID, so a later signal in this escalation
    cannot land on an unrelated group.
    """
    if _group_is_settled(process, label=label):
        return True
    for signum in (signal.SIGTERM, signal.SIGKILL):
        _signal_process_group(process, signum)
        deadline = time.monotonic() + grace
        while True:
            if _group_is_settled(process, label=label):
                return True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
    return _group_is_settled(process, label=label)


def _release_readers(
    process: subprocess.Popen[bytes], readers: list[threading.Thread]
) -> None:
    """Let capture threads finish, then close any pipe still open.

    Only ever called once the group is gone, so every writer has closed and a
    reader blocked in ``read`` returns at EOF. The join is still bounded, and
    any stream left open is closed afterwards so a thread that never started
    cannot strand a descriptor.
    """
    for reader in readers:
        reader.join(timeout=_CONVERTER_TERMINATE_GRACE_SECONDS)
    if any(reader.is_alive() for reader in readers):
        # A live reader still owns its stream; closing would block on the lock
        # that reader holds. Leave it owned rather than hang the caller.
        return
    for name in ("stdout", "stderr"):
        stream = getattr(process, name, None)
        if stream is None:
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _reap_after_group_cleanup(
    process: subprocess.Popen[bytes],
    *,
    label: str,
    on_cleaned: Callable[[], None] | None = None,
) -> int:
    """Clear the whole group, then reap the leader that reserved its group id.

    The leader is deliberately left unreaped until every same-group descendant
    is gone: while it remains a zombie the kernel cannot recycle its PID/PGID
    into an unrelated group, so the escalating signals cannot go astray.
    ``_terminate_remaining_process_group`` raises when a member survives
    escalation, so a returned code always means the complete group ended.
    """
    _terminate_remaining_process_group(process, label=label)
    if on_cleaned is not None:
        on_cleaned()
    return process.wait()


def _reap_only(process: subprocess.Popen[bytes], *, label: str) -> int:
    """Reap a leader whose group is already proven empty, with bounded retry.

    Used by the guards' fallback paths: once the group is gone the only
    outstanding work is the reap, and repeating group cleanup would be wrong
    work on a dead group.
    """
    last = None
    for _attempt in range(3):
        try:
            return process.wait()
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise InstallError(f"{label} could not be reaped after cleanup") from last


def _force_group_end(
    process: subprocess.Popen[bytes],
    *,
    label: str,
    on_cleaned: Callable[[], None] | None = None,
) -> None:
    """Force a whole group down and reap it, or refuse if that cannot be shown.

    Used by the timeout and failure paths, which must stay bounded: every wait
    here has a deadline, and the leader is only reaped once the group is proven
    empty, so this can neither hang nor release a group id that still has a
    live member in it.
    """
    if not _teardown_process_group(process, label=label):
        raise _CleanupRefusal(f"{label} left a surviving process")
    if on_cleaned is not None:
        on_cleaned()
    process.wait()


def _run(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one command in its own process group and capture its output.

    ``subprocess.run`` and ``Popen.communicate`` reap the direct child and
    return as soon as that child exits, so a command that leaves helpers behind
    can report success while a descendant keeps running against the staging
    directory. Worse, ``communicate`` blocks until every writer closes the
    pipe, so an inherited-stdio descendant wedges an otherwise finished
    command until its timeout.

    The child leads a new session here. Output is drained by readers that a
    descendant cannot wedge, the leader's exit is observed *without* reaping it
    so its group id stays unambiguous, and every return path -- exit zero, exit
    nonzero, timeout and exception alike -- clears the complete group before the
    leader is reaped. If a group member survives escalation this raises rather
    than return a result that is not final.
    """
    # Everything fallible is prepared BEFORE the spawn, so the only work
    # between creating the process and entering the guard is the assignment
    # itself. Ownership of the group belongs to this call from that instant.
    label = _CHILD_COMMAND_LABEL
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    reader_failures: list[BaseException] = []
    readers: list[threading.Thread] = []

    def collect() -> tuple[bytes, bytes]:
        # Called only after the group is gone, so every writer has closed and
        # the readers finish immediately. Capture is incomplete in two ways,
        # and both must refuse rather than hand back a prefix: a reader still
        # live is holding an open pipe, and a reader that failed part-way has
        # already stopped, so liveness alone would not notice it. The refusal
        # names neither the underlying error nor any path.
        for reader in readers:
            reader.join(timeout=_CONVERTER_TERMINATE_GRACE_SECONDS)
        if any(reader.is_alive() for reader in readers) or reader_failures:
            raise InstallError(f"{label} output could not be captured")
        return bytes(captured["stdout"]), bytes(captured["stderr"])

    # Explicit cleanup phase. Booleans cannot express CLEANED_UNREAPED, the
    # window between "group proven empty" and "leader reaped": if the reap
    # itself fails there, the guard must retry the reap ONLY, never repeat
    # group cleanup.
    phase = ["LIVE"]

    def cleaned():
        phase[0] = "CLEANED_UNREAPED"

    process = None
    try:
        process = subprocess.Popen(  # nosec B603
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            if stream is None:
                raise InstallError(f"{label} output could not be captured")
            reader = threading.Thread(
                target=_drain_stream,
                args=(stream, captured[name], reader_failures),
                name=f"kilix-content-{name}",
                daemon=True,
            )
            reader.start()
            readers.append(reader)

        bound = math.inf if timeout is None else timeout
        if not _wait_without_reaping(process, bound, label=label):
            try:
                _force_group_end(process, label=label, on_cleaned=cleaned)
            except _CleanupRefusal:
                # Cleanup ran and refused. That refusal is the final word:
                # retrying it below would signal a group we already failed to
                # clear and could reap a leader we deliberately kept.
                phase[0] = "REFUSED"
                raise
            phase[0] = "REAPED"
            stdout, stderr = collect()
            raise subprocess.TimeoutExpired(
                argv, timeout, output=stdout, stderr=stderr
            ) from None
        try:
            returncode = _reap_after_group_cleanup(
                process, label=label, on_cleaned=cleaned)
        except _CleanupRefusal:
            phase[0] = "REFUSED"
            raise
        phase[0] = "REAPED"
        # Collection is inside the guard: it can refuse, and the pipes must be
        # released on that path too.
        stdout, stderr = collect()
    except BaseException as exc:
        if process is None:
            raise  # the spawn itself failed: there is nothing to own
        # Only paths that never reached cleanup do cleanup here. A completed
        # refusal propagates untouched, with the leader left unreaped so its
        # group id stays reserved against the member that would not die.
        settled = phase[0] == "REAPED"
        if phase[0] == "CLEANED_UNREAPED":
            # The group is already proven empty; only the reap is outstanding.
            # Repeating group cleanup here would be wrong work on a dead group.
            _reap_only(process, label=label)
            settled = True
        elif phase[0] == "LIVE":
            if not _teardown_process_group(process, label=label):
                raise _CleanupRefusal(
                    f"{label} left a surviving process") from exc
            # The fallback has now proven the group empty too, so record that
            # before reaping: a failure in this reap is reap-only work, not a
            # reason to clean the group again.
            phase[0] = "CLEANED_UNREAPED"
            _reap_only(process, label=label)
            settled = True
        # Releasing the readers is only safe once the group is provably gone.
        # A live writer still holds the pipe, so a reader thread stays blocked
        # in ``read`` holding the stream's lock -- and ``close`` would then
        # block on that lock, hanging a call whose whole purpose was to refuse
        # promptly. On an unproven group the daemon readers and their streams
        # are deliberately left owned by the dying process.
        if settled:
            _release_readers(process, readers)
        raise
    _release_readers(process, readers)
    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


def _run_with_tail(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    tail_bytes: int = 16 * 1024,
    timeout: float | None = None,
) -> tuple[int, str]:
    tail = bytearray()

    def decoded() -> str:
        # Build output is attacker-influenced text that reaches a terminal via
        # the returned tail and the timeout message alike, so it goes through
        # the same sanitizer the converter path uses. Still bounded: the tail
        # buffer caps the bytes, and the sanitizer caps the characters.
        return _sanitize_tail(bytes(tail), limit=tail_bytes)

    # Explicit cleanup phase, shared with the guard below:
    #   LIVE              nothing cleaned yet -- full fallback teardown
    #   CLEANED_UNREAPED  group proven empty, reap outstanding -- reap only
    #   REAPED            leader gone -- nothing to do
    #   REFUSED           cleanup completed and refused -- never retry
    phase = ["LIVE"]

    def cleaned():
        phase[0] = "CLEANED_UNREAPED"

    def timed_out() -> InstallError:
        try:
            _force_group_end(
                process, label=_BUILD_COMMAND_LABEL, on_cleaned=cleaned)
        except _CleanupRefusal:
            phase[0] = "REFUSED"
            raise
        phase[0] = "REAPED"
        detail = decoded()
        suffix = f": {detail}" if detail else ""
        return InstallError(
            f"{argv[0]} timed out after {timeout:g} seconds{suffix}"
        )

    # Everything fallible above is prepared before the spawn; the spawn itself
    # and every later operation live inside the guard, so no failure can
    # abandon a live session.
    process = None
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )  # nosec B603
        output = process.stdout
        if output is None:
            raise RuntimeError("could not capture build output")
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
                ready = bool(poller.select(interval))
                if ready and not absorb():
                    break  # Every writer closed the pipe: output is complete.
                # The leader's exit is checked on *every* iteration, not only
                # when the selector times out. A descendant that writes
                # continuously keeps the descriptor ready forever, so an exit
                # check reachable only on idle would let it wedge a finished
                # command until the build timeout. The leader is observed
                # without reaping, so its group id stays reserved for the
                # cleanup below.
                if _wait_without_reaping(process, 0, label=_BUILD_COMMAND_LABEL):
                    _drain_pending(poller, absorb)
                    break

        # The pipe closing does not mean the command finished: a build may close
        # stdout and keep working. Wait for the leader itself, still without
        # reaping it, and only then clear the group it is holding open.
        remaining = (
            math.inf if deadline is None else max(0.0, deadline - time.monotonic())
        )
        if not _wait_without_reaping(
            process, remaining, label=_BUILD_COMMAND_LABEL
        ):
            raise timed_out()
        try:
            returncode = _reap_after_group_cleanup(
                process, label=_BUILD_COMMAND_LABEL, on_cleaned=cleaned)
        except _CleanupRefusal:
            phase[0] = "REFUSED"
            raise
        phase[0] = "REAPED"
    except BaseException as exc:
        if process is None:
            raise  # the spawn itself failed: there is nothing to own
        # A completed refusal propagates untouched. A group already proven
        # empty needs only its outstanding reap. Only a still-LIVE group gets
        # the full fallback teardown.
        if phase[0] == "CLEANED_UNREAPED":
            _reap_only(process, label=_BUILD_COMMAND_LABEL)
        elif phase[0] == "LIVE":
            if not _teardown_process_group(process, label=_BUILD_COMMAND_LABEL):
                raise _CleanupRefusal(
                    f"{_BUILD_COMMAND_LABEL} left a surviving process"
                ) from exc
            phase[0] = "CLEANED_UNREAPED"
            _reap_only(process, label=_BUILD_COMMAND_LABEL)
        raise
    return returncode, decoded()


def _signal_process_group(process: subprocess.Popen[bytes], signum: int) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def _wait_without_reaping(
    process: subprocess.Popen[bytes],
    timeout: float,
    *,
    label: str = "asset converter",
) -> bool:
    """Observe parent exit while retaining its PID/process-group identity."""
    deadline = time.monotonic() + timeout
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    while True:
        try:
            result = os.waitid(os.P_PID, process.pid, flags)
        except InterruptedError:
            continue
        except ChildProcessError as exc:
            raise InstallError(f"{label} parent could not be observed") from exc
        if result is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _live_process_group_members(
    process: subprocess.Popen[bytes], *, label: str = "asset converter"
) -> tuple[int, ...]:
    """List live descendants while the unreaped leader reserves its group id."""
    members: list[int] = []
    try:
        process_entries = os.scandir("/proc")
    except OSError as exc:
        raise InstallError(f"{label} process group could not be inspected") from exc
    with process_entries:
        for entry in process_entries:
            if not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            if pid == process.pid:
                continue
            try:
                with open(  # noqa: PTH123 -- procfs has no pathlib trust benefit
                    os.path.join(entry.path, "stat"), "rb"
                ) as stream:
                    raw = stream.read(4096)
            except (FileNotFoundError, ProcessLookupError):
                continue  # exited between the scan and the read: provably gone
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.ESRCH):
                    continue
                # Anything else -- permission, EIO -- leaves this member's
                # identity unknown. Skipping it could falsely prove the group
                # empty, reap the leader and hand back a result that is not
                # final, which is exactly what the refusal contract forbids.
                # The message names no pid and no procfs path.
                raise InstallError(
                    f"{label} process group could not be inspected"
                ) from exc
            # The comm field is parenthesised and may itself contain spaces or
            # parentheses, so everything after the LAST ')' is the fixed-width
            # remainder. Without that delimiter the record cannot be parsed at
            # all -- and a slice from -1 could still happen to yield three
            # fields, which is why the boundary is checked explicitly.
            boundary = raw.rfind(b")")
            if boundary < 0 or raw[boundary : boundary + 2] != b") ":
                # The separator must be exactly ") ". Without it the remaining
                # fields are shifted, and a shifted parse can read some other
                # column as the process group -- silently skipping a real
                # same-group member and falsely proving the group empty.
                raise InstallError(
                    f"{label} process group could not be inspected"
                )
            fields = raw[boundary + 2 :].split()
            if len(fields) < 3 or len(fields[0]) != 1:
                raise InstallError(
                    f"{label} process group could not be inspected"
                )
            state = fields[0]
            try:
                process_group = int(fields[2])
            except ValueError as exc:
                raise InstallError(
                    f"{label} process group could not be inspected"
                ) from exc
            if process_group == process.pid and state not in (b"X", b"Z"):
                members.append(pid)
    return tuple(members)


def _terminate_remaining_process_group(
    process: subprocess.Popen[bytes], *, label: str = "asset converter"
) -> None:
    """End descendants before reaping the leader, preventing PGID reuse races."""
    if not _live_process_group_members(process, label=label):
        return
    _signal_process_group(process, signal.SIGTERM)
    deadline = time.monotonic() + _CONVERTER_TERMINATE_GRACE_SECONDS
    while _live_process_group_members(process, label=label):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.01, remaining))
    if _live_process_group_members(process, label=label):
        _signal_process_group(process, signal.SIGKILL)
        deadline = time.monotonic() + _CONVERTER_TERMINATE_GRACE_SECONDS
        while _live_process_group_members(process, label=label):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _CleanupRefusal(f"{label} left a surviving process")
            time.sleep(min(0.01, remaining))


def _sanitize_tail(raw: bytes, *, limit: int) -> str:
    """Decode one captured tail into bounded, printable, control-free text.

    The single sanitization rule for every child-command diagnostic: replace
    anything non-printable or in the Cc/Cf/Cs categories -- which is where
    ESC, OSC, other terminal controls and bidirectional format characters
    live -- collapse runs of whitespace, and keep only the last ``limit``
    characters.
    """
    text = raw.decode("utf-8", errors="replace")
    cleaned = "".join(
        character
        if character.isprintable()
        and unicodedata.category(character) not in ("Cc", "Cf", "Cs")
        else " "
        for character in text
    )
    return " ".join(cleaned.split())[-limit:]


def _sanitize_converter_tail(raw: bytes) -> str:
    return _sanitize_tail(raw, limit=2048)


def _run_converter(
    argv: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout: float = _CONVERTER_TIMEOUT_SECONDS,
) -> tuple[int, str]:
    """Run one converter with bounded diagnostics and whole-group timeout.

    Same ownership contract as the other two runners, and deliberately not a
    third protocol: everything fallible is prepared before the spawn, the spawn
    and every later step live inside one guard, and the explicit
    LIVE/CLEANED_UNREAPED/REAPED/REFUSED phase decides what the guard may do.
    A completed refusal is never retried and never reaps; a group proven empty
    needs only its outstanding reap.

    Public shape is unchanged: ``tuple[int, str]`` with a 2048-character
    sanitized tail, ``stdin`` at DEVNULL, and the same normalized errors.
    """
    label = "asset converter"
    tail = bytearray()
    reader_errors: list[BaseException] = []
    readers: list[threading.Thread] = []
    phase = ["LIVE"]

    def cleaned():
        phase[0] = "CLEANED_UNREAPED"

    released = [False]

    def release_reader(stream):
        """Idempotent, and never closes a stream a live reader still owns.

        Closing a stream whose reader thread is blocked in ``read`` waits on
        that thread's lock, so a stream is closed only once every reader has
        actually finished. Called on more than one path, hence the latch.
        """
        if released[0]:
            return
        for reader in readers:
            reader.join(timeout=_CONVERTER_TERMINATE_GRACE_SECONDS)
        if any(reader.is_alive() for reader in readers):
            return
        released[0] = True
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    process = None
    output = None
    try:
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )  # nosec B603
        except (OSError, ValueError) as exc:
            raise InstallError("asset conversion could not start") from exc

        output = process.stdout
        if output is None:
            raise InstallError("asset conversion output could not be captured")

        def read_output() -> None:
            try:
                while block := output.read(64 * 1024):
                    tail.extend(block)
                    if len(tail) > _CONVERTER_TAIL_BYTES:
                        del tail[:-_CONVERTER_TAIL_BYTES]
            except (OSError, ValueError) as exc:
                reader_errors.append(exc)

        reader = threading.Thread(
            target=read_output,
            name="kilix-content-converter-output",
            daemon=True,
        )
        reader.start()
        readers.append(reader)

        if not _wait_without_reaping(process, timeout, label=label):
            try:
                _force_group_end(process, label=label, on_cleaned=cleaned)
            except _CleanupRefusal:
                phase[0] = "REFUSED"
                raise
            phase[0] = "REAPED"
            release_reader(output)
            raise InstallError("asset conversion timed out")

        try:
            returncode = _reap_after_group_cleanup(
                process, label=label, on_cleaned=cleaned)
        except _CleanupRefusal:
            phase[0] = "REFUSED"
            raise
        phase[0] = "REAPED"
        release_reader(output)
        if readers[0].is_alive():
            raise InstallError("asset conversion output could not be captured")
    except BaseException as exc:
        if process is None:
            raise  # the spawn itself failed: there is nothing to own
        if phase[0] == "CLEANED_UNREAPED":
            _reap_only(process, label=label)
        elif phase[0] == "LIVE":
            if not _teardown_process_group(process, label=label):
                raise _CleanupRefusal(
                    f"{label} left a surviving process") from exc
            phase[0] = "CLEANED_UNREAPED"
            _reap_only(process, label=label)
        # On REFUSED the group is not proven gone, so the reader and its
        # stream are deliberately left owned: closing here could block on the
        # lock a reader holds while a live writer still has the pipe.
        if phase[0] != "REFUSED":
            release_reader(output)
        raise
    if reader_errors:
        raise InstallError(
            "asset conversion output could not be captured") from reader_errors[0]
    return returncode, _sanitize_converter_tail(bytes(tail))


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


def _valid_archive_identity(urls: object, sha256: object) -> bool:
    if not (
        isinstance(urls, tuple)
        and 0 < len(urls) <= 256
        and isinstance(sha256, str)
        and len(sha256) == 64
        and all(character in "0123456789abcdef" for character in sha256)
    ):
        return False
    for url in urls:
        if (
            not isinstance(url, str)
            or not url
            or len(url) > 4096
            or "\x00" in url
        ):
            return False
        try:
            url.encode("utf-8")
        except UnicodeError:
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

    def required_input(self, spec: AssetSpec) -> AcquisitionRequired | None:
        """Return trusted acquisition facts without performing I/O."""
        spec = self._validated_asset_spec(spec)
        if spec.source_mode != "user-supplied":
            return None
        return AcquisitionRequired(
            asset_id=spec.asset_id,
            official_url=spec.official_url,
            reason=spec.reason,
            input_bytes=spec.input_bytes,
            input_sha256=spec.input_sha256,
            conversion_required=bool(spec.conversion_argv),
            conversion_tool_asset_id=spec.conversion_tool_asset_id,
        )

    @staticmethod
    def _validated_asset_spec(spec: AssetSpec) -> AssetSpec:
        if not isinstance(spec, AssetSpec):
            raise InstallError("operation needs a validated asset record")
        try:
            validated = AssetSpec.canonicalized(spec)
        except (CatalogError, AttributeError, TypeError, ValueError) as exc:
            raise InstallError("asset record failed canonical validation") from exc
        if validated != spec:
            raise InstallError("asset record is not in canonical validated form")
        return validated

    @staticmethod
    def _validated_content_spec(spec: ContentSpec) -> ContentSpec:
        if not isinstance(spec, ContentSpec):
            raise InstallError("operation needs a validated content record")
        try:
            validated = ContentSpec.canonicalized(spec)
        except (CatalogError, AttributeError, TypeError, ValueError) as exc:
            raise InstallError("content record failed canonical validation") from exc
        if validated != spec:
            raise InstallError("content record is not in canonical validated form")
        return validated

    def _ensure_asset_parent(self, spec: AssetSpec) -> str:
        parent = os.path.dirname(self.asset_destination(spec))
        try:
            if not os.path.lexists(parent):
                os.mkdir(parent, 0o700)
                os.chmod(parent, 0o700, follow_symlinks=False)
            info = os.stat(parent, follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise InstallError("could not create a private asset root") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise InstallError("asset root has unsafe type, owner, or mode")
        return parent

    @contextmanager
    def _asset_lock(self, spec: AssetSpec, parent: str) -> Iterator[None]:
        identity = hashlib.sha256(
            f"{spec.asset_id}\x00{spec.version}".encode("utf-8")
        ).hexdigest()
        lock_path = os.path.join(parent, f".install-{identity}.lock")
        descriptor = -1
        try:
            descriptor = os.open(
                lock_path,
                os.O_RDWR
                | os.O_CREAT
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise InstallError("asset install lock has unsafe metadata")
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    break
                except InterruptedError:
                    continue
            yield
        except InstallError:
            raise
        except (OSError, ValueError) as exc:
            raise InstallError("could not acquire the asset install lock") from exc
        finally:
            if descriptor >= 0:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)

    @staticmethod
    def _copy_verified_input(source: VerifiedInput, destination: str) -> None:
        source_descriptor = source.duplicate_descriptor()
        destination_descriptor = -1
        digest = hashlib.sha256()
        copied = 0
        try:
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
            )
            while True:
                try:
                    block = os.read(source_descriptor, 1024 * 1024)
                except InterruptedError:
                    continue
                if not block:
                    break
                digest.update(block)
                copied += len(block)
                view = memoryview(block)
                written = 0
                while written < len(view):
                    try:
                        count = os.write(
                            destination_descriptor, view[written:]
                        )
                    except InterruptedError:
                        continue
                    if count <= 0:
                        raise OSError(errno.EIO, "short staged-input write")
                    written += count
            os.fchmod(destination_descriptor, 0o600)
            os.fsync(destination_descriptor)
        except OSError as exc:
            raise InstallError("could not stage user-supplied input") from exc
        finally:
            os.close(source_descriptor)
            if destination_descriptor >= 0:
                os.close(destination_descriptor)
        if copied != source.bytes or digest.hexdigest() != source.sha256:
            raise BindingMismatch("staged input does not match the verified input")

    @staticmethod
    def _conversion_environment(stage: str) -> dict[str, str]:
        home = os.path.join(stage, "home")
        temporary = os.path.join(stage, "tmp")
        cache = os.path.join(stage, "cache")
        config = os.path.join(stage, "config")
        for directory in (home, temporary, cache, config):
            os.mkdir(directory, 0o700)
        return {
            "HOME": home,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": temporary,
            "XDG_CACHE_HOME": cache,
            "XDG_CONFIG_HOME": config,
        }

    def _resolve_conversion_tool(
        self,
        spec: AssetSpec,
        catalog: Catalog,
        report: Report,
    ) -> tuple[ContentSpec, str]:
        if spec.conversion_tool_asset_id == spec.asset_id:
            raise InstallError("asset conversion tool must not be self-referential")
        try:
            tool = catalog.require(spec.conversion_tool_asset_id)
        except CatalogError as exc:
            raise InstallError("asset conversion tool is absent from the catalog") from exc
        tool = self._validated_content_spec(tool)
        if not tool.binary:
            raise InstallError("asset conversion tool has no executable")
        if tool.source_type not in ("git", "archive"):
            raise InstallError(
                "asset conversion tool must have a pinned Git or archive source"
            )
        if tool.source_type == "git" and not _valid_git_identity(
            tool.repository, tool.ref
        ):
            raise InstallError("asset conversion tool Git identity is invalid")
        if tool.source_type == "archive" and not _valid_archive_identity(
            tool.urls, tool.sha256
        ):
            raise InstallError("asset conversion tool archive identity is invalid")
        previously_ready = self.ready(tool)
        program = previously_ready or self.ensure(tool, report)
        expected = self.executable(tool)
        if (
            program != expected
            or not os.path.isabs(expected)
            or not self._executable_stays_within(self.destination(tool), expected)
            or self.ready(tool) != expected
        ):
            raise InstallError("asset conversion tool failed integrity verification")
        attestation = self._conversion_attestation_path(tool)
        if not os.path.lexists(attestation):
            if previously_ready is not None and not self._tracked_git_program(
                tool, expected
            ):
                raise InstallError(
                    "pre-existing conversion tool lacks an install attestation; "
                    "reinstall its pinned source"
                )
            self._create_conversion_attestation(tool, expected, attestation)
        self._verify_conversion_attestation(tool, expected, attestation)
        return tool, expected

    def _conversion_attestation_path(self, tool: ContentSpec) -> str:
        identity = hashlib.sha256(
            f"{tool.content_id}\x00{tool.binary}".encode("utf-8")
        ).hexdigest()
        return os.path.join(
            self.destination(tool), f".converter-attestation-{identity}.v1"
        )

    @staticmethod
    def _conversion_source_digest(tool: ContentSpec) -> str:
        source = {
            "binary": tool.binary,
            "build": list(tool.build),
            "install_id": tool.install_id,
            "ref": tool.ref,
            "repository": tool.repository,
            "sha256": tool.sha256,
            "source_type": tool.source_type,
            "urls": list(tool.urls),
        }
        document = json.dumps(
            source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(document).hexdigest()

    @classmethod
    def _conversion_attestation_document(
        cls, tool: ContentSpec, program: str
    ) -> bytes:
        try:
            with VerifiedInput.open(program) as verified_program:
                program_digest = verified_program.sha256
        except BindingMismatch as exc:
            raise InstallError(
                "conversion tool program could not be securely hashed"
            ) from exc
        return (
            f"{_CONVERTER_ATTESTATION_SCHEMA}\n"
            f"{cls._conversion_source_digest(tool)}\n"
            f"{program_digest}\n"
        ).encode("ascii")

    def _tracked_git_program(self, tool: ContentSpec, program: str) -> bool:
        if tool.source_type != "git" or program != self.executable(tool):
            return False
        try:
            result = _run(
                ["git", "ls-files", "--error-unmatch", "--", tool.binary],
                cwd=self.destination(tool),
                env=_git_environment(self.env),
            )
        except OSError:
            return False
        return result.returncode == 0

    @classmethod
    def _create_conversion_attestation(
        cls, tool: ContentSpec, program: str, target: str
    ) -> None:
        descriptor = -1
        try:
            document = cls._conversion_attestation_document(tool, program)
            descriptor = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
            )
            written = 0
            while written < len(document):
                try:
                    count = os.write(descriptor, document[written:])
                except InterruptedError:
                    continue
                if count <= 0:
                    raise OSError(errno.EIO, "short converter-attestation write")
                written += count
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except OSError as exc:
            raise InstallError(
                "could not create the conversion-tool install attestation"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @classmethod
    def _verify_conversion_attestation(
        cls, tool: ContentSpec, program: str, target: str
    ) -> None:
        descriptor = -1
        try:
            descriptor = os.open(
                target,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > _CONVERTER_ATTESTATION_BYTES
            ):
                raise InstallError(
                    "conversion-tool install attestation has unsafe metadata"
                )
            document = bytearray()
            while len(document) <= _CONVERTER_ATTESTATION_BYTES:
                block = os.read(
                    descriptor,
                    _CONVERTER_ATTESTATION_BYTES + 1 - len(document),
                )
                if not block:
                    break
                document.extend(block)
            if bytes(document) != cls._conversion_attestation_document(tool, program):
                raise InstallError(
                    "conversion tool no longer matches its install attestation"
                )
        except InstallError:
            raise
        except OSError as exc:
            raise InstallError(
                "could not verify the conversion-tool install attestation"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _conversion_arguments(
        spec: AssetSpec, program: str, staged_input: str, output: str
    ) -> list[str]:
        arguments = spec.conversion_argv
        if (
            arguments.count("{input}") != 1
            or arguments.count("{output}") != 1
            or any(
                ("{" in argument or "}" in argument)
                and argument not in ("{input}", "{output}")
                for argument in arguments
            )
        ):
            raise InstallError("asset conversion placeholders are invalid")
        return [
            program,
            *(
                staged_input
                if argument == "{input}"
                else output
                if argument == "{output}"
                else argument
                for argument in arguments
            ),
        ]

    def asset_ready(
        self, spec: AssetSpec, store: ReceiptStore, release: ReleaseContext
    ) -> tuple[str, ...] | None:
        """Return exact paths only after license authorization and integrity checks."""
        spec = self._validated_asset_spec(spec)
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
                        or info.st_uid != os.geteuid()
                        or info.st_nlink != 1
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

    @staticmethod
    def _populate_mirrored_asset(
        spec: AssetSpec,
        stage: str,
        report: Report,
    ) -> str:
        archive_path = os.path.join(stage, ".download")
        output = os.path.join(stage, "content")
        os.mkdir(output, 0o700)
        download(spec.mirrors, archive_path, report, spec.archive_sha256)
        try:
            with tarfile.open(archive_path, "r:*") as archive:
                safe_extract_tar(archive, output)
        except tarfile.ReadError:
            try:
                with zipfile.ZipFile(archive_path) as archive:
                    safe_extract_zip(archive, output)
            except zipfile.BadZipFile as exc:
                raise InstallError(
                    "asset download is neither a supported tar nor ZIP archive"
                ) from exc
        return output

    def _populate_user_supplied_asset(
        self,
        spec: AssetSpec,
        catalog: Catalog,
        verified_input: VerifiedInput,
        stage: str,
        report: Report,
    ) -> str:
        if (
            verified_input.bytes != spec.input_bytes
            or verified_input.sha256 != spec.input_sha256
        ):
            raise BindingMismatch(
                "user-supplied input does not match the required size and digest"
            )
        staged_input = os.path.join(stage, "input")
        output = os.path.join(stage, "content")
        os.mkdir(output, 0o700)
        self._copy_verified_input(verified_input, staged_input)

        if spec.conversion_argv:
            tool, program = self._resolve_conversion_tool(spec, catalog, report)
            argv = self._conversion_arguments(
                spec, program, staged_input, output
            )
            environment = self._conversion_environment(stage)
            report(f"converting {spec.label} …")
            self._verify_conversion_attestation(
                tool, program, self._conversion_attestation_path(tool)
            )
            returncode, detail = _run_converter(
                argv,
                cwd=stage,
                env=environment,
                timeout=_CONVERTER_TIMEOUT_SECONDS,
            )
            if returncode != 0:
                suffix = f": {detail}" if detail else ""
                raise InstallError(
                    f"asset conversion failed with status {returncode}{suffix}"
                )
        else:
            if len(spec.files) != 1:
                raise InstallError(
                    "user-supplied identity acquisition requires exactly one output file"
                )
            item = spec.files[0]
            if (
                spec.input_sha256 != item.sha256
                or spec.input_bytes != item.bytes
            ):
                raise InstallError(
                    "user-supplied identity input must equal its sole output"
                )
            target = _safe_member_path(os.path.realpath(output), item.path)
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            os.replace(staged_input, target)
        return output

    def _finalize_asset_stage(
        self,
        spec: AssetSpec,
        store: ReceiptStore,
        release: ReleaseContext,
        output: str,
        destination: str,
        verified_input: VerifiedInput | None = None,
    ) -> tuple[str, ...]:
        if self._verify_asset_directory(spec, output) is None:
            raise InstallError("staged asset tree does not match its manifest")
        # Authorization can be removed or corrupted during long acquisition.
        store.require_asset(spec, release)
        if verified_input is not None:
            verified_input.revalidate()
        self._replace_stage(output, destination)
        selected = self.asset_ready(spec, store, release)
        if selected is None:
            raise InstallError("installed asset failed final verification")
        return selected

    def _ensure_asset(
        self,
        spec: AssetSpec,
        store: ReceiptStore,
        release: ReleaseContext,
        report: Report,
        *,
        catalog: Catalog | None = None,
        input_path: str | None = None,
    ) -> tuple[str, ...]:
        spec = self._validated_asset_spec(spec)
        self._ensure_root()
        store.require_asset(spec, release)
        ready = self._asset_integrity_ready(spec)
        if ready is not None:
            return ready
        if spec.source_mode == "mirrored":
            if input_path is not None or catalog is not None:
                raise InstallError("mirrored assets do not accept user input")
        elif spec.source_mode == "user-supplied":
            if input_path is None or not isinstance(catalog, Catalog):
                raise InstallError("user-supplied asset input and catalog are required")
        else:
            raise InstallError("asset source mode is unsupported")

        destination = self.asset_destination(spec)
        parent = self._ensure_asset_parent(spec)
        with self._asset_lock(spec, parent):
            # A waiting caller must re-check both authority and selected bytes.
            store.require_asset(spec, release)
            ready = self._asset_integrity_ready(spec)
            if ready is not None:
                return ready
            if os.path.lexists(destination):
                raise InstallError(
                    "refusing to replace an unverified asset selection"
                )
            stage = tempfile.mkdtemp(prefix=".asset-install-", dir=parent)
            try:
                if spec.source_mode == "mirrored":
                    output = self._populate_mirrored_asset(spec, stage, report)
                    return self._finalize_asset_stage(
                        spec, store, release, output, destination
                    )
                with VerifiedInput.open(input_path) as verified_input:
                    output = self._populate_user_supplied_asset(
                        spec,
                        catalog,
                        verified_input,
                        stage,
                        report,
                    )
                    return self._finalize_asset_stage(
                        spec,
                        store,
                        release,
                        output,
                        destination,
                        verified_input,
                    )
            except (InstallError, ReceiptError):
                raise
            except (
                OSError,
                tarfile.TarError,
                zipfile.BadZipFile,
                RuntimeError,
            ) as exc:
                raise InstallError("asset installation failed") from exc
            finally:
                shutil.rmtree(stage, ignore_errors=True)

    def ensure_asset(
        self,
        spec: AssetSpec,
        store: ReceiptStore,
        release: ReleaseContext,
        report: Report = lambda _message: None,
    ) -> tuple[str, ...]:
        """Install one exact mirrored asset after every license is authorized."""
        return self._ensure_asset(spec, store, release, report)

    def ensure_user_supplied_asset(
        self,
        spec: AssetSpec,
        catalog: Catalog,
        store: ReceiptStore,
        release: ReleaseContext,
        input_path: str,
        report: Report = lambda _message: None,
    ) -> tuple[str, ...]:
        """Install verified user-supplied bytes without reopening their path."""
        return self._ensure_asset(
            spec,
            store,
            release,
            report,
            catalog=catalog,
            input_path=input_path,
        )

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
        spec = self._validated_content_spec(spec)
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
        if not _valid_archive_identity(spec.urls, spec.sha256):
            raise InstallError("archive source identity is invalid")
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
                returncode, detail = _run_with_tail(
                    list(spec.build),
                    cwd=directory,
                    env=self.env,
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
