"""fetch_exact: HTTPS-only download of pinned bytes (R4-049)."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

ReportProgress = Callable[["Progress"], None]
Cancelled = Callable[[], bool]

_RESUME_MIN_BYTES = 64 * 1024 * 1024
_BLOCK = 1024 * 1024
_PROGRESS_PERIOD = 0.25
_REMEDY = {
    "offline": "check the network or proxy, then re-run; download resumes",
    "proxy": "proxy authentication or tunnel failed; check the proxy and re-run",
    "tls": "certificate verification failed; check SSL_CERT_FILE or proxy interception",
    "http-status": "upstream no longer serves the pinned file; nothing installed; report it",
    "size-mismatch": "upstream size differs from the pin; refusing; report it",
    "digest-mismatch": "upstream bytes differ from the pin; refusing; report it",
    "deadline": "download exceeded its deadline; re-run to resume",
    "cancelled": "nothing installed; re-run to resume",
    "no-space": "free disk space and re-run",
    "redirect": "HTTPS redirect refused; nothing installed",
}


class DownloadError(RuntimeError):
    """Closed download failure. ``kind`` is the only machine-readable field."""

    def __init__(
        self,
        kind: str,
        *,
        status: int | None = None,
        need: int | None = None,
        free: int | None = None,
    ) -> None:
        if kind not in _REMEDY and not kind.startswith("http-status"):
            kind = "offline"
        self.kind = kind
        self.status = status
        self.need = need
        self.free = free
        if kind == "http-status" and status is not None:
            label = f"http-status:{status}"
            remedy = _REMEDY["http-status"]
        else:
            label = kind
            remedy = _REMEDY.get(kind, _REMEDY["offline"])
        super().__init__(f"{label}: {remedy}")


@dataclass(frozen=True)
class Progress:
    """Byte progress for a first-use download. Emitted at most 4 times per second."""

    phase: str
    done: int = 0
    total: int = 0
    host: str = ""
    via_proxy: bool = False
    owner_pid: int | None = None
    started: str = ""


class _HTTPSPartRedirects(urllib.request.HTTPRedirectHandler):
    """Keep every hop on HTTPS. The stdlib handler's http downgrade is the defect."""

    max_repeats = 5
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            target = urlsplit(newurl)
            permitted = (
                target.scheme == "https"
                and bool(target.hostname)
                and target.username is None
                and target.password is None
            )
            target.port
        except (TypeError, ValueError):
            permitted = False
        if not permitted:
            raise DownloadError("tls")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoHTTP(urllib.request.HTTPHandler):
    def http_open(self, req):  # noqa: ARG002
        raise DownloadError("tls")


def _opener() -> urllib.request.OpenerDirector:
    cert = os.environ.get("SSL_CERT_FILE")
    if cert:
        context = ssl.create_default_context(cafile=cert)
    else:
        context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        _HTTPSPartRedirects(),
        _NoHTTP(),
        urllib.request.HTTPSHandler(context=context),
    )


def _host(url: str) -> str:
    try:
        hostname = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return hostname


def _via_proxy() -> bool:
    for key in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        value = os.environ.get(key, "")
        if value:
            return True
    return False


def _preflight_disk(path: str, need: int) -> None:
    parent = os.path.dirname(os.path.abspath(path)) or "."
    try:
        vfs = os.statvfs(parent)
    except OSError as exc:
        raise DownloadError("no-space") from exc
    free = vfs.f_bavail * vfs.f_frsize
    if free < need:
        raise DownloadError("no-space", need=need, free=free)


def _emit(
    progress: ReportProgress | None,
    state: list[float],
    event: Progress,
) -> None:
    if progress is None:
        return
    now = time.monotonic()
    if event.phase == "download":
        if state[0] != 0.0 and now - state[0] < _PROGRESS_PERIOD:
            return
        state[0] = now
    progress(event)


def _sidecar_path(partial: str) -> str:
    return partial + ".sidecar"


def _load_sidecar(path: str) -> dict[str, object] | None:
    try:
        with open(path, "rb") as handle:
            raw = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def _write_sidecar(path: str, payload: dict[str, object]) -> None:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _delete_partial(partial: str) -> None:
    for path in (partial, _sidecar_path(partial)):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def fetch_exact(
    candidates: str | Iterable[str],
    destination: str,
    *,
    expected_bytes: int,
    expected_sha256: str,
    deadline: float | None = None,
    cancelled: Cancelled | None = None,
    progress: ReportProgress | None = None,
    partial_dir: str | None = None,
    installed_bytes: int = 0,
) -> str:
    """Download exactly ``expected_bytes`` of ``expected_sha256`` over HTTPS."""
    urls = (candidates,) if isinstance(candidates, str) else tuple(candidates)
    if not urls:
        raise DownloadError("offline")
    if (
        type(expected_bytes) is not int
        or expected_bytes < 0
        or not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise DownloadError("digest-mismatch")
    destination = os.path.abspath(destination)
    parent = os.path.dirname(destination)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    rate = [0.0]
    _emit(progress, rate, Progress(phase="preflight", total=expected_bytes, via_proxy=_via_proxy()))
    already = 0
    partial = ""
    if partial_dir:
        os.makedirs(partial_dir, mode=0o700, exist_ok=True)
        partial = os.path.join(partial_dir, "0.part")
        if os.path.isfile(partial):
            already = os.path.getsize(partial)
            if already >= expected_bytes:
                _delete_partial(partial)
                already = 0
                partial = os.path.join(partial_dir, "0.part")
    need = expected_bytes - already + max(0, installed_bytes) + _RESUME_MIN_BYTES
    _preflight_disk(destination, need)
    last_error: DownloadError | None = None
    for url in urls:
        if cancelled is not None and cancelled():
            raise DownloadError("cancelled")
        if deadline is not None and time.monotonic() >= deadline:
            raise DownloadError("deadline")
        try:
            _fetch_one(
                url,
                destination,
                expected_bytes=expected_bytes,
                expected_sha256=expected_sha256,
                deadline=deadline,
                cancelled=cancelled,
                progress=progress,
                rate=rate,
                partial=partial,
                already=already,
            )
            return destination
        except DownloadError as exc:
            last_error = exc
            if exc.kind in {"cancelled", "deadline", "no-space"}:
                raise
            continue
    if last_error is not None:
        raise last_error
    raise DownloadError("offline")


def _fetch_one(
    url: str,
    destination: str,
    *,
    expected_bytes: int,
    expected_sha256: str,
    deadline: float | None,
    cancelled: Cancelled | None,
    progress: ReportProgress | None,
    rate: list[float],
    partial: str,
    already: int,
) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DownloadError("tls")
    resume = (
        bool(partial)
        and expected_bytes >= _RESUME_MIN_BYTES
        and already > 0
        and already < expected_bytes
    )
    etag = ""
    last_modified = ""
    sidecar: dict[str, object] | None = None
    if resume:
        sidecar = _load_sidecar(_sidecar_path(partial))
        if sidecar is None or sidecar.get("expected_sha256") != expected_sha256:
            _delete_partial(partial)
            already = 0
            resume = False
        elif sidecar.get("url") != url or sidecar.get("expected_bytes") != expected_bytes:
            _delete_partial(partial)
            already = 0
            resume = False
        else:
            etag = str(sidecar.get("etag") or "")
            last_modified = str(sidecar.get("last_modified") or "")
    headers = {"User-Agent": "kilix-content/0.4"}
    start = already if resume else 0
    if resume:
        headers["Range"] = f"bytes={start}-"
        if etag:
            headers["If-Range"] = etag
        elif last_modified:
            headers["If-Range"] = last_modified
    request = urllib.request.Request(url, headers=headers)
    remaining_time = None if deadline is None else max(0.05, deadline - time.monotonic())
    if remaining_time is not None and remaining_time <= 0:
        raise DownloadError("deadline")
    socket_timeout = 0.2 if cancelled is not None else 30.0
    if remaining_time is not None:
        socket_timeout = min(socket_timeout if cancelled is not None else 30.0, remaining_time)
    _emit(
        progress,
        rate,
        Progress(
            phase="connect",
            done=start,
            total=expected_bytes,
            host=_host(url),
            via_proxy=_via_proxy(),
        ),
    )
    opener = _opener()
    try:
        response = opener.open(request, timeout=socket_timeout)
    except DownloadError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code in {407, 502, 503} and _via_proxy():
            raise DownloadError("proxy") from None
        raise DownloadError("http-status", status=int(exc.code)) from None
    except ssl.SSLError as exc:
        raise DownloadError("tls") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLError):
            raise DownloadError("tls") from exc
        raise DownloadError("offline") from exc
    with response:
        status = getattr(response, "status", None) or response.getcode()
        if resume and status == 200:
            start = 0
            if partial:
                _delete_partial(partial)
        elif resume and status == 206:
            content_range = response.headers.get("Content-Range", "")
            if not content_range.startswith("bytes ") or "/" not in content_range:
                raise DownloadError("size-mismatch")
            span, total = content_range.removeprefix("bytes ").split("/", 1)
            try:
                range_start = int(span.split("-", 1)[0])
                range_total = int(total)
            except ValueError as exc:
                raise DownloadError("size-mismatch") from exc
            if range_start != start or range_total != expected_bytes:
                raise DownloadError("size-mismatch")
        elif status != 200:
            raise DownloadError("http-status", status=int(status))
        advertised = response.headers.get("Content-Length")
        remaining = expected_bytes - start
        if advertised is not None:
            try:
                length = int(advertised)
            except ValueError as exc:
                raise DownloadError("size-mismatch") from exc
            if length != remaining:
                raise DownloadError("size-mismatch")
        target = partial if partial else destination + ".part"
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        mode = "r+b" if resume and start > 0 and os.path.isfile(target) else "wb"
        digest = hashlib.sha256()
        count = start
        if resume and start > 0 and os.path.isfile(target):
            with open(target, "rb") as existing:
                existing.seek(0)
                while True:
                    block = existing.read(_BLOCK)
                    if not block:
                        break
                    digest.update(block)
        keep_partial = False
        try:
            with open(target, mode) as output:
                if resume and start > 0:
                    output.seek(start)
                    output.truncate(start)
                while count < expected_bytes:
                    if cancelled is not None and cancelled():
                        keep_partial = True
                        raise DownloadError("cancelled")
                    if deadline is not None and time.monotonic() >= deadline:
                        keep_partial = True
                        raise DownloadError("deadline")
                    want = min(_BLOCK, expected_bytes - count)
                    if cancelled is not None:
                        want = min(want, 64 * 1024)
                    try:
                        block = response.read(want)
                    except (TimeoutError, socket.timeout, urllib.error.URLError):
                        if cancelled is not None and cancelled():
                            keep_partial = True
                            raise DownloadError("cancelled") from None
                        if deadline is not None and time.monotonic() >= deadline:
                            keep_partial = True
                            raise DownloadError("deadline") from None
                        continue
                    except (OSError, ValueError) as exc:
                        keep_partial = True
                        raise DownloadError("offline") from exc
                    if not block:
                        break
                    if count + len(block) > expected_bytes:
                        if partial:
                            _delete_partial(partial)
                        raise DownloadError("size-mismatch")
                    output.write(block)
                    digest.update(block)
                    count += len(block)
                    _emit(
                        progress,
                        rate,
                        Progress(
                            phase="download",
                            done=count,
                            total=expected_bytes,
                            host=_host(url),
                            via_proxy=_via_proxy(),
                        ),
                    )
                extra = response.read(1)
                if extra:
                    if partial:
                        _delete_partial(partial)
                    raise DownloadError("size-mismatch")
            if count != expected_bytes:
                raise DownloadError("size-mismatch")
            actual = digest.hexdigest()
            _emit(
                progress,
                rate,
                Progress(
                    phase="verify",
                    done=expected_bytes,
                    total=expected_bytes,
                    host=_host(url),
                    via_proxy=_via_proxy(),
                ),
            )
            if actual != expected_sha256:
                if partial:
                    _delete_partial(partial)
                elif os.path.isfile(target) and target != destination:
                    try:
                        os.unlink(target)
                    except OSError:
                        pass
                raise DownloadError("digest-mismatch")
            os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
            os.replace(target, destination)
            if partial:
                try:
                    os.unlink(_sidecar_path(partial))
                except FileNotFoundError:
                    pass
        except DownloadError:
            if keep_partial and partial and os.path.isfile(target):
                _write_sidecar(
                    _sidecar_path(partial),
                    {
                        "etag": response.headers.get("ETag") or etag,
                        "expected_bytes": expected_bytes,
                        "expected_sha256": expected_sha256,
                        "last_modified": response.headers.get("Last-Modified") or last_modified,
                        "url": url,
                    },
                )
            elif not keep_partial and partial:
                pass
            raise
