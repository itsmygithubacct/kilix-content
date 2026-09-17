"""FakeUpstream TLS server, fixture archives, store guard (R4-048)."""

from __future__ import annotations

import hashlib
import http.server
import io
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any

from kilix_content.paths import require_isolated_env

ROOT = Path(__file__).resolve().parents[1]


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _log(self, extra: dict[str, Any] | None = None) -> None:
        entry = {
            "command": self.command,
            "path": self.path,
            "scheme": "https" if self.server.tls else "http",  # type: ignore[attr-defined]
            "time": time.monotonic(),
        }
        if extra:
            entry.update(extra)
        self.server.log.append(entry)  # type: ignore[attr-defined]

    def do_CONNECT(self) -> None:  # noqa: N802
        self._log({"connect": self.path})
        self.send_response(HTTPStatus.OK)
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(body=False)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(body=True)

    def _serve(self, *, body: bool) -> None:
        route = self.server.routes.get(self.path)  # type: ignore[attr-defined]
        if route is None:
            self._log({"status": 404})
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        kind = route.get("kind", "ok")
        payload: bytes = route.get("body", b"")
        if kind == "downgrade-to-http":
            http_port = self.server.http_port  # type: ignore[attr-defined]
            self._log({"status": 302, "kind": kind})
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"http://127.0.0.1:{http_port}/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if kind == "redirect-crosshost":
            other = self.server.peer_url  # type: ignore[attr-defined]
            self._log({"status": 302, "kind": kind})
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"{other}/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if kind == "404":
            self._log({"status": 404})
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if kind == "410":
            self._log({"status": 410})
            self.send_error(HTTPStatus.GONE)
            return
        if kind == "wrong-length-header":
            self._log({"status": 200, "kind": kind})
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", str(len(payload) + 64))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            if body:
                self.wfile.write(payload)
            return
        if kind == "oversize":
            extra = payload + b"x"
            self._log({"status": 200, "kind": kind})
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", str(len(extra)))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            if body:
                self.wfile.write(extra)
            return
        range_header = self.headers.get("Range", "")
        if kind in {"range-ok", "range-ignored", "etag-changed"} and range_header.startswith("bytes="):
            start = int(range_header.removeprefix("bytes=").split("-", 1)[0])
            if kind == "range-ignored":
                self._log({"status": 200, "kind": kind})
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                if body:
                    self.wfile.write(payload)
                return
            if kind == "etag-changed":
                mutated = b"Z" + payload[1:]
                self._log({"status": 206, "kind": kind})
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header(
                    "Content-Range", f"bytes {start}-{len(mutated) - 1}/{len(mutated)}"
                )
                self.send_header("Content-Length", str(len(mutated) - start))
                self.end_headers()
                if body:
                    self.wfile.write(mutated[start:])
                return
            self._log({"status": 206, "kind": kind})
            self.send_response(HTTPStatus.PARTIAL_CONTENT)
            self.send_header(
                "Content-Range", f"bytes {start}-{len(payload) - 1}/{len(payload)}"
            )
            self.send_header("Content-Length", str(len(payload) - start))
            self.send_header("ETag", '"fixture"')
            self.end_headers()
            if body:
                self.wfile.write(payload[start:])
            return
        status = HTTPStatus.OK
        self._log({"status": int(status), "kind": kind})
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("ETag", '"fixture"')
        self.send_header("Last-Modified", "Tue, 08 Dec 2020 15:39:47 GMT")
        if kind == "truncate":
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if body:
                self.wfile.write(payload[: max(0, len(payload) // 2)])
            return
        if kind == "trickle-headers":
            time.sleep(route.get("delay", 2.0))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if not body:
            return
        if kind in {"trickle-body", "slow"}:
            delay = float(route.get("delay", 0.2))
            for index in range(0, len(payload), 1):
                self.wfile.write(payload[index : index + 1])
                self.wfile.flush()
                time.sleep(delay)
            return
        self.wfile.write(payload)


class _TLSServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], tls: bool) -> None:
        super().__init__(address, _Handler)
        self.tls = tls
        self.log: list[dict[str, Any]] = []
        self.routes: dict[str, dict[str, Any]] = {}
        self.http_port = 0
        self.peer_url = ""


def _make_cert(directory: Path) -> tuple[Path, Path]:
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class FakeUpstream:
    """Loopback TLS (and HTTP) fixture server with a request log."""

    def __init__(self, *, cert: Path | None = None, key: Path | None = None) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="kilix-content-upstream-")
        self.directory = Path(self.temp.name)
        if cert is None or key is None:
            self.cert, self.key = _make_cert(self.directory)
        else:
            self.cert, self.key = cert, key
        self.https = _TLSServer(("127.0.0.1", 0), tls=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert), str(self.key))
        self.https.socket = context.wrap_socket(self.https.socket, server_side=True)
        self.http = _TLSServer(("127.0.0.1", 0), tls=False)
        self.https.http_port = int(self.http.server_address[1])
        self.thread = threading.Thread(target=self.https.serve_forever, daemon=True)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.http_thread.start()
        os.environ["SSL_CERT_FILE"] = str(self.cert)

    @property
    def url(self) -> str:
        host, port = self.https.server_address[:2]
        return f"https://{host}:{port}"

    @property
    def http_url(self) -> str:
        host, port = self.http.server_address[:2]
        return f"http://{host}:{port}"

    def add(self, path: str, body: bytes, *, kind: str = "ok", **fields: Any) -> str:
        digest = hashlib.sha256(body).hexdigest()
        route = {"kind": kind, "body": body, "sha256": digest, **fields}
        self.https.routes[path] = route
        self.http.routes[path] = route
        return f"{self.url}{path}"

    def requests(self) -> list[dict[str, Any]]:
        return list(self.https.log) + list(self.http.log)

    def http_requests(self) -> list[dict[str, Any]]:
        return [item for item in self.requests() if item.get("scheme") == "http"]

    def close(self) -> None:
        self.https.shutdown()
        self.http.shutdown()
        self.https.server_close()
        self.http.server_close()
        self.temp.cleanup()


def _zip_bytes(members: dict[str, bytes], *, root: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in members.items():
            info = zipfile.ZipInfo(f"{root}/{name}", date_time=(2020, 1, 1, 0, 0, 0))
            archive.writestr(info, payload)
    return buffer.getvalue()


def vosk_fixture_zip(*, extra: dict[str, bytes] | None = None, root: str = "vosk-model-small-en-us-0.15") -> bytes:
    members = {
        "README": b"Copyright 2020 Alpha Cephei Inc\n",
        "conf/model.conf": b"model-conf\n",
        "am/final.mdl": b"mdl-" + (b"A" * 4096),
        "graph/HCLr.fst": b"fst-fixture",
        "ivector/final.ie": b"ie-fixture",
    }
    if extra:
        members.update(extra)
    return _zip_bytes(members, root=root)


def hostile_symlink_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("vosk-model-small-en-us-0.15/link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "/tmp/escape")
    return buffer.getvalue()


def hostile_parent_zip() -> bytes:
    return _zip_bytes({"../escape": b"nope"}, root="vosk-model-small-en-us-0.15")


def hostile_two_roots_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("one/README", b"a")
        archive.writestr("two/README", b"b")
    return buffer.getvalue()


def install_store_guard(temp_root: Path) -> None:
    require_isolated_env(temp_root)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def archive_members(payload: bytes, root: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    prefix = root + "/"
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.filename.endswith("/"):
                continue
            name = info.filename
            if name.startswith(prefix):
                name = name[len(prefix) :]
            data = archive.read(info)
            files.append({"bytes": len(data), "path": name, "sha256": sha256_bytes(data)})
    files.sort(key=lambda item: item["path"])
    return files


def make_archive_asset(
    *,
    asset_id: str,
    url: str,
    archive: bytes,
    root: str,
    license_record,
    notice: bytes,
    licensors: list[str],
) -> dict[str, Any]:
    files = archive_members(archive, root)
    files.append(
        {
            "bytes": len(notice),
            "path": "notices/LICENSE-apache-2.0.txt",
            "sha256": sha256_bytes(notice),
        }
    )
    files.sort(key=lambda item: item["path"])
    installed = sum(item["bytes"] for item in files)
    return {
        "compatibility": {
            "consumer_schema": "kilix.speech.models/v1",
            "maximum": 1,
            "minimum": 1,
        },
        "files": files,
        "id": asset_id,
        "label": asset_id,
        "licenses": [
            {
                "decision": license_record.decision_class,
                "id": "apache-2.0",
                "licensors": list(licensors),
                "record_digest": license_record.digest,
                "text_sha256": license_record.text_sha256,
            }
        ],
        "provider": "kilix-voice",
        "schema": "kilix.content.asset/v3",
        "sizes": {
            "download_bytes": len(archive),
            "installed_bytes": installed,
            "temporary_bytes": len(archive) + installed,
        },
        "source": {
            "archive_bytes": len(archive),
            "archive_sha256": sha256_bytes(archive),
            "format": "zip",
            "mode": "upstream-archive",
            "provenance": {
                "original_url": url,
                "project": "alphacep/vosk-models",
                "revision": "fixture",
            },
            "root": root,
            "url": url,
        },
        "stream": "F104",
        "version": "fixture",
    }


def requests_before(log: list[dict[str, Any]], event: Callable[[dict[str, Any]], bool]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for item in log:
        collected.append(item)
        if event(item):
            break
    return collected
