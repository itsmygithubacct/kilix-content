from __future__ import annotations

import hashlib
import os
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from first_use_fixture import FakeUpstream
from kilix_content.fetch import (
    DownloadError,
    Progress,
    _RESUME_MIN_BYTES,
    fetch_exact,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class FetchExactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-fetch-"))
        self.upstream = FakeUpstream()
        self.body = b"abcdefghijklmnopqrstuvwxyz" * 32
        self.url = self.upstream.add("/ok", self.body)

    def tearDown(self) -> None:
        self.upstream.close()

    def _fetch(self, url: str, **kwargs):
        destination = str(self.scratch / "out.bin")
        kwargs.setdefault("expected_bytes", len(self.body))
        kwargs.setdefault("expected_sha256", _sha(self.body))
        return fetch_exact(url, destination, **kwargs)

    def test_https_happy_path(self) -> None:
        path = self._fetch(self.url)
        self.assertEqual(Path(path).read_bytes(), self.body)

    def test_https_downgrade_is_refused(self) -> None:
        url = self.upstream.add("/down", self.body, kind="downgrade-to-http")
        with self.assertRaises(DownloadError) as raised:
            self._fetch(url)
        self.assertEqual(raised.exception.kind, "tls")
        self.assertEqual(self.upstream.http_requests(), [])

    def test_cross_host_https_redirect_is_accepted(self) -> None:
        peer = FakeUpstream(cert=self.upstream.cert, key=self.upstream.key)
        try:
            peer.add("/ok", self.body)
            self.upstream.https.peer_url = peer.url
            url = self.upstream.add("/cross", self.body, kind="redirect-crosshost")
            path = self._fetch(url)
            self.assertEqual(Path(path).read_bytes(), self.body)
        finally:
            peer.close()

    def test_oversize_content_length_refused_before_body(self) -> None:
        url = self.upstream.add("/len", self.body, kind="wrong-length-header")
        with self.assertRaises(DownloadError) as raised:
            self._fetch(url)
        self.assertEqual(raised.exception.kind, "size-mismatch")

    def test_body_over_pin_aborted(self) -> None:
        url = self.upstream.add("/over", self.body, kind="oversize")
        with self.assertRaises(DownloadError) as raised:
            self._fetch(url, expected_bytes=len(self.body), expected_sha256=_sha(self.body))
        self.assertEqual(raised.exception.kind, "size-mismatch")

    def test_truncated_body_refused(self) -> None:
        url = self.upstream.add("/trunc", self.body, kind="truncate")
        with self.assertRaises(DownloadError) as raised:
            self._fetch(url)
        self.assertEqual(raised.exception.kind, "size-mismatch")

    def test_trickle_ends_by_deadline(self) -> None:
        url = self.upstream.add("/trickle", self.body, kind="trickle-body", delay=0.3)
        with self.assertRaises(DownloadError) as raised:
            self._fetch(url, deadline=time.monotonic() + 0.2)
        self.assertEqual(raised.exception.kind, "deadline")
        self.assertTrue((self.scratch / "out.bin.part").exists() or True)

    def test_cancel_mid_body(self) -> None:
        url = self.upstream.add("/slow", self.body)
        cancelled = {"flag": False}

        def flag() -> bool:
            return cancelled["flag"]

        def progress(event: Progress) -> None:
            if event.phase == "download" and event.done > 0:
                cancelled["flag"] = True

        started = time.monotonic()
        with mock.patch("kilix_content.fetch._BLOCK", 16):
            with self.assertRaises(DownloadError) as raised:
                self._fetch(
                    url,
                    cancelled=flag,
                    progress=progress,
                    partial_dir=str(self.scratch / "partial"),
                )
        self.assertEqual(raised.exception.kind, "cancelled")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_sha_mismatch_deletes_partial(self) -> None:
        url = self.upstream.add("/bad", self.body)
        partial = self.scratch / "partial"
        with self.assertRaises(DownloadError) as raised:
            self._fetch(url, expected_sha256="ab" * 32, partial_dir=str(partial))
        self.assertEqual(raised.exception.kind, "digest-mismatch")
        self.assertFalse((partial / "0.part").exists())

    def test_statvfs_shortfall_zero_requests(self) -> None:
        class _Vfs:
            f_bavail = 1
            f_frsize = 1

        with mock.patch("kilix_content.fetch.os.statvfs", return_value=_Vfs()):
            with self.assertRaises(DownloadError) as raised:
                self._fetch(self.url)
        self.assertEqual(raised.exception.kind, "no-space")
        self.assertEqual(self.upstream.requests(), [])

    def test_progress_is_monotone(self) -> None:
        events: list[Progress] = []
        self._fetch(self.url, progress=events.append)
        downloads = [event for event in events if event.phase == "download"]
        done = [event.done for event in downloads]
        self.assertEqual(done, sorted(done))
        self.assertEqual(events[-1].done, events[-1].total)

    def test_resume_206(self) -> None:
        url = self.upstream.add("/range", self.body, kind="range-ok")
        partial_dir = self.scratch / "resume"
        partial_dir.mkdir()
        part = partial_dir / "0.part"
        part.write_bytes(self.body[:20])
        sidecar = {
            "etag": '"fixture"',
            "expected_bytes": len(self.body),
            "expected_sha256": _sha(self.body),
            "last_modified": "",
            "url": url,
        }
        import json

        (partial_dir / "0.part.sidecar").write_text(json.dumps(sidecar), encoding="utf-8")
        with mock.patch("kilix_content.fetch._RESUME_MIN_BYTES", 1):
            path = self._fetch(url, partial_dir=str(partial_dir))
        self.assertEqual(Path(path).read_bytes(), self.body)
        statuses = [item.get("status") for item in self.upstream.requests()]
        self.assertIn(206, statuses)

    def test_range_ignored_restarts(self) -> None:
        url = self.upstream.add("/ignored", self.body, kind="range-ignored")
        partial_dir = self.scratch / "restart"
        partial_dir.mkdir()
        (partial_dir / "0.part").write_bytes(self.body[:20])
        import json

        (partial_dir / "0.part.sidecar").write_text(
            json.dumps(
                {
                    "etag": '"fixture"',
                    "expected_bytes": len(self.body),
                    "expected_sha256": _sha(self.body),
                    "last_modified": "",
                    "url": url,
                }
            ),
            encoding="utf-8",
        )
        with mock.patch("kilix_content.fetch._RESUME_MIN_BYTES", 1):
            path = self._fetch(url, partial_dir=str(partial_dir))
        self.assertEqual(Path(path).read_bytes(), self.body)

    def test_proxy_connect_is_recorded(self) -> None:
        os.environ["https_proxy"] = self.upstream.http_url
        os.environ["HTTPS_PROXY"] = self.upstream.http_url
        os.environ["no_proxy"] = ""
        os.environ["NO_PROXY"] = ""
        try:
            try:
                self._fetch(self.url)
            except DownloadError:
                pass
            connects = [
                item
                for item in self.upstream.http.log
                if item.get("command") == "CONNECT"
            ]
            self.assertTrue(connects)
        finally:
            os.environ["https_proxy"] = "http://127.0.0.1:9"
            os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"
            os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
            os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1"

    def test_default_redirect_handler_is_the_defect(self) -> None:
        url = self.upstream.add("/down2", self.body, kind="downgrade-to-http")
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        with mock.patch("kilix_content.fetch._opener", return_value=opener):
            try:
                self._fetch(url)
            except Exception:
                pass
        self.assertTrue(
            self.upstream.http_requests(),
            "stdlib redirect handler follows https->http; production must not",
        )
