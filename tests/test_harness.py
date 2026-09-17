from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from kilix_license.errors import LiveStoreForbidden
from kilix_license.paths import live_store_root

from fake_store import FakeStore
from first_use_fixture import FakeUpstream, install_store_guard
from kilix_content.fetch import fetch_exact
from kilix_content.paths import asset_store_root
from live_store_guard import live_root


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-harness-"))
        state = os.environ.get("XDG_STATE_HOME")
        if state:
            install_store_guard(Path(state).parent)

    def test_fake_store_root_is_temp(self) -> None:
        store = FakeStore(self.scratch / "receipts")
        self.assertTrue(str(store.root).startswith(str(self.scratch)))
        self.assertFalse(str(store.root).startswith(str(live_store_root())))

    def test_fake_store_refuses_live_root(self) -> None:
        with self.assertRaises(LiveStoreForbidden):
            FakeStore(live_store_root())

    def test_planted_live_store_write_is_refused(self) -> None:
        planted = live_root() / "planted-kilix-content-must-not-exist.json"
        existed_before = planted.exists()
        with self.assertRaises(LiveStoreForbidden):
            planted.write_text("planted", encoding="utf-8")
        self.assertEqual(existed_before, planted.exists())
        self.assertFalse(existed_before)

    def test_store_guard_refuses_unset_xdg_state_home(self) -> None:
        previous = os.environ.pop("XDG_STATE_HOME", None)
        try:
            with self.assertRaises(LiveStoreForbidden):
                asset_store_root()
        finally:
            if previous is not None:
                os.environ["XDG_STATE_HOME"] = previous

    def test_non_loopback_connect_is_refused(self) -> None:
        planted = "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip"
        destination = str(self.scratch / "planted.bin")
        with self.assertRaises(OSError):
            fetch_exact(
                planted,
                destination,
                expected_bytes=4,
                expected_sha256="0" * 64,
            )

    def test_fake_upstream_serves_loopback_https(self) -> None:
        upstream = FakeUpstream()
        try:
            body = b"fixture-bytes"
            url = upstream.add("/ok", body)
            destination = str(self.scratch / "ok.bin")
            fetch_exact(
                url,
                destination,
                expected_bytes=len(body),
                expected_sha256=__import__("hashlib").sha256(body).hexdigest(),
            )
            self.assertEqual(Path(destination).read_bytes(), body)
            self.assertEqual(upstream.http_requests(), [])
        finally:
            upstream.close()
