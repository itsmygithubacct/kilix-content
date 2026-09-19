from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kilix_license.errors import LiveStoreForbidden
from kilix_license.paths import live_store_root

import network_guard
from fake_store import FakeStore
from first_use_fixture import FakeUpstream, install_store_guard
from kilix_content.fetch import DownloadError, fetch_exact
from kilix_content.paths import asset_store_root
from live_store_guard import live_root

ROOT = Path(__file__).resolve().parents[1]

# Every variable that could route a fetch around the audit hook, or satisfy a
# refusal test by accident: a dead proxy, or a certificate path left behind
# by an earlier FakeUpstream (ssl.create_default_context then raises OSError).
_LEAKABLE = (
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
    "SSL_CERT_FILE",
)

# Environment the make test recipe must hand to unittest, all under its scratch.
_SCRATCH_ENV = (
    "HOME",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "KILIX_DATA_HOME",
    "KILIX_STORAGE_HOME",
    "KILIX_HOME",
    "GPU_TERMINAL_HOME",
)


def _exception_chain(error: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    pending: list[object] = [error]
    while pending:
        item = pending.pop()
        if not isinstance(item, BaseException) or any(item is known for known in seen):
            continue
        seen.append(item)
        pending.extend((item.__cause__, item.__context__, getattr(item, "reason", None)))
    return seen


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
        """Refused by the audit hook itself, alone or in any test order (C2E-VERIFY F4)."""
        # 1. The hook is installed. sys.audit only raises the event in this
        #    process; nothing is resolved or connected. Without the hook the
        #    test fails here, before any fetch is attempted.
        self.assertTrue(network_guard.installed())
        with self.assertRaisesRegex(OSError, "^non-loopback DNS refused: alphacephei.com$"):
            sys.audit("socket.getaddrinfo", "alphacephei.com", 443, 0, 0, 0)
        with self.assertRaisesRegex(OSError, "^non-loopback connect refused: 192.0.2.1$"):
            sys.audit("socket.connect", None, ("192.0.2.1", 443))
        # 2. fetch_exact meets the hook, not a dead proxy or a stale
        #    certificate path: both are removed for the attempt.
        planted = "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip"
        destination = self.scratch / "planted.bin"
        with mock.patch.dict(os.environ):
            for key in _LEAKABLE:
                os.environ.pop(key, None)
            with self.assertRaises(DownloadError) as raised:
                fetch_exact(
                    planted,
                    str(destination),
                    expected_bytes=4,
                    expected_sha256="0" * 64,
                )
        self.assertEqual(raised.exception.kind, "offline")
        refusals = [
            str(item)
            for item in _exception_chain(raised.exception)
            if type(item) is OSError and str(item).startswith("non-loopback ")
        ]
        self.assertEqual(refusals, ["non-loopback DNS refused: alphacephei.com"])
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_tests_package_isolation_is_loaded(self) -> None:
        """make test must import tests/__init__.py: its env redirect and hook (F4)."""
        package = sys.modules.get("tests")
        self.assertIsNotNone(package, "tests/__init__.py was not imported (discover -t .)")
        self.assertEqual(Path(package.__file__).resolve(), ROOT / "tests" / "__init__.py")
        scratch = Path(package._SCRATCH)
        for key, name in (
            ("XDG_STATE_HOME", "xdg-state"),
            ("XDG_RUNTIME_DIR", "xdg-runtime"),
            ("KILIX_DATA_HOME", "kilix-data"),
            ("KILIX_STORAGE_HOME", "kilix-storage"),
            ("KILIX_HOME", "kilix-home"),
            ("GPU_TERMINAL_HOME", "gpu-terminal"),
        ):
            self.assertEqual(os.environ.get(key), str(scratch / name), key)
        self.assertTrue(network_guard.installed())

    def test_make_test_runs_unittest_in_its_scratch_environment(self) -> None:
        """The recipe's scratch reaches unittest, not only compileall (F4)."""
        if os.environ.get("KILIX_CONTENT_MAKE_TEST") != "1":
            self.skipTest("not run by this repository's make test")
        scratch = os.environ.get("KILIX_CONTENT_TEST_SCRATCH")
        self.assertTrue(scratch, "make test did not export its scratch to unittest")
        root = os.path.realpath(scratch)
        for key in _SCRATCH_ENV:
            value = os.path.realpath(os.environ.get(key, ""))
            self.assertTrue(value.startswith(root + os.sep), f"{key}={value} is not under {root}")
        self.assertTrue(os.path.realpath(tempfile.gettempdir()).startswith(root + os.sep))
        self.assertIn("tests", sys.modules)

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
