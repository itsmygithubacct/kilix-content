from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
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


def _run_by_make() -> bool:
    """Whether a make recipe started this process.

    make itself puts MAKELEVEL in every recipe's environment, so no edit of
    this repository's Makefile can drop it together with the recipe's exports
    and the KILIX_CONTENT_MAKE_TEST marker (C2E-FIX-VERIFY R2).
    """
    return "MAKELEVEL" in os.environ or "KILIX_CONTENT_MAKE_TEST" in os.environ


class _Backstop(Exception):
    """A socket call got past the network guard; stopped before it reached libc."""


_BACKSTOP_THREADS: set[int] = set()
_BACKSTOP_INSTALLED = False


def _backstop(event: str, _args: tuple[object, ...]) -> None:
    if event.startswith("socket.") and threading.get_ident() in _BACKSTOP_THREADS:
        raise _Backstop(event)


@contextlib.contextmanager
def _network_backstop() -> Iterator[None]:
    """Stop, on this thread, every socket call the network guard lets through.

    Audit hooks run in the order they were added, and the guard was added
    first (sitecustomize, tests/__init__.py). A call the guard refuses raises
    its OSError; any other call raises _Backstop here, before libc, even when
    the guard is broken. So these tests never make a real lookup or send.
    """
    global _BACKSTOP_INSTALLED
    if not _BACKSTOP_INSTALLED:
        sys.addaudithook(_backstop)
        _BACKSTOP_INSTALLED = True
    ident = threading.get_ident()
    _BACKSTOP_THREADS.add(ident)
    try:
        yield
    finally:
        _BACKSTOP_THREADS.discard(ident)


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

    def test_every_hooked_socket_call_is_refused_before_libc(self) -> None:
        """Real calls for each event the guard claims, bytes hosts too (C2E-FIX-VERIFY R3)."""
        self.assertTrue(network_guard.installed())
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(udp.close)
        dns = "non-loopback DNS refused: "
        calls = {
            "getaddrinfo": (lambda: socket.getaddrinfo("alphacephei.com", 443), dns + "alphacephei.com"),
            "getaddrinfo, bytes host": (
                lambda: socket.getaddrinfo(b"alphacephei.com", 443),
                dns + "alphacephei.com",
            ),
            "gethostbyname": (lambda: socket.gethostbyname("alphacephei.com"), dns + "alphacephei.com"),
            "gethostbyname_ex": (
                lambda: socket.gethostbyname_ex("alphacephei.com"),
                dns + "alphacephei.com",
            ),
            "gethostbyaddr": (lambda: socket.gethostbyaddr("192.0.2.1"), dns + "192.0.2.1"),
            "getnameinfo": (lambda: socket.getnameinfo(("192.0.2.1", 443), 0), dns + "192.0.2.1"),
            "connect": (lambda: udp.connect(("192.0.2.1", 9)), "non-loopback connect refused: 192.0.2.1"),
            "sendto": (lambda: udp.sendto(b"x", ("192.0.2.1", 9)), "non-loopback send refused: 192.0.2.1"),
            "sendmsg": (
                lambda: udp.sendmsg([b"x"], [], 0, ("192.0.2.1", 9)),
                "non-loopback send refused: 192.0.2.1",
            ),
            "create_connection": (
                lambda: socket.create_connection(("alphacephei.com", 443), timeout=1),
                dns + "alphacephei.com",
            ),
        }
        for label, (call, message) in calls.items():
            with self.subTest(call=label):
                with _network_backstop():
                    with self.assertRaisesRegex(OSError, f"^{re.escape(message)}$"):
                        call()
        # Control: loopback passes the guard, so the backstop is what stops it.
        for host in ("127.0.0.1", b"127.0.0.1"):
            with self.subTest(control=host):
                with _network_backstop():
                    with self.assertRaises(_Backstop):
                        socket.getaddrinfo(host, 9)

    def test_python_children_load_the_network_guard(self) -> None:
        """A child started as the suite starts them has the guard (C2E-FIX-VERIFY R3).

        It inherits this environment and runs from a temporary directory, where
        a relative tests/support on PYTHONPATH would not resolve.
        """
        if not _run_by_make():
            self.skipTest("not run by make")
        probe = (
            "import sys\n"
            "print(getattr(sys.modules.get('sitecustomize'), '__file__', None))\n"
            "try:\n"
            "    sys.audit('socket.getaddrinfo', 'alphacephei.com', 443, 0, 0, 0)\n"
            "except OSError as error:\n"
            "    print(error)\n"
            "else:\n"
            "    print('not refused')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=self.scratch,
            env=dict(os.environ),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        loaded, refused = result.stdout.splitlines()
        self.assertEqual(Path(loaded).resolve(), ROOT / "tests" / "support" / "sitecustomize.py")
        self.assertEqual(refused, "non-loopback DNS refused: alphacephei.com")

    def test_only_the_test_recipe_puts_tests_support_on_pythonpath(self) -> None:
        """No other recipe loads the test sitecustomize (C2E-FIX-VERIFY R4)."""
        make = shutil.which("make")
        self.assertIsNotNone(make, "make is not on PATH")
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("PYTHONPATH", "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES")
        }

        def make_output(*args: str) -> str:
            result = subprocess.run(
                [make, "-s", "--no-print-directory", "-C", str(ROOT), *args],
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        # What make exports to every recipe: nothing on PYTHONPATH.
        probe = "kilix-content-pythonpath-probe: ; @printf '[%s]\\n' \"$$PYTHONPATH\""
        self.assertEqual(
            make_output("--eval", probe, "kilix-content-pythonpath-probe"), "[]\n"
        )
        # What each other recipe sets itself (-n prints, never runs).
        for target in ("generate", "pins", "hygiene", "benchmark"):
            with self.subTest(target=target):
                commands = make_output("-n", target)
                self.assertTrue(commands.strip(), target)
                self.assertNotIn("tests/support", commands)
        self.assertIn("tests/support", make_output("-n", "test"))
        # Recipe text is not enough: a target-specific `export PYTHONPATH` sets
        # the variable without naming it in any command (C2E-FIX2-VERIFY T5).
        # So run each Python recipe with a probe in place of the interpreter and
        # read the environment and the sitecustomize it actually loaded.
        probe_dir = Path(tempfile.mkdtemp(prefix="kilix-content-python-probe-"))
        probe = probe_dir / "probe.py"
        probe.write_text(
            "import json, os, sys\n"
            "module = sys.modules.get('sitecustomize')\n"
            "print(json.dumps({\n"
            "    'pythonpath': os.environ.get('PYTHONPATH', ''),\n"
            "    'sitecustomize': getattr(module, '__file__', None),\n"
            "    'argv': sys.argv[1:],\n"
            "}))\n",
            encoding="utf-8",
        )
        for target in ("generate", "pins", "benchmark"):
            with self.subTest(target=target, arm="environment"):
                reports = [
                    json.loads(line)
                    for line in make_output(
                        target, f"PYTHON={sys.executable} {probe}"
                    ).splitlines()
                    if line.startswith("{")
                ]
                self.assertTrue(reports, f"{target} started no Python")
                for report in reports:
                    self.assertNotIn("tests/support", report["pythonpath"], report)
                    loaded = report["sitecustomize"] or ""
                    self.assertNotIn("tests/support", loaded, report)

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

    def test_caller_proxy_is_replaced_by_the_dead_proxy(self) -> None:
        """A caller's loopback proxy would pass the hook, then reach the network."""
        env = dict(os.environ)
        planted = "http://127.0.0.1:18080"
        for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
            env[key] = planted
        env["all_proxy"] = env["ALL_PROXY"] = "socks5://127.0.0.1:1080"
        env["no_proxy"] = env["NO_PROXY"] = "*"
        env["PYTHONPATH"] = os.pathsep.join(
            str(path)
            for path in (
                ROOT,
                ROOT / "src",
                ROOT / "third_party" / "kilix-license" / "src",
                ROOT / "tests" / "support",
            )
        )
        probe = (
            "import json, os, tests\n"
            "keys = ('https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY',\n"
            "        'no_proxy', 'NO_PROXY', 'all_proxy', 'ALL_PROXY')\n"
            "print(json.dumps({key: os.environ.get(key) for key in keys}))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        seen = json.loads(result.stdout)
        for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
            self.assertEqual(seen[key], "http://127.0.0.1:9", key)
        for key in ("no_proxy", "NO_PROXY"):
            self.assertEqual(seen[key], "localhost,127.0.0.1,::1", key)
        self.assertIsNone(seen["all_proxy"])
        self.assertIsNone(seen["ALL_PROXY"])

    def test_make_test_runs_unittest_in_its_scratch_environment(self) -> None:
        """The recipe's scratch reaches unittest, not only compileall (F4).

        Skipped only outside make. Under make, a lost marker or scratch is a
        failure, never a skip (C2E-FIX-VERIFY R2).
        """
        if not _run_by_make():
            self.skipTest("not run by make")
        self.assertEqual(
            os.environ.get("KILIX_CONTENT_MAKE_TEST"),
            "1",
            "run by make, but make test did not export KILIX_CONTENT_MAKE_TEST=1",
        )
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
