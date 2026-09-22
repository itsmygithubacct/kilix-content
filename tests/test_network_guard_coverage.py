"""What the network audit hook can and cannot see -- measured, not assumed (F1).

Three seats have reported "0 audit lines" as a zero-network proof. It is not
one. `tests/support/network_guard.py` is a CPython audit hook over seven socket
events in one interpreter; a connection made any other way arrives without
raising any of them, and the log stays empty. C-V3-EXTEND-VERIFY proved that by
bringing `lo` up, binding a listener in the same process and connecting four
ways: the Python control logged 1 line, and `ctypes` libc `connect()`, a
Python child, and `bash`'s `/dev/tcp` each **reached the listener** while the
log recorded **0**.

This module commits that battery, so the instrument's boundary is a measurement
that runs on every suite run rather than a claim in a report. Every route the
hook cannot cover is named here and asserted to be named in
`network_guard.NOT_COVERED` as well -- a route that stops being listed there
fails this module rather than quietly becoming an unnamed gap.

What makes a zero meaningful is the namespace: `unshare -cn` with `lo` DOWN and
an empty route table. The hook is corroboration. `test_the_module_says_the_
namespace_is_the_real_control` pins that sentence in the module itself.

Nothing here leaves the machine: every route connects to a listener this
process bound on 127.0.0.1, which the guard allows anyway (OD-S: no weight
byte, and no upstream host is named).
"""

from __future__ import annotations

import ctypes
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import network_guard

ROOT = Path(__file__).resolve().parents[1]

#: Routes this battery drives, and whether the hook is expected to log them.
#: "logged" is the measurement the whole zero-network claim rests on.
ROUTES_THE_HOOK_SEES = ("python socket.connect",)
ROUTES_THAT_ESCAPE = (
    "ctypes libc connect",
    "subprocess python child",
    "bash /dev/tcp",
)


class NetworkGuardCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(network_guard.installed(), "the audit hook is not installed")
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-netcov-"))
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.log = self.scratch / "audit.log"
        self.log.write_text("")
        previous = os.environ.get(network_guard.AUDIT_LOG_ENV)
        os.environ[network_guard.AUDIT_LOG_ENV] = str(self.log)

        def restore() -> None:
            if previous is None:
                os.environ.pop(network_guard.AUDIT_LOG_ENV, None)
            else:
                os.environ[network_guard.AUDIT_LOG_ENV] = previous

        self.addCleanup(restore)

    # ---- the listener -----------------------------------------------------

    def _listener(self) -> tuple[socket.socket | None, str, int]:
        """Bind a real listener in this process, or report that we could not.

        With `lo` DOWN the bind can fail. The logging half of the battery -- the
        half the zero-network claim actually rests on -- is measured either way;
        only the "did it arrive" half needs a reachable listener, and the test
        says which half it ran rather than skipping.
        """
        try:
            server = socket.socket()
            server.bind(("127.0.0.1", 0))
            server.listen(8)
        except OSError:
            return None, "127.0.0.1", 9
        self.addCleanup(server.close)
        host, port = server.getsockname()
        return server, host, port

    def _lines(self) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if line]

    def _arrived(self, server: socket.socket | None) -> bool:
        if server is None:
            return False
        server.settimeout(1.0)
        try:
            handle, _ = server.accept()
        except OSError:
            return False
        handle.close()
        return True

    def _drive(self, route, server) -> tuple[int, bool]:
        before = len(self._lines())
        try:
            route()
        except OSError:
            pass
        except subprocess.SubprocessError:
            pass
        return len(self._lines()) - before, self._arrived(server)

    # ---- the four routes --------------------------------------------------

    @staticmethod
    def _python_connect(host: str, port: int) -> None:
        handle = socket.socket()
        handle.settimeout(1.0)
        try:
            handle.connect((host, port))
        finally:
            handle.close()

    @staticmethod
    def _ctypes_connect(host: str, port: int) -> None:
        """libc connect() through ctypes: no audit event of any kind."""
        libc = ctypes.CDLL(None, use_errno=True)
        handle = socket.socket()
        try:
            # sin_family is host byte order; sin_port and sin_addr are network.
            address = (
                struct.pack("=H", socket.AF_INET)
                + struct.pack("!H", port)
                + socket.inet_aton(host)
                + b"\x00" * 8
            )
            if libc.connect(handle.fileno(), address, len(address)) != 0:
                errno = ctypes.get_errno()
                raise OSError(errno, os.strerror(errno))
        finally:
            handle.close()

    @staticmethod
    def _child_connect(host: str, port: int) -> None:
        """A Python child with no PYTHONPATH: its own interpreter, no hook."""
        code = (
            "import socket\n"
            "handle = socket.socket()\n"
            "handle.settimeout(1.0)\n"
            f"handle.connect(({host!r}, {port}))\n"
            "handle.close()\n"
        )
        subprocess.run(
            [sys.executable, "-c", code],
            env={},
            check=False,
            capture_output=True,
            timeout=60,
        )

    @staticmethod
    def _bash_devtcp(host: str, port: int) -> None:
        """bash's /dev/tcp: the kernel opens the socket, not Python."""
        bash = shutil.which("bash")
        if bash is None:  # named, not silently omitted -- see the test below
            raise OSError("bash is not on PATH")
        subprocess.run(
            [bash, "-c", f"exec 3<>/dev/tcp/{host}/{port}; exec 3<&-; exec 3>&-"],
            check=False,
            capture_output=True,
            timeout=60,
        )

    # ---- the battery ------------------------------------------------------

    def test_the_four_route_battery(self) -> None:
        """One control that is logged, three escapes that are not.

        The point is not that the escapes work -- of course they do. The point
        is that the audit log cannot tell you they happened, so a zero in it is
        evidence about seven events and not about the network.
        """
        server, host, port = self._listener()
        measured: dict[str, tuple[int, bool]] = {}

        measured["python socket.connect"] = self._drive(
            lambda: self._python_connect(host, port), server
        )
        measured["ctypes libc connect"] = self._drive(
            lambda: self._ctypes_connect(host, port), server
        )
        measured["subprocess python child"] = self._drive(
            lambda: self._child_connect(host, port), server
        )
        bash_available = shutil.which("bash") is not None
        measured["bash /dev/tcp"] = self._drive(
            lambda: self._bash_devtcp(host, port), server
        )

        # The control: the hook sees Python's own connect, so an empty log is
        # an empty log and not a hook that was never listening.
        logged, arrived = measured["python socket.connect"]
        self.assertEqual(logged, 1, measured)
        if server is not None:
            self.assertTrue(arrived, measured)

        # The escapes: zero lines each, and where a listener could be bound,
        # a real connection that completed.
        for route in ROUTES_THAT_ESCAPE:
            if route == "bash /dev/tcp" and not bash_available:
                # Named rather than omitted: the route is still asserted to be
                # declared uncovered below; only the measurement is missing.
                self.assertIn("bash", " ".join(network_guard.NOT_COVERED))
                continue
            with self.subTest(route=route):
                logged, arrived = measured[route]
                self.assertEqual(logged, 0, measured)
                if server is not None:
                    self.assertTrue(
                        arrived,
                        f"{route} did not reach the listener; "
                        f"this battery measures nothing: {measured}",
                    )

        # The whole log for this test contains exactly the control's one line.
        lines = self._lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("socket.connect", lines[0])

    def test_getent_and_af_unix_are_invisible_too(self) -> None:
        """Two more routes, one accidental and one deliberate."""
        server, _, _ = self._listener()
        del server
        before = len(self._lines())
        getent = shutil.which("getent")
        if getent is not None:
            subprocess.run(
                [getent, "hosts", "localhost"],
                check=False,
                capture_output=True,
                timeout=60,
            )
            self.assertEqual(len(self._lines()) - before, 0)

        # AF_UNIX is deliberate: `_audit` returns early on a non-tuple address
        # because an AF_UNIX path is not a network host. Deliberate is still
        # invisible, so it is measured here rather than assumed.
        directory = Path(tempfile.mkdtemp(dir=self.scratch))
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(directory / "s"))
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(client.close)
        before = len(self._lines())
        client.connect(str(directory / "s"))
        self.assertEqual(len(self._lines()) - before, 0)

    # ---- the instrument describes itself ----------------------------------

    def test_every_escaping_route_is_named_by_the_module(self) -> None:
        """A gap that stops being named fails here, not in a later report."""
        declared = " ".join(network_guard.NOT_COVERED).lower()
        for fragment in ("ctypes", "subprocess", "/dev/tcp", "af_unix", "getent"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, declared)
        self.assertEqual(len(network_guard.COVERED_EVENTS), 7, network_guard.COVERED_EVENTS)
        self.assertEqual(
            network_guard.COVERED_EVENTS,
            (
                "socket.connect",
                "socket.getaddrinfo",
                "socket.gethostbyaddr",
                "socket.gethostbyname",
                "socket.getnameinfo",
                "socket.sendmsg",
                "socket.sendto",
            ),
        )

    def test_every_message_the_hook_prints_carries_its_scope(self) -> None:
        """An allowed line, a refused line and the refusal all state the limit.

        A log line lifted into a report must carry its own scope, because the
        thing being claimed from it -- "no network" -- is exactly what it
        cannot support on its own.
        """
        try:
            # Port 9 (discard) is closed here; the attempt is the event,
            # its outcome is irrelevant.
            self._python_connect("127.0.0.1", 9)
        except OSError:
            pass
        allowed = self._lines()
        self.assertEqual(len(allowed), 1, allowed)
        self.assertIn(network_guard.COVERAGE, allowed[0])

        with self.assertRaises(OSError) as raised:
            sys.audit("socket.getaddrinfo", "models.example.test", 443, 0, 0, 0)
        self.assertIn(network_guard.COVERAGE, str(raised.exception))
        refused = self._lines()
        self.assertEqual(len(refused), 2, refused)
        self.assertIn(network_guard.COVERAGE, refused[1])

        for fragment in ("not-covered", "ctypes", "child-processes", "AF_UNIX"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, network_guard.COVERAGE)

    def test_the_module_says_the_namespace_is_the_real_control(self) -> None:
        """The sentence that stops the next report over-claiming an empty log."""
        text = (ROOT / "tests/support/network_guard.py").read_text(encoding="utf-8")
        self.assertIn("unshare -cn", text)
        self.assertIn("The namespace is the real control, not this hook.", text)
        note = network_guard.coverage_note()
        self.assertIn("unshare -cn", note)
        self.assertIn("does NOT observe", note)
        self.assertIn("does not prove it", note)

    # ---- the child-process claim, now true --------------------------------

    def _child_guard_state(self, pythonpath: str) -> tuple[str, str]:
        probe = (
            "import network_guard, sys\n"
            "print('installed', network_guard.installed())\n"
            "try:\n"
            "    sys.audit('socket.getaddrinfo', 'models.example.test', 443, 0, 0, 0)\n"
            "except OSError:\n"
            "    print('refused True')\n"
            "else:\n"
            "    print('refused False')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            env={"PYTHONPATH": pythonpath, "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout, result.stderr

    def test_a_child_with_only_tests_support_still_gets_the_network_guard(self) -> None:
        """The fail-open the verifier found: sitecustomize died before install.

        `live_store_guard` imports `kilix_license`. With only `tests/support` on
        PYTHONPATH that import fails, and it used to be the *first* line of
        sitecustomize -- so the module died with a one-line warning and the
        network guard was never installed, in a process the docstring claimed
        was covered. The guard is now installed first and unconditionally.
        """
        out, err = self._child_guard_state(str(ROOT / "tests/support"))
        self.assertIn("installed True", out)
        self.assertIn("refused True", out)
        # The live-store guard genuinely cannot install there, and says so
        # loudly instead of in a line nobody reads.
        self.assertIn("LIVE STORE GUARD NOT INSTALLED", err)
        self.assertIn("network guard IS installed", err)

    def test_a_child_with_the_full_test_path_gets_both_guards(self) -> None:
        full = os.pathsep.join(
            str(ROOT / part)
            for part in ("src", "third_party/kilix-license/src", "tests/support")
        )
        out, err = self._child_guard_state(full)
        self.assertIn("installed True", out)
        self.assertIn("refused True", out)
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
