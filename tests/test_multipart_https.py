"""Real loopback TLS and process-boundary checks; no public mirrors needed."""

from __future__ import annotations

import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from kilix_content import AssetSpec, InstallError
from kilix_content import install
from tests.test_multipart import fixture


class MultipartHTTPSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_directory = tempfile.TemporaryDirectory(prefix="multipart-tls-")
        cls.addClassCleanup(cls.cert_directory.cleanup)
        cls.cert = Path(cls.cert_directory.name) / "cert.pem"
        cls.key = Path(cls.cert_directory.name) / "key.pem"
        subprocess.run([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=20)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="multipart-https-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.destination = self.root / "archive.tar"
        self.document, responses, self.archive, _files = fixture()
        self.payloads = {urlsplit(url).path: data for url, data in responses.items()}
        self.seen = []
        self.release = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                owner.seen.append(path)
                try:
                    if path == "/trickle-headers":
                        self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Trickle: ")
                        while not owner.release.wait(0.03):
                            self.connection.sendall(b"x")
                    elif path == "/trickle-body":
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(owner.payloads["/model/part-0"])))
                        self.end_headers()
                        while not owner.release.wait(0.03):
                            self.wfile.write(b"x")
                            self.wfile.flush()
                    elif path in ("/redirect", "/downgrade"):
                        self.send_response(302)
                        scheme = "https" if path == "/redirect" else "http"
                        self.send_header("Location", f"{scheme}://localhost:{owner.server.server_port}/model/part-0?signature=opaque")
                        self.end_headers()
                    else:
                        data = owner.payloads[path]
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                except (OSError, KeyError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.origin = f"https://localhost:{self.server.server_port}"
        for index, part in enumerate(self.document["source"]["parts"]):
            part["mirrors"] = [f"{self.origin}/model/part-{index}"]
        environment = mock.patch.dict(os.environ, {
            "SSL_CERT_FILE": str(self.cert), "NO_PROXY": "localhost,127.0.0.1",
            "no_proxy": "localhost,127.0.0.1",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def close_server(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def download(self, document=None):
        install._download_multipart_asset(
            AssetSpec.from_mapping(document or self.document), str(self.destination), lambda _message: None
        )

    def test_actual_tls_worker_assembly_and_signed_redirect(self):
        self.document["source"]["parts"][0]["mirrors"] = [self.origin + "/redirect"]
        self.download()
        self.assertEqual(self.destination.read_bytes(), self.archive)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
        self.assertIn("/redirect", self.seen)
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_actual_worker_fallback_and_downgrade_refusal(self):
        self.payloads["/bad"] = b"invalid archive bytes"
        original = self.document["source"]["parts"][0]["mirrors"][0]
        self.document["source"]["parts"][0]["mirrors"] = [self.origin + "/bad", original]
        self.download()
        self.assertEqual(self.destination.read_bytes(), self.archive)
        self.assertEqual(self.seen[:2], ["/bad", "/model/part-0"])
        self.document["source"]["parts"][0]["mirrors"] = [self.origin + "/downgrade"]
        self.seen.clear()
        with self.assertRaises(InstallError):
            self.download()
        self.assertEqual(self.seen, ["/downgrade"])
        self.assertEqual(self.destination.read_bytes(), self.archive)
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_hard_deadline_covers_trickling_headers_and_body(self):
        self.destination.write_bytes(b"keep old output")
        original_spawn = install.subprocess.Popen
        for endpoint in ("/trickle-headers", "/trickle-body"):
            processes = []
            def spawn(*args, **kwargs):
                process = original_spawn(*args, **kwargs)
                processes.append(process)
                return process
            self.document["source"]["parts"][0]["mirrors"] = [self.origin + endpoint]
            started = time.monotonic()
            with (
                self.subTest(endpoint=endpoint),
                mock.patch.object(install, "_MULTIPART_DOWNLOAD_SECONDS", 2.0),
                mock.patch.object(install.subprocess, "Popen", side_effect=spawn),
                self.assertRaises(InstallError),
            ):
                self.download()
            self.assertLess(time.monotonic() - started, 6.0)
            self.assertIn(endpoint, self.seen)
            self.assertEqual(len(processes), 1)
            self.assertIsNotNone(processes[0].returncode)
            self.assertFalse(Path(f"/proc/{processes[0].pid}").exists())
            self.assertEqual(self.destination.read_bytes(), b"keep old output")
            self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_interrupt_reaps_worker_and_preserves_selection(self):
        self.destination.write_bytes(b"keep old output")
        self.document["source"]["parts"][0]["mirrors"] = [self.origin + "/trickle-headers"]
        original_wait = install._wait_without_reaping
        original_spawn = install.subprocess.Popen
        processes = []
        interrupt = [True]
        def spawn(*args, **kwargs):
            process = original_spawn(*args, **kwargs)
            processes.append(process)
            return process
        def wait(*args, **kwargs):
            if interrupt[0]:
                interrupt[0] = False
                raise KeyboardInterrupt
            return original_wait(*args, **kwargs)
        with (
            mock.patch.object(install.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(install, "_wait_without_reaping", side_effect=wait),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.download()
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        self.assertFalse(Path(f"/proc/{processes[0].pid}").exists())
        self.assertEqual(self.destination.read_bytes(), b"keep old output")
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_worker_excludes_ambient_python_startup_hooks(self):
        hook = self.root / "sitecustomize.py"
        marker = self.root / "unwanted-hook"
        hook.write_text(f"open({str(marker)!r}, 'w').write('unexpected')\n")
        with mock.patch.dict(os.environ, {
            "PYTHONPATH": str(self.root), "PYTHONSTARTUP": str(hook), "PYTHONHOME": str(self.root),
        }):
            self.download()
        self.assertEqual(self.destination.read_bytes(), self.archive)
        self.assertFalse(marker.exists())

    def test_plan_digest_and_file_type_refuse_before_network(self):
        plan_path = self.root / "plan"
        plan_path.write_bytes(b'{}')
        plan_path.chmod(0o600)
        descriptors = set(os.listdir("/proc/self/fd"))
        with mock.patch.object(install.urllib.request, "build_opener") as opener:
            self.assertEqual(install._multipart_worker_main(str(plan_path), "0" * 64, str(self.destination)), 1)
            plan_path.unlink()
            os.mkfifo(plan_path, 0o600)
            self.assertEqual(install._multipart_worker_main(str(plan_path), "0" * 64, str(self.destination)), 1)
            plan_path.unlink()
            plan_path.symlink_to(self.cert)
            self.assertEqual(install._multipart_worker_main(str(plan_path), "0" * 64, str(self.destination)), 1)
            opener.assert_not_called()
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        self.assertFalse(self.destination.exists())

    def test_parent_refuses_invalid_worker_output_before_replace(self):
        self.destination.write_bytes(b"keep old output")
        for invalid in ("bytes", "fifo", "symlink"):
            def pretend_success(argv, **_kwargs):
                output = Path(argv[-1])
                if invalid == "bytes":
                    output.write_bytes(b"x" * len(self.archive))
                    output.chmod(0o600)
                elif invalid == "fifo":
                    os.mkfifo(output, 0o600)
                else:
                    output.symlink_to(self.destination)
                return 0, ""
            with (
                self.subTest(output=invalid),
                mock.patch.object(install, "_run_with_tail", side_effect=pretend_success),
                self.assertRaises(InstallError),
            ):
                self.download()
            self.assertEqual(self.destination.read_bytes(), b"keep old output")
            self.assertEqual(list(self.root.iterdir()), [self.destination])


if __name__ == "__main__":
    unittest.main()
