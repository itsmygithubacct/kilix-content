from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker

from kilix_content import AssetSpec, BindingMismatch, CatalogError, Installer, InstallError
from kilix_content import LicenseDecision, ReceiptMissing, ReleaseContext
from kilix_content import install as install_module
from kilix_content import receipt as receipt_module
from tests.receipt_store_support import open_test_store

ROOT = Path(__file__).resolve().parents[1]
LICENSE = b"Multipart fixture license text.\n"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fixture():
    files = {"weights/model.bin": b"unchanged model bytes" * 257, "notices/LICENSE.txt": LICENSE}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    payload = stream.getvalue()
    pieces = [payload[:3137], payload[3137:7777], payload[7777:]]
    urls = [f"https://assets.example.org/model/part-{index}" for index in range(len(pieces))]
    document = {
        "schema": "kilix.content.asset/v2", "id": "fixture-model", "label": "Model",
        "provider": "fixture-provider", "stream": "F104", "version": "1",
        "files": [{"path": name, "bytes": len(data), "sha256": digest(data)} for name, data in files.items()],
        "source": {
            "mode": "multipart-mirrored", "archive_sha256": digest(payload),
            "parts": [{"bytes": len(data), "sha256": digest(data), "mirrors": [url]} for data, url in zip(pieces, urls)],
            "provenance": {"project": "fixture", "revision": "a" * 40, "original_url": "https://example.org/models/fixture"},
        },
        "sizes": {"download_bytes": len(payload), "installed_bytes": sum(map(len, files.values())), "temporary_bytes": len(payload) + sum(map(len, files.values()))},
        "licenses": [{"id": "fixture-license", "decision": "informational", "text_sha256": digest(LICENSE)}],
        "compatibility": {"consumer_schema": "fixture.runtime", "minimum": 1, "maximum": 1},
    }
    return document, dict(zip(urls, pieces)), payload, files


class MultipartTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="multipart-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.document, self.responses, self.archive, self.files = fixture()
        self.spec = AssetSpec.from_mapping(self.document)
        self.destination = self.root / "archive.tar"
        self.opened = []
        self.opener = mock.Mock()
        self.opener.open.side_effect = self.response
        patch = mock.patch.object(install_module.urllib.request, "build_opener", return_value=self.opener)
        patch.start()
        self.addCleanup(patch.stop)
        # These assembly/installer unit tests use in-memory mirrors. Separate
        # HTTPS tests exercise the actual isolated subprocess boundary.
        def inline(spec, destination, report):
            return install_module._assemble_multipart_asset(
                spec.parts, spec.download_bytes, spec.archive_sha256, destination, report
            )
        patch = mock.patch.object(install_module, "_download_multipart_asset", side_effect=inline)
        patch.start()
        self.addCleanup(patch.stop)

    def response(self, request, **kwargs):
        self.opened.append(request.full_url)
        value = self.responses[request.full_url]
        if isinstance(value, BaseException):
            raise value
        return io.BytesIO(value)

    def download(self, spec=None, report=lambda _message: None):
        install_module._download_multipart_asset(spec or self.spec, str(self.destination), report)

    def authorize(self, store, spec=None):
        spec = spec or self.spec
        release = ReleaseContext.from_catalog("0.2.2", b"multipart fixture release")
        decision = LicenseDecision.from_mapping({
            "schema": "kilix.install.license/v1", "kind": "decision", "decision_class": "informational",
            "license_id": "fixture-license", "license_text_sha256": digest(LICENSE),
            "artifact_ids": [spec.asset_id], "release": "0.2.2", "presenter": "fixture", "outcome": "record",
        })
        store.record(decision, LICENSE, release, [spec])
        return release

    def test_schema_roundtrip_and_packaged_identity(self):
        schema_path = ROOT / "contracts/kilix.content.asset-v2.schema.json"
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(self.document)
        self.assertEqual(self.spec.to_mapping(), self.document)
        self.assertEqual(self.spec.canonicalized(), self.spec)
        self.assertEqual(schema_path.read_bytes(), (ROOT / "src/kilix_content/contracts" / schema_path.name).read_bytes())
        self.assertEqual(digest(schema_path.read_bytes()), receipt_module._ASSET_V2_SCHEMA_SHA256)
        self.assertEqual(digest((ROOT / "contracts/kilix.content.asset-v1.schema.json").read_bytes()), receipt_module._ASSET_SCHEMA_SHA256)

    def test_protocol_budgets_and_version_are_enforced(self):
        changes = [
            lambda d: d.update(schema="kilix.content.asset/v1"),
            lambda d: d["source"].update(parts=[]),
            lambda d: d["source"].update(parts=[d["source"]["parts"][0]] * 65),
            lambda d: d["source"].update(extra=True),
            lambda d: d["source"].update(archive_sha256="A" * 64),
            lambda d: d["source"]["parts"][0].update(bytes=0),
            lambda d: d["source"]["parts"][0].update(bytes=True),
            lambda d: d["source"]["parts"][0].update(bytes=2 * 1024**3),
            lambda d: d["source"]["parts"][0].update(sha256=[]),
            lambda d: d["source"]["parts"][0].update(mirrors=[]),
            lambda d: d["source"]["parts"][0].update(mirrors=["https://example.org/x"] * 2),
            lambda d: d["source"]["parts"][0].update(mirrors=[f"https://example.org/{i}" for i in range(9)]),
            lambda d: d["source"]["parts"][0].update(mirrors=["http://example.org/x"]),
            lambda d: d["source"]["parts"][0].update(mirrors=["https://user:secret@example.org/x"]),
            lambda d: d["source"]["parts"][0].update(mirrors=["https://example.org/x?token=secret"]),
            lambda d: d["sizes"].update(download_bytes=d["sizes"]["download_bytes"] + 1),
            lambda d: d["sizes"].update(temporary_bytes=d["sizes"]["temporary_bytes"] - 1),
            lambda d: d["source"].update(mode="mirrored"),
        ]
        for index, change in enumerate(changes):
            document = copy.deepcopy(self.document)
            change(document)
            with self.subTest(mutation=index), self.assertRaises(CatalogError):
                AssetSpec.from_mapping(document)

    def test_assembly_preserves_exact_archive(self):
        self.download()
        self.assertEqual(self.destination.read_bytes(), self.archive)
        self.assertEqual(self.opened, list(self.responses))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["archive.tar"])
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)

    def test_failed_part_mirror_rolls_back_bytes_and_hash_state(self):
        document = copy.deepcopy(self.document)
        second = document["source"]["parts"][1]
        original = second["mirrors"][0]
        for value in (self.responses[original][:-1], self.responses[original] + b"x", b"X" * second["bytes"], OSError("private diagnostic")):
            with self.subTest(failure=type(value).__name__):
                bad = "https://assets.example.org/bad"
                self.responses[bad] = value
                second["mirrors"] = [bad, original]
                self.download(AssetSpec.from_mapping(document))
                self.assertEqual(self.destination.read_bytes(), self.archive)

    def test_bad_part_or_final_digest_preserves_existing_output(self):
        self.destination.write_bytes(b"previous output")
        for field in ("part", "archive"):
            document = copy.deepcopy(self.document)
            if field == "part":
                document["source"]["parts"][1]["sha256"] = "0" * 64
            else:
                document["source"]["archive_sha256"] = "0" * 64
            with self.subTest(field=field), self.assertRaises(InstallError):
                self.download(AssetSpec.from_mapping(document))
            self.assertEqual(self.destination.read_bytes(), b"previous output")
            self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["archive.tar"])

    def test_reordered_valid_parts_fail_original_archive_digest(self):
        document = copy.deepcopy(self.document)
        document["source"]["parts"].reverse()
        with self.assertRaises(InstallError):
            self.download(AssetSpec.from_mapping(document))
        self.assertFalse(self.destination.exists())

    def test_cleanup_after_fdopen_failure_and_interrupted_progress(self):
        before = set(os.listdir("/proc/self/fd"))
        with mock.patch.object(install_module.os, "fdopen", side_effect=MemoryError), self.assertRaises(MemoryError):
            self.download()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        def interrupted(_message):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.download(report=interrupted)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_expired_download_never_selects(self):
        with mock.patch.object(install_module, "_MULTIPART_DOWNLOAD_SECONDS", -1), self.assertRaises(InstallError):
            self.download()
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.opened, [])

    def test_symlink_destination_does_not_modify_target(self):
        target = self.root / "keep"
        target.write_bytes(b"original")
        self.destination.symlink_to(target)
        self.download()
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(self.destination.read_bytes(), self.archive)

    def test_redirects_refuse_downgrade_and_credentials(self):
        handler = install_module._HTTPSPartRedirects()
        request = urllib.request.Request("https://example.org/part")
        for target in ("http://example.org/part", "file:///tmp/part", "https://u:p@example.org/part", "https://example.org:bad/part"):
            with self.subTest(target=target), self.assertRaises(InstallError):
                handler.redirect_request(request, None, 302, "Found", {}, target)
        signed = "https://cdn.example.org/part?signature=opaque"
        self.assertEqual(handler.redirect_request(request, None, 302, "Found", {}, signed).full_url, signed)

    def test_receipt_precedes_download_and_install_verifies_all_members(self):
        installer = Installer(str(self.root / "content"))
        release = ReleaseContext.from_catalog("0.2.2", b"multipart fixture release")
        with open_test_store(str(self.root / "state"), assets=[self.spec]) as store:
            with self.assertRaises(ReceiptMissing):
                installer.ensure_asset(self.spec, store, release)
            self.assertEqual(self.opened, [])
            release = self.authorize(store)
            paths = installer.ensure_asset(self.spec, store, release)
            self.assertEqual(len(paths), len(self.files))
            for path, expected in zip(paths, self.files.values()):
                self.assertEqual(Path(path).read_bytes(), expected)
            self.opened.clear()
            self.assertEqual(installer.asset_ready(self.spec, store, release), paths)
            self.assertEqual(installer.ensure_asset(self.spec, store, release), paths)
            self.assertEqual(self.opened, [])
            changed = copy.deepcopy(self.document)
            changed["source"]["parts"].reverse()
            with self.assertRaises(BindingMismatch):
                installer.ensure_asset(AssetSpec.from_mapping(changed), store, release)
            self.assertEqual(self.opened, [])

    def test_archive_members_must_match_after_all_part_hashes_pass(self):
        document = copy.deepcopy(self.document)
        document["files"][0]["sha256"] = "0" * 64
        spec = AssetSpec.from_mapping(document)
        installer = Installer(str(self.root / "content"))
        with open_test_store(str(self.root / "state"), assets=[spec]) as store:
            release = self.authorize(store, spec)
            with self.assertRaises(InstallError):
                installer.ensure_asset(spec, store, release)
            self.assertIsNone(installer.asset_ready(spec, store, release))
            self.assertFalse(Path(installer.asset_destination(spec)).exists())


if __name__ == "__main__":
    unittest.main()
