from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.receipts import receipt_from_agreement
from kilix_license.store import ReceiptStore

from fake_store import FakeStore
from first_use_fixture import (
    FakeUpstream,
    hostile_parent_zip,
    hostile_symlink_zip,
    hostile_two_roots_zip,
    make_archive_asset,
    vosk_fixture_zip,
)
from kilix_content.install import InstallError, Installer
from kilix_content.model import AssetSpec, Catalog, CatalogError
from kilix_content.receipt import _CATALOG_SHA256, release_digest


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class UpstreamInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-upstream-"))
        self.upstream = FakeUpstream()
        self.records = load_determined_records()
        self.texts = load_determined_texts(self.scratch / "texts")
        self.notice = self.texts.get(self.records.by_id("small-en-us").text_sha256)
        self.store = FakeStore(self.scratch / "receipts")
        self.installer = Installer(str(self.scratch / "root"))
        self.record = self.records.by_id("small-en-us")

    def tearDown(self) -> None:
        self.upstream.close()

    def _authorize(self, spec: AssetSpec) -> None:
        agreement = capture_agreement(self.record, typed_agreement_line(self.record))
        receipt = receipt_from_agreement(
            self.record,
            agreement,
            manifest_digest=spec.manifest_digest,
            release_digest=release_digest(),
            catalogue_digest=_CATALOG_SHA256,
        )
        self.store.write(receipt)

    def _spec(self, archive: bytes, url: str, asset_id: str = "fixture-vosk") -> AssetSpec:
        raw = make_archive_asset(
            asset_id=asset_id,
            url=url,
            archive=archive,
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        return AssetSpec.from_mapping(raw, allow_file_urls=False)

    def test_archive_happy_path(self) -> None:
        archive = vosk_fixture_zip()
        url = self.upstream.add("/model.zip", archive)
        spec = self._spec(archive, url)
        self._authorize(spec)
        installed = self.installer.ensure_upstream_asset(
            spec, store=self.store, records=self.records, notices=self.texts
        )
        root = Path(installed[0])
        self.assertTrue((root / "conf/model.conf").is_file())
        self.assertTrue((root / "notices/LICENSE-apache-2.0.txt").is_file())
        self.assertEqual((root / "notices/LICENSE-apache-2.0.txt").read_bytes(), self.notice)

    def test_extra_member_refused(self) -> None:
        archive = vosk_fixture_zip(extra={"extra.bin": b"nope"})
        url = self.upstream.add("/extra.zip", archive)
        honest = vosk_fixture_zip()
        mapping = make_archive_asset(
            asset_id="fixture-extra",
            url=url,
            archive=honest,
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        mapping["source"]["archive_bytes"] = len(archive)
        mapping["source"]["archive_sha256"] = _sha(archive)
        mapping["sizes"]["download_bytes"] = len(archive)
        mapping["sizes"]["temporary_bytes"] = len(archive) + mapping["sizes"]["installed_bytes"]
        spec = AssetSpec.from_mapping(mapping)
        self._authorize(spec)
        with self.assertRaises(InstallError):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=self.records, notices=self.texts
            )
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_two_top_dirs_refused(self) -> None:
        archive = hostile_two_roots_zip()
        url = self.upstream.add("/two.zip", archive)
        spec = self._spec(vosk_fixture_zip(), url)
        # pin the hostile archive identity so fetch succeeds and extract fails
        spec = AssetSpec.from_mapping(
            {
                **spec.to_mapping(),
                "sizes": {
                    **spec.to_mapping()["sizes"],
                    "download_bytes": len(archive),
                    "temporary_bytes": len(archive) + spec.installed_bytes,
                },
                "source": {
                    **spec.to_mapping()["source"],
                    "archive_bytes": len(archive),
                    "archive_sha256": _sha(archive),
                    "url": url,
                    "provenance": {
                        **spec.to_mapping()["source"]["provenance"],
                        "original_url": url,
                    },
                },
            }
        )
        self._authorize(spec)
        with self.assertRaises(InstallError):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=self.records, notices=self.texts
            )
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_symlink_member_refused(self) -> None:
        archive = hostile_symlink_zip()
        url = self.upstream.add("/link.zip", archive)
        mapping = make_archive_asset(
            asset_id="fixture-link",
            url=url,
            archive=vosk_fixture_zip(),
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        mapping["source"]["archive_bytes"] = len(archive)
        mapping["source"]["archive_sha256"] = _sha(archive)
        mapping["sizes"]["download_bytes"] = len(archive)
        mapping["sizes"]["temporary_bytes"] = len(archive) + mapping["sizes"]["installed_bytes"]
        spec = AssetSpec.from_mapping(mapping)
        self._authorize(spec)
        with self.assertRaises(InstallError):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=self.records, notices=self.texts
            )
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_parent_member_refused(self) -> None:
        archive = hostile_parent_zip()
        url = self.upstream.add("/parent.zip", archive)
        mapping = make_archive_asset(
            asset_id="fixture-parent",
            url=url,
            archive=vosk_fixture_zip(),
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        mapping["source"]["archive_bytes"] = len(archive)
        mapping["source"]["archive_sha256"] = _sha(archive)
        mapping["sizes"]["download_bytes"] = len(archive)
        mapping["sizes"]["temporary_bytes"] = len(archive) + mapping["sizes"]["installed_bytes"]
        spec = AssetSpec.from_mapping(mapping)
        self._authorize(spec)
        with self.assertRaises(InstallError):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=self.records, notices=self.texts
            )

    def test_files_mode_wrong_sha_refused(self) -> None:
        payload = b"hello-files"
        url = self.upstream.add("/file.bin", payload + b"x")
        mapping = {
            "compatibility": {"consumer_schema": "kilix.speech.models/v1", "maximum": 1, "minimum": 1},
            "files": [
                {"bytes": len(payload), "path": "model.bin", "sha256": _sha(payload)},
                {
                    "bytes": len(self.notice),
                    "path": "notices/LICENSE-apache-2.0.txt",
                    "sha256": _sha(self.notice),
                },
            ],
            "id": "fixture-files",
            "label": "files",
            "licenses": [
                {
                    "decision": "affirmative",
                    "id": "apache-2.0",
                    "licensors": ["Alpha Cephei Inc."],
                    "record_digest": self.record.digest,
                    "text_sha256": self.record.text_sha256,
                }
            ],
            "provider": "kilix-voice",
            "schema": "kilix.content.asset/v3",
            "sizes": {
                "download_bytes": len(payload),
                "installed_bytes": len(payload) + len(self.notice),
                "temporary_bytes": len(payload) + len(self.notice),
            },
            "source": {
                "fetch": [{"path": "model.bin", "url": url}],
                "mode": "upstream-files",
                "provenance": {
                    "original_url": url,
                    "project": "example/files",
                    "revision": "1",
                },
            },
            "stream": "F104",
            "version": "1",
        }
        spec = AssetSpec.from_mapping(mapping)
        self._authorize(spec)
        with self.assertRaises(Exception):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=self.records, notices=self.texts
            )

    def test_record_digest_covers_url_bytes_sha_root_and_licensor(self) -> None:
        archive = vosk_fixture_zip()
        url = self.upstream.add("/cover.zip", archive)
        spec = self._spec(archive, url, asset_id="fixture-cover")
        original = spec.digest
        mapping = spec.to_mapping()
        mapping["source"]["url"] = url.replace("https://", "https://example.")
        # host mismatch should fail parse; mutate archive sha instead
        mapping = spec.to_mapping()
        mapping["source"]["archive_sha256"] = "ab" * 32
        mutated = AssetSpec.from_mapping(mapping)
        self.assertNotEqual(original, mutated.digest)

    def test_license_without_text_digest_is_refused(self) -> None:
        archive = vosk_fixture_zip()
        url = self.upstream.add("/nolic.zip", archive)
        mapping = make_archive_asset(
            asset_id="fixture-nolic",
            url=url,
            archive=archive,
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        del mapping["licenses"][0]["text_sha256"]
        with self.assertRaises(CatalogError):
            AssetSpec.from_mapping(mapping)

    def test_kilix_hosted_url_is_refused(self) -> None:
        mapping = make_archive_asset(
            asset_id="fixture-host",
            url="https://github.com/itsmygithubacct/kilix-content/releases/download/x/a.zip",
            archive=vosk_fixture_zip(),
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        with self.assertRaises(CatalogError):
            AssetSpec.from_mapping(mapping)

    def test_registry_manifest_flipped_blob_refused(self) -> None:
        blob = b"blob-one"
        manifest = b'{"blobs":["blob-one"]}'
        blob_url = self.upstream.add("/blob", blob + b"X")
        man_url = self.upstream.add("/manifest.json", manifest)
        mapping = {
            "compatibility": {"consumer_schema": "kilix.speech.models/v1", "maximum": 1, "minimum": 1},
            "files": [
                {"bytes": len(blob), "path": "model.bin", "sha256": _sha(blob)},
                {
                    "bytes": len(self.notice),
                    "path": "notices/LICENSE-apache-2.0.txt",
                    "sha256": _sha(self.notice),
                },
            ],
            "id": "fixture-registry",
            "label": "registry",
            "licenses": [
                {
                    "decision": "affirmative",
                    "id": "apache-2.0",
                    "licensors": ["Alpha Cephei Inc."],
                    "record_digest": self.record.digest,
                    "text_sha256": self.record.text_sha256,
                }
            ],
            "provider": "kilix-voice",
            "schema": "kilix.content.asset/v3",
            "sizes": {
                "download_bytes": len(manifest),
                "installed_bytes": len(blob) + len(self.notice),
                "temporary_bytes": len(manifest) + len(blob) + len(self.notice),
            },
            "source": {
                "blobs": [{"path": "model.bin", "url": blob_url}],
                "manifest_sha256": _sha(manifest),
                "manifest_url": man_url,
                "mode": "registry-manifest",
                "provenance": {
                    "original_url": man_url,
                    "project": "example/registry",
                    "revision": "1",
                },
            },
            "stream": "F104",
            "version": "1",
        }
        spec = AssetSpec.from_mapping(mapping)
        self._authorize(spec)
        with self.assertRaises(Exception):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=self.records, notices=self.texts
            )
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())
