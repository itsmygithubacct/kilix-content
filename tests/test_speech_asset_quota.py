"""Quota failure and in-use removal for one selected catalog speech asset.

Both checks are fixture injections. Neither creates a quota mount, starts
a guest, nor writes a production receipt. A passing result here is not
guest acceptance.
"""

from __future__ import annotations

import errno
import fcntl
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.receipts import receipt_from_agreement

from fake_store import FakeStore
from first_use_fixture import make_files_asset
from kilix_content.install import InstallError, Installer, SuppliedFile
from kilix_content.model import AssetSpec
from kilix_content.receipt import _CATALOG_SHA256, release_digest

HOST = "https://models.example.test"


class SpeechAssetQuotaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-speech-quota-"))
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.records = load_determined_records()
        self.texts = load_determined_texts(self.scratch / "texts")
        self.record = self.records.by_id("small-en-us")
        self.notice = self.texts.get(self.record.text_sha256)
        self.store = FakeStore(self.scratch / "receipts")
        self.installer = Installer(str(self.scratch / "root"))
        self.sentinel = self.scratch / "root" / "user-data" / "sentinel"
        self.sentinel.parent.mkdir(parents=True)
        self.sentinel.write_bytes(b"keep-me")

    def files_asset(
        self, asset_id: str, marker: bytes = b""
    ) -> tuple[AssetSpec, dict[str, bytes]]:
        payloads = {
            "model.bin": b"weights-are-fixture-bytes" + marker,
            "config.json": b"{}\n",
        }
        mapping = make_files_asset(
            asset_id=asset_id,
            files={
                path: (f"{HOST}/{asset_id}/{path}", payload)
                for path, payload in payloads.items()
            },
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        spec = AssetSpec.from_mapping(mapping)
        self.assertEqual(spec.consumer_schema, "kilix.speech.models/v1")
        self.assertEqual(spec.stream, "F104")
        return spec, payloads

    def supply(self, name: str, payloads: dict[str, bytes]) -> Path:
        root = self.scratch / "supplied" / name
        for path, payload in payloads.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return root

    def authorize(self, spec: AssetSpec) -> None:
        agreement = capture_agreement(self.record, typed_agreement_line(self.record))
        self.store.write(
            receipt_from_agreement(
                self.record,
                agreement,
                manifest_digest=spec.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        )

    def install(self, asset_id: str, marker: bytes = b"") -> tuple[AssetSpec, dict[str, bytes]]:
        spec, payloads = self.files_asset(asset_id, marker)
        self.authorize(spec)
        self.installer.ensure_supplied_asset(
            spec,
            supplied=self.supply(asset_id, payloads),
            store=self.store,
            records=self.records,
            notices=self.texts,
        )
        return spec, payloads

    def assert_no_stage(self) -> None:
        root = Path(self.installer.root)
        staged = [
            path
            for path in root.rglob("*")
            if path.name.startswith(".asset-install-")
        ]
        self.assertEqual(staged, [])

    def assert_kept(self, spec: AssetSpec, payloads: dict[str, bytes]) -> None:
        root = Path(self.installer.asset_destination(spec))
        self.assertEqual((root / "model.bin").read_bytes(), payloads["model.bin"])
        self.assertEqual((root / "config.json").read_bytes(), payloads["config.json"])
        self.assertEqual(self.sentinel.read_bytes(), b"keep-me")
        self.assert_no_stage()

    def test_injected_edquot_leaves_no_stage_and_keeps_the_selection(self) -> None:
        kept, kept_bytes = self.install("kept-speech", b"-kept")
        quota, _quota_bytes = self.files_asset("quota-speech", b"-quota")
        self.authorize(quota)
        supplied = self.supply("quota-speech", _quota_bytes)
        exhausted = OSError(errno.EDQUOT, "Disk quota exceeded")
        self.assertEqual(exhausted.errno, 122)

        with mock.patch(
            "kilix_content.install.tempfile.mkdtemp", side_effect=exhausted
        ):
            with self.assertRaises(InstallError) as caught:
                self.installer.ensure_supplied_asset(
                    quota,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        self.assertIn("staging directory", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertEqual(caught.exception.__cause__.errno, errno.EDQUOT)
        self.assertFalse(Path(self.installer.asset_destination(quota)).exists())
        self.assert_kept(kept, kept_bytes)

        def fail_quota(_self: SuppliedFile, _target: str) -> None:
            raise OSError(errno.EDQUOT, "Disk quota exceeded")

        with mock.patch.object(SuppliedFile, "copy_to", fail_quota):
            with self.assertRaises(InstallError) as caught:
                self.installer.ensure_supplied_asset(
                    quota,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        self.assertIn("asset installation failed", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertEqual(caught.exception.__cause__.errno, errno.EDQUOT)
        self.assertFalse(Path(self.installer.asset_destination(quota)).exists())
        self.assert_kept(kept, kept_bytes)

    def test_runtime_hold_refuses_removal_of_the_selected_speech_asset(self) -> None:
        kept, kept_bytes = self.install("kept-speech", b"-kept")
        held, held_bytes = self.install("held-speech", b"-held")
        destination = self.installer.asset_destination(held)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        holder = os.open(destination, flags)
        try:
            fcntl.flock(holder, fcntl.LOCK_SH | fcntl.LOCK_NB)

            with self.assertRaises(InstallError) as caught:
                self.installer.remove_selected_asset(held)
            self.assertIn("in use", str(caught.exception))
            self.assert_kept(held, held_bytes)
            self.assert_kept(kept, kept_bytes)

            self.installer.remove_selected_asset(kept)
            self.assertFalse(Path(self.installer.asset_destination(kept)).exists())
            self.assert_kept(held, held_bytes)
        finally:
            os.close(holder)
        self.installer.remove_selected_asset(held)
        self.assertFalse(Path(destination).exists())
        self.assertFalse(Path(destination).is_symlink())
        self.assertEqual(self.sentinel.read_bytes(), b"keep-me")
        self.assert_no_stage()

    def test_removal_does_not_follow_a_symlink(self) -> None:
        spec, _payloads = self.files_asset("linked-speech")
        destination = Path(self.installer.asset_destination(spec))
        destination.parent.mkdir(parents=True)
        outside = self.scratch / "outside-tree"
        outside.mkdir()
        secret = outside / "secret"
        secret.write_bytes(b"secret")
        destination.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(InstallError) as caught:
            self.installer.remove_selected_asset(spec)
        self.assertIn("not a directory", str(caught.exception))
        self.assertTrue(destination.is_symlink())
        self.assertEqual(secret.read_bytes(), b"secret")
        self.assertEqual(self.sentinel.read_bytes(), b"keep-me")
        self.assert_no_stage()
