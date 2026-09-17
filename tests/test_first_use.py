from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from kilix_license.agreement import typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts

from fake_store import FakeStore
from first_use_fixture import FakeUpstream, make_archive_asset, vosk_fixture_zip
from kilix_content.first_use import install_with_agreement
from kilix_content.install import Installer
from kilix_content.model import AssetSpec


class FirstUseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-first-use-"))
        self.upstream = FakeUpstream()
        self.records = load_determined_records()
        self.texts = load_determined_texts(self.scratch / "texts")
        self.notice = self.texts.get(self.records.by_id("small-en-us").text_sha256)
        self.store = FakeStore(self.scratch / "receipts")
        self.installer = Installer(str(self.scratch / "root"))
        self.archive = vosk_fixture_zip()
        self.url = self.upstream.add("/model.zip", self.archive)
        mapping = make_archive_asset(
            asset_id="fixture-first-use",
            url=self.url,
            archive=self.archive,
            root="vosk-model-small-en-us-0.15",
            license_record=self.records.by_id("small-en-us"),
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        self.spec = AssetSpec.from_mapping(mapping)
        self.record = self.records.by_id("small-en-us")

    def tearDown(self) -> None:
        self.upstream.close()

    def test_decline_writes_nothing(self) -> None:
        screen = io.BytesIO()
        result = install_with_agreement(
            self.spec,
            installer=self.installer,
            store=self.store,
            records=self.records,
            texts=self.texts,
            typed_text=None,
            screen=screen,
            decline=True,
        )
        self.assertIsNone(result)
        self.assertEqual(list(self.store.root.glob("*.json")), [])
        self.assertEqual(self.upstream.requests(), [])
        self.assertFalse(Path(self.installer.asset_destination(self.spec)).exists())
        self.assertIn(self.spec.asset_id.encode(), screen.getvalue())

    def test_accept_downloads_and_records_one_receipt(self) -> None:
        screen = io.BytesIO()
        result = install_with_agreement(
            self.spec,
            installer=self.installer,
            store=self.store,
            records=self.records,
            texts=self.texts,
            typed_text=typed_agreement_line(self.record),
            screen=screen,
        )
        self.assertIsNotNone(result)
        receipts = list(self.store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        hosts = {item.get("path") for item in self.upstream.requests()}
        self.assertIn("/model.zip", hosts)
        self.assertTrue(Path(result[0], "notices/LICENSE-apache-2.0.txt").is_file())
        self.assertIn(b"Alpha Cephei Inc.", screen.getvalue())
