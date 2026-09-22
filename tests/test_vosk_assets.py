from __future__ import annotations

import hashlib
import io
import unittest

from kilix_license.agreement import typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts

from fake_store import FakeStore
from kilix_content import default_catalog
from kilix_content.first_use import present_asset
from kilix_content.model import AssetSpec
from kilix_content.receipt import (
    _CATALOG_SHA256,
    catalog_sha256,
    verify_packaged_catalog,
)


class VoskAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_vosk_speech_assets_are_upstream_sourced_with_licensors(self) -> None:
        small = self.catalog.require_asset("vosk-model-small-en-us-0.15")
        lgraph = self.catalog.require_asset("vosk-model-en-us-0.22-lgraph")
        self.assertEqual(small.source_mode, "upstream-archive")
        self.assertEqual(lgraph.source_mode, "upstream-archive")
        self.assertEqual(small.source_host, "alphacephei.com")
        self.assertEqual(lgraph.source_host, "alphacephei.com")
        self.assertEqual(
            small.archive_sha256,
            "30f26242c4eb449f948e42cb302dd7a686cb29a3423a8367f99ff41780942498",
        )
        self.assertEqual(small.archive_bytes, 41205931)
        self.assertEqual(
            lgraph.archive_sha256,
            "d9838b4aaa82a75c4a17f5aca300eaca129aaab2a7cbf951bafbb500eb9c4334",
        )
        self.assertEqual(lgraph.archive_bytes, 130557655)
        self.assertEqual(small.provider, "kilix-voice")
        self.assertEqual(small.stream, "F104")
        self.assertEqual(small.consumer_schema, "kilix.speech.models/v1")
        self.assertTrue(small.licenses[0].licensors)
        self.assertEqual(small.licenses[0].licensors, ("Alpha Cephei Inc.",))
        self.assertEqual(lgraph.licenses[0].licensors, ("Appen", "Alpha Cephei"))
        for spec in (small, lgraph):
            notice = next(item for item in spec.files if item.path.startswith("notices/"))
            self.assertEqual(spec.licenses[0].text_sha256, notice.sha256)
            packed = spec.to_mapping()
            self.assertNotIn("itsmygithubacct", str(packed))
            self.assertEqual(spec.licenses[0].record_digest, self.records.by_id(
                "small-en-us" if spec is small else "lgraph-en-us"
            ).digest)

    def test_no_packaged_asset_source_url_is_kilix_hosted(self) -> None:
        for spec in self.catalog.assets:
            packed = spec.to_mapping()
            self.assertNotIn("itsmygithubacct", str(packed).lower())
            self.assertNotIn("assets-0.2.2-candidate", str(packed))

    def test_catalog_sha_matches_packaged_bytes(self) -> None:
        verify_packaged_catalog()
        self.assertEqual(catalog_sha256(), _CATALOG_SHA256)

    def test_first_use_screen_names_model_url_bytes_licence(self) -> None:
        spec = self.catalog.require_asset("vosk-model-small-en-us-0.15")
        record = self.records.by_id("small-en-us")
        texts = load_determined_texts(self._scratch_texts())
        store = FakeStore(self._scratch_texts() / "receipts")
        screen = present_asset(
            spec, record, texts, receipts=store, records=self.records
        ).decode("utf-8")
        self.assertIn("vosk-model-small-en-us-0.15", screen)
        self.assertIn("alphacephei.com", screen)
        self.assertIn("41205931", screen)
        self.assertIn("apache-2.0", screen)
        self.assertIn("Alpha Cephei Inc.", screen)
        self.assertIn(typed_agreement_line(record).split(" from ")[1], screen)

    def test_not_preinstalled(self) -> None:
        from kilix_content.install import Installer
        import tempfile

        installer = Installer(tempfile.mkdtemp(prefix="kilix-content-empty-"))
        spec = self.catalog.require_asset("vosk-model-small-en-us-0.15")
        self.assertIsNone(installer._asset_integrity_ready(spec))

    def _scratch_texts(self):
        import tempfile
        from pathlib import Path

        return Path(tempfile.mkdtemp(prefix="kilix-content-texts-"))
