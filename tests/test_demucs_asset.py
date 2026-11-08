"""demucs-htdemucs-6s: the separator kilix split runs, behind its own record.

The owner asked on 2026-11-08 to route kilix split through kilix-license. The
asset is Meta's unchanged htdemucs_6s weights file, exactly as adefossez/demucs
eeac1d15 names it, under that repository's MIT licence. htdemucs_6s.yaml names
that one model with default weights, so it is not installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import kilix_content as api
import kilix_license as lic
from kilix_license.catalog import load_determined_records, load_determined_texts

from fake_store import FakeStore
from kilix_content.first_use import present_asset

ROOT = Path(__file__).resolve().parents[1]
ASSET_ID = "demucs-htdemucs-6s"
REV = "eeac1d15891af95b1288d2884b95baa3e5baa96c"
WEIGHTS = "models/5c90dfd2-34c22ccb.th"
MEMBERS = {
    WEIGHTS: (54_996_327, "34c22ccb381c6f9fdbf324f04e1e2fe21aaaf293f5ded163a162697ff9a02ddd"),
}
URLS = {
    WEIGHTS: "https://dl.fbaipublicfiles.com/demucs/hybrid_transformer/5c90dfd2-34c22ccb.th",
}
META_MIT_SHA256 = "cf9b17822d1fcd4ff32ccbe14183386fb3adf6f2ff92dc184130823f7fc28173"


class DemucsAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = api.verified_packaged_catalog()
        self.records = load_determined_records()
        self.spec = self.catalog.require_asset(ASSET_ID)
        self.record = self.records.by_id(ASSET_ID)

    def test_asset_pins_metas_weights_file(self) -> None:
        spec = self.spec
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-split")
        self.assertEqual(spec.consumer_schema, "kilix.split.demucs/v1")
        self.assertEqual(spec.version, REV)
        self.assertEqual(spec.provenance_revision, REV)
        self.assertEqual(spec.provenance_project, "adefossez/demucs")
        self.assertEqual(spec.download_bytes, 54_996_327)
        self.assertEqual(spec.source_host, "dl.fbaipublicfiles.com")
        members = {item.path: (item.bytes, item.sha256) for item in spec.files
                   if not item.path.startswith("notices/")}
        self.assertEqual(members, MEMBERS)
        # Demucs checks a .th file against the sha256 prefix in its name.
        self.assertTrue(MEMBERS[WEIGHTS][1].startswith(WEIGHTS.split("-")[-1][:-3]))
        self.assertEqual({item.path: item.url for item in spec.fetch}, URLS)
        for url in URLS.values():
            self.assertEqual(urlsplit(url).scheme, "https")
            self.assertNotIn("huggingface.co", url)
        notices = [(item.path, item.sha256) for item in spec.files if item.path.startswith("notices/")]
        self.assertEqual(notices, [("notices/LICENSE-mit.txt", META_MIT_SHA256)])
        pin = json.loads((ROOT / "tools/upstream-pins" / f"{ASSET_ID}.json").read_text(encoding="utf-8"))
        self.assertEqual(pin["license_record_id"], ASSET_ID)
        self.assertNotIn("itsmygithubacct", str(spec.to_mapping()).lower())

    def test_licence_row_cites_its_own_record(self) -> None:
        self.assertEqual(len(self.spec.licenses), 1)
        row = self.spec.licenses[0]
        self.assertEqual(row.license_id, "mit")
        self.assertEqual(row.decision, "affirmative")
        self.assertEqual(row.licensors, ("Meta Platforms, Inc. and affiliates",))
        self.assertEqual(row.record_digest, self.record.digest)
        self.assertEqual(row.text_sha256, META_MIT_SHA256)
        self.assertEqual(self.record.licensor, "Meta Platforms, Inc. and affiliates")
        self.assertTrue(lic.standard_policy_eligible(self.record))

    def test_first_use_screen_names_the_host_and_metas_mit_text(self) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-demucs-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(
            self.spec, self.record, texts,
            receipts=FakeStore(scratch / "receipts"), records=self.records,
        ).decode("utf-8")
        self.assertIn(f"id: {ASSET_ID}", screen)
        self.assertIn("host: dl.fbaipublicfiles.com", screen)
        self.assertIn("/demucs/hybrid_transformer/5c90dfd2-34c22ccb.th", screen)
        self.assertIn("licence: mit", screen)
        self.assertIn("licensors: Meta Platforms, Inc. and affiliates", screen)
        self.assertIn("Copyright (c) Meta Platforms, Inc. and affiliates.", screen)

    @unittest.skipUnless(os.environ.get("DEMUCS_SUPPLIED_DIR"),
                         "the exact upstream weights file is not provided")
    def test_real_supplied_bytes_need_a_receipt_and_install_exactly(self) -> None:
        source = Path(os.environ["DEMUCS_SUPPLIED_DIR"])
        for path, (size, digest) in MEMBERS.items():
            raw = (source / path).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest), path)
        texts_root = Path(tempfile.mkdtemp(prefix="kilix-content-demucs-texts-"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = lic.ReceiptStore(root / "receipts")
            texts = lic.load_determined_texts(texts_root)
            installer = api.Installer(str(root / "apps"))
            with self.assertRaises(lic.CoverageRefused):
                installer.ensure_supplied_asset(self.spec, supplied=source, store=store,
                                                records=self.records, notices=texts)
            self.assertFalse(Path(installer.asset_destination(self.spec)).exists())
            agreement = lic.capture_standard_policy(self.record)
            self.assertIsNone(agreement.typed_text)
            from kilix_content.receipt import catalog_sha256, release_digest
            receipt = lic.receipt_from_agreement(
                self.record, agreement, manifest_digest=self.spec.manifest_digest,
                catalogue_digest=catalog_sha256(), release_digest=release_digest())
            store.write(receipt)
            lic.require(lic.AssetRef(ASSET_ID, self.record.digest, self.spec.manifest_digest),
                        records=self.records, store=store)
            with self.assertRaises(lic.CoverageRefused):
                lic.require(lic.AssetRef(ASSET_ID, self.record.digest, "0" * 64),
                            records=self.records, store=store)
            installer.ensure_supplied_asset(self.spec, supplied=source, store=store,
                                            records=self.records, notices=texts)
            installed = Path(installer.asset_destination(self.spec))
            self.assertEqual(installed.name, ASSET_ID)
            for item in self.spec.files:
                content = (installed / item.path).read_bytes()
                self.assertEqual((len(content), hashlib.sha256(content).hexdigest()),
                                 (item.bytes, item.sha256), item.path)
            wrong = root / "wrong"
            (wrong / "models").mkdir(parents=True)
            (wrong / WEIGHTS).write_bytes(b"not the weights")
            other = api.Installer(str(root / "other-apps"))
            with self.assertRaises(api.InstallError):
                other.ensure_supplied_asset(self.spec, supplied=wrong, store=store,
                                            records=self.records, notices=texts)
            self.assertFalse(Path(other.asset_destination(self.spec)).exists())


if __name__ == "__main__":
    unittest.main()
