"""faster-whisper-large-v3: multilingual Whisper for Playalong, medium.en's MIT.

large-v3 has its own kilix-license record (owner determination 2026-11-08).
Its terms are faster-whisper-medium-en's: MIT, OpenAI weights, SYSTRAN
CTranslate2 conversion. Kilix Playalong offers it for lyrics that are not in
English; it is installed only after a yes on its first-use screen.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from kilix_license.catalog import load_determined_records, load_determined_texts

from fake_store import FakeStore
from kilix_content import default_catalog
from kilix_content.first_use import present_asset

ROOT = Path(__file__).resolve().parents[1]
ASSET_ID = "faster-whisper-large-v3"
RECORD_ID = "faster-whisper-large-v3"
MEDIUM_ID = "faster-whisper-medium-en"
REV = "edaa852ec7e145841d8ffdb056a99866b5f0a478"
MEMBERS = {
    "model.bin": (
        3_087_284_237,
        "69f74147e3334731bc3a76048724833325d2ec74642fb52620eda87352e3d4f1",
    ),
    "config.json": (
        2_394,
        "a9306624f5ec14270a014b647e5c316b6e03a662c369758d1b90697a7b0655b9",
    ),
    # large-v3 has 128 mel bins; faster-whisper reads them from this file.
    "preprocessor_config.json": (
        340,
        "7ccc62c6f2765af1f3b46c00c9b5894426835a05021c8b9c01eecb6dfb542711",
    ),
    "tokenizer.json": (
        2_480_617,
        "6d8cbd7cd0d8d5815e478dac67b85a26bbe77c1f5e0c6d76d1ce2abc0e5f21ca",
    ),
    "vocabulary.json": (
        1_068_114,
        "c69260f2ab26d659b7c398f9a2b2b48ed0df16c3b47d7326782fd9cba71690c1",
    ),
    "README.md": (
        2_052,
        "39e96252229f5a3d0141dc81afb65a36fd205461ac21e5b70f2cd1248ef0082c",
    ),
}
WHISPER_MIT_SHA256 = "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d"
DOWNLOAD_BYTES = sum(size for size, _digest in MEMBERS.values())


class WhisperLargeV3AssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()
        self.spec = self.catalog.require_asset(ASSET_ID)
        self.record = self.records.by_id(RECORD_ID)

    def test_asset_pins_the_large_v3_revision_for_playalong(self) -> None:
        spec = self.spec
        self.assertEqual(spec.source_mode, "upstream-files")
        # Its provider is Playalong, which puts it on the wizard's Playalong page.
        self.assertEqual(spec.provider, "kilix-playalong")
        self.assertEqual(spec.consumer_schema, "kilix.whisper.models/v1")
        self.assertEqual(spec.version, REV)
        self.assertEqual(spec.provenance_revision, REV)
        self.assertEqual(spec.provenance_project, "Systran/faster-whisper-large-v3")
        self.assertEqual(spec.source_host, "huggingface.co")
        self.assertEqual(spec.download_bytes, DOWNLOAD_BYTES)
        members = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
        self.assertEqual({path: (item.bytes, item.sha256) for path, item in members.items()}, MEMBERS)
        fetch = {item.path: item.url for item in spec.fetch}
        self.assertEqual(set(fetch), set(MEMBERS))
        for path, url in fetch.items():
            parsed = urlsplit(url)
            self.assertEqual((parsed.scheme, parsed.hostname), ("https", "huggingface.co"))
            self.assertEqual(
                parsed.path, f"/Systran/faster-whisper-large-v3/resolve/{REV}/{path}"
            )
        notices = [item for item in spec.files if item.path.startswith("notices/")]
        self.assertEqual(
            [(item.path, item.sha256) for item in notices],
            [("notices/LICENSE-mit.txt", WHISPER_MIT_SHA256)],
        )
        pin = json.loads((ROOT / "tools/upstream-pins" / f"{ASSET_ID}.json").read_text(encoding="utf-8"))
        self.assertEqual(pin["license_record_id"], RECORD_ID)
        self.assertNotIn("destination", pin)
        self.assertEqual({member["path"]: (member["bytes"], member["sha256"]) for member in pin["members"]}, MEMBERS)
        self.assertNotIn("itsmygithubacct", str(spec.to_mapping()).lower())

    def test_licence_row_cites_its_own_record_with_medium_english_terms(self) -> None:
        medium = self.records.by_id(MEDIUM_ID)
        self.assertNotEqual(self.record.digest, medium.digest)
        self.assertEqual(
            (self.record.licence_ids, self.record.text_sha256, self.record.licensor),
            (medium.licence_ids, medium.text_sha256, medium.licensor),
        )
        self.assertEqual(len(self.spec.licenses), 1)
        row = self.spec.licenses[0]
        self.assertEqual(row.license_id, "mit")
        self.assertEqual(row.decision, "affirmative")
        self.assertEqual(row.licensors, ("OpenAI", "SYSTRAN"))
        self.assertEqual(row.record_digest, self.record.digest)
        self.assertEqual(row.text_sha256, WHISPER_MIT_SHA256)
        # medium.en's own row is untouched by this asset.
        medium_rows = self.catalog.require_asset(MEDIUM_ID).licenses
        self.assertEqual([r.record_digest for r in medium_rows], [medium.digest])

    def test_first_use_screen_names_large_v3_and_the_shared_mit_text(self) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-whisper-large-v3-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(
            self.spec, self.record, texts,
            receipts=FakeStore(scratch / "receipts"), records=self.records,
        ).decode("utf-8")
        self.assertIn(f"id: {ASSET_ID}", screen)
        self.assertIn(f"/Systran/faster-whisper-large-v3/resolve/{REV}/", screen)
        self.assertIn("host: huggingface.co", screen)
        self.assertIn(f"bytes: {DOWNLOAD_BYTES}", screen)
        self.assertIn("licence: mit", screen)
        self.assertIn("licensors: OpenAI, SYSTRAN", screen)
        self.assertIn("Copyright (c) 2022 OpenAI", screen)


if __name__ == "__main__":
    unittest.main()
