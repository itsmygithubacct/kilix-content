"""faster-whisper-medium-en: English-only Whisper medium, same MIT as small.

Medium is a second model, not a new licence. The pin reuses the
faster-whisper-small-en determination (OpenAI weights, SYSTRAN CTranslate2
conversion), so the vendored licence records and their digests stay put.
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
ASSET_ID = "faster-whisper-medium-en"
RECORD_ID = "faster-whisper-small-en"
REV = "a29b04bd15381511a9af671baec01072039215e3"
MEMBERS = {
    "model.bin": (
        1_527_904_330,
        "11b220779aea4c6f3ce9d2549c8a95ea869ed84066864b999531ef53e594fe5b",
    ),
    "config.json": (
        2_643,
        "4a1848ebabe7938d9797c15a2e8e4ce1d36e6fd4a43d096ae5955257c67c7962",
    ),
    "tokenizer.json": (
        2_128_466,
        "929c5252409436dce1b38a75d1abbcb5e132d170d8e324e4e04ed915fa2d22df",
    ),
    "vocabulary.txt": (
        422_309,
        "ff77588746d3a2595d32ab5b69ffd7b95ce2441ac57533cb66fc3eb575a115cf",
    ),
    "README.md": (
        1_337,
        "ab3ddd3b6af4ea0ef353cb80004f26613ba33217f81652fc13738d3b098c7675",
    ),
}
WHISPER_MIT_SHA256 = "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d"
VOICE_STORE = "$KILIX_DATA_HOME/voice/models/whisper-medium-en"
DOWNLOAD_BYTES = 1_530_459_085


class WhisperMediumAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()
        self.spec = self.catalog.require_asset(ASSET_ID)
        self.record = self.records.by_id(RECORD_ID)

    def test_asset_pins_the_english_medium_revision(self) -> None:
        spec = self.spec
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-whisper-stt")
        self.assertEqual(spec.consumer_schema, "kilix.whisper.models/v1")
        self.assertEqual(spec.version, REV)
        self.assertEqual(spec.provenance_revision, REV)
        self.assertEqual(spec.provenance_project, "Systran/faster-whisper-medium.en")
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
                parsed.path, f"/Systran/faster-whisper-medium.en/resolve/{REV}/{path}"
            )
        notices = [item for item in spec.files if item.path.startswith("notices/")]
        self.assertEqual(
            [(item.path, item.sha256) for item in notices],
            [("notices/LICENSE-mit.txt", WHISPER_MIT_SHA256)],
        )
        pin = json.loads((ROOT / "tools/upstream-pins" / f"{ASSET_ID}.json").read_text(encoding="utf-8"))
        self.assertEqual(pin["license_record_id"], RECORD_ID)
        self.assertEqual(pin["destination"], VOICE_STORE)
        self.assertEqual({member["path"]: (member["bytes"], member["sha256"]) for member in pin["members"]}, MEMBERS)
        packed = str(spec.to_mapping()).lower()
        self.assertNotIn("itsmygithubacct", packed)
        small = self.catalog.require_asset(RECORD_ID)
        self.assertEqual(small.download_bytes, 486_100_128)
        self.assertEqual(small.provenance_revision, "d1d751a5f8271d482d14ca55d9e2deeebbae577f")

    def test_licence_row_reuses_the_small_english_record(self) -> None:
        with self.assertRaises(KeyError):
            self.records.by_id(ASSET_ID)
        self.assertEqual(len(self.spec.licenses), 1)
        row = self.spec.licenses[0]
        self.assertEqual(row.license_id, "mit")
        self.assertEqual(row.decision, "affirmative")
        self.assertEqual(row.licensors, ("OpenAI", "SYSTRAN"))
        self.assertEqual(row.record_digest, self.record.digest)
        self.assertEqual(row.text_sha256, WHISPER_MIT_SHA256)
        self.assertEqual(self.record.licensor, "OpenAI; SYSTRAN")

    def test_first_use_screen_names_medium_and_the_shared_mit_text(self) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-whisper-medium-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(
            self.spec, self.record, texts,
            receipts=FakeStore(scratch / "receipts"), records=self.records,
        ).decode("utf-8")
        self.assertIn(f"id: {ASSET_ID}", screen)
        self.assertIn(f"/Systran/faster-whisper-medium.en/resolve/{REV}/", screen)
        self.assertIn("host: huggingface.co", screen)
        self.assertIn(f"bytes: {DOWNLOAD_BYTES}", screen)
        self.assertIn("licence: mit", screen)
        self.assertIn("licensors: OpenAI, SYSTRAN", screen)
        self.assertIn("Copyright (c) 2022 OpenAI", screen)


if __name__ == "__main__":
    unittest.main()
