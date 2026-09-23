"""Pocket CPU source pin, catalog, and first-use screen contracts."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit

from fake_store import FakeStore
from kilix_content import default_catalog
from kilix_content.first_use import present_asset
from kilix_license.catalog import load_determined_records, load_determined_texts

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "tools/upstream-pins/pocket-tts-english-python-alba.json"
CONVERT = ROOT / "tools/upstream-pins/pocket-tts-english-q8_0.json"
REVISION = "d29db7978e464fb90cb3359ee0c69a273b9142cc"


class PocketPythonPinTests(unittest.TestCase):
    def test_pin_is_complete_and_distinct_from_native_conversion(self):
        pin = json.loads(PIN.read_text(encoding="utf-8"))
        native = json.loads(CONVERT.read_text(encoding="utf-8"))
        self.assertEqual(pin["id"], "pocket-tts-english-python-alba")
        self.assertEqual(pin["mode"], "upstream-files")
        self.assertEqual(pin["provider"], "kilix-voice")
        self.assertEqual(pin["license_record_id"], pin["id"])
        self.assertNotEqual(pin["license_record_id"], native["license_record_id"])
        self.assertEqual(pin["version"], REVISION)
        members = {item["path"]: item for item in pin["members"]}
        self.assertEqual(set(members), {
            "model/README.md", "model/model.safetensors",
            "model/tokenizer.model", "model/embeddings/alba.safetensors"})
        self.assertEqual(members["model/model.safetensors"]["sha256"],
                         native["input"]["sha256"])
        self.assertEqual(members["model/tokenizer.model"]["sha256"],
                         native["members"][1]["sha256"])
        self.assertEqual(members["model/embeddings/alba.safetensors"]["sha256"],
                         "e4a323e8e771f14fd669428d83e7af6d83b4d6d0f0e282c30122f04824f17b1c")
        for item in members.values():
            self.assertGreater(item["bytes"], 0)
            self.assertEqual(len(item["sha256"]), 64)
            url = urlsplit(item["url"])
            self.assertEqual(url.scheme, "https")
            self.assertEqual(url.hostname, "huggingface.co")
            self.assertIn(f"/resolve/{REVISION}/", url.path)

    def test_catalog_screen_binds_new_record_and_shows_alba(self):
        catalog = default_catalog()
        spec = catalog.require_asset("pocket-tts-english-python-alba")
        old = catalog.require_asset("pocket-tts-english-q8_0")
        records = load_determined_records()
        record = records.by_id(spec.asset_id)
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.licenses[0].record_digest, record.digest)
        self.assertNotEqual(spec.licenses[0].record_digest,
                            old.licenses[0].record_digest)
        self.assertEqual(spec.consumer_schema, "kilix.speech.models/v1")
        self.assertEqual(spec.download_bytes, 225294146)
        with tempfile.TemporaryDirectory(prefix="pocket-content-screen-") as scratch:
            root = Path(scratch)
            screen = present_asset(spec, record, load_determined_texts(root / "texts"),
                                   receipts=FakeStore(root / "receipts"),
                                   records=records).decode("utf-8")
        self.assertIn("id: pocket-tts-english-python-alba", screen)
        self.assertIn("Characters voice-acted by Alba MacKenna:", screen)
        self.assertIn("Released under the CC BY 4.0 licence.", screen)
        self.assertIn("binding:pocket-prohibited-use", screen)


if __name__ == "__main__":
    unittest.main()
