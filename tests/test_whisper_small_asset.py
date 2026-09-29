"""faster-whisper-small-en: the default Kilix dictation model on capable hardware.

Owner determination 2026-09-29: MIT, licensors OpenAI (weights) and SYSTRAN
(CTranslate2 conversion), the Whisper model card caution as an advisory,
downloaded on first use from the pinned upstream revision.
"""

from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from kilix_license.agreement import typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.receipts import parse_receipt_bytes

from fake_store import FakeStore
from first_use_fixture import FakeUpstream, make_files_asset
from kilix_content import default_catalog
from kilix_content.first_use import install_with_agreement, present_asset
from kilix_content.install import Installer
from kilix_content.model import AssetSpec

ROOT = Path(__file__).resolve().parents[1]
ASSET_ID = "faster-whisper-small-en"
REV = "d1d751a5f8271d482d14ca55d9e2deeebbae577f"
# Typed from the Hugging Face LFS oids and git blob ids at REV, not read back
# from the pin: a drifted pin must fail here.
MEMBERS = {
    "model.bin": (
        483_545_366,
        "62b2a45b05ee59acb4a5341b33ee35e041395d378d418a18acfe4c9e768ee37a",
    ),
    "config.json": (
        2_657,
        "666a9605530ac1f61fa8177f3702b4dacec9966749e42610839fcc32661d5fae",
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
        1_330,
        "c87ff776137c2ecb30ee3b324b4cf5f38abf9423464613641ee45430bf580851",
    ),
}
WHISPER_MIT_SHA256 = "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d"
CAUTION_SHA256 = "0e9d0d19fa02b8f246d9902d93a2b0b0fac7cb07a518257ffa7d102d1c37c638"
VOICE_STORE = "$KILIX_DATA_HOME/voice/models/whisper-small-en"


class WhisperSmallAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()
        self.spec = self.catalog.require_asset(ASSET_ID)
        self.record = self.records.by_id(ASSET_ID)

    def test_asset_pins_the_systran_revision_and_every_member(self) -> None:
        spec = self.spec
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-whisper-stt")
        self.assertEqual(spec.consumer_schema, "kilix.whisper.models/v1")
        self.assertEqual(spec.stream, "F104")
        self.assertEqual(spec.version, REV)
        self.assertEqual(spec.provenance_revision, REV)
        self.assertEqual(spec.provenance_project, "Systran/faster-whisper-small.en")
        self.assertEqual(spec.source_host, "huggingface.co")
        self.assertEqual(spec.download_bytes, 486_100_128)
        members = {i.path: i for i in spec.files if not i.path.startswith("notices/")}
        self.assertEqual({p: (i.bytes, i.sha256) for p, i in members.items()}, MEMBERS)
        fetch = {item.path: item.url for item in spec.fetch}
        self.assertEqual(set(fetch), set(MEMBERS))
        for path, url in fetch.items():
            parsed = urlsplit(url)
            self.assertEqual((parsed.scheme, parsed.hostname), ("https", "huggingface.co"))
            self.assertEqual(
                parsed.path, f"/Systran/faster-whisper-small.en/resolve/{REV}/{path}"
            )
        notices = [i for i in spec.files if i.path.startswith("notices/")]
        self.assertEqual([(i.path, i.sha256) for i in notices],
                         [("notices/LICENSE-mit.txt", WHISPER_MIT_SHA256)])
        pin = json.loads(
            (ROOT / "tools/upstream-pins" / f"{ASSET_ID}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(pin["destination"], VOICE_STORE)
        self.assertEqual(
            {m["path"]: (m["bytes"], m["sha256"]) for m in pin["members"]}, MEMBERS
        )
        packed = str(spec.to_mapping()).lower()
        self.assertNotIn("itsmygithubacct", packed)
        self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_licence_row_binds_the_record_and_names_both_licensors(self) -> None:
        self.assertEqual(len(self.spec.licenses), 1)
        row = self.spec.licenses[0]
        self.assertEqual(row.license_id, "mit")
        self.assertEqual(row.decision, "affirmative")
        self.assertEqual(row.licensors, ("OpenAI", "SYSTRAN"))
        self.assertEqual(row.record_digest, self.record.digest)
        self.assertEqual(row.text_sha256, WHISPER_MIT_SHA256)
        self.assertEqual(self.record.licensor, "OpenAI; SYSTRAN")
        self.assertEqual(
            [(a.id, a.text_sha256) for a in self.record.advisories],
            [("whisper-card-caution", CAUTION_SHA256)],
        )
        self.assertEqual(self.record.binding_conditions, ())

    def test_first_use_screen_and_receipt(self) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-whisper-small-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(
            self.spec, self.record, texts,
            receipts=FakeStore(scratch / "receipts"), records=self.records,
        ).decode("utf-8")
        self.assertIn(f"id: {ASSET_ID}", screen)
        self.assertIn(f"/Systran/faster-whisper-small.en/resolve/{REV}/", screen)
        self.assertIn("host: huggingface.co", screen)
        self.assertIn("bytes: 486100128", screen)
        self.assertIn("licence: mit", screen)
        self.assertIn("licensors: OpenAI, SYSTRAN", screen)
        self.assertIn("decision: affirmative", screen)
        self.assertIn("Copyright (c) 2022 OpenAI", screen)
        self.assertIn("we caution against using Whisper models to transcribe recordings",
                      screen)

        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        payloads = {"model.bin": b"ct2-stub", "config.json": b"{}\n",
                    "tokenizer.json": b"{}\n", "vocabulary.txt": b"a\n"}
        files = {path: (upstream.add(f"/{path}", body), body) for path, body in payloads.items()}
        fixture = AssetSpec.from_mapping(make_files_asset(
            asset_id="fixture-whisper-small", files=files, license_record=self.record,
            notice=texts.get(self.record.text_sha256), licensors=["OpenAI", "SYSTRAN"],
            provider="kilix-whisper-stt", consumer_schema="kilix.whisper.models/v1",
            notice_path="notices/LICENSE-mit.txt", license_id="mit",
        ))
        declined = install_with_agreement(
            fixture, installer=installer, store=store, records=self.records, texts=texts,
            typed_text=None, screen=io.BytesIO(), decline=True,
        )
        self.assertIsNone(declined)
        self.assertEqual(list(store.root.glob("*.json")), [])
        self.assertEqual(upstream.requests(), [])
        self.assertFalse(Path(installer.asset_destination(fixture)).exists())

        result = install_with_agreement(
            fixture, installer=installer, store=store, records=self.records, texts=texts,
            typed_text=typed_agreement_line(self.record), screen=io.BytesIO(),
        )
        self.assertIsNotNone(result)
        receipts = list(store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = parse_receipt_bytes(receipts[0].read_bytes())
        self.assertEqual(receipt.decision, "accept")
        self.assertEqual(receipt.licensor, "OpenAI; SYSTRAN")
        self.assertEqual(receipt.record_digest, self.record.digest)
        self.assertEqual(receipt.advisory_digests, {"whisper-card-caution": CAUTION_SHA256})
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["licence_text_digest"], WHISPER_MIT_SHA256)
        self.assertNotIn(CAUTION_SHA256, payload["binding_condition_text_digests"].values())
        # kilix models install lays members out flat under assets/<asset id>.
        root = Path(result[0])
        self.assertEqual(root, Path(installer.asset_destination(fixture)))
        self.assertEqual(root.parent.name, "assets")
        self.assertEqual((root / "model.bin").read_bytes(), b"ct2-stub")
        self.assertTrue((root / "notices/LICENSE-mit.txt").is_file())
        upstream.close()


if __name__ == "__main__":
    unittest.main()
