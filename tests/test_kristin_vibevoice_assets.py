from __future__ import annotations

import io
import json
import os
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
from kilix_content.model import AssetSpec, _is_kilix_hosted
from kilix_content.receipt import _CATALOG_SHA256, catalog_sha256

ROOT = Path(__file__).resolve().parents[1]
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
KRISTIN_REV = "39ab474be869e9181350af6a65e4953eef67aaa0"
VIBEVOICE_REV = "66e78021ab8f5f06133d1ab421ba4d348bda97c9"
PIPER_PINS = {
    "en_US-kristin-medium.onnx": (
        63_531_379,
        "5849957f929cbf720c258f8458692d6103fff2f0e3d3b19c8259474bb06a18d4",
    ),
    "en_US-kristin-medium.onnx.json": (
        4_968,
        "5681426d4aead22195de70531eeeeddb46493cfaffc5764b2ea3db73428b651c",
    ),
    "MODEL_CARD": (
        479,
        "8c181b1d5f7d8152b914faab941fcbe6b8f0495e63e5189d6f27b8c68c8393fc",
    ),
}
B1_PINS = {
    "config.json": (
        3527,
        "4873cb753c97f042886a93adfef478978662c21169755670de20f2ff73fa4ca1",
    ),
    "generation_config.json": (
        138,
        "8c970692323e3ea0e9b8b0a4dca79388d31226e41f83c9fd6014804280ebf6e8",
    ),
}
MODEL_JSON_DEFAULT = {
    "vibeasr-lm-i2_s-embed-q6_k.gguf": (
        992877600,
        "fbe273d8dc2f2433bb25f849e19d77ea65aaa2188d12c20cee987ab6f321e002",
    ),
    "vibeasr-vae-encoder-i8_s.gguf": (
        703080064,
        "4941c82608c253ec066b5cc74d3dd11a5c8fef96cccbc5b87359ef0fe4338df6",
    ),
    "config.json": B1_PINS["config.json"],
    "generation_config.json": B1_PINS["generation_config.json"],
    "tokenizer.json": (7028015, None),
    "tokenizer_config.json": (1289, None),
    "vocab.json": (2776833, None),
    "README.md": (4124, None),
}
BONSAI_STORE_DEFAULT = "$KILIX_DATA_HOME/voice/models/vibevoice-asr-bitnet"
ADVISORY_SHA256 = "9ef874baa37eb4edc5fd731ad7c2587149986f9dff4760679421735e5b6daee3"
QWEN_COMPONENT_SHA256 = (
    "832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e"
)


def _pin(name: str) -> dict:
    return json.loads((ROOT / "tools" / "upstream-pins" / name).read_text(encoding="utf-8"))


def _https_huggingface(url: str, commit: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "huggingface.co":
        raise AssertionError(url)
    if "/resolve/" not in parsed.path:
        raise AssertionError(url)
    found = parsed.path.split("/resolve/", 1)[1].split("/", 1)[0]
    if not _HEX40.fullmatch(found) or found != commit:
        raise AssertionError(url)


class KristinVibeVoiceAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_kristin_is_upstream_files_from_piper_voices(self) -> None:
        spec = self.catalog.require_asset("piper-en-us-kristin-medium")
        record = self.records.by_id("piper-en-us-kristin-medium")
        pin = _pin("piper-en-us-kristin-medium.json")
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-piper-tts")
        self.assertEqual(spec.consumer_schema, "kilix.piper.models/v1")
        self.assertEqual(spec.stream, "F104")
        self.assertEqual(spec.version, KRISTIN_REV)
        self.assertEqual(spec.provenance_revision, KRISTIN_REV)
        self.assertEqual(spec.provenance_project, "rhasspy/piper-voices")
        self.assertEqual(spec.source_host, "huggingface.co")
        self.assertEqual(spec.licenses[0].decision, "informational")
        self.assertEqual(spec.licenses[0].license_id, "public-domain")
        self.assertEqual(spec.licenses[0].licensors, ("Bryce Beattie",))
        self.assertTrue(spec.licenses[0].licensors)
        self.assertEqual(spec.licenses[0].record_digest, record.digest)
        self.assertEqual(spec.licenses[0].text_sha256, record.text_sha256)
        notice = next(item for item in spec.files if item.path.startswith("notices/"))
        self.assertEqual(notice.path, "notices/public-domain.txt")
        self.assertEqual(notice.sha256, record.text_sha256)
        members = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
        self.assertEqual(set(members), set(PIPER_PINS))
        for path, (size, digest) in PIPER_PINS.items():
            self.assertEqual(members[path].bytes, size)
            self.assertEqual(members[path].sha256, digest)
        fetch = {item.path: item.url for item in spec.fetch}
        self.assertEqual(set(fetch), set(PIPER_PINS))
        for path, url in fetch.items():
            _https_huggingface(url, KRISTIN_REV)
            self.assertIn("/rhasspy/piper-voices/resolve/", url)
            self.assertTrue(url.endswith("/en/en_US/kristin/medium/" + path))
        pin_members = {item["path"]: item for item in pin["members"]}
        for path, item in members.items():
            self.assertEqual(item.bytes, pin_members[path]["bytes"])
            self.assertEqual(item.sha256, pin_members[path]["sha256"])
        packed = str(spec.to_mapping()).lower()
        self.assertNotIn("itsmygithubacct", packed)
        self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_vibevoice_matches_bonsai_model_json_and_b1_pins(self) -> None:
        spec = self.catalog.require_asset("vibevoice-asr-bitnet")
        record = self.records.by_id("vibevoice-asr-bitnet")
        pin = _pin("vibevoice-asr-bitnet.json")
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-bonsai")
        self.assertEqual(spec.consumer_schema, "kilix.bonsai.runtime")
        self.assertEqual(spec.version, VIBEVOICE_REV)
        self.assertEqual(spec.provenance_revision, VIBEVOICE_REV)
        self.assertEqual(spec.provenance_project, "microsoft/VibeVoice-ASR-BitNet")
        self.assertEqual(spec.source_host, "huggingface.co")
        self.assertEqual(pin["destination"], BONSAI_STORE_DEFAULT)
        self.assertTrue(BONSAI_STORE_DEFAULT.endswith("/" + spec.asset_id))
        self.assertEqual(len(spec.licenses), 2)
        mit = spec.licenses[0]
        apache = spec.licenses[1]
        self.assertEqual(mit.license_id, "mit")
        self.assertEqual(mit.decision, "affirmative")
        self.assertEqual(mit.licensors, ("Microsoft Corporation",))
        self.assertEqual(mit.record_digest, record.digest)
        self.assertEqual(mit.text_sha256, record.text_sha256)
        self.assertEqual(apache.license_id, "apache-2.0")
        self.assertEqual(apache.licensors, ("Alibaba Cloud",))
        self.assertEqual(apache.record_digest, record.digest)
        self.assertEqual(apache.text_sha256, QWEN_COMPONENT_SHA256)
        self.assertEqual(record.advisories[0].text_sha256, ADVISORY_SHA256)
        members = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
        self.assertEqual(set(members), set(MODEL_JSON_DEFAULT))
        for path, (size, digest) in MODEL_JSON_DEFAULT.items():
            self.assertEqual(members[path].bytes, size)
            self.assertTrue(_HEX64.fullmatch(members[path].sha256))
            if digest is not None:
                self.assertEqual(members[path].sha256, digest)
        for path, (size, digest) in B1_PINS.items():
            self.assertEqual(members[path].bytes, size)
            self.assertEqual(members[path].sha256, digest)
        self.assertIsNone(next((item for item in spec.files if item.sha256 is None), None))
        fetch = {item.path: item.url for item in spec.fetch}
        self.assertEqual(set(fetch), set(MODEL_JSON_DEFAULT))
        for path, url in fetch.items():
            _https_huggingface(url, VIBEVOICE_REV)
            self.assertIn("/microsoft/VibeVoice-ASR-BitNet/resolve/", url)
            self.assertTrue(url.endswith("/" + path))
        notices = {item.path: item for item in spec.files if item.path.startswith("notices/")}
        self.assertEqual(
            set(notices),
            {"notices/LICENSE-mit.txt", "notices/LICENSE-apache-2.0.txt"},
        )
        self.assertEqual(notices["notices/LICENSE-mit.txt"].sha256, record.text_sha256)
        self.assertEqual(
            notices["notices/LICENSE-apache-2.0.txt"].sha256, QWEN_COMPONENT_SHA256
        )
        packed = str(spec.to_mapping()).lower()
        self.assertNotIn("itsmygithubacct", packed)
        self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_no_packaged_asset_source_url_is_kilix_hosted(self) -> None:
        for spec in self.catalog.assets:
            packed = str(spec.to_mapping()).lower()
            self.assertNotIn("itsmygithubacct", packed)
            self.assertNotIn("assets-0.2.2-candidate", packed)
            for item in spec.fetch:
                parsed = urlsplit(item.url)
                self.assertEqual(parsed.scheme, "https")
                self.assertFalse(_is_kilix_hosted(item.url), item.url)
            if spec.source_mode == "upstream-archive":
                self.assertFalse(_is_kilix_hosted(spec.url), spec.url)

    def test_catalog_sha_matches_packaged_bytes(self) -> None:
        self.assertEqual(catalog_sha256(), _CATALOG_SHA256)

    def test_kristin_first_use_screen_and_receipt(self) -> None:
        spec = self.catalog.require_asset("piper-en-us-kristin-medium")
        record = self.records.by_id("piper-en-us-kristin-medium")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-kristin-screen-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(spec, record, texts).decode("utf-8")
        self.assertIn("piper-en-us-kristin-medium", screen)
        self.assertIn("huggingface.co", screen)
        self.assertIn(str(spec.download_bytes), screen)
        self.assertIn("public-domain", screen)
        self.assertIn("Bryce Beattie", screen)
        self.assertIn("informational", screen)
        self.assertIn("License: public domain", screen)
        self.assertIn("Feel free to use these for any legal and ethical purpose", screen)
        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        notice = texts.get(record.text_sha256)
        payloads = {
            "en_US-kristin-medium.onnx": b"onnx-stub",
            "en_US-kristin-medium.onnx.json": b'{"stub":true}',
            "MODEL_CARD": b"card-stub",
        }
        files = {
            path: (upstream.add(f"/{path}", body), body) for path, body in payloads.items()
        }
        mapping = make_files_asset(
            asset_id="fixture-kristin",
            files=files,
            license_record=record,
            notice=notice,
            licensors=["Bryce Beattie"],
            provider="kilix-piper-tts",
            consumer_schema="kilix.piper.models/v1",
            notice_path="notices/public-domain.txt",
            license_id="public-domain",
        )
        fixture = AssetSpec.from_mapping(mapping)
        declined = io.BytesIO()
        none = install_with_agreement(
            fixture,
            installer=installer,
            store=store,
            records=self.records,
            texts=texts,
            typed_text=None,
            screen=declined,
            decline=True,
        )
        self.assertIsNone(none)
        self.assertEqual(list(store.root.glob("*.json")), [])
        self.assertEqual(upstream.requests(), [])
        self.assertFalse(Path(installer.asset_destination(fixture)).exists())
        accepted = io.BytesIO()
        result = install_with_agreement(
            fixture,
            installer=installer,
            store=store,
            records=self.records,
            texts=texts,
            typed_text=None,
            screen=accepted,
        )
        self.assertIsNotNone(result)
        receipts = list(store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = parse_receipt_bytes(receipts[0].read_bytes())
        self.assertEqual(receipt.decision, "record")
        self.assertEqual(receipt.licensor, "Bryce Beattie")
        self.assertEqual(receipt.record_digest, record.digest)
        self.assertEqual(receipt.advisory_digests, {})
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertNotIn("advisory_digests", payload)
        self.assertIn("advisory_digests", payload["context"])
        root = Path(result[0])
        self.assertTrue((root / "notices/public-domain.txt").is_file())
        self.assertEqual((root / "en_US-kristin-medium.onnx").read_bytes(), b"onnx-stub")
        upstream.close()

    def test_vibevoice_first_use_records_advisory_context_not_bound(self) -> None:
        spec = self.catalog.require_asset("vibevoice-asr-bitnet")
        record = self.records.by_id("vibevoice-asr-bitnet")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-vibevoice-screen-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(spec, record, texts).decode("utf-8")
        self.assertIn("vibevoice-asr-bitnet", screen)
        self.assertIn("huggingface.co", screen)
        self.assertIn("/microsoft/VibeVoice-ASR-BitNet/resolve/", screen)
        self.assertIn(VIBEVOICE_REV, screen)
        self.assertIn(str(spec.download_bytes), screen)
        self.assertIn("mit", screen)
        self.assertIn("apache-2.0", screen)
        self.assertIn("Microsoft Corporation", screen)
        self.assertIn("Alibaba Cloud", screen)
        self.assertIn("research and development purposes only", screen)
        self.assertIn("Copyright (c) 2025 Microsoft", screen)
        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        notice = texts.get(record.text_sha256)
        payloads = {"config.json": b'{"stub":1}', "generation_config.json": b"{}\n"}
        files = {
            path: (upstream.add(f"/{path}", body), body) for path, body in payloads.items()
        }
        mapping = make_files_asset(
            asset_id="fixture-vibevoice",
            files=files,
            license_record=record,
            notice=notice,
            licensors=["Microsoft Corporation"],
            provider="kilix-bonsai",
            consumer_schema="kilix.bonsai.runtime",
            notice_path="notices/LICENSE-mit.txt",
            license_id="mit",
        )
        fixture = AssetSpec.from_mapping(mapping)
        declined = io.BytesIO()
        none = install_with_agreement(
            fixture,
            installer=installer,
            store=store,
            records=self.records,
            texts=texts,
            typed_text=None,
            screen=declined,
            decline=True,
        )
        self.assertIsNone(none)
        self.assertEqual(list(store.root.glob("*.json")), [])
        self.assertEqual(upstream.requests(), [])
        accepted = io.BytesIO()
        result = install_with_agreement(
            fixture,
            installer=installer,
            store=store,
            records=self.records,
            texts=texts,
            typed_text=typed_agreement_line(record),
            screen=accepted,
        )
        self.assertIsNotNone(result)
        receipts = list(store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = parse_receipt_bytes(receipts[0].read_bytes())
        self.assertEqual(receipt.decision, "accept")
        self.assertEqual(receipt.licensor, "Microsoft Corporation")
        self.assertEqual(
            receipt.advisory_digests,
            {"vibevoice-research-advisory": ADVISORY_SHA256},
        )
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertNotIn("advisory_digests", payload)
        self.assertEqual(
            payload["context"]["advisory_digests"]["vibevoice-research-advisory"],
            ADVISORY_SHA256,
        )
        self.assertNotIn(ADVISORY_SHA256, payload["binding_condition_text_digests"].values())
        self.assertEqual(payload["licence_text_digest"], record.text_sha256)
        self.assertNotEqual(payload["licence_text_digest"], ADVISORY_SHA256)
        self.assertTrue(Path(result[0], "notices/LICENSE-mit.txt").is_file())
        upstream.close()

    def test_generator_matches_packaged_catalog(self) -> None:
        import subprocess

        env = dict(os.environ)
        env["PYTHONPATH"] = "src:third_party/kilix-license/src"
        result = subprocess.run(
            ["python3", "tools/generate_upstream_records.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
