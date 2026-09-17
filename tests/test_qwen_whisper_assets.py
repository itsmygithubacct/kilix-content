from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from kilix_license.catalog import load_determined_records

from kilix_content import default_catalog
from kilix_content.receipt import _CATALOG_SHA256, catalog_sha256

ROOT = Path(__file__).resolve().parents[1]
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_QWEN_REQUIRED = {
    "model/config.json",
    "model/generation_config.json",
    "model/model.safetensors",
    "model/preprocessor_config.json",
    "model/tokenizer_config.json",
    "model/vocab.json",
    "model/merges.txt",
    "model/speech_tokenizer/config.json",
    "model/speech_tokenizer/model.safetensors",
    "model/speech_tokenizer/preprocessor_config.json",
}
_QWEN_IDS = (
    "qwen3-tts-0.6b-base",
    "qwen3-tts-0.6b-customvoice",
    "qwen3-tts-1.7b-voicedesign",
)
_PINS = {
    "qwen3-tts-0.6b-base": "5d83992436eae1d760afd27aff78a71d676296fc",
    "qwen3-tts-0.6b-customvoice": "85e237c12c027371202489a0ec509ded67b5e4b5",
    "qwen3-tts-1.7b-voicedesign": "5ecdb67327fd37bb2e042aab12ff7391903235d3",
    "whisper-tiny-ggml": "5359861c739e955e79d9a303bcbc70fb988958b1",
}


class QwenWhisperAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_qwen_records_are_upstream_files_from_huggingface(self) -> None:
        for asset_id in _QWEN_IDS:
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(asset_id)
            self.assertEqual(spec.source_mode, "upstream-files")
            self.assertEqual(spec.provider, "kilix-qwen-tts")
            self.assertEqual(spec.consumer_schema, "kilix.qwen-tts.runtime")
            self.assertEqual(spec.stream, "F104")
            self.assertEqual(spec.version, _PINS[asset_id])
            self.assertEqual(spec.provenance_revision, _PINS[asset_id])
            self.assertEqual(spec.source_host, "huggingface.co")
            self.assertEqual(spec.licenses[0].decision, "affirmative")
            self.assertEqual(spec.licenses[0].license_id, "apache-2.0")
            self.assertEqual(spec.licenses[0].licensors, ("Alibaba Cloud",))
            self.assertEqual(
                spec.licenses[0].text_sha256,
                "a44a6081c73ad75f0255bb2bb5cab74ef1829565a895a24e53a4f11290ab7655",
            )
            self.assertEqual(spec.licenses[0].record_digest, record.digest)
            notice = next(item for item in spec.files if item.path.startswith("notices/"))
            self.assertEqual(notice.path, "notices/LICENSE-apache-2.0.txt")
            self.assertEqual(notice.sha256, spec.licenses[0].text_sha256)
            paths = {item.path for item in spec.files if not item.path.startswith("notices/")}
            self.assertTrue(_QWEN_REQUIRED <= paths)
            fetch_paths = {item.path for item in spec.fetch}
            self.assertEqual(fetch_paths, paths)
            for item in spec.fetch:
                parsed = urlsplit(item.url)
                self.assertEqual(parsed.scheme, "https")
                self.assertEqual(parsed.hostname, "huggingface.co")
                self.assertIn("/resolve/", parsed.path)
                commit = parsed.path.split("/resolve/", 1)[1].split("/", 1)[0]
                self.assertTrue(_HEX40.fullmatch(commit), item.url)
                self.assertEqual(commit, _PINS[asset_id])
            packed = spec.to_mapping()
            blob = str(packed).lower()
            self.assertNotIn("itsmygithubacct", blob)
            self.assertNotIn("assets-0.2.2-candidate", blob)

    def test_whisper_tiny_is_upstream_ggml_tiny_as_model_bin(self) -> None:
        spec = self.catalog.require_asset("whisper-tiny-ggml")
        record = self.records.by_id("whisper-tiny-ggml")
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-transcribe")
        self.assertEqual(spec.consumer_schema, "kilix.transcribe.runtime")
        self.assertEqual(spec.version, _PINS["whisper-tiny-ggml"])
        self.assertEqual(spec.provenance_revision, _PINS["whisper-tiny-ggml"])
        self.assertEqual(spec.source_host, "huggingface.co")
        self.assertEqual(spec.licenses[0].decision, "affirmative")
        self.assertEqual(spec.licenses[0].license_id, "mit")
        self.assertEqual(spec.licenses[0].licensors, ("OpenAI",))
        self.assertEqual(
            spec.licenses[0].text_sha256,
            "b5d65a59060e68c4ff940e1eddfa6f94b2d68fdf58ed7f4dd57721c997e35e9d",
        )
        self.assertEqual(spec.licenses[0].record_digest, record.digest)
        member = next(item for item in spec.files if item.path == "model.bin")
        self.assertEqual(member.bytes, 77691713)
        self.assertTrue(member.sha256.startswith("be07e048"))
        self.assertEqual(
            member.sha256,
            "be07e048e1e599ad46341c8d2a135645097a538221678b7acdd1b1919c6e1b21",
        )
        self.assertEqual(len(spec.fetch), 1)
        self.assertEqual(spec.fetch[0].path, "model.bin")
        self.assertIn("/ggerganov/whisper.cpp/resolve/", spec.fetch[0].url)
        self.assertTrue(spec.fetch[0].url.endswith("/ggml-tiny.bin"))
        self.assertIn(_PINS["whisper-tiny-ggml"], spec.fetch[0].url)
        notice = next(item for item in spec.files if item.path.startswith("notices/"))
        self.assertEqual(notice.path, "notices/LICENSE-mit.txt")
        self.assertEqual(notice.sha256, spec.licenses[0].text_sha256)
        packed = str(spec.to_mapping()).lower()
        self.assertNotIn("itsmygithubacct", packed)
        self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_catalog_sha_matches_packaged_bytes(self) -> None:
        self.assertEqual(catalog_sha256(), _CATALOG_SHA256)

    def test_generator_matches_packaged_catalog(self) -> None:
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
