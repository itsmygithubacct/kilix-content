from __future__ import annotations

import io
import json
import os
import re
import subprocess
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
from kilix_content.model import AssetSpec, CatalogError, _is_kilix_hosted
from kilix_content.receipt import _CATALOG_SHA256, catalog_sha256

ROOT = Path(__file__).resolve().parents[1]
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
YOLOX_IDS = ("yolox_s", "yolox_tiny", "yolox_nano")
YOLOX_TAG = "0.1.1rc0"
YOLOX_COMMIT = "e1052df71842031413f6030723c3607b839c80ce"
YOLOX_RELEASE = (
    "https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0"
)
APACHE_YOLOX = "577c03d505ec80f667ebf96ebd0cc4f6825c817ca1088ee348c48aaabd51bd92"
APACHE_YAMNET = "5b17814bf0de8cf65069bc6d7cc38cff19fcaa864d243423ad3ef3db01b52385"
AUDIOSET_NOTE = "df564260a7db24121dad6c28b90d82bbde199d5bb4d0cd6060c9fe19ad5e19af"
YAMNET_URL = (
    "https://storage.googleapis.com/mediapipe-models/"
    "audio_classifier/yamnet/float32/1/yamnet.tflite"
)
YAMNET_SHA256 = "4d8b4a53282dc83ef04e3e7dbc4fbc98082e34e44ed798e16c3a0cdd4c584faf"
SOUND_FETCH = Path(
    "/home/pleb/gpu_terminal/kilix-modules/kilix-sound-detect/tools/"
    "kilix-sound-fetch-model"
)
YOLOX_SUMS = Path("/home/pleb/gpu_terminal/kilix-modules/kilix-yolox/models/SHA256SUMS")


def _pin(name: str) -> dict:
    return json.loads((ROOT / "tools" / "upstream-pins" / name).read_text(encoding="utf-8"))


def _sound_fetch_pins() -> tuple[str, str]:
    ns: dict[str, object] = {}
    exec(SOUND_FETCH.read_text(encoding="utf-8").split("def models_dir")[0], ns)
    model = ns["MODELS"]["sound"]  # type: ignore[index]
    return model["url"], model["sha256"]


class YoloxYamnetAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_yolox_s_tiny_nano_are_upstream_files_from_github_release(self) -> None:
        sums = {}
        if YOLOX_SUMS.is_file():
            for line in YOLOX_SUMS.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) == 2:
                    sums[parts[1]] = parts[0].lower()
        for asset_id in YOLOX_IDS:
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(asset_id)
            pin = _pin(f"{asset_id}.json")
            filename = f"{asset_id}.onnx"
            self.assertEqual(spec.source_mode, "upstream-files")
            self.assertEqual(spec.provider, "kilix-object-detect")
            self.assertEqual(spec.consumer_schema, "kilix.object-detect.runtime")
            self.assertEqual(spec.stream, "F104")
            self.assertEqual(spec.version, YOLOX_TAG)
            self.assertEqual(spec.provenance_project, "Megvii-BaseDetection/YOLOX")
            self.assertEqual(spec.provenance_revision, YOLOX_COMMIT)
            self.assertTrue(_HEX40.fullmatch(spec.provenance_revision))
            self.assertEqual(spec.source_host, "github.com")
            self.assertEqual(spec.licenses[0].decision, "affirmative")
            self.assertEqual(spec.licenses[0].license_id, "apache-2.0")
            self.assertEqual(
                spec.licenses[0].licensors,
                ("Megvii (Base Detection / Megvii Inc.)",),
            )
            self.assertEqual(spec.licenses[0].text_sha256, APACHE_YOLOX)
            self.assertEqual(spec.licenses[0].record_digest, record.digest)
            self.assertEqual(record.text_sha256, APACHE_YOLOX)
            notice = next(item for item in spec.files if item.path.startswith("notices/"))
            self.assertEqual(notice.path, "notices/LICENSE-apache-2.0.txt")
            self.assertEqual(notice.sha256, APACHE_YOLOX)
            members = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
            self.assertEqual(set(members), {filename})
            self.assertTrue(_HEX64.fullmatch(members[filename].sha256))
            self.assertEqual(members[filename].sha256, pin["members"][0]["sha256"])
            self.assertEqual(members[filename].bytes, pin["members"][0]["bytes"])
            if filename in sums:
                self.assertEqual(members[filename].sha256, sums[filename])
            self.assertEqual(len(spec.fetch), 1)
            url = spec.fetch[0].url
            self.assertEqual(spec.fetch[0].path, filename)
            self.assertEqual(url, f"{YOLOX_RELEASE}/{filename}")
            parsed = urlsplit(url)
            self.assertEqual(parsed.scheme, "https")
            self.assertEqual(parsed.hostname, "github.com")
            self.assertTrue(parsed.path.startswith("/Megvii-BaseDetection/YOLOX/releases/download/"))
            self.assertIn(f"/releases/download/{YOLOX_TAG}/", parsed.path)
            self.assertFalse(_is_kilix_hosted(url), url)
            packed = str(spec.to_mapping()).lower()
            self.assertNotIn("itsmygithubacct", packed)
            self.assertNotIn("assets-0.2.2-candidate", packed)
            self.assertNotIn("ultralytics", packed)
            self.assertNotIn("yolo26", packed)

    def test_yamnet_matches_sound_fetch_model_pins(self) -> None:
        spec = self.catalog.require_asset("yamnet")
        record = self.records.by_id("yamnet")
        pin = _pin("yamnet.json")
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-sound-detect")
        self.assertEqual(spec.consumer_schema, "kilix.sound-detect.runtime")
        self.assertEqual(spec.stream, "F104")
        self.assertEqual(spec.version, "float32/1")
        self.assertEqual(spec.source_host, "storage.googleapis.com")
        self.assertEqual(spec.licenses[0].decision, "affirmative")
        self.assertEqual(spec.licenses[0].license_id, "apache-2.0")
        self.assertEqual(spec.licenses[0].licensors, ("Google",))
        self.assertEqual(spec.licenses[0].text_sha256, APACHE_YAMNET)
        self.assertEqual(spec.licenses[0].record_digest, record.digest)
        self.assertEqual(record.advisories[0].id, "audioset-ontology-cc-by-sa")
        self.assertEqual(record.advisories[0].text_sha256, AUDIOSET_NOTE)
        members = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
        self.assertEqual(set(members), {"yamnet.tflite"})
        self.assertEqual(members["yamnet.tflite"].sha256, YAMNET_SHA256)
        self.assertEqual(members["yamnet.tflite"].sha256, pin["members"][0]["sha256"])
        self.assertEqual(members["yamnet.tflite"].bytes, pin["members"][0]["bytes"])
        self.assertEqual(len(spec.fetch), 1)
        self.assertEqual(spec.fetch[0].path, "yamnet.tflite")
        self.assertEqual(spec.fetch[0].url, YAMNET_URL)
        self.assertEqual(spec.fetch[0].url, pin["members"][0]["url"])
        notice = next(item for item in spec.files if item.path.startswith("notices/"))
        self.assertEqual(notice.path, "notices/LICENSE-apache-2.0.txt")
        self.assertEqual(notice.sha256, APACHE_YAMNET)
        if SOUND_FETCH.is_file():
            url, digest = _sound_fetch_pins()
            self.assertEqual(spec.fetch[0].url, url)
            self.assertEqual(members["yamnet.tflite"].sha256, digest)
        packed = str(spec.to_mapping()).lower()
        self.assertNotIn("itsmygithubacct", packed)
        self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_no_ultralytics_or_yolo26_in_content_records(self) -> None:
        for spec in self.catalog.assets:
            packed = str(spec.to_mapping()).lower()
            self.assertNotIn("ultralytics", packed, spec.asset_id)
            self.assertNotIn("yolo26", packed, spec.asset_id)

    def test_no_packaged_asset_source_url_is_kilix_hosted(self) -> None:
        for spec in self.catalog.assets:
            packed = str(spec.to_mapping()).lower()
            self.assertNotIn("itsmygithubacct", packed)
            self.assertNotIn("assets-0.2.2-candidate", packed)
            for item in spec.fetch:
                parsed = urlsplit(item.url)
                self.assertEqual(parsed.scheme, "https")
                self.assertFalse(_is_kilix_hosted(item.url), item.url)
            for item in spec.blobs:
                parsed = urlsplit(item.url)
                self.assertEqual(parsed.scheme, "https")
                self.assertFalse(_is_kilix_hosted(item.url), item.url)
            if spec.source_mode == "upstream-archive":
                self.assertFalse(_is_kilix_hosted(spec.url), spec.url)
            if spec.source_mode == "upstream-convert":
                self.assertFalse(_is_kilix_hosted(spec.convert_url), spec.convert_url)
            if spec.source_mode == "registry-manifest":
                self.assertFalse(_is_kilix_hosted(spec.manifest_url), spec.manifest_url)

    def test_planted_kilix_host_url_is_refused(self) -> None:
        record = self.records.by_id("yamnet")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-yamnet-plant-"))
        texts = load_determined_texts(scratch / "texts")
        notice = texts.get(record.text_sha256)
        planted = (
            "https://github.com/itsmygithubacct/kilix-content/releases/"
            "download/x/yamnet.tflite"
        )
        mapping = make_files_asset(
            asset_id="fixture-yamnet-planted",
            files={"yamnet.tflite": (planted, b"tflite-stub")},
            license_record=record,
            notice=notice,
            licensors=["Google"],
            provider="kilix-sound-detect",
            consumer_schema="kilix.sound-detect.runtime",
        )
        with self.assertRaises(CatalogError):
            AssetSpec.from_mapping(mapping)
        honest = self.catalog.require_asset("yamnet").to_mapping()
        honest["source"]["fetch"][0]["url"] = planted
        honest["source"]["provenance"]["original_url"] = planted
        with self.assertRaises(CatalogError) as raised:
            AssetSpec.from_mapping(honest)
        self.assertIn("upstream", str(raised.exception).lower())

    def test_yolox_first_use_decline_and_accept(self) -> None:
        spec = self.catalog.require_asset("yolox_nano")
        record = self.records.by_id("yolox_nano")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-yolox-screen-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(spec, record, texts).decode("utf-8")
        self.assertIn("yolox_nano", screen)
        self.assertIn("github.com", screen)
        self.assertIn("/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_nano.onnx", screen)
        self.assertIn(str(spec.download_bytes), screen)
        self.assertIn("apache-2.0", screen)
        self.assertIn("Megvii (Base Detection / Megvii Inc.)", screen)
        self.assertIn("Copyright 2021 Megvii, Base Detection", screen)
        self.assertIn("Apache License", screen)
        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        notice = texts.get(record.text_sha256)
        body = b"onnx-stub"
        github_path = "/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_nano.onnx"
        url = upstream.add(github_path, body)
        mapping = make_files_asset(
            asset_id="fixture-yolox-nano",
            files={"yolox_nano.onnx": (url, body)},
            license_record=record,
            notice=notice,
            licensors=["Megvii (Base Detection / Megvii Inc.)"],
            provider="kilix-object-detect",
            consumer_schema="kilix.object-detect.runtime",
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
            typed_text=typed_agreement_line(record),
            screen=accepted,
        )
        self.assertIsNotNone(result)
        receipts = list(store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = parse_receipt_bytes(receipts[0].read_bytes())
        self.assertEqual(receipt.decision, "accept")
        self.assertEqual(receipt.licensor, "Megvii (Base Detection / Megvii Inc.)")
        self.assertEqual(receipt.record_digest, record.digest)
        gotten = {
            item.get("path")
            for item in upstream.requests()
            if item.get("command") == "GET"
        }
        self.assertEqual(gotten, {github_path})
        self.assertTrue(Path(result[0], "notices/LICENSE-apache-2.0.txt").is_file())
        self.assertEqual(Path(result[0], "yolox_nano.onnx").read_bytes(), body)
        upstream.close()

    def test_yamnet_first_use_audioset_advisory_not_bound(self) -> None:
        spec = self.catalog.require_asset("yamnet")
        record = self.records.by_id("yamnet")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-yamnet-screen-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(spec, record, texts).decode("utf-8")
        self.assertIn("yamnet", screen)
        self.assertIn("storage.googleapis.com", screen)
        self.assertIn("/audio_classifier/yamnet/float32/1/yamnet.tflite", screen)
        self.assertIn(str(spec.download_bytes), screen)
        self.assertIn("apache-2.0", screen)
        self.assertIn("Google", screen)
        self.assertIn("Creative Commons", screen)
        self.assertIn("Attribution-ShareAlike 4.0", screen)
        self.assertIn("CC BY-SA 4.0", screen)
        self.assertIn("advisory:audioset-ontology-cc-by-sa", screen)
        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        notice = texts.get(record.text_sha256)
        body = b"tflite-stub"
        path = "/mediapipe-models/audio_classifier/yamnet/float32/1/yamnet.tflite"
        url = upstream.add(path, body)
        mapping = make_files_asset(
            asset_id="fixture-yamnet",
            files={"yamnet.tflite": (url, body)},
            license_record=record,
            notice=notice,
            licensors=["Google"],
            provider="kilix-sound-detect",
            consumer_schema="kilix.sound-detect.runtime",
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
        self.assertEqual(receipt.licensor, "Google")
        self.assertEqual(
            receipt.advisory_digests,
            {"audioset-ontology-cc-by-sa": AUDIOSET_NOTE},
        )
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertNotIn("advisory_digests", payload)
        self.assertEqual(
            payload["context"]["advisory_digests"]["audioset-ontology-cc-by-sa"],
            AUDIOSET_NOTE,
        )
        self.assertNotIn(AUDIOSET_NOTE, payload["binding_condition_text_digests"].values())
        self.assertEqual(payload["licence_text_digest"], record.text_sha256)
        self.assertNotEqual(payload["licence_text_digest"], AUDIOSET_NOTE)
        self.assertTrue(Path(result[0], "notices/LICENSE-apache-2.0.txt").is_file())
        self.assertEqual(Path(result[0], "yamnet.tflite").read_bytes(), body)
        upstream.close()

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
