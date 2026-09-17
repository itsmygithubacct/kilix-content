from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.errors import AgreementRequired
from kilix_license.paraphrase import POCKET_TERMS_SUMMARY
from kilix_license.receipts import parse_receipt_bytes, receipt_from_agreement

from fake_store import FakeStore
from first_use_fixture import FakeUpstream, make_convert_asset, make_files_asset
from kilix_content import default_catalog
from kilix_content.first_use import install_with_agreement, present_asset
from kilix_content.install import Installer
from kilix_content.model import AssetSpec, _is_kilix_hosted
from kilix_content.receipt import _CATALOG_SHA256, catalog_sha256, release_digest

ROOT = Path(__file__).resolve().parents[1]
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
BONSAI_8B = "48516770dd04643643e9f9019a2a349cf26c5dbd"
BONSAI_27B = "f10afb355f104535e3e3e98cf7ab7795c72bd292"
BITNET_GGUF = "a1f2f1c765812aa8af3f6eda4a313707064bba15"
BITNET_BASE = "04c3b9ad9361b824064a1f25ea60a8be9599b127"
POCKET_REV = "d29db7978e464fb90cb3359ee0c69a273b9142cc"
CARD_SHA256 = "ae2ebac6f8039d761ca90e2b742136dce9d7872ec8dd2105e3b2de1e3021e3aa"
LLAMA_BINDING = "b73a2906c0224dcb54cece1820b54f1540411f8e81aca3f7c41271c908ccb311"
LLAMA_FILE = "4fa551d4f938f68b8c1e6afa9d28befb70e3f33f75d0753248d530364aeea40f"
PROHIBITED = "38ea33043da12f5a67895f9b35ed8776c0869371091a2bf0e4fa96a77db421c1"
NAME_INFERRED = (
    "**The owner accepts on record** that the link from the Ollama artefact "
    "to the upstream publisher is name-inferred"
)
OLLAMA_IDS = {
    "granite4.1-3b": (
        "granite4.1:3b",
        "6fd349357287c7ffc9e38189a93b48ea175d24fc566b38f09cfc564fb7f303eb",
        "https://registry.ollama.ai/v2/library/granite4.1/manifests/3b",
        829,
    ),
    "nomic-embed-text-v1.5": (
        "nomic-embed-text:v1.5",
        "0a109f422b47e3a30ba2b10eca18548e944e8a23073ee3f3e947efcf3c45e59f",
        "https://registry.ollama.ai/v2/library/nomic-embed-text/manifests/v1.5",
        708,
    ),
    "granite3.2-vision-2b": (
        "granite3.2-vision:2b",
        "3be41a661804ad72cd08269816c5a145f1df6479ad07e2b3a7e29dba575d2669",
        "https://registry.ollama.ai/v2/library/granite3.2-vision/manifests/2b",
        1405,
    ),
    "qwen3.5-4b": (
        "qwen3.5:4b",
        "2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd",
        "https://registry.ollama.ai/v2/library/qwen3.5/manifests/4b",
        709,
    ),
}
GGUF_NOT_TRACKED = "87c310bfeae4ba8a9e4016c01114013823d08451d10292c2bd64a8e7b9b529c6"


def _pin(name: str) -> dict:
    return json.loads((ROOT / "tools" / "upstream-pins" / name).read_text(encoding="utf-8"))


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class C2dAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_no_null_digest_in_any_record(self) -> None:
        for spec in self.catalog.assets:
            for item in spec.files:
                self.assertTrue(_HEX64.fullmatch(item.sha256), f"{spec.asset_id}:{item.path}")
                self.assertIsNotNone(item.sha256)
            if spec.source_mode == "upstream-convert":
                self.assertTrue(_HEX64.fullmatch(spec.convert_sha256))
            if spec.source_mode == "registry-manifest":
                self.assertTrue(_HEX64.fullmatch(spec.manifest_sha256))
                self.assertTrue(spec.blobs)

    def test_bonsai_8b_and_27b_are_apache_upstream_files(self) -> None:
        expected = {
            "bonsai-8b": (BONSAI_8B, "prism-ml/Bonsai-8B-gguf", "Bonsai-8B-Q1_0.gguf"),
            "bonsai-27b": (BONSAI_27B, "prism-ml/Bonsai-27B-gguf", "Bonsai-27B-Q1_0.gguf"),
        }
        for asset_id, (revision, project, gguf) in expected.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(asset_id)
            pin = _pin(f"{asset_id}.json")
            self.assertEqual(spec.source_mode, "upstream-files")
            self.assertEqual(spec.provider, "kilix-bonsai")
            self.assertEqual(spec.consumer_schema, "kilix.bonsai.runtime")
            self.assertEqual(spec.version, revision)
            self.assertTrue(_HEX40.fullmatch(spec.provenance_revision))
            self.assertEqual(spec.provenance_project, project)
            self.assertEqual(spec.source_host, "huggingface.co")
            self.assertEqual(spec.licenses[0].decision, "affirmative")
            self.assertEqual(spec.licenses[0].license_id, "apache-2.0")
            self.assertEqual(spec.licenses[0].licensors, ("Prism ML, Inc.",))
            self.assertEqual(spec.licenses[0].record_digest, record.digest)
            members = {
                item.path: item for item in spec.files if not item.path.startswith("notices/")
            }
            self.assertIn(gguf, members)
            pin_members = {item["path"]: item for item in pin["members"]}
            self.assertEqual(set(members), set(pin_members))
            for path, item in members.items():
                self.assertEqual(item.sha256, pin_members[path]["sha256"])
                self.assertEqual(item.bytes, pin_members[path]["bytes"])
                self.assertTrue(_HEX64.fullmatch(item.sha256))
            fetch = {item.path: item.url for item in spec.fetch}
            for path, url in fetch.items():
                parsed = urlsplit(url)
                self.assertEqual(parsed.hostname, "huggingface.co")
                self.assertIn(f"/resolve/{revision}/", parsed.path)
                self.assertFalse(_is_kilix_hosted(url), url)

    def test_bitnet_spans_two_repositories_and_binds_llama(self) -> None:
        spec = self.catalog.require_asset("bitnet-b1.58-2b4t")
        record = self.records.by_id("bitnet-b1.58-2b4t")
        pin = _pin("bitnet-b1.58-2b4t.json")
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.provider, "kilix-bonsai")
        self.assertEqual(spec.version, BITNET_GGUF)
        self.assertEqual(spec.licenses[0].license_id, "mit")
        self.assertEqual(spec.licenses[0].licensors, ("Microsoft Corporation",))
        self.assertEqual(spec.licenses[1].license_id, "llama-3-community")
        self.assertEqual(spec.licenses[1].licensors, ("Meta Platforms, Inc.",))
        self.assertEqual(spec.licenses[1].text_sha256, LLAMA_FILE)
        self.assertEqual(record.binding_conditions[0].id, "llama3-community-licence-full-text")
        self.assertEqual(record.binding_conditions[0].text_sha256, LLAMA_BINDING)
        self.assertTrue(record.binding_conditions[0].agreement_required)
        members = {item.path: item for item in spec.files if not item.path.startswith("notices/")}
        pin_members = {item["path"]: item for item in pin["members"]}
        self.assertEqual(set(members), set(pin_members))
        fetch = {item.path: item.url for item in spec.fetch}
        self.assertIn("/microsoft/bitnet-b1.58-2B-4T-gguf/resolve/" + BITNET_GGUF, fetch["ggml-model-i2_s.gguf"])
        self.assertIn("/microsoft/bitnet-b1.58-2B-4T/resolve/" + BITNET_BASE, fetch["tokenizer.json"])
        self.assertIn("/microsoft/bitnet-b1.58-2B-4T/resolve/" + BITNET_BASE, fetch["LICENSE"])
        notices = {item.path: item for item in spec.files if item.path.startswith("notices/")}
        self.assertEqual(
            set(notices),
            {"notices/LICENSE-mit.txt", "notices/LICENSE-llama-3-community.txt"},
        )
        self.assertEqual(notices["notices/LICENSE-llama-3-community.txt"].sha256, LLAMA_FILE)

    def test_ollama_registry_manifest_pins(self) -> None:
        for asset_id, (label, digest, url, size) in OLLAMA_IDS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(label)
            pin = _pin(f"{asset_id}.json")
            self.assertEqual(spec.source_mode, "registry-manifest")
            self.assertEqual(spec.provider, "kilix-ollama")
            self.assertEqual(spec.consumer_schema, "kilix.ollama.runtime")
            self.assertEqual(spec.manifest_sha256, digest)
            self.assertEqual(spec.version, digest)
            self.assertTrue(spec.manifest_sha256.startswith(digest[:8]))
            self.assertEqual(spec.manifest_url, url)
            self.assertEqual(spec.download_bytes, size)
            self.assertEqual(spec.source_host, "registry.ollama.ai")
            self.assertEqual(spec.licenses[0].decision, "affirmative")
            self.assertEqual(spec.licenses[0].license_id, "apache-2.0")
            self.assertEqual(spec.licenses[0].record_digest, record.digest)
            pin_blobs = {item["path"]: item for item in pin["blobs"]}
            members = {
                item.path: item for item in spec.files if not item.path.startswith("notices/")
            }
            self.assertEqual(set(members), set(pin_blobs))
            self.assertEqual({item.path for item in spec.blobs}, set(pin_blobs))
            for path, item in members.items():
                self.assertEqual(item.sha256, pin_blobs[path]["sha256"])
                self.assertEqual(item.bytes, pin_blobs[path]["bytes"])
                self.assertTrue(_HEX64.fullmatch(item.sha256))
            for blob in spec.blobs:
                parsed = urlsplit(blob.url)
                self.assertEqual(parsed.hostname, "registry.ollama.ai")
                self.assertIn("/blobs/sha256:", parsed.path)
                self.assertFalse(_is_kilix_hosted(blob.url), blob.url)

    def test_qwen35_name_inferred_publisher_link_text_present(self) -> None:
        spec = self.catalog.require_asset("qwen3.5-4b")
        packed = json.dumps(spec.to_mapping(), ensure_ascii=False)
        self.assertIn(NAME_INFERRED, packed)
        self.assertIn(NAME_INFERRED, spec.label)
        self.assertIn(NAME_INFERRED, spec.provenance_project)
        self.assertIn("qwen3.5:4b", spec.label)

    def test_pocket_is_upstream_convert_without_gguf_or_embeddings(self) -> None:
        spec = self.catalog.require_asset("pocket-tts-english-q8_0")
        record = self.records.by_id("pocket-tts-english-q8_0")
        pin = _pin("pocket-tts-english-q8_0.json")
        self.assertEqual(spec.source_mode, "upstream-convert")
        self.assertEqual(spec.provider, "kilix-ollama")
        self.assertEqual(spec.label, "pocket-tts-english")
        self.assertEqual(spec.version, POCKET_REV)
        self.assertEqual(spec.convert_input_path, "languages/english/model.safetensors")
        self.assertEqual(spec.convert_sha256, pin["input"]["sha256"])
        self.assertEqual(spec.convert_tool_asset_id, "pocket-tts-convert-hf-to-gguf")
        self.assertIn("{sources}", spec.convert_argv)
        self.assertIn("{output}/pocket-tts-english-q8_0.gguf", spec.convert_argv)
        members = {
            item.path: item for item in spec.files if not item.path.startswith("notices/")
        }
        self.assertEqual(
            set(members),
            {
                "languages/english/model.safetensors",
                "languages/english/tokenizer.model",
                "README.md",
            },
        )
        self.assertEqual(members["README.md"].sha256, CARD_SHA256)
        self.assertTrue(members["README.md"].sha256.startswith("ae2ebac6"))
        self.assertFalse(any(path.endswith(".gguf") for path in members))
        packed = json.dumps(spec.to_mapping())
        self.assertNotIn(GGUF_NOT_TRACKED, packed)
        self.assertNotIn("/embeddings/", packed)
        self.assertNotIn("embeddings_v2", packed)
        self.assertNotIn("embeddings_v3", packed)
        for item in spec.fetch:
            self.assertNotIn("/embeddings", item.url)
        self.assertNotIn("/embeddings", spec.convert_url)
        self.assertEqual(spec.licenses[0].license_id, "cc-by-4.0")
        self.assertEqual(spec.licenses[0].licensors, ("Kyutai",))
        self.assertEqual(spec.licenses[0].record_digest, record.digest)
        self.assertEqual(record.binding_conditions[0].text_sha256, PROHIBITED)

    def test_bitnet_first_use_binds_llama_and_records_advisory_context(self) -> None:
        spec = self.catalog.require_asset("bitnet-b1.58-2b4t")
        record = self.records.by_id("bitnet-b1.58-2b4t")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-bitnet-screen-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(spec, record, texts).decode("utf-8")
        self.assertIn("bitnet-b1.58-2b4t", screen)
        self.assertIn("huggingface.co", screen)
        self.assertIn("mit", screen)
        self.assertIn("llama-3-community", screen)
        self.assertIn("Microsoft Corporation", screen)
        self.assertIn("Meta Llama 3 Acceptable Use Policy", screen)
        self.assertIn("META LLAMA 3 COMMUNITY LICENSE AGREEMENT", screen)
        self.assertIn("binding:llama3-community-licence-full-text", screen)
        llama = texts.get(LLAMA_BINDING).decode("utf-8")
        self.assertIn(llama, screen)
        for advisory in record.advisories:
            self.assertIn(f"advisory:{advisory.id}", screen)
        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        notice = texts.get(record.text_sha256)
        body = b'{"stub": true}'
        url = upstream.add("/config.json", body)
        mapping = make_files_asset(
            asset_id="fixture-bitnet",
            files={"config.json": (url, body)},
            license_record=record,
            notice=notice,
            licensors=["Microsoft Corporation"],
            provider="kilix-bonsai",
            consumer_schema="kilix.bonsai.runtime",
            notice_path="notices/LICENSE-mit.txt",
            license_id="mit",
        )
        fixture = AssetSpec.from_mapping(mapping)
        result = install_with_agreement(
            fixture,
            installer=installer,
            store=store,
            records=self.records,
            texts=texts,
            typed_text=typed_agreement_line(record),
            screen=io.BytesIO(),
        )
        self.assertIsNotNone(result)
        receipts = list(store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = parse_receipt_bytes(receipts[0].read_bytes())
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt.decision, "accept")
        self.assertEqual(
            receipt.binding_condition_text_digests["llama3-community-licence-full-text"],
            LLAMA_BINDING,
        )
        self.assertIn(LLAMA_BINDING, payload["binding_condition_text_digests"].values())
        self.assertNotIn("advisory_digests", payload)
        for advisory in record.advisories:
            self.assertEqual(
                payload["context"]["advisory_digests"][advisory.id],
                advisory.text_sha256,
            )
            self.assertNotIn(advisory.text_sha256, payload["binding_condition_text_digests"].values())
        upstream.close()

    def test_planted_aup_omission_fails(self) -> None:
        record = self.records.by_id("bitnet-b1.58-2b4t")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-aup-plant-"))
        texts = load_determined_texts(scratch / "texts")
        full = texts.get(LLAMA_BINDING)
        omitted = full.split(b"Meta Llama 3 Acceptable Use Policy")[0]
        self.assertTrue(omitted)
        self.assertNotIn(b"Meta Llama 3 Acceptable Use Policy", omitted)
        planted = _sha(omitted)
        self.assertNotEqual(planted, LLAMA_BINDING)
        spec = self.catalog.require_asset("bitnet-b1.58-2b4t")
        agreement = capture_agreement(record, typed_agreement_line(record))
        planted_agreement = capture_agreement(record, typed_agreement_line(record))
        planted_agreement = planted_agreement.__class__(
            licence_id=planted_agreement.licence_id,
            named_binding_ids=planted_agreement.named_binding_ids,
            decision=planted_agreement.decision,
            typed_text=planted_agreement.typed_text,
            record_digest=planted_agreement.record_digest,
            binding_condition_text_digests={
                "llama3-community-licence-full-text": planted
            },
        )
        with self.assertRaises(AgreementRequired):
            receipt_from_agreement(
                record,
                planted_agreement,
                manifest_digest=spec.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        honest = receipt_from_agreement(
            record,
            agreement,
            manifest_digest=spec.manifest_digest,
            release_digest=release_digest(),
            catalogue_digest=_CATALOG_SHA256,
        )
        self.assertEqual(
            honest.binding_condition_text_digests["llama3-community-licence-full-text"],
            LLAMA_BINDING,
        )

    def test_registry_flipped_blob_refused_before_publish(self) -> None:
        spec = self.catalog.require_asset("granite4.1-3b")
        record = self.records.by_id("granite4.1:3b")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-registry-flip-"))
        texts = load_determined_texts(scratch / "texts")
        notice = texts.get(record.text_sha256)
        upstream = FakeUpstream()
        blob = b"blob-one"
        manifest = b'{"schemaVersion":2}'
        blob_url = upstream.add("/blob", blob + b"X")
        man_url = upstream.add("/manifest.json", manifest)
        mapping = {
            "compatibility": {
                "consumer_schema": "kilix.ollama.runtime",
                "maximum": 1,
                "minimum": 1,
            },
            "files": [
                {"bytes": len(blob), "path": "blobs/model", "sha256": _sha(blob)},
                {
                    "bytes": len(notice),
                    "path": "notices/LICENSE-apache-2.0.txt",
                    "sha256": _sha(notice),
                },
            ],
            "id": "fixture-granite-flip",
            "label": "granite4.1:3b",
            "licenses": [
                {
                    "decision": "affirmative",
                    "id": "apache-2.0",
                    "licensors": ["IBM"],
                    "record_digest": record.digest,
                    "text_sha256": record.text_sha256,
                }
            ],
            "provider": "kilix-ollama",
            "schema": "kilix.content.asset/v3",
            "sizes": {
                "download_bytes": len(manifest),
                "installed_bytes": len(blob) + len(notice),
                "temporary_bytes": len(manifest) + len(blob) + len(notice),
            },
            "source": {
                "blobs": [{"path": "blobs/model", "url": blob_url}],
                "manifest_sha256": _sha(manifest),
                "manifest_url": man_url,
                "mode": "registry-manifest",
                "provenance": {
                    "original_url": man_url,
                    "project": "example/registry",
                    "revision": "1",
                },
            },
            "stream": "F104",
            "version": "1",
        }
        fixture = AssetSpec.from_mapping(mapping)
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        agreement = capture_agreement(record, typed_agreement_line(record))
        store.write(
            receipt_from_agreement(
                record,
                agreement,
                manifest_digest=fixture.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        )
        with self.assertRaises(Exception):
            installer.ensure_upstream_asset(
                fixture, store=store, records=self.records, notices=texts
            )
        self.assertFalse(Path(installer.asset_destination(fixture)).exists())
        upstream.close()
        self.assertEqual(spec.source_mode, "registry-manifest")

    def test_pocket_first_use_quotes_prohibited_use_and_names_card(self) -> None:
        spec = self.catalog.require_asset("pocket-tts-english-q8_0")
        record = self.records.by_id("pocket-tts-english-q8_0")
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-pocket-screen-"))
        texts = load_determined_texts(scratch / "texts")
        screen = present_asset(spec, record, texts).decode("utf-8")
        prohibited = texts.get(PROHIBITED).decode("utf-8")
        self.assertIn(prohibited, screen)
        self.assertIn("## Prohibited use", screen)
        self.assertIn("binding:pocket-prohibited-use", screen)
        self.assertIn("cc-by-4.0", screen)
        self.assertIn("Kyutai", screen)
        self.assertIn(CARD_SHA256, json.dumps(spec.to_mapping()))
        self.assertNotEqual(screen.strip(), POCKET_TERMS_SUMMARY)
        self.assertNotIn(POCKET_TERMS_SUMMARY, prohibited)
        if POCKET_TERMS_SUMMARY in screen:
            self.fail("first-use screen planted the TERMS_SUMMARY paraphrase")
        upstream = FakeUpstream()
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        notice = texts.get(record.text_sha256)
        payloads = {
            "languages/english/model.safetensors": b"safetensors-stub",
            "languages/english/tokenizer.model": b"tok-stub",
            "README.md": b"card-stub",
        }
        files = {
            path: (upstream.add("/" + path, body), body) for path, body in payloads.items()
        }
        mapping = make_convert_asset(
            asset_id="fixture-pocket",
            input_path="languages/english/model.safetensors",
            files=files,
            license_record=record,
            notice=notice,
            licensors=["Kyutai"],
            argv=["/bin/true"],
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
        payload = json.loads(receipts[0].read_text(encoding="utf-8"))
        self.assertEqual(receipt.decision, "accept")
        self.assertEqual(
            receipt.binding_condition_text_digests["pocket-prohibited-use"],
            PROHIBITED,
        )
        self.assertEqual(receipt.manifest_digest, fixture.manifest_digest)
        self.assertEqual(members_card(spec), CARD_SHA256)
        self.assertTrue(CARD_SHA256.startswith("ae2ebac6"))
        self.assertIn(CARD_SHA256, json.dumps(spec.to_mapping()))
        gotten = {
            item.get("path")
            for item in upstream.requests()
            if item.get("command") == "GET"
        }
        self.assertEqual(
            gotten,
            {
                "/languages/english/model.safetensors",
                "/languages/english/tokenizer.model",
                "/README.md",
            },
        )
        self.assertFalse(any("embeddings" in path for path in gotten))
        root = Path(result[0])
        self.assertTrue((root / "languages/english/model.safetensors").is_file())
        self.assertTrue((root / "README.md").is_file())
        self.assertFalse(any(path.suffix == ".gguf" for path in root.rglob("*")))
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


def members_card(spec: AssetSpec) -> str:
    return next(item.sha256 for item in spec.files if item.path == "README.md")
