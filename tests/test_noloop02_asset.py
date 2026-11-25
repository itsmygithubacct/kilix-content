"""qwen-0.8b-no-loop-02 is one GGUF from the kilix-llm release with Apache-2.0 and CC BY 4.0 rows."""
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from kilix_license.agreement import typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.noloop02 import APACHE, CC_BY, COMPONENT, EDIT_LICENSOR, SOURCE, SOURCE_LICENCE, generate_noloop02_records
from kilix_license.receipts import parse_receipt_bytes
from kilix_license.standard_policy import standard_policy_eligible

from fake_store import FakeStore
from first_use_fixture import FakeUpstream
from kilix_content import verified_packaged_catalog
from kilix_content.first_use import install_with_agreement, present_asset
from kilix_content.install import Installer
from kilix_content.model import AssetSpec, CatalogError

ROOT = Path(__file__).resolve().parents[1]
ID = "qwen-0.8b-no-loop-02"
GGUF = "qwen-0.8b-no-loop-02.gguf"
GGUF_SHA = "e4d6e93eb644da62e0c5ac0b7b188b4c2cbf31f07a7dcfd42764b6236f96d8a0"
GGUF_BYTES = 833592416
# The kilix-llm commit the qwen-0.8b-no-loop-02 release tag points at (the
# base of the commit that catalogues the model), as for kilix-female-02.
REVISION = "4267e55277de7ab3d3380a561a1f5f0d58261f18"
NOTICES = {
    "notices/LICENSE-apache-2.0.txt": APACHE,
    "notices/LICENSE-cc-by-4.0.txt": CC_BY,
    "notices/LICENSE-lm_understand-logs.txt": SOURCE_LICENCE,
    "notices/modified-model.txt": "2569309df198a85501c07065c837ecf18d48a0387208cfdb755702f3be2d9b44",
    "notices/weight-edit-attribution.txt": "a4e74ed6c5f68677ebe95445696de6d9e2f789b5f63184d95a7a70a5f8cd962f",
}


def _raw():
    catalog = json.loads((ROOT / "src/kilix_content/catalog/plebian.json").read_bytes())
    return next(asset for asset in catalog["assets"] if asset["id"] == ID)


class NoLoop02AssetTests(unittest.TestCase):
    def setUp(self):
        self.records = load_determined_records()
        self.record = self.records.by_id(ID)

    def test_one_gguf_from_the_kilix_llm_release(self):
        spec = verified_packaged_catalog().require_asset(ID)
        self.assertEqual((spec.provider, spec.consumer_schema), ("kilix-llm", "kilix.llm.models/v1"))
        self.assertEqual(spec.source_mode, "upstream-files")
        self.assertEqual(spec.version, ID)
        self.assertEqual(spec.install_name, ID)
        self.assertEqual((spec.provenance_project, spec.provenance_revision),
                         ("itsmygithubacct/kilix-llm", REVISION))
        self.assertEqual(spec.provenance_url, SOURCE)
        self.assertEqual(spec.download_bytes, GGUF_BYTES)
        self.assertEqual([(item.path, item.url) for item in spec.fetch], [(GGUF, SOURCE)])
        weights = next(item for item in spec.files if item.path == GGUF)
        self.assertEqual((weights.bytes, weights.sha256), (GGUF_BYTES, GGUF_SHA))
        pin = json.loads((ROOT / "tools/upstream-pins" / (ID + ".json")).read_bytes())
        self.assertEqual(pin["members"], [{"path": GGUF, "url": SOURCE, "bytes": GGUF_BYTES, "sha256": GGUF_SHA}])

    def test_apache_and_cc_by_rows_name_one_record(self):
        spec = verified_packaged_catalog().require_asset(ID)
        rows = [(row.license_id, row.decision, row.licensors, row.record_digest, row.text_sha256)
                for row in spec.licenses]
        self.assertEqual(rows, [
            ("apache-2.0", "affirmative", ("Alibaba Cloud / Qwen",), self.record.digest, APACHE),
            ("cc-by-4.0", "affirmative", (EDIT_LICENSOR,), self.record.digest, CC_BY),
        ])
        records = generate_noloop02_records(ROOT / "third_party/kilix-license/src/kilix_license/data")
        self.assertEqual(records[0].digest, self.record.digest)
        self.assertEqual([(c.id, c.exception_text_sha256) for c in self.record.components], [(COMPONENT, CC_BY)])
        # The owner put this pinned CC BY 4.0 text under the standard
        # distribution policy (2026-11-09), as for kilix-female-02.
        self.assertTrue(standard_policy_eligible(self.record))

    def test_notices_are_the_record_texts(self):
        spec = verified_packaged_catalog().require_asset(ID)
        notices = {item.path: item.sha256 for item in spec.files if item.path.startswith("notices/")}
        self.assertEqual(notices, NOTICES)
        shown = {self.record.text_sha256, *(c.exception_text_sha256 for c in self.record.components),
                 *(s.text_sha256 for s in self.record.statements)}
        self.assertEqual(set(notices.values()), shown)
        texts = ROOT / "third_party/kilix-license/src/kilix_license/data/texts"
        for path, digest in notices.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((texts / digest).read_bytes()).hexdigest(), digest)
        # The notices refer to each other by these names.
        for digest in (NOTICES["notices/modified-model.txt"], NOTICES["notices/weight-edit-attribution.txt"]):
            body = (texts / digest).read_text(encoding="utf-8")
            for name in ("LICENSE-cc-by-4.0.txt", "LICENSE-lm_understand-logs.txt"):
                self.assertIn(name, body)
                self.assertIn("notices/" + name, notices)

    def test_only_this_release_file_is_admitted(self):
        AssetSpec.from_mapping(_raw())
        other = SOURCE.replace(GGUF, "other.gguf")
        for label, change in (
            ("url", lambda raw: raw["source"]["fetch"][0].update(url=other)),
            ("version", lambda raw: raw.update(version="qwen-0.8b-no-loop-03")),
            ("provider", lambda raw: raw.update(provider="kilix-ollama")),
            ("revision", lambda raw: raw["source"]["provenance"].update(revision="0" * 40)),
        ):
            with self.subTest(changed=label):
                raw = copy.deepcopy(_raw())
                change(raw)
                with self.assertRaisesRegex(CatalogError, "upstream"):
                    AssetSpec.from_mapping(raw)

    def test_first_use_screen_receipt_and_notices(self):
        spec = verified_packaged_catalog().require_asset(ID)
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-noloop02-"))
        texts = load_determined_texts(scratch / "texts")
        store = FakeStore(scratch / "receipts")
        screen = present_asset(spec, self.record, texts, receipts=store, records=self.records).decode("utf-8")
        for expected in (ID, SOURCE, str(GGUF_BYTES), "apache-2.0", "cc-by-4.0", "Apache License",
                         "Attribution 4.0 International", "Alibaba Cloud / Qwen", EDIT_LICENSOR,
                         "Copyright 2026 Alibaba Cloud", "exp8_math/runs/p50c/edit",
                         "the edit is scaled to one third (alpha 2 of 6)"):
            self.assertIn(expected, screen)
        # A stub GGUF on a loopback upstream, with the real rows and notices.
        upstream = FakeUpstream()
        self.addCleanup(upstream.close)
        body = b"GGUF-stub"
        url = upstream.add("/" + GGUF, body)
        raw = copy.deepcopy(_raw())
        raw["source"]["fetch"] = [{"path": GGUF, "url": url}]
        raw["source"]["provenance"] = {"original_url": url, "project": "example/files", "revision": "1"}
        raw["id"] = raw["label"] = "fixture-noloop02"
        raw["version"] = "fixture"
        for item in raw["files"]:
            if item["path"] == GGUF:
                item.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        installed = sum(item["bytes"] for item in raw["files"])
        raw["sizes"] = {"download_bytes": len(body), "installed_bytes": installed, "temporary_bytes": installed}
        fixture = AssetSpec.from_mapping(raw)
        installer = Installer(str(scratch / "root"))
        declined = install_with_agreement(fixture, installer=installer, store=store, records=self.records,
                                          texts=texts, typed_text=None, screen=io.BytesIO(), decline=True)
        self.assertIsNone(declined)
        self.assertEqual(list(store.root.glob("*.json")), [])
        self.assertEqual(upstream.requests(), [])
        result = install_with_agreement(fixture, installer=installer, store=store, records=self.records,
                                        texts=texts, typed_text=typed_agreement_line(self.record),
                                        screen=io.BytesIO())
        self.assertIsNotNone(result)
        root = Path(result[0])
        self.assertEqual(root, Path(installer.asset_destination(fixture)))
        self.assertEqual((root / GGUF).read_bytes(), body)
        for path, digest in NOTICES.items():
            with self.subTest(notice=path):
                self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
        receipt, = (parse_receipt_bytes(path.read_bytes()) for path in store.root.glob("*.json"))
        self.assertEqual(receipt.decision, "accept")
        self.assertEqual(receipt.record_digest, self.record.digest)
        self.assertEqual(receipt.licensor, self.record.licensor)
        self.assertEqual(receipt.component_exception_digests, {COMPONENT: CC_BY})
