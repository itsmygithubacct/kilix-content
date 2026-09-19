"""Catalog records for the kilix-pdf-conversion [granite] engine models (R4-066, OD-AY).

The owner determined three models and only three: P1 Granite-Docling 258M, N1
DocumentFigureClassifier v2.5 and N2 Granite Vision 4.1 4B
(`licence-evidence-pdf-engines-2026-09-15/OWNER-DETERMINATION-pdf-engines.md`).
The Datalab/Surya checkpoints P2-P6, marker's render font, and N3 and N4 are
not determined and must not appear here.

Each record lists every file the extra actually loads. docling asks
huggingface_hub for a whole-repository snapshot at the pinned revision
(`models/utils/hf_model_download.py` passes no `allow_patterns`), for the VLM
convert stage (P1), the picture-classification stage (N1, which defaults to the
transformers engine) and the chart-extraction stage (N2). So the file list is
the repository tree at the pin, and every digest in it is non-null.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from fake_store import FakeStore
from kilix_license.catalog import load_determined_records, load_determined_texts
from screen_marker import changed_block

from kilix_content import default_catalog
from kilix_content.first_use import license_record_for, present_asset
from kilix_content.model import _is_kilix_hosted

ROOT = Path(__file__).resolve().parents[1]
DETERMINATIONS = (
    ROOT
    / "third_party"
    / "kilix-license"
    / "src"
    / "kilix_license"
    / "data"
    / "determinations.json"
)
CATALOG_JSON = ROOT / "src" / "kilix_content" / "catalog" / "plebian.json"
PIN_DIR = ROOT / "tools" / "upstream-pins"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

APACHE_TEXT = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
MIT_TEXT = "b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5"

MODELS = {
    "granite-docling-258m": {
        "record": "granite-docling-258m",
        "project": "ibm-granite/granite-docling-258M",
        "revision": "982fe3b40f2fa73c365bdb1bcacf6c81b7184bfe",
        "files": 17,
        "licence": "apache-2.0",
        "licensor": "IBM",
        "text": APACHE_TEXT,
        "notice": "notices/LICENSE-apache-2.0.txt",
        "reached": "default",
        "statements": 2,
        "weights": ("model.safetensors",),
    },
    "documentfigureclassifier-v2.5": {
        "record": "documentfigureclassifier-v2.5",
        "project": "docling-project/DocumentFigureClassifier-v2.5",
        "revision": "f859dfbff5c9916cd996942d4b0db7fa25808220",
        "files": 8,
        "licence": "mit",
        "licensor": "docling-project",
        "text": MIT_TEXT,
        "notice": "notices/LICENSE-mit.txt",
        "reached": "--chart-extraction",
        "statements": 1,
        # The snapshot carries both; the transformers engine (the preset's
        # default) loads model.safetensors, the ONNX engine model.onnx.
        "weights": ("model.safetensors", "model.onnx"),
    },
    "granite-vision-4.1-4b": {
        "record": "granite-vision-4.1-4b",
        "project": "ibm-granite/granite-vision-4.1-4b",
        "revision": "dd48e97503de471803850df70843cf9eb5da8712",
        "files": 30,
        "licence": "apache-2.0",
        "licensor": "IBM",
        "text": APACHE_TEXT,
        "notice": "notices/LICENSE-apache-2.0.txt",
        "reached": "--chart-extraction",
        "statements": 3,
        "weights": (
            "model-00001-of-00002.safetensors",
            "model-00002-of-00002.safetensors",
        ),
    },
}
REMOTE_CODE = ("configuration.py", "downsampling.py", "modeling.py", "processing.py")
# Refused in 0.2.2 (OD-AY): not determined, and no record may name them.
REFUSED_STRINGS = (
    "models.datalab.to",
    "datalab",
    "surya",
    "text_recognition/2025_09_23",
    "layout/2025_09_23",
    "text_detection/2025_05_07",
    "table_recognition/2025_02_18",
    "ocr_error_detection/2025_02_18",
    "gonotocurrent",
    "marker-pdf",
    "granite-vision-3.3-2b-chart2csv-preview",
    "granite-docling-258m-mlx",
    "vikp",
    "texify",
)


def _pin(asset_id: str) -> dict:
    return json.loads((PIN_DIR / f"{asset_id}.json").read_text(encoding="utf-8"))


def _determination(entry_id: str) -> dict:
    data = json.loads(DETERMINATIONS.read_text(encoding="utf-8"))
    return next(item for item in data["entries"] if item["entry_id"] == entry_id)


class PdfEngineRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_one_record_per_determined_model_and_no_others(self) -> None:
        pdf = [
            spec
            for spec in self.catalog.assets
            if spec.provider == "kilix-pdf-conversion"
        ]
        self.assertEqual(sorted(spec.asset_id for spec in pdf), sorted(MODELS))
        for asset_id, expected in MODELS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(expected["record"])
            with self.subTest(asset=asset_id):
                self.assertEqual(spec.source_mode, "upstream-files")
                self.assertEqual(spec.consumer_schema, "kilix.pdf-conversion.runtime")
                self.assertEqual(spec.version, expected["revision"])
                self.assertEqual(spec.provenance_revision, expected["revision"])
                self.assertEqual(spec.provenance_project, expected["project"])
                self.assertEqual(spec.source_host, "huggingface.co")
                self.assertEqual(spec.licenses[0].record_digest, record.digest)
                self.assertIn(expected["reached"], spec.label)
                self.assertTrue(spec.label.startswith(asset_id), spec.label)

    def test_every_digest_is_non_null_and_equal_to_the_pin(self) -> None:
        for asset_id, expected in MODELS.items():
            spec = self.catalog.require_asset(asset_id)
            pin = _pin(asset_id)
            with self.subTest(asset=asset_id):
                self.assertEqual(len(pin["members"]), expected["files"])
                members = {
                    item.path: item
                    for item in spec.files
                    if not item.path.startswith("notices/")
                }
                pinned = {item["path"]: item for item in pin["members"]}
                self.assertEqual(set(members), set(pinned))
                self.assertEqual(len(spec.files), expected["files"] + 1)
                for path, item in members.items():
                    self.assertIsNotNone(item.sha256, f"{asset_id}:{path}")
                    self.assertTrue(_HEX64.fullmatch(item.sha256), f"{asset_id}:{path}")
                    self.assertEqual(item.sha256, pinned[path]["sha256"], path)
                    self.assertEqual(item.bytes, pinned[path]["bytes"], path)
                for weight in expected["weights"]:
                    self.assertIn(weight, members)
                self.assertEqual(
                    spec.download_bytes,
                    sum(item["bytes"] for item in pin["members"]),
                )
                fetch = {item.path: item.url for item in spec.fetch}
                self.assertEqual(set(fetch), set(pinned))
                for path, url in fetch.items():
                    parsed = urlsplit(url)
                    self.assertEqual(parsed.hostname, "huggingface.co")
                    self.assertEqual(
                        parsed.path,
                        f"/{expected['project']}/resolve/{expected['revision']}/{path}",
                    )
                    self.assertFalse(_is_kilix_hosted(url), url)
                packed = json.dumps(spec.to_mapping()).lower()
                self.assertNotIn("itsmygithubacct", packed)
                self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_pins_agree_with_the_kilix_license_determination(self) -> None:
        for asset_id, expected in MODELS.items():
            pin = _pin(asset_id)
            entry = _determination(expected["record"])
            upstream = entry["upstream"]
            members = {item["path"]: item for item in pin["members"]}
            with self.subTest(asset=asset_id):
                self.assertEqual(entry["status"], "DETERMINED")
                self.assertEqual(upstream["mode"], "upstream-files")
                self.assertEqual(upstream["project"], expected["project"])
                self.assertEqual(upstream["revision"], expected["revision"])
                base = (
                    f"https://huggingface.co/{expected['project']}"
                    f"/resolve/{expected['revision']}"
                )
                self.assertEqual(upstream["url_base"], base)
                for listed in upstream.get("files", []):
                    self.assertEqual(
                        members[listed["path"]]["sha256"], listed["sha256"]
                    )
                    self.assertEqual(members[listed["path"]]["bytes"], listed["bytes"])
                record = self.records.by_id(expected["record"])
                self.assertEqual(
                    [name["name"] for name in entry["licensors"]], [record.licensor]
                )
                self.assertEqual(list(record.licence_ids), entry["licence"]["spdx"])

    def test_licence_rows_name_the_owner_determination(self) -> None:
        for asset_id, expected in MODELS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(expected["record"])
            with self.subTest(asset=asset_id):
                self.assertEqual(len(spec.licenses), 1)
                row = spec.licenses[0]
                self.assertEqual(row.license_id, expected["licence"])
                self.assertEqual(row.decision, "affirmative")
                self.assertEqual(row.licensors, (expected["licensor"],))
                self.assertEqual(row.text_sha256, expected["text"])
                self.assertEqual(record.text_sha256, expected["text"])
                self.assertEqual(record.licensor, expected["licensor"])
                self.assertEqual(record.binding_conditions, ())
                self.assertEqual(len(record.statements), expected["statements"])
                notices = {
                    item.path: item
                    for item in spec.files
                    if item.path.startswith("notices/")
                }
                self.assertEqual(set(notices), {expected["notice"]})
                self.assertEqual(notices[expected["notice"]].sha256, expected["text"])

    def test_the_first_use_screen_names_the_model_licence_and_card_statements(
        self,
    ) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-pdf-screen-"))
        texts = load_determined_texts(scratch / "texts")
        store = FakeStore(scratch / "receipts")
        for asset_id, expected in MODELS.items():
            spec = self.catalog.require_asset(asset_id)
            record = license_record_for(spec, self.records)
            with self.subTest(asset=asset_id):
                screen = present_asset(
                    spec, record, texts, receipts=store, records=self.records
                )
                self.assertIn(f"id: {asset_id}\n".encode("utf-8"), screen)
                self.assertIn(
                    f"version: {expected['revision']}\n".encode("utf-8"), screen
                )
                self.assertIn(b"host: huggingface.co\n", screen)
                self.assertIn(
                    f"licence: {expected['licence']}\n".encode("utf-8"), screen
                )
                self.assertIn(
                    f"licensors: {expected['licensor']}\n".encode("utf-8"), screen
                )
                self.assertIn(b"decision: affirmative\n", screen)
                self.assertIn(texts.get(expected["text"]), screen)
                for statement in record.statements:
                    self.assertIn(
                        f"=== statement:{statement.id} ===".encode("utf-8"), screen
                    )
                    self.assertIn(texts.get(statement.text_sha256), screen)
                self.assertEqual(changed_block(screen), [])
                self.assertNotIn(b"=== binding:", screen)

    def test_the_granite_vision_record_pins_the_code_it_runs(self) -> None:
        """N2 loads repository Python with trust_remote_code=True (OD-AY)."""
        asset_id = "granite-vision-4.1-4b"
        spec = self.catalog.require_asset(asset_id)
        pin = _pin(asset_id)
        self.assertEqual(tuple(pin["remote_code"]), REMOTE_CODE)
        members = {item.path: item for item in spec.files}
        for path in REMOTE_CODE:
            self.assertIn(path, members, path)
            self.assertTrue(_HEX64.fullmatch(members[path].sha256), path)
            self.assertGreater(members[path].bytes, 0)
        # The screen says so: the label is the first line the user reads.
        self.assertIn("trust_remote_code=True", spec.label)
        entry = _determination("granite-vision-4.1-4b")
        self.assertIn("trust_remote_code=True", entry["upstream"]["files_note"])
        for path in REMOTE_CODE:
            self.assertIn(path, entry["upstream"]["files_note"])

    def test_no_undetermined_pdf_engine_model_is_in_the_catalog(self) -> None:
        """P2-P6, the marker font, N3 and N4 are refused in 0.2.2 (OD-AY)."""
        catalog = CATALOG_JSON.read_text(encoding="utf-8").lower()
        for needle in REFUSED_STRINGS:
            self.assertNotIn(needle, catalog, needle)
        pins = sorted(path.name for path in PIN_DIR.glob("*.json"))
        for name in pins:
            text = (PIN_DIR / name).read_text(encoding="utf-8").lower()
            for needle in REFUSED_STRINGS:
                self.assertNotIn(needle, text, f"{name}:{needle}")
        self.assertEqual(
            sorted(
                spec.asset_id
                for spec in self.catalog.assets
                if "granite" in spec.asset_id or "document" in spec.asset_id
            ),
            [
                "documentfigureclassifier-v2.5",
                "granite-docling-258m",
                "granite-vision-4.1-4b",
                "granite3.2-vision-2b",
                "granite4.1-3b",
            ],
        )
        # A planted uncatalogued model is refused by kilix-pdf-conversion's own
        # routing tests (R4-107, PDF1); nothing here can refuse a download.
        self.assertEqual(
            [
                spec.asset_id
                for spec in self.catalog.assets
                if spec.provider == "kilix-pdf-conversion"
            ],
            ["granite-docling-258m", "documentfigureclassifier-v2.5", "granite-vision-4.1-4b"],
        )

    def test_every_pinned_member_is_guarded_against_landing_in_git(self) -> None:
        """No weights in git: each member digest is in the weight-guard list."""
        from weight_scan import load_catalog_digests

        _text, guarded = load_catalog_digests(
            ROOT / "tests" / "data" / "catalog_digests.txt"
        )
        for asset_id, expected in MODELS.items():
            spec = self.catalog.require_asset(asset_id)
            with self.subTest(asset=asset_id):
                for item in spec.files:
                    if item.path.startswith("notices/"):
                        # Licence text, not a model file (C1-VERIFY F-01).
                        self.assertNotIn(item.sha256, guarded, item.path)
                        continue
                    self.assertIn(item.sha256, guarded, item.path)
                for weight in expected["weights"]:
                    digest = next(
                        item.sha256 for item in spec.files if item.path == weight
                    )
                    self.assertIn(digest, guarded, weight)


if __name__ == "__main__":
    unittest.main()
