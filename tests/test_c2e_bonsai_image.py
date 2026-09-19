"""bonsai-image-4b records: Apache-2.0 Prism ML plus the binding BFL Usage Policy (R4-065, OD-AH)."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.coverage import covers
from kilix_license.errors import CoverageRefused
from kilix_license.receipts import parse_receipt_bytes, receipt_from_agreement
from kilix_license.records import BindingCondition, RecordIndex

from fake_store import FakeStore
from first_use_fixture import (
    FakeUpstream,
    make_archive_asset,
    make_files_asset,
    vosk_fixture_zip,
)
from kilix_content import default_catalog
from kilix_content.first_use import (
    changed_binding_conditions,
    install_with_agreement,
    needs_agreement,
    present_asset,
)
from kilix_content.install import Installer
from kilix_content.model import AssetFileSpec, AssetSpec, _is_kilix_hosted
from kilix_content.receipt import _CATALOG_SHA256, release_digest

ROOT = Path(__file__).resolve().parents[1]
DETERMINATIONS = (
    ROOT / "third_party" / "kilix-license" / "src" / "kilix_license" / "data" / "determinations.json"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

TERNARY_REV = "bf047aa80569f193d2c4960033af6ba2629988fa"
BINARY_REV = "121529b06562ff8c5b75aa34c54c371d2655929b"
LICENSE_SHA256 = "69849221bfb90053de2134ef5e6d540287b4b98062326492f1f96f5da685524b"
NOTICE_SHA256 = "bbefa4a26b836efc040c1a0f155a425d1d833eae1b2534ffc414b1eada3cd922"
POLICY_SHA256 = "3fa706724776c03b2b6f2290de4bb09e7ba4dae239dfcfba27bac26f41d86e02"
POLICY_HTML_SHA256 = "699fda151c063c4c2ed55963e75d7aa3623355da5a7d250f00f97a66b0b8eaf8"
SELF_HOSTED_HTML_SHA256 = "e70b8a0260cd25736236197f92b24e9adc0a954b961a3a36074284c18e52a89a"
SELF_HOSTED_TXT_SHA256 = "547f82f179cfd7e8757ccc14ede772263636604399d94dfec8f594675da4b6b1"
POLICY_LINES = 32
POLICY_BYTES = 6525

VARIANTS = {
    "bonsai-image-4b-ternary-gemlite": {
        "record": "bonsai-image-4b:ternary-gemlite",
        "revision": TERNARY_REV,
        "project": "prism-ml/bonsai-image-ternary-4B-gemlite-2bit",
        "policy_id": "bfl-usage-policy",
        "default": True,
    },
    "bonsai-image-4b-binary-gemlite": {
        "record": "bonsai-image-4b:binary-gemlite",
        "revision": BINARY_REV,
        "project": "prism-ml/bonsai-image-binary-4B-gemlite-1bit",
        "policy_id": "bfl-usage-policy-binary",
        "default": False,
    },
}
DEFAULT_ASSET = "bonsai-image-4b-ternary-gemlite"


def _pin(asset_id: str) -> dict:
    path = ROOT / "tools" / "upstream-pins" / f"{asset_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _determination(record_id: str) -> dict:
    data = json.loads(DETERMINATIONS.read_text(encoding="utf-8"))
    return next(item for item in data["entries"] if item["entry_id"] == record_id)


def _one_byte_policy_change(policy: bytes) -> bytes:
    """Change exactly one byte of the displayed policy: the Last Revised day."""
    marker = b"Last Revised on August 4, 2026"
    index = policy.index(marker) + len(b"Last Revised on August ")
    planted = policy[:index] + b"5" + policy[index + 1 :]
    return planted


def _future_schema_receipt(licence_id: str, binding_id: str, digest: str) -> bytes:
    """A receipt a later kilix-license could write: receipt/v1 fields, schema v2."""
    raw = {
        "binding_condition_text_digests": {binding_id: digest},
        "context": {
            "advisory_digests": {},
            "catalogue_digest": "c" * 64,
            "release_digest": "d" * 64,
        },
        "decision": "accept",
        "licence_id": licence_id,
        "licence_text_digest": LICENSE_SHA256,
        "licensor": "Prism ML, Inc.",
        "manifest_digest": "b" * 64,
        "record_digest": "a" * 64,
        "schema": "kilix.license.receipt/v2",
    }
    return json.dumps(raw, sort_keys=True).encode("utf-8") + b"\n"


def _unhashable_decision_receipt() -> bytes:
    raw = json.loads(_future_schema_receipt("x", "y", "e" * 64))
    raw["schema"] = "kilix.license.receipt/v1"
    raw["decision"] = ["accept"]
    return json.dumps(raw, sort_keys=True).encode("utf-8")


# Files a receipt store can hold that this build cannot use (C2E-VERIFY F1).
# None plants a directory. Names sort both before and after a real receipt
# (64 hex characters), so a scan that stops at the first bad file is caught.
JUNK_RECEIPT_FILES: dict[str, bytes | None] = {
    "0000-planted-non-utf8.json": b"\xff\xfe\x00 not a receipt\n",
    "0001-planted-receipt-v2.json": _future_schema_receipt(
        "bonsai-image-4b:ternary-gemlite", "bfl-usage-policy", "e" * 64
    ),
    "zzzz-planted-non-object.json": b"[]\n",
    "zzzz-planted-unhashable-decision.json": _unhashable_decision_receipt(),
    "zzzz-planted-deep-nesting.json": b"[" * 100000,
    "zzzz-planted-directory.json": None,
}


def _plant_junk(root: Path, names: tuple[str, ...] | None = None) -> dict[str, bytes | None]:
    planted = {
        name: payload
        for name, payload in JUNK_RECEIPT_FILES.items()
        if names is None or name in names
    }
    for name, payload in planted.items():
        if payload is None:
            (root / name).mkdir()
        else:
            (root / name).write_bytes(payload)
    return planted


class BonsaiImageRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()

    def test_two_variant_records_with_ternary_default(self) -> None:
        defaults = []
        for asset_id, expected in VARIANTS.items():
            spec = self.catalog.require_asset(asset_id)
            pin = _pin(asset_id)
            record = self.records.by_id(expected["record"])
            self.assertEqual(spec.source_mode, "upstream-files")
            self.assertEqual(spec.provider, "kilix-bonsai")
            self.assertEqual(spec.consumer_schema, "kilix.bonsai.runtime")
            self.assertEqual(spec.version, expected["revision"])
            self.assertEqual(spec.provenance_revision, expected["revision"])
            self.assertEqual(spec.provenance_project, expected["project"])
            self.assertEqual(spec.source_host, "huggingface.co")
            self.assertTrue(spec.label.startswith(expected["record"]))
            self.assertEqual(pin["license_record_id"], expected["record"])
            self.assertEqual(pin["default"], expected["default"])
            self.assertEqual("(default)" in spec.label, expected["default"])
            self.assertEqual(spec.licenses[0].record_digest, record.digest)
            if pin["default"]:
                defaults.append(asset_id)
        self.assertEqual(defaults, [DEFAULT_ASSET])
        self.assertTrue(TERNARY_REV.startswith("bf047aa8"))
        self.assertTrue(BINARY_REV.startswith("121529b0"))

    def test_every_digest_non_null_and_equal_to_the_pin(self) -> None:
        for asset_id, expected in VARIANTS.items():
            spec = self.catalog.require_asset(asset_id)
            pin = _pin(asset_id)
            self.assertEqual(len(pin["members"]), 20)
            members = {
                item.path: item for item in spec.files if not item.path.startswith("notices/")
            }
            pin_members = {item["path"]: item for item in pin["members"]}
            self.assertEqual(set(members), set(pin_members))
            for path, item in members.items():
                self.assertIsNotNone(item.sha256, f"{asset_id}:{path}")
                self.assertTrue(_HEX64.fullmatch(item.sha256), f"{asset_id}:{path}")
                self.assertEqual(item.sha256, pin_members[path]["sha256"])
                self.assertEqual(item.bytes, pin_members[path]["bytes"])
            self.assertEqual(members["LICENSE"].sha256, LICENSE_SHA256)
            self.assertEqual(members["NOTICE.md"].sha256, NOTICE_SHA256)
            self.assertEqual(
                spec.download_bytes, sum(item["bytes"] for item in pin["members"])
            )
            fetch = {item.path: item.url for item in spec.fetch}
            self.assertEqual(set(fetch), set(pin_members))
            for path, url in fetch.items():
                parsed = urlsplit(url)
                self.assertEqual(parsed.hostname, "huggingface.co")
                self.assertTrue(
                    parsed.path.startswith(
                        f"/{expected['project']}/resolve/{expected['revision']}/"
                    ),
                    url,
                )
                self.assertTrue(parsed.path.endswith("/" + path), url)
                self.assertFalse(_is_kilix_hosted(url), url)
            weights = [path for path in members if path.endswith((".pt", ".safetensors"))]
            self.assertEqual(len(weights), 3)
            packed = json.dumps(spec.to_mapping()).lower()
            self.assertNotIn("itsmygithubacct", packed)
            self.assertNotIn("assets-0.2.2-candidate", packed)

    def test_pins_agree_with_the_kilix_license_determination(self) -> None:
        for asset_id, expected in VARIANTS.items():
            pin = _pin(asset_id)
            entry = _determination(expected["record"])
            members = {item["path"]: item for item in pin["members"]}
            upstream = entry["upstream"]
            self.assertEqual(upstream["revision"], expected["revision"])
            self.assertEqual(upstream["project"], expected["project"])
            self.assertEqual(
                members[upstream["manifest"]["path"]]["sha256"],
                upstream["manifest"]["sha256"],
            )
            for listed in upstream["files"]:
                self.assertEqual(members[listed["path"]]["sha256"], listed["sha256"])
                self.assertEqual(members[listed["path"]]["bytes"], listed["bytes"])
            specific = {
                item["field"]: item["value"]
                for item in entry["receipt_binds"]["determination_specific"]
            }
            self.assertEqual(specific["LICENSE sha256 (from manifest.json)"], LICENSE_SHA256)
            self.assertEqual(specific["NOTICE.md sha256 (from manifest.json)"], NOTICE_SHA256)
            self.assertEqual(
                specific["displayed BFL Usage Policy text sha256 (lines 10-41)"],
                POLICY_SHA256,
            )

    def test_licence_is_apache_prism_with_flux_and_qwen_components(self) -> None:
        for asset_id, expected in VARIANTS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(expected["record"])
            self.assertEqual(len(spec.licenses), 1)
            row = spec.licenses[0]
            self.assertEqual(row.license_id, "apache-2.0")
            self.assertEqual(row.decision, "affirmative")
            self.assertEqual(row.licensors, ("Prism ML, Inc.",))
            self.assertEqual(row.text_sha256, LICENSE_SHA256)
            self.assertEqual(record.licensor, "Prism ML, Inc.")
            self.assertEqual(record.licence_ids, ("Apache-2.0",))
            self.assertEqual(record.text_sha256, LICENSE_SHA256)
            self.assertEqual(
                [item.id for item in record.components],
                ["flux.2-klein-4b", "qwen3-4b-text-encoder"],
            )
            self.assertEqual(
                [(item.id, item.text_sha256) for item in record.binding_conditions],
                [(expected["policy_id"], POLICY_SHA256)],
            )
            self.assertTrue(record.binding_conditions[0].agreement_required)
            self.assertEqual(record.expected_decision, "accept")
            notices = {item.path: item for item in spec.files if item.path.startswith("notices/")}
            self.assertEqual(set(notices), {"notices/LICENSE-apache-2.0.txt"})
            self.assertEqual(notices["notices/LICENSE-apache-2.0.txt"].sha256, LICENSE_SHA256)

    def test_screen_quotes_policy_in_full_with_notice_and_licence(self) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-bonsai-image-screen-"))
        texts = load_determined_texts(scratch / "texts")
        policy = texts.get(POLICY_SHA256)
        self.assertEqual(len(policy), POLICY_BYTES)
        lines = policy.split(b"\n")
        self.assertEqual(len(lines), POLICY_LINES)
        self.assertEqual(lines[0], b"Usage Policy")
        self.assertEqual(lines[1], b"Last Revised on August 4, 2026")
        self.assertTrue(lines[-1].endswith(b"legal@blackforestlabs.ai."))
        for chrome in (b"Contact Sales", b"All rights reserved", b"BLACK FOREST LABS.", b"Imprint"):
            self.assertNotIn(chrome, policy)
        for asset_id, expected in VARIANTS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(expected["record"])
            screen = present_asset(spec, record, texts)
            section = f"=== binding:{expected['policy_id']} ===\n".encode("utf-8")
            self.assertIn(section + policy + b"\n", screen)
            self.assertIn(b"Last Revised on August 4, 2026", screen)
            self.assertIn(f"licence:{expected['record']}".encode("utf-8"), screen)
            self.assertIn(texts.get(LICENSE_SHA256), screen)
            self.assertIn(b"licensors: Prism ML, Inc.", screen)
            self.assertIn(b"licence: apache-2.0", screen)
            statement = record.statements[0]
            notice_text = texts.get(statement.text_sha256)
            self.assertEqual(_sha(notice_text + b"\n"), NOTICE_SHA256)
            self.assertIn(notice_text + b"\n", screen)
            self.assertIn(
                b"FLUX.2 [klein] 4B, Copyright 2026 Black Forest Labs", screen
            )
            self.assertIn(b"Qwen3-4B, Copyright 2024 Alibaba Cloud", screen)
            for advisory in record.advisories:
                self.assertIn(f"advisory:{advisory.id}".encode("utf-8"), screen)
            self.assertNotIn(b"=== changed since your last acceptance ===", screen)

    def test_self_hosted_commercial_terms_do_not_apply(self) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-bonsai-image-selfhosted-"))
        texts = load_determined_texts(scratch / "texts")
        for asset_id, expected in VARIANTS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(expected["record"])
            screen = present_asset(spec, record, texts)
            for phrase in (b"Self-Hosted", b"FLUX [dev]", b"Commercial License Terms"):
                self.assertNotIn(phrase, screen)
            referenced = {record.text_sha256}
            referenced.update(item.text_sha256 for item in record.binding_conditions)
            referenced.update(item.text_sha256 for item in record.advisories)
            referenced.update(item.text_sha256 for item in record.statements)
            for digest in (SELF_HOSTED_HTML_SHA256, SELF_HOSTED_TXT_SHA256, POLICY_HTML_SHA256):
                self.assertNotIn(digest, referenced)
            packed = json.dumps(spec.to_mapping())
            self.assertNotIn("self-hosted", packed.lower())
            self.assertNotIn(SELF_HOSTED_HTML_SHA256, packed)
            entry = _determination(expected["record"])
            roles = {item["sha256"]: item["role"] for item in entry["licence_texts"]}
            self.assertNotIn(SELF_HOSTED_HTML_SHA256, roles)
            self.assertNotIn(SELF_HOSTED_TXT_SHA256, roles)

    def test_receipt_binds_licence_notice_and_displayed_policy(self) -> None:
        for asset_id, expected in VARIANTS.items():
            spec = self.catalog.require_asset(asset_id)
            record = self.records.by_id(expected["record"])
            agreement = capture_agreement(record, typed_agreement_line(record))
            receipt = receipt_from_agreement(
                record,
                agreement,
                manifest_digest=spec.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
            self.assertEqual(receipt.licence_text_digest, LICENSE_SHA256)
            self.assertEqual(
                receipt.binding_condition_text_digests,
                {expected["policy_id"]: POLICY_SHA256},
            )
            listed = {item.path: item.sha256 for item in spec.files}
            self.assertEqual(listed["LICENSE"], LICENSE_SHA256)
            self.assertEqual(listed["NOTICE.md"], NOTICE_SHA256)
            files_payload = json.dumps(
                [item.to_mapping() for item in spec.files],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(receipt.manifest_digest, _sha(files_payload))
            self.assertTrue(covers(record, receipt, manifest_digest=spec.manifest_digest))
            bound = json.dumps(
                {key: value for key, value in receipt.to_jsonable().items() if key != "context"}
            )
            self.assertIn(POLICY_SHA256, bound)
            self.assertNotIn(POLICY_HTML_SHA256, bound)
            self.assertNotIn(POLICY_HTML_SHA256, json.dumps(receipt.to_jsonable()))
            for member, digest in (("NOTICE.md", NOTICE_SHA256), ("LICENSE", LICENSE_SHA256)):
                flipped = digest[:-1] + ("0" if digest[-1] != "0" else "1")
                files = tuple(
                    AssetFileSpec(item.path, item.bytes, flipped)
                    if item.path == member
                    else item
                    for item in spec.files
                )
                changed_spec = dataclasses.replace(spec, files=files)
                self.assertNotEqual(changed_spec.manifest_digest, spec.manifest_digest)
                with self.assertRaises(CoverageRefused) as caught:
                    covers(record, receipt, manifest_digest=changed_spec.manifest_digest)
                self.assertEqual(caught.exception.field, "manifest_digest")

    def test_source_html_is_provenance_not_coverage(self) -> None:
        for expected in VARIANTS.values():
            entry = _determination(expected["record"])
            context = entry["receipt_binds"]["acceptance_context_not_coverage"]
            provenance = [
                item
                for item in context
                if isinstance(item, dict) and item.get("kind") == "provenance"
            ]
            self.assertEqual(len(provenance), 1)
            self.assertEqual(provenance[0]["value"], POLICY_HTML_SHA256)
            self.assertTrue(POLICY_HTML_SHA256.startswith("699fda15"))
            roles = {item["sha256"]: item["role"] for item in entry["licence_texts"]}
            self.assertEqual(roles[POLICY_HTML_SHA256], "binding-condition-source")
            binding = entry["binding_conditions"][0]
            self.assertEqual(binding["text_sha256"], POLICY_SHA256)
            self.assertEqual((binding["line_start"], binding["line_end"]), (10, 41))


class BonsaiImagePolicyChangeTests(unittest.TestCase):
    """OD-AH: a changed policy is presented as changed and never silently accepted."""

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-bonsai-image-policy-"))
        self.upstream = FakeUpstream()
        self.records = load_determined_records()
        self.texts = load_determined_texts(self.scratch / "texts")
        self.store = FakeStore(self.scratch / "receipts")
        self.installer = Installer(str(self.scratch / "root"))
        self.record = self.records.by_id("bonsai-image-4b:ternary-gemlite")
        self.policy = self.texts.get(POLICY_SHA256)
        licence = self.texts.get(LICENSE_SHA256)
        notice = self.texts.get(self.record.statements[0].text_sha256) + b"\n"
        self.assertEqual(_sha(licence), LICENSE_SHA256)
        self.assertEqual(_sha(notice), NOTICE_SHA256)
        payloads = {
            "LICENSE": licence,
            "NOTICE.md": notice,
            "transformer-gemlite-int2/config.json": b'{"stub": true}',
        }
        self.files = {
            path: (self.upstream.add("/" + path, body), body)
            for path, body in payloads.items()
        }

    def tearDown(self) -> None:
        self.upstream.close()

    def _fixture(self, record, asset_id: str = "fixture-bonsai-image") -> AssetSpec:
        mapping = make_files_asset(
            asset_id=asset_id,
            files=self.files,
            license_record=record,
            notice=self.texts.get(record.text_sha256),
            licensors=["Prism ML, Inc."],
            provider="kilix-bonsai",
            consumer_schema="kilix.bonsai.runtime",
        )
        return AssetSpec.from_mapping(mapping)

    def _planted_record(self):
        planted = _one_byte_policy_change(self.policy)
        self.assertEqual(len(planted), len(self.policy))
        self.assertEqual(
            sum(1 for left, right in zip(planted, self.policy) if left != right), 1
        )
        digest = self.texts.put(planted, label="planted-policy")
        self.assertNotEqual(digest, POLICY_SHA256)
        condition = self.record.binding_conditions[0]
        changed = dataclasses.replace(
            self.record,
            binding_conditions=(
                BindingCondition(
                    id=condition.id,
                    text_sha256=digest,
                    agreement_required=condition.agreement_required,
                ),
            ),
        )
        self.assertEqual(changed.id, self.record.id)
        self.assertNotEqual(changed.digest, self.record.digest)
        return planted, digest, changed

    def _accept_original(self) -> AssetSpec:
        spec = self._fixture(self.record)
        self.assertTrue(needs_agreement(spec, records=self.records, store=self.store))
        result = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=self.records,
            texts=self.texts,
            typed_text=typed_agreement_line(self.record),
            screen=io.BytesIO(),
        )
        self.assertIsNotNone(result)
        receipts = list(self.store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = parse_receipt_bytes(receipts[0].read_bytes())
        self.assertEqual(receipt.binding_condition_text_digests, {"bfl-usage-policy": POLICY_SHA256})
        self.assertEqual(receipt.licence_text_digest, LICENSE_SHA256)
        self.assertEqual(receipt.manifest_digest, spec.manifest_digest)
        listed = {item.path: item.sha256 for item in spec.files}
        self.assertEqual(listed["LICENSE"], LICENSE_SHA256)
        self.assertEqual(listed["NOTICE.md"], NOTICE_SHA256)
        self.assertFalse(needs_agreement(spec, records=self.records, store=self.store))
        return spec

    def test_unchanged_policy_is_covered_and_not_marked_changed(self) -> None:
        spec = self._accept_original()
        self.assertEqual(changed_binding_conditions(self.record, self.store), {})
        buffer = io.BytesIO()
        result = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=self.records,
            texts=self.texts,
            typed_text=None,
            screen=buffer,
            decline=True,
        )
        self.assertIsNone(result)
        shown = buffer.getvalue()
        self.assertIn(b"=== binding:bfl-usage-policy ===\n" + self.policy + b"\n", shown)
        self.assertNotIn(b"=== changed since your last acceptance ===", shown)
        self.assertNotIn(b"changed: binding:", shown)

    def test_planted_one_byte_policy_change_re_presents_as_changed(self) -> None:
        self._accept_original()
        gets_before = len(self.upstream.requests())
        planted, digest, changed_record = self._planted_record()
        records = RecordIndex([changed_record])
        spec = self._fixture(changed_record, asset_id="fixture-bonsai-image-changed")
        old = parse_receipt_bytes(next(self.store.root.glob("*.json")).read_bytes())
        with self.assertRaises(CoverageRefused) as caught:
            covers(changed_record, old, manifest_digest=spec.manifest_digest)
        self.assertEqual(caught.exception.field, "binding_condition_text_digests:bfl-usage-policy")
        self.assertTrue(needs_agreement(spec, records=records, store=self.store))
        self.assertEqual(
            changed_binding_conditions(changed_record, self.store),
            {"bfl-usage-policy": (POLICY_SHA256,)},
        )
        with self.assertRaises(CoverageRefused):
            self.installer.ensure_upstream_asset(
                spec, store=self.store, records=records, notices=self.texts
            )
        self.assertEqual(len(self.upstream.requests()), gets_before)
        declined = io.BytesIO()
        result = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=records,
            texts=self.texts,
            typed_text=None,
            screen=declined,
            decline=True,
        )
        self.assertIsNone(result)
        shown = declined.getvalue()
        self.assertIn(b"=== changed since your last acceptance ===\n", shown)
        self.assertIn(b"changed: binding:bfl-usage-policy\n", shown)
        self.assertIn(f"accepted sha256: {POLICY_SHA256}\n".encode("utf-8"), shown)
        self.assertIn(f"shown sha256: {digest}\n".encode("utf-8"), shown)
        self.assertIn(b"=== binding:bfl-usage-policy ===\n" + planted + b"\n", shown)
        self.assertNotIn(self.policy, shown)
        self.assertLess(
            shown.index(b"=== changed since your last acceptance ==="),
            shown.index(b"=== binding:bfl-usage-policy ==="),
        )
        self.assertEqual(len(list(self.store.root.glob("*.json"))), 1)
        self.assertEqual(len(self.upstream.requests()), gets_before)
        accepted = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=records,
            texts=self.texts,
            typed_text=typed_agreement_line(changed_record),
            screen=io.BytesIO(),
        )
        self.assertIsNotNone(accepted)
        self.assertEqual(len(list(self.store.root.glob("*.json"))), 2)
        self.assertFalse(needs_agreement(spec, records=records, store=self.store))
        self.assertEqual(changed_binding_conditions(changed_record, self.store), {})
        newest = parse_receipt_bytes(
            self.store.path_for(changed_record.digest, spec.manifest_digest).read_bytes()
        )
        self.assertEqual(newest.binding_condition_text_digests, {"bfl-usage-policy": digest})

    def test_changed_block_is_still_shown_beside_junk_receipt_files(self) -> None:
        """C2E-VERIFY F1 (b): junk in the store neither blocks nor hides the marker."""
        self._accept_original()
        planted_junk = _plant_junk(self.store.root)
        self.assertIn("0000-planted-non-utf8.json", planted_junk)
        self.assertIn("0001-planted-receipt-v2.json", planted_junk)
        valid = [
            path.name
            for path in self.store.root.glob("*.json")
            if path.name not in planted_junk
        ]
        self.assertEqual(len(valid), 1)
        names = sorted(path.name for path in self.store.root.glob("*.json"))
        self.assertLess(names.index("0000-planted-non-utf8.json"), names.index(valid[0]))
        self.assertLess(names.index("0001-planted-receipt-v2.json"), names.index(valid[0]))
        planted, digest, changed_record = self._planted_record()
        records = RecordIndex([changed_record])
        spec = self._fixture(changed_record, asset_id="fixture-bonsai-image-changed")
        self.assertEqual(
            changed_binding_conditions(changed_record, self.store),
            {"bfl-usage-policy": (POLICY_SHA256,)},
        )
        declined = io.BytesIO()
        result = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=records,
            texts=self.texts,
            typed_text=None,
            screen=declined,
            decline=True,
        )
        self.assertIsNone(result)
        shown = declined.getvalue()
        self.assertIn(b"=== changed since your last acceptance ===\n", shown)
        self.assertIn(b"changed: binding:bfl-usage-policy\n", shown)
        self.assertEqual(shown.count(b"accepted sha256: "), 1)
        self.assertIn(f"accepted sha256: {POLICY_SHA256}\n".encode("utf-8"), shown)
        self.assertIn(f"shown sha256: {digest}\n".encode("utf-8"), shown)
        self.assertNotIn(("e" * 64).encode("utf-8"), shown)
        self.assertIn(b"=== binding:bfl-usage-policy ===\n" + planted + b"\n", shown)
        accepted = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=records,
            texts=self.texts,
            typed_text=typed_agreement_line(changed_record),
            screen=io.BytesIO(),
        )
        self.assertIsNotNone(accepted)
        self.assertEqual(changed_binding_conditions(changed_record, self.store), {})
        for name, payload in planted_junk.items():
            if payload is None:
                self.assertTrue((self.store.root / name).is_dir(), name)
            else:
                self.assertEqual((self.store.root / name).read_bytes(), payload, name)


class ReceiptStoreJunkTests(unittest.TestCase):
    """C2E-VERIFY F1 (a): one unusable file must not block an unrelated first-use install.

    The changed marker is presentation only. require() enforces coverage from
    the exact receipt path, so the marker scan skips what it cannot use.
    """

    def setUp(self) -> None:
        self.upstream = FakeUpstream()
        self.records = load_determined_records()
        self.record = self.records.by_id("small-en-us")
        self.archive = vosk_fixture_zip()
        self.url = self.upstream.add("/model.zip", self.archive)

    def tearDown(self) -> None:
        self.upstream.close()

    def _install_vosk_beside(self, names: tuple[str, ...]) -> None:
        scratch = Path(tempfile.mkdtemp(prefix="kilix-content-junk-receipts-"))
        texts = load_determined_texts(scratch / "texts")
        store = FakeStore(scratch / "receipts")
        installer = Installer(str(scratch / "root"))
        spec = AssetSpec.from_mapping(
            make_archive_asset(
                asset_id="fixture-vosk-beside-junk",
                url=self.url,
                archive=self.archive,
                root="vosk-model-small-en-us-0.15",
                license_record=self.record,
                notice=texts.get(self.record.text_sha256),
                licensors=["Alpha Cephei Inc."],
            )
        )
        planted = _plant_junk(store.root, names)
        self.assertEqual(set(planted), set(names))
        self.assertEqual(changed_binding_conditions(self.record, store), {})
        screen = io.BytesIO()
        gets_before = len(self.upstream.requests())
        result = install_with_agreement(
            spec,
            installer=installer,
            store=store,
            records=self.records,
            texts=texts,
            typed_text=typed_agreement_line(self.record),
            screen=screen,
        )
        self.assertIsNotNone(result)
        self.assertTrue(Path(result[0], "conf", "model.conf").is_file())
        self.assertGreater(len(self.upstream.requests()), gets_before)
        shown = screen.getvalue()
        self.assertIn(b"id: fixture-vosk-beside-junk\n", shown)
        self.assertNotIn(b"=== changed since your last acceptance ===", shown)
        receipt_path = store.path_for(self.record.digest, spec.manifest_digest)
        self.assertEqual(parse_receipt_bytes(receipt_path.read_bytes()).licence_id, "small-en-us")
        self.assertFalse(needs_agreement(spec, records=self.records, store=store))
        for name, payload in planted.items():
            if payload is None:
                self.assertTrue((store.root / name).is_dir(), name)
            else:
                self.assertEqual((store.root / name).read_bytes(), payload, name)

    def test_non_utf8_receipt_file_does_not_block_an_unrelated_install(self) -> None:
        self._install_vosk_beside(("0000-planted-non-utf8.json",))

    def test_future_schema_receipt_does_not_block_an_unrelated_install(self) -> None:
        self._install_vosk_beside(("0001-planted-receipt-v2.json",))

    def test_every_unusable_receipt_shape_is_skipped(self) -> None:
        for name in JUNK_RECEIPT_FILES:
            with self.subTest(name=name):
                self._install_vosk_beside((name,))
        with self.subTest(name="all together"):
            self._install_vosk_beside(tuple(JUNK_RECEIPT_FILES))


if __name__ == "__main__":
    unittest.main()
