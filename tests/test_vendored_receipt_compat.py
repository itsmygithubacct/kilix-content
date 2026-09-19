"""Receipts written by the older vendored kilix-license still cover (LIC4-FIX).

`tests/data/receipts-d8e2c40a/` holds one receipt per catalog asset as it stood
at the C2e head, written by the kilix-license code this repository vendored
then (`d8e2c40a`), by
`takeover-2026-09-17/c2f-impl-evidence/gen_d8e2c40a_receipts.py`. LIC4 and
LIC4-FIX added receipt context keys; the head must still read those older bytes,
return them unchanged, and honour them as coverage (OD-AI).
"""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from fake_store import FakeStore
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.coverage import covers, require
from kilix_license.receipts import parse_receipt_bytes
from kilix_license.records import RecordIndex

from kilix_content import default_catalog
from kilix_content.first_use import (
    _asset_ref,
    install_with_agreement,
    license_record_for,
    needs_agreement,
    present_asset,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "data" / "receipts-d8e2c40a"
# The catalog at the C2e head (b49c0bf), which is what d8e2c40a code could write for.
FIXTURE_COUNT = 22
# receipt/v1 context as d8e2c40a wrote it: LIC4 and LIC4-FIX keys are absent.
OLD_CONTEXT_KEYS = {"advisory_digests", "catalogue_digest", "release_digest"}
LIC4_CONTEXT_KEYS = (
    "binding_text_ids",
    "component_exception_digests",
    "statement_digests",
    "licence_text_id",
)


class VendoredReceiptCompatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = default_catalog()
        self.records = load_determined_records()
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-old-receipts-"))
        self.texts = load_determined_texts(self.scratch / "texts")
        self.fixtures = sorted(FIXTURES.glob("*.json"))
        self.by_key = {
            (
                license_record_for(spec, self.records).digest,
                spec.manifest_digest,
            ): spec
            for spec in self.catalog.assets
        }

    def test_the_fixtures_are_pre_lic4_receipts_for_catalog_assets(self) -> None:
        self.assertEqual(len(self.fixtures), FIXTURE_COUNT)
        for path in self.fixtures:
            with self.subTest(fixture=path.name):
                raw = json.loads(path.read_bytes())
                self.assertEqual(raw["schema"], "kilix.license.receipt/v1")
                self.assertEqual(set(raw["context"]), OLD_CONTEXT_KEYS)
                receipt = parse_receipt_bytes(path.read_bytes())
                self.assertEqual(
                    path.name, f"{receipt.record_digest}-{receipt.manifest_digest}.json"
                )
                for field in LIC4_CONTEXT_KEYS:
                    self.assertIsNone(getattr(receipt, field), field)
                self.assertIn(
                    (receipt.record_digest, receipt.manifest_digest), self.by_key
                )

    def test_old_receipts_round_trip_and_still_cover(self) -> None:
        for path in self.fixtures:
            payload = path.read_bytes()
            receipt = parse_receipt_bytes(payload)
            spec = self.by_key[(receipt.record_digest, receipt.manifest_digest)]
            with self.subTest(asset=spec.asset_id):
                # The head returns the older bytes unchanged: no key is added.
                self.assertEqual(receipt.to_bytes(), payload)
                record = license_record_for(spec, self.records)
                self.assertTrue(
                    covers(record, receipt, manifest_digest=spec.manifest_digest)
                )
                store = FakeStore(self.scratch / f"store-{spec.asset_id}")
                shutil.copy(path, store.root / path.name)
                found = require(_asset_ref(spec), records=self.records, store=store)
                self.assertEqual(found.record_digest, receipt.record_digest)
                self.assertFalse(
                    needs_agreement(spec, records=self.records, store=store)
                )
                screen = present_asset(
                    spec, record, self.texts, receipts=store, records=self.records
                )
                self.assertNotIn(b"=== changed since your last acceptance ===", screen)
                self.assertEqual(
                    (store.root / path.name).read_bytes(), payload, "receipt rewritten"
                )

    def test_an_old_receipt_covers_a_declined_install_without_a_new_one(self) -> None:
        """A store holding only old receipts needs no re-acceptance (OD-AI)."""
        spec = self.catalog.require_asset("vosk-model-small-en-us-0.15")
        record = license_record_for(spec, self.records)
        store = FakeStore(self.scratch / "store-decline")
        name = f"{record.digest}-{spec.manifest_digest}.json"
        shutil.copy(FIXTURES / name, store.root / name)
        before = sorted(item.name for item in store.root.iterdir())
        buffer = io.BytesIO()
        result = install_with_agreement(
            spec,
            installer=_UNUSED_INSTALLER,
            store=store,
            records=self.records,
            texts=self.texts,
            typed_text=None,
            screen=buffer,
            decline=True,
        )
        self.assertIsNone(result)
        self.assertIn(b"id: vosk-model-small-en-us-0.15\n", buffer.getvalue())
        self.assertNotIn(
            b"=== changed since your last acceptance ===", buffer.getvalue()
        )
        self.assertEqual(sorted(item.name for item in store.root.iterdir()), before)

    def test_an_old_receipt_still_marks_a_revised_binding_text(self) -> None:
        """SR-4 resolves a pre-LIC4 receipt through the records index."""
        import dataclasses

        spec = self.catalog.require_asset("bonsai-image-4b-ternary-gemlite")
        record = license_record_for(spec, self.records)
        store = FakeStore(self.scratch / "store-revised")
        name = f"{record.digest}-{spec.manifest_digest}.json"
        shutil.copy(FIXTURES / name, store.root / name)
        condition = record.binding_conditions[0]
        policy = self.texts.get(condition.text_sha256)
        planted = policy.replace(b"Last Revised on August 4", b"Last Revised on August 5")
        self.assertEqual(len(planted), len(policy))
        digest = self.texts.put(planted, label="planted-policy-compat")
        revised = dataclasses.replace(
            record,
            binding_conditions=(dataclasses.replace(condition, text_sha256=digest),),
        )
        revised_spec = dataclasses.replace(
            spec,
            licenses=(
                dataclasses.replace(spec.licenses[0], record_digest=revised.digest),
            )
            + tuple(spec.licenses[1:]),
        )
        records = RecordIndex([revised])
        screen = present_asset(
            revised_spec, revised, self.texts, receipts=store, records=records
        )
        self.assertIn(b"=== changed since your last acceptance ===\n", screen)
        self.assertIn(b"changed: binding:bfl-usage-policy\n", screen)
        self.assertIn(
            f"accepted sha256: {condition.text_sha256}\n".encode("utf-8"), screen
        )
        self.assertIn(f"shown sha256: {digest}\n".encode("utf-8"), screen)
        self.assertTrue(needs_agreement(revised_spec, records=records, store=store))


class _UnusedInstaller:
    """install_with_agreement never fetches on a declined screen."""

    def ensure_upstream_asset(self, *args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("declined install must not fetch")


_UNUSED_INSTALLER = _UnusedInstaller()


if __name__ == "__main__":
    unittest.main()
