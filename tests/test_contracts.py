from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from kilix_content.receipt import (
    _ASSET_V3_SCHEMA_SHA256,
    asset_v3_schema_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "src" / "kilix_content" / "contracts" / "kilix.content.asset-v3.schema.json"
PUBLIC_SCHEMA = ROOT / "contracts" / "kilix.content.asset-v3.schema.json"


class ContractTests(unittest.TestCase):
    def test_packaged_schema_matches_public_copy(self) -> None:
        self.assertEqual(SCHEMA.read_bytes(), PUBLIC_SCHEMA.read_bytes())

    def test_frozen_schema_digest(self) -> None:
        actual = hashlib.sha256(asset_v3_schema_bytes()).hexdigest()
        self.assertEqual(actual, _ASSET_V3_SCHEMA_SHA256)

    def test_schema_flip_is_detected(self) -> None:
        payload = json.loads(SCHEMA.read_text(encoding="utf-8"))
        payload["title"] = payload["title"] + "x"
        flipped = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.assertNotEqual(flipped, _ASSET_V3_SCHEMA_SHA256)

    def test_schema_declares_v3(self) -> None:
        payload = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(payload["properties"]["schema"]["const"], "kilix.content.asset/v3")

    def test_kilix_license_is_pinned_lic2_archive(self) -> None:
        pin = (ROOT / "third_party" / "kilix-license.pin").read_text(encoding="utf-8").strip()
        self.assertEqual(pin, "d8e2c40ab9c1e4594f8297a9a9bf957933b105ef")
        self.assertTrue(
            (ROOT / "third_party" / "kilix-license" / "src" / "kilix_license" / "data" / "records" / "small-en-us.json").is_file()
        )
