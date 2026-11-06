"""Paradee 1.2 is one catalogued int8 ONNX with an Apache-2.0 receipt."""
import unittest
from pathlib import Path

from kilix_content import verified_packaged_catalog
from kilix_license.paradee import SOURCE, generate_paradee_records

ROOT = Path(__file__).resolve().parents[1]
ONNX_SHA = "a6989796692ac173597e15d405c971989202d5c73cfad65f22e90bd7b6c97da1"
APACHE = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


class ParadeeAssetTests(unittest.TestCase):
    def test_one_file_four_voices_with_a_licence_receipt(self):
        spec = verified_packaged_catalog().require_asset("paradee-8m-v1.2")
        self.assertEqual(spec.provider, "paradee")
        self.assertEqual(spec.version, "ed2934d4df8a4fd891e29584c5e1104649409765")
        self.assertEqual(spec.download_bytes, 8462119)
        weights = next(item for item in spec.files if item.path == "onnx/paradee_int8.onnx")
        self.assertEqual((weights.bytes, weights.sha256), (8462119, ONNX_SHA))
        self.assertEqual(spec.fetch[0].url, SOURCE)
        notice = next(item for item in spec.files if item.path == "notices/LICENSE-apache-2.0.txt")
        self.assertEqual(notice.sha256, APACHE)
        row = spec.licenses[0]
        self.assertEqual((row.license_id, row.decision, row.licensors),
                         ("apache-2.0", "affirmative", ("Sahil Mahendrakar",)))
        records = generate_paradee_records(
            ROOT / "third_party/kilix-license/src/kilix_license/data")
        self.assertEqual(records[0].digest, row.record_digest)
        self.assertEqual(records[0].licensor, "Sahil Mahendrakar")
