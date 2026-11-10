"""en_core_web_sm 3.8.0 is one MIT wheel plus its training-source statement."""
import unittest
from pathlib import Path

from kilix_content import verified_packaged_catalog
from kilix_license.en_core_web_sm import SOURCE, generate_en_core_web_sm_records
from kilix_license.standard_policy import standard_policy_eligible

ROOT = Path(__file__).resolve().parents[1]
WHEEL = "en_core_web_sm-3.8.0-py3-none-any.whl"
WHEEL_SHA = "1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85"
MIT = "3933c176979b68bc6d0bcc902c7d6c130f1d127f476f17ba5cdba8d99cfd0012"
SOURCES = "20d9dfacd215112251f15341edd1a47b1f98bf393a212f10f194ffdc7ee98a90"


class EnCoreWebSmAssetTests(unittest.TestCase):
    def test_wheel_mit_licence_and_training_sources(self):
        spec = verified_packaged_catalog().require_asset("en-core-web-sm-3.8.0")
        self.assertEqual(spec.provider, "spacy")
        self.assertEqual(spec.version, "3.8.0")
        self.assertEqual(spec.download_bytes, 12806118)
        wheel = next(item for item in spec.files if item.path == WHEEL)
        self.assertEqual((wheel.bytes, wheel.sha256), (12806118, WHEEL_SHA))
        self.assertEqual(spec.fetch[0].url, SOURCE)
        notice = next(item for item in spec.files if item.path == "notices/LICENSE-mit.txt")
        sources = next(item for item in spec.files if item.path == "notices/LICENSES_SOURCES.txt")
        self.assertEqual((notice.bytes, notice.sha256), (1056, MIT))
        self.assertEqual((sources.bytes, sources.sha256), (2347, SOURCES))
        row = spec.licenses[0]
        self.assertEqual((row.license_id, row.decision, row.licensors),
                         ("mit", "affirmative", ("ExplosionAI GmbH",)))
        records = generate_en_core_web_sm_records(
            ROOT / "third_party/kilix-license/src/kilix_license/data")
        self.assertEqual(records[0].digest, row.record_digest)
        self.assertTrue(standard_policy_eligible(records[0]))
