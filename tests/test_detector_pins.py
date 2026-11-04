"""Verify detector selection through the production catalog authority."""
import json
from pathlib import Path
import subprocess
import unittest
from kilix_content import verified_packaged_catalog


class DetectorPins(unittest.TestCase):
    def test_selection_preserves_assets_and_application_behavior(self):
        pins = {
            'kilix-object-detect': 'ee8ca0679503bcfacccbba0e61fff5c055ad9113',
            'kilix-nvr': 'e68b5d144cdff3330bc0f29ee5bc6e96649a26ae',
        }
        catalog = verified_packaged_catalog()
        for name, ref in pins.items():
            self.assertEqual(catalog.require(name).ref, ref)
        root = Path(__file__).resolve().parents[1]
        before = json.loads(subprocess.check_output([
            'git', 'show', '9a1aa54c39d46794f94fe13d0408290d281f0753:src/kilix_content/catalog/plebian.json'], cwd=root))
        after = json.loads((root / 'src/kilix_content/catalog/plebian.json').read_bytes())
        self.assertEqual(before['assets'], after['assets'])
        for entry in before['content']:
            if entry['id'] in pins:
                entry['source']['ref'] = pins[entry['id']]
        self.assertEqual(before, after)
