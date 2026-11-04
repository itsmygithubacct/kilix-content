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
        for document in (before, after):
            document['assets'] = [asset for asset in document['assets']
                                  if asset['id'] not in ('lfm2-kilix-commands', 'lfm3-kilix-commands')]
        self.assertEqual(before['assets'], after['assets'])
        for entry in before['content']:
            if entry['id'] in pins:
                entry['source']['ref'] = pins[entry['id']]
            elif entry['id'] == 'kilix-pdf-conversion':
                entry['source']['ref'] = 'e841241b0134fef42045a946199a92e9fa35ffbf'
            elif entry['id'] == 'kilix-needle':
                entry['source']['ref'] = 'f128e18fb43865b71d1f0073785ed6e5119963f2'
        # Help has its own source/action contract and can evolve independently
        # of detector selection. Retain the byte comparison for every other app.
        for document in (before, after):
            document['content'] = [entry for entry in document['content']
                                   if entry['id'] != 'kilix-help-llm']
        self.assertEqual(before, after)
