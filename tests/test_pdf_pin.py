"""Exercise the production trust root when selecting the reviewed PDF app."""
import json
from pathlib import Path
import subprocess
import unittest
from kilix_content import verified_packaged_catalog

class PDFPinTests(unittest.TestCase):
    def test_reviewed_pdf_and_unchanged_model_assets(self):
        catalog=verified_packaged_catalog()
        self.assertEqual(catalog.require('kilix-pdf-conversion').ref,'e841241b0134fef42045a946199a92e9fa35ffbf')
        root=Path(__file__).resolve().parents[1]
        before=json.loads(subprocess.check_output(['git','show','b54bc86936dc74017e6cb267b58f294b45af1221:src/kilix_content/catalog/plebian.json'],cwd=root))
        after=json.loads((root/'src/kilix_content/catalog/plebian.json').read_bytes())
        self.assertEqual(len(after['assets']),38)
        after=dict(after,assets=[asset for asset in after['assets'] if asset['id']!='basic-pitch-icassp-2022-onnx'])
        self.assertEqual(before['assets'],after['assets'])
        for entry in before['content']:
            if entry['id']=='kilix-pdf-conversion':
                entry['source']['ref']='e841241b0134fef42045a946199a92e9fa35ffbf'
        for entry in before['content']:
            if entry['id']=='kilix-nvr':
                entry['source']['ref']='e68b5d144cdff3330bc0f29ee5bc6e96649a26ae'
            elif entry['id']=='kilix-object-detect':
                entry['source']['ref']='ee8ca0679503bcfacccbba0e61fff5c055ad9113'
        self.assertEqual(before,after)
