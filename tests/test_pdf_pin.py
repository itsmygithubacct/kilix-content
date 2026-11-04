"""Exercise the production trust root when selecting the reviewed PDF, Help and Needle apps."""
import json
from pathlib import Path
import subprocess
import unittest
from kilix_content import verified_packaged_catalog

class PDFPinTests(unittest.TestCase):
    def test_reviewed_consumers_and_unchanged_model_assets(self):
        catalog=verified_packaged_catalog()
        self.assertEqual(catalog.require('kilix-pdf-conversion').ref,'e841241b0134fef42045a946199a92e9fa35ffbf')
        self.assertEqual(catalog.require('kilix-help-llm').ref,'41dd050560a6d0b8067b57fa76ab333e05e6bc72')
        self.assertEqual(catalog.require('kilix-needle').ref,'0a936d30893c3063cf0ad36d07bbcee12c522ee5')
        root=Path(__file__).resolve().parents[1]
        before=json.loads(subprocess.check_output(['git','show','b54bc86936dc74017e6cb267b58f294b45af1221:src/kilix_content/catalog/plebian.json'],cwd=root))
        after=json.loads((root/'src/kilix_content/catalog/plebian.json').read_bytes())
        self.assertEqual(len(after['assets']),38)
        after=dict(after,assets=[asset for asset in after['assets'] if asset['id']!='basic-pitch-icassp-2022-onnx'])
        self.assertEqual(before['assets'],after['assets'])
        # Application actions can advance independently of model asset bytes.
        # The selected consumer pins and model assets above remain checked.
