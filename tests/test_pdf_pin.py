"""Exercise the production trust root when selecting the reviewed PDF, Help and Needle apps."""
import json
from pathlib import Path
import subprocess
import unittest
from kilix_content import verified_packaged_catalog

class PDFPinTests(unittest.TestCase):
    def test_reviewed_consumers_and_unchanged_model_assets(self):
        catalog=verified_packaged_catalog()
        self.assertEqual(catalog.require('kilix-pdf-conversion').ref,'3aefadd6cce39e89eb17d5bc26e1d0b058a99a44')
        self.assertEqual(catalog.require('kilix-help-llm').ref,'82e2d76e6e114ec2c71b4c302fb9dfbf322a70e4')
        self.assertEqual(catalog.require('kilix-needle').ref,'f128e18fb43865b71d1f0073785ed6e5119963f2')
        root=Path(__file__).resolve().parents[1]
        before=json.loads(subprocess.check_output(['git','show','b54bc86936dc74017e6cb267b58f294b45af1221:src/kilix_content/catalog/plebian.json'],cwd=root))
        after=json.loads((root/'src/kilix_content/catalog/plebian.json').read_bytes())
        self.assertEqual(len(after['assets']),38)
        after=dict(after,assets=[asset for asset in after['assets'] if asset['id']!='basic-pitch-icassp-2022-onnx'])
        self.assertEqual(before['assets'],after['assets'])
        for entry in before['content']:
            if entry['id']=='kilix-pdf-conversion':
                entry['source']['ref']='3aefadd6cce39e89eb17d5bc26e1d0b058a99a44'
            if entry['id']=='kilix-help-llm':
                entry['source']['ref']='82e2d76e6e114ec2c71b4c302fb9dfbf322a70e4'
            if entry['id']=='kilix-needle':
                entry['source']['ref']='f128e18fb43865b71d1f0073785ed6e5119963f2'
        self.assertEqual(before,after)
