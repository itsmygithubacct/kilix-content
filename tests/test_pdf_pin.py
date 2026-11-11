"""Exercise the production trust root when selecting the reviewed PDF, Help and Needle apps."""
import json
from pathlib import Path
import subprocess
import unittest
from kilix_content import verified_packaged_catalog

class PDFPinTests(unittest.TestCase):
    def test_reviewed_consumers_and_unchanged_model_assets(self):
        catalog=verified_packaged_catalog()
        self.assertEqual(catalog.require('kilix-pdf-conversion').ref,'873f3298cfe9bcbf295061cd35d5054a46f4b21a')
        self.assertEqual(catalog.require('kilix-help-llm').ref,'4abc52e9236899a05738807d32a3431270b6a3c2')
        self.assertEqual(catalog.require('kilix-needle').ref,'30ee74fe770a6c3b19b23e68e3a4c7dbe4deae77')
        root=Path(__file__).resolve().parents[1]
        before=json.loads(subprocess.check_output(['git','show','bc7ab69d6e0089729c7113b58563f3f0f0186301:src/kilix_content/catalog/plebian.json'],cwd=root))
        after=json.loads((root/'src/kilix_content/catalog/plebian.json').read_bytes())
        self.assertEqual(len(after['assets']),47)
        for document in (before, after):
            document['assets']=[asset for asset in document['assets']
                                if asset['id'] not in ('basic-pitch-icassp-2022-onnx',
                                                       'paradee-8m-v1.2', 'en-core-web-sm-3.8.0', 'qwen-0.8b-no-loop-02',
                                                       'pp-ocrv6-small-det', 'pp-ocrv6-small-rec',
                                                       'faster-whisper-medium-en',
                                                       'demucs-htdemucs-6s',
                                                       'faster-whisper-large-v3',
                                                       'lfm2-kilix-commands', 'lfm3-kilix-commands')]
        self.assertEqual(before['assets'],after['assets'])
        # Application actions can advance independently of model asset bytes.
        # The selected consumer pins and model assets above remain checked.
