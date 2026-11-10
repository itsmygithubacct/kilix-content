"""An explicit command-model promotion must preserve unrelated catalog assets."""
import json
from pathlib import Path
import subprocess
import unittest

from kilix_content import verified_packaged_catalog


class CommandModelReleaseTests(unittest.TestCase):
    def test_selected_release_and_unrelated_assets(self):
        root = Path(__file__).resolve().parents[1]
        before = json.loads(subprocess.check_output([
            'git', 'show', 'bc7ab69d6e0089729c7113b58563f3f0f0186301:src/kilix_content/catalog/plebian.json'], cwd=root))
        after = json.loads((root / 'src/kilix_content/catalog/plebian.json').read_bytes())
        for document in (before, after):
            document['assets'] = [a for a in document['assets']
                                  if a['id'] not in ('lfm2-kilix-commands', 'lfm3-kilix-commands', 'paradee-8m-v1.2', 'en-core-web-sm-3.8.0', 'qwen-0.8b-no-loop-02',
                                                'faster-whisper-medium-en', 'demucs-htdemucs-6s',
                                                'faster-whisper-large-v3')]
        self.assertEqual(before['assets'], after['assets'])
        spec = verified_packaged_catalog().require_asset('lfm2-kilix-commands')
        self.assertEqual(spec.version, 'lfm2-kilix-commands-20261106-v9')
        model = next(f for f in spec.files if f.path == 'model.gguf')
        self.assertEqual(model.sha256, '3fa22c105b1f80823088de21a45fd2f3dc30a4cfdc63d21037c9344585fae4dd')
        self.assertEqual(model.bytes, 1388859040)
