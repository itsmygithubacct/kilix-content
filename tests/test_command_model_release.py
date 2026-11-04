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
            'git', 'show', '92f6dbc6cdddeb97dd38ee4500bb1441bd1e838f:src/kilix_content/catalog/plebian.json'], cwd=root))
        after = json.loads((root / 'src/kilix_content/catalog/plebian.json').read_bytes())
        for document in (before, after):
            document['assets'] = [a for a in document['assets']
                                  if a['id'] not in ('lfm2-kilix-commands', 'lfm3-kilix-commands')]
        self.assertEqual(before['assets'], after['assets'])
        spec = verified_packaged_catalog().require_asset('lfm2-kilix-commands')
        self.assertEqual(spec.version, 'lfm2-kilix-commands-20261104-v8')
        model = next(f for f in spec.files if f.path == 'model.gguf')
        self.assertEqual(model.sha256, '7815032c4bdd44fbde002ec734ef3dd8eb14a8a44214b395738dae6e55ce897d')
        self.assertEqual(model.bytes, 1388859040)
