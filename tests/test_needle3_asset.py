"""The optional command model is pinned independently of existing assets."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from kilix_content import default_catalog
from kilix_content.model import Catalog, CatalogError
from kilix_license.catalog import load_determined_records

ROOT = Path(__file__).resolve().parents[1]


class Needle3AssetTests(unittest.TestCase):
    def test_bundle_and_notices_match_their_pins_and_licence_record(self):
        pin = json.loads((ROOT / 'tools/upstream-pins/needle3-kilix-commands.json').read_text())
        spec = default_catalog().require_asset('needle3-kilix-commands')
        record = load_determined_records().by_id('needle3-kilix-commands')
        self.assertEqual(spec.version, pin['version'])
        files = {item.path: item for item in spec.files}
        for member in pin['members']:
            item = files[member['path']]
            self.assertEqual((item.bytes, item.sha256), (member['bytes'], member['sha256']))
        notices = {'notices/LICENSE-apache-2.0.txt': record.text_sha256,
                   'notices/LICENSE-runtime.txt': record.components[0].exception_text_sha256}
        notices.update({'notices/' + item.id + '.txt': item.text_sha256 for item in record.statements})
        for path, digest in notices.items():
            self.assertEqual(files[path].sha256, digest)
            body = (ROOT / 'third_party/kilix-license/src/kilix_license/data/texts' / digest).read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        self.assertEqual(spec.licenses[0].record_digest, record.digest)

    def test_owned_archive_permission_does_not_extend_to_other_models_or_mirrors(self):
        raw = json.loads((ROOT / 'src/kilix_content/catalog/plebian.json').read_text())
        for change in ('id', 'url', 'version', 'licence'):
            changed = copy.deepcopy(raw)
            model = next(x for x in changed['assets'] if x['id'] == 'needle3-kilix-commands')
            if change == 'id': model['id'] = 'unrelated-model'
            elif change == 'url': model['source']['url'] += '?mirror=1'
            elif change == 'version': model['version'] = 'unversioned'
            else: model['licenses'][0]['id'] = 'mit'
            with self.subTest(change=change), self.assertRaises(CatalogError):
                Catalog.from_mapping(changed)
