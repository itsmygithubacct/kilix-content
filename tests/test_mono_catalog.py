"""Exact mono/tool metadata and refusal gates; no model execution or consent."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kilix_content import (
    BindingMismatch, Installer, ReceiptMissing, ReceiptStore, ReleaseContext,
    verified_packaged_catalog,
)
from tests.receipt_store_support import open_test_store


class MonoCatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = verified_packaged_catalog()
        self.spec = self.catalog.require_asset('encodec-24khz-stateful')

    def test_exact_local_only_input_and_graph_population(self):
        spec = self.spec
        self.assertEqual(spec.version, 'op17-v2-02201a5a')
        self.assertEqual(spec.provider, 'kilix-encodec')
        self.assertEqual(spec.stream, 'F101')
        self.assertEqual(spec.consumer_schema, 'kilix.encodec.graphs/v1')
        self.assertEqual((spec.compatibility_minimum, spec.compatibility_maximum), (1, 1))
        self.assertEqual(spec.source_mode, 'user-supplied')
        self.assertEqual((spec.mirrors, spec.parts, spec.archive_sha256), ((), (), ''))
        self.assertEqual(spec.input_bytes, 93171529)
        self.assertEqual(spec.input_sha256, 'd7cc33bcf1aad7f2dad9836f36431530744abeace3ca033005e3290ed4fa47bf')
        self.assertEqual(spec.official_url, 'https://dl.fbaipublicfiles.com/encodec/v0/encodec_24khz-d7cc33bc.th')
        self.assertEqual(spec.provenance_url, spec.official_url)
        self.assertEqual(len(spec.files), 10)
        population = json.dumps(spec.to_mapping()['files'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(hashlib.sha256(population).hexdigest(), '98aaf0440e965e7a4280a93195e8fafdae8185212b5059497780c33a4ab10e53')
        self.assertEqual(sum(item.bytes for item in spec.files), spec.installed_bytes)
        self.assertEqual((spec.download_bytes, spec.installed_bytes, spec.temporary_bytes),
                         (0, 102005840, 4294967296))

    def test_notice_requires_a_user_supplied_decision(self):
        notice, = (item for item in self.spec.files if item.path.startswith('notices/'))
        requirement, = self.spec.licenses
        self.assertEqual(notice.path, 'notices/NO-MODEL-GRANT-24KHZ.txt')
        self.assertEqual(notice.bytes, 638)
        self.assertEqual(requirement.license_id, 'encodec-24khz-user-supplied')
        self.assertEqual(requirement.decision, 'user-supplied')
        self.assertEqual(requirement.text_sha256, notice.sha256)

    def test_conversion_resolves_one_ordinary_exact_tool(self):
        tool = self.catalog.require(self.spec.conversion_tool_asset_id)
        self.assertEqual(tool.content_id, 'kilix-encodec-convert-24khz')
        self.assertNotIn(tool.content_id, {asset.asset_id for asset in self.catalog.assets})
        self.assertEqual(tool.kind, 'tool')
        self.assertEqual(tool.source_type, 'git')
        self.assertEqual(tool.repository, 'https://github.com/itsmygithubacct/kilix-encodec')
        self.assertEqual(tool.ref, '3bc3cb002aa1c8ad0edfd819a6639b35858d7ea8')
        self.assertEqual(tool.binary, 'bin/kilix-encodec-convert-24khz')
        self.assertEqual(tool.build, ('python3', 'tools/build_converter.py', '--timeout', '900'))
        self.assertFalse(tool.command)
        self.assertEqual(self.spec.conversion_argv,
                         ('--input', '{input}', '--output', '{output}', '--timeout', '180'))

    def test_catalog_alone_authorizes_neither_acquisition_nor_open(self):
        # This private fixture uses the production store class and its actual
        # packaged authority. It creates no decision/receipt and uses no input.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installer = Installer(str(root / 'content'))
            release = ReleaseContext.packaged()
            with open_test_store(str(root / 'receipts'), store_type=ReceiptStore) as store:
                with self.assertRaises(ReceiptMissing):
                    store.require_asset(self.spec, release)
                with patch('kilix_content.install._run_converter') as convert:
                    with self.assertRaises(ReceiptMissing):
                        installer.ensure_user_supplied_asset(
                            self.spec, self.catalog, store, release, str(root/'absent-input'))
                    convert.assert_not_called()
                with self.assertRaises(ReceiptMissing):
                    installer.open_asset(self.spec, store, release, maximum_bytes=134217728)
                for changed in (
                    replace(self.spec, input_sha256='0' * 64),
                    replace(self.spec, conversion_tool_asset_id='another-converter'),
                    replace(self.spec, conversion_argv=('--input', '{input}', '--output', '{output}')),
                ):
                    with self.subTest(changed=changed.conversion_tool_asset_id):
                        with self.assertRaises(BindingMismatch):
                            store.require_asset(changed, release)


if __name__ == '__main__':
    unittest.main()
