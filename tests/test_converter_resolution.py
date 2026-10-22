"""A desktop installation can acquire its pinned converter without /usr/lib."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from kilix_content import Installer, InstallError, verified_packaged_catalog


class ConverterResolutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.installer = Installer(str(self.root / 'apps'))
        self.spec = verified_packaged_catalog().require_asset('encodec-24khz-stateful')
        self.stage = self.root / 'stage'
        self.stage.mkdir()

    def populate(self, spec):
        return self.installer._populate_upstream_asset(
            spec, str(self.stage), lambda _: None, Mock(),
            store=Mock(root=self.root / 'receipts'))

    def test_missing_system_converter_uses_pinned_user_install(self):
        with patch('kilix_content.install.shutil.which', return_value=None), \
                patch.object(self.installer, 'ensure', return_value='/user/converter') as ensure, \
                patch('kilix_content.install.fetch_exact'), \
                patch.object(self.installer, '_write_notices'), \
                patch('kilix_content.install._run_with_tail', return_value=(0, '')) as run:
            self.populate(self.spec)
        tool = ensure.call_args.args[0]
        self.assertEqual(tool.ref, '684b010b211470f7c358105d2da453fb7a9d0ec5')
        self.assertEqual(tool.content_id, 'kilix-encodec-convert-24khz')
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], '/user/converter')
        self.assertEqual(argv[argv.index('--manifest-digest') + 1], self.spec.manifest_digest)
        self.assertEqual(argv[argv.index('--receipt-store') + 1], str(self.root / 'receipts'))

    def test_failed_converter_build_precedes_model_download(self):
        with patch('kilix_content.install.shutil.which', return_value=None), \
                patch.object(self.installer, 'ensure', side_effect=InstallError('build failed')), \
                patch('kilix_content.install.fetch_exact') as fetch:
            with self.assertRaisesRegex(InstallError, 'build failed'):
                self.populate(self.spec)
        fetch.assert_not_called()

    def test_changed_asset_cannot_borrow_packaged_converter(self):
        altered = replace(self.spec, convert_argv=('/missing/other-converter',))
        with patch('kilix_content.install.shutil.which', return_value=None), \
                patch.object(self.installer, 'ensure') as ensure, \
                patch('kilix_content.install.fetch_exact') as fetch:
            with self.assertRaisesRegex(InstallError, 'converter is unavailable'):
                self.populate(altered)
        ensure.assert_not_called()
        fetch.assert_not_called()
