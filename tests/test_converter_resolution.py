"""A desktop installation can acquire its pinned converter without /usr/lib."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from kilix_content import ConverterPrerequisiteError, Installer, InstallError, verified_packaged_catalog


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
        self.assertEqual(tool.ref, '22290fb4a0587d5b7f937e345c99aa5d599c2282')
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

    def test_external_converters_fail_before_any_model_fetch(self):
        for name, tool in (('kilix-diarization-cpu', 'kilix-diarization-convert'),
                           ('pocket-tts-english-q8_0', 'pocket-tts-convert-hf-to-gguf')):
            spec = verified_packaged_catalog().require_asset(name)
            with self.subTest(model=name), \
                    patch('kilix_content.install.shutil.which', return_value=None), \
                    patch.object(self.installer, 'ensure') as ensure, \
                    patch('kilix_content.install.fetch_exact') as fetch:
                with self.assertRaises(ConverterPrerequisiteError) as caught:
                    self.populate(spec)
                self.assertEqual(caught.exception.tool_asset_id, tool)
                self.assertEqual(caught.exception.converter, spec.convert_argv[0])
                ensure.assert_not_called()
                fetch.assert_not_called()

    def test_installed_diarization_converter_gets_exact_inputs_and_gate(self):
        spec = verified_packaged_catalog().require_asset('kilix-diarization-cpu')
        with patch('kilix_content.install.shutil.which', return_value=spec.convert_argv[0]), \
                patch.object(self.installer, 'ensure') as ensure, \
                patch('kilix_content.install.fetch_exact') as fetch, \
                patch.object(self.installer, '_write_notices'), \
                patch('kilix_content.install._run_with_tail', return_value=(0, '')) as run:
            self.populate(spec)
        ensure.assert_not_called()
        self.assertEqual([(call.args[0], call.kwargs['expected_bytes'], call.kwargs['expected_sha256'])
                          for call in fetch.call_args_list], [
            (spec.convert_url, 29357703, '5b1a88b6f8d85826fabef804779c3372b42f3af21457fa48bd5c097c0686b2de'),
            (spec.convert_inputs[0].url, 5992913, '220ad67ca923bef2fa91f2390c786097bf305bceb5e261d4af67b38e938e1079')])
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], spec.convert_argv[0])
        self.assertEqual(argv[argv.index('--input') + 1], str(self.stage / 'input'))
        self.assertEqual(argv[argv.index('--manifest-digest') + 1], spec.manifest_digest)
        self.assertEqual(argv[argv.index('--receipt-store') + 1], str(self.root / 'receipts'))

    def test_all_advertised_conversion_tools_have_a_known_resolution_route(self):
        catalog = verified_packaged_catalog()
        routes = {spec.asset_id: (spec.convert_tool_asset_id, catalog.get(spec.convert_tool_asset_id) is not None)
                  for spec in catalog.assets if spec.source_mode == 'upstream-convert'}
        self.assertEqual(routes, {
            'kilix-diarization-cpu': ('kilix-diarization-convert', False),
            'pocket-tts-english-q8_0': ('pocket-tts-convert-hf-to-gguf', False),
            'encodec-24khz-stateful': ('kilix-encodec-convert-24khz', True),
            'encodec-48khz-frame': ('kilix-encodec-convert-48khz', True)})
        for name in ('encodec-24khz-stateful', 'encodec-48khz-frame'):
            spec = catalog.require_asset(name)
            tool = catalog.require(spec.convert_tool_asset_id)
            self.assertEqual(tool.ref, '22290fb4a0587d5b7f937e345c99aa5d599c2282')
