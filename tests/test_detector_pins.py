"""Verify detector selection through the production catalog authority."""
import json
from pathlib import Path
import subprocess
import unittest
from kilix_content import verified_packaged_catalog


class DetectorPins(unittest.TestCase):
    def test_selection_preserves_assets_and_application_behavior(self):
        pins = {
            'kilix-object-detect': 'ee8ca0679503bcfacccbba0e61fff5c055ad9113',
            'kilix-nvr': 'e68b5d144cdff3330bc0f29ee5bc6e96649a26ae',
        }
        catalog = verified_packaged_catalog()
        for name, ref in pins.items():
            self.assertEqual(catalog.require(name).ref, ref)
        root = Path(__file__).resolve().parents[1]
        before = json.loads(subprocess.check_output([
            'git', 'show', 'bc7ab69d6e0089729c7113b58563f3f0f0186301:src/kilix_content/catalog/plebian.json'], cwd=root))
        after = json.loads((root / 'src/kilix_content/catalog/plebian.json').read_bytes())
        for document in (before, after):
            document['assets'] = [asset for asset in document['assets']
                                  if asset['id'] not in ('lfm2-kilix-commands', 'lfm3-kilix-commands', 'paradee-8m-v1.2', 'en-core-web-sm-3.8.0', 'pp-ocrv6-small-det', 'pp-ocrv6-small-rec', 'qwen-0.8b-no-loop-02',
                                                'faster-whisper-medium-en', 'demucs-htdemucs-6s',
                                                'faster-whisper-large-v3')]
        self.assertEqual(before['assets'], after['assets'])
        for entry in before['content']:
            if entry['id'] in pins:
                entry['source']['ref'] = pins[entry['id']]
            elif entry['id'] == 'kilix-pdf-conversion':
                entry['source']['ref'] = '873f3298cfe9bcbf295061cd35d5054a46f4b21a'
            elif entry['id'] == 'playalong':
                # 2026-11-08: Playalong takes every model from Kilix's
                # licence records and never downloads one itself.
                entry['source']['ref'] = 'a11a02195765f3411249587918864e95dbf1fd9b'
            elif entry['id'] == 'kilix-needle':
                entry['source']['ref'] = 'bcef7e1738188ca951a6e16b608a01ec26f723e3'
                # Owner determination 2026-11-07: LFM2's terms are a notice.
                entry['dependency_hint'] = entry['dependency_hint'].replace(
                    'after licence review and acceptance;',
                    'after showing its licence terms, which are a notice and take no agreement;')
                # Owner decision 2026-11-15: LFM2 is a first-use download and
                # Ask uses its grammar until the model is installed.
                for field, old, new in (
                        ('dependency_hint',
                         '`kilix-needle install --commands` installs the default LFM2 Ask model',
                         'Ask uses its grammar until a model is installed and downloads none on its own; '
                         '`kilix-needle install --commands` installs the LFM2 Ask model'),
                        ('description',
                         'with a pinned local LFM2 model, an optional Needle 3 model and grammar shortcuts.',
                         'with its grammar, and with the pinned local LFM2 model once that is installed, '
                         'or an optional Needle 3 model.')):
                    self.assertEqual(entry[field].count(old), 1, field)
                    entry[field] = entry[field].replace(old, new)
            elif entry['id'] == 'kilix-claudex':
                # RC9 selects Claudex 1f9d3c9: trust prompts are reported,
                # fresh readings skipped, and the dashboard opens in a pane.
                entry['source']['ref'] = '1f9d3c9c5950589182250e5e0b3267b3e65843a4'
        # RC9 selects shared inventory and log adapters from kilix-tui-utils.
        for package in before['packages']:
            if package['id'] == 'kilix-tui-utils':
                package['source']['ref'] = 'bd1999bd446a7e1f2d8ed440ff1c880884721452'
        # Help has its own source/action contract and can evolve independently
        # of detector selection. Retain the byte comparison for every other app.
        for document in (before, after):
            document['content'] = [entry for entry in document['content']
                                   if entry['id'] != 'kilix-help-llm']
        self.assertEqual(before, after)
