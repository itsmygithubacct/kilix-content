"""The installed Help app offers answers and an explicit model setup action."""
import json
from pathlib import Path
import unittest

from kilix_content import verified_packaged_catalog


class HelpActions(unittest.TestCase):
    def test_default_answers_preserve_separate_search_and_setup(self):
        catalog = verified_packaged_catalog()
        self.assertEqual(catalog.require('kilix-help-llm').ref,
                         '4abc52e9236899a05738807d32a3431270b6a3c2')
        root = Path(__file__).resolve().parents[1]
        raw = json.loads((root / 'src/kilix_content/catalog/plebian.json').read_bytes())
        help_app = next(app for app in raw['content'] if app['id'] == 'kilix-help-llm')
        # Installation imports the documentation search without downloading weights.
        self.assertEqual(help_app['build'], ['python3', '-B', '-c', 'import help_llm.lookup'])
        actions = help_app['actions']
        self.assertEqual(set(actions), {'answer', 'lookup', 'setup', 'model-status'})
        for name in ('answer', 'lookup'):
            self.assertEqual(actions[name]['argv'], [name, '--'])
            self.assertTrue(actions[name]['accepts_input'])
        for name in ('setup', 'model-status'):
            self.assertEqual(actions[name]['argv'], [name])
            self.assertFalse(actions[name].get('accepts_input', False))
