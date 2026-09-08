"""The selected Amp source and build must advance together."""
import unittest

from kilix_content import verified_packaged_catalog


class ConsumerSelectionTests(unittest.TestCase):
    def test_amp_selects_the_installed_admission_build(self):
        amp = verified_packaged_catalog().require('kilix-amp')
        self.assertEqual(amp.ref, 'e876632e4aef73b2db301ea30bd27f8dfec73781')
        self.assertEqual(amp.build, ('make', 'all', 'ENCODEC=1'))
        self.assertEqual(amp.binary, 'kilix-amp')


if __name__ == '__main__':
    unittest.main()
