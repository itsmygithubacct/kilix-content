"""Android is optional while retaining its managed presentation policy."""
import unittest

from kilix_content import verified_packaged_catalog


class WaydroidApplicationTests(unittest.TestCase):
    def test_optional_entry_preserves_owned_xpane_lifecycle(self):
        spec = verified_packaged_catalog().require("kilix-waydroid")
        self.assertEqual(spec.source_type, "git")
        self.assertEqual(spec.ref, "9d1803dfe3c148d8823fa21335460b0c7677ef5b")
        self.assertEqual(spec.kind, "app")
        self.assertEqual(spec.binary, "kilix-waydroid")
        self.assertEqual(spec.command, ())
        self.assertEqual(spec.build, ("python3", "-m", "compileall", "-q", "src", "kilix-waydroid"))
        self.assertEqual(spec.launch_mode, "xpane")
        self.assertTrue(spec.lifecycle.single_instance)
        self.assertTrue(spec.lifecycle.requires_kilix_session)
        self.assertTrue(spec.lifecycle.preserve_on_failure)
