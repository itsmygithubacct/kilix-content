"""The managed Android application keeps its host presentation policy."""
import unittest

from kilix_content import verified_packaged_catalog


class WaydroidApplicationTests(unittest.TestCase):
    def test_managed_system_entry_preserves_owned_xpane_lifecycle(self):
        spec = verified_packaged_catalog().require("kilix-waydroid")
        self.assertEqual(spec.source_type, "system")
        self.assertEqual(spec.kind, "app")
        self.assertEqual(spec.command, ("kilix-waydroid", "window", "--size", "960x600"))
        self.assertEqual(spec.launch_mode, "xpane")
        self.assertTrue(spec.lifecycle.single_instance)
        self.assertTrue(spec.lifecycle.requires_kilix_session)
        self.assertTrue(spec.lifecycle.preserve_on_failure)
