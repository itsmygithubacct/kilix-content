"""The two component selections a gitlink re-pin would otherwise roll back.

This repository's shared catalog is the single place that says which commit of
`kilix-amp` and `kilix-tui-utils` a release builds, and with which build
arguments. kilix reads those values out of the catalog it has pinned as a
submodule, so advancing that gitlink replaces kilix's answers wholesale.

Two of those answers were older on this line than on the one the release
currently pins, because this line branched at `07431765` and the bumps landed
afterwards, at `c275334f`, on the F100 authority line that OD-BM discarded:

* `kilix-tui-utils` `dc462372` -> `af7e8481` -- the Music playback wave.
* `kilix-amp` `2bcb035d` -> `e876632e` with `make all ENCODEC=1` -- EnCodec
  playback and the installed-content admission it needs.

`kilix-amp` has since moved forward once more, `e876632e` -> `92f252b3`, a
strict descendant whose two commits bring its EnCodec admission fixture and
README onto asset/v3 and kilix-license receipts. The build stays
`make all ENCODEC=1`.

The two EnCodec converters, `kilix-encodec-convert-24khz` and
`kilix-encodec-convert-48khz`, select `kilix-encodec` `684b010b`, the commit
that carries the asset/v3 migration. Their only other test,
`test_both_tools_are_pinned_at_the_same_ref_for_c5`, asks that the two agree,
so rolling both back to `16ad64ce` together passed every test while EnCodec
playback would break at runtime. Their ref is typed here for the same reason
Amp's is, and the pin generator's default ref is held to it, so a bare
`tools/generate_encodec_pins.py --check` checks the commit the catalog selects.

The `kilix-tui-utils` half was at least loud: kilix's own
`test_component_pin_delivery.CatalogPinTests.test_tui_utils_pin_matches_the_shared_catalog`
compares `scripts/install-kilix-tui-utils.sh`'s pinned default against this
catalog and fails on a mismatch. **The `kilix-amp` half was silent.** Nothing in
kilix binds the Amp selection to a value it did not itself read out of this
catalog -- `test_consumer_selection.ConsumerSelectionTests` there asserts that
`install-kilix-amp.py --resolve` relays `amp.ref` and `amp.build`, which is true
whatever they are -- so dropping `ENCODEC=1` would have come off in a green
suite, reversing OD-BN (0.2.2 **does** ship EnCodec playback in Amp and Music)
without anyone seeing it.

So the values are typed here, as literals, in the repository that owns them.
A test that recomputed them from the catalog would restate the catalog rather
than bind it, which is the shape that let the flag disappear in the first place.
"""

import json
from pathlib import Path
import unittest

from kilix_content import verified_packaged_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "kilix_content" / "catalog" / "plebian.json"

# The selections a re-pin must deliver, typed rather than derived.
TUI_UTILS_REF = "af7e8481588c090fd703be51aa4dddf597b07ef8"
AMP_REF = "92f252b3cf64ad85c252b7e0ab00c6325ea8442f"
AMP_BUILD = ("make", "all", "ENCODEC=1")
ENCODEC_CONVERTER_REF = "684b010b211470f7c358105d2da453fb7a9d0ec5"
ENCODEC_CONVERTERS = ("kilix-encodec-convert-24khz", "kilix-encodec-convert-48khz")


class ConsumerSelectionTests(unittest.TestCase):
    """Read through the verified entry point: unpinned bytes are never asserted on."""

    def test_amp_selects_the_encodec_playback_source_and_build(self) -> None:
        amp = verified_packaged_catalog().require("kilix-amp")
        self.assertEqual(amp.ref, AMP_REF)
        self.assertEqual(amp.build, AMP_BUILD)
        self.assertEqual(amp.binary, "kilix-amp")

    def test_amp_build_carries_the_encodec_flag(self) -> None:
        """OD-BN, stated on its own so a build-list edit cannot pass quietly.

        The previous test would also fail if the build list were reordered or
        re-spelled; this one fails only on the thing OD-BN decided, and says so
        in its name, so the failure message names the decision that was reversed.
        """
        amp = verified_packaged_catalog().require("kilix-amp")
        self.assertIn(
            "ENCODEC=1",
            amp.build,
            "OD-BN: 0.2.2 ships EnCodec playback in Amp and Music; the Amp "
            "build must carry ENCODEC=1",
        )

    def test_each_encodec_converter_selects_the_asset_v3_migration(self) -> None:
        """Each converter on its own: agreeing with the other is not enough."""
        catalog = verified_packaged_catalog()
        for content_id in ENCODEC_CONVERTERS:
            with self.subTest(content_id=content_id):
                self.assertEqual(catalog.require(content_id).ref, ENCODEC_CONVERTER_REF)

    def test_the_encodec_pin_generator_defaults_to_the_selected_ref(self) -> None:
        """A bare `--check` must check the commit the catalog selects."""
        import importlib.util

        path = ROOT / "tools" / "generate_encodec_pins.py"
        spec = importlib.util.spec_from_file_location("generate_encodec_pins", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        self.assertEqual(module.DEFAULT_REF, ENCODEC_CONVERTER_REF)

    def test_tui_utils_package_selects_the_music_playback_wave(self) -> None:
        catalog = verified_packaged_catalog()
        package = catalog.require_package("kilix-tui-utils")
        self.assertEqual(package.ref, TUI_UTILS_REF)
        self.assertEqual(package.build, ("make", "runtime"))

    def test_every_entry_the_tui_package_supplies_reports_the_selected_ref(self) -> None:
        """kilix asks `--print-ref` and compares it with a content entry's ref.

        kilix's `test_consumer_selection.test_tui_print_ref_equals_catalog_package_selection`
        reads `kilix-file`, not the package, so the inherited value is the one
        that has to be right. Every entry the package supplies is checked, not
        just the one kilix happens to read today.
        """
        catalog = verified_packaged_catalog()
        supplied = catalog.provided_by("kilix-tui-utils")
        self.assertGreater(len(supplied), 1)
        for entry in supplied:
            with self.subTest(content_id=entry.content_id):
                self.assertEqual(entry.ref, TUI_UTILS_REF)

    def test_the_selections_are_the_catalog_file_s_own_bytes(self) -> None:
        """The parsed answers above are what the shipped JSON actually says.

        `verified_packaged_catalog()` already refuses bytes that do not match
        `_CATALOG_SHA256`; this reads the file a second way, without the model
        layer, so a parsing bug could not satisfy every assertion above while
        the shipped file said something else.
        """
        raw = json.loads(CATALOG.read_text(encoding="utf-8"))
        package = next(
            entry for entry in raw["packages"] if entry["id"] == "kilix-tui-utils"
        )
        amp = next(entry for entry in raw["content"] if entry["id"] == "kilix-amp")
        self.assertEqual(package["source"]["ref"], TUI_UTILS_REF)
        self.assertEqual(amp["source"]["ref"], AMP_REF)
        self.assertEqual(tuple(amp["build"]), AMP_BUILD)
        for content_id in ENCODEC_CONVERTERS:
            converter = next(
                entry for entry in raw["content"] if entry["id"] == content_id
            )
            with self.subTest(content_id=content_id):
                self.assertEqual(converter["source"]["ref"], ENCODEC_CONVERTER_REF)


if __name__ == "__main__":
    unittest.main()
