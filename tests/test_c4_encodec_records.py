"""EnCodec records as first-use upstream-convert downloads (R4-068, OD-AR, OD-U).

OD-AR determined both EnCodec checkpoints **CC BY-NC 4.0, licensor Meta
Platforms**, binding, with the user's agreement required. It superseded the
0.2.1 records: the 48 kHz "MIT, informational" one and the 24 kHz "no grant,
user-supplied" one. In particular it ruled that "the E4 'mirrored' catalogue
record becomes a first-use download from the upstream pin (OD-U)".

The catalogue-wide guard below is the acceptance line "no record names a
Kilix-hosted URL, and no mode user-supplied or mirrored remains for EnCodec".
It is written over the whole catalog, not over this wave's two records, so a
later merge of the 0.2.1 EnCodec lineage (which carried both defects) cannot
re-introduce either one silently.

The two defects it pins are the concrete ones R0-INV found:

* `C-encodec-48khz-frame` named a Kilix mirror release that does not exist,
  `github.com/itsmygithubacct/kilix-content/releases/download/
  assets-0.2.2-candidate/encodec-48khz-frame-6f0cadba….tar`;
* `C-encodec-24khz-stateful` carried `mode: user-supplied`, which required the
  user to supply the checkpoint by hand.

Asset records carry model bytes, so no URL in one may be Kilix-hosted (OD-S).
Content and package records name their own Kilix source repositories, which is
what they are for; they are checked for the two modes, not for the host.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from kilix_content import default_catalog
from kilix_content.model import _is_kilix_hosted

ROOT = Path(__file__).resolve().parents[1]
CATALOG_JSON = ROOT / "src" / "kilix_content" / "catalog" / "plebian.json"

# The modes OD-AR superseded. Neither may appear in any record, in any section.
REFUSED_MODES = ("user-supplied", "mirrored")

# Keys that only ever existed to carry a mirror or a hand-supplied input.
REFUSED_SOURCE_KEYS = ("mirrors", "official_url")

_URL = re.compile(r"https?://[^\s\"'\\]+")


def urls_in(value: object) -> list[str]:
    """Every http(s) URL anywhere inside a record, whatever key holds it."""
    return _URL.findall(json.dumps(value))


def modes_in(value: object) -> list[str]:
    """Every `mode` value anywhere inside a record."""
    found: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, item in node.items():
                if key == "mode" and isinstance(item, str):
                    found.append(item)
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return found


def source_keys_in(value: object) -> list[str]:
    """Every key used anywhere under a `source` mapping."""
    found: list[str] = []

    def walk(node: object, *, under_source: bool) -> None:
        if isinstance(node, dict):
            for key, item in node.items():
                if under_source:
                    found.append(key)
                walk(item, under_source=under_source or key == "source")
        elif isinstance(node, list):
            for item in node:
                walk(item, under_source=under_source)

    walk(value, under_source=False)
    return found


class CatalogWideEncodecGuardTests(unittest.TestCase):
    """The R4-068 acceptance guard, over every record in the catalog."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = default_catalog()
        cls.raw = json.loads(CATALOG_JSON.read_text(encoding="utf-8"))

    def records(self) -> list[tuple[str, str, dict]]:
        rows: list[tuple[str, str, dict]] = []
        for section in ("assets", "content", "packages"):
            for record in self.raw.get(section, []):
                rows.append((section, record.get("id", "<no id>"), record))
        return rows

    def test_the_catalog_sections_are_all_scanned(self) -> None:
        """Visibility control: the guards below run over a non-empty scan."""
        rows = self.records()
        self.assertEqual(
            sorted({section for section, _id, _record in rows}),
            ["assets", "content", "packages"],
        )
        self.assertGreater(len(rows), 60, "the scan must see the whole catalog")
        self.assertTrue(
            any(urls_in(record) for _s, _i, record in rows),
            "a scan that finds no URL at all proves nothing",
        )

    def test_no_asset_record_names_a_kilix_hosted_url(self) -> None:
        """OD-S: model bytes come from upstream, never from a Kilix release."""
        for section, asset_id, record in self.records():
            if section != "assets":
                continue
            for url in urls_in(record):
                with self.subTest(asset=asset_id, url=url):
                    self.assertFalse(_is_kilix_hosted(url), url)

    def test_no_parsed_asset_url_is_kilix_hosted(self) -> None:
        """The same guard through the parsed specs, for every source mode."""
        seen = 0
        for spec in self.catalog.assets:
            for url in (spec.url, spec.convert_url, spec.manifest_url):
                if url:
                    seen += 1
                    self.assertFalse(_is_kilix_hosted(url), url)
            for item in spec.fetch + spec.blobs:
                seen += 1
                self.assertFalse(_is_kilix_hosted(item.url), item.url)
            seen += 1
            self.assertFalse(
                _is_kilix_hosted(spec.provenance_url), spec.provenance_url
            )
        self.assertGreater(seen, 0, "no URL was checked")

    def test_no_record_carries_a_superseded_mode(self) -> None:
        """OD-AR removed `user-supplied` and `mirrored` for EnCodec, everywhere."""
        for section, record_id, record in self.records():
            for mode in modes_in(record):
                with self.subTest(section=section, record=record_id, mode=mode):
                    self.assertNotIn(mode, REFUSED_MODES)

    def test_no_record_carries_a_mirror_or_hand_supplied_source_key(self) -> None:
        """The keys those two modes needed are gone with them."""
        for section, record_id, record in self.records():
            keys = source_keys_in(record)
            for refused in REFUSED_SOURCE_KEYS:
                with self.subTest(section=section, record=record_id, key=refused):
                    self.assertNotIn(refused, keys)

    def test_every_encodec_asset_record_is_an_upstream_convert_download(self) -> None:
        """Whatever EnCodec records the catalog holds, they are first-use downloads."""
        for spec in self.catalog.assets:
            if "encodec" not in spec.asset_id:
                continue
            with self.subTest(asset=spec.asset_id):
                self.assertEqual(spec.source_mode, "upstream-convert")


class CatalogWideGuardPlantedDefectTests(unittest.TestCase):
    """Each guard above must fail on the exact defect shape it claims to catch.

    A guard that passes over a catalog with no EnCodec record in it proves
    nothing, so each shape is planted into a copy of the real catalog and the
    scanning helper is run over it directly.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = json.loads(CATALOG_JSON.read_text(encoding="utf-8"))

    def planted(self, record: dict) -> dict:
        catalog = json.loads(json.dumps(self.raw))
        catalog["assets"] = list(catalog["assets"]) + [record]
        return catalog

    # R0-INV's exact 48 kHz defect.
    MIRROR_URL = (
        "https://github.com/itsmygithubacct/kilix-content/releases/download/"
        "assets-0.2.2-candidate/"
        "encodec-48khz-frame-"
        "6f0cadba554c63970bc7407028e8510abf01dfcfb04e7713340162f5ba973253.tar"
    )

    def test_a_planted_kilix_mirror_url_is_found(self) -> None:
        planted = self.planted(
            {
                "id": "encodec-48khz-frame",
                "source": {"mode": "mirrored", "mirrors": [self.MIRROR_URL]},
            }
        )
        offenders = [
            url
            for record in planted["assets"]
            for url in urls_in(record)
            if _is_kilix_hosted(url)
        ]
        self.assertEqual(offenders, [self.MIRROR_URL])

    def test_the_mirror_url_is_kilix_hosted_on_its_own(self) -> None:
        """Control: the helper's verdict, independent of the scan."""
        self.assertTrue(_is_kilix_hosted(self.MIRROR_URL))
        self.assertFalse(
            _is_kilix_hosted(
                "https://dl.fbaipublicfiles.com/encodec/v0/"
                "encodec_24khz-d7cc33bc.th"
            )
        )

    def test_a_planted_mirrored_mode_is_found(self) -> None:
        planted = self.planted(
            {"id": "encodec-48khz-frame", "source": {"mode": "mirrored"}}
        )
        found = [
            mode for record in planted["assets"] for mode in modes_in(record)
        ]
        self.assertIn("mirrored", found)

    def test_a_planted_user_supplied_mode_is_found(self) -> None:
        planted = self.planted(
            {"id": "encodec-24khz-stateful", "source": {"mode": "user-supplied"}}
        )
        found = [
            mode for record in planted["assets"] for mode in modes_in(record)
        ]
        self.assertIn("user-supplied", found)

    def test_a_planted_official_url_key_is_found(self) -> None:
        planted = self.planted(
            {
                "id": "encodec-24khz-stateful",
                "source": {
                    "mode": "upstream-convert",
                    "official_url": (
                        "https://dl.fbaipublicfiles.com/encodec/v0/"
                        "encodec_24khz-d7cc33bc.th"
                    ),
                },
            }
        )
        keys = [
            key for record in planted["assets"] for key in source_keys_in(record)
        ]
        self.assertIn("official_url", keys)

    def test_the_helpers_are_quiet_on_the_real_catalog(self) -> None:
        """The same three helpers, over the unplanted catalog, find nothing."""
        records = [
            record
            for section in ("assets", "content", "packages")
            for record in self.raw.get(section, [])
        ]
        self.assertEqual(
            [
                url
                for record in self.raw["assets"]
                for url in urls_in(record)
                if _is_kilix_hosted(url)
            ],
            [],
        )
        self.assertEqual(
            [
                mode
                for record in records
                for mode in modes_in(record)
                if mode in REFUSED_MODES
            ],
            [],
        )
        self.assertEqual(
            [
                key
                for record in records
                for key in source_keys_in(record)
                if key in REFUSED_SOURCE_KEYS
            ],
            [],
        )


if __name__ == "__main__":
    unittest.main()
