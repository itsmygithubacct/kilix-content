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

import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fake_store import FakeStore
from kilix_license.agreement import typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts

from kilix_content import default_catalog
from kilix_content.first_use import install_with_agreement
from kilix_content.install import InstallError, Installer
from kilix_content.model import AssetSpec, CatalogError, _is_kilix_hosted

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


# A stand-in for the kilix-encodec converter that keeps the one behaviour this
# wave has to prove: E1-VERIFY F7 says the real gate admits *whatever* manifest
# digest the caller asserts, so long as a receipt covers it. The gate is the
# real kilix-license `require()`; only the export is stubbed out.
STUB_CONVERTER = '''\
import argparse, json, os, sys
from kilix_license.catalog import load_determined_records
from kilix_license.coverage import AssetRef, require
from kilix_license.errors import CoverageRefused
from kilix_license.store import ReceiptStore

parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--receipt-store", default=None)
parser.add_argument("--manifest-digest", default=None)
parser.add_argument("--asset-id", required=True)
parser.add_argument("--record-id", required=True)
parser.add_argument("--population", required=True)
parser.add_argument("--argv-log", required=True)
arguments = parser.parse_args()

with open(arguments.argv_log, "w", encoding="utf-8") as handle:
    json.dump(sys.argv[1:], handle)

# The gate runs before any input, runtime or output is touched.
if not arguments.receipt_store:
    sys.exit("conversion refused: a receipt store is required")
if not arguments.manifest_digest:
    sys.exit("conversion refused: a manifest digest is required")
record = load_determined_records().by_id(arguments.record_id)
try:
    require(
        AssetRef(
            id=arguments.asset_id,
            record_digest=record.digest,
            manifest_digest=arguments.manifest_digest,
        ),
        records=load_determined_records(),
        store=ReceiptStore(arguments.receipt_store),
    )
except CoverageRefused as error:
    sys.exit("conversion refused: " + str(error))

output = arguments.output
if not os.path.isdir(output) or os.listdir(output):
    sys.exit("conversion refused: output must be an existing, private empty directory")

# The pinned inputs must all be where the installer staged them.
population = json.loads(arguments.population)
for name in population.pop("__inputs__"):
    candidate = (
        os.path.join(arguments.input, name)
        if os.path.isdir(arguments.input)
        else arguments.input
    )
    if not os.path.isfile(candidate):
        sys.exit("conversion refused: missing input " + name)

for name, text in population.items():
    target = os.path.join(output, name)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as handle:
        handle.write(text.encode("utf-8"))
'''


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class EncodecShapedInstallTests(unittest.TestCase):
    """The install path over FakeUpstream, in the EnCodec record's shape.

    The two packaged records name the real kilix-encodec converter, which is a
    900 MB build this suite must not run and whose inputs are model weights
    this suite must never download. These tests therefore drive the *installer*
    over a fixture asset with the same record shape -- conversion output as the
    installed tree, inputs staged outside it, and the same argv -- against the
    real licence authority.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.records = load_determined_records()

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-c4-"))
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.texts = load_determined_texts(self.scratch / "texts")
        self.store = FakeStore(self.scratch / "receipts")
        self.installer = Installer(str(self.scratch / "root"))
        self.argv_log = self.scratch / "argv.json"
        self.converter = self.scratch / "stub-converter.py"
        self.converter.write_text(STUB_CONVERTER, encoding="utf-8")
        from first_use_fixture import FakeUpstream

        self.upstream = FakeUpstream()
        self.addCleanup(self.upstream.close)

    POPULATION = {
        "manifest.json": '{"population": "fixture"}',
        "encoder_frame_op17.onnx": "encoder-fixture",
        "rvq-codebooks.f32le": "codebooks-fixture",
    }

    def make_asset(
        self,
        *,
        record_id: str = "encodec-48khz-frame",
        asset_id: str = "fixture-encodec-48khz",
        manifest_digest_argument: str | None = None,
        receipt_store_argument: str | None = None,
        extra_inputs: bool = True,
    ) -> dict[str, Any]:
        """A record whose installed tree is the conversion's own output."""
        record = self.records.by_id(record_id)
        notice = self.texts.get(record.text_sha256)
        files = [
            {
                "bytes": len(text.encode("utf-8")),
                "path": name,
                "sha256": sha256_bytes(text.encode("utf-8")),
            }
            for name, text in self.POPULATION.items()
        ]
        files.append(
            {
                "bytes": len(notice),
                "path": "notices/LICENSE-cc-by-nc-4.0.txt",
                "sha256": sha256_bytes(notice),
            }
        )
        files.sort(key=lambda item: item["path"])

        primary = b"safetensors-fixture-weights"
        primary_url = self.upstream.add("/model.safetensors", primary)
        extras = {
            "config.json": b'{"config": "fixture"}',
            "preprocessor_config.json": b'{"preprocessor": "fixture"}',
        }
        inputs = [
            {
                "bytes": len(body),
                "path": name,
                "sha256": sha256_bytes(body),
                "url": self.upstream.add("/" + name, body),
            }
            for name, body in extras.items()
        ]
        payload = dict(self.POPULATION)
        payload["__inputs__"] = ["model.safetensors"] + (
            [item["path"] for item in inputs] if extra_inputs else []
        )
        argv = [
            sys.executable,
            str(self.converter),
            "--input",
            "{input}",
            "--output",
            "{output}",
            "--asset-id",
            asset_id,
            "--record-id",
            record_id,
            "--population",
            json.dumps(payload),
            "--argv-log",
            str(self.argv_log),
        ]
        if receipt_store_argument is None:
            argv += ["--receipt-store", "{receipt_store}"]
        elif receipt_store_argument != "":
            argv += ["--receipt-store", receipt_store_argument]
        if manifest_digest_argument is None:
            argv += ["--manifest-digest", "{manifest_digest}"]
        elif manifest_digest_argument != "":
            argv += ["--manifest-digest", manifest_digest_argument]

        source: dict[str, Any] = {
            "conversion": {"argv": argv, "tool_asset_id": "kilix-encodec-convert-48khz"},
            "input": {
                "bytes": len(primary),
                "path": "model.safetensors",
                "sha256": sha256_bytes(primary),
                "url": primary_url,
            },
            "mode": "upstream-convert",
            "provenance": {
                "original_url": primary_url,
                "project": "facebook/encodec_48khz",
                "revision": "fixture",
            },
        }
        if extra_inputs:
            source["inputs"] = inputs
        installed = sum(int(item["bytes"]) for item in files)
        download = len(primary) + sum(len(body) for body in extras.values())
        return {
            "compatibility": {
                "consumer_schema": "kilix.encodec.graphs/v1",
                "maximum": 1,
                "minimum": 1,
            },
            "files": files,
            "id": asset_id,
            "label": asset_id,
            "licenses": [
                {
                    "decision": record.decision_class,
                    "id": "cc-by-nc-4.0",
                    "licensors": ["Meta Platforms"],
                    "record_digest": record.digest,
                    "text_sha256": record.text_sha256,
                }
            ],
            "provider": "kilix-encodec",
            "schema": "kilix.content.asset/v3",
            "sizes": {
                "download_bytes": download,
                "installed_bytes": installed,
                "temporary_bytes": download + installed,
            },
            "source": source,
            "stream": "F101",
            "version": "fixture",
        }

    def install(self, mapping: dict[str, Any], *, record_id: str = "encodec-48khz-frame"):
        spec = AssetSpec.from_mapping(mapping)
        record = self.records.by_id(record_id)
        return spec, install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=self.records,
            texts=self.texts,
            typed_text=typed_agreement_line(record),
            screen=io.BytesIO(),
        )

    def logged_argv(self) -> list[str]:
        return json.loads(self.argv_log.read_text(encoding="utf-8"))

    # ---- the gate arguments (E1-VERIFY F7) ----

    def test_the_installer_passes_the_real_receipt_store_and_manifest_digest(self) -> None:
        """Not a stand-in: the store the receipt was written to, and the record's own digest."""
        spec, result = self.install(self.make_asset())
        self.assertIsNotNone(result)
        argv = self.logged_argv()
        self.assertIn("--receipt-store", argv)
        self.assertIn("--manifest-digest", argv)
        self.assertEqual(
            argv[argv.index("--receipt-store") + 1], os.fspath(self.store.root)
        )
        passed = argv[argv.index("--manifest-digest") + 1]
        self.assertEqual(passed, spec.manifest_digest)
        self.assertRegex(passed, r"^[0-9a-f]{64}$")
        # The receipt the screen wrote binds the same digest the gate was given.
        receipts = list(self.store.root.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertIn(passed, receipts[0].name)
        # And it is not any of the obvious stand-ins.
        for stand_in in ("c" * 64, "9" * 64, "f" * 64, "0" * 64):
            self.assertNotEqual(passed, stand_in)

    def test_a_stand_in_manifest_digest_is_refused_by_the_gate(self) -> None:
        """The reason the real digest is load-bearing: a receipt covers only its own."""
        with self.assertRaises(InstallError) as raised:
            self.install(self.make_asset(manifest_digest_argument="c" * 64))
        self.assertIn("conversion failed", str(raised.exception))
        self.assertEqual(self.logged_argv()[-1], "c" * 64)

    def test_an_absent_manifest_digest_is_refused_by_the_gate(self) -> None:
        with self.assertRaises(InstallError):
            self.install(self.make_asset(manifest_digest_argument=""))
        self.assertNotIn("--manifest-digest", self.logged_argv())

    def test_an_absent_receipt_store_is_refused_by_the_gate(self) -> None:
        with self.assertRaises(InstallError):
            self.install(self.make_asset(receipt_store_argument=""))
        self.assertNotIn("--receipt-store", self.logged_argv())

    def test_a_receipt_store_that_holds_no_covering_receipt_is_refused(self) -> None:
        empty = self.scratch / "empty-store"
        empty.mkdir(mode=0o700)
        with self.assertRaises(InstallError):
            self.install(self.make_asset(receipt_store_argument=str(empty)))

    # ---- the installed tree is the conversion's own output ----

    def test_the_installed_tree_is_the_population_and_the_notice_only(self) -> None:
        spec, result = self.install(self.make_asset())
        root = Path(result[0])
        present = sorted(
            str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
        )
        self.assertEqual(present, sorted(item.path for item in spec.files))
        for name in ("model.safetensors", "config.json", "preprocessor_config.json"):
            self.assertFalse((root / name).exists(), name)
        self.assertTrue((root / "notices/LICENSE-cc-by-nc-4.0.txt").is_file())

    def test_only_the_pinned_upstream_bytes_are_downloaded(self) -> None:
        self.install(self.make_asset())
        gotten = sorted(
            item["path"]
            for item in self.upstream.requests()
            if item.get("command") == "GET"
        )
        self.assertEqual(
            gotten, ["/config.json", "/model.safetensors", "/preprocessor_config.json"]
        )

    def test_every_extra_input_reaches_the_converter(self) -> None:
        """Control: drop one pinned input and the converter refuses for want of it.

        The record still asks the converter for all three names, so this fails
        at the missing file rather than at the licence gate.
        """
        mapping = self.make_asset()
        dropped = mapping["source"]["inputs"].pop()
        self.assertEqual(dropped["path"], "preprocessor_config.json")
        with self.assertRaises(InstallError) as raised:
            self.install(mapping)
        self.assertIn("conversion failed", str(raised.exception))
        self.assertIn("missing input preprocessor_config.json", str(raised.exception))

    # ---- the record shape itself ----

    def test_an_input_that_is_also_an_installed_file_is_refused(self) -> None:
        mapping = self.make_asset()
        mapping["source"]["inputs"][0]["path"] = "manifest.json"
        with self.assertRaises(CatalogError) as raised:
            AssetSpec.from_mapping(mapping)
        self.assertIn("must not be an installed file", str(raised.exception))

    def test_an_input_name_with_a_directory_part_is_refused(self) -> None:
        mapping = self.make_asset()
        mapping["source"]["inputs"][0]["path"] = "nested/config.json"
        with self.assertRaises(CatalogError) as raised:
            AssetSpec.from_mapping(mapping)
        self.assertIn("plain file name", str(raised.exception))

    def test_inputs_and_fetch_are_mutually_exclusive(self) -> None:
        mapping = self.make_asset()
        mapping["source"]["fetch"] = [
            {"path": "manifest.json", "url": mapping["source"]["input"]["url"]}
        ]
        with self.assertRaises(CatalogError) as raised:
            AssetSpec.from_mapping(mapping)
        self.assertIn("mutually exclusive", str(raised.exception))

    def test_the_extra_inputs_are_part_of_the_record_identity(self) -> None:
        """A changed extra input changes the record digest, not just its bytes."""
        from kilix_content.model import source_objects_sha256

        first = AssetSpec.from_mapping(self.make_asset())
        mapping = self.make_asset()
        mapping["source"]["inputs"][0]["sha256"] = "a" * 64
        second = AssetSpec.from_mapping(mapping)
        self.assertNotEqual(first.digest, second.digest)
        self.assertNotEqual(
            source_objects_sha256(first), source_objects_sha256(second)
        )


if __name__ == "__main__":
    unittest.main()
