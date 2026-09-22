"""EnCodec records as first-use upstream-convert downloads (R4-068, OD-AR, OD-U).

OD-AR determined both EnCodec checkpoints **CC BY-NC 4.0, licensor Meta
Platforms**, binding, with the user's agreement required. It superseded the
0.2.1 records: the 48 kHz "MIT, informational" one and the 24 kHz "no grant,
user-supplied" one. In particular it ruled that "the E4 'mirrored' catalogue
record becomes a first-use download from the upstream pin (OD-U)".

The catalogue-wide guard below is the acceptance line "no record names a
Kilix-hosted URL, and no mode user-supplied or mirrored remains for EnCodec".
It is written over the whole catalog, not over this wave's two records.

Its worth is narrower than "the net that catches a bad merge" (C4-VERIFY F3):
`model.py` refuses each of those shapes at parse time, so on a real merge of
the 0.2.1 EnCodec lineage the parser fails first and the guard never sees the
catalog. What the guard adds is that it reads the raw JSON — so it survives a
future *relaxation* of the parser, and it sees keys the parser stops looking
at — and that a parse failure now makes it fail by naming the defect instead
of erroring out of `setUpClass`.

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
import subprocess
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


# This module is the one tracked file that legitimately holds the superseded
# digests as literals (SUPERSEDED_MANIFESTS below), so the scan excludes it by
# pathspec rather than by hand-reading its hits.
SELF_PATHSPEC = ":!tests/test_c4_encodec_records.py"


def tracked_files_holding(*patterns: str) -> tuple[list[str], int]:
    """Tracked files holding any of `patterns`, and git's own exit status.

    One `-e` per pattern (C4-VERIFY F1): with two bare patterns after `--`,
    git reads the second as a revision and dies `rc 128` with empty stdout, so
    an unchecked returncode makes the *error* read as a clean tree. The status
    is returned, not swallowed, and every caller asserts it is 0 or 1 — the
    absent/invisible distinction, decided by the command rather than assumed.
    """
    arguments = ["git", "grep", "-lF"]
    for pattern in patterns:
        arguments.extend(["-e", pattern])
    arguments.extend(["--", SELF_PATHSPEC])
    completed = subprocess.run(
        arguments, cwd=ROOT, capture_output=True, text=True
    )
    return [line for line in completed.stdout.splitlines() if line], (
        completed.returncode
    )


class CatalogWideEncodecGuardTests(unittest.TestCase):
    """The R4-068 acceptance guard, over every record in the catalog.

    **What this guard is worth, stated narrowly (C4-VERIFY F3).** It is not
    "the net that catches a bad merge". `model.py` refuses every shape a
    verifier could plant — a Kilix-hosted URL, an `official_url` or `mirrors`
    source key, `launch.mode: mirrored`, a licence row with no `record_digest`
    — at parse time, and a real bad merge therefore fails in the parser, not
    here. Its genuine value is narrower and worth stating so R4-180 does not
    over-rely on it: the guards below read the **raw JSON**, so they still act
    if the parser is ever relaxed, and they cover keys the parser never looks
    at once a record stops carrying them.

    Because the parser fires first, it must not be able to take this class
    down with it. `setUpClass` used to call `default_catalog()` directly, so an
    unparseable catalog **errored out of setUpClass** and the guard's
    diagnostic on a real bad merge was a traceback rather than "record X
    carries mode mirrored". The parse is attempted, its failure is held, the
    raw-JSON guards run regardless, and the two guards that genuinely need the
    parsed catalog fail with the parser's own message — which names the
    offending record.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = json.loads(CATALOG_JSON.read_text(encoding="utf-8"))
        try:
            cls.catalog = default_catalog()
        except Exception as error:  # CatalogError, and anything else
            cls.catalog = None
            cls.catalog_error = error
        else:
            cls.catalog_error = None

    def parsed_catalog(self):
        """The parsed catalog, or a failure naming why it could not be read."""
        if self.catalog_error is None:
            return self.catalog
        self.fail(
            "the packaged catalog does not parse, so the parsed-spec guards "
            "cannot run; the raw-JSON guards in this class still did. "
            f"{type(self.catalog_error).__name__}: {self.catalog_error}"
        )

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
        for spec in self.parsed_catalog().assets:
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
        for spec in self.parsed_catalog().assets:
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

    BAD_MERGE_ID = "encodec-48khz-frame-from-a-bad-merge"

    def bad_merge(self) -> dict:
        """The real 48 kHz record, carrying the 0.2.1 mode and mirror again.

        Copied from the live record rather than written out, so the planted
        record is well-formed everywhere except the defect: a hand-written
        stub fails on a missing field first and proves nothing about the
        defect's diagnostic.
        """
        record = json.loads(
            json.dumps(
                next(
                    item
                    for item in self.raw["assets"]
                    if item["id"] == "encodec-48khz-frame"
                )
            )
        )
        record["id"] = self.BAD_MERGE_ID
        record["source"] = {
            "mode": "mirrored",
            "mirrors": [self.MIRROR_URL],
            "provenance": record["source"]["provenance"],
        }
        return record

    def test_an_unparseable_merge_is_named_not_tracebacked(self) -> None:
        """C4-VERIFY F3: the diagnostic on a real bad merge names the record.

        A merged 0.2.1 record fails in `model.py`, not in the guards. What the
        guard class owes is that the failure a reader sees identifies the
        record instead of being a traceback out of `setUpClass`.
        """
        from kilix_content.model import Catalog

        planted = self.planted(self.bad_merge())
        with self.assertRaises(CatalogError) as raised:
            Catalog.loads(json.dumps(planted), label="planted catalog")
        message = str(raised.exception)
        self.assertIn(self.BAD_MERGE_ID, message)
        # And that message is what the guard class reports: parsed_catalog()
        # carries it into the failure text rather than letting setUpClass die.
        guard = CatalogWideEncodecGuardTests(
            "test_the_catalog_sections_are_all_scanned"
        )
        guard.catalog = None
        guard.catalog_error = raised.exception
        with self.assertRaises(guard.failureException) as failed:
            guard.parsed_catalog()
        self.assertIn(self.BAD_MERGE_ID, str(failed.exception))
        self.assertIn(
            "raw-JSON guards in this class still did", str(failed.exception)
        )

    def test_the_raw_guards_still_act_when_the_parser_refuses(self) -> None:
        """The narrow claim, made concrete: the raw scan needs no parser.

        The same three raw guards the class runs, over the same planted
        catalog the parser above refuses, scoped exactly as the class scopes
        them: the host guard over asset records (content and package records
        legitimately name Kilix's own repositories), the mode and source-key
        guards over every section.
        """
        planted = self.planted(self.bad_merge())
        rows = [
            (section, record.get("id", "<no id>"), record)
            for section in ("assets", "content", "packages")
            for record in planted.get(section, [])
        ]
        self.assertGreater(len(rows), 60, "the scan must see the whole catalog")
        by_mode = {
            record_id
            for _s, record_id, record in rows
            if set(modes_in(record)) & set(REFUSED_MODES)
        }
        by_key = {
            record_id
            for _s, record_id, record in rows
            if set(source_keys_in(record)) & set(REFUSED_SOURCE_KEYS)
        }
        by_host = {
            record_id
            for section, record_id, record in rows
            if section == "assets"
            and any(_is_kilix_hosted(url) for url in urls_in(record))
        }
        self.assertEqual(by_mode, {self.BAD_MERGE_ID})
        self.assertEqual(by_key, {self.BAD_MERGE_ID})
        self.assertEqual(by_host, {self.BAD_MERGE_ID})

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


# The accepted kilix-encodec populations (SR-1, SR-3, SR-5, SR-10), as
# kilix-encodec's own python/graph_population.py binds them.
ACCEPTED_MANIFESTS = {
    "encodec-24khz-stateful": (
        "bb615145d4a33dbfa4c07c1ff3283303b461af1c6fc83dbf50b59bcf6489f81b",
        "op17-v2-bb615145",
        9,
    ),
    "encodec-48khz-frame": (
        "2ce5225dc458dd30fe91854755dcfb360300fe3cee7d0c5682e7be684eae7a87",
        "op17-v1-2ce5225d",
        4,
    ),
}

# The 0.2.1 populations OD-AR superseded. Neither may survive as a live pin.
SUPERSEDED_MANIFESTS = (
    "02201a5a947dc0a0b9cce84d585eca35fb8a7e57aee4d404d5cb14f495f40b6c",
    "844d8fcfdb2fb13d0485a9429c83debb590dcf964244fe0d06c50b5ec3380e38",
)

# The kilix-license EnCodec records the two catalog records refer to.
RECORD_DIGESTS = {
    "encodec-24khz-stateful": (
        "8af1dc699df34436899f0b93dce271d2fadb119f62e136e74ad797686d880f4b"
    ),
    "encodec-48khz-frame": (
        "9c1baee4ad48816bba2568c7e14f136b388f11722d6e422a933a1a4a24d30f3f"
    ),
}
CC_BY_NC_TEXT = "41003d4a74749c0220e33dd415042164b5a1093ed401f36277234f772d22d3d0"
# The licence-history note, as kilix-license 7104ea5c binds it. Until 4db48b4c
# the advisory carried OD-AR's *specification* of the note instead of the note
# (C4-VERIFY F2); LIC6/LIC7 replaced it with text quoted byte for byte from the
# evidence packet's `upstream-licence-history.txt`.
HISTORY_NOTE_TEXT = (
    "8cfc463c41113f776eebc60642a0e4f9841aaff247d9659d8abc466743755260"
)
# The evidence source that note quotes, by its own digest. Pinning it is how
# this repository can tell a note that quotes a source from a note that merely
# describes one, without restating a single line of licence text here.
HISTORY_NOTE_SOURCE = (
    "1ce36c87223cc7a1cdd052a876440abd48e11604ffc0037a2b4afadef6da1e90"
)
NONCOMMERCIAL_TEXT = (
    "fa152afc73238001c008ff67f5b8a3c6d645cfb714a3900a37a2481a8e75d748"
)


class PackagedEncodecRecordTests(unittest.TestCase):
    """The two packaged records, as R4-068 requires them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = default_catalog()
        cls.records = load_determined_records()
        cls.raw = json.loads(CATALOG_JSON.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-c4-records-"))
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.texts = load_determined_texts(self.scratch / "texts")

    def test_both_records_are_first_use_upstream_convert_downloads(self) -> None:
        for asset_id in ACCEPTED_MANIFESTS:
            spec = self.catalog.require_asset(asset_id)
            with self.subTest(asset=asset_id):
                self.assertEqual(spec.source_mode, "upstream-convert")
                self.assertEqual(spec.provider, "kilix-encodec")
                self.assertEqual(spec.stream, "F101")
                self.assertEqual(spec.consumer_schema, "kilix.encodec.graphs/v1")
                # Downloaded, not supplied by hand: the record names the bytes.
                self.assertGreater(spec.download_bytes, 0)
                self.assertGreater(spec.convert_bytes, 0)
                self.assertTrue(spec.convert_url.startswith("https://"))

    def test_temporary_bytes_is_derived_and_never_below_its_floor(self) -> None:
        """C4-VERIFY F5: `temporary_bytes` gates a pre-install free-space check.

        Both records carried `4294967296`, which no measurement or derivation
        in this tree produces: the 24 kHz value was inherited from the E4
        `user-supplied` record (whose `download_bytes` was 0), and the 48 kHz
        record was raised 31x by copying it. An over-estimate refuses installs
        that would have worked.

        E4's 48 kHz `136405425` is *not* an independent measurement either --
        it is exactly that record's own `download_bytes + installed_bytes` --
        so carrying it here would put this record below its own floor. For an
        `upstream-convert` install the fetched inputs and the produced outputs
        are on disk at the same time, so that sum is the floor, and it is what
        the generator derives when the pin states nothing. The floor is
        asserted, not the exact value: a real conversion may measure more (see
        the converter-scratch caveat in C4-FIX-IMPL) and raise it through the
        pin's optional `temporary_bytes`.
        """
        pins = ROOT / "tools" / "upstream-pins"
        for asset_id in ACCEPTED_MANIFESTS:
            spec = self.catalog.require_asset(asset_id)
            raw = next(
                item for item in self.raw["assets"] if item["id"] == asset_id
            )
            sizes = raw["sizes"]
            with self.subTest(asset=asset_id):
                floor = sizes["download_bytes"] + sizes["installed_bytes"]
                self.assertGreaterEqual(sizes["temporary_bytes"], floor)
                self.assertEqual(sizes["download_bytes"], spec.download_bytes)
                # Derived, not declared: the pin states no override, so the
                # value in the record is the generator's own sum.
                pin = json.loads(
                    (pins / f"{asset_id}.json").read_text(encoding="utf-8")
                )
                if "temporary_bytes" not in pin:
                    self.assertEqual(sizes["temporary_bytes"], floor)
        # Control: the same rule holds for the only other upstream-convert
        # record, so this is the catalog's convention and not a local choice.
        other = next(
            item
            for item in self.raw["assets"]
            if item["source"]["mode"] == "upstream-convert"
            and item["id"] not in ACCEPTED_MANIFESTS
        )
        self.assertEqual(
            other["sizes"]["temporary_bytes"],
            other["sizes"]["download_bytes"] + other["sizes"]["installed_bytes"],
        )

    def test_the_populations_are_the_accepted_manifests(self) -> None:
        for asset_id, (manifest, version, count) in ACCEPTED_MANIFESTS.items():
            spec = self.catalog.require_asset(asset_id)
            with self.subTest(asset=asset_id):
                listed = {item.path: item.sha256 for item in spec.files}
                self.assertEqual(listed["manifest.json"], manifest)
                self.assertEqual(spec.version, version)
                self.assertTrue(version.endswith(manifest[:8]))
                graphs = [
                    item for item in spec.files
                    if not item.path.startswith("notices/")
                ]
                self.assertEqual(len(graphs), count)

    def test_no_superseded_population_survives_as_a_live_pin(self) -> None:
        """02201a5a (24 kHz) and 844d8fcf (48 kHz) are gone from the tree."""
        hits, code = tracked_files_holding(*SUPERSEDED_MANIFESTS)
        # 0 = a hit, 1 = no hit. Anything else is git failing, and a git
        # failure must never be read as an absence (C4-VERIFY F1).
        self.assertIn(code, (0, 1), f"git grep exited {code}")
        self.assertEqual(hits, [], hits)
        # Visibility control, in the SAME two-pattern shape the guard uses:
        # two digests that really are in the tree are found by it.
        seen, seen_code = tracked_files_holding(
            ACCEPTED_MANIFESTS["encodec-24khz-stateful"][0],
            ACCEPTED_MANIFESTS["encodec-48khz-frame"][0],
        )
        self.assertIn(seen_code, (0, 1), f"git grep exited {seen_code}")
        self.assertNotEqual(seen, [])

    def test_the_superseded_scan_refuses_a_git_failure(self) -> None:
        """A guard that cannot fail is worse than no guard (C4-VERIFY F1).

        The old command shape — two bare patterns after `--` — is what dies
        `rc 128` with empty stdout. Run it here on purpose: the status is not
        in (0, 1), which is exactly what the guard above now asserts, so the
        error cannot pass for a clean tree.
        """
        broken = subprocess.run(
            ["git", "grep", "-lF", "--", *SUPERSEDED_MANIFESTS],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(broken.stdout.strip(), "")
        self.assertNotIn(broken.returncode, (0, 1))
        self.assertIn("ambiguous argument", broken.stderr)
        # The corrected shape runs: it answers 0 or 1, never 128. What its
        # answer IS belongs to the guard above, not here.
        self.assertIn(tracked_files_holding(*SUPERSEDED_MANIFESTS)[1], (0, 1))

    def test_the_24khz_input_is_the_upstream_download(self) -> None:
        """Never user-supplied: the exact checkpoint, from Meta's own host."""
        spec = self.catalog.require_asset("encodec-24khz-stateful")
        self.assertEqual(
            spec.convert_url,
            "https://dl.fbaipublicfiles.com/encodec/v0/encodec_24khz-d7cc33bc.th",
        )
        self.assertEqual(spec.source_host, "dl.fbaipublicfiles.com")
        self.assertEqual(spec.convert_bytes, 93171529)
        self.assertEqual(
            spec.convert_sha256,
            "d7cc33bcf1aad7f2dad9836f36431530744abeace3ca033005e3290ed4fa47bf",
        )
        # A single file: no input directory, and nothing staged into the tree.
        self.assertEqual(spec.convert_inputs, ())
        self.assertEqual(spec.fetch, ())
        self.assertEqual(spec.convert_input_path, "")

    def test_the_48khz_input_is_the_pinned_hugging_face_revision(self) -> None:
        spec = self.catalog.require_asset("encodec-48khz-frame")
        revision = "c3def8e7185ac8c8efdce6eb8c4a651e487a503e"
        self.assertEqual(spec.provenance_project, "facebook/encodec_48khz")
        self.assertEqual(spec.provenance_revision, revision)
        self.assertEqual(
            spec.convert_sha256,
            "47a15ffbaf7bb76176d0833e10590de0a8988a7848748608cefc36a1c88adfdc",
        )
        self.assertEqual(spec.convert_bytes, 76291152)
        self.assertEqual(spec.convert_input_path, "model.safetensors")
        self.assertEqual(
            [item.path for item in spec.convert_inputs],
            ["config.json", "preprocessor_config.json"],
        )
        for item in (spec.convert_url, *[i.url for i in spec.convert_inputs]):
            self.assertIn(f"/resolve/{revision}/", item)
        # The converter's inputs are not part of the installed tree.
        installed = {file.path for file in spec.files}
        for name in ("model.safetensors", "config.json", "preprocessor_config.json"):
            self.assertNotIn(name, installed)

    def test_both_records_bind_cc_by_nc_4_0_with_attribution_to_meta(self) -> None:
        for asset_id, record_digest in RECORD_DIGESTS.items():
            spec = self.catalog.require_asset(asset_id)
            with self.subTest(asset=asset_id):
                self.assertEqual(len(spec.licenses), 1)
                row = spec.licenses[0]
                self.assertEqual(row.license_id, "cc-by-nc-4.0")
                self.assertEqual(list(row.licensors), ["Meta Platforms"])
                self.assertEqual(row.decision, "affirmative")
                self.assertEqual(row.record_digest, record_digest)
                self.assertEqual(row.text_sha256, CC_BY_NC_TEXT)
                # The record referred to is the vendored kilix-license one.
                record = self.records.by_digest(record_digest)
                self.assertEqual(record.id, asset_id)
                self.assertEqual(list(record.licence_ids), ["CC BY-NC 4.0"])
                self.assertEqual(record.licensor, "Meta Platforms")
                self.assertIn(
                    "notices/LICENSE-cc-by-nc-4.0.txt",
                    [file.path for file in spec.files],
                )

    def test_the_agreement_is_required_and_binding(self) -> None:
        """OD-AR: the user must agree; the non-commercial condition is binding."""
        from kilix_license.agreement import capture_agreement
        from kilix_license.errors import AgreementRequired

        for asset_id in RECORD_DIGESTS:
            record = self.records.by_id(asset_id)
            with self.subTest(asset=asset_id):
                required = [
                    condition
                    for condition in record.binding_conditions
                    if condition.agreement_required
                ]
                self.assertEqual(
                    [condition.id for condition in required],
                    ["encodec-noncommercial-binding"],
                )
                self.assertEqual(required[0].text_sha256, NONCOMMERCIAL_TEXT)
                with self.assertRaises(AgreementRequired):
                    capture_agreement(record, None)
                with self.assertRaises(AgreementRequired):
                    capture_agreement(record, "accept")
                self.assertIsNotNone(
                    capture_agreement(record, typed_agreement_line(record))
                )

    def screen_for(self, asset_id: str) -> str:
        from kilix_content.first_use import license_record_for, present_asset

        spec = self.catalog.require_asset(asset_id)
        record = license_record_for(spec, self.records)
        store = FakeStore(self.scratch / f"receipts-{asset_id}")
        return present_asset(
            spec, record, self.texts, receipts=store, records=self.records
        ).decode("utf-8")

    def test_the_first_use_screen_presents_the_licence_and_the_history_note(self) -> None:
        for asset_id in RECORD_DIGESTS:
            screen = self.screen_for(asset_id)
            with self.subTest(asset=asset_id):
                self.assertIn("licence: cc-by-nc-4.0", screen)
                self.assertIn("licensors: Meta Platforms", screen)
                self.assertIn(f"=== licence:{asset_id} ===", screen)
                self.assertIn("=== binding:encodec-noncommercial-binding ===", screen)
                self.assertIn("=== advisory:encodec-licence-history-note ===", screen)
                # The CC BY-NC 4.0 legal code itself, verbatim.
                self.assertIn(
                    self.texts.get(CC_BY_NC_TEXT).decode("utf-8"), screen
                )
                self.assertIn(
                    "Attribution-NonCommercial 4.0 International", screen
                )

    def test_the_licence_history_note_is_shown_verbatim_not_paraphrased(self) -> None:
        """The note is the bound text, byte for byte; nothing restates it."""
        note = self.texts.get(HISTORY_NOTE_TEXT).decode("utf-8")
        self.assertEqual(
            hashlib.sha256(note.encode("utf-8")).hexdigest(), HISTORY_NOTE_TEXT
        )
        for asset_id in RECORD_DIGESTS:
            record = self.records.by_id(asset_id)
            with self.subTest(asset=asset_id):
                advisories = {
                    advisory.id: advisory.text_sha256
                    for advisory in record.advisories
                }
                self.assertEqual(
                    advisories.get("encodec-licence-history-note"),
                    HISTORY_NOTE_TEXT,
                )
                self.assertIn(note, self.screen_for(asset_id))

    def test_the_bound_note_quotes_a_named_source(self) -> None:
        """R4-068 wants a *verbatim-sourced* note, not a description of one.

        C4-VERIFY F2: the advisory bound at kilix-license 4db48b4c was OD-AR's
        sentence specifying the note, sitting where the note should be, so the
        screen promised a verbatim-sourced note and did not keep the promise.
        A description cannot name the digest of the file it quotes, so the
        note's own text is checked for the quoting marker and that digest.
        Nothing here restates a line of licence text: the licence and the note
        both live in kilix-license's store and are shown from it.
        """
        note = self.texts.get(HISTORY_NOTE_TEXT).decode("utf-8")
        self.assertIn("quoted from", note)
        self.assertIn(HISTORY_NOTE_SOURCE, note)
        # A specification of the note would be a sentence; a quoting note
        # carries the quoted lines. Length alone is weak, so it is a floor,
        # not the assertion: the two above carry the claim.
        self.assertGreater(len(note), 512)

    def test_a_planted_changed_licence_text_re_presents(self) -> None:
        """SR-4: an earlier acceptance does not cover a changed bound text."""
        import dataclasses

        from kilix_license.agreement import capture_agreement
        from kilix_license.receipts import receipt_from_agreement
        from kilix_content.first_use import (
            license_record_for,
            needs_agreement,
            present_asset,
        )
        from kilix_content.receipt import _CATALOG_SHA256, release_digest
        from screen_marker import changed_block

        spec = self.catalog.require_asset("encodec-24khz-stateful")
        record = license_record_for(spec, self.records)
        store = FakeStore(self.scratch / "changed-receipts")
        store.write(
            receipt_from_agreement(
                record,
                capture_agreement(record, typed_agreement_line(record)),
                manifest_digest=spec.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        )
        self.assertFalse(
            needs_agreement(spec, records=self.records, store=store)
        )
        quiet = present_asset(
            spec, record, self.texts, receipts=store, records=self.records
        )
        self.assertEqual(changed_block(quiet), [])

        # One byte of the binding condition's text changes upstream.
        condition = record.binding_conditions[0]
        original = self.texts.get(condition.text_sha256)
        planted = original.replace(b"must agree", b"must Agree")
        self.assertEqual(len(planted), len(original))
        self.assertNotEqual(planted, original)
        digest = self.texts.put(planted, label="planted-encodec-binding")
        revised = dataclasses.replace(
            record,
            binding_conditions=(
                dataclasses.replace(condition, text_sha256=digest),
            ),
        )
        marked = present_asset(
            spec, revised, self.texts, receipts=store, records=self.records
        )
        block = changed_block(marked)
        self.assertNotEqual(block, [])
        self.assertIn("changed: binding:encodec-noncommercial-binding", block)
        self.assertIn(f"accepted sha256: {NONCOMMERCIAL_TEXT}", block)
        self.assertIn(f"shown sha256: {digest}", block)


class ConverterToolRecordTests(unittest.TestCase):
    """The tool asset records the two conversions name (R4-068 part 3)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = default_catalog()
        cls.raw = json.loads(CATALOG_JSON.read_text(encoding="utf-8"))

    TOOLS = ("kilix-encodec-convert-24khz", "kilix-encodec-convert-48khz")

    def tool(self, content_id: str) -> dict:
        return next(
            record for record in self.raw["content"] if record["id"] == content_id
        )

    def test_both_converters_have_a_tool_record(self) -> None:
        present = [
            record["id"]
            for record in self.raw["content"]
            if record["id"].startswith("kilix-encodec-convert-")
        ]
        self.assertEqual(sorted(present), sorted(self.TOOLS))
        for content_id in self.TOOLS:
            spec = self.catalog.require(content_id)
            with self.subTest(tool=content_id):
                self.assertEqual(spec.kind, "tool")
                self.assertEqual(spec.source_type, "git")
                self.assertEqual(
                    spec.repository,
                    "https://github.com/itsmygithubacct/kilix-encodec",
                )
                self.assertEqual(len(spec.ref), 40)

    def test_each_record_names_the_tool_that_converts_it(self) -> None:
        for asset_id, tool_id in (
            ("encodec-24khz-stateful", "kilix-encodec-convert-24khz"),
            ("encodec-48khz-frame", "kilix-encodec-convert-48khz"),
        ):
            spec = self.catalog.require_asset(asset_id)
            with self.subTest(asset=asset_id):
                self.assertEqual(spec.convert_tool_asset_id, tool_id)
                tool = self.catalog.require(tool_id)
                # argv[0] is the tool's own binary, by name.
                self.assertEqual(
                    Path(spec.convert_argv[0]).name, Path(tool.binary).name
                )
                self.assertEqual(Path(tool.binary).name, tool_id)

    def test_each_tool_builds_only_its_own_profile(self) -> None:
        for content_id, profile in (
            ("kilix-encodec-convert-24khz", "24khz"),
            ("kilix-encodec-convert-48khz", "48khz"),
        ):
            spec = self.catalog.require(content_id)
            with self.subTest(tool=content_id):
                build = list(spec.build)
                self.assertIn("--profile", build)
                self.assertEqual(build[build.index("--profile") + 1], profile)
                self.assertIn("tools/build_converter.py", build)

    def test_both_tools_are_pinned_at_the_same_ref_for_c5(self) -> None:
        """C4 pins the accepted release line; C5 re-pins to the released head."""
        refs = {self.catalog.require(name).ref for name in self.TOOLS}
        self.assertEqual(len(refs), 1, refs)

    def test_neither_tool_downloads_a_model(self) -> None:
        for content_id in self.TOOLS:
            spec = self.catalog.require(content_id)
            with self.subTest(tool=content_id):
                self.assertNotIn("network", spec.capabilities)

    def test_both_conversions_pass_the_gate_arguments(self) -> None:
        """The record's argv, not the caller, supplies the store and digest."""
        for asset_id in ACCEPTED_MANIFESTS:
            spec = self.catalog.require_asset(asset_id)
            argv = list(spec.convert_argv)
            with self.subTest(asset=asset_id):
                self.assertIn("--receipt-store", argv)
                self.assertIn("--manifest-digest", argv)
                self.assertEqual(
                    argv[argv.index("--receipt-store") + 1], "{receipt_store}"
                )
                self.assertEqual(
                    argv[argv.index("--manifest-digest") + 1], "{manifest_digest}"
                )
                self.assertEqual(argv[argv.index("--input") + 1], "{input}")
                self.assertEqual(argv[argv.index("--output") + 1], "{output}")
                # No literal digest may stand in for the record's own.
                for argument in argv:
                    self.assertNotRegex(argument, r"^[0-9a-f]{64}$")


def _pin_generator():
    """tools/generate_encodec_pins.py, loaded by path (tools/ is not a package)."""
    import importlib.util

    path = ROOT / "tools" / "generate_encodec_pins.py"
    spec = importlib.util.spec_from_file_location("generate_encodec_pins", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class EncodecPinGeneratorTests(unittest.TestCase):
    """The committed pin generator (C4-VERIFY F6), with planted controls.

    C4-IMPL generated `tools/upstream-pins/encodec-*.json` with a script it did
    not commit, so the pins were not re-derivable here. The script is now in
    the tree. It reads the other repository with `git show` only, so it needs
    that repository to run end to end; what the suite can do offline is exercise
    its guards on planted upstream data, and each guard is planted with the
    exact shape it claims to refuse. A generator whose refusals are never
    exercised is a generator with no refusals.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = _pin_generator()

    def upstream(self) -> tuple[dict, dict]:
        """The two upstream sources, rebuilt from the committed pins.

        Built from this repository's own pins so the fixture needs no other
        repository; the controls below then diverge one field at a time.
        """
        profiles: dict[str, dict] = {}
        native: dict[str, tuple[str, int, dict]] = {}
        for name, authored in self.generator.PROFILES.items():
            pin = json.loads(
                (ROOT / "tools" / "upstream-pins" / f"{authored['id']}.json")
                .read_text(encoding="utf-8")
            )
            inputs = {
                Path(pin["input"].get("path", pin["provenance"]["original_url"])).name: {
                    "bytes": pin["input"]["bytes"],
                    "sha256": pin["input"]["sha256"],
                    "url": pin["input"]["url"],
                }
            }
            for item in pin.get("inputs", []):
                inputs[item["path"]] = {
                    "bytes": item["bytes"],
                    "sha256": item["sha256"],
                    "url": item["url"],
                }
            outputs = {
                item["path"]: {"bytes": item["bytes"], "sha256": item["sha256"]}
                for item in pin["outputs"]
            }
            profile = {
                "command": authored["tool_asset_id"],
                "inputs": inputs,
                "outputs": outputs,
            }
            if name == "48khz":
                profile["revision"] = pin["provenance"]["revision"]
            profiles[name] = profile
            native[authored["id"]] = (
                pin["version"],
                sum(item["bytes"] for item in outputs.values()) + 1,
                # A deep copy, so a control that diverges one source really
                # does diverge it: sharing the dicts makes every "disagree"
                # control agree with itself and pass for the wrong reason.
                json.loads(json.dumps(outputs)),
            )
        return profiles, native

    def build(self, profiles: dict, native: dict, name: str = "24khz") -> dict:
        return self.generator.build_pin(
            name, profiles[name], native[self.generator.PROFILES[name]["id"]]
        )

    def test_the_fixture_reproduces_the_committed_pins(self) -> None:
        """Control: with nothing planted, the generator rebuilds both pins."""
        profiles, native = self.upstream()
        for name, authored in self.generator.PROFILES.items():
            with self.subTest(profile=name):
                rendered = self.generator.render(self.build(profiles, native, name))
                committed = (
                    ROOT / "tools" / "upstream-pins" / f"{authored['id']}.json"
                ).read_text(encoding="utf-8")
                self.assertEqual(rendered, committed)

    def test_a_superseded_population_is_refused(self) -> None:
        """The refusal is positive: the manifest must be the accepted one."""
        profiles, native = self.upstream()
        # Neither superseded digest is written here; any other digest is
        # refused, which is the property, and a stronger one.
        profiles["24khz"]["outputs"]["manifest.json"]["sha256"] = "a" * 64
        native["encodec-24khz-stateful"][2]["manifest.json"]["sha256"] = "a" * 64
        with self.assertRaises(self.generator.PinError) as raised:
            self.build(profiles, native)
        self.assertIn("not the accepted population", str(raised.exception))

    def test_the_two_upstream_sources_must_agree(self) -> None:
        profiles, native = self.upstream()
        profiles["24khz"]["outputs"]["encoder_stateful_op17.onnx"]["bytes"] += 1
        with self.assertRaises(self.generator.PinError) as raised:
            self.build(profiles, native)
        message = str(raised.exception)
        self.assertIn("disagree about", message)
        self.assertIn("encoder_stateful_op17.onnx", message)

    def test_a_version_that_does_not_name_its_population_is_refused(self) -> None:
        profiles, native = self.upstream()
        version, budget, population = native["encodec-24khz-stateful"]
        native["encodec-24khz-stateful"] = (version + "x", budget, population)
        with self.assertRaises(self.generator.PinError) as raised:
            self.build(profiles, native)
        self.assertIn("first eight hex characters", str(raised.exception))

    def test_a_population_over_the_native_budget_is_refused(self) -> None:
        profiles, native = self.upstream()
        version, _budget, population = native["encodec-24khz-stateful"]
        native["encodec-24khz-stateful"] = (version, 1, population)
        with self.assertRaises(self.generator.PinError) as raised:
            self.build(profiles, native)
        self.assertIn("over the native", str(raised.exception))

    def test_an_unpinned_digest_in_the_rendered_pin_is_refused(self) -> None:
        profiles, native = self.upstream()
        pin = self.build(profiles, native)
        pin["label"] = pin["label"] + " " + "b" * 64
        with self.assertRaises(self.generator.PinError) as raised:
            self.generator.check_no_stand_in(pin, self.generator.render(pin))
        self.assertIn("unpinned 64-hex", str(raised.exception))

    def test_the_generator_holds_no_superseded_digest(self) -> None:
        """It must not: the tree-wide scan would find it (F1's pathspec)."""
        text = (ROOT / "tools" / "generate_encodec_pins.py").read_text(
            encoding="utf-8"
        )
        for digest in SUPERSEDED_MANIFESTS:
            self.assertNotIn(digest, text)


if __name__ == "__main__":
    unittest.main()
