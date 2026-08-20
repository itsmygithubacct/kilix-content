from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker

from kilix_content import (
    AssetSpec,
    Catalog,
    CatalogError,
    Installer,
    InstallError,
    LicenseDecision,
    ReceiptMissing,
    ReceiptStore,
    ReleaseContext,
)
from tests.receipt_store_support import open_test_store

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"
SCHEMA_PATHS = {
    "asset": CONTRACTS / "kilix.content.asset-v1.schema.json",
    "license": CONTRACTS / "kilix.install.license-v1.schema.json",
}
EXPECTED_INVALID_FAILURES = {
    "asset-bad-file-digest.json": (("files", 0, "sha256"), "pattern"),
    "asset-http-mirror.json": (("source",), "oneOf"),
    "asset-parent-path.json": (("files", 0, "path"), "pattern"),
    "asset-unknown-property.json": ((), "additionalProperties"),
    "license-affirmative-record.json": (("outcome",), "enum"),
    "license-bad-timestamp.json": (("recorded_at",), "format"),
    "license-duplicate-artifact.json": (("artifact_ids",), "uniqueItems"),
    "license-restricted-receipt.json": ((), None),
    "license-user-supplied-missing-input.json": ((), "required"),
}
EXPECTED_SEMANTIC_FAILURES = {
    "asset-duplicate-file-path.json": "duplicate-file-path",
    "asset-installed-size-mismatch.json": "installed-size-mismatch",
    "asset-reversed-compatibility.json": "reversed-compatibility",
    "asset-unsafe-conversion-placeholders.json": "conversion-placeholders",
    "asset-user-supplied-license-mismatch.json": "user-supplied-license",
}
LICENSE_TEXT = b"Exact contract-test license text.\n"


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def release_context() -> ReleaseContext:
    return ReleaseContext.from_catalog(
        "0.2.1", b'{"release":"0.2.1","catalog":"contract-test"}\n'
    )


def authorize_asset(
    store: ReceiptStore, spec: AssetSpec, release: ReleaseContext
) -> None:
    requirement = spec.licenses[0]
    outcomes = {
        "informational": "record",
        "affirmative": "accept",
        "user-supplied": "supply",
    }
    decision = {
        "artifact_ids": [spec.asset_id],
        "decision_class": requirement.decision,
        "kind": "decision",
        "license_id": requirement.license_id,
        "license_text_sha256": requirement.text_sha256,
        "outcome": outcomes[requirement.decision],
        "presenter": "contract-test",
        "release": release.release_id,
        "schema": "kilix.install.license/v1",
    }
    if requirement.decision == "user-supplied":
        decision["input_sha256"] = spec.input_sha256
        decision["upstream_url"] = spec.official_url
    store.record(
        LicenseDecision.from_mapping(decision),
        LICENSE_TEXT,
        release,
        [spec],
    )


def asset_semantic_errors(value: dict) -> set[str]:
    """Validate v1 invariants JSON Schema cannot express portably."""
    errors: set[str] = set()
    paths = [entry["path"] for entry in value["files"]]
    if len(paths) != len(set(paths)):
        errors.add("duplicate-file-path")
    if value["sizes"]["installed_bytes"] != sum(
        entry["bytes"] for entry in value["files"]
    ):
        errors.add("installed-size-mismatch")
    compatibility = value["compatibility"]
    if compatibility["minimum"] > compatibility["maximum"]:
        errors.add("reversed-compatibility")
    source = value["source"]
    conversion = source.get("conversion")
    if conversion is not None:
        argv = conversion["argv"]
        if argv.count("{input}") != 1 or argv.count("{output}") != 1:
            errors.add("conversion-placeholders")
    if source["mode"] == "user-supplied" and not any(
        license_entry["decision"] == "user-supplied"
        for license_entry in value["licenses"]
    ):
        errors.add("user-supplied-license")
    return errors


class ContractFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validators = {}
        for name, path in SCHEMA_PATHS.items():
            schema = load_json(path)
            Draft202012Validator.check_schema(schema)
            cls.validators[name] = Draft202012Validator(
                schema, format_checker=FormatChecker()
            )

    def fixture_validator(self, path: Path) -> Draft202012Validator:
        kind = path.name.split("-", 1)[0]
        self.assertIn(kind, self.validators, f"unknown fixture schema: {path}")
        return self.validators[kind]

    def test_valid_golden_fixtures(self) -> None:
        paths = sorted((FIXTURES / "valid").glob("*.json"))
        self.assertTrue(paths, "valid fixture corpus is empty")
        for path in paths:
            with self.subTest(path=path.name):
                errors = list(
                    self.fixture_validator(path).iter_errors(load_json(path))
                )
                self.assertEqual(errors, [], "\n".join(map(str, errors)))

    def test_invalid_golden_fixtures(self) -> None:
        paths = sorted((FIXTURES / "invalid").glob("*.json"))
        self.assertTrue(paths, "invalid fixture corpus is empty")
        self.assertEqual(
            set(EXPECTED_INVALID_FAILURES) | set(EXPECTED_SEMANTIC_FAILURES),
            {p.name for p in paths},
        )
        for path in paths:
            with self.subTest(path=path.name):
                value = load_json(path)
                errors = list(
                    self.fixture_validator(path).iter_errors(value)
                )
                if path.name in EXPECTED_SEMANTIC_FAILURES:
                    self.assertEqual(errors, [], "semantic fixture is structurally invalid")
                    self.assertIn(
                        EXPECTED_SEMANTIC_FAILURES[path.name],
                        asset_semantic_errors(value),
                    )
                    continue
                self.assertTrue(errors, f"invalid fixture was accepted: {path}")
                failures = {
                    (tuple(error.absolute_path), error.validator)
                    for error in self._error_tree(errors)
                }
                self.assertIn(EXPECTED_INVALID_FAILURES[path.name], failures)

    def test_valid_assets_satisfy_semantic_invariants(self) -> None:
        for path in sorted((FIXTURES / "valid").glob("asset-*.json")):
            with self.subTest(path=path.name):
                self.assertEqual(asset_semantic_errors(load_json(path)), set())

    def test_schema_four_catalog_parses_and_indexes_assets(self) -> None:
        records = [
            load_json(path)
            for path in sorted((FIXTURES / "valid").glob("asset-*.json"))
        ]
        catalog = Catalog.from_mapping(
            {"schema_version": 4, "packages": [], "content": [], "assets": records}
        )
        self.assertEqual(len(catalog.assets), 2)
        mirrored = catalog.require_asset("voice.demo-small")
        supplied = catalog.require_asset("game.user-data")
        self.assertEqual(mirrored.source_mode, "mirrored")
        self.assertEqual(mirrored.files[0].path, "models/voice.bin")
        self.assertEqual(supplied.source_mode, "user-supplied")
        self.assertEqual(
            supplied.conversion_argv, ("extract", "{input}", "{output}")
        )
        self.assertIs(catalog.get_asset(mirrored.asset_id), mirrored)

    def test_asset_runtime_rejects_every_invalid_asset_fixture(self) -> None:
        paths = sorted((FIXTURES / "invalid").glob("asset-*.json"))
        for path in paths:
            with self.subTest(path=path.name), self.assertRaises(CatalogError):
                AssetSpec.from_mapping(load_json(path))

    def test_asset_runtime_enforces_frozen_array_and_string_limits(self) -> None:
        mirrored = load_json(FIXTURES / "valid" / "asset-mirrored.json")
        mirrored["source"]["mirrors"].append(
            mirrored["source"]["mirrors"][0]
        )
        with self.assertRaisesRegex(CatalogError, "duplicates"):
            AssetSpec.from_mapping(mirrored)

        supplied = load_json(FIXTURES / "valid" / "asset-user-supplied.json")
        supplied["source"]["conversion"]["argv"] = (
            ["extract", "{input}", "{output}"] + ["argument"] * 254
        )
        with self.assertRaisesRegex(CatalogError, "at most 256"):
            AssetSpec.from_mapping(supplied)

        supplied = load_json(FIXTURES / "valid" / "asset-user-supplied.json")
        supplied["source"]["conversion"]["argv"][0] = "x" * 4097
        with self.assertRaises(CatalogError):
            AssetSpec.from_mapping(supplied)

    def test_assets_require_schema_four_and_unique_ids(self) -> None:
        record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
        with self.assertRaisesRegex(CatalogError, "schema version 4"):
            Catalog.from_mapping(
                {"schema_version": 3, "packages": [], "content": [], "assets": [record]}
            )
        with self.assertRaisesRegex(CatalogError, "duplicate asset id"):
            Catalog.from_mapping(
                {
                    "schema_version": 4,
                    "packages": [],
                    "content": [],
                    "assets": [record, record],
                }
            )

    def test_asset_ready_verifies_exact_non_executable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = b"model-bytes"
            record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
            record["files"] = [
                {
                    "path": "models/model.bin",
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            ]
            record["sizes"]["installed_bytes"] = len(payload)
            record["licenses"][0]["text_sha256"] = hashlib.sha256(
                LICENSE_TEXT
            ).hexdigest()
            spec = AssetSpec.from_mapping(record)
            installer = Installer(temporary)
            selected = Path(installer.asset_destination(spec))
            target = selected / "models" / "model.bin"
            target.parent.mkdir(parents=True)
            target.write_bytes(payload)
            target.chmod(0o600)
            release = release_context()
            with open_test_store(str(Path(temporary) / "receipts")) as store:
                with self.assertRaises(ReceiptMissing):
                    installer.asset_ready(spec, store, release)
                authorize_asset(store, spec, release)
                self.assertEqual(
                    installer.asset_ready(spec, store, release), (str(target),)
                )

                target.chmod(0o700)
                self.assertIsNone(installer.asset_ready(spec, store, release))
                target.chmod(0o600)
                target.write_bytes(b"wrong-bytes")
                self.assertIsNone(installer.asset_ready(spec, store, release))
                target.write_bytes(payload)
                (selected / "unexpected").write_bytes(b"extra")
                self.assertIsNone(installer.asset_ready(spec, store, release))

    def test_ensure_asset_installs_verified_mirror_atomically_and_is_idempotent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"model-bytes"
            source = root / "source"
            target = source / "models" / "model.bin"
            target.parent.mkdir(parents=True)
            target.write_bytes(payload)
            archive = root / "model.tar"
            with tarfile.open(archive, "w") as handle:
                handle.add(target, arcname="models/model.bin")

            record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
            record["files"] = [
                {
                    "path": "models/model.bin",
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            ]
            record["sizes"]["installed_bytes"] = len(payload)
            record["licenses"][0]["text_sha256"] = hashlib.sha256(
                LICENSE_TEXT
            ).hexdigest()
            record["source"]["archive_sha256"] = hashlib.sha256(
                archive.read_bytes()
            ).hexdigest()
            spec = AssetSpec.from_mapping(record)
            installer = Installer(str(root / "installed"))
            release = release_context()

            with open_test_store(str(root / "receipts")) as store:
                authorize_asset(store, spec, release)

                def copy_download(_urls, destination, _report, expected_sha256):
                    self.assertEqual(
                        expected_sha256, record["source"]["archive_sha256"]
                    )
                    shutil.copyfile(archive, destination)
                    return destination

                with mock.patch(
                    "kilix_content.install.download", side_effect=copy_download
                ) as download_mock:
                    paths = installer.ensure_asset(spec, store, release)
                    self.assertEqual(
                        paths, installer.ensure_asset(spec, store, release)
                    )
                self.assertEqual(download_mock.call_count, 1)
            self.assertEqual(Path(paths[0]).read_bytes(), payload)
            self.assertEqual(Path(paths[0]).stat().st_mode & 0o111, 0)
            self.assertFalse(
                any(
                    path.name.startswith(f".{spec.version}.install-")
                    for path in Path(installer.asset_destination(spec)).parent.iterdir()
                )
            )

    def test_ensure_asset_rejects_bad_tree_without_selecting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "wrong.bin"
            payload.write_bytes(b"wrong")
            archive = root / "wrong.tar"
            with tarfile.open(archive, "w") as handle:
                handle.add(payload, arcname="models/voice.bin")
            record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
            record["licenses"][0]["text_sha256"] = hashlib.sha256(
                LICENSE_TEXT
            ).hexdigest()
            record["source"]["archive_sha256"] = hashlib.sha256(
                archive.read_bytes()
            ).hexdigest()
            spec = AssetSpec.from_mapping(record)
            installer = Installer(str(root / "installed"))
            release = release_context()

            with open_test_store(str(root / "receipts")) as store:
                authorize_asset(store, spec, release)
                with (
                    mock.patch(
                        "kilix_content.install.download",
                        side_effect=lambda _urls, destination, _report, _sha: shutil.copyfile(
                            archive, destination
                        ),
                    ),
                    self.assertRaisesRegex(InstallError, "does not match"),
                ):
                    installer.ensure_asset(spec, store, release)
            self.assertFalse(Path(installer.asset_destination(spec)).exists())

    def test_ensure_asset_fails_closed_without_exact_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            installer = Installer(temporary)
            release = release_context()
            affirmative = load_json(
                FIXTURES / "valid" / "asset-mirrored.json"
            )
            affirmative["licenses"][0]["decision"] = "affirmative"
            affirmative["licenses"][0]["text_sha256"] = hashlib.sha256(
                LICENSE_TEXT
            ).hexdigest()

            supplied = load_json(
                FIXTURES / "valid" / "asset-user-supplied.json"
            )
            supplied["licenses"][0]["text_sha256"] = hashlib.sha256(
                LICENSE_TEXT
            ).hexdigest()
            with open_test_store(str(Path(temporary) / "receipts")) as store:
                with self.assertRaises(ReceiptMissing):
                    installer.ensure_asset(
                        AssetSpec.from_mapping(affirmative), store, release
                    )
                with self.assertRaises(ReceiptMissing):
                    installer.ensure_asset(
                        AssetSpec.from_mapping(supplied), store, release
                    )

    @classmethod
    def _error_tree(cls, errors):
        for error in errors:
            yield error
            yield from cls._error_tree(error.context)

    def test_fixtures_have_canonical_json_bytes(self) -> None:
        paths = sorted(FIXTURES.glob("*/*.json"))
        for path in paths:
            with self.subTest(path=path.relative_to(FIXTURES)):
                expected = (
                    json.dumps(load_json(path), indent=2, sort_keys=True) + "\n"
                ).encode("utf-8")
                self.assertEqual(path.read_bytes(), expected)

    def test_fixture_sha256_manifest(self) -> None:
        manifest = FIXTURES / "SHA256SUMS"
        expected_paths = sorted(SCHEMA_PATHS.values()) + sorted(
            FIXTURES.glob("*/*.json")
        )
        expected = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(ROOT).as_posix()}\n"
            for path in expected_paths
        )
        self.assertEqual(manifest.read_text(encoding="ascii"), expected)


if __name__ == "__main__":
    unittest.main()
