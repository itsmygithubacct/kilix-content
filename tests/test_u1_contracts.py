from __future__ import annotations

import hashlib
import json
import os
import unittest
import zipfile
from pathlib import Path

from jsonschema import Draft202012Validator

from kilix_content import (
    U1_SCHEMA_NAMES,
    U1ContractError,
    canonical_digest,
    canonical_json_bytes,
    packaged_resource_bytes,
    parse_json_bytes,
    validate_u1,
    verify_packaged_u1_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
FIXTURES = ROOT / "tests" / "fixtures" / "u1"
ZERO = "0" * 64


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class U1ContractTests(unittest.TestCase):
    def test_every_frozen_schema_is_valid_and_packaged_byte_identical(self) -> None:
        self.assertEqual(len(U1_SCHEMA_NAMES), 21)
        for name in U1_SCHEMA_NAMES:
            with self.subTest(name=name):
                root = CONTRACTS / name
                package = packaged_resource_bytes(name)
                self.assertEqual(root.read_bytes(), package)
                Draft202012Validator.check_schema(load(root))
        verify_packaged_u1_manifest()

    def test_all_valid_golden_contracts_are_semantic_admissions(self) -> None:
        paths = sorted((FIXTURES / "valid").glob("*.json"))
        self.assertEqual(len(paths), 19)
        for path in paths:
            with self.subTest(path=path.name):
                value = load(path)
                validate_u1(value)
                self.assertEqual(path.read_bytes(), canonical_json_bytes(value))

    def test_invalid_golden_contracts_refuse(self) -> None:
        paths = sorted((FIXTURES / "invalid").glob("*.json"))
        self.assertEqual(len(paths), 7)
        for path in paths:
            with self.subTest(path=path.name):
                value = load(path)
                with self.assertRaises(U1ContractError):
                    validate_u1(value)

    def test_schema_and_fixture_hash_manifest_is_current(self) -> None:
        from tests.update_u1_hashes import expected_manifest

        self.assertEqual(
            (FIXTURES / "SHA256SUMS").read_text(encoding="ascii"),
            expected_manifest(),
        )

    def test_catalog_global_namespace_alias_and_dependency_cycle_guards(self) -> None:
        catalog = load(FIXTURES / "valid" / "catalog-v5.json")
        with self.assertRaisesRegex(U1ContractError, "collides"):
            collision = json.loads(json.dumps(catalog))
            collision["aliases"]["demo.app"] = {
                "package_id": "demo.pkg",
                "member_path": "bin/demo",
            }
            validate_u1(collision)
        with self.assertRaisesRegex(U1ContractError, "cycle"):
            cyclic = json.loads(json.dumps(catalog))
            cyclic["packages"][0]["install"]["dependencies"] = [
                {"id": "demo.pkg", "role": "runtime"}
            ]
            validate_u1(cyclic)

    def test_catalog_install_modes_aliases_and_profile_references_are_closed(self) -> None:
        catalog = load(FIXTURES / "valid" / "catalog-v5.json")
        package = catalog["packages"][0]
        with self.assertRaises(U1ContractError):
            broken = json.loads(json.dumps(catalog))
            broken["packages"][0]["install"]["version"] = 1
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = json.loads(json.dumps(catalog))
            del broken["packages"][0]["install"]["source_bytes"]
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = json.loads(json.dumps(catalog))
            broken["packages"][0]["install"]["source_bytes"] = 4096
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = json.loads(json.dumps(catalog))
            broken["packages"][0]["install"]["system_requirements"][0] = {
                "id": "system.profile",
                "sha256": "0" * 64,
            }
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = json.loads(json.dumps(catalog))
            broken["packages"][0]["install"]["source_mode"] = "git"
            validate_u1(broken)

        direct = {
            "id": "direct.asset",
            "kind": "asset",
            "stable_slot": "direct-slot",
            "install": json.loads(json.dumps(package["install"])),
        }
        direct["install"]["source_mode"] = "user-supplied"
        direct["install"]["source_bytes"] = 1
        direct["install"]["source_bytes_max"] = 1
        catalog["content"].append(direct)
        validate_u1(catalog)
        with self.assertRaises(U1ContractError):
            direct["package_id"] = "demo.pkg"
            validate_u1(catalog)

    def test_profile_shapes_and_retention_directory_rules_are_non_vacuous(self) -> None:
        for name in ("system-requirements", "toolchain-profile", "sandbox-profile"):
            with self.subTest(name=name):
                validate_u1(load(FIXTURES / "valid" / f"{name}.json"))
        with self.assertRaises(U1ContractError):
            broken = load(FIXTURES / "valid" / "toolchain-profile.json")
            broken["environment"]["assignments"]["HOME"] = "/tmp"
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = load(FIXTURES / "valid" / "sandbox-profile.json")
            broken["mount_manifest"].append(dict(broken["mount_manifest"][0]))
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = load(FIXTURES / "valid" / "retention-directory-phase.json")
            broken["directory"]["temp_name"] = "ordinary-temp"
            validate_u1(broken)
        with self.assertRaises(U1ContractError):
            broken = load(FIXTURES / "valid" / "retention-impossible-state.json")
            broken["observed"]["transaction_phase"] = "hostile-phase"
            validate_u1(broken)
        envelope = load(FIXTURES / "valid" / "retention-envelope.json")
        self.assertTrue(all("ino" not in item["identity"] for item in envelope["components"]))

    def test_diagnostics_are_fixed_and_do_not_echo_untrusted_values(self) -> None:
        hostile = "PRIVATE/path/should-not-appear"
        for data in (
            b'{"a":1,"a":"' + hostile.encode() + b'"}',
        ):
            with self.assertRaises(U1ContractError) as caught:
                parse_json_bytes(data)
            self.assertNotIn(hostile, str(caught.exception))
        value = parse_json_bytes(b'{"' + hostile.encode() + b'":1}')
        with self.assertRaises(U1ContractError) as caught:
            validate_u1(value)
        self.assertNotIn(hostile, str(caught.exception))

    def test_canonical_parser_rejects_duplicates_numbers_and_noncanonical_bytes(self) -> None:
        with self.assertRaises(U1ContractError):
            parse_json_bytes(b'{"a":1,"a":2}\n')
        with self.assertRaises(U1ContractError):
            parse_json_bytes(b'{"a":1.0}\n')
        value = {"b": 1, "a": [True, None]}
        self.assertEqual(canonical_json_bytes(value), b'{"a":[true,null],"b":1}\n')
        self.assertEqual(
            canonical_digest("retention-intent", value),
            hashlib.sha256(b"kilix-content retention intent/v1\0" + canonical_json_bytes(value)).hexdigest(),
        )

    def test_capacity_roles_and_retention_terminal_state_are_closed(self) -> None:
        capacity = load(FIXTURES / "valid" / "capacity-v2.json")
        with self.assertRaisesRegex(U1ContractError, "root roles"):
            broken = json.loads(json.dumps(capacity))
            del broken["root_roles"]["installed-data"]
            validate_u1(broken)
        terminal = load(FIXTURES / "valid" / "retention-terminal-reuse.json")
        with self.assertRaisesRegex(U1ContractError, "terminal"):
            broken = json.loads(json.dumps(terminal))
            broken["children"] = ["M", "R", "P"]
            validate_u1(broken)

    def test_retention_provenance_fields_are_required(self) -> None:
        cases = (
            ("retention-journal.json", "envelope_digest"),
            ("retention-accounted.json", "envelope_digest"),
            ("retention-handoff-proof.json", "envelope_digest"),
            ("retention-handoff-proof.json", "handoff_nonce"),
        )
        for filename, field in cases:
            with self.subTest(filename=filename, field=field):
                value = load(FIXTURES / "valid" / filename)
                self.assertIn(field, value)
                broken = dict(value)
                del broken[field]
                with self.assertRaises(U1ContractError):
                    validate_u1(broken)

    def test_u1_scope_does_not_expose_u2_or_u3_operations(self) -> None:
        import kilix_content.u1 as u1

        names = set(dir(u1))
        self.assertNotIn("open_store", names)
        self.assertNotIn("recover_transaction", names)
        self.assertNotIn("record_authorization", names)
        self.assertEqual(ZERO, "0" * 64)

    def test_production_license_is_not_a_fixture_authority(self) -> None:
        self.assertEqual((ROOT / "src/kilix_content/licenses/MIT.txt").read_bytes(), packaged_resource_bytes("MIT.txt"))
        self.assertNotIn(b"fixture", packaged_resource_bytes("MIT.txt").lower())

    @unittest.skipUnless(os.environ.get("KILIX_CONTENT_WHEEL"), "run with the built wheel path")
    def test_wheel_contains_no_tests_or_fixture_authority(self) -> None:
        wheel = os.environ["KILIX_CONTENT_WHEEL"]
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
        for required in (
            "kilix.content.catalog-v5.schema.json",
            "kilix.pleb.system-requirements-v1.schema.json",
            "kilix.content.toolchain-profile-v1.schema.json",
            "kilix.content.sandbox-profile-v1.schema.json",
            "kilix.content.capacity-reserve-v2.schema.json",
            "kilix.content.u1-resources-v1.json",
        ):
            with self.subTest(required=required):
                self.assertTrue(any(name.endswith(f"/contracts/{required}") for name in names))
        self.assertTrue(any(name.endswith("/licenses/MIT.txt") for name in names))
        self.assertFalse(any("tests/" in name or "fixtures/" in name for name in names))
        self.assertFalse(any("u1-fixture" in name or "synthetic" in name for name in names))
        self.assertNotIn("kilix_content/contracts/SHA256SUMS", names)


if __name__ == "__main__":
    unittest.main()
