from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import MappingProxyType
from unittest import mock

from jsonschema import Draft202012Validator, ValidationError

import kilix_content.u1 as u1_module
from kilix_content import (
    U1_SCHEMA_NAMES,
    PackagedReleaseCapability,
    U1ContractError,
    U1_MANIFEST_NAME,
    U1_MANIFEST_SHA256,
    canonical_json_bytes,
    filesystem_key_bytes,
    filesystem_key_digest,
    packaged_release_capability,
    packaged_resource_bytes,
    parse_json_bytes,
    production_capacity_policy_available,
    validate_u1_bytes,
    verify_packaged_u1_manifest,
)
from kilix_content.u1_capacity import (
    CAPACITY_PHASES,
    validate_capacity_generation_chain,
)
from kilix_content.u1_catalog import (
    validate_authorization_against_records,
    validate_catalog_resource_bundle,
    validate_catalog_transition,
    validate_license_text_bundle,
)
from kilix_content.u1_core import (
    S64_MAX,
    authorization_record_digest,
    canonical_digest,
    checked_add,
    checked_mul,
    checked_round_up,
)
from kilix_content.u1_retention import (
    validate_accounted_provenance,
    validate_directory_observation,
    validate_handoff_provenance,
    validate_intent_envelope,
    validate_marker_against_intent,
    validate_relation_against_marker,
    validate_retention_admission,
    validate_transaction_generation_chain,
)
from tests.u1_vectors import (
    authorization,
    authority_binding,
    capacity_chain,
    catalog,
    clone,
    directory_observation,
    license_manifest,
    logical_state,
    output_binding,
    physical_state,
    retention_envelope,
    retention_provenance_bundle,
    sandbox_profile,
    sha,
    system_profile,
    toolchain_profile,
)
from tools.render_u1_fixtures import REQUIRED_VECTOR_IDS, build_vectors


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
PACKAGE = ROOT / "src" / "kilix_content"
FIXTURES = ROOT / "tests" / "fixtures" / "u1"


def load_json(path: Path) -> object:
    return json.loads(path.read_bytes())


def expected_sums() -> str:
    paths = sorted(
        [FIXTURES / "index.json", *(FIXTURES / "corpus").rglob("*.json")],
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    return "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(ROOT).as_posix()}\n"
        for path in paths
    )


class U1ResourceAndCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capability = packaged_release_capability()

    def test_exact_schema_inventory_and_packaged_bytes(self) -> None:
        self.assertEqual(len(U1_SCHEMA_NAMES), 25)
        manifest_root = CONTRACTS / U1_MANIFEST_NAME
        manifest_package = PACKAGE / "contracts" / U1_MANIFEST_NAME
        raw_manifest = manifest_root.read_bytes()
        self.assertEqual(raw_manifest, manifest_package.read_bytes())
        self.assertEqual(hashlib.sha256(raw_manifest).hexdigest(), U1_MANIFEST_SHA256)
        self.assertEqual(raw_manifest, canonical_json_bytes(parse_json_bytes(raw_manifest)))
        self.assertFalse(raw_manifest.endswith(b"\n"))

        manifest = parse_json_bytes(raw_manifest)
        entries = manifest["resources"]
        self.assertEqual(len(entries), 26)
        schema_entries = [entry for entry in entries if entry["role"] == "schema"]
        self.assertEqual(
            {Path(entry["path"]).name for entry in schema_entries},
            set(U1_SCHEMA_NAMES),
        )
        self.assertEqual(
            [entry for entry in entries if entry["role"] == "license-text"],
            [
                next(
                    entry
                    for entry in entries
                    if entry["path"] == "licenses/MIT.txt"
                )
            ],
        )
        for entry in schema_entries:
            with self.subTest(schema_id=entry["schema_id"]):
                name = Path(entry["path"]).name
                root_payload = (CONTRACTS / "u1" / name).read_bytes()
                package_payload = packaged_resource_bytes(name)
                self.assertEqual(root_payload, package_payload)
                self.assertEqual(len(root_payload), entry["size"])
                self.assertEqual(hashlib.sha256(root_payload).hexdigest(), entry["sha256"])
                self.assertEqual(root_payload, canonical_json_bytes(parse_json_bytes(root_payload)))
                Draft202012Validator.check_schema(parse_json_bytes(root_payload))
        verify_packaged_u1_manifest()

    def test_corpus_index_hashes_and_renderer_are_exact(self) -> None:
        raw_index = (FIXTURES / "index.json").read_bytes()
        index = parse_json_bytes(raw_index)
        self.assertEqual(raw_index, canonical_json_bytes(index))
        rendered = {entry["id"]: entry for entry in build_vectors()}
        indexed = {entry["id"]: entry for entry in index["entries"]}
        self.assertEqual(set(indexed), set(rendered))
        self.assertTrue(set(REQUIRED_VECTOR_IDS) <= set(indexed))
        self.assertEqual(len(indexed), 151)

        indexed_paths: set[str] = set()
        for identifier, entry in indexed.items():
            with self.subTest(identifier=identifier):
                vector = rendered[identifier]
                expected_path = f"corpus/{entry['class']}/{identifier}.json"
                self.assertEqual(entry["path"], expected_path)
                self.assertEqual(entry["class"], vector["class"])
                self.assertEqual(entry["schema_id"], vector["schema_id"])
                self.assertEqual(entry["expected_stage"], vector["expected_stage"])
                self.assertEqual(entry["expected_code"], vector["expected_code"])
                payload = (FIXTURES / entry["path"]).read_bytes()
                self.assertEqual(payload, vector["raw"])
                self.assertEqual(entry["size"], len(payload))
                self.assertEqual(entry["sha256"], hashlib.sha256(payload).hexdigest())
                indexed_paths.add(entry["path"])
        actual_paths = {
            path.relative_to(FIXTURES).as_posix()
            for path in (FIXTURES / "corpus").rglob("*.json")
        }
        self.assertEqual(actual_paths, indexed_paths)
        self.assertEqual((FIXTURES / "SHA256SUMS").read_text("ascii"), expected_sums())

    def test_every_corpus_record_fails_at_its_declared_earliest_stage(self) -> None:
        index = parse_json_bytes((FIXTURES / "index.json").read_bytes())
        for entry in index["entries"]:
            with self.subTest(identifier=entry["id"]):
                raw = (FIXTURES / entry["path"]).read_bytes()
                expected_stage = entry["expected_stage"]
                if expected_stage in {"parser", "canonical"}:
                    with self.assertRaises(U1ContractError) as caught:
                        parse_json_bytes(raw)
                    self.assertEqual(caught.exception.code, entry["expected_code"])
                    continue

                value = parse_json_bytes(raw)
                if expected_stage == "routing":
                    with self.assertRaises(U1ContractError) as caught:
                        validate_u1_bytes(entry["schema_id"], raw, self.capability)
                    self.assertEqual(caught.exception.code, entry["expected_code"])
                    continue

                schema_path = self.capability._routes[entry["schema_id"]]
                schema = parse_json_bytes(self.capability._resources[schema_path])
                validator = Draft202012Validator(schema)
                if expected_stage == "schema":
                    with self.assertRaises(ValidationError):
                        validator.validate(value)
                    with self.assertRaises(U1ContractError) as caught:
                        validate_u1_bytes(entry["schema_id"], raw, self.capability)
                    self.assertEqual(caught.exception.code, entry["expected_code"])
                    continue

                validator.validate(value)
                if expected_stage == "semantic":
                    with self.assertRaises(U1ContractError) as caught:
                        validate_u1_bytes(entry["schema_id"], raw, self.capability)
                    self.assertEqual(caught.exception.code, entry["expected_code"])
                    continue

                result = validate_u1_bytes(entry["schema_id"], raw, self.capability)
                self.assertEqual(result.raw_bytes, raw)
                self.assertIsInstance(result.value, MappingProxyType)


class U1AdmissionAndAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capability = packaged_release_capability()
        cls.catalog_raw = canonical_json_bytes(catalog())

    def test_only_raw_bytes_and_the_genuine_capability_admit(self) -> None:
        class TextSubclass(str):
            pass

        class BytesSubclass(bytes):
            pass

        for schema_id, raw, capability in (
            (TextSubclass("kilix.content.catalog/v5"), self.catalog_raw, self.capability),
            ("kilix.content.catalog/v5", BytesSubclass(self.catalog_raw), self.capability),
            ("kilix.content.catalog/v5", self.catalog_raw, object()),
        ):
            with self.subTest(schema_id=type(schema_id), raw=type(raw)):
                with self.assertRaises(U1ContractError):
                    validate_u1_bytes(schema_id, raw, capability)  # type: ignore[arg-type]

        fake = object.__new__(PackagedReleaseCapability)
        object.__setattr__(fake, "_token", object())
        object.__setattr__(fake, "_manifest_sha256", U1_MANIFEST_SHA256)
        object.__setattr__(fake, "_resources", MappingProxyType({}))
        object.__setattr__(fake, "_routes", MappingProxyType({}))
        with self.assertRaises(U1ContractError):
            validate_u1_bytes("kilix.content.catalog/v5", self.catalog_raw, fake)
        with self.assertRaises(U1ContractError):
            copy.copy(self.capability)
        with self.assertRaises(U1ContractError):
            copy.deepcopy(self.capability)

    def test_schema_invocation_is_non_vacuous_and_results_are_deeply_immutable(self) -> None:
        result = validate_u1_bytes(
            "kilix.content.catalog/v5", self.catalog_raw, self.capability
        )
        with self.assertRaises(TypeError):
            result.value["release_id"] = "changed"  # type: ignore[index]
        self.assertIsInstance(result.value["packages"], tuple)
        self.assertIsInstance(result.value["packages"][0], MappingProxyType)

        class RefusingValidator:
            def __init__(self, _schema: object) -> None:
                pass

            def validate(self, _value: object) -> None:
                raise ValidationError("non-vacuous control")

        with mock.patch.object(u1_module, "Draft202012Validator", RefusingValidator):
            with self.assertRaisesRegex(U1ContractError, "JSON Schema"):
                validate_u1_bytes(
                    "kilix.content.catalog/v5", self.catalog_raw, self.capability
                )

    def test_public_surface_has_no_dict_store_recovery_or_decision_bypass(self) -> None:
        public = set(u1_module.__all__)
        for forbidden in (
            "validate_u1",
            "open_store",
            "recover_transaction",
            "record_authorization",
            "create_capability",
        ):
            self.assertNotIn(forbidden, public)
            self.assertFalse(hasattr(u1_module, forbidden))

    def test_diagnostics_are_bounded_fixed_and_do_not_echo_hostile_input(self) -> None:
        hostile = "PRIVATE/path/should-not-appear"
        attacks = (
            b'{"a":1,"a":"PRIVATE/path/should-not-appear"}',
            canonical_json_bytes({"schema": hostile}),
            b'{"schema":"kilix.content.catalog/v5","x":"\xff"}',
        )
        for raw in attacks:
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(U1ContractError) as caught:
                    validate_u1_bytes("kilix.content.catalog/v5", raw, self.capability)
                self.assertNotIn(hostile, str(caught.exception))
                self.assertLessEqual(len(str(caught.exception)), 160)
                self.assertRegex(caught.exception.code, r"^U1_[A-Z0-9_]+$")

    def test_canonical_bytes_have_one_representation_and_typed_domains(self) -> None:
        value = {"b": 1, "a": [True, None, "é"]}
        raw = b'{"a":[true,null,"\xc3\xa9"],"b":1}'
        self.assertEqual(canonical_json_bytes(value), raw)
        self.assertEqual(parse_json_bytes(raw), value)
        self.assertEqual(canonical_json_bytes(parse_json_bytes(raw)), raw)
        self.assertFalse(raw.endswith(b"\n"))
        with self.assertRaises(U1ContractError):
            canonical_digest("caller-selected-domain", value)

    def test_catalog_alias_authority_and_authorization_chain_are_exact(self) -> None:
        package = authority_binding("demo.package")
        self.assertEqual(package, authority_binding("demo.codec"))
        self.assertEqual(package, authority_binding("demo.model"))

        restricted = catalog()
        restricted["packages"][0]["install"]["licenses"][0]["decision"] = "restricted"
        from kilix_content.u1_catalog import derive_install_authority_binding

        with self.assertRaises(U1ContractError):
            derive_install_authority_binding(restricted, "demo.codec")

        changed_kind = catalog()
        direct = changed_kind["contents"].pop(0)
        digest = sha("kind-transition-output")
        direct["output_manifest_sha256"] = digest
        direct["install"]["output_manifest_sha256"] = digest
        changed_kind["assets"].append(direct)
        changed_kind["assets"] = sorted(
            changed_kind["assets"], key=canonical_json_bytes
        )
        with self.assertRaises(U1ContractError):
            validate_catalog_transition(catalog(), changed_kind)

        validate_authorization_against_records(
            authorization(), catalog(), authority_binding(), output_binding(), "demo.codec"
        )
        broken = authorization()
        broken["output_binding_sha256"] = sha("wrong-output")
        broken["record_sha256"] = authorization_record_digest(broken)
        with self.assertRaises(U1ContractError):
            validate_authorization_against_records(
                broken, catalog(), authority_binding(), output_binding(), "demo.codec"
            )

    def test_catalog_profiles_and_license_text_are_cross_bound_to_exact_bytes(self) -> None:
        resources = {
            "profiles/system.json": canonical_json_bytes(system_profile()),
            "profiles/toolchain.json": canonical_json_bytes(toolchain_profile()),
            "profiles/sandbox.json": canonical_json_bytes(sandbox_profile()),
            "licenses/licenses.test.json": canonical_json_bytes(license_manifest()),
        }
        hashes = {
            path: hashlib.sha256(payload).hexdigest()
            for path, payload in resources.items()
        }

        def admit(schema_id: str, raw: bytes) -> MappingProxyType:
            return validate_u1_bytes(schema_id, raw, self.capability).value  # type: ignore[return-value]

        validate_catalog_resource_bundle(
            catalog(), resources, hashes, validate_json_resource=admit
        )
        broken_hashes = dict(hashes)
        broken_hashes["profiles/system.json"] = sha("wrong-resource")
        with self.assertRaises(U1ContractError):
            validate_catalog_resource_bundle(
                catalog(), resources, broken_hashes, validate_json_resource=admit
            )

        manifest = license_manifest()
        validate_license_text_bundle(
            manifest, {"licenses/MIT.txt": packaged_resource_bytes("MIT.txt")}
        )
        with self.assertRaises(U1ContractError):
            validate_license_text_bundle(
                manifest, {"licenses/MIT.txt": packaged_resource_bytes("MIT.txt") + b"x"}
            )


class U1ResourceRootMutationTests(unittest.TestCase):
    def _copy_root(self, destination: Path) -> None:
        shutil.copytree(PACKAGE / "contracts", destination / "contracts")
        shutil.copytree(PACKAGE / "licenses", destination / "licenses")

    def _verify(self, root: Path, raw: bytes, digest: str = U1_MANIFEST_SHA256) -> None:
        with (
            mock.patch.object(u1_module, "_package_root", return_value=root),
            mock.patch.object(u1_module, "U1_MANIFEST_SHA256", digest),
        ):
            u1_module._validate_manifest(raw)

    def test_resource_manifest_and_external_root_mutations_all_refuse(self) -> None:
        original = (CONTRACTS / U1_MANIFEST_NAME).read_bytes()
        manifest = parse_json_bytes(original)
        schema_entry = next(
            entry for entry in manifest["resources"] if entry["role"] == "schema"
        )
        schema_relative = Path(schema_entry["path"])

        cases = ("resource", "manifest", "both", "external", "extra", "missing", "role", "license", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._copy_root(root)
                raw = original
                external = U1_MANIFEST_SHA256
                target = root / schema_relative
                if case == "resource":
                    target.write_bytes(target.read_bytes() + b" ")
                elif case == "manifest":
                    changed = clone(manifest)
                    changed["release_id"] = "0.2.1-mutated"
                    raw = canonical_json_bytes(changed)
                elif case == "both":
                    target.write_bytes(target.read_bytes() + b" ")
                    changed = clone(manifest)
                    changed_entry = next(
                        entry
                        for entry in changed["resources"]
                        if entry["path"] == schema_entry["path"]
                    )
                    changed_entry["size"] += 1
                    changed_entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
                    raw = canonical_json_bytes(changed)
                elif case == "external":
                    external = "0" * 64
                elif case == "extra":
                    (root / "contracts" / "u1" / "extra.schema.json").write_bytes(b"{}")
                elif case == "missing":
                    target.unlink()
                elif case == "role":
                    changed = clone(manifest)
                    changed_entry = next(
                        entry
                        for entry in changed["resources"]
                        if entry["path"] == schema_entry["path"]
                    )
                    changed_entry["schema_id"] = "kilix.content.substituted/v1"
                    raw = canonical_json_bytes(changed)
                    external = hashlib.sha256(raw).hexdigest()
                elif case == "license":
                    license_path = root / "licenses" / "MIT.txt"
                    license_path.write_bytes(license_path.read_bytes() + b"x")
                elif case == "symlink":
                    actual = root / "schema-target.json"
                    target.rename(actual)
                    target.symlink_to(actual)
                with self.assertRaises(U1ContractError):
                    self._verify(root, raw, external)


class U1CapacityAndRetentionTests(unittest.TestCase):
    def test_filesystem_key_has_fixed_preimage_and_every_field_is_bound(self) -> None:
        value = {
            "boot_id": "11" * 16,
            "filesystem_magic": 0xEF53,
            "filesystem_type_utf8": "ext4",
            "st_dev_major": 8,
            "st_dev_minor": 1,
            "statfs_fsid_word_0": 0x0102030405060708,
            "statfs_fsid_word_1": 0x1112131415161718,
        }
        expected_hex = (
            "6b696c69782d636f6e74656e742066696c6573797374656d2063617061636974792f"
            "763200000000101111111111111111111111111111111100000008000000000000ef"
            "53000000046578743400000004000000080000000400000001000000080102030405"
            "060708000000081112131415161718"
        )
        self.assertEqual(filesystem_key_bytes(value).hex(), expected_hex)
        self.assertEqual(
            filesystem_key_digest(value),
            "d0f81b27029569c5fc8bb81b7b3f6400bac5cb3140f4401d2c7fab6a9e058ee5",
        )
        mutations = {
            "boot_id": "12" + "11" * 15,
            "filesystem_magic": 0xEF54,
            "filesystem_type_utf8": "xfs",
            "st_dev_major": 9,
            "st_dev_minor": 2,
            "statfs_fsid_word_0": 2,
            "statfs_fsid_word_1": 3,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = dict(value)
                changed[field] = replacement
                self.assertNotEqual(filesystem_key_bytes(changed), filesystem_key_bytes(value))
                self.assertNotEqual(filesystem_key_digest(changed), filesystem_key_digest(value))

    def test_capacity_normal_recovery_and_retention_generation_chains(self) -> None:
        validate_capacity_generation_chain(capacity_chain(list(CAPACITY_PHASES)))
        recovery_phases = [
            "RESERVED",
            "SUBMITTER_ARMING",
            "SUBMITTER_LIVE",
            "UNIT_PREPARED",
            "UNIT_MAYBE_SENT",
            "UNIT_OBSERVED",
            "RELEASING",
            "RELEASE_PROOFED",
        ]
        validate_capacity_generation_chain(capacity_chain(recovery_phases), recovery=True)
        bundle = retention_provenance_bundle()
        validate_capacity_generation_chain(bundle["capacity_chain"])
        validate_transaction_generation_chain(bundle["transaction_chain"])

        skipped = clone(bundle["capacity_chain"])
        skipped.pop(3)
        with self.assertRaises(U1ContractError):
            validate_capacity_generation_chain(skipped)
        replay = clone(bundle["capacity_chain"])
        replay[1]["predecessor_sha256"] = sha("replayed")
        with self.assertRaises(U1ContractError):
            validate_capacity_generation_chain(replay)
        self.assertFalse(production_capacity_policy_available())

    def test_checked_arithmetic_refuses_overflow(self) -> None:
        self.assertEqual(checked_add((1, 2, 3)), 6)
        self.assertEqual(checked_mul(7, 9), 63)
        self.assertEqual(checked_round_up(65, 64), 128)
        for operation in (
            lambda: checked_add((S64_MAX, 1)),
            lambda: checked_mul(S64_MAX, 2),
            lambda: checked_round_up(S64_MAX, 2),
        ):
            with self.assertRaises(U1ContractError):
                operation()

    def test_complete_m_r_p_h_provenance_is_recomputed(self) -> None:
        bundle = retention_provenance_bundle()
        validate_intent_envelope(bundle["intent"], retention_envelope())
        validate_marker_against_intent(
            bundle["marker"],
            bundle["intent"],
            bundle["intent_capacity"],
            bundle["prepared_generation"],
        )
        validate_relation_against_marker(
            bundle["relation"],
            bundle["marker"],
            bundle["marker_generation"],
            bundle["intent"],
        )
        validate_accounted_provenance(
            bundle["accounted"],
            bundle["marker"],
            bundle["relation"],
            bundle["ready_generation"],
            bundle["intent_capacity"],
        )
        validate_handoff_provenance(
            bundle["handoff"],
            bundle["accounted"],
            bundle["accounted_generation"],
            bundle["capacity_accounted"],
            bundle["capacity_releasing"],
        )

        mutations = (
            ("marker", "intent_capacity_generation_sha256"),
            ("relation", "marker_sha256"),
            ("accounted", "ready_transaction_generation_sha256"),
            ("handoff", "capacity_releasing_generation_sha256"),
        )
        for record_name, field in mutations:
            with self.subTest(record=record_name, field=field):
                broken = clone(bundle)
                broken[record_name][field] = sha(f"wrong-{record_name}-{field}")
                with self.assertRaises(U1ContractError):
                    if record_name == "marker":
                        validate_marker_against_intent(
                            broken["marker"], broken["intent"], broken["intent_capacity"], broken["prepared_generation"]
                        )
                    elif record_name == "relation":
                        validate_relation_against_marker(
                            broken["relation"], broken["marker"], broken["marker_generation"], broken["intent"]
                        )
                    elif record_name == "accounted":
                        validate_accounted_provenance(
                            broken["accounted"], broken["marker"], broken["relation"], broken["ready_generation"], broken["intent_capacity"]
                        )
                    else:
                        validate_handoff_provenance(
                            broken["handoff"], broken["accounted"], broken["accounted_generation"], broken["capacity_accounted"], broken["capacity_releasing"]
                        )

    def test_directory_current_temporary_and_admission_equations(self) -> None:
        observation = directory_observation()
        temporary = {
            "name": ".new-retention-" + sha("temporary") + "-dir-0",
            "role": "D",
            "object_type": "directory",
            "descriptor_sha256": sha("temporary-descriptor"),
        }
        observation["current_temporary"] = {"present": True, "child": temporary}
        observation["observed_children"] = sorted(
            [*observation["baseline_children"], temporary], key=canonical_json_bytes
        )
        validate_directory_observation(observation)
        unexpected = clone(observation)
        unexpected["observed_children"].append(
            {
                "name": ".new-retention-" + sha("other") + "-dir-0",
                "role": "D",
                "object_type": "directory",
                "descriptor_sha256": sha("other-descriptor"),
            }
        )
        unexpected["observed_children"] = sorted(
            unexpected["observed_children"], key=canonical_json_bytes
        )
        with self.assertRaises(U1ContractError):
            validate_directory_observation(unexpected)

        limits = {
            "retained_unique_objects_max": 2,
            "retained_allocated_bytes_max": 1_000_000,
            "retained_inodes_max": 10,
            "retained_versions_per_stable_slot_max": 2,
            "ambiguous_retained_objects_max": 2,
        }
        validate_retention_admission(logical_state(), physical_state(), limits)
        closed = logical_state()
        closed["retention_admission_closed"] = True
        closed["admission_closed_reasons"] = ["limit-exceeded"]
        with self.assertRaises(U1ContractError):
            validate_retention_admission(closed, physical_state(), limits)


class U1ScopeAndWheelTests(unittest.TestCase):
    def test_u1_modules_are_declarative_and_have_no_mutating_or_execution_imports(self) -> None:
        forbidden_imports = {
            "asyncio",
            "fcntl",
            "http",
            "os",
            "requests",
            "shutil",
            "socket",
            "subprocess",
            "tempfile",
            "urllib.request",
        }
        for path in sorted((PACKAGE).glob("u1*.py")):
            tree = ast.parse(path.read_text("utf-8"), filename=str(path))
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            with self.subTest(path=path.name):
                self.assertFalse(imported & forbidden_imports)
                source = path.read_text("utf-8")
                for call in (".unlink(", ".rename(", ".replace(", ".mkdir(", "Popen("):
                    self.assertNotIn(call, source)

    @unittest.skipUnless(os.environ.get("KILIX_CONTENT_WHEEL"), "run with built wheel path")
    def test_wheel_contains_only_production_u1_authority(self) -> None:
        wheel = Path(os.environ["KILIX_CONTENT_WHEEL"])
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
        for name in U1_SCHEMA_NAMES:
            self.assertTrue(
                any(member.endswith(f"/contracts/u1/{name}") for member in names),
                name,
            )
        self.assertTrue(
            any(member.endswith(f"/contracts/{U1_MANIFEST_NAME}") for member in names)
        )
        self.assertTrue(any(member.endswith("/licenses/MIT.txt") for member in names))
        self.assertFalse(any("tests/" in name or "fixtures/" in name for name in names))
        self.assertFalse(any("u1_vectors" in name for name in names))


if __name__ == "__main__":
    unittest.main()
