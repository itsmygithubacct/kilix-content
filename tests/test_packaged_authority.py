"""F100 step 5 — packaged catalog/release authority.

Production authority has exactly one root: the packaged catalog bytes this
component shipped, pinned by a code constant, plus a packaged release-ID
constant. These tests prove the root holds, that no other construction path
reaches it, and that a verified context alone never authorizes a record the
packaged catalog does not publish.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from kilix_content import (
    AssetSpec,
    BindingMismatch,
    Catalog,
    CatalogError,
    ContentSpec,
    LicenseDecision,
    ReceiptError,
    ReceiptStore,
    ReleaseContext,
    UnsafeStore,
    VerifiedInput,
    verified_packaged_catalog,
)
from kilix_content import receipt as receipt_module
from kilix_content.receipt import (
    _ASSET_SCHEMA_SHA256,
    _CATALOG_RESOURCE,
    _CATALOG_SHA256,
    _PUBLIC_SCHEMA_SHA256,
    _RELEASE,
    _RELEASE_ID,
    _packaged_bytes,
)
from tests.receipt_store_support import ClosedGateReceiptStore, open_test_store

ROOT = Path(__file__).resolve().parents[1]
PACKAGED_CATALOG = ROOT / "src/kilix_content/catalog/plebian.json"
PACKAGED_CONTRACTS = ROOT / "src/kilix_content/contracts"
FIXTURE_CATALOG = ROOT / "tests/fixtures/catalogs/packaged-authority-v4.json"

LICENSE_TEXT = b"Exact packaged-authority test license.\n"
ALT_LICENSE_TEXT = b"Alternate packaged-authority test license.\n"
GENUINE_PAYLOAD = b"genuine user-supplied payload\n"
ALT_PAYLOAD = b"alternate user-supplied payload\n"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def fixture_records() -> dict[str, dict]:
    document = json.loads(FIXTURE_CATALOG.read_text(encoding="utf-8"))
    return {record["id"]: record for record in document["assets"]}


class MockPackagedBytes:
    """Replace only the packaged catalog read, leaving schema reads intact."""

    def __init__(self, payload: bytes, *, digest: str | None = None) -> None:
        self.payload = payload
        self.digest = digest
        self.original_reader = receipt_module._packaged_bytes
        self.original_digest = receipt_module._CATALOG_SHA256

    def __enter__(self) -> MockPackagedBytes:
        original = self.original_reader

        def replacement(relative: str, label: str) -> bytes:
            if relative == _CATALOG_RESOURCE:
                return self.payload
            return original(relative, label)

        receipt_module._packaged_bytes = replacement
        if self.digest is not None:
            receipt_module._CATALOG_SHA256 = self.digest
        return self

    def __exit__(self, *_exc: object) -> None:
        receipt_module._packaged_bytes = self.original_reader
        receipt_module._CATALOG_SHA256 = self.original_digest


def mock_packaged_bytes(payload: bytes, *, digest: str | None = None) -> MockPackagedBytes:
    return MockPackagedBytes(payload, digest=digest)


def past_the_digest(document: object) -> MockPackagedBytes:
    """Serve a hostile catalog whose digest gate passes, so the parser refuses."""
    payload = canonical(document)
    return mock_packaged_bytes(payload, digest=hashlib.sha256(payload).hexdigest())


class PackagedCatalogTests(unittest.TestCase):
    """G1, G2, G3, G4, G5 — the shipped bytes and the constants that pin them."""

    def test_packaged_catalog_is_canonical_schema_v4_with_no_production_assets(
        self,
    ) -> None:
        raw = PACKAGED_CATALOG.read_bytes()
        document = json.loads(raw)
        self.assertEqual(raw, canonical(document), "packaged catalog is not canonical")
        self.assertEqual(document["schema_version"], 4)
        self.assertEqual(
            document["assets"],
            [],
            "step 5 ships an explicit empty production assets array; real assets "
            "arrive with F101 at plan step 7",
        )
        self.assertTrue(document["content"], "content records must survive promotion")

    def test_packaged_constants_are_recomputable_from_the_shipped_tree(self) -> None:
        self.assertEqual(
            hashlib.sha256(PACKAGED_CATALOG.read_bytes()).hexdigest(), _CATALOG_SHA256
        )
        self.assertEqual(
            hashlib.sha256(
                (PACKAGED_CONTRACTS / "kilix.install.license-v1.schema.json").read_bytes()
            ).hexdigest(),
            _PUBLIC_SCHEMA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(
                (PACKAGED_CONTRACTS / "kilix.content.asset-v1.schema.json").read_bytes()
            ).hexdigest(),
            _ASSET_SCHEMA_SHA256,
        )

    def test_release_id_is_the_literal_value_and_satisfies_the_release_grammar(
        self,
    ) -> None:
        self.assertEqual(_RELEASE_ID, "0.2.1")
        self.assertIsNotNone(_RELEASE.fullmatch(_RELEASE_ID))

    def test_both_frozen_contracts_are_importable_from_the_package(self) -> None:
        for relative, expected in (
            ("contracts/kilix.install.license-v1.schema.json", _PUBLIC_SCHEMA_SHA256),
            ("contracts/kilix.content.asset-v1.schema.json", _ASSET_SCHEMA_SHA256),
        ):
            with self.subTest(relative=relative):
                payload = _packaged_bytes(relative, "schema")
                self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)

    def test_verified_catalog_refuses_any_mutation_before_parsing(self) -> None:
        raw = PACKAGED_CATALOG.read_bytes()
        mutations = {
            "one byte": raw[:-2] + bytes([raw[-2] ^ 0x01]) + raw[-1:],
            "truncated": raw[: len(raw) // 2],
            "empty": b"",
            "appended space": raw + b" ",
        }
        for label, payload in mutations.items():
            with self.subTest(mutation=label):
                with mock_packaged_bytes(payload), self.assertRaises(BindingMismatch):
                    verified_packaged_catalog()

    def test_missing_packaged_resource_is_a_typed_refusal(self) -> None:
        def absent(_relative: str, label: str) -> bytes:
            raise ReceiptError(f"the frozen {label} is unavailable")

        original = receipt_module._packaged_bytes
        receipt_module._packaged_bytes = absent
        try:
            with self.assertRaises(ReceiptError):
                verified_packaged_catalog()
        finally:
            receipt_module._packaged_bytes = original


class HostileCatalogParserTests(unittest.TestCase):
    """§11.2 — hostile payloads must be refused by the parser, not the digest.

    Each case is served with a matching patched expected digest so the outer
    byte gate passes and ``Catalog.loads`` is demonstrably what refuses.
    """

    def base_document(self) -> dict:
        return json.loads(PACKAGED_CATALOG.read_text(encoding="utf-8"))

    def assert_parser_refuses(self, payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        with mock_packaged_bytes(payload, digest=digest):
            with self.assertRaises(BindingMismatch) as caught:
                verified_packaged_catalog()
        detail = str(caught.exception)
        self.assertIn(
            "unusable",
            detail,
            "the refusal must come from the parser, not the digest gate",
        )
        return detail

    def test_non_utf8_payload_is_refused_by_the_decode_gate(self) -> None:
        # Served with a matching digest so the byte gate passes and the UTF-8
        # gate itself is what refuses, before any parsing is attempted.
        payload = b"\xff\xfe" + canonical(self.base_document())
        digest = hashlib.sha256(payload).hexdigest()
        with mock_packaged_bytes(payload, digest=digest):
            with self.assertRaises(BindingMismatch) as caught:
                verified_packaged_catalog()
        self.assertIn("not valid UTF-8", str(caught.exception))

    def test_duplicate_field_is_refused_by_the_parser(self) -> None:
        self.assert_parser_refuses(
            b'{"assets":[],"content":[],"packages":[],'
            b'"schema_version":4,"schema_version":4}'
        )

    def test_non_integer_numeric_is_refused_by_the_parser(self) -> None:
        self.assert_parser_refuses(
            b'{"assets":[],"content":[],"packages":[],"schema_version":4.0}'
        )

    def test_oversize_catalog_is_refused_by_the_parser(self) -> None:
        document = self.base_document()
        document["content"] = []
        filler = "x" * (1024 * 1024)
        document["packages"] = [{"id": "pad", "label": filler}]
        self.assert_parser_refuses(canonical(document))

    def test_v3_declaring_assets_is_refused_by_the_parser(self) -> None:
        document = self.base_document()
        document["schema_version"] = 3
        document["assets"] = [fixture_records()["voice.demo-small"]]
        self.assert_parser_refuses(canonical(document))

    def test_restricted_asset_decision_is_refused_by_the_parser(self) -> None:
        document = self.base_document()
        record = json.loads(json.dumps(fixture_records()["voice.demo-small"]))
        record["licenses"][0]["decision"] = "restricted"
        document["assets"] = [record]
        self.assert_parser_refuses(canonical(document))

    def test_hostile_provider_records_are_refused_by_the_parser(self) -> None:
        cases = {
            "unknown field": lambda record: record.update({"surprise": "value"}),
            "path escape": lambda record: record["files"][0].update(
                {"path": "../escape.bin"}
            ),
            "absolute path": lambda record: record["files"][0].update(
                {"path": "/etc/escape.bin"}
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                document = self.base_document()
                record = json.loads(json.dumps(fixture_records()["voice.demo-small"]))
                mutate(record)
                document["assets"] = [record]
                self.assert_parser_refuses(canonical(document))

    def test_mutable_git_ref_in_a_content_record_is_refused_by_the_parser(self) -> None:
        # Mutate a real Git-sourced entry so the branch name is the only
        # invalidity. `binary` lives at the entry top level; putting it inside
        # `source` would trip the unknown-source-field check first and the ref
        # would never be examined.
        document = self.base_document()
        for entry in document["content"]:
            if entry.get("source", {}).get("type") == "git":
                self.assertEqual(len(entry["source"]["ref"]), 40)
                entry["source"]["ref"] = "main"
                break
        else:  # pragma: no cover - the packaged catalog pins Git entries
            self.fail("packaged catalog has no Git-sourced content entry")
        detail = self.assert_parser_refuses(canonical(document))
        self.assertIn(
            "must be exactly 40 lowercase hexadecimal characters",
            detail,
            "the exact-ref rule must be the stated reason",
        )

    def test_more_than_max_assets_is_refused(self) -> None:
        # Serialized 4097 records exceed the 1 MiB byte gate long before the
        # count check, so the bound is proven at Catalog construction where the
        # byte limit does not dominate.
        base = AssetSpec.from_mapping(fixture_records()["voice.demo-small"])
        limit = receipt_module_max_assets()
        self.assertEqual(limit, 4096)
        specs = tuple(
            replace(base, asset_id=f"pad.asset-{index}") for index in range(limit + 1)
        )
        with self.assertRaisesRegex(CatalogError, f"more than {limit} assets"):
            Catalog((), schema_version=4, assets=specs)


def receipt_module_max_assets() -> int:
    from kilix_content import model as model_module

    return model_module._MAX_ASSETS


class ProductionProvenanceTests(unittest.TestCase):
    """G6, G8 — only ``packaged()`` yields a context the gate accepts."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.spec = AssetSpec.from_mapping(fixture_records()["voice.demo-small"])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def production_store(self, name: str = "xdg") -> ReceiptStore:
        return ReceiptStore.open_default(
            {"XDG_STATE_HOME": str(self.root / name), "HOME": str(self.root / "poison")}
        )

    def decision(self) -> LicenseDecision:
        requirement = self.spec.licenses[0]
        return LicenseDecision.from_mapping(
            {
                "artifact_ids": [self.spec.asset_id],
                "decision_class": requirement.decision,
                "kind": "decision",
                "license_id": requirement.license_id,
                "license_text_sha256": requirement.text_sha256,
                "outcome": "record",
                "presenter": "kilix-installer",
                "release": _RELEASE_ID,
                "schema": "kilix.install.license/v1",
            }
        )

    def assert_refused_at_both_call_sites(self, context: ReleaseContext) -> None:
        with self.production_store() as store:
            with self.assertRaises(BindingMismatch):
                store.record(self.decision(), LICENSE_TEXT, context, [self.spec])
            with self.assertRaises(BindingMismatch):
                store.require_asset(self.spec, context)
            self.assertEqual(tuple(Path(store.root).glob("*.json")), ())

    def test_from_catalog_with_the_exact_packaged_bytes_is_refused(self) -> None:
        context = ReleaseContext.from_catalog(
            _RELEASE_ID, PACKAGED_CATALOG.read_bytes()
        )
        self.assertEqual(context.catalog_sha256, _CATALOG_SHA256)
        self.assertEqual(context.release_id, _RELEASE_ID)
        self.assert_refused_at_both_call_sites(context)

    def test_direct_construction_with_the_exact_constants_is_refused(self) -> None:
        self.assert_refused_at_both_call_sites(
            ReleaseContext(_RELEASE_ID, _CATALOG_SHA256)
        )

    def test_replace_of_a_packaged_context_loses_provenance_and_is_refused(
        self,
    ) -> None:
        packaged = ReleaseContext.packaged()
        rebuilt = replace(packaged)
        self.assertEqual(rebuilt, packaged, "public shape must be unchanged")
        self.assert_refused_at_both_call_sites(rebuilt)

    def test_subclass_cannot_obtain_or_alter_the_packaged_path(self) -> None:
        class Forged(ReleaseContext):
            pass

        with self.assertRaises(BindingMismatch):
            Forged.packaged()

    def test_packaged_context_public_shape_is_unchanged(self) -> None:
        packaged = ReleaseContext.packaged()
        self.assertEqual(
            packaged.to_mapping(),
            {"catalog_sha256": _CATALOG_SHA256, "id": _RELEASE_ID},
        )

    def test_packaged_context_is_refused_when_the_catalog_does_not_verify(
        self,
    ) -> None:
        with mock_packaged_bytes(b"{}"), self.assertRaises(BindingMismatch):
            ReleaseContext.packaged()

    def test_packaged_context_is_refused_when_a_frozen_schema_is_missing(
        self,
    ) -> None:
        # Found by the omitted-schema wheel check: verifying only the catalog
        # let packaged() hand out a context on a build whose frozen contracts
        # were absent, deferring the refusal to the first authority call.
        original = receipt_module._packaged_bytes

        def without_asset_schema(relative: str, label: str) -> bytes:
            if relative.endswith("kilix.content.asset-v1.schema.json"):
                raise ReceiptError(f"the frozen {label} is unavailable")
            return original(relative, label)

        receipt_module._packaged_bytes = without_asset_schema
        try:
            with self.assertRaises(ReceiptError):
                ReleaseContext.packaged()
        finally:
            receipt_module._packaged_bytes = original

    def test_production_store_refuses_subclass_and_attribute_injection(self) -> None:
        class CallerOverride(ReceiptStore):
            __slots__ = ()

            def _require_release_authority(self, release: ReleaseContext) -> None:
                del release

        with self.assertRaisesRegex(UnsafeStore, "subclass"):
            CallerOverride.open_default(
                {"XDG_STATE_HOME": str(self.root / "override")}
            )
        with self.production_store("attr") as store, self.assertRaises(AttributeError):
            store._testing = True

    def test_the_five_forbidden_names_remain_absent(self) -> None:
        self.assertFalse(hasattr(ReleaseContext, "_from_authoritative_catalog"))
        self.assertFalse(hasattr(ReleaseContext, "_from_stored_digest"))
        self.assertFalse(hasattr(ReceiptStore, "_open_test"))
        self.assertFalse(hasattr(ReceiptStore, "_open_test_path"))
        self.assertFalse(hasattr(receipt_module, "_TestReceiptStore"))


class PoisonedSpec(AssetSpec):
    """An ``AssetSpec`` whose ``to_mapping`` lies about its own fields."""

    genuine: dict[str, object] = {}

    def to_mapping(self) -> dict[str, object]:
        return dict(type(self).genuine)


class CatalogMembershipTests(unittest.TestCase):
    """G7 / §11.1 — every stated mutation shape, at both call sites.

    Each record-side request is derived from the *mutated* record — decision
    identity, licence text preimage and verified input alike — so the only
    thing wrong with it is that the packaged catalog does not publish it. If
    membership were removed these requests would otherwise be valid.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.records = fixture_records()
        self.mirrored = AssetSpec.from_mapping(self.records["voice.demo-small"])
        self.pair = AssetSpec.from_mapping(self.records["voice.demo-pair"])
        self.supplied = AssetSpec.from_mapping(self.records["game.user-data"])
        self.texts = {
            hashlib.sha256(LICENSE_TEXT).hexdigest(): LICENSE_TEXT,
            hashlib.sha256(ALT_LICENSE_TEXT).hexdigest(): ALT_LICENSE_TEXT,
        }
        self.payloads = {
            hashlib.sha256(GENUINE_PAYLOAD).hexdigest(): GENUINE_PAYLOAD,
            hashlib.sha256(ALT_PAYLOAD).hexdigest(): ALT_PAYLOAD,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self, name: str) -> ReceiptStore:
        return open_test_store(
            str(self.root / name),
            assets=(self.mirrored, self.pair, self.supplied),
        )

    @staticmethod
    def context() -> ReleaseContext:
        return ReleaseContext.from_catalog(_RELEASE_ID, b'{"catalog":"membership"}')

    def decision_for(self, spec: AssetSpec) -> LicenseDecision:
        requirement = spec.licenses[0]
        payload = {
            "artifact_ids": [spec.asset_id],
            "decision_class": requirement.decision,
            "kind": "decision",
            "license_id": requirement.license_id,
            "license_text_sha256": requirement.text_sha256,
            "outcome": {
                "informational": "record",
                "affirmative": "accept",
                "user-supplied": "supply",
            }[requirement.decision],
            "presenter": "kilix-installer",
            "release": _RELEASE_ID,
            "schema": "kilix.install.license/v1",
        }
        if requirement.decision == "user-supplied":
            payload["upstream_url"] = spec.official_url
            payload["input_sha256"] = spec.input_sha256
        return LicenseDecision.from_mapping(payload)

    def input_for(self, spec: AssetSpec, name: str) -> VerifiedInput | None:
        if spec.source_mode != "user-supplied":
            return None
        payload = self.payloads.get(spec.input_sha256)
        if payload is None:
            return None
        path = self.root / f"{name}-input.bin"
        path.write_bytes(payload)
        path.chmod(0o600)
        return VerifiedInput.open(str(path))

    def assert_refused_at_both_call_sites(
        self, spec: AssetSpec, name: str, *, reason: str = "packaged release catalog"
    ) -> None:
        text = self.texts.get(spec.licenses[0].text_sha256, LICENSE_TEXT)
        opened = self.input_for(spec, name)
        try:
            with self.store(name) as store:
                with self.assertRaises(BindingMismatch) as recorded:
                    store.record(
                        self.decision_for(spec),
                        text,
                        self.context(),
                        [spec],
                        verified_input=opened,
                    )
                self.assertIn(reason, str(recorded.exception))
                with self.assertRaises(BindingMismatch) as required:
                    store.require_asset(spec, self.context())
                self.assertIn(reason, str(required.exception))
                self.assertEqual(
                    tuple(Path(store.root).glob("*.json")),
                    (),
                    "a refused record must never leave receipt state",
                )
        finally:
            if opened is not None:
                opened.close()

    def mutate(self, base: str, **changes: object) -> AssetSpec:
        record = json.loads(json.dumps(self.records[base]))
        for path, value in changes.items():
            cursor = record
            parts = path.split(".")
            for part in parts[:-1]:
                cursor = cursor[int(part)] if part.isdigit() else cursor[part]
            last = parts[-1]
            if last.isdigit():
                cursor[int(last)] = value
            else:
                cursor[last] = value
        return AssetSpec.from_mapping(record)

    def removed_file(self) -> AssetSpec:
        """Drop one file from a record the catalog publishes with two."""
        record = json.loads(json.dumps(self.records["voice.demo-pair"]))
        self.assertEqual(len(record["files"]), 2)
        kept = record["files"][0]
        record["files"] = [kept]
        record["sizes"]["installed_bytes"] = kept["bytes"]
        return AssetSpec.from_mapping(record)

    def test_a_genuine_published_record_is_accepted_at_both_call_sites(self) -> None:
        # The two-file record is admitted here so the "removed file" mutation
        # below is proven to fail on binding mismatch rather than absent id.
        for spec, name in ((self.mirrored, "genuine-mirrored"),
                           (self.pair, "genuine-pair"),
                           (self.supplied, "genuine-supplied")):
            with self.subTest(asset=spec.asset_id):
                opened = self.input_for(spec, name)
                try:
                    with self.store(name) as store:
                        result = store.record(
                            self.decision_for(spec),
                            LICENSE_TEXT,
                            self.context(),
                            [spec],
                            verified_input=opened,
                        )
                        self.assertTrue(result.key)
                        self.assertIn(result.status, {"created", "existing"})
                        self.assertTrue(store.require_asset(spec, self.context()))
                finally:
                    if opened is not None:
                        opened.close()

    def test_every_mirrored_mutation_shape_is_refused(self) -> None:
        cases = {
            "absent id": self.mutate("voice.demo-small", id="voice.not-published"),
            "files digest": self.mutate(
                "voice.demo-small",
                **{"files.0.sha256": hashlib.sha256(b"other").hexdigest()},
            ),
            "files path": self.mutate(
                "voice.demo-small", **{"files.0.path": "models/other.bin"}
            ),
            # sizes must stay internally consistent, or the record would fail
            # parsing and the refusal would not be membership.
            "files byte count": self.mutate(
                "voice.demo-small",
                **{"files.0.bytes": 9999, "sizes.installed_bytes": 9999},
            ),
            "version": self.mutate("voice.demo-small", version="9.9"),
            "licence id": self.mutate(
                "voice.demo-small", **{"licenses.0.id": "Other-1.0"}
            ),
            "licence text digest": self.mutate(
                "voice.demo-small",
                **{
                    "licenses.0.text_sha256": hashlib.sha256(
                        ALT_LICENSE_TEXT
                    ).hexdigest()
                },
            ),
            "licence decision": self.mutate(
                "voice.demo-small", **{"licenses.0.decision": "affirmative"}
            ),
            "source mirrors": self.mutate(
                "voice.demo-small",
                **{"source.mirrors": ["https://example.invalid/other.tar"]},
            ),
            "dataclasses.replace": replace(self.mirrored, version="replaced"),
            "removed file": self.removed_file(),
        }
        for label, spec in cases.items():
            with self.subTest(mutation=label):
                # Everything except the absent id must fail on binding
                # mismatch, proving the published base record was present.
                reason = (
                    "not published by the packaged release catalog"
                    if label == "absent id"
                    else "does not match the packaged release catalog record"
                )
                self.assert_refused_at_both_call_sites(
                    spec, label.replace(" ", "-"), reason=reason
                )

    def test_added_file_entry_is_refused(self) -> None:
        record = json.loads(json.dumps(self.records["voice.demo-small"]))
        extra = json.loads(json.dumps(record["files"][0]))
        extra["path"] = "models/added.bin"
        record["files"].append(extra)
        record["sizes"]["installed_bytes"] = sum(
            item["bytes"] for item in record["files"]
        )
        self.assert_refused_at_both_call_sites(
            AssetSpec.from_mapping(record), "added-file"
        )

    def test_every_user_supplied_mutation_shape_is_refused(self) -> None:
        cases = {
            "official url": self.mutate(
                "game.user-data", **{"source.official_url": "https://example.invalid/x"}
            ),
            "input digest": self.mutate(
                "game.user-data",
                **{
                    "source.input_bytes": len(ALT_PAYLOAD),
                    "source.input_sha256": hashlib.sha256(ALT_PAYLOAD).hexdigest(),
                },
            ),
            "conversion argv": self.mutate(
                "game.user-data",
                **{"source.conversion.argv": ["convert", "{input}", "{output}"]},
            ),
            "conversion tool id": self.mutate(
                "game.user-data",
                **{"source.conversion.tool_asset_id": "game.other-extractor"},
            ),
        }
        for label, spec in cases.items():
            with self.subTest(mutation=label):
                self.assert_refused_at_both_call_sites(spec, label.replace(" ", "-"))

    def test_a_wholly_attacker_authored_schema_valid_record_is_refused(self) -> None:
        record = json.loads(json.dumps(self.records["voice.demo-small"]))
        record["id"] = "attacker.payload"
        record["label"] = "Attacker payload"
        record["provider"] = "attacker"
        record["version"] = "1.0"
        record["files"] = [
            {
                "bytes": 4,
                "path": "payload/run.bin",
                "sha256": hashlib.sha256(b"evil").hexdigest(),
            }
        ]
        record["sizes"] = {
            "download_bytes": 4,
            "installed_bytes": 4,
            "temporary_bytes": 4,
        }
        record["source"]["mirrors"] = ["https://attacker.invalid/payload.tar"]
        self.assert_refused_at_both_call_sites(
            AssetSpec.from_mapping(record), "attacker"
        )

    def test_a_lying_assetspec_subclass_is_refused_at_both_call_sites(self) -> None:
        attacker = json.loads(json.dumps(self.records["voice.demo-small"]))
        attacker["version"] = "attacker"
        attacker["files"][0]["sha256"] = hashlib.sha256(b"evil").hexdigest()
        poisoned = PoisonedSpec(**vars(AssetSpec.from_mapping(attacker)))
        type(poisoned).genuine = dict(self.records["voice.demo-small"])
        try:
            self.assertEqual(
                poisoned.to_mapping()["version"],
                self.records["voice.demo-small"]["version"],
                "the override must actually lie for this test to mean anything",
            )
            self.assertEqual(poisoned.version, "attacker")
            self.assert_refused_at_both_call_sites(poisoned, "poisoned")
        finally:
            type(poisoned).genuine = {}


class RollbackTests(unittest.TestCase):
    """G12 — closing the gate refuses without destroying recorded state."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.spec = AssetSpec.from_mapping(fixture_records()["voice.demo-small"])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_reverting_the_gate_refuses_and_preserves_existing_receipts(self) -> None:
        release = ReleaseContext.from_catalog(_RELEASE_ID, b'{"catalog":"rollback"}')
        requirement = self.spec.licenses[0]
        decision = LicenseDecision.from_mapping(
            {
                "artifact_ids": [self.spec.asset_id],
                "decision_class": requirement.decision,
                "kind": "decision",
                "license_id": requirement.license_id,
                "license_text_sha256": requirement.text_sha256,
                "outcome": "record",
                "presenter": "kilix-installer",
                "release": _RELEASE_ID,
                "schema": "kilix.install.license/v1",
            }
        )
        def snapshot(root: str) -> dict[str, bytes]:
            return {
                path.name: path.read_bytes()
                for path in sorted(Path(root).glob("*"))
                if path.is_file()
            }

        root = str(self.root / "rollback")
        with open_test_store(root, assets=(self.spec,)) as store:
            store.record(decision, LICENSE_TEXT, release, [self.spec])
            before = snapshot(store.root)
            self.assertTrue(store.require_asset(self.spec, release))
        self.assertTrue(before, "the recorded receipt must exist before rollback")

        # Simulate reverting step 5: the gate returns to its pre-step-5
        # behaviour of refusing every context. Nothing may be deleted.
        with open_test_store(
            root, assets=(self.spec,), store_type=ClosedGateReceiptStore
        ) as closed:
            with self.assertRaises(BindingMismatch):
                closed.require_asset(self.spec, release)
            with self.assertRaises(BindingMismatch):
                closed.record(decision, LICENSE_TEXT, release, [self.spec])
            after = snapshot(closed.root)
        self.assertEqual(
            before,
            after,
            "a closed gate must refuse without altering receipt bytes",
        )


class CatalogCollisionTests(unittest.TestCase):
    """An id that names both an asset and a content entry is unusable."""

    def test_asset_and_content_id_collision_is_refused(self) -> None:
        spec = AssetSpec.from_mapping(fixture_records()["voice.demo-small"])
        colliding = ContentSpec(
            content_id=spec.asset_id,
            label="Colliding entry",
            kind="tool",
            icon="",
            description="",
            source_type="custom",
        )
        with self.assertRaisesRegex(CatalogError, "conflicts with an asset id"):
            Catalog((colliding,), schema_version=4, assets=(spec,))

    def test_distinct_namespaces_still_load(self) -> None:
        spec = AssetSpec.from_mapping(fixture_records()["voice.demo-small"])
        neighbour = ContentSpec(
            content_id="voice.demo-tool",
            label="Neighbour entry",
            kind="tool",
            icon="",
            description="",
            source_type="custom",
        )
        catalog = Catalog((neighbour,), schema_version=4, assets=(spec,))
        self.assertEqual(catalog.require_asset(spec.asset_id), spec)
        self.assertEqual(catalog.require("voice.demo-tool"), neighbour)


class PackagedCatalogParsesTests(unittest.TestCase):
    """The verified production catalog is usable, not merely well formed."""

    def test_default_catalog_verifies_and_exposes_no_assets(self) -> None:
        catalog = verified_packaged_catalog()
        self.assertEqual(catalog.schema_version, 4)
        self.assertEqual(catalog.assets, ())
        self.assertTrue(tuple(catalog))


if __name__ == "__main__":
    unittest.main()
