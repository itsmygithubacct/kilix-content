from __future__ import annotations

import errno
import hashlib
import json
import os
import signal
import shutil
import tarfile
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest import mock

from kilix_content import (
    AssetSpec,
    BindingMismatch,
    Catalog,
    CatalogError,
    DecisionDeclined,
    DecisionInvalid,
    DurabilityUnknown,
    InstallError,
    Installer,
    LicenseDecision,
    ReceiptMissing,
    ReceiptError,
    ReceiptStore,
    ReconcileResult,
    ReleaseContext,
    StoredReceiptInvalid,
    UnsafeStore,
    VerifiedInput,
    download,
)
import kilix_content.receipt as receipt_module
from tests.receipt_store_support import open_test_store

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ReceiptStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.license_text = b"Exact demo license bytes.\n"
        record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
        record["licenses"][0]["text_sha256"] = hashlib.sha256(
            self.license_text
        ).hexdigest()
        self.spec = AssetSpec.from_mapping(record)
        self.release = ReleaseContext.from_catalog(
            "0.2.1", b'{"release":"0.2.1","assets":"frozen"}\n'
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def decision(
        self,
        spec: AssetSpec | None = None,
        *,
        presenter: str = "kilix-installer",
        artifact_ids: list[str] | None = None,
    ) -> LicenseDecision:
        spec = self.spec if spec is None else spec
        requirement = spec.licenses[0]
        outcomes = {
            "informational": "record",
            "affirmative": "accept",
            "user-supplied": "supply",
        }
        value = {
            "artifact_ids": artifact_ids or [spec.asset_id],
            "decision_class": requirement.decision,
            "kind": "decision",
            "license_id": requirement.license_id,
            "license_text_sha256": requirement.text_sha256,
            "outcome": outcomes[requirement.decision],
            "presenter": presenter,
            "release": self.release.release_id,
            "schema": "kilix.install.license/v1",
        }
        if requirement.decision == "user-supplied":
            value["input_sha256"] = spec.input_sha256
            value["upstream_url"] = spec.official_url
        return LicenseDecision.from_mapping(value)

    def open_store(self, *, clock=lambda: 1.0) -> ReceiptStore:
        return open_test_store(str(self.root / "state"), clock=clock)

    def test_runtime_decision_parser_conforms_and_is_stricter_at_boundary(self) -> None:
        valid = sorted((FIXTURES / "valid").glob("license-*-decision.json"))
        self.assertTrue(valid)
        for path in valid:
            with self.subTest(path=path.name):
                parsed = LicenseDecision.from_mapping(load_json(path))
                self.assertEqual(parsed.to_mapping(), load_json(path))
                self.assertEqual(
                    LicenseDecision.loads(path.read_bytes()), parsed
                )

        invalid = sorted((FIXTURES / "invalid").glob("license-*.json"))
        for path in invalid:
            with self.subTest(path=path.name), self.assertRaises(DecisionInvalid):
                LicenseDecision.from_mapping(load_json(path))

        supplied = load_json(
            FIXTURES / "valid" / "license-user-supplied-decision.json"
        )
        for url in (
            "https://user:secret@example.org/model",
            "https://example.org/model?token=secret",
            "https://example.org/model#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(DecisionInvalid):
                LicenseDecision.from_mapping({**supplied, "upstream_url": url})
        informational = load_json(
            FIXTURES / "valid" / "license-informational-decision.json"
        )
        with self.assertRaises(DecisionInvalid):
            LicenseDecision.from_mapping(
                {**informational, "input_sha256": "a" * 64}
            )
        canonical = json.dumps(informational, separators=(",", ":"))
        duplicate = canonical.replace(
            '{"artifact_ids"', '{"schema":"duplicate","artifact_ids"', 1
        )
        with self.assertRaises(DecisionInvalid):
            LicenseDecision.loads(duplicate)
        with self.assertRaises(DecisionInvalid):
            LicenseDecision.loads(b"\xff")
        with self.assertRaises(DecisionInvalid):
            LicenseDecision.loads(b"{" + b" " * (1024 * 1024))
        with self.assertRaises(DecisionInvalid):
            LicenseDecision.loads('{"unexpected":' + "9" * 5000 + "}")
        with self.assertRaises(DecisionInvalid):
            LicenseDecision.loads("[" * 1000 + "0" + "]" * 1000)

    def test_restricted_decision_is_typed_but_can_never_create_authority(self) -> None:
        requirement = replace(self.spec.licenses[0], decision="restricted")
        spec = replace(self.spec, licenses=(requirement,))
        decision = LicenseDecision.from_mapping(
            {
                "artifact_ids": [spec.asset_id],
                "decision_class": "restricted",
                "kind": "decision",
                "license_id": requirement.license_id,
                "license_text_sha256": requirement.text_sha256,
                "outcome": "decline",
                "presenter": "kilix-installer",
                "release": self.release.release_id,
                "schema": "kilix.install.license/v1",
            }
        )
        with self.open_store() as store, self.assertRaises(DecisionDeclined):
            store.record(decision, self.license_text, self.release, [spec])
        self.assertEqual(tuple((self.root / "state").glob("*.json")), ())

    def test_record_revalidates_direct_dataclass_construction(self) -> None:
        invalid = replace(self.decision(), outcome="accept")
        with self.open_store() as store, self.assertRaises(DecisionInvalid):
            store.record(invalid, self.license_text, self.release, [self.spec])

    def test_record_is_durable_private_idempotent_and_redacts_export(self) -> None:
        ticks = iter((1.25, 9.0))
        with self.open_store(clock=lambda: next(ticks)) as store:
            first = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            second = store.record(
                self.decision(presenter="another-renderer"),
                self.license_text,
                self.release,
                [self.spec],
            )
            self.assertEqual(first.status, "created")
            self.assertEqual(second.status, "existing")
            self.assertEqual(first.key, second.key)
            self.assertEqual(first.recorded_at, second.recorded_at)
            verified = store.require_asset(self.spec, self.release)
            self.assertEqual(verified[0].key, first.key)

            root_info = Path(store.root).stat()
            self.assertEqual(root_info.st_mode & 0o777, 0o700)
            for path in Path(store.root).iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            receipt_path = Path(store.root) / f"{first.key}.json"
            self.assertEqual(receipt_path.stat().st_nlink, 1)

            exported = store.export_redacted().decode("utf-8")
            redacted = json.loads(exported)
            self.assertNotIn(store.account, exported)
            self.assertNotIn(first.recorded_at, exported)
            self.assertNotIn(self.spec.provenance_url, exported)
            self.assertNotIn(self.spec.archive_sha256, exported)
            self.assertIn(self.spec.licenses[0].text_sha256, exported)
            self.assertEqual(
                redacted["schema"],
                "kilix.install.license-redacted/v1",
            )
            record = redacted["authorizations"][0]
            self.assertEqual(
                record["license_text_sha256"], self.spec.licenses[0].text_sha256
            )
            self.assertEqual(
                record["artifact_bindings"][0]["artifact_id"], self.spec.asset_id
            )
            for field in ("record_sha256", "manifest_sha256"):
                self.assertRegex(
                    record["artifact_bindings"][0][field], r"^[a-f0-9]{64}$"
                )
                self.assertNotIn(field, redacted["redacted_fields"])
            self.assertIn("upstream_url", redacted["redacted_fields"])
            export_root = self.root / "private-export"
            export_root.mkdir(mode=0o700)
            destination = export_root / "receipts.json"
            store.export_redacted_to(str(destination))
            self.assertEqual(destination.read_bytes(), store.export_redacted())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ReceiptError, "already exists"):
                store.export_redacted_to(str(destination))

            victim = export_root / "victim"
            victim.write_bytes(b"unchanged")
            victim.chmod(0o600)
            linked_destination = export_root / "linked.json"
            linked_destination.symlink_to(victim)
            with self.assertRaises(UnsafeStore):
                store.export_redacted_to(str(linked_destination))
            self.assertTrue(linked_destination.is_symlink())
            self.assertEqual(victim.read_bytes(), b"unchanged")

            permissive = export_root / "permissive.json"
            permissive.write_bytes(b"unchanged")
            permissive.chmod(0o644)
            with self.assertRaises(UnsafeStore):
                store.export_redacted_to(str(permissive))
            self.assertEqual(permissive.read_bytes(), b"unchanged")

            multiply_linked = export_root / "multiply-linked.json"
            os.link(victim, multiply_linked)
            with self.assertRaises(UnsafeStore):
                store.export_redacted_to(str(multiply_linked))
            self.assertEqual(victim.stat().st_nlink, 2)
            unsafe_export = self.root / "unsafe-export"
            unsafe_export.mkdir(mode=0o755)
            unsafe_export.chmod(0o755)
            with self.assertRaises(UnsafeStore):
                store.export_redacted_to(str(unsafe_export / "receipts.json"))

            parent_token = "private-export-parent-token"
            linked_parent_target = self.root / "linked-parent-target"
            linked_parent_target.mkdir(mode=0o700)
            linked_parent = self.root / parent_token
            linked_parent.symlink_to(linked_parent_target, target_is_directory=True)
            with self.assertRaises(UnsafeStore) as linked_parent_error:
                store.export_redacted_to(str(linked_parent / "receipts.json"))
            self.assertNotIn(parent_token, str(linked_parent_error.exception))
            self.assertTrue(linked_parent.is_symlink())
            self.assertFalse((linked_parent_target / "receipts.json").exists())

            regular_parent = self.root / "regular-private-export-parent-token"
            regular_parent.write_bytes(b"unchanged")
            regular_parent.chmod(0o600)
            with self.assertRaises(UnsafeStore) as regular_parent_error:
                store.export_redacted_to(str(regular_parent / "receipts.json"))
            self.assertNotIn(
                "regular-private-export-parent-token",
                str(regular_parent_error.exception),
            )
            self.assertEqual(regular_parent.read_bytes(), b"unchanged")

            missing_parent = self.root / "missing-private-export-parent-token"
            with self.assertRaises(UnsafeStore) as missing_parent_error:
                store.export_redacted_to(str(missing_parent / "receipts.json"))
            self.assertNotIn(
                "missing-private-export-parent-token",
                str(missing_parent_error.exception),
            )
            self.assertFalse(missing_parent.exists())

            malformed_marker = "private-malformed-export-token"
            malformed_destinations = (
                f"{self.root}/\x00{malformed_marker}/receipts.json",
                os.fsencode(f"/tmp/{malformed_marker}/receipts.json"),
            )
            for malformed in malformed_destinations:
                with self.subTest(malformed=malformed):
                    with self.assertRaises(ReceiptError) as malformed_error:
                        store.export_redacted_to(malformed)  # type: ignore[arg-type]
                    self.assertNotIn(
                        malformed_marker, str(malformed_error.exception)
                    )

            malformed_leaves = (
                f"receipts-\x00{malformed_marker}.json",
                f"receipts-\ud800{malformed_marker}.json",
            )
            for malformed_leaf in malformed_leaves:
                with self.subTest(malformed_leaf=repr(malformed_leaf)):
                    before = tuple(sorted(path.name for path in export_root.iterdir()))
                    with self.assertRaisesRegex(
                        ReceiptError, "^redacted export destination is invalid$"
                    ) as malformed_leaf_error:
                        store.export_redacted_to(str(export_root / malformed_leaf))
                    self.assertNotIn(
                        malformed_marker, str(malformed_leaf_error.exception)
                    )
                    after = tuple(sorted(path.name for path in export_root.iterdir()))
                    self.assertEqual(after, before)
                    self.assertFalse(
                        any(name.startswith(".receipts-") for name in after)
                    )

    def test_exact_release_catalog_asset_and_text_bindings_are_required(self) -> None:
        with self.open_store() as store:
            with self.assertRaises(BindingMismatch):
                store.record(
                    self.decision(), b"different", self.release, [self.spec]
                )
            stored = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            self.assertEqual(stored.status, "created")

            changed_catalog = ReleaseContext.from_catalog(
                "0.2.1", b'{"release":"0.2.1","assets":"changed"}\n'
            )
            with self.assertRaises(ReceiptMissing):
                store.require_asset(self.spec, changed_catalog)

            changed_spec = replace(self.spec, version="1.0-repacked")
            with self.assertRaises(ReceiptMissing):
                store.require_asset(changed_spec, self.release)

            changed_decision = replace(self.decision(), release="0.2.2")
            with self.assertRaises(BindingMismatch):
                store.record(
                    changed_decision, self.license_text, self.release, [self.spec]
                )

    def test_decline_never_records_or_deletes_authority(self) -> None:
        affirmative = replace(
            self.spec,
            licenses=(replace(self.spec.licenses[0], decision="affirmative"),),
        )
        accepted = self.decision(affirmative)
        declined = replace(accepted, outcome="decline")
        with self.open_store() as store:
            with self.assertRaises(DecisionDeclined):
                store.record(
                    declined, self.license_text, self.release, [affirmative]
                )
            self.assertEqual(store.list_metadata(), ())
            store.record(
                accepted, self.license_text, self.release, [affirmative]
            )
            with self.assertRaises(DecisionDeclined):
                store.record(
                    declined, self.license_text, self.release, [affirmative]
                )
            self.assertEqual(len(store.list_metadata()), 1)

    def test_user_input_is_bound_to_the_same_open_file(self) -> None:
        payload = b"owned-copy"
        record = load_json(FIXTURES / "valid" / "asset-user-supplied.json")
        record["licenses"][0]["text_sha256"] = hashlib.sha256(
            self.license_text
        ).hexdigest()
        record["source"]["input_bytes"] = len(payload)
        record["source"]["input_sha256"] = hashlib.sha256(payload).hexdigest()
        spec = AssetSpec.from_mapping(record)
        input_path = self.root / "game.input"
        input_path.write_bytes(payload)

        with self.open_store() as store, VerifiedInput.open(str(input_path)) as opened:
            input_path.rename(self.root / "original.input")
            input_path.write_bytes(b"path-swapped")
            result = store.record(
                self.decision(spec),
                self.license_text,
                self.release,
                [spec],
                verified_input=opened,
            )
            self.assertEqual(result.status, "created")
            self.assertEqual(len(store.require_asset(spec, self.release)), 1)
            duplicate = opened.duplicate_descriptor()
            try:
                self.assertEqual(os.read(duplicate, len(payload)), payload)
            finally:
                os.close(duplicate)

        mutable = self.root / "mutable.input"
        mutable.write_bytes(payload)
        with self.open_store() as store, VerifiedInput.open(str(mutable)) as opened:
            mutable.write_bytes(b"mutated!!!")
            with self.assertRaises(BindingMismatch):
                store.record(
                    self.decision(spec),
                    self.license_text,
                    self.release,
                    [spec],
                    verified_input=opened,
                )

    def test_batch_receipt_covers_each_exact_artifact_independent_of_order(self) -> None:
        second = replace(self.spec, asset_id="voice.demo-two", version="2.0")
        decision = self.decision(
            artifact_ids=[second.asset_id, self.spec.asset_id]
        )
        with self.open_store() as store:
            store.record(
                decision,
                self.license_text,
                self.release,
                [second, self.spec],
            )
            self.assertEqual(len(store.require_asset(self.spec, self.release)), 1)
            self.assertEqual(len(store.require_asset(second, self.release)), 1)

    def test_corrupt_direct_receipt_is_not_hidden_by_valid_batch_receipt(self) -> None:
        second = replace(self.spec, asset_id="voice.demo-two", version="2.0")
        with self.open_store() as store:
            store.record(
                self.decision(
                    artifact_ids=[self.spec.asset_id, second.asset_id]
                ),
                self.license_text,
                self.release,
                [self.spec, second],
            )
            direct = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            direct_path = Path(store.root) / f"{direct.key}.json"
            direct_path.write_bytes(b"{not-json")
            direct_path.chmod(0o600)
            with self.assertRaises(StoredReceiptInvalid):
                store.require_asset(self.spec, self.release)

    def test_store_refuses_relative_xdg_root_privilege_and_unsafe_objects(self) -> None:
        with self.assertRaises(UnsafeStore):
            ReceiptStore.open_default({"XDG_STATE_HOME": "relative/state"})
        with (
            mock.patch("kilix_content.receipt.os.getuid", return_value=0),
            mock.patch("kilix_content.receipt.os.geteuid", return_value=0),
            self.assertRaises(UnsafeStore),
        ):
            ReceiptStore.open_default({"XDG_STATE_HOME": str(self.root / "xdg")})

        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaises(UnsafeStore):
            open_test_store(str(unsafe))
        self.assertEqual(unsafe.stat().st_mode & 0o777, 0o755)

        target = self.root / "target"
        target.mkdir(mode=0o700)
        link = self.root / "linked"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(UnsafeStore):
            open_test_store(str(link))

        lock_root = self.root / "lock-root"
        lock_root.mkdir(mode=0o700)
        lock_path = lock_root / ".lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)
        with self.assertRaises(UnsafeStore):
            open_test_store(str(lock_root))
        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o644)

        transition_root = self.root / "transition"
        with (
            open_test_store(str(transition_root)) as store, mock.patch(
                "kilix_content.receipt.os.geteuid", return_value=store.uid + 1
            ),
            self.assertRaises(UnsafeStore),
        ):
            store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )

        replaced_root = self.root / "replaced-lock"
        with open_test_store(str(replaced_root)) as store:
            (replaced_root / ".lock").unlink()
            (replaced_root / ".lock").write_bytes(b"")
            (replaced_root / ".lock").chmod(0o600)
            with self.assertRaises(UnsafeStore):
                store.record(
                    self.decision(), self.license_text, self.release, [self.spec]
                )

    def test_default_store_ignores_home_and_blocks_synthetic_production_context(self) -> None:
        xdg = self.root / "xdg-state"
        self.assertFalse(hasattr(ReleaseContext, "_from_authoritative_catalog"))
        self.assertFalse(hasattr(ReleaseContext, "_from_stored_digest"))
        self.assertFalse(hasattr(ReceiptStore, "_open_test"))
        self.assertFalse(hasattr(ReceiptStore, "_open_test_path"))
        self.assertFalse(hasattr(receipt_module, "_TestReceiptStore"))

        class CallerOverride(ReceiptStore):
            __slots__ = ()

            def _require_release_authority(self, release: ReleaseContext) -> None:
                del release

        with self.assertRaisesRegex(UnsafeStore, "subclass"):
            CallerOverride.open_default({"XDG_STATE_HOME": str(self.root / "override")})
        with ReceiptStore.open_default(
            {"XDG_STATE_HOME": str(xdg), "HOME": str(self.root / "poison")}
        ) as store:
            self.assertEqual(
                Path(store.root),
                xdg / "kilix-content" / "license-receipts" / "v1",
            )
            self.assertFalse((self.root / "poison").exists())
            contexts = (
                self.release,
                ReleaseContext("0.2.1", "a" * 64),
            )
            with self.assertRaises(AttributeError):
                store._testing = True
            for context in contexts:
                with self.subTest(context=context), self.assertRaisesRegex(
                    BindingMismatch, "production authorization"
                ):
                    store.record(
                        self.decision(), self.license_text, context, [self.spec]
                    )
            with self.assertRaisesRegex(
                BindingMismatch, "production authorization"
            ):
                store.require_asset(self.spec, self.release)

    def test_unknown_store_generation_and_raw_public_receipts_never_authorize(self) -> None:
        store_root = self.root / "generation"
        with open_test_store(str(store_root)):
            pass
        marker = store_root / ".format"
        marker.write_text('{"schema":"kilix.install.license-store/v2"}\n')
        marker.chmod(0o600)
        with self.assertRaises(UnsafeStore):
            open_test_store(str(store_root))

        fresh = self.root / "fresh"
        with open_test_store(str(fresh)) as store:
            public = load_json(
                FIXTURES / "valid" / "license-informational-receipt.json"
            )
            legacy = fresh / "legacy-public-receipt.json"
            legacy.write_text(json.dumps(public) + "\n")
            legacy.chmod(0o600)
            with self.assertRaises(ReceiptMissing):
                store.require_asset(self.spec, self.release)

    def test_format_initialization_is_atomic_and_aborted_pending_state_recovers(self) -> None:
        state = self.root / "format-atomic"

        def partial_write(descriptor: int, document: bytes) -> None:
            os.write(descriptor, document[:1])
            raise OSError(errno.EIO, "injected partial initialization")

        with (
            mock.patch(
                "kilix_content.receipt.ReceiptStore._write_all",
                side_effect=partial_write,
            ),
            self.assertRaisesRegex(ReceiptError, "format marker"),
        ):
            open_test_store(str(state))
        self.assertFalse((state / ".format").exists())
        self.assertEqual(tuple(state.glob(".tmp-*")), ())

        with open_test_store(str(state)) as store:
            self.assertTrue((state / ".format").is_file())
            target = "a" * 64 + ".json"
            with store._locked():
                self.assertTrue(
                    store._create_fixed_file(
                        ".pending",
                        store._pending_document(target),
                        "pending marker",
                    )
                )
            self.assertEqual(store.reconcile(), ReconcileResult("aborted", "a" * 64))
            self.assertFalse((state / ".pending").exists())

    def test_corrupt_duplicate_key_wrong_mode_and_hardlink_fail_closed(self) -> None:
        cases = (
            "duplicate",
            "mode",
            "hardlink",
            "oversize",
            "utf8",
            "deep",
            "huge-int",
        )
        for case in cases:
            with self.subTest(case=case):
                root = self.root / case
                with open_test_store(str(root)) as store:
                    result = store.record(
                        self.decision(),
                        self.license_text,
                        self.release,
                        [self.spec],
                    )
                    receipt = root / f"{result.key}.json"
                    if case == "duplicate":
                        original = receipt.read_text(encoding="utf-8")
                        receipt.write_text(
                            '{"schema":"duplicate",' + original[1:],
                            encoding="utf-8",
                        )
                        receipt.chmod(0o600)
                        expected = StoredReceiptInvalid
                    elif case == "mode":
                        receipt.chmod(0o644)
                        expected = UnsafeStore
                    elif case == "hardlink":
                        os.link(receipt, root / ("f" * 64 + ".json"))
                        expected = UnsafeStore
                    elif case == "oversize":
                        receipt.write_bytes(b"{" + b" " * (1024 * 1024))
                        receipt.chmod(0o600)
                        expected = StoredReceiptInvalid
                    elif case == "utf8":
                        receipt.write_bytes(b"\xff")
                        receipt.chmod(0o600)
                        expected = StoredReceiptInvalid
                    elif case == "deep":
                        receipt.write_text("[" * 40 + "0" + "]" * 40)
                        receipt.chmod(0o600)
                        expected = StoredReceiptInvalid
                    else:
                        receipt.write_text(
                            '{"unexpected":' + "9" * 5000 + "}",
                            encoding="utf-8",
                        )
                        receipt.chmod(0o600)
                        expected = StoredReceiptInvalid
                    with self.assertRaises(expected):
                        store.require_asset(self.spec, self.release)

    def test_visible_but_unconfirmed_write_reports_durability_unknown(self) -> None:
        state = self.root / "state"
        with self.open_store() as store:
            real_fsync = os.fsync
            root_syncs = 0

            def fail_receipt_root_sync(descriptor: int) -> None:
                nonlocal root_syncs
                if descriptor == store._root_descriptor:
                    root_syncs += 1
                    if root_syncs == 2:
                        raise OSError(errno.EIO, "injected directory failure")
                real_fsync(descriptor)

            with (
                mock.patch(
                    "kilix_content.receipt.os.fsync",
                    side_effect=fail_receipt_root_sync,
                ),
                self.assertRaises(DurabilityUnknown),
            ):
                store.record(
                    self.decision(), self.license_text, self.release, [self.spec]
                )
            receipts = tuple(Path(store.root).glob("[0-9a-f]*.json"))
            self.assertEqual(len(receipts), 1)
            self.assertTrue((state / ".pending").is_file())
            with self.assertRaises(DurabilityUnknown):
                store.require_asset(self.spec, self.release)

        with self.open_store() as reopened:
            with self.assertRaises(DurabilityUnknown):
                reopened.require_asset(self.spec, self.release)
            installer = Installer(str(self.root / "installed-pending"))
            with (
                mock.patch(
                    "kilix_content.install.download",
                    side_effect=AssertionError("network must remain blocked"),
                ),
                self.assertRaises(DurabilityUnknown),
            ):
                installer.ensure_asset(self.spec, reopened, self.release)

            real_fsync = os.fsync

            def fail_all_root_syncs(descriptor: int) -> None:
                if descriptor == reopened._root_descriptor:
                    raise OSError(errno.EIO, "persistent directory failure")
                real_fsync(descriptor)

            with (
                mock.patch(
                    "kilix_content.receipt.os.fsync",
                    side_effect=fail_all_root_syncs,
                ),
                self.assertRaises(DurabilityUnknown),
            ):
                reopened.reconcile()
            self.assertTrue((state / ".pending").is_file())
            with self.assertRaises(DurabilityUnknown):
                reopened.require_asset(self.spec, self.release)

            reconciled = reopened.reconcile()
            self.assertEqual(
                reconciled,
                ReconcileResult("committed", receipts[0].stem),
            )
            self.assertFalse((state / ".pending").exists())
            self.assertEqual(len(reopened.require_asset(self.spec, self.release)), 1)

    def test_crash_temporary_cleanup_recovers_no_overwrite_target(self) -> None:
        with self.open_store() as store:
            first = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            target = Path(store.root) / f"{first.key}.json"
            linked_temp = Path(store.root) / (".tmp-" + "a" * 48)
            os.link(target, linked_temp)
            self.assertEqual(target.stat().st_nlink, 2)
            recovered = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            self.assertEqual(recovered.status, "existing")
            self.assertFalse(linked_temp.exists())
            self.assertEqual(target.stat().st_nlink, 1)

            orphan = Path(store.root) / (".tmp-" + "b" * 48)
            orphan.write_bytes(b"orphan")
            orphan.chmod(0o600)
            again = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            self.assertEqual(again.status, "existing")
            self.assertFalse(orphan.exists())

    def test_concurrent_identical_records_converge_without_overwrite(self) -> None:
        state = self.root / "concurrent"
        with open_test_store(str(state)):
            pass

        def record_once(_index: int):
            with open_test_store(str(state), clock=lambda: 4.0) as store:
                return store.record(
                    self.decision(), self.license_text, self.release, [self.spec]
                )

        with ThreadPoolExecutor(max_workers=6) as executor:
            results = tuple(executor.map(record_once, range(12)))
        self.assertEqual(sum(item.status == "created" for item in results), 1)
        self.assertEqual(sum(item.status == "existing" for item in results), 11)
        self.assertEqual(len({item.key for item in results}), 1)
        self.assertEqual(len(tuple(state.glob("[0-9a-f]*.json"))), 1)

    def test_shared_instance_threads_and_separate_processes_converge(self) -> None:
        shared_state = self.root / "shared-instance"
        with open_test_store(str(shared_state), clock=lambda: 5.0) as store:
            def shared_record(_index: int):
                return store.record(
                    self.decision(), self.license_text, self.release, [self.spec]
                )

            with ThreadPoolExecutor(max_workers=8) as executor:
                shared_results = tuple(executor.map(shared_record, range(16)))
        self.assertEqual(sum(item.status == "created" for item in shared_results), 1)
        self.assertEqual(sum(item.status == "existing" for item in shared_results), 15)

        process_state = self.root / "process-race"
        with open_test_store(str(process_state)):
            pass
        workers: list[tuple[int, int]] = []
        for _index in range(4):
            read_descriptor, write_descriptor = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_descriptor)
                try:
                    with open_test_store(
                        str(process_state), clock=lambda: 6.0
                    ) as child_store:
                        status = child_store.record(
                            self.decision(),
                            self.license_text,
                            self.release,
                            [self.spec],
                        ).status
                    os.write(write_descriptor, status.encode("ascii"))
                    code = 0
                except Exception as exc:  # noqa: BLE001 - child reports type only
                    os.write(write_descriptor, type(exc).__name__.encode("ascii"))
                    code = 1
                finally:
                    os.close(write_descriptor)
                os._exit(code)
            os.close(write_descriptor)
            workers.append((pid, read_descriptor))

        statuses = []
        for pid, descriptor in workers:
            statuses.append(os.read(descriptor, 128).decode("ascii"))
            os.close(descriptor)
            _waited, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)
        self.assertEqual(statuses.count("created"), 1)
        self.assertEqual(statuses.count("existing"), 3)

    def test_post_fork_reuse_refuses_and_killed_lock_holder_releases(self) -> None:
        with self.open_store() as store:
            read_descriptor, write_descriptor = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_descriptor)
                try:
                    store.require_asset(self.spec, self.release)
                except Exception as exc:  # noqa: BLE001 - child reports type only
                    os.write(write_descriptor, type(exc).__name__.encode("ascii"))
                finally:
                    os.close(write_descriptor)
                os._exit(0)
            os.close(write_descriptor)
            child_result = os.read(read_descriptor, 128).decode("ascii")
            os.close(read_descriptor)
            os.waitpid(pid, 0)
            self.assertEqual(child_result, "UnsafeStore")

        state = self.root / "killed-holder"
        with open_test_store(str(state)):
            pass
        ready_read, ready_write = os.pipe()
        holder = os.fork()
        if holder == 0:
            os.close(ready_read)
            with open_test_store(str(state)) as child_store:
                with child_store._locked():
                    os.write(ready_write, b"ready")
                    signal.pause()
            os._exit(0)
        os.close(ready_write)
        self.assertEqual(os.read(ready_read, 5), b"ready")
        os.close(ready_read)
        os.kill(holder, signal.SIGKILL)
        os.waitpid(holder, 0)
        with open_test_store(str(state)) as recovered:
            result = recovered.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
        self.assertEqual(result.status, "created")

    def test_installer_rechecks_authority_before_atomic_selection(self) -> None:
        payload = b"model-bytes"
        source = self.root / "source"
        target = source / "models" / "model.bin"
        target.parent.mkdir(parents=True)
        target.write_bytes(payload)
        archive = self.root / "model.tar"
        with tarfile.open(archive, "w") as handle:
            handle.add(target, arcname="models/model.bin")

        record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
        record["licenses"][0]["text_sha256"] = hashlib.sha256(
            self.license_text
        ).hexdigest()
        record["files"] = [
            {
                "path": "models/model.bin",
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ]
        record["sizes"]["installed_bytes"] = len(payload)
        record["source"]["archive_sha256"] = hashlib.sha256(
            archive.read_bytes()
        ).hexdigest()
        spec = AssetSpec.from_mapping(record)
        installer = Installer(str(self.root / "installed"))
        with self.open_store() as store:
            store.record(
                self.decision(spec), self.license_text, self.release, [spec]
            )
            authorization = store.require_asset(spec, self.release)
            with (
                mock.patch(
                    "kilix_content.install.download",
                    side_effect=lambda _urls, destination, _report, _sha: shutil.copyfile(
                        archive, destination
                    ),
                ),
                mock.patch.object(
                    type(store),
                    "require_asset",
                    side_effect=(authorization, ReceiptMissing("injected revocation")),
                ),
                self.assertRaises(ReceiptMissing),
            ):
                installer.ensure_asset(spec, store, self.release)
        self.assertFalse(Path(installer.asset_destination(spec)).exists())

    def test_runtime_rejects_duplicate_license_id_ambiguity(self) -> None:
        record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
        record["licenses"].append(
            {**record["licenses"][0], "decision": "affirmative"}
        )
        with self.assertRaisesRegex(CatalogError, "duplicate license id"):
            AssetSpec.from_mapping(record)

    def test_catalog_and_download_diagnostics_reject_token_and_control_leaks(self) -> None:
        record = load_json(FIXTURES / "valid" / "asset-mirrored.json")
        for unsafe_id in ("notice\nspoof", "notice\x1b[31mspoof", "notice\u202espoof"):
            changed = json.loads(json.dumps(record))
            changed["licenses"][0]["id"] = unsafe_id
            with self.subTest(unsafe_id=repr(unsafe_id)), self.assertRaises(
                CatalogError
            ):
                AssetSpec.from_mapping(changed)
        for unsafe_url in (
            "https://example.org/model?token=secret",
            "https://example.org/model#fragment",
            "https://user:secret@example.org/model",
            "https://example.org:99999/model",
        ):
            changed = json.loads(json.dumps(record))
            changed["source"]["mirrors"] = [unsafe_url]
            with self.subTest(unsafe_url=unsafe_url), self.assertRaises(CatalogError):
                AssetSpec.from_mapping(changed)

        reports: list[str] = []
        secret = "private-query-token"
        with (
            mock.patch(
                "kilix_content.install.urllib.request.urlopen",
                side_effect=OSError(f"upstream rejected {secret}"),
            ),
            self.assertRaises(InstallError) as raised,
        ):
            download(
                f"https://example.org/model.bin?token={secret}",
                str(self.root / "download.bin"),
                reports.append,
                "a" * 64,
            )
        diagnostics = "\n".join((*reports, str(raised.exception)))
        self.assertNotIn(secret, diagnostics)
        self.assertNotIn("token=", diagnostics)
        self.assertIn("model.bin", reports[0])

    def test_unknown_json_field_names_are_never_echoed_in_diagnostics(self) -> None:
        informational = load_json(
            FIXTURES / "valid" / "license-informational-decision.json"
        )
        injected_name = "\x1b[31mprivate-field-token"
        with self.assertRaises(DecisionInvalid) as decision_error:
            LicenseDecision.from_mapping({**informational, injected_name: True})
        self.assertNotIn("\x1b", str(decision_error.exception))
        self.assertNotIn("private-field-token", str(decision_error.exception))

        with self.open_store() as store:
            recorded = store.record(
                self.decision(), self.license_text, self.release, [self.spec]
            )
            path = Path(store.root) / f"{recorded.key}.json"
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope[injected_name] = True
            path.write_text(
                json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaises(StoredReceiptInvalid) as stored_error:
                store.list_metadata()
        self.assertNotIn("\x1b", str(stored_error.exception))
        self.assertNotIn("private-field-token", str(stored_error.exception))

    def test_duplicate_json_field_names_are_never_echoed_in_diagnostics(self) -> None:
        marker = "private-duplicate-field-token"
        duplicate_names = (
            f"printable-{marker}",
            f"\x1b[31m{marker}",
            f"\u202e{marker}",
        )
        for index, duplicate_name in enumerate(duplicate_names):
            with self.subTest(parser="decision", duplicate_name=duplicate_name):
                encoded_name = json.dumps(duplicate_name)
                duplicate = f"{{{encoded_name}:1,{encoded_name}:2}}"
                with self.assertRaises(DecisionInvalid) as decision_error:
                    LicenseDecision.loads(duplicate)
                decision_message = str(decision_error.exception)
                self.assertNotIn(marker, decision_message)
                self.assertNotIn("\x1b", decision_message)
                self.assertNotIn("\u202e", decision_message)

            with self.subTest(parser="stored", duplicate_name=duplicate_name):
                root = self.root / f"duplicate-field-{index}"
                with open_test_store(str(root)) as store:
                    recorded = store.record(
                        self.decision(), self.license_text, self.release, [self.spec]
                    )
                    path = Path(store.root) / f"{recorded.key}.json"
                    original = path.read_text(encoding="utf-8")
                    path.write_text(
                        f"{{{encoded_name}:1,{encoded_name}:2," + original[1:],
                        encoding="utf-8",
                    )
                    path.chmod(0o600)
                    with self.assertRaises(StoredReceiptInvalid) as stored_error:
                        store.list_metadata()
                stored_message = str(stored_error.exception)
                self.assertNotIn(marker, stored_message)
                self.assertNotIn("\x1b", stored_message)
                self.assertNotIn("\u202e", stored_message)

            with self.subTest(parser="catalog", duplicate_name=duplicate_name):
                with self.assertRaises(CatalogError) as catalog_error:
                    Catalog.loads(duplicate)
                catalog_message = str(catalog_error.exception)
                self.assertEqual(
                    catalog_message, "catalog JSON contains a duplicate field"
                )
                self.assertNotIn(marker, catalog_message)

    def test_every_distinct_license_requires_its_own_exact_receipt(self) -> None:
        first = self.spec.licenses[0]
        second = replace(first, license_id="notice-two")
        spec = replace(self.spec, licenses=(first, second))
        first_decision = self.decision(spec)
        second_decision = LicenseDecision.from_mapping(
            {
                **first_decision.to_mapping(),
                "license_id": second.license_id,
            }
        )
        with self.open_store() as store:
            store.record(
                first_decision, self.license_text, self.release, [spec]
            )
            with self.assertRaises(ReceiptMissing):
                store.require_asset(spec, self.release)
            store.record(
                second_decision, self.license_text, self.release, [spec]
            )
            self.assertEqual(len(store.require_asset(spec, self.release)), 2)


if __name__ == "__main__":
    unittest.main()
