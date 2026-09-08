"""Real packaged authority, durable receipts and immutable installed model FDs."""

from contextlib import ExitStack
import copy
from dataclasses import replace
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from kilix_content import (
    AssetSpec, BindingMismatch, InstalledAssetError, Installer, LicenseDecision,
    ReceiptMissing, ReceiptStore, ReleaseContext,
)
from kilix_content import installed
from tests.test_packaged_authority import canonical, mock_packaged_bytes, PACKAGED_CATALOG


class InstalledAssetTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.payloads = {"model/weights.bin": b"exact installed weights\n",
                         "LICENSE": b"Installed snapshot fixture license.\n"}
        record = json.loads((Path(__file__).parent /
                             "fixtures/contracts/valid/asset-mirrored.json").read_text())
        record["files"] = [{"path": name, "bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()}
                           for name, data in self.payloads.items()]
        record["sizes"]["installed_bytes"] = sum(map(len, self.payloads.values()))
        record["sizes"]["temporary_bytes"] = record["sizes"]["installed_bytes"] + 10
        record["licenses"][0]["text_sha256"] = hashlib.sha256(self.payloads["LICENSE"]).hexdigest()
        record["compatibility"]["maximum"] = 4
        self.spec = AssetSpec.from_mapping(record)
        document = json.loads(PACKAGED_CATALOG.read_bytes())
        document["assets"] = [self.spec.to_mapping()]
        payload = canonical(document)
        self.stack.enter_context(mock_packaged_bytes(payload, digest=hashlib.sha256(payload).hexdigest()))
        self.release = ReleaseContext.packaged()
        self.store = self.stack.enter_context(ReceiptStore.open_default(
            {"XDG_STATE_HOME": str(self.root / "state")}))
        requirement = self.spec.licenses[0]
        decision = LicenseDecision.from_mapping({
            "artifact_ids": [self.spec.asset_id], "decision_class": "informational",
            "kind": "decision", "license_id": requirement.license_id,
            "license_text_sha256": requirement.text_sha256, "outcome": "record",
            "presenter": "kilix-installer", "release": self.release.release_id,
            "schema": "kilix.install.license/v1",
        })
        self.store.record(decision, self.payloads["LICENSE"], self.release, [self.spec])
        self.installer, self.selected = self.population("data")

    def population(self, name):
        installer = Installer(str(self.root / name))
        selected = Path(installer.asset_destination(self.spec))
        selected.mkdir(mode=0o700, parents=True)
        for relative, data in self.payloads.items():
            target = selected / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o600)
        return installer, selected

    def open(self, **kwargs):
        args = dict(maximum_bytes=self.spec.installed_bytes)
        args.update(kwargs)
        return self.installer.open_asset(self.spec, self.store, self.release, **args)

    @staticmethod
    def fd_count():
        return len(os.listdir("/proc/self/fd"))

    def test_exact_receipt_binding_readonly_seals_and_owned_lifetime(self):
        before = self.fd_count()
        with self.open() as asset:
            self.assertEqual(asset.release, self.release)
            self.assertEqual(asset.binding, installed.ArtifactBinding.from_spec(self.spec))
            self.assertEqual(asset.receipts, self.store.require_asset(self.spec, self.release))
            self.assertEqual(asset.files, self.spec.files)
            for name, data in self.payloads.items():
                descriptor = asset.duplicate(name)
                try:
                    self.assertEqual(os.pread(descriptor, len(data) + 1, 0), data)
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                    self.assertEqual(fcntl.fcntl(descriptor, 1034) & installed._SEALS,
                                     installed._SEALS)
                    with self.assertRaises(OSError):
                        os.pwrite(descriptor, b"x", 0)
                    with self.assertRaises(OSError):
                        os.ftruncate(descriptor, 0)
                finally:
                    os.close(descriptor)
            retained = asset.duplicate("model/weights.bin")
            separate = asset.duplicate("model/weights.bin")
            try:
                self.assertEqual(os.read(retained, 100), self.payloads["model/weights.bin"])
                self.assertEqual(os.read(separate, 100), self.payloads["model/weights.bin"])
            finally:
                os.close(separate)
            with self.assertRaises(TypeError):
                copy.copy(asset)
        try:
            self.assertEqual(os.pread(retained, 100, 0), self.payloads["model/weights.bin"])
            with self.assertRaises(InstalledAssetError):
                asset.duplicate("model/weights.bin")
            asset.close()
        finally:
            os.close(retained)
        self.assertEqual(self.fd_count(), before)

    def test_later_path_destruction_cannot_change_snapshot(self):
        with self.open() as asset:
            path = self.selected / "model/weights.bin"
            path.unlink()
            path.write_bytes(b"different later bytes")
            descriptor = asset.duplicate("model/weights.bin")
            try:
                self.assertEqual(os.pread(descriptor, 100, 0), self.payloads["model/weights.bin"])
            finally:
                os.close(descriptor)

    def test_missing_receipt_and_synthetic_context_refuse_before_allocation(self):
        with patch.object(installed, "_create_memfd", side_effect=AssertionError("must not allocate")):
            forged = ReleaseContext(self.release.release_id, self.release.catalog_sha256)
            with self.assertRaises(BindingMismatch):
                self.installer.open_asset(self.spec, self.store, forged,
                                          maximum_bytes=self.spec.installed_bytes)
            with ReceiptStore.open_default({"XDG_STATE_HOME": str(self.root / "empty")}) as store:
                with self.assertRaises(ReceiptMissing):
                    self.installer.open_asset(self.spec, store, self.release,
                                              maximum_bytes=self.spec.installed_bytes)
            with self.assertRaises(BindingMismatch):
                self.installer.open_asset(replace(self.spec, version="different"), self.store,
                                          self.release, maximum_bytes=self.spec.installed_bytes)

    def test_invalid_budgets_and_cancellation_inputs_refuse(self):
        cases = [{"maximum_bytes": value} for value in
                 (False, 0, -1, 1.0, self.spec.installed_bytes - 1, 8 * 1024**3 + 1)]
        cases += [{"timeout": value} for value in
                  (True, 0, -1, float("nan"), float("inf"), 3601, 10**1000)]
        cases.append({"cancelled": []})
        with patch.object(installed, "_create_memfd", side_effect=AssertionError("must not allocate")):
            for args in cases:
                with self.subTest(args=args), self.assertRaises(InstalledAssetError):
                    self.open(**args)

    def test_receipt_lock_waits_share_snapshot_deadline_and_cancellation(self):
        # Keep each real lock held until the caller has already refused. This
        # catches a late check that reports timeout only after acquiring it.
        for phase in ("initial", "final"):
            for kind in ("flock", "thread"):
                for ending in ("deadline", "already-cancelled", "cancel-waiter"):
                    with self.subTest(phase=phase, kind=kind, ending=ending):
                        before = self.fd_count()
                        descriptor = os.open(f"/proc/self/fd/{self.store._lock_descriptor}",
                                             os.O_RDWR | os.O_CLOEXEC)
                        held = threading.Event()
                        cancel = threading.Event()
                        errors = []
                        completed_while_held = False
                        copied = 0
                        member = installed._member

                        def hold():
                            if kind == "flock":
                                fcntl.flock(descriptor, fcntl.LOCK_EX)
                            else:
                                self.store._thread_lock.acquire()
                            if ending == "already-cancelled":
                                cancel.set()
                            held.set()

                        def after_copy(parent, item, check):
                            nonlocal copied
                            result = member(parent, item, check)
                            copied += 1
                            if copied == len(self.spec.files):
                                hold()
                            return result

                        def call():
                            try:
                                with self.open(timeout=0.15, cancelled=cancel.is_set):
                                    errors.append("unexpected success")
                            except BaseException as error:
                                errors.append(error)

                        if phase == "initial":
                            hold()
                        with patch.object(installed, "_member",
                                          after_copy if phase == "final" else member):
                            worker = threading.Thread(target=call)
                            try:
                                worker.start()
                                self.assertTrue(held.wait(1), "final receipt check not reached")
                                if ending == "cancel-waiter":
                                    time.sleep(0.02)
                                    cancel.set()
                                worker.join(0.75)
                                completed_while_held = not worker.is_alive()
                            finally:
                                if held.is_set():
                                    if kind == "flock":
                                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                                    else:
                                        self.store._thread_lock.release()
                                os.close(descriptor)
                                worker.join(6)
                        self.assertFalse(worker.is_alive())
                        self.assertTrue(completed_while_held, "receipt wait ignored operation budget")
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], InstalledAssetError)
                        self.assertIn("deadline" if ending == "deadline" else "cancelled",
                                      str(errors[0]))
                        self.assertEqual(self.fd_count(), before)

    def test_invalid_populations_are_refused_without_descriptor_leaks(self):
        for kind in ("missing", "extra", "empty-directory", "symlink", "fifo", "hardlink",
                     "execute", "shared-write", "size", "digest"):
            with self.subTest(kind=kind):
                installer, selected = self.population(kind)
                path = selected / "model/weights.bin"
                if kind in {"missing", "symlink", "fifo"}:
                    path.unlink()
                if kind == "extra":
                    (selected / "extra").write_bytes(b"extra")
                elif kind == "empty-directory":
                    (selected / "extra").mkdir()
                elif kind == "symlink":
                    path.symlink_to(selected / "LICENSE")
                elif kind == "fifo":
                    os.mkfifo(path)
                elif kind == "hardlink":
                    os.link(path, self.root / "other-link")
                elif kind == "execute":
                    path.chmod(0o700)
                elif kind == "shared-write":
                    path.chmod(0o620)
                elif kind == "size":
                    path.write_bytes(b"short")
                elif kind == "digest":
                    path.write_bytes(b"x" * len(self.payloads["model/weights.bin"]))
                before = self.fd_count()
                with self.assertRaises(InstalledAssetError):
                    installer.open_asset(self.spec, self.store, self.release,
                                         maximum_bytes=self.spec.installed_bytes)
                self.assertEqual(self.fd_count(), before)

    def test_shared_or_symlink_ancestor_refuses_before_member_allocation(self):
        actual = self.root / "data"
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        alias_installer = Installer(str(alias / "nested"))
        with patch.object(installed, "_create_memfd", side_effect=AssertionError("must not allocate")):
            with self.assertRaises(InstalledAssetError):
                alias_installer.open_asset(self.spec, self.store, self.release,
                                           maximum_bytes=self.spec.installed_bytes)
            actual.chmod(0o777)
            try:
                with self.assertRaises(InstalledAssetError):
                    self.open()
            finally:
                actual.chmod(0o700)

    def test_fifo_replacement_after_population_does_not_block_or_allocate(self):
        original = installed._member
        def replace_before_open(parent, item, check):
            if item.path == "model/weights.bin":
                path = self.selected / item.path
                path.unlink()
                os.mkfifo(path)
            return original(parent, item, check)
        before = self.fd_count()
        with patch.object(installed, "_member", replace_before_open), self.assertRaises(InstalledAssetError):
            self.open()
        self.assertEqual(self.fd_count(), before)

    def test_allocation_failure_closes_source_and_directory_descriptors(self):
        before = self.fd_count()
        with patch.object(installed, "_create_memfd", side_effect=OSError(errno.EMFILE, "fixture limit")):
            with self.assertRaises(InstalledAssetError):
                self.open()
        self.assertEqual(self.fd_count(), before)

    def test_linux_memfd_without_python_wrapper_still_requires_kernel_seals(self):
        with patch.object(os, "memfd_create", None, create=True):
            with self.open() as asset:
                descriptor = asset.duplicate("model/weights.bin")
                try:
                    self.assertEqual(os.pread(descriptor, 100, 0), self.payloads["model/weights.bin"])
                    self.assertEqual(fcntl.fcntl(descriptor, 1034) & 0x000F, 0x000F)
                    self.assertFalse(os.get_inheritable(descriptor))
                finally:
                    os.close(descriptor)

    def test_growth_during_actual_read_is_refused(self):
        original = os.read
        path = self.selected / "model/weights.bin"
        inode = path.stat().st_ino
        changed = False
        def grow(descriptor, count):
            nonlocal changed
            data = original(descriptor, count)
            if not changed and os.fstat(descriptor).st_ino == inode:
                changed = True
                with path.open("ab") as output:
                    output.write(b"growth")
            return data
        before = self.fd_count()
        with patch.object(os, "read", grow), self.assertRaises(InstalledAssetError):
            self.open()
        self.assertTrue(changed)
        self.assertEqual(self.fd_count(), before)

    def test_cancel_and_deadline_after_read_close_partial_snapshots(self):
        for kind in ("cancel", "deadline"):
            with self.subTest(kind=kind):
                original = os.read
                read = False
                def observe(descriptor, count):
                    nonlocal read
                    data = original(descriptor, count)
                    if os.fstat(descriptor).st_ino == (self.selected / "model/weights.bin").stat().st_ino:
                        read = True
                    return data
                before = self.fd_count()
                with patch.object(os, "read", observe):
                    with patch.object(installed.time, "monotonic", side_effect=lambda: 200 if read else 0):
                        with self.assertRaises(InstalledAssetError):
                            self.open(cancelled=(lambda: read) if kind == "cancel" else None)
                self.assertTrue(read)
                self.assertEqual(self.fd_count(), before)

    def test_selection_replacement_during_snapshot_preserves_both_trees(self):
        original = installed._member
        moved = self.selected.with_name("retained-old")
        changed = False
        def replace_after_read(parent, item, check):
            nonlocal changed
            result = original(parent, item, check)
            if not changed:
                changed = True
                self.selected.rename(moved)
                self.selected.mkdir(mode=0o700)
                (self.selected / "marker").write_bytes(b"preserve replacement")
            return result
        before = self.fd_count()
        with patch.object(installed, "_member", replace_after_read), self.assertRaises(InstalledAssetError):
            self.open()
        self.assertEqual((self.selected / "marker").read_bytes(), b"preserve replacement")
        self.assertEqual((moved / "model/weights.bin").read_bytes(), self.payloads["model/weights.bin"])
        self.assertEqual(self.fd_count(), before)

    def test_receipt_revoked_during_snapshot_is_rechecked(self):
        original = installed._member
        key = self.store.require_asset(self.spec, self.release)[0].key
        revoked = False
        def revoke_after_read(parent, item, check):
            nonlocal revoked
            result = original(parent, item, check)
            if not revoked:
                revoked = True
                (Path(self.store.root) / (key + ".json")).unlink()
            return result
        before = self.fd_count()
        with patch.object(installed, "_member", revoke_after_read), self.assertRaises(ReceiptMissing):
            self.open()
        self.assertEqual(self.fd_count(), before)


if __name__ == "__main__":
    unittest.main()
