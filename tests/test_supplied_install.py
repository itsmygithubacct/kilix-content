"""Installing from bytes the user already holds, with no network at all (OD-BO).

asset/v3 has no `user-supplied` source mode and must not get one: OD-AR
superseded that mode and `tests/test_c4_encodec_records.py` refuses it
catalog-wide. What was lost with it is the *capability* -- installing a model
from a checkpoint the user already has, on an air-gapped or metered machine --
and at v3 that does not need a mode, because the manifest (`files`: path,
bytes, sha256) determines the installed tree for every mode alike.

So supply is an acquisition, not a record shape: `ensure_supplied_asset` reads
the same manifest the download path verifies, under the same receipt, and the
tests below hold it to that. The air-gapped claim is measured, not asserted:
the network audit hook records *every* socket event it sees, allowed or
refused, and a supplied install must produce **zero** lines in it -- with a
control in the same process that does produce one.

**What that zero is worth (F1).** The hook sees seven CPython socket audit
events in this interpreter. `ctypes`/FFI, child processes, `bash`'s `/dev/tcp`
and AF_UNIX escape it, and `tests/test_network_guard_coverage.py` measures
three of them reaching a real listener while the log stays empty. So a zero
here means "the supplied install raised none of those seven events", which is
the right measurement for this path -- it is Python, it calls no converter and
spawns no child -- and it is not, by itself, proof that no socket was used.
What excludes the rest is the namespace the suite runs in: `unshare -cn`, and
for the standalone evidence run `lo` DOWN with no routes.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.errors import AgreementRequired, CoverageRefused
from kilix_license.receipts import receipt_from_agreement

import network_guard
from fake_store import FakeStore
from first_use_fixture import (
    archive_members,
    make_archive_asset,
    make_convert_asset,
    make_files_asset,
    sha256_bytes,
    vosk_fixture_zip,
)
from kilix_content.first_use import (
    install_with_agreement,
    license_record_for,
    present_asset,
)
from kilix_content.install import InstallError, Installer, SuppliedFile
from kilix_content.model import AssetSpec
from kilix_content.receipt import _CATALOG_SHA256, release_digest

# Upstream URLs that exist in the record and are never contacted. A supplied
# install must not reach them; if it tried, the audit assertions below would
# see the name lookup.
HOST = "https://models.example.test"


class SuppliedInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-supplied-"))
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.records = load_determined_records()
        self.texts = load_determined_texts(self.scratch / "texts")
        self.record = self.records.by_id("small-en-us")
        self.notice = self.texts.get(self.record.text_sha256)
        self.store = FakeStore(self.scratch / "receipts")
        self.installer = Installer(str(self.scratch / "root"))
        self.audit = self.scratch / "network-audit.log"

    # ---- fixtures ---------------------------------------------------------

    def files_asset(
        self, asset_id: str = "supplied-files", marker: bytes = b""
    ) -> tuple[AssetSpec, dict]:
        payloads = {
            "model.bin": b"weights-are-fixture-bytes" + marker,
            "config.json": b"{}\n",
        }
        mapping = make_files_asset(
            asset_id=asset_id,
            files={
                path: (f"{HOST}/{path}", payload)
                for path, payload in payloads.items()
            },
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        return AssetSpec.from_mapping(mapping), payloads

    def archive_asset(self) -> tuple[AssetSpec, dict]:
        archive = vosk_fixture_zip()
        mapping = make_archive_asset(
            asset_id="supplied-archive",
            url=f"{HOST}/model.zip",
            archive=archive,
            root="vosk-model-small-en-us-0.15",
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        import zipfile

        payloads = {}
        prefix = "vosk-model-small-en-us-0.15/"
        with zipfile.ZipFile(io.BytesIO(archive)) as opened:
            for info in opened.infolist():
                if info.is_dir():
                    continue
                payloads[info.filename[len(prefix):]] = opened.read(info)
        self.assertEqual(
            sorted(payloads), sorted(item["path"] for item in archive_members(archive, "vosk-model-small-en-us-0.15"))
        )
        return AssetSpec.from_mapping(mapping), payloads

    def convert_asset(self) -> tuple[AssetSpec, dict]:
        payloads = {"model.safetensors": b"input-bytes", "graph.onnx": b"output-bytes"}
        mapping = make_convert_asset(
            asset_id="supplied-convert",
            input_path="model.safetensors",
            files={
                path: (f"{HOST}/{path}", payload)
                for path, payload in payloads.items()
            },
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
            argv=["/nonexistent/converter", "{input}", "{output}"],
            notice_path="notices/LICENSE-apache-2.0.txt",
            license_id="apache-2.0",
        )
        return AssetSpec.from_mapping(mapping), payloads

    def registry_asset(self) -> tuple[AssetSpec, dict]:
        blob = b"registry-blob-bytes"
        manifest = b'{"blobs":["model.bin"]}'
        mapping = {
            "compatibility": {
                "consumer_schema": "kilix.speech.models/v1",
                "maximum": 1,
                "minimum": 1,
            },
            "files": [
                {"bytes": len(blob), "path": "model.bin", "sha256": sha256_bytes(blob)},
                {
                    "bytes": len(self.notice),
                    "path": "notices/LICENSE-apache-2.0.txt",
                    "sha256": sha256_bytes(self.notice),
                },
            ],
            "id": "supplied-registry",
            "label": "registry",
            "licenses": [
                {
                    "decision": self.record.decision_class,
                    "id": "apache-2.0",
                    "licensors": ["Alpha Cephei Inc."],
                    "record_digest": self.record.digest,
                    "text_sha256": self.record.text_sha256,
                }
            ],
            "provider": "kilix-voice",
            "schema": "kilix.content.asset/v3",
            "sizes": {
                "download_bytes": len(manifest),
                "installed_bytes": len(blob) + len(self.notice),
                "temporary_bytes": len(manifest) + len(blob) + len(self.notice),
            },
            "source": {
                "blobs": [{"path": "model.bin", "url": f"{HOST}/blob"}],
                "manifest_sha256": sha256_bytes(manifest),
                "manifest_url": f"{HOST}/manifest.json",
                "mode": "registry-manifest",
                "provenance": {
                    "original_url": f"{HOST}/manifest.json",
                    "project": "example/registry",
                    "revision": "1",
                },
            },
            "stream": "F104",
            "version": "1",
        }
        return AssetSpec.from_mapping(mapping), {"model.bin": blob}

    def supply(self, name: str, payloads: dict[str, bytes]) -> Path:
        root = self.scratch / "supplied" / name
        root.mkdir(parents=True, exist_ok=True)
        for path, payload in payloads.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return root

    def authorize(self, spec: AssetSpec) -> None:
        agreement = capture_agreement(self.record, typed_agreement_line(self.record))
        self.store.write(
            receipt_from_agreement(
                self.record,
                agreement,
                manifest_digest=spec.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        )

    # ---- the zero-network proof -------------------------------------------

    def audited(self, call) -> list[str]:
        """Run `call` with every socket event this process makes recorded."""
        self.assertTrue(
            network_guard.installed(), "the audit hook is not installed"
        )
        previous = os.environ.get(network_guard.AUDIT_LOG_ENV)
        os.environ[network_guard.AUDIT_LOG_ENV] = str(self.audit)
        before = self.audit.read_text() if self.audit.exists() else ""
        try:
            call()
        finally:
            if previous is None:
                os.environ.pop(network_guard.AUDIT_LOG_ENV, None)
            else:
                os.environ[network_guard.AUDIT_LOG_ENV] = previous
        after = self.audit.read_text() if self.audit.exists() else ""
        self.assertTrue(after.startswith(before))
        return [line for line in after[len(before):].splitlines() if line]

    def test_a_supplied_install_makes_no_network_request_at_all(self) -> None:
        """Zero hooked socket events, not merely zero fetches -- with a control.

        The audit hook logs allowed loopback events as well as refused ones, so
        an empty log is the absence of every name lookup, connect and datagram
        **that reaches those seven CPython audit events** -- not the absence of
        every socket operation a process could perform. Named limits, measured
        in `tests/test_network_guard_coverage.py`: `ctypes`/FFI, child
        processes, `bash` `/dev/tcp` and AF_UNIX raise none of them. This path
        uses none of those -- no `ctypes`, no `subprocess`, no AF_UNIX -- which
        is why the measurement is the right one for it, and the namespace is
        what excludes the rest.

        The control below runs through the same hook, in the same process,
        under the same log, and does produce a line: so the emptiness above is
        evidence about the install, not about a hook that was not listening.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("files", payloads)
        self.authorize(spec)
        events = self.audited(
            lambda: self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        )
        self.assertEqual(events, [], events)

        control = self.audited(self._loopback_attempt)
        self.assertNotEqual(control, [])
        self.assertTrue(any("socket.connect" in line for line in control), control)

        root = Path(self.installer.asset_destination(spec))
        self.assertEqual((root / "model.bin").read_bytes(), payloads["model.bin"])
        self.assertEqual(
            (root / "notices/LICENSE-apache-2.0.txt").read_bytes(), self.notice
        )

    @staticmethod
    def _loopback_attempt() -> None:
        handle = socket.socket()
        handle.settimeout(0.5)
        try:
            # Port 9 (discard) is closed here; the connect attempt is the
            # event, its outcome is irrelevant.
            handle.connect(("127.0.0.1", 9))
        except OSError:
            pass
        finally:
            handle.close()

    def test_the_whole_first_use_flow_is_silent_on_the_network(self) -> None:
        """The screen, the agreement, the receipt and the install together."""
        spec, payloads = self.files_asset("supplied-first-use")
        supplied = self.supply("first-use", payloads)
        screen = io.BytesIO()
        events = self.audited(
            lambda: install_with_agreement(
                spec,
                installer=self.installer,
                store=self.store,
                records=self.records,
                texts=self.texts,
                typed_text=typed_agreement_line(self.record),
                screen=screen,
                supplied=supplied,
            )
        )
        self.assertEqual(events, [], events)
        self.assertEqual(len(list(self.store.root.glob("*.json"))), 1)
        self.assertIn(b"Alpha Cephei Inc.", screen.getvalue())
        self.assertIn(str(supplied).encode(), screen.getvalue())
        self.assertIn(b"download: none", screen.getvalue())

    # ---- every mode, one manifest -----------------------------------------

    def test_every_source_mode_can_be_supplied(self) -> None:
        """The manifest, not the mode, decides the installed tree at v3."""
        cases = {
            "upstream-files": self.files_asset,
            "upstream-archive": self.archive_asset,
            "upstream-convert": self.convert_asset,
            "registry-manifest": self.registry_asset,
        }
        self.assertEqual(sorted(cases), sorted(_SOURCE_MODES))
        for mode, build in cases.items():
            with self.subTest(mode=mode):
                spec, payloads = build()
                self.assertEqual(spec.source_mode, mode)
                supplied = self.supply(mode, payloads)
                self.authorize(spec)
                events = self.audited(
                    lambda: self.installer.ensure_supplied_asset(
                        spec,
                        supplied=supplied,
                        store=self.store,
                        records=self.records,
                        notices=self.texts,
                    )
                )
                self.assertEqual(events, [], events)
                root = Path(self.installer.asset_destination(spec))
                installed = sorted(
                    str(path.relative_to(root))
                    for path in root.rglob("*")
                    if path.is_file()
                )
                self.assertEqual(
                    installed, sorted(item.path for item in spec.files)
                )

    # ---- the licence discipline -------------------------------------------

    def test_supplied_bytes_without_a_receipt_install_nothing(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("unlicensed", payloads)
        with self.assertRaises(CoverageRefused):
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_a_receipt_for_another_manifest_does_not_cover_supplied_bytes(self) -> None:
        spec, payloads = self.files_asset()
        # A different manifest, not merely a different id: `manifest_digest`
        # is over `files` alone, so two ids with one file list share it.
        other, _ = self.files_asset("supplied-other", marker=b"-other")
        self.assertNotEqual(spec.manifest_digest, other.manifest_digest)
        self.authorize(other)
        supplied = self.supply("wrong-receipt", payloads)
        with self.assertRaises(CoverageRefused):
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_declining_the_screen_supplies_nothing(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("declined", payloads)
        screen = io.BytesIO()
        result = install_with_agreement(
            spec,
            installer=self.installer,
            store=self.store,
            records=self.records,
            texts=self.texts,
            typed_text=None,
            screen=screen,
            decline=True,
            supplied=supplied,
        )
        self.assertIsNone(result)
        self.assertEqual(list(self.store.root.glob("*.json")), [])
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())
        self.assertIn(str(supplied).encode(), screen.getvalue())

    def test_a_wrong_typed_line_supplies_nothing(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("wrong-line", payloads)
        with self.assertRaises(AgreementRequired):
            install_with_agreement(
                spec,
                installer=self.installer,
                store=self.store,
                records=self.records,
                texts=self.texts,
                typed_text=typed_agreement_line(self.record) + "!",
                screen=io.BytesIO(),
                supplied=supplied,
            )
        self.assertEqual(list(self.store.root.glob("*.json")), [])
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_the_notice_comes_from_the_authority_not_the_supplied_directory(self) -> None:
        """A supplier cannot substitute the licence text it agreed to."""
        spec, payloads = self.files_asset()
        supplied = self.supply(
            "forged-notice",
            {**payloads, "notices/LICENSE-apache-2.0.txt": b"not the licence"},
        )
        self.authorize(spec)
        self.installer.ensure_supplied_asset(
            spec,
            supplied=supplied,
            store=self.store,
            records=self.records,
            notices=self.texts,
        )
        installed = Path(
            self.installer.asset_destination(spec), "notices/LICENSE-apache-2.0.txt"
        )
        self.assertEqual(installed.read_bytes(), self.notice)
        self.assertNotEqual(installed.read_bytes(), b"not the licence")

    # ---- the three receipt checks, one test each (F3) ----------------------

    def revoke(self) -> None:
        """Remove every receipt, as a revocation or a cleared store would.

        `ReceiptStore.lookup` reads the store from disk on every call and
        caches nothing, so this is a real mid-install revocation and not a
        simulated one.
        """
        for path in self.store.root.glob("*.json"):
            path.unlink()
        self.assertEqual(list(self.store.root.glob("*.json")), [])

    def test_the_receipt_is_required_before_anything_is_staged(self) -> None:
        """Check 1 of 3, bound: refused before the lock is even taken.

        "A covering receipt is required three times" was prose no test held:
        each of the three calls could be deleted on its own with the whole
        suite green, because the other two still refused
        (C-V3-EXTEND-VERIFY F3, and the first call too -- the verifier tried
        only the last two). These three tests distinguish *which* check
        refused, by what had already happened when it did.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("check-one", payloads)
        parents: list[str] = []
        original = Installer._ensure_asset_parent

        def watched(installer, asset):
            parents.append(asset.asset_id)
            return original(installer, asset)

        try:
            Installer._ensure_asset_parent = watched
            with self.assertRaises(CoverageRefused):
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        finally:
            Installer._ensure_asset_parent = original
        # Nothing was prepared: the refusal is the first check, not the second.
        self.assertEqual(parents, [])
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_the_receipt_is_required_again_under_the_lock(self) -> None:
        """Check 2 of 3, bound: revoked after check 1, nothing is staged.

        This is the case the repeat exists for -- a receipt removed while an
        install is in flight -- and it is where the second check is the only
        one that can see it: the first has already passed, and the third runs
        after the bytes have been read.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("check-two", payloads)
        self.authorize(spec)
        staged: list[str] = []
        parent = Installer._ensure_asset_parent
        populate = Installer._populate_supplied_asset

        def revoke_between_the_first_and_second_check(installer, asset):
            result = parent(installer, asset)
            self.revoke()
            return result

        def watched(installer, *args, **kwargs):
            staged.append(args[0].asset_id)
            return populate(installer, *args, **kwargs)

        try:
            Installer._ensure_asset_parent = revoke_between_the_first_and_second_check
            Installer._populate_supplied_asset = watched
            with self.assertRaises(CoverageRefused):
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        finally:
            Installer._ensure_asset_parent = parent
            Installer._populate_supplied_asset = populate
        # Not one supplied byte was read: the refusal is under the lock.
        self.assertEqual(staged, [])
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_the_receipt_is_required_again_after_the_tree_is_verified(self) -> None:
        """Check 3 of 3, bound: revoked during staging, nothing is selected.

        The staged tree is complete and matches the manifest; only the third
        check stands between it and the installed path. Without it the asset
        is published under a receipt that no longer exists.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("check-three", payloads)
        self.authorize(spec)
        populate = Installer._populate_supplied_asset

        def revoke_after_staging(installer, *args, **kwargs):
            output = populate(installer, *args, **kwargs)
            self.revoke()
            return output

        try:
            Installer._populate_supplied_asset = revoke_after_staging
            with self.assertRaises(CoverageRefused):
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        finally:
            Installer._populate_supplied_asset = populate
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    # ---- the manifest check -----------------------------------------------

    def test_one_wrong_byte_is_refused_and_nothing_is_installed(self) -> None:
        spec, payloads = self.files_asset()
        broken = dict(payloads)
        broken["model.bin"] = payloads["model.bin"][:-1] + b"X"
        supplied = self.supply("wrong-byte", broken)
        self.authorize(spec)
        with self.assertRaises(InstallError) as raised:
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertIn("does not match the manifest", str(raised.exception))
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_a_missing_file_is_refused(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("missing", {"model.bin": payloads["model.bin"]})
        self.authorize(spec)
        with self.assertRaises(InstallError) as raised:
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertIn("could not open supplied file", str(raised.exception))
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_a_missing_directory_is_refused(self) -> None:
        spec, _ = self.files_asset()
        self.authorize(spec)
        with self.assertRaises(InstallError) as raised:
            self.installer.ensure_supplied_asset(
                spec,
                supplied=self.scratch / "nowhere",
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertIn("supplied directory does not exist", str(raised.exception))

    def test_an_extra_file_beside_the_manifest_is_never_installed(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("extra", {**payloads, "extra.bin": b"not in the manifest"})
        self.authorize(spec)
        selected = self.installer.ensure_supplied_asset(
            spec,
            supplied=supplied,
            store=self.store,
            records=self.records,
            notices=self.texts,
        )
        root = Path(selected[0])
        self.assertFalse((root / "extra.bin").exists())
        self.assertEqual(
            sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()),
            sorted(item.path for item in spec.files),
        )

    def test_a_staged_tree_that_does_not_match_the_manifest_reaches_nothing(self) -> None:
        """F4: the staged-tree check, bound on the supplied path at last.

        `_verify_asset_directory`'s refusal made a no-op survives every other
        test in this module; it was killed only by a pre-existing download
        test, while this module's report listed it as discipline the supplied
        install *gets*. So the defect is planted where it decides the outcome:
        the staged copy is corrupted **after** it is written, so the supplied
        file's own descriptor still revalidates and the per-file check still
        passes. Only the staged-tree check can see it, and nothing may reach
        the installed path.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("staged-corrupt", payloads)
        self.authorize(spec)
        original = SuppliedFile.copy_to

        def copy_then_corrupt_the_stage(handle, target):
            original(handle, target)
            if target.endswith("model.bin"):
                # The stage, not the source: same size, different bytes.
                with open(target, "r+b") as writer:
                    writer.write(b"X" * min(8, handle.bytes))

        try:
            SuppliedFile.copy_to = copy_then_corrupt_the_stage
            with self.assertRaises(InstallError) as raised:
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        finally:
            SuppliedFile.copy_to = original
        self.assertIn(
            "staged asset tree does not match its manifest", str(raised.exception)
        )
        destination = Path(self.installer.asset_destination(spec))
        self.assertFalse(destination.exists())
        self.assertFalse(destination.is_symlink())

    def test_a_refusal_after_publication_leaves_nothing_installed(self) -> None:
        """F4, the other half: the last refusal must withdraw what it refuses.

        With the staged-tree check a no-op the corrupt tree was published at
        the installed path and only the final verification refused -- after
        the bytes had moved, and leaving them there. That is the shape
        C-MIGRATE-KILIX-VERIFY V3 recorded for kilix, reproduced here on the
        supplied path.

        The no-op is planted deliberately below, on the *staged* tree only, so
        the final verification stays real. The property being held is not "the
        first guard catches it" -- it is "a refusal leaves nothing behind",
        which must be true however the install got there.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("published-then-refused", payloads)
        self.authorize(spec)
        destination = Path(self.installer.asset_destination(spec))
        copy = SuppliedFile.copy_to
        verify = Installer._verify_asset_directory

        def copy_then_corrupt_the_stage(handle, target):
            copy(handle, target)
            if target.endswith("model.bin"):
                with open(target, "r+b") as writer:
                    writer.write(b"X" * min(8, handle.bytes))

        def accept_any_staged_tree(installer, asset, directory):
            if Path(directory) == destination:
                return verify(installer, asset, directory)   # the final check is real
            return directory                                 # the staged check is a no-op

        try:
            SuppliedFile.copy_to = copy_then_corrupt_the_stage
            Installer._verify_asset_directory = accept_any_staged_tree
            with self.assertRaises(InstallError) as raised:
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        finally:
            SuppliedFile.copy_to = copy
            Installer._verify_asset_directory = verify
        # It really did get past the staged-tree check and reach publication:
        # this is the *final* refusal, not the earlier one.
        self.assertIn(
            "installed asset failed final verification", str(raised.exception)
        )
        self.assertFalse(destination.exists())
        self.assertFalse(destination.is_symlink())
        self.assertEqual(
            [path.name for path in destination.parent.iterdir()
             if not path.name.startswith(".")],
            [],
        )

    def test_a_symlinked_supplied_file_is_refused(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("symlink", {"config.json": payloads["config.json"]})
        real = self.scratch / "elsewhere.bin"
        real.write_bytes(payloads["model.bin"])
        (supplied / "model.bin").symlink_to(real)
        self.authorize(spec)
        with self.assertRaises(InstallError) as raised:
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertIn("could not open supplied file", str(raised.exception))
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_a_fifo_is_refused_without_blocking(self) -> None:
        spec, payloads = self.files_asset()
        supplied = self.supply("fifo", {"config.json": payloads["config.json"]})
        os.mkfifo(supplied / "model.bin")
        self.authorize(spec)
        with self.assertRaises(InstallError) as raised:
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertIn("not a regular file", str(raised.exception))

    # ---- no symlink below the supplied root (F6) ---------------------------

    def nested_asset(self) -> tuple[AssetSpec, dict]:
        payloads = {
            "weights/model.bin": b"nested-weights-are-fixture-bytes",
            "config.json": b"{}\n",
        }
        mapping = make_files_asset(
            asset_id="supplied-nested",
            files={
                name: (f"{HOST}/{name}", payload)
                for name, payload in payloads.items()
            },
            license_record=self.record,
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        return AssetSpec.from_mapping(mapping), payloads

    def test_a_symlinked_directory_below_the_supplied_root_is_refused(self) -> None:
        """F6: the boundary holds at every depth, not only at the leaf.

        The bytes behind the symlink are the **right** ones -- the digest would
        pass -- so the only thing that can refuse this is the walk. Then the
        same bytes in a real directory install, so the refusal is about the
        symlink and nothing else.
        """
        spec, payloads = self.nested_asset()
        supplied = self.supply("nested", {"config.json": payloads["config.json"]})
        outside = self.scratch / "outside-the-supplied-directory"
        outside.mkdir()
        (outside / "model.bin").write_bytes(payloads["weights/model.bin"])
        (supplied / "weights").symlink_to(outside, target_is_directory=True)
        self.authorize(spec)
        with self.assertRaises(InstallError) as raised:
            self.installer.ensure_supplied_asset(
                spec,
                supplied=supplied,
                store=self.store,
                records=self.records,
                notices=self.texts,
            )
        self.assertIn("could not open supplied file", str(raised.exception))
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

        (supplied / "weights").unlink()
        (supplied / "weights").mkdir()
        (supplied / "weights" / "model.bin").write_bytes(payloads["weights/model.bin"])
        self.installer.ensure_supplied_asset(
            spec,
            supplied=supplied,
            store=self.store,
            records=self.records,
            notices=self.texts,
        )
        root = Path(self.installer.asset_destination(spec))
        self.assertEqual(
            (root / "weights" / "model.bin").read_bytes(), payloads["weights/model.bin"]
        )

    def test_the_nominated_root_itself_may_be_a_symlink(self) -> None:
        """The operator nominated the root; only what is BELOW it is walked."""
        spec, payloads = self.nested_asset()
        real = self.supply("nested-real", payloads)
        link = self.scratch / "nominated-through-a-link"
        link.symlink_to(real, target_is_directory=True)
        self.authorize(spec)
        self.installer.ensure_supplied_asset(
            spec,
            supplied=link,
            store=self.store,
            records=self.records,
            notices=self.texts,
        )
        root = Path(self.installer.asset_destination(spec))
        self.assertEqual((root / "config.json").read_bytes(), payloads["config.json"])

    def test_open_beneath_refuses_a_path_that_is_not_plainly_below_the_root(self) -> None:
        root = self.supply("plain", {"a/b.bin": b"bytes"})
        (self.scratch / "supplied" / "sibling.bin").write_bytes(b"bytes")
        for relative in ("../sibling.bin", "a/../a/b.bin", "/etc/hostname", "a//b.bin", "", "a/"):
            with self.subTest(relative=relative):
                with self.assertRaises(InstallError):
                    SuppliedFile.open_beneath(root, relative)
        with SuppliedFile.open_beneath(root, "a/b.bin") as handle:
            self.assertEqual(handle.sha256, sha256_bytes(b"bytes"))
            self.assertEqual(handle.path, os.path.join(str(root), "a/b.bin"))

    def test_open_beneath_refuses_a_symlinked_leaf_and_open_does_not_walk(self) -> None:
        """The two entry points are different guards, and the tests say which."""
        root = self.supply("leafs", {"real/file.bin": b"bytes"})
        (root / "leaf.bin").symlink_to(root / "real" / "file.bin")
        (root / "via").symlink_to(root / "real", target_is_directory=True)
        with self.assertRaises(InstallError):
            SuppliedFile.open_beneath(root, "leaf.bin")
        with self.assertRaises(InstallError):
            SuppliedFile.open_beneath(root, "via/file.bin")
        # `open` guards the leaf only: the directory symlink above it is followed.
        with self.assertRaises(InstallError):
            SuppliedFile.open(root / "leaf.bin")
        with SuppliedFile.open(root / "via" / "file.bin") as handle:
            self.assertEqual(handle.sha256, sha256_bytes(b"bytes"))

    # ---- the supplied path on the consent screen (F5) ---------------------

    def screen_for(self, spec: AssetSpec, supplied) -> bytes:
        return present_asset(
            spec,
            license_record_for(spec, self.records),
            self.texts,
            receipts=self.store,
            records=self.records,
            supplied=supplied,
        )

    def test_a_supplied_path_with_a_terminal_control_is_refused_before_the_screen(
        self,
    ) -> None:
        """F5: nothing is written to the screen, no receipt, nothing installed.

        CR overwrites what the reader just read; ESC and CSI (C1 U+009B) repaint
        it; LF and TAB forge a header line. `\r\n` is refused, not normalised
        into a second header: the path check runs before OD-BT's CRLF
        normalisation ever sees the screen.
        """
        spec, _payloads = self.files_asset()
        for control in ("\r", "\r\n", "\n", "\t", "\x00", "\x1b[2J", "\x7f", "\x85", "\x9b"):
            with self.subTest(control=control):
                supplied = str(self.scratch / f"sup{control}plied")
                screen = io.BytesIO()
                with self.assertRaises(InstallError) as raised:
                    install_with_agreement(
                        spec,
                        installer=self.installer,
                        store=self.store,
                        records=self.records,
                        texts=self.texts,
                        typed_text=typed_agreement_line(self.record),
                        screen=screen,
                        supplied=supplied,
                    )
                self.assertEqual(screen.getvalue(), b"")
                self.assertEqual(list(self.store.root.glob("*.json")), [])
                self.assertFalse(Path(self.installer.asset_destination(spec)).exists())
                message = str(raised.exception)
                self.assertIn("terminal control", message)
                self.assertIn(repr(os.path.abspath(supplied)), message)
                for char in control:
                    if ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0:
                        self.assertNotIn(char, message)

    def test_exactly_c0_del_and_c1_are_refused_in_the_supplied_path(self) -> None:
        """Every code point below U+00A0, decided one by one, plus the neighbours."""
        spec, _payloads = self.files_asset()
        for point in range(0x00, 0xA2):
            char = chr(point)
            supplied = f"/supplied/a{char}b"
            refused = point < 0x20 or 0x7F <= point < 0xA0
            with self.subTest(code_point=f"U+{point:04X}"):
                if refused:
                    with self.assertRaises(InstallError):
                        self.screen_for(spec, supplied)
                else:
                    screen = self.screen_for(spec, supplied)
                    self.assertIn(f"supplied: {supplied}\n".encode("utf-8"), screen)
        screen = self.screen_for(spec, "/supplied/caf\u00e9-\u4e2d")
        self.assertIn("supplied: /supplied/caf\u00e9-\u4e2d\n".encode("utf-8"), screen)

    # ---- the held descriptor ----------------------------------------------

    def test_a_file_rewritten_in_place_after_the_check_is_refused(self) -> None:
        """The F100 property: verification and use are the same descriptor."""
        path = self.scratch / "mutable.bin"
        path.write_bytes(b"first-bytes")
        with SuppliedFile.open(path) as handle:
            self.assertEqual(handle.sha256, sha256_bytes(b"first-bytes"))
            with open(path, "r+b") as writer:      # same inode, same size
                writer.write(b"secXnd-byte")
            with self.assertRaises(InstallError) as raised:
                handle.revalidate()
        self.assertIn("changed after it was opened", str(raised.exception))

    def test_the_path_is_never_reopened_after_the_check(self) -> None:
        """A path swapped for another file cannot change what was copied."""
        path = self.scratch / "swapped.bin"
        path.write_bytes(b"original-bytes")
        target = self.scratch / "copied.bin"
        with SuppliedFile.open(path) as handle:
            replacement = self.scratch / "replacement.bin"
            replacement.write_bytes(b"attacker-bytes")
            os.replace(replacement, path)          # new inode at the same name
            handle.copy_to(str(target))
            handle.revalidate()                    # the held inode is unchanged
        self.assertEqual(target.read_bytes(), b"original-bytes")
        self.assertEqual(path.read_bytes(), b"attacker-bytes")

    def test_an_install_whose_source_changes_under_the_copy_is_refused(self) -> None:
        """The post-copy re-read is load-bearing, through the real install.

        Planted where it actually matters: the file is rewritten in place after
        the staged copy has been taken, so the staged bytes are still the
        correct ones and the staged-tree verification passes. Only the re-read
        of the held descriptor can see it, and the install must refuse.
        """
        spec, payloads = self.files_asset()
        supplied = self.supply("mutating", payloads)
        self.authorize(spec)
        original = SuppliedFile.copy_to

        def copy_then_rewrite(handle, target):
            original(handle, target)
            with open(handle.path, "r+b") as writer:
                writer.write(b"X" * min(4, handle.bytes))

        try:
            SuppliedFile.copy_to = copy_then_rewrite
            with self.assertRaises(InstallError) as raised:
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
        finally:
            SuppliedFile.copy_to = original
        self.assertIn("changed after it was opened", str(raised.exception))
        self.assertFalse(Path(self.installer.asset_destination(spec)).exists())

    def test_a_truncated_file_is_refused(self) -> None:
        path = self.scratch / "truncated.bin"
        path.write_bytes(b"0123456789")
        with SuppliedFile.open(path) as handle:
            os.truncate(path, 4)
            with self.assertRaises(InstallError):
                handle.revalidate()

    # ---- the two paths are one path ---------------------------------------

    def test_the_catalog_still_carries_no_user_supplied_mode(self) -> None:
        """OD-BO restores the capability without reinstating the OD-AR mode.

        `tests/test_c4_encodec_records.py` refuses `user-supplied` anywhere in
        the catalog; this states the other half, that the restored capability
        did not need it. The parser's mode set is the check.
        """
        from kilix_content.model import _ASSET_SOURCE_MODES

        self.assertNotIn("user-supplied", _ASSET_SOURCE_MODES)
        self.assertNotIn("mirrored", _ASSET_SOURCE_MODES)
        catalog = json.loads(
            (Path(__file__).resolve().parents[1]
             / "src/kilix_content/catalog/plebian.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("user-supplied", json.dumps(catalog))

    def test_both_acquisitions_run_the_same_selection_path(self) -> None:
        """Not "the two agree today": they are one method, `_select_asset`.

        A supplied install with a staging path of its own could drift away
        from the licence and manifest discipline the downloading one runs.
        Both public methods delegate to the same one, which is why the receipt
        checks and the manifest verification cannot differ between them. The
        unauthorised upstream call proves the delegation for that path too --
        it refuses inside `_select_asset`, before anything is fetched, so this
        test still makes no network request.
        """
        spec, payloads = self.files_asset()
        self.authorize(spec)
        unauthorised, _ = self.files_asset("supplied-unauthorised", marker=b"-none")
        supplied = self.supply("shared-path", payloads)
        seen: list[str] = []
        original = Installer._select_asset

        def spy(installer, asset, populate, **kwargs):
            seen.append(kwargs["covered_message"])
            return original(installer, asset, populate, **kwargs)

        def both() -> None:
            try:
                Installer._select_asset = spy
                self.installer.ensure_supplied_asset(
                    spec,
                    supplied=supplied,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                )
                with self.assertRaises(CoverageRefused):
                    self.installer.ensure_upstream_asset(
                        unauthorised,
                        store=self.store,
                        records=self.records,
                        notices=self.texts,
                    )
            finally:
                Installer._select_asset = original

        self.assertEqual(self.audited(both), [])
        self.assertEqual(len(seen), 2)
        self.assertEqual(len(set(seen)), 2)


_SOURCE_MODES = (
    "upstream-archive",
    "upstream-convert",
    "upstream-files",
    "registry-manifest",
)


if __name__ == "__main__":
    unittest.main()
