"""Offline archive transactions with real files, receipts and installed FDs."""

from contextlib import ExitStack, contextmanager
from dataclasses import replace
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from kilix_content import (
    AssetSpec,
    InstallError,
    Installer,
    LicenseDecision,
    ReceiptStore,
    ReleaseContext,
)
from kilix_content import local_archive
from kilix_content.receipt import ReceiptError, VerifiedInput
from tests.test_packaged_authority import (
    canonical,
    mock_packaged_bytes,
    PACKAGED_CATALOG,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def fixture(mode="mirrored", members=None, authorize=True, prefix=b"", suffix=b""):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        payloads = {
            "model/weights.bin": b"exact fixture weights\n" * 11,
            "notices/LICENSE": b"Synthetic fixture license, no real grant.\n",
        }
        output = io.BytesIO()
        with tarfile.open(
            fileobj=output, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            for name, data, kind, mode_bits in members or [
                (name, data, tarfile.REGTYPE, 0o644) for name, data in payloads.items()
            ]:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = mode_bits
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                    member.linkname = "../../outside"
                archive.addfile(
                    member, io.BytesIO(data) if kind == tarfile.REGTYPE else None
                )
        blob = prefix + output.getvalue() + suffix
        path = root / "input.tar"
        path.write_bytes(blob)
        path.chmod(0o600)
        raw = json.loads(
            (
                Path(__file__).parent / "fixtures/contracts/valid/asset-mirrored.json"
            ).read_bytes()
        )
        raw["files"] = [
            {"path": name, "bytes": len(data), "sha256": sha(data)}
            for name, data in payloads.items()
        ]
        raw["sizes"].update(
            download_bytes=len(blob),
            installed_bytes=sum(map(len, payloads.values())),
            temporary_bytes=len(blob) + sum(map(len, payloads.values())),
        )
        raw["source"]["archive_sha256"] = sha(blob)
        raw["licenses"][0].update(
            text_sha256=sha(payloads["notices/LICENSE"]), decision="informational"
        )
        raw["compatibility"]["maximum"] = 4
        if mode == "multipart-mirrored":
            raw["schema"] = "kilix.content.asset/v2"
            raw["source"].pop("mirrors")
            raw["source"].update(
                mode=mode,
                parts=[
                    {
                        "bytes": len(part),
                        "sha256": sha(part),
                        "mirrors": ["https://example.invalid/part"],
                    }
                    for part in (blob[:5120], blob[5120:])
                ],
            )
        elif mode == "user-supplied":
            raw["source"] = {
                "mode": mode,
                "input_bytes": len(blob),
                "input_sha256": sha(blob),
                "official_url": "https://example.invalid/input",
                "reason": "fixture only",
                "provenance": raw["source"]["provenance"],
            }
            raw["licenses"][0]["decision"] = "user-supplied"
        spec = AssetSpec.from_mapping(raw)
        catalog = json.loads(PACKAGED_CATALOG.read_bytes())
        catalog["assets"] = [spec.to_mapping()]
        catalog_bytes = canonical(catalog)
        stack.enter_context(
            mock_packaged_bytes(catalog_bytes, digest=sha(catalog_bytes))
        )
        release = ReleaseContext.packaged()
        store = stack.enter_context(
            ReceiptStore.open_default({"XDG_STATE_HOME": str(root / "state")})
        )
        if authorize:
            decision = {
                "schema": "kilix.install.license/v1",
                "kind": "decision",
                "artifact_ids": [spec.asset_id],
                "decision_class": spec.licenses[0].decision,
                "license_id": spec.licenses[0].license_id,
                "license_text_sha256": spec.licenses[0].text_sha256,
                "outcome": "supply" if mode == "user-supplied" else "record",
                "presenter": "kilix-installer",
                "release": release.release_id,
            }
            if mode == "user-supplied":
                decision.update(
                    input_sha256=spec.input_sha256, upstream_url=spec.official_url
                )
                verified = stack.enter_context(VerifiedInput.open(path))
            else:
                verified = None
            store.record(
                LicenseDecision.from_mapping(decision),
                payloads["notices/LICENSE"],
                release,
                [spec],
                verified_input=verified,
            )
        installer = Installer(str(root / "data"))
        value = SimpleNamespace(
            root=root,
            path=path,
            blob=blob,
            spec=spec,
            store=store,
            release=release,
            installer=installer,
            payloads=payloads,
        )
        value.destination = Path(installer.asset_destination(spec))
        yield value


class LocalArchiveTests(unittest.TestCase):
    @staticmethod
    def fd_count():
        return len(os.listdir("/proc/self/fd"))

    def import_file(self, value, **kwargs):
        options = dict(maximum_bytes=len(value.blob))
        options.update(kwargs)
        return value.installer.import_asset_archive(
            value.spec, value.store, value.release, value.path, **options
        )

    def assert_refused_clean(self, value, call):
        before = self.fd_count()
        with self.assertRaises((InstallError, ReceiptError)):
            call()
        self.assertEqual(self.fd_count(), before)
        self.assertFalse(value.destination.exists())
        self.assertFalse(list(Path(value.installer.root).glob("*/.asset-import-*")))

    def test_exact_three_source_modes_use_same_receipts_and_readonly_installed_fds(
        self,
    ):
        for mode in ("mirrored", "multipart-mirrored", "user-supplied"):
            with self.subTest(mode=mode), fixture(mode) as value:
                before = self.fd_count()
                with (
                    patch(
                        "kilix_content.install.download",
                        side_effect=AssertionError("network"),
                    ),
                    patch(
                        "kilix_content.install._run_converter",
                        side_effect=AssertionError("converter"),
                    ),
                ):
                    paths = self.import_file(value)
                self.assertEqual(len(paths), 2)
                for path in paths:
                    self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                with value.installer.open_asset(
                    value.spec,
                    value.store,
                    value.release,
                    maximum_bytes=value.spec.installed_bytes,
                ) as asset:
                    for name, expected in value.payloads.items():
                        descriptor = asset.duplicate(name)
                        try:
                            self.assertEqual(
                                os.read(descriptor, len(expected) + 1), expected
                            )
                            self.assertEqual(fcntl.fcntl(descriptor, 1034) & 15, 15)
                        finally:
                            os.close(descriptor)
                self.assertEqual(self.fd_count(), before)
                self.assertEqual(value.path.read_bytes(), value.blob)

    def test_missing_receipt_and_cancel_refuse_before_input_or_staging(self):
        with (
            fixture(authorize=False) as value,
            patch.object(
                local_archive,
                "_copy_archive",
                side_effect=AssertionError("input opened"),
            ),
        ):
            self.assert_refused_clean(value, lambda: self.import_file(value))
            self.assertEqual(list(Path(value.installer.root).iterdir()), [])
        with fixture() as value:
            self.assert_refused_clean(
                value, lambda: self.import_file(value, cancelled=lambda: True)
            )
            self.assertEqual(list(Path(value.installer.root).iterdir()), [])
            for number in (True, -1, 0, 10**1000, float("nan")):
                self.assert_refused_clean(
                    value, lambda: self.import_file(value, timeout=number)
                )

    def test_existing_entries_are_never_replaced(self):
        for kind in ("directory", "file", "fifo", "dangling", "symlink", "hardlink"):
            with self.subTest(kind=kind), fixture() as value:
                value.destination.parent.mkdir(mode=0o700)
                target = value.root / "preserved"
                target.write_bytes(b"preserve bytes")
                if kind == "directory":
                    value.destination.mkdir(mode=0o700)
                elif kind == "file":
                    value.destination.write_bytes(b"existing")
                elif kind == "fifo":
                    os.mkfifo(value.destination)
                elif kind == "dangling":
                    value.destination.symlink_to(value.root / "absent")
                elif kind == "symlink":
                    value.destination.symlink_to(target)
                else:
                    os.link(target, value.destination)
                before = os.lstat(value.destination)
                descriptors = self.fd_count()
                with self.assertRaises(InstallError):
                    self.import_file(value)
                after = os.lstat(value.destination)
                self.assertEqual(
                    (before.st_dev, before.st_ino, before.st_mode),
                    (after.st_dev, after.st_ino, after.st_mode),
                )
                self.assertEqual(target.read_bytes(), b"preserve bytes")
                self.assertEqual(self.fd_count(), descriptors)

    def test_input_type_size_digest_and_link_refusals(self):
        for kind in (
            "fifo",
            "symlink",
            "hardlink",
            "oversize",
            "short",
            "wrong-digest",
        ):
            with self.subTest(kind=kind), fixture() as value:
                value.path.unlink()
                if kind == "fifo":
                    os.mkfifo(value.path, 0o600)
                elif kind in {"symlink", "hardlink"}:
                    other = value.root / "other"
                    other.write_bytes(value.blob)
                    other.chmod(0o600)
                    if kind == "symlink":
                        value.path.symlink_to(other)
                    else:
                        os.link(other, value.path)
                else:
                    data = value.blob + b"x" if kind == "oversize" else value.blob[:-1]
                    if kind == "wrong-digest":
                        data = b"x" + value.blob[1:]
                    value.path.write_bytes(data)
                    value.path.chmod(0o600)
                started = time.monotonic()
                self.assert_refused_clean(value, lambda: self.import_file(value))
                self.assertLess(time.monotonic() - started, 1)

    def test_complete_archive_digest_does_not_excuse_wrong_members(self):
        normal = [
            (
                "model/weights.bin",
                b"exact fixture weights\n" * 11,
                tarfile.REGTYPE,
                0o644,
            ),
            (
                "notices/LICENSE",
                b"Synthetic fixture license, no real grant.\n",
                tarfile.REGTYPE,
                0o644,
            ),
        ]
        cases = [
            normal + [normal[0]],
            normal[:1],
            normal + [("../outside", b"evil", tarfile.REGTYPE, 0o644)],
            normal + [("extra", b"evil", tarfile.REGTYPE, 0o644)],
            [(normal[0][0], b"", tarfile.SYMTYPE, 0o644)] + normal[1:],
            [(normal[0][0], b"x" * len(normal[0][1]), tarfile.REGTYPE, 0o644)]
            + normal[1:],
            [(normal[0][0], normal[0][1], tarfile.REGTYPE, 0o755)] + normal[1:],
        ]
        for members in cases:
            with self.subTest(members=members), fixture(members=members) as value:
                self.assert_refused_clean(value, lambda: self.import_file(value))
                self.assertFalse((value.root / "outside").exists())

    def test_input_mutation_during_copy_refuses(self):
        with fixture() as value:
            actual = os.read
            identity = value.path.stat().st_ino
            changed = []

            def mutate(descriptor, size):
                data = actual(descriptor, size)
                if data and os.fstat(descriptor).st_ino == identity and not changed:
                    writer = os.open(value.path, os.O_WRONLY)
                    try:
                        os.pwrite(writer, b"x", 1)
                    finally:
                        os.close(writer)
                    changed.append(True)
                return data

            with patch.object(os, "read", mutate):
                self.assert_refused_clean(value, lambda: self.import_file(value))
            self.assertEqual(changed, [True])

    def test_cancel_after_copy_cleans_private_archive_and_files(self):
        with fixture() as value:
            copied = []
            actual = local_archive._copy_archive

            def copy(*args):
                descriptor = actual(*args)
                copied.append(True)
                return descriptor

            with patch.object(local_archive, "_copy_archive", copy):
                self.assert_refused_clean(
                    value,
                    lambda: self.import_file(value, cancelled=lambda: bool(copied)),
                )

    def test_real_asset_lock_honors_deadline(self):
        with fixture() as value:
            value.destination.parent.mkdir(mode=0o700)
            token = sha(f"{value.spec.asset_id}\x00{value.spec.version}".encode())
            lock = os.open(
                value.destination.parent / f".install-{token}.lock",
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
                0o600,
            )
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)
                started = time.monotonic()
                self.assert_refused_clean(
                    value, lambda: self.import_file(value, timeout=0.03)
                )
                self.assertLess(time.monotonic() - started, 0.3)
            finally:
                os.close(lock)

    def test_ancestor_replacement_preserves_outside_and_refuses_selection(self):
        with fixture() as value:
            actual = local_archive._extract
            outside = value.root / "outside"
            outside.mkdir(mode=0o700)
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"do not touch")

            def replace_ancestor(*args):
                result = actual(*args)
                Path(value.installer.root).rename(value.root / "old-data")
                Path(value.installer.root).symlink_to(outside)
                return result

            with patch.object(local_archive, "_extract", replace_ancestor):
                self.assert_refused_clean(value, lambda: self.import_file(value))
            self.assertEqual(sentinel.read_bytes(), b"do not touch")
            self.assertEqual(list(outside.iterdir()), [sentinel])
            self.assertFalse(list((value.root / "old-data").glob("*/.asset-import-*")))

    def test_output_mutation_and_extra_member_before_selection_refuse(self):
        for kind in ("mutate", "replace", "extra"):
            with self.subTest(kind=kind), fixture() as value:
                actual = local_archive._extract

                def change(archive, output, spec, check):
                    identities = actual(archive, output, spec, check)
                    path = Path(f"/proc/self/fd/{output}/model/weights.bin")
                    if kind == "replace":
                        path.unlink()
                    if kind == "extra":
                        path = Path(f"/proc/self/fd/{output}/extra")
                    path.write_bytes(b"changed")
                    return identities

                with patch.object(local_archive, "_extract", change):
                    self.assert_refused_clean(value, lambda: self.import_file(value))

    def test_recorded_converter_and_insufficient_budget_do_not_run(self):
        with fixture() as value:
            self.assert_refused_clean(
                value,
                lambda: self.import_file(value, maximum_bytes=len(value.blob) - 1),
            )
            value.spec = replace(value.spec, temporary_bytes=1)
            self.assert_refused_clean(value, lambda: self.import_file(value))
        with fixture("user-supplied") as value:
            value.spec = replace(
                value.spec,
                conversion_tool_asset_id="conversion-tool",
                conversion_argv=("{input}", "{output}"),
            )
            with patch(
                "kilix_content.install._run_converter",
                side_effect=AssertionError("converter"),
            ):
                self.assert_refused_clean(value, lambda: self.import_file(value))

    def test_extended_metadata_refuses_at_first_bounded_header(self):
        metadata = tarfile.TarInfo("metadata")
        metadata.type = tarfile.XGLTYPE
        metadata.mode = 0o644
        empty = metadata.tobuf(format=tarfile.USTAR_FORMAT)
        metadata.size = 2 * 1024 * 1024
        large = metadata.tobuf(format=tarfile.USTAR_FORMAT) + bytes(metadata.size)
        for prefix in (empty * 1200, large):
            with self.subTest(bytes=len(prefix)), fixture(prefix=prefix) as value:
                actual_extract = local_archive._extract
                actual_read = os.pread
                reads = []

                def extract(descriptor, *args):
                    def read(fd, count, offset):
                        if fd == descriptor:
                            reads.append((count, offset))
                        return actual_read(fd, count, offset)

                    with patch.object(local_archive.os, "pread", read):
                        return actual_extract(descriptor, *args)

                with patch.object(local_archive, "_extract", extract):
                    self.assert_refused_clean(value, lambda: self.import_file(value))
                self.assertEqual(reads, [(512, 0)])

    def test_cancellation_after_header_prevents_any_member_read(self):
        with fixture() as value:
            actual_extract = local_archive._extract
            actual_read = os.pread
            reads = []
            cancelled = []

            def extract(descriptor, *args):
                def read(fd, count, offset):
                    result = actual_read(fd, count, offset)
                    if fd == descriptor:
                        reads.append((count, offset))
                        cancelled.append(True)
                    return result

                with patch.object(local_archive.os, "pread", read):
                    return actual_extract(descriptor, *args)

            with patch.object(local_archive, "_extract", extract):
                self.assert_refused_clean(
                    value, lambda: self.import_file(value, cancelled=lambda: bool(cancelled))
                )
            self.assertEqual(reads, [(512, 0)])

    def test_ustar_directories_and_trailing_population_are_checked(self):
        directory = tarfile.TarInfo("model/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        header = directory.tobuf(format=tarfile.USTAR_FORMAT)
        with fixture(prefix=header) as value:
            paths = self.import_file(value)
            self.assertEqual(len(paths), len(value.payloads))
        invalid_checksum = bytearray(header)
        invalid_checksum[0] ^= 1
        for prefix, suffix in ((bytes(invalid_checksum), b""), (b"", b"x" * 512),
                               (b"", b"\0")):
            with self.subTest(prefix=len(prefix), suffix=len(suffix)), fixture(
                    prefix=prefix, suffix=suffix) as value:
                self.assert_refused_clean(value, lambda: self.import_file(value))


if __name__ == "__main__":
    unittest.main()
