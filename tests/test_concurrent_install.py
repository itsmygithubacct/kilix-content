from __future__ import annotations

import hashlib
import json
import os
import signal
import tempfile
import time
import unittest
from multiprocessing import Queue, get_context
from pathlib import Path

from kilix_license.agreement import capture_agreement, typed_agreement_line
from kilix_license.catalog import load_determined_records, load_determined_texts
from kilix_license.receipts import receipt_from_agreement

from fake_store import FakeStore
from first_use_fixture import FakeUpstream, make_archive_asset, vosk_fixture_zip
from kilix_content.install import Installer
from kilix_content.model import AssetSpec
from kilix_content.receipt import _CATALOG_SHA256, release_digest


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _child_install(
    root: str,
    receipts: str,
    texts: str,
    mapping: dict,
    queue: Queue,
    delay: float,
) -> None:
    os.environ.setdefault("SSL_CERT_FILE", os.environ.get("SSL_CERT_FILE", ""))
    time.sleep(delay)
    records = load_determined_records()
    store = FakeStore(receipts)
    notice_store = load_determined_texts(texts)
    installer = Installer(root)
    spec = AssetSpec.from_mapping(mapping)
    other: list[bool] = []
    installer.ensure_upstream_asset(
        spec,
        store=store,
        records=records,
        notices=notice_store,
        installed_by_other=other,
    )
    queue.put(bool(other))


class ConcurrentInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="kilix-content-concurrent-"))
        self.upstream = FakeUpstream()
        self.records = load_determined_records()
        self.texts = load_determined_texts(self.scratch / "texts")
        self.notice = self.texts.get(self.records.by_id("small-en-us").text_sha256)
        self.store = FakeStore(self.scratch / "receipts")
        self.archive = vosk_fixture_zip()
        self.url = self.upstream.add("/model.zip", self.archive)
        mapping = make_archive_asset(
            asset_id="fixture-concurrent",
            url=self.url,
            archive=self.archive,
            root="vosk-model-small-en-us-0.15",
            license_record=self.records.by_id("small-en-us"),
            notice=self.notice,
            licensors=["Alpha Cephei Inc."],
        )
        self.spec = AssetSpec.from_mapping(mapping)
        agreement = capture_agreement(
            self.records.by_id("small-en-us"),
            typed_agreement_line(self.records.by_id("small-en-us")),
        )
        self.store.write(
            receipt_from_agreement(
                self.records.by_id("small-en-us"),
                agreement,
                manifest_digest=self.spec.manifest_digest,
                release_digest=release_digest(),
                catalogue_digest=_CATALOG_SHA256,
            )
        )
        self.mapping = self.spec.to_mapping()

    def tearDown(self) -> None:
        self.upstream.close()

    def test_two_processes_one_get_sequence(self) -> None:
        ctx = get_context("spawn")
        queue: Queue = ctx.Queue()
        root = str(self.scratch / "root")
        receipts = str(self.store.root)
        texts = str(self.texts.root)
        first = ctx.Process(
            target=_child_install,
            args=(root, receipts, texts, self.mapping, queue, 0.0),
        )
        second = ctx.Process(
            target=_child_install,
            args=(root, receipts, texts, self.mapping, queue, 0.05),
        )
        first.start()
        second.start()
        first.join(timeout=30)
        second.join(timeout=30)
        self.assertEqual(first.exitcode, 0)
        self.assertEqual(second.exitcode, 0)
        gets = [
            item
            for item in self.upstream.requests()
            if item.get("command") == "GET" and item.get("path") == "/model.zip"
        ]
        self.assertEqual(len(gets), 1)
        flags = [queue.get(timeout=1), queue.get(timeout=1)]
        self.assertTrue(any(flags))

    def test_waiter_cancel(self) -> None:
        installer = Installer(str(self.scratch / "root-cancel"))
        cancelled = {"flag": False}

        def flag() -> bool:
            return cancelled["flag"]

        def run() -> None:
            try:
                installer.ensure_upstream_asset(
                    self.spec,
                    store=self.store,
                    records=self.records,
                    notices=self.texts,
                    cancelled=flag,
                    deadline=time.monotonic() + 5,
                )
            except Exception:
                pass

        holder = get_context("spawn").Process(
            target=_child_install,
            args=(
                str(self.scratch / "root-cancel"),
                str(self.store.root),
                str(self.texts.root),
                self.mapping,
                get_context("spawn").Queue(),
                0.0,
            ),
        )
        # A local cancel without a holder still returns promptly.
        start = time.monotonic()
        cancelled["flag"] = True
        from kilix_content.fetch import DownloadError

        with self.assertRaises(DownloadError):
            installer.ensure_upstream_asset(
                self.spec,
                store=self.store,
                records=self.records,
                notices=self.texts,
                cancelled=lambda: True,
            )
        self.assertLess(time.monotonic() - start, 1.0)
        if holder.pid is not None:
            holder.terminate()
            holder.join(timeout=1)
