"""First-use screen, agreement, receipt, then fetch (R4-052, R4-065)."""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO

from kilix_license.agreement import capture_agreement
from kilix_license.coverage import AssetRef, require
from kilix_license.errors import CoverageRefused
from kilix_license.receipts import receipt_from_agreement
from kilix_license.records import LicenseRecord, RecordIndex
from kilix_license.screen import render_screen
from kilix_license.store import ReceiptStore
from kilix_license.texts import TextStore

from .install import Installer
from .model import AssetSpec
from .receipt import _CATALOG_SHA256, release_digest

Report = Callable[[str], None]


def license_record_for(spec: AssetSpec, records: RecordIndex) -> LicenseRecord:
    return records.by_digest(spec.licenses[0].record_digest)


def _asset_ref(spec: AssetSpec) -> AssetRef:
    return AssetRef(
        id=spec.asset_id,
        record_digest=spec.licenses[0].record_digest,
        manifest_digest=spec.manifest_digest,
    )


def needs_agreement(
    spec: AssetSpec, *, records: RecordIndex, store: ReceiptStore
) -> bool:
    """True unless a stored receipt covers the asset's current binding (OD-AI)."""
    try:
        require(_asset_ref(spec), records=records, store=store)
    except CoverageRefused:
        return True
    return False


def present_asset(
    spec: AssetSpec,
    record: LicenseRecord,
    texts: TextStore,
    *,
    receipts: ReceiptStore,
    records: RecordIndex,
) -> bytes:
    """Identity, source, size, licence, changed texts and the verbatim text.

    The screen below the header is kilix-license's (OD-AJ, SR-4): it marks
    every bound text that changed since an earlier acceptance in `receipts`,
    and `records` resolves the identities of receipts written for sibling
    records or before LIC4.
    """
    licence_ids = ", ".join(row.license_id for row in spec.licenses)
    licensors = ", ".join(
        dict.fromkeys(
            licensor for row in spec.licenses for licensor in row.licensors
        )
    )
    header = (
        f"model: {spec.label}\n"
        f"id: {spec.asset_id}\n"
        f"version: {spec.version}\n"
        f"source: {spec.source_url}\n"
        f"host: {spec.source_host}\n"
        f"bytes: {spec.download_bytes}\n"
        f"licence: {licence_ids}\n"
        f"licensors: {licensors}\n"
        f"decision: {spec.licenses[0].decision}\n"
    ).encode("utf-8")
    return header + b"\n" + render_screen(
        record, texts, receipts=receipts, records=records
    )


def install_with_agreement(
    spec: AssetSpec,
    *,
    installer: Installer,
    store: ReceiptStore,
    records: RecordIndex,
    texts: TextStore,
    typed_text: str | None,
    screen: BinaryIO | None = None,
    decline: bool = False,
    report: Report = lambda _message: None,
    cancelled: Callable[[], bool] | None = None,
    deadline: float | None = None,
) -> tuple[str, ...] | None:
    """Render the screen, record a receipt on accept, then fetch. Decline writes nothing."""
    record = license_record_for(spec, records)
    payload = present_asset(spec, record, texts, receipts=store, records=records)
    if screen is not None:
        screen.write(payload)
        screen.flush()
    if decline:
        return None
    agreement = capture_agreement(record, typed_text)
    receipt = receipt_from_agreement(
        record,
        agreement,
        manifest_digest=spec.manifest_digest,
        release_digest=release_digest(),
        catalogue_digest=_CATALOG_SHA256,
    )
    store.write(receipt)
    require(_asset_ref(spec), records=records, store=store)
    return installer.ensure_upstream_asset(
        spec,
        store=store,
        records=records,
        report=report,
        cancelled=cancelled,
        deadline=deadline,
        notices=texts,
    )
