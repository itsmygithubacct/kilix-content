"""First-use screen, agreement, receipt, then fetch (R4-052, R4-065)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import BinaryIO

from kilix_license.agreement import capture_agreement
from kilix_license.coverage import AssetRef, require
from kilix_license.errors import CoverageRefused, LicenseError
from kilix_license.receipts import parse_receipt_bytes, receipt_from_agreement
from kilix_license.records import LicenseRecord, RecordIndex
from kilix_license.screen import render_screen
from kilix_license.store import ReceiptStore
from kilix_license.texts import TextStore

from .install import Installer
from .model import AssetSpec
from .receipt import _CATALOG_SHA256, release_digest

Report = Callable[[str], None]
ChangedBindings = Mapping[str, tuple[str, ...]]


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


def changed_binding_conditions(
    record: LicenseRecord, store: ReceiptStore
) -> dict[str, tuple[str, ...]]:
    """Binding texts that differ from the text an earlier receipt bound (OD-AH).

    Returns binding id -> the digests earlier receipts for this licence bound.
    A binding whose current text an earlier receipt already bound is not
    changed. A binding no earlier receipt names is new, not changed.

    The marker is presentation only. Coverage is enforced by require(), which
    reads the exact receipt path. A store file this build cannot read, that is
    not a JSON object, or whose schema or shape it does not know is skipped
    here, so it cannot stop the screen or the install of any asset.
    """
    current = record.agreement_binding_digests()
    accepted: dict[str, set[str]] = {key: set() for key in current}
    for path in sorted(store.root.glob("*.json")):
        if path.name.startswith("."):
            continue
        try:
            receipt = parse_receipt_bytes(path.read_bytes())
        except (OSError, ValueError, TypeError, RecursionError, LicenseError):
            continue
        if receipt.licence_id != record.id:
            continue
        for key in current:
            digest = receipt.binding_condition_text_digests.get(key)
            if digest is not None:
                accepted[key].add(digest)
    return {
        key: tuple(sorted(earlier))
        for key, earlier in accepted.items()
        if earlier and current[key] not in earlier
    }


def _changed_block(record: LicenseRecord, changed: ChangedBindings) -> bytes:
    current = record.agreement_binding_digests()
    lines = ["=== changed since your last acceptance ==="]
    for key in sorted(changed):
        lines.append(f"changed: binding:{key}")
        for digest in changed[key]:
            lines.append(f"accepted sha256: {digest}")
        lines.append(f"shown sha256: {current[key]}")
    lines.append(
        "The text below differs from the text you accepted before. "
        "Your earlier acceptance does not cover it."
    )
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def present_asset(
    spec: AssetSpec,
    record: LicenseRecord,
    texts: TextStore,
    *,
    changed: ChangedBindings | None = None,
) -> bytes:
    """Identity, source, size, licence, changed bindings and the verbatim text."""
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
    notice = _changed_block(record, changed) if changed else b""
    return header + b"\n" + notice + render_screen(record, texts)


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
    changed = changed_binding_conditions(record, store)
    payload = present_asset(spec, record, texts, changed=changed)
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
