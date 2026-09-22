"""First-use screen, agreement, receipt, then fetch (R4-052, R4-065)."""

from __future__ import annotations

import os
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

from .install import InstallError, Installer
from .model import AssetSpec
from .receipt import _CATALOG_SHA256, release_digest

Report = Callable[[str], None]

_CRLF = b"\r\n"
_LF = b"\n"

# C0, DEL and C1: every code point that is a terminal control on its own.
_PATH_CONTROLS = frozenset((*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0)))


def supplied_path_for_screen(supplied: str | os.PathLike[str]) -> str:
    """The `supplied:` header value, refused if it carries a terminal control.

    The supplied directory's path is operator input, and it is printed on the
    **consent screen**. A carriage return there overwrites what the reader has
    just read, and an escape sequence can repaint it -- a consent defect, not a
    cosmetic one (C-V3-FIX F5). A newline or tab is refused too: this is a
    single `key: value` header line, and a newline in it forges a header.

    **Order, relative to OD-BT's CRLF normalisation: this runs first, on the
    raw absolute path, before the header is assembled and before `crlf_to_lf`
    sees any byte.** Normalisation is never applied to the path to make it
    pass: a path holding `\r\n` is refused here, not turned into a forged
    second header line. (Because LF is itself in the refused set, no order of
    the two steps could admit a path that this order refuses; the check is
    placed first so that its verdict never depends on the renderer.)

    Raises `InstallError`, so every caller's existing handler applies, and the
    message names the path with its controls escaped (`repr`) rather than
    leaving the consumer's guard to refuse "the screen" for something the
    operator can fix by renaming a directory.
    """
    shown = os.path.abspath(os.fspath(supplied))
    if isinstance(shown, bytes):
        shown = os.fsdecode(shown)
    found = sorted({ord(char) for char in shown if ord(char) in _PATH_CONTROLS})
    if found:
        raise InstallError(
            "supplied directory path contains terminal control characters "
            f"({', '.join(f'U+{point:04X}' for point in found)}); "
            f"rename it and try again: {shown!r}"
        )
    return shown


def crlf_to_lf(payload: bytes) -> bytes:
    """CRLF to LF, at render only, for the bytes a terminal will be given (OD-BT).

    The authority quotes upstream notices byte-exactly, and one of them -- the
    `bonsai-8b` attribution statement, whose own determination note says
    "uses CRLF line ends (kept)" -- is a verbatim span of a `NOTICE.txt` written
    with CRLF. The consumer refuses to write any CR to a terminal during
    consent. Both rules are right, and they collide on exactly that quotation.

    OD-BT resolves it here, in the renderer, and nowhere else. Nothing on disk
    changes: the stored quotation stays byte-exact, no digest moves and nothing
    is re-vendored. A line ending changes; not a word.

    **A bare CR is deliberately left in place.** A lone carriage return returns
    the cursor and lets what follows overwrite the line the reader just read,
    which is the attack the consumer's guard exists to stop. Normalising CRLF
    must not become a licence to pass any CR, so this is one left-to-right pass
    over non-overlapping matches and never a repeated one: `\\r\\r\\n` becomes
    `\\r\\n`, which still carries a CR and is still refused, where a repeated
    substitution would collapse it to `\\n` and admit exactly the byte the rule
    exists to keep out.

    Working on bytes rather than on decoded text is safe and is not an
    approximation: UTF-8 is self-synchronising, and `0x0D`/`0x0A` can never
    appear inside a multi-byte sequence, so this is the same substitution the
    decoded form would make. `tests/test_screen_presentability.py` asserts that
    equivalence rather than assuming it.
    """
    return payload.replace(_CRLF, _LF)


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
    supplied: str | os.PathLike[str] | None = None,
) -> bytes:
    """Identity, source, size, licence, changed texts and the verbatim text.

    The screen below the header is kilix-license's (OD-AJ, SR-4): it marks
    every bound text that changed since an earlier acceptance in `receipts`,
    and `records` resolves the identities of receipts written for sibling
    records or before LIC4.

    `supplied` adds one header line naming the directory the bytes will be
    read from, so a user-supplied install (OD-BO) shows the same licence
    screen as every other install and still says where its bytes come from.
    That path is refused before anything is rendered if it carries a C0, DEL
    or C1 control (`supplied_path_for_screen`), so nothing is ever written to
    the screen for it.

    The returned bytes are CRLF-normalised (OD-BT, `crlf_to_lf` above). This is
    the only place a first-use screen is rendered, so the bytes returned here
    are exactly the bytes the consumer checks and exactly the bytes it writes:
    there is no second copy to normalise in one place and check in another.
    """
    shown = None if supplied is None else supplied_path_for_screen(supplied)
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
    )
    if shown is not None:
        header += (
            f"supplied: {shown}\n"
            "download: none (every file is verified against the manifest)\n"
        )
    header = header.encode("utf-8")
    return crlf_to_lf(
        header
        + b"\n"
        + render_screen(record, texts, receipts=receipts, records=records)
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
    supplied: str | os.PathLike[str] | None = None,
) -> tuple[str, ...] | None:
    """Render the screen, record a receipt on accept, then fetch. Decline writes nothing.

    With `supplied` the bytes are read from a directory the user already holds
    instead of fetched (OD-BO). Only the last step changes: the screen, the
    typed agreement, the receipt and the coverage check above it are the same
    code, so the air-gapped path cannot drift away from the licence discipline
    of the downloading one.
    """
    record = license_record_for(spec, records)
    payload = present_asset(
        spec, record, texts, receipts=store, records=records, supplied=supplied
    )
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
    if supplied is not None:
        return installer.ensure_supplied_asset(
            spec,
            supplied=supplied,
            store=store,
            records=records,
            report=report,
            cancelled=cancelled,
            deadline=deadline,
            notices=texts,
        )
    return installer.ensure_upstream_asset(
        spec,
        store=store,
        records=records,
        report=report,
        cancelled=cancelled,
        deadline=deadline,
        notices=texts,
    )
