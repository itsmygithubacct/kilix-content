"""Pinned content catalog and user-level installer."""

from functools import lru_cache

from .install import (
    AcquisitionRequired,
    Installer,
    InstallError,
    download,
    safe_extract_tar,
    safe_extract_zip,
    sha256_file,
    verify_git_checkout,
)
from .model import (
    ActionSpec,
    AssetFileSpec,
    AssetLicenseSpec,
    AssetSpec,
    Catalog,
    CatalogError,
    ContentSpec,
    LifecycleSpec,
    PackageSpec,
)
from .receipt import (
    BindingMismatch,
    DecisionDeclined,
    DecisionInvalid,
    DurabilityUnknown,
    LicenseDecision,
    ReceiptError,
    ReceiptMissing,
    ReceiptStore,
    ReconcileResult,
    RecordResult,
    ReleaseContext,
    StoreBusy,
    StoredReceiptInvalid,
    UnsafeStore,
    VerifiedInput,
    VerifiedReceipt,
    verified_packaged_catalog,
)

__version__ = "0.4.0"


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    """Return the packaged catalog after verifying its exact frozen bytes."""
    return verified_packaged_catalog()


__all__ = [
    "AcquisitionRequired",
    "ActionSpec",
    "AssetFileSpec",
    "AssetLicenseSpec",
    "AssetSpec",
    "BindingMismatch",
    "Catalog",
    "CatalogError",
    "ContentSpec",
    "DecisionDeclined",
    "DecisionInvalid",
    "DurabilityUnknown",
    "InstallError",
    "Installer",
    "LicenseDecision",
    "LifecycleSpec",
    "PackageSpec",
    "ReceiptError",
    "ReceiptMissing",
    "ReceiptStore",
    "ReconcileResult",
    "RecordResult",
    "ReleaseContext",
    "StoreBusy",
    "StoredReceiptInvalid",
    "UnsafeStore",
    "VerifiedInput",
    "VerifiedReceipt",
    "verified_packaged_catalog",
    "default_catalog",
    "download",
    "safe_extract_tar",
    "safe_extract_zip",
    "sha256_file",
    "verify_git_checkout",
]
