"""Pinned content catalog and user-level installer."""

from functools import lru_cache
from importlib.resources import files

from .paths import ensure_license_importable

ensure_license_importable()

from .fetch import DownloadError, Progress, fetch_exact
from .install import (
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
    AssetLicenseSpec,
    AssetSpec,
    Catalog,
    CatalogError,
    ContentSpec,
    LifecycleSpec,
    PackageSpec,
    source_objects_sha256,
)
from .receipt import verified_catalog_bytes, verify_packaged_catalog

__version__ = "0.4.0"


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    """The packaged catalog, parsed with **no** digest check (and cached).

    For callers that only read metadata. Anything that acts on the catalog
    wants `verified_packaged_catalog()`; see the warning there about this
    function's cache.
    """
    resource = files("kilix_content").joinpath("catalog/plebian.json")
    with resource.open(encoding="utf-8") as stream:
        return Catalog.loads(stream.read(), label="packaged catalog")


def verified_packaged_catalog() -> Catalog:
    """The packaged catalog, parsed **from the bytes that were verified**.

    The production entry point for every consumer that installs from the
    packaged catalog. One read: `receipt.verified_catalog_bytes()` reads
    `catalog/plebian.json` once, refuses unless those bytes match
    `_CATALOG_SHA256` (and the frozen schema its digest), and hands them back;
    this parses exactly them. Nothing unauthenticated reaches the parser.

    **Why it is written this way, and why it is not cached.** It used to run
    the check over one read of the file and then call `default_catalog()`,
    which opens and reads the file a second time -- so a tamper landing
    between the two reads was verified and not parsed, parsed and not
    verified, and returned with no refusal. Worse, `default_catalog()` is
    `lru_cache`d, so a caller that had already parsed a tampered file got the
    *cached bad parse* back from this function with no race and no attacker
    timing at all: only call order. Both were demonstrated
    (C-V3-EXTEND-VERIFY F2; C-MIGRATE-KILIX-VERIFY V4). Parsing every time is
    the point: a cache here is a parse that can pre-date its own check, which
    is exactly how this went wrong.

    **Cross-repository contract (OD-BP).** kilix's `config/content_models.py`
    looks this name up on the `kilix_content` module and uses it in preference
    to the private `receipt._verify_frozen_schema`; with neither present it
    refuses to run. `receipt.verify_packaged_catalog` documents what a rename
    costs.
    """
    return Catalog.loads(
        verified_catalog_bytes().decode("utf-8"), label="packaged catalog"
    )


__all__ = [
    "ActionSpec",
    "AssetLicenseSpec",
    "AssetSpec",
    "Catalog",
    "CatalogError",
    "ContentSpec",
    "DownloadError",
    "InstallError",
    "Installer",
    "LifecycleSpec",
    "PackageSpec",
    "Progress",
    "default_catalog",
    "download",
    "fetch_exact",
    "safe_extract_tar",
    "safe_extract_zip",
    "sha256_file",
    "source_objects_sha256",
    "verified_catalog_bytes",
    "verified_packaged_catalog",
    "verify_git_checkout",
    "verify_packaged_catalog",
]
