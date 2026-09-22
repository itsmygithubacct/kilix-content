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
from .receipt import verify_packaged_catalog

__version__ = "0.4.0"


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    resource = files("kilix_content").joinpath("catalog/plebian.json")
    with resource.open(encoding="utf-8") as stream:
        return Catalog.loads(stream.read(), label="packaged catalog")


def verified_packaged_catalog() -> Catalog:
    """The packaged catalog, parsed only after its bytes match the pins.

    The production entry point for every consumer that installs from the
    packaged catalog: `verify_packaged_catalog()` first, `default_catalog()`
    second, so a catalog whose bytes are not the pinned ones is never parsed
    and never acted on. `default_catalog()` remains the unverified parse for
    callers that only read metadata.

    **Cross-repository contract (OD-BP).** kilix's `config/content_models.py`
    looks this name up on the `kilix_content` module and uses it in preference
    to the private `receipt._verify_frozen_schema`; with neither present it
    refuses to run. `receipt.verify_packaged_catalog` documents what a rename
    costs.
    """
    verify_packaged_catalog()
    return default_catalog()


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
    "verified_packaged_catalog",
    "verify_git_checkout",
    "verify_packaged_catalog",
]
