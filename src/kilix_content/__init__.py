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

__version__ = "0.4.0"


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    resource = files("kilix_content").joinpath("catalog/plebian.json")
    with resource.open(encoding="utf-8") as stream:
        return Catalog.loads(stream.read(), label="packaged catalog")


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
    "verify_git_checkout",
]
