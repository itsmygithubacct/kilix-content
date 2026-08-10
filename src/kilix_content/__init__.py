"""Pinned content catalog and user-level installer."""

from functools import lru_cache
from importlib.resources import files

from .install import (
    Installer,
    InstallError,
    download,
    safe_extract_tar,
    safe_extract_zip,
    sha256_file,
    verify_git_checkout,
)
from .model import Catalog, CatalogError, ContentSpec

__version__ = "0.2.2"


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    resource = files("kilix_content").joinpath("catalog/plebian.json")
    with resource.open(encoding="utf-8") as stream:
        return Catalog.loads(stream.read(), label="packaged catalog")


__all__ = [
    "Catalog",
    "CatalogError",
    "ContentSpec",
    "InstallError",
    "Installer",
    "default_catalog",
    "download",
    "safe_extract_tar",
    "safe_extract_zip",
    "sha256_file",
    "verify_git_checkout",
]
