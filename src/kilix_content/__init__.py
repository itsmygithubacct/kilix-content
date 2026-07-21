"""Pinned content catalog and user-level installer."""

from importlib.resources import files

from .install import (
    InstallError,
    Installer,
    download,
    safe_extract_tar,
    safe_extract_zip,
    sha256_file,
    verify_git_checkout,
)
from .model import Catalog, CatalogError, ContentSpec


__version__ = "0.1.0"


def default_catalog() -> Catalog:
    resource = files("kilix_content").joinpath("catalog/plebian.json")
    with resource.open(encoding="utf-8") as stream:
        import json
        return Catalog.from_mapping(json.load(stream))


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

