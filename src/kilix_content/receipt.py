"""Catalog and schema pins for asset/v3. Receipt storage lives in kilix-license."""

from __future__ import annotations

import hashlib
from importlib.resources import files

_CATALOG_RESOURCE = "catalog/plebian.json"
_ASSET_V3_SCHEMA_RESOURCE = "contracts/kilix.content.asset-v3.schema.json"
_RELEASE_ID = "0.2.2"

# Production trust root. Re-pinned by tools/generate_upstream_records.py with
# the old-value guard whenever catalog/plebian.json bytes change.
_CATALOG_SHA256 = (
    "c52bf76a680f3995d648db902d8b8681acee1ec0262a2884d808c132627d1af0"
)
_ASSET_V3_SCHEMA_SHA256 = (
    "f69cb0cf2ab1dbf42418ca4cf82f9915e19cac85078d8b5c806ca8ba2324973d"
)


def _resource_bytes(name: str) -> bytes:
    resource = files("kilix_content").joinpath(name)
    with resource.open("rb") as handle:
        return handle.read()


def catalog_bytes() -> bytes:
    return _resource_bytes(_CATALOG_RESOURCE)


def catalog_sha256() -> str:
    return hashlib.sha256(catalog_bytes()).hexdigest()


def asset_v3_schema_bytes() -> bytes:
    return _resource_bytes(_ASSET_V3_SCHEMA_RESOURCE)


def _verify_frozen_schema() -> None:
    actual = hashlib.sha256(asset_v3_schema_bytes()).hexdigest()
    if actual != _ASSET_V3_SCHEMA_SHA256:
        raise RuntimeError("asset/v3 schema bytes do not match the frozen digest")
    actual_catalog = catalog_sha256()
    if actual_catalog != _CATALOG_SHA256:
        raise RuntimeError("packaged catalog bytes do not match _CATALOG_SHA256")


def release_digest() -> str:
    return hashlib.sha256(f"kilix-content-release:{_RELEASE_ID}".encode("utf-8")).hexdigest()
