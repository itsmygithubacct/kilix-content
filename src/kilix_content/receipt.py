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
    "a5aafcd6ad543c4894e263f246527b53b0a1d27accef0416b4a7ea7d7dd4a57e"
)
_ASSET_V3_SCHEMA_SHA256 = (
    "07cb268fb8aa0c6131d6c230af3f7ede094270a1214efd3ae5deb407d6a8e870"
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


def verify_packaged_catalog() -> None:
    """Refuse the packaged catalog unless its bytes are the pinned ones.

    Compares the packaged `catalog/plebian.json` against `_CATALOG_SHA256` and
    the frozen asset/v3 schema against `_ASSET_V3_SCHEMA_SHA256`, and raises
    `RuntimeError` on either mismatch. `default_catalog()` parses without this
    check; `kilix_content.verified_packaged_catalog()` is the production entry
    point that runs it first.

    **This is a cross-repository contract (OD-BP), not an internal helper.**
    kilix's `config/content_models.py` verifies the packaged catalog through
    this repository, fail-closed: it prefers the public
    `kilix_content.verified_packaged_catalog`, falls back to the private
    `kilix_content.receipt._verify_frozen_schema`, and **refuses to run
    `kilix models` at all** if it finds neither. So renaming or removing both
    names here does not degrade the consumer's verification quietly -- it turns
    every `kilix models install` into a hard refusal at install time, for a
    component whose gitlink is pinned and cannot be fixed from this repository.
    Change the name only together with the consumer, and keep the old name
    working until every pinned consumer has moved.
    """
    actual = hashlib.sha256(asset_v3_schema_bytes()).hexdigest()
    if actual != _ASSET_V3_SCHEMA_SHA256:
        raise RuntimeError("asset/v3 schema bytes do not match the frozen digest")
    actual_catalog = catalog_sha256()
    if actual_catalog != _CATALOG_SHA256:
        raise RuntimeError("packaged catalog bytes do not match _CATALOG_SHA256")


# Retained for the pinned kilix consumer, which reaches across the repository
# boundary for this exact name (see the docstring above). It is the same
# function object, so the two names cannot drift. Remove it only after every
# consumer has moved to `verify_packaged_catalog` / `verified_packaged_catalog`.
_verify_frozen_schema = verify_packaged_catalog


def release_digest() -> str:
    return hashlib.sha256(f"kilix-content-release:{_RELEASE_ID}".encode("utf-8")).hexdigest()
