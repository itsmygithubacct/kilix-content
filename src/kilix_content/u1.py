"""Externally rooted, schema-backed admission for frozen F100 U1 records.

This module loads only packaged declarative resources.  It never creates or
opens a content store, acquires a transaction lock, executes recovery, records
an authorization, invokes a process, or touches a network.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .u1_capacity import CAPACITY_VALIDATORS, production_capacity_policy_available
from .u1_catalog import (
    validate_authority_binding,
    validate_authorization_v2,
    validate_catalog_v5,
    validate_install_record,
    validate_output_binding,
)
from .u1_core import (
    U1ContractError,
    canonical_json_bytes,
    parse_json_bytes,
    refuse,
    require_array,
    require_digest,
    require_keys,
    require_object,
    require_s64,
    require_sorted_unique,
    require_text,
)
from .u1_profiles import (
    validate_license_manifest,
    validate_sandbox_profile,
    validate_system_requirements,
    validate_toolchain_profile,
)
from .u1_retention import RETENTION_VALIDATORS


U1_MANIFEST_NAME = "kilix.content.u1-resources-v1.json"
U1_LICENSE_NAME = "MIT.txt"
U1_MANIFEST_SHA256 = "b8ebefbc48f746239c4c209532594f30706639e2f6f6ab28d4049697f4b70ecc"
SCHEMA_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}/v[0-9]{1,3}$")
RESOURCE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
U1_SCHEMA_NAMES = (
    "kilix.content.capacity-generation-v2.schema.json",
    "kilix.content.capacity-lock-v2.schema.json",
    "kilix.content.capacity-reserve-v2.schema.json",
    "kilix.content.catalog-v5.schema.json",
    "kilix.content.directory-observation-v1.schema.json",
    "kilix.content.install-authority-binding-v1.schema.json",
    "kilix.content.install-record-v5.schema.json",
    "kilix.content.license-manifest-v1.schema.json",
    "kilix.content.output-binding-v1.schema.json",
    "kilix.content.recovery-vector-v1.schema.json",
    "kilix.content.release-proof-v2.schema.json",
    "kilix.content.retention-accounted-v1.schema.json",
    "kilix.content.retention-component-v1.schema.json",
    "kilix.content.retention-envelope-v1.schema.json",
    "kilix.content.retention-handoff-proof-v1.schema.json",
    "kilix.content.retention-intent-v1.schema.json",
    "kilix.content.retention-logical-state-v1.schema.json",
    "kilix.content.retention-marker-v1.schema.json",
    "kilix.content.retention-physical-state-v1.schema.json",
    "kilix.content.retention-relation-v1.schema.json",
    "kilix.content.sandbox-profile-v1.schema.json",
    "kilix.content.system-requirements-v1.schema.json",
    "kilix.content.toolchain-profile-v1.schema.json",
    "kilix.content.transaction-generation-v1.schema.json",
    "kilix.install.authorization-v2.schema.json",
)


SemanticValidator = Callable[[Any], None]
_SEMANTIC_VALIDATORS: dict[str, SemanticValidator] = {
    "kilix.content.catalog/v5": validate_catalog_v5,
    "kilix.content.install-record/v5": validate_install_record,
    "kilix.content.system-requirements/v1": validate_system_requirements,
    "kilix.content.toolchain-profile/v1": validate_toolchain_profile,
    "kilix.content.sandbox-profile/v1": validate_sandbox_profile,
    "kilix.content.license-manifest/v1": validate_license_manifest,
    "kilix.content.install-authority-binding/v1": validate_authority_binding,
    "kilix.content.output-binding/v1": validate_output_binding,
    "kilix.install.authorization/v2": validate_authorization_v2,
    **CAPACITY_VALIDATORS,
    **RETENTION_VALIDATORS,
}
if len(_SEMANTIC_VALIDATORS) != 25:
    raise RuntimeError("the compiled U1 route table is incomplete")


@dataclass(frozen=True, slots=True)
class ValidatedU1Record:
    """Immutable result returned only after the complete admission path."""

    schema_id: str
    raw_bytes: bytes
    value: Mapping[str, Any]


class PackagedReleaseCapability:
    """Opaque identity for one verified, externally rooted resource bundle."""

    __slots__ = ("_manifest_sha256", "_resources", "_routes", "_token")

    def __init__(
        self,
        token: object,
        manifest_sha256: str,
        packaged: Mapping[str, bytes],
        routes: Mapping[str, str],
    ) -> None:
        if token is not _CAPABILITY_TOKEN:
            refuse("packaged release capability construction is private")
        self._token = token
        self._manifest_sha256 = manifest_sha256
        self._resources = MappingProxyType(dict(packaged))
        self._routes = MappingProxyType(dict(routes))

    def __copy__(self) -> None:
        refuse("packaged release capability cannot be copied")

    def __deepcopy__(self, _memo: Any) -> None:
        refuse("packaged release capability cannot be copied")


_CAPABILITY_TOKEN = object()
_CAPABILITY_CACHE: PackagedReleaseCapability | None = None


def _package_root() -> Any:
    try:
        return resources.files("kilix_content")
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise U1ContractError("packaged U1 resource root is unavailable") from exc


def _read_packaged(path: str) -> bytes:
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        refuse("packaged U1 resource path is unsafe")
    try:
        item = _package_root().joinpath(*candidate.parts)
        is_symlink = getattr(item, "is_symlink", None)
        if (callable(is_symlink) and is_symlink()) or not item.is_file():
            refuse("packaged U1 resource is not a regular file")
        return item.read_bytes()
    except U1ContractError:
        raise
    except (FileNotFoundError, IsADirectoryError, OSError) as exc:
        raise U1ContractError("packaged U1 resource is unavailable") from exc


def _validate_manifest(raw: bytes) -> tuple[dict[str, bytes], dict[str, str]]:
    if hashlib.sha256(raw).hexdigest() != U1_MANIFEST_SHA256:
        refuse("packaged U1 manifest does not match its external root")
    manifest = require_object(parse_json_bytes(raw))
    require_keys(manifest, required=("schema", "release_id", "resources"))
    if (
        manifest["schema"] != "kilix.content.u1-resources/v1"
        or manifest["release_id"] != "0.2.1"
    ):
        refuse("packaged U1 manifest identity is not frozen")
    entries = require_array(manifest["resources"], minimum=26, maximum=26)
    packaged: dict[str, bytes] = {}
    routes: dict[str, str] = {}
    for raw_entry in entries:
        entry = require_object(raw_entry)
        require_keys(
            entry,
            required=(
                "role",
                "schema_id",
                "path",
                "size",
                "sha256",
                "wheel_disposition",
                "sdist_disposition",
            ),
        )
        if entry["role"] not in {"license-text", "schema"}:
            refuse("packaged U1 resource role is outside the frozen enum")
        if entry["role"] == "schema":
            require_text(entry["schema_id"], SCHEMA_ID_RE, maximum=72)
        path = require_text(entry["path"], RESOURCE_PATH_RE, maximum=512)
        path_parts = PurePosixPath(path).parts
        if PurePosixPath(path).is_absolute() or any(
            part in {"", ".", ".."} for part in path_parts
        ):
            refuse("packaged U1 resource path is unsafe")
        if path in packaged:
            refuse("packaged U1 resource path is duplicated")
        if (
            entry["wheel_disposition"] != "required"
            or entry["sdist_disposition"] != "required"
        ):
            refuse("packaged U1 resource disposition is not required")
        size = require_s64(entry["size"], positive=True)
        digest = require_digest(entry["sha256"])
        payload = _read_packaged(path)
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
            refuse("packaged U1 resource size or digest is inconsistent")
        packaged[path] = payload
        if entry["role"] == "schema":
            if entry["schema_id"] in routes:
                refuse("packaged U1 schema role is duplicated")
            routes[entry["schema_id"]] = path
            schema = parse_json_bytes(payload)
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as exc:
                raise U1ContractError("packaged U1 JSON Schema is invalid") from exc
            if require_object(schema).get("$id") != entry["schema_id"]:
                refuse("packaged U1 schema ID diverges from its manifest role")
        else:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise U1ContractError("packaged license text is not UTF-8") from exc
            if not text or "\x00" in text:
                refuse("packaged license text is not canonical")
    require_sorted_unique(entries)
    if set(routes) != set(_SEMANTIC_VALIDATORS):
        refuse("packaged U1 schema route set is incomplete or has extras")

    expected_paths = set(packaged)
    observed_paths: set[str] = set()
    for directory, prefix in (
        ("contracts/u1", "contracts/u1"),
        ("licenses", "licenses"),
    ):
        location = _package_root().joinpath(*PurePosixPath(directory).parts)
        try:
            children = list(location.iterdir())
        except (FileNotFoundError, NotADirectoryError, OSError) as exc:
            raise U1ContractError(
                "packaged U1 resource namespace is unavailable"
            ) from exc
        for child in children:
            is_symlink = getattr(child, "is_symlink", None)
            if callable(is_symlink) and is_symlink():
                refuse("packaged U1 resource namespace contains a linked entry")
            if child.is_file():
                observed_paths.add(f"{prefix}/{child.name}")
            elif child.is_dir():
                refuse(
                    "packaged U1 resource namespace contains an unexpected directory"
                )
            else:
                refuse("packaged U1 resource namespace contains a non-file")
    if observed_paths != expected_paths:
        refuse("packaged U1 resource namespace is not set-equal to its manifest")
    return packaged, routes


def packaged_release_capability() -> PackagedReleaseCapability:
    """Return the sole genuine capability after exhaustive resource verification."""
    global _CAPABILITY_CACHE
    if _CAPABILITY_CACHE is None:
        raw = _read_packaged(f"contracts/{U1_MANIFEST_NAME}")
        packaged, routes = _validate_manifest(raw)
        _CAPABILITY_CACHE = PackagedReleaseCapability(
            _CAPABILITY_TOKEN,
            U1_MANIFEST_SHA256,
            packaged,
            routes,
        )
    return _CAPABILITY_CACHE


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if type(value) is list:
        return tuple(_freeze(child) for child in value)
    return value


def validate_u1_bytes(
    expected_schema_id: str,
    raw_bytes: bytes,
    packaged_release: PackagedReleaseCapability,
) -> ValidatedU1Record:
    """Run the sole authoritative U1 raw-byte admission path."""
    if type(expected_schema_id) is not str or type(raw_bytes) is not bytes:
        refuse("U1 admission arguments have the wrong base type")
    if (
        type(packaged_release) is not PackagedReleaseCapability
        or packaged_release._token is not _CAPABILITY_TOKEN
        or packaged_release._manifest_sha256 != U1_MANIFEST_SHA256
        or packaged_release is not _CAPABILITY_CACHE
    ):
        refuse("U1 admission lacks the genuine packaged release capability")
    route = packaged_release._routes.get(expected_schema_id)
    semantic = _SEMANTIC_VALIDATORS.get(expected_schema_id)
    if route is None or semantic is None:
        refuse("U1 admission expected schema is outside the frozen route table")
    value = require_object(parse_json_bytes(raw_bytes))
    if value.get("schema") != expected_schema_id:
        refuse("U1 admission schema does not match the expected resource role")
    schema = parse_json_bytes(packaged_release._resources[route])
    try:
        Draft202012Validator(schema).validate(value)
    except ValidationError as exc:
        raise U1ContractError("U1 JSON Schema validation refused the record") from exc
    try:
        semantic(value)
    except U1ContractError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        UnicodeError,
    ) as exc:
        raise U1ContractError("U1 semantic validation refused the record") from exc
    return ValidatedU1Record(expected_schema_id, bytes(raw_bytes), _freeze(value))


def packaged_resource_bytes(name: str) -> bytes:
    """Compatibility reader restricted to manifest-rooted U1 resources."""
    capability = packaged_release_capability()
    candidates = [
        path
        for path in capability._resources
        if path == name or PurePosixPath(path).name == name
    ]
    if len(candidates) != 1:
        refuse("packaged U1 resource name is unknown or ambiguous")
    return capability._resources[candidates[0]]


def packaged_u1_hashes() -> dict[str, str]:
    capability = packaged_release_capability()
    return {
        PurePosixPath(path).name: hashlib.sha256(payload).hexdigest()
        for path, payload in capability._resources.items()
    }


def verify_packaged_u1_resources(expected: Mapping[str, str]) -> None:
    if type(expected) is not dict or expected != packaged_u1_hashes():
        refuse("caller resource expectations diverge from external packaged authority")


def verify_packaged_u1_manifest() -> None:
    packaged_release_capability()


__all__ = [
    "PackagedReleaseCapability",
    "U1ContractError",
    "U1_LICENSE_NAME",
    "U1_MANIFEST_NAME",
    "U1_MANIFEST_SHA256",
    "U1_SCHEMA_NAMES",
    "ValidatedU1Record",
    "canonical_json_bytes",
    "packaged_release_capability",
    "packaged_resource_bytes",
    "packaged_u1_hashes",
    "parse_json_bytes",
    "production_capacity_policy_available",
    "validate_u1_bytes",
    "verify_packaged_u1_manifest",
    "verify_packaged_u1_resources",
]
