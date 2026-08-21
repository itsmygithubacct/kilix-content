"""Frozen F100 Step-6 U1 contract resources and semantic checks.

This module deliberately contains schemas, canonicalization, and pure
validation only.  It does not create a store, acquire a lock, recover a
transaction, or sequence authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from importlib import resources
from typing import Any


class U1ContractError(ValueError):
    """A frozen U1 value is not structurally or semantically valid."""


_HEX = re.compile(r"^[0-9a-f]{64}$")
_IDENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PATH = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,255}$")
_DIGEST_DOMAINS = {
    "install-authority": "kilix-content install-authority/v1\0",
    "output": "kilix-content output-binding/v1\0",
    "retention-intent": "kilix-content retention intent/v1\0",
    "retention-accounted": "kilix-content retention accounted/v1\0",
    "retention-handoff": "kilix-content retention handoff/v1\0",
}

U1_SCHEMA_NAMES = (
    "kilix.content.asset-v1.schema.json",
    "kilix.install.license-v1.schema.json",
    "kilix.content.catalog-v5.schema.json",
    "kilix.content.install-authority-binding-v1.schema.json",
    "kilix.content.output-binding-v1.schema.json",
    "kilix.install.authorization-v2.schema.json",
    "kilix.content.capacity-reserve-v2.schema.json",
    "kilix.pleb.system-requirements-v1.schema.json",
    "kilix.content.toolchain-profile-v1.schema.json",
    "kilix.content.sandbox-profile-v1.schema.json",
    "kilix.content.retention-intent-v1.schema.json",
    "kilix.content.retention-envelope-v1.schema.json",
    "kilix.content.retention-journal-v1.schema.json",
    "kilix.content.retention-capacity-state-v1.schema.json",
    "kilix.content.retention-counts-v1.schema.json",
    "kilix.content.retention-admission-v1.schema.json",
    "kilix.content.retention-directory-phase-v1.schema.json",
    "kilix.content.retention-accounted-v1.schema.json",
    "kilix.content.retention-handoff-proof-v1.schema.json",
    "kilix.content.retention-terminal-reuse-v1.schema.json",
    "kilix.content.retention-impossible-state-v1.schema.json",
)
U1_LICENSE_NAME = "MIT.txt"
U1_MANIFEST_NAME = "kilix.content.u1-resources-v1.json"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise U1ContractError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise U1ContractError("non-standard JSON constant")


def _float(value: str) -> Any:
    raise U1ContractError("floating-point JSON value is forbidden")


def parse_json_bytes(data: bytes, *, label: str = "value") -> Any:
    """Parse bounded UTF-8 JSON while rejecting duplicates and non-JSON values."""
    if len(data) > 4 * 1024 * 1024:
        raise U1ContractError("JSON input exceeds the 4 MiB contract bound")
    try:
        text = data.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise U1ContractError("JSON input is not valid UTF-8 JSON") from exc
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole U1 JSON representation: compact, sorted, UTF-8, newline."""
    _walk_json(value)
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise U1ContractError("value cannot be canonically encoded") from exc


def _walk_json(value: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise U1ContractError("contract nesting exceeds the U1 bound")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise U1ContractError("object keys must be non-empty strings")
            _walk_json(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 4096:
            raise U1ContractError("array exceeds the U1 bound")
        for child in value:
            _walk_json(child, depth=depth + 1)
    elif isinstance(value, str):
        if "\x00" in value or len(value) > 65536:
            raise U1ContractError("string exceeds the U1 bound")
    elif value is None or type(value) is bool or type(value) is int:
        return
    else:
        raise U1ContractError("floating-point and extension values are forbidden")


def canonical_digest(domain: str, value: Any) -> str:
    try:
        prefix = _DIGEST_DOMAINS[domain]
    except KeyError as exc:
        raise U1ContractError(f"unknown digest domain: {domain}") from exc
    return hashlib.sha256(prefix.encode("ascii") + canonical_json_bytes(value)).hexdigest()


def _object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise U1ContractError(f"{label} must be an object")
    return value


def _keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise U1ContractError("object contains an unknown key")


def _required(value: Mapping[str, Any], names: Sequence[str], label: str) -> None:
    missing = [name for name in names if name not in value]
    if missing:
        raise U1ContractError("object is missing a required field")


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise U1ContractError(f"{label} must be non-empty text")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise U1ContractError(f"{label} is not canonical")
    return value


def _digest(value: Any, label: str) -> str:
    return _text(value, label, pattern=_HEX)


def _count(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0) or value > 2**63 - 1:
        raise U1ContractError(f"{label} must be a bounded signed 64-bit integer")
    return value


def _id(value: Any, label: str) -> str:
    return _text(value, label, pattern=_IDENT)


def _path(value: Any, label: str) -> str:
    value = _text(value, label, pattern=_PATH)
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise U1ContractError(f"{label} must be a canonical relative path")
    return value


def _digest_ref(value: Any, label: str) -> None:
    entry = _object(value, label)
    _keys(entry, {"id", "sha256"}, label)
    _required(entry, ("id", "sha256"), label)
    _id(entry["id"], f"{label}.id")
    _digest(entry["sha256"], f"{label}.sha256")


def _unique_ids(values: Sequence[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise U1ContractError(f"{label} contains duplicate identifiers")


def _validate_install(install: Any, *, owner: str) -> None:
    value = _object(install, f"{owner}.install")
    allowed = {
        "version", "source_mode", "source_bytes", "source_bytes_max", "temporary_bytes_max",
        "process_memory_bytes_max", "installed_bytes_max", "temporary_files_max",
        "installed_files_max", "dependencies", "system_requirements", "toolchain",
        "sandbox", "licenses",
    }
    _keys(value, allowed, f"{owner}.install")
    _required(
        value,
        (
            "version", "source_mode", "source_bytes_max", "temporary_bytes_max",
            "process_memory_bytes_max", "installed_bytes_max", "temporary_files_max",
            "installed_files_max", "dependencies", "system_requirements", "toolchain",
            "sandbox", "licenses",
        ),
        f"{owner}.install",
    )
    _text(value["version"], "install.version")
    if value["source_mode"] not in {"git", "archive", "mirrored", "user-supplied"}:
        raise U1ContractError("install.source_mode is not a frozen enum")
    if value["source_mode"] == "git":
        if "source_bytes" in value:
            raise U1ContractError("git installation must omit source_bytes")
    else:
        if "source_bytes" not in value:
            raise U1ContractError("non-Git installation must declare source_bytes")
        _count(value["source_bytes"], "install.source_bytes", positive=True)
        if value["source_bytes"] > value["source_bytes_max"]:
            raise U1ContractError("source_bytes exceeds source_bytes_max")
    for name in (
        "source_bytes_max", "temporary_bytes_max", "process_memory_bytes_max",
        "installed_bytes_max", "temporary_files_max", "installed_files_max",
    ):
        _count(value[name], f"{owner}.install.{name}", positive=True)
    dependencies = value["dependencies"]
    if type(dependencies) is not list or len(dependencies) > 4096:
        raise U1ContractError(f"{owner}.install.dependencies is not bounded")
    dependency_ids: list[str] = []
    for dependency in dependencies:
        item = _object(dependency, f"{owner}.dependency")
        _keys(item, {"id", "role"}, "dependency")
        _required(item, ("id", "role"), "dependency")
        dependency_ids.append(_id(item["id"], "dependency.id"))
        if item["role"] not in {"build", "conversion", "runtime"}:
            raise U1ContractError("dependency.role is not a frozen enum")
    _unique_ids(dependency_ids, f"{owner}.dependencies")
    requirements = value["system_requirements"]
    if type(requirements) is not list:
        raise U1ContractError("system_requirements must be an array")
    requirement_ids: list[str] = []
    for item in requirements:
        item = _object(item, "system requirement")
        _keys(item, {"id", "manifest_sha256"}, "system requirement")
        _required(item, ("id", "manifest_sha256"), "system requirement")
        requirement_ids.append(_id(item["id"], "system requirement.id"))
        _digest(item["manifest_sha256"], "system requirement.manifest_sha256")
    _unique_ids(requirement_ids, f"{owner}.system_requirements")
    for name in ("toolchain", "sandbox"):
        _digest_ref(value[name], f"{owner}.install.{name}")
    licenses = value["licenses"]
    if type(licenses) is not list or not licenses or len(licenses) > 256:
        raise U1ContractError(f"{owner}.install.licenses must be bounded and non-empty")
    license_ids: list[str] = []
    for item in licenses:
        entry = _object(item, "license")
        _keys(entry, {"id", "text_sha256", "decision"}, "license")
        _required(entry, ("id", "text_sha256", "decision"), "license")
        license_ids.append(_id(entry["id"], "license.id"))
        _digest(entry["text_sha256"], "license.text_sha256")
        if entry["decision"] not in {"informational", "affirmative", "user-supplied", "restricted"}:
            raise U1ContractError("license.decision is not a frozen enum")
    _unique_ids(license_ids, f"{owner}.licenses")


def _dependency_cycles(installables: Mapping[str, Mapping[str, Any]]) -> None:
    graph: dict[str, list[str]] = {}
    for identifier, record in installables.items():
        graph[identifier] = [item["id"] for item in record["install"]["dependencies"]]
        for child in graph[identifier]:
            if child == identifier:
                raise U1ContractError("dependency graph contains a cycle or self-dependency")
            if child not in installables:
                raise U1ContractError("dependency is not in the global namespace")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise U1ContractError("dependency graph contains a cycle")
        if identifier in visited:
            return
        visiting.add(identifier)
        for child in graph[identifier]:
            visit(child)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in graph:
        visit(identifier)


def validate_catalog_v5(value: Any) -> None:
    root = _object(value, "catalog")
    _keys(root, {"schema", "release_id", "catalog_sha256", "packages", "content", "aliases"}, "catalog")
    _required(root, ("schema", "release_id", "catalog_sha256", "packages", "content", "aliases"), "catalog")
    if root["schema"] != "kilix.content.catalog/v5":
        raise U1ContractError("catalog schema is not v5")
    _id(root["release_id"], "catalog.release_id")
    _digest(root["catalog_sha256"], "catalog.catalog_sha256")
    packages = _object_array(root["packages"], "catalog.packages")
    content = _object_array(root["content"], "catalog.content")
    installables: dict[str, Mapping[str, Any]] = {}
    namespace: set[str] = set()
    for package in packages:
        _keys(package, {"id", "kind", "members", "install", "stable_slot"}, "package")
        _required(package, ("id", "kind", "members", "install", "stable_slot"), "package")
        identifier = _id(package["id"], "package.id")
        if package["kind"] != "package" or identifier in namespace:
            raise U1ContractError("package namespace collision or wrong kind")
        namespace.add(identifier)
        _id(package["stable_slot"], "package.stable_slot")
        members = package["members"]
        if type(members) is not list:
            raise U1ContractError("package.members must be an array")
        member_ids = [_id(item, "package.member") for item in members]
        _unique_ids(member_ids, "package.members")
        installables[identifier] = package
        _validate_install(package["install"], owner=f"package {identifier}")
    for item in content:
        _keys(item, {"id", "kind", "package_id", "member_path", "install", "stable_slot"}, "content")
        _required(item, ("id", "kind"), "content")
        identifier = _id(item["id"], "content.id")
        if identifier in namespace:
            raise U1ContractError("global catalog namespace collision")
        namespace.add(identifier)
        if item["kind"] not in {"content", "asset"}:
            raise U1ContractError("content.kind is not a frozen enum")
        has_package_mapping = "package_id" in item or "member_path" in item
        if has_package_mapping:
            if set(item) != {"id", "kind", "package_id", "member_path"}:
                raise U1ContractError("package-provided content has an independent install authority")
            package_id = _id(item["package_id"], "content.package_id")
            if package_id not in installables:
                raise U1ContractError("content package is not in the catalog")
            _path(item["member_path"], "content.member_path")
        else:
            if set(item) != {"id", "kind", "install", "stable_slot"}:
                raise U1ContractError("direct content has an incomplete install authority")
            _id(item["stable_slot"], "content.stable_slot")
            _validate_install(item["install"], owner=f"content {identifier}")
            installables[identifier] = item
    aliases = _object(root["aliases"], "catalog.aliases")
    for alias, target in aliases.items():
        _id(alias, "alias")
        if alias in namespace:
            raise U1ContractError("alias collides with global namespace")
        entry = _object(target, "alias")
        _keys(entry, {"package_id", "member_path"}, "alias")
        _required(entry, ("package_id", "member_path"), "alias")
        package_id = _id(entry["package_id"], "alias.package_id")
        if package_id not in installables:
            raise U1ContractError("alias package is not in the catalog")
        _path(entry["member_path"], "alias.member_path")
    _dependency_cycles(installables)


def _object_array(value: Any, label: str) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > 4096 or any(type(x) is not dict for x in value):
        raise U1ContractError(f"{label} must be a bounded object array")
    return value


def validate_authority_binding(value: Any) -> None:
    root = _object(value, "authority binding")
    _keys(root, {"schema", "kind", "stable_slot", "version", "release_id", "catalog_sha256", "authority_digest", "source_digest", "output_manifest_digest", "content_ids", "alias_members"}, "authority binding")
    _required(root, ("schema", "kind", "stable_slot", "version", "release_id", "catalog_sha256", "authority_digest", "source_digest", "content_ids", "alias_members"), "authority binding")
    if root["schema"] != "kilix.content.install-authority-binding/v1":
        raise U1ContractError("authority binding schema is not v1")
    if root["kind"] not in {"asset", "content", "package"}:
        raise U1ContractError("authority binding kind is not frozen")
    _id(root["stable_slot"], "stable_slot")
    _count(root["version"], "version", positive=True)
    _id(root["release_id"], "release_id")
    for name in ("catalog_sha256", "authority_digest", "source_digest"):
        _digest(root[name], name)
    if "output_manifest_digest" in root:
        _digest(root["output_manifest_digest"], "output_manifest_digest")
    ids = [_id(item, "content_id") for item in root["content_ids"]] if type(root["content_ids"]) is list else []
    _unique_ids(ids, "content_ids")
    aliases = _object(root["alias_members"], "alias_members")
    for alias, member in aliases.items():
        _id(alias, "alias_members key")
        entry = _object(member, "alias member")
        _keys(entry, {"package_id", "member_path"}, "alias member")
        _required(entry, ("package_id", "member_path"), "alias member")
        _id(entry["package_id"], "alias member package_id")
        _path(entry["member_path"], "alias member member_path")


def validate_output_binding(value: Any) -> None:
    root = _object(value, "output binding")
    _keys(root, {"schema", "authority_digest", "source_digest", "input_digest", "dependency_digests", "toolchain_digest", "sandbox_digest", "selected_tree_digest", "byte_count", "file_count", "journal_schema", "output_format_version"}, "output binding")
    _required(root, ("schema", "authority_digest", "source_digest", "input_digest", "dependency_digests", "toolchain_digest", "sandbox_digest", "selected_tree_digest", "byte_count", "file_count", "journal_schema", "output_format_version"), "output binding")
    if root["schema"] != "kilix.content.output-binding/v1":
        raise U1ContractError("output binding schema is not v1")
    for name in ("authority_digest", "source_digest", "input_digest", "toolchain_digest", "sandbox_digest", "selected_tree_digest"):
        _digest(root[name], name)
    dependencies = root["dependency_digests"]
    if type(dependencies) is not list:
        raise U1ContractError("dependency_digests must be an array")
    for digest in dependencies:
        _digest(digest, "dependency_digest")
    _count(root["byte_count"], "byte_count")
    _count(root["file_count"], "file_count")
    _text(root["journal_schema"], "journal_schema")
    _count(root["output_format_version"], "output_format_version", positive=True)


def validate_authorization_v2(value: Any) -> None:
    root = _object(value, "authorization")
    _keys(root, {"schema", "authorization_id", "authority_digest", "output_digest", "decision", "release_id", "catalog_sha256"}, "authorization")
    _required(root, ("schema", "authorization_id", "authority_digest", "output_digest", "decision", "release_id", "catalog_sha256"), "authorization")
    if root["schema"] != "kilix.install.authorization/v2":
        raise U1ContractError("authorization schema is not v2")
    _id(root["authorization_id"], "authorization_id")
    for name in ("authority_digest", "output_digest", "catalog_sha256"):
        _digest(root[name], name)
    if root["decision"] not in {"informational", "affirmative", "user-supplied"}:
        raise U1ContractError("authorization decision is not executable")
    _id(root["release_id"], "release_id")


_ROOT_ROLES = {"installed-data", "resumable-cache", "transaction-state", "license-receipts-v1", "install-authorizations-v2"}
_CAPACITY_PHASES = {"RESOLVE", "ACQUIRING", "ACQUIRED", "VERIFYING", "OUTPUT_VERIFIED", "PROMOTING", "SELECTED", "FINAL_VERIFIED", "COMPLETE"}


def validate_capacity_v2(value: Any) -> None:
    root = _object(value, "capacity")
    _keys(root, {"schema", "release_id", "authority_digest", "hardware_tier", "tier_inputs", "root_roles", "phase_maxima", "retention_limits", "reservation", "stable_lock", "generation_zero", "mutable_generations", "reservation_tombstone", "ordinary_release_proof", "filesystem_key"}, "capacity")
    _required(root, ("schema", "release_id", "authority_digest", "hardware_tier", "tier_inputs", "root_roles", "phase_maxima", "retention_limits", "reservation", "stable_lock", "generation_zero", "mutable_generations", "reservation_tombstone", "ordinary_release_proof", "filesystem_key"), "capacity")
    if root["schema"] != "kilix.content.capacity-reserve/v2":
        raise U1ContractError("capacity schema is not v2")
    _id(root["release_id"], "capacity.release_id")
    _digest(root["authority_digest"], "capacity.authority_digest")
    _id(root["hardware_tier"], "capacity.hardware_tier")
    _object(root["tier_inputs"], "capacity.tier_inputs")
    roles = _object(root["root_roles"], "capacity.root_roles")
    if set(roles) != _ROOT_ROLES:
        raise U1ContractError("capacity root roles are incomplete or have extras")
    for role, item in roles.items():
        entry = _object(item, role)
        _keys(entry, {"relative_path", "fs_magic", "descriptor_relative"}, role)
        _required(entry, ("relative_path", "fs_magic", "descriptor_relative"), role)
        _path(entry["relative_path"], f"{role}.relative_path")
        _text(entry["fs_magic"], f"{role}.fs_magic")
        if type(entry["descriptor_relative"]) is not bool:
            raise U1ContractError(f"{role}.descriptor_relative must be boolean")
    maxima = _object(root["phase_maxima"], "capacity.phase_maxima")
    for phase, item in maxima.items():
        if phase not in _CAPACITY_PHASES:
            raise U1ContractError("capacity phase is not frozen")
        entry = _object(item, f"phase {phase}")
        _keys(entry, {"bytes", "inodes", "temporary_files"}, f"phase {phase}")
        _required(entry, ("bytes", "inodes", "temporary_files"), f"phase {phase}")
        for name in ("bytes", "inodes", "temporary_files"):
            _count(entry[name], f"phase {phase}.{name}", positive=True)
    limits = _object(root["retention_limits"], "retention_limits")
    for name in ("per_slot", "global", "objects", "relations"):
        _count(limits.get(name), f"retention_limits.{name}", positive=True)
    reservation = _object(root["reservation"], "reservation")
    for name in ("memory_bytes", "disk_bytes", "inode_count"):
        _count(reservation.get(name), f"reservation.{name}", positive=True)
    lock = _object(root["stable_lock"], "stable lock")
    _keys(lock, {"schema", "path", "generation", "inode_digest", "authority_digest", "state_digest"}, "stable lock")
    _required(lock, ("schema", "path", "generation", "inode_digest", "authority_digest", "state_digest"), "stable lock")
    if lock["schema"] != "kilix.content.capacity-lock/v1":
        raise U1ContractError("capacity lock schema is not frozen")
    _path(lock["path"], "stable lock path")
    _count(lock["generation"], "stable lock generation")
    for name in ("inode_digest", "authority_digest", "state_digest"):
        _digest(lock[name], "capacity lock digest")
    zero = _object(root["generation_zero"], "generation zero")
    _keys(zero, {"generation", "state", "state_digest"}, "generation zero")
    _required(zero, ("generation", "state", "state_digest"), "generation zero")
    if zero["generation"] != 0 or zero["state"] != "ABSENT":
        raise U1ContractError("generation zero is not the absent state")
    _digest(zero["state_digest"], "generation zero digest")
    generations = root["mutable_generations"]
    if type(generations) is not list:
        raise U1ContractError("mutable generations must be an array")
    for generation in generations:
        item = _object(generation, "mutable generation")
        _keys(item, {"generation", "state", "state_digest", "predecessor_digest"}, "mutable generation")
        _required(item, ("generation", "state", "state_digest", "predecessor_digest"), "mutable generation")
        _count(item["generation"], "mutable generation number", positive=True)
        if item["state"] not in {"RESERVED", "ACCOUNTED", "RELEASING", "PROOFED", "TOMBSTONED"}:
            raise U1ContractError("mutable generation state is not frozen")
        _digest(item["state_digest"], "mutable generation digest")
        _digest(item["predecessor_digest"], "mutable predecessor digest")
    tombstone = _object(root["reservation_tombstone"], "reservation tombstone")
    _keys(tombstone, {"schema", "reservation_id", "generation", "state", "digest", "absent_after"}, "reservation tombstone")
    _required(tombstone, ("schema", "reservation_id", "generation", "state", "digest", "absent_after"), "reservation tombstone")
    if tombstone["schema"] != "kilix.content.reservation-tombstone/v1" or tombstone["state"] != "RELEASED" or tombstone["absent_after"] is not True:
        raise U1ContractError("reservation tombstone is not a closed release record")
    _id(tombstone["reservation_id"], "reservation tombstone id")
    _count(tombstone["generation"], "reservation tombstone generation", positive=True)
    _digest(tombstone["digest"], "reservation tombstone digest")
    proof = _object(root["ordinary_release_proof"], "ordinary release proof")
    _keys(proof, {"schema", "kind", "release_kind", "proof_digest", "reservation_id", "generation", "resources", "permanent"}, "ordinary release proof")
    _required(proof, ("schema", "kind", "release_kind", "proof_digest", "reservation_id", "generation", "resources", "permanent"), "ordinary release proof")
    if proof["schema"] != "kilix.content.release-proof/v1" or proof["kind"] != "release-proof" or proof["release_kind"] != "ordinary" or proof["permanent"] is not False:
        raise U1ContractError("ordinary release proof is not a closed record")
    _digest(proof["proof_digest"], "ordinary proof digest")
    _id(proof["reservation_id"], "ordinary proof reservation")
    _count(proof["generation"], "ordinary proof generation", positive=True)
    if type(proof["resources"]) is not list or not proof["resources"]:
        raise U1ContractError("ordinary proof resources are empty")
    filesystem = _object(root["filesystem_key"], "filesystem key")
    _keys(filesystem, {"magic", "mount_id", "device", "root_id", "key_digest"}, "filesystem key")
    _required(filesystem, ("magic", "mount_id", "device", "root_id", "key_digest"), "filesystem key")
    _text(filesystem["magic"], "filesystem magic")
    for name in ("mount_id", "device", "root_id"):
        _count(filesystem[name], "filesystem identity")
    _digest(filesystem["key_digest"], "filesystem key digest")


def validate_system_requirements(value: Any) -> None:
    root = _object(value, "system requirements")
    _keys(root, {"schema", "id", "version", "distribution", "architecture", "packages", "manifest_sha256"}, "system requirements")
    _required(root, ("schema", "id", "version", "distribution", "architecture", "packages", "manifest_sha256"), "system requirements")
    if root["schema"] != "kilix.pleb.system-requirements/v1":
        raise U1ContractError("system requirement schema is not frozen")
    _id(root["id"], "system requirement id")
    _text(root["version"], "system requirement version")
    _text(root["distribution"], "system requirement distribution")
    _text(root["architecture"], "system requirement architecture")
    _digest(root["manifest_sha256"], "system requirement manifest")
    packages = _object_array(root["packages"], "system requirement packages")
    package_names: list[str] = []
    for item in packages:
        _keys(item, {"name", "version", "architecture", "sha256"}, "system requirement package")
        _required(item, ("name", "version", "architecture", "sha256"), "system requirement package")
        _text(item["name"], "system requirement package name")
        package_names.append(item["name"])
        _text(item["version"], "system requirement package version")
        _text(item["architecture"], "system requirement package architecture")
        _digest(item["sha256"], "system requirement package digest")
    _unique_ids(package_names, "system requirement package names")


def validate_toolchain_profile(value: Any) -> None:
    root = _object(value, "toolchain profile")
    _keys(root, {"schema", "id", "debian_snapshot", "architecture", "packages", "executables", "libraries", "python", "uv", "environment", "abi"}, "toolchain profile")
    _required(root, ("schema", "id", "debian_snapshot", "architecture", "packages", "executables", "libraries", "python", "uv", "environment", "abi"), "toolchain profile")
    if root["schema"] != "kilix.content.toolchain-profile/v1":
        raise U1ContractError("toolchain profile schema is not frozen")
    _id(root["id"], "toolchain profile id")
    for name in ("debian_snapshot", "architecture"):
        _text(root[name], "toolchain profile field")
    for collection in ("packages", "executables", "libraries"):
        if type(root[collection]) is not list or len(root[collection]) > 4096:
            raise U1ContractError("toolchain profile collection is not a bounded array")
    package_names: list[str] = []
    for item in root["packages"]:
        item = _object(item, "toolchain package")
        _keys(item, {"name", "version", "sha256"}, "toolchain package")
        _required(item, ("name", "version", "sha256"), "toolchain package")
        package_names.append(_text(item["name"], "toolchain package name"))
        _text(item["version"], "toolchain package version")
        _digest(item["sha256"], "toolchain package digest")
    _unique_ids(package_names, "toolchain package names")
    executable_paths: list[str] = []
    for item in root["executables"]:
        item = _object(item, "toolchain executable")
        _keys(item, {"path", "sha256"}, "toolchain executable")
        _required(item, ("path", "sha256"), "toolchain executable")
        executable_paths.append(_path(item["path"], "toolchain executable path"))
        _digest(item["sha256"], "toolchain executable digest")
    _unique_ids(executable_paths, "toolchain executable paths")
    library_names: list[str] = []
    for item in root["libraries"]:
        item = _object(item, "toolchain library")
        _keys(item, {"soname", "sha256"}, "toolchain library")
        _required(item, ("soname", "sha256"), "toolchain library")
        library_names.append(_text(item["soname"], "toolchain library soname"))
        _digest(item["sha256"], "toolchain library digest")
    _unique_ids(library_names, "toolchain library names")
    python = _object(root["python"], "toolchain Python")
    _keys(python, {"implementation", "version", "executable_sha256", "prefix"}, "toolchain Python")
    _required(python, ("implementation", "version", "executable_sha256", "prefix"), "toolchain Python")
    if python["implementation"] != "CPython":
        raise U1ContractError("toolchain Python implementation is not frozen")
    _text(python["version"], "toolchain Python version")
    _digest(python["executable_sha256"], "toolchain Python digest")
    _path(python["prefix"], "toolchain Python prefix")
    uv = _object(root["uv"], "toolchain uv")
    _keys(uv, {"version", "executable_sha256", "lock_sha256", "offline"}, "toolchain uv")
    _required(uv, ("version", "executable_sha256", "lock_sha256", "offline"), "toolchain uv")
    _text(uv["version"], "toolchain uv version")
    for name in ("executable_sha256", "lock_sha256"):
        _digest(uv[name], "toolchain uv digest")
    if uv["offline"] is not True:
        raise U1ContractError("toolchain uv must be offline")
    environment = _object(root["environment"], "toolchain environment")
    _keys(environment, {"allowlist", "assignments"}, "toolchain environment")
    _required(environment, ("allowlist", "assignments"), "toolchain environment")
    allowlist = environment["allowlist"]
    if type(allowlist) is not list or any(type(name) is not str or not name for name in allowlist):
        raise U1ContractError("toolchain environment allowlist is not canonical")
    _unique_ids(allowlist, "toolchain environment allowlist")
    assignments = _object(environment["assignments"], "toolchain environment assignments")
    if not set(assignments) <= set(allowlist) or any(type(item) is not str or not item for item in assignments.values()):
        raise U1ContractError("toolchain environment assignment is not allowlisted")
    abi = _object(root["abi"], "toolchain ABI")
    _keys(abi, {"libc", "kernel", "endianness"}, "toolchain ABI")
    _required(abi, ("libc", "kernel", "endianness"), "toolchain ABI")
    _text(abi["libc"], "toolchain ABI libc")
    _text(abi["kernel"], "toolchain ABI kernel")
    if abi["endianness"] not in {"little", "big"}:
        raise U1ContractError("toolchain ABI endianness is not frozen")


def validate_sandbox_profile(value: Any) -> None:
    root = _object(value, "sandbox profile")
    _keys(root, {"schema", "id", "mount_manifest", "namespace", "capabilities", "seccomp", "resource_limits", "quota_backend"}, "sandbox profile")
    _required(root, ("schema", "id", "mount_manifest", "namespace", "capabilities", "seccomp", "resource_limits", "quota_backend"), "sandbox profile")
    if root["schema"] != "kilix.content.sandbox-profile/v1":
        raise U1ContractError("sandbox profile schema is not frozen")
    _id(root["id"], "sandbox profile id")
    mounts = _object_array(root["mount_manifest"], "sandbox mount manifest")
    mount_targets: list[str] = []
    for item in mounts:
        _keys(item, {"source", "target", "read_only", "kind"}, "sandbox mount")
        _required(item, ("source", "target", "read_only", "kind"), "sandbox mount")
        _text(item["source"], "sandbox mount source")
        mount_targets.append(_path(item["target"], "sandbox mount target"))
        if type(item["read_only"]) is not bool or item["kind"] not in {"tmpfs", "proc", "bind", "dev"}:
            raise U1ContractError("sandbox mount is not a closed entry")
    _unique_ids(mount_targets, "sandbox mount targets")
    namespace = _object(root["namespace"], "sandbox namespace")
    _keys(namespace, {"user", "mount", "pid", "network"}, "sandbox namespace")
    _required(namespace, ("user", "mount", "pid", "network"), "sandbox namespace")
    if any(namespace[name] is not True for name in ("user", "mount", "pid", "network")):
        raise U1ContractError("sandbox namespace is not fully isolated")
    if type(root["capabilities"]) is not list or any(type(item) is not str or not item for item in root["capabilities"]) or type(root["seccomp"]) is not dict or type(root["resource_limits"]) is not dict:
        raise U1ContractError("sandbox profile sections are not closed")
    _unique_ids(root["capabilities"], "sandbox capabilities")
    seccomp = root["seccomp"]
    _keys(seccomp, {"profile_id", "default_action", "denied_syscalls"}, "sandbox seccomp")
    _required(seccomp, ("profile_id", "default_action", "denied_syscalls"), "sandbox seccomp")
    _text(seccomp["profile_id"], "sandbox seccomp profile")
    if seccomp["default_action"] != "kill" or type(seccomp["denied_syscalls"]) is not list or any(type(item) is not str or not item for item in seccomp["denied_syscalls"]):
        raise U1ContractError("sandbox seccomp policy is not frozen")
    _unique_ids(seccomp["denied_syscalls"], "sandbox denied syscalls")
    limits = root["resource_limits"]
    _keys(limits, {"memory_bytes", "cpu_seconds", "pids", "tmpfs_bytes", "tmpfs_inodes"}, "sandbox limits")
    _required(limits, ("memory_bytes", "cpu_seconds", "pids", "tmpfs_bytes", "tmpfs_inodes"), "sandbox limits")
    for name in limits:
        _count(limits[name], "sandbox limit", positive=True)
    quota = _object(root["quota_backend"], "sandbox quota")
    _keys(quota, {"kind", "version", "enforced"}, "sandbox quota")
    _required(quota, ("kind", "version", "enforced"), "sandbox quota")
    if quota["kind"] != "tmpfs-cgroup" or quota["version"] != 1 or quota["enforced"] is not True:
        raise U1ContractError("sandbox quota backend is not frozen")


_RETENTION_KINDS = {
    "intent", "envelope", "journal", "capacity-state", "counts", "admission",
    "directory-phase", "accounted", "handoff-proof", "terminal-reuse", "impossible",
}

_RETENTION_ALLOWED = {
    "intent": {"schema", "kind", "version", "release_id", "intent_digest", "nonce", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "reservation_id", "expected_generation", "target_roles"},
    "envelope": {"schema", "kind", "version", "release_id", "intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "reservation_id", "generation", "target_roles", "components"},
    "journal": {"schema", "kind", "version", "release_id", "transaction_phase", "generation", "intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "reservation_id", "envelope_digest", "capacity_digest", "state_digest", "predecessor_digest", "directory_names", "phase_child_set_digest"},
    "capacity-state": {"schema", "kind", "version", "release_id", "capacity_phase", "generation", "intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "reservation_id", "predecessor_digest", "state_digest", "reservation_path", "tombstone_path", "proof_path", "absence"},
    "counts": {"schema", "kind", "version", "release_id", "stable_slot_digest", "authority_digest", "output_digest", "counts"},
    "admission": {"schema", "kind", "version", "release_id", "stable_slot_digest", "authority_digest", "output_digest", "counts_digest", "account_digest", "admission_closed", "account_quarantined", "pending_relation", "incomplete_representation", "limit_exceeded", "reasons"},
    "directory-phase": {"schema", "kind", "version", "release_id", "directory"},
    "accounted": {"schema", "kind", "version", "release_id", "intent", "intent_digest", "envelope_digest", "reservation_id", "generation", "state_digest", "stable_slot_digest", "authority_digest", "output_digest", "profile_digest", "ready_journal_generation", "ready_journal_digest", "descriptor_digest", "content_digest", "O_counted", "R_counted", "per_slot_bytes", "per_slot_files", "global_bytes", "global_files", "prospective_bytes", "prospective_files", "capacity_digest", "release_schema_digest", "proof_nonce", "p_path", "p_max_bytes", "p_max_files", "transaction_phase", "capacity_phase"},
    "handoff-proof": {"schema", "kind", "version", "release_id", "proof_digest", "release_kind", "permanent", "transaction_phase", "capacity_phase", "handoff_nonce", "intent_digest", "envelope_digest", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "p_path", "m_path", "r_path", "descriptor_digest", "content_digest", "counts", "physical_max", "h_temp_path", "h_final_path", "absence_before", "capacity_predecessor_digest", "journal_predecessor_digest"},
    "terminal-reuse": {"schema", "kind", "version", "release_id", "stable_slot_digest", "authority_digest", "output_digest", "state", "permanent", "children", "capacity_names_absent", "journal_anomaly_absent", "provenance", "counts"},
    "impossible": {"schema", "kind", "version", "release_id", "reason_code", "state_digest", "observed", "expected"},
}

_INTENT_FIELDS = {"intent_digest", "nonce", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "reservation_id", "expected_generation", "target_roles"}


def validate_retention(value: Any) -> None:
    root = _object(value, "retention")
    _required(root, ("schema", "kind", "version", "release_id"), "retention")
    if root["schema"] != "kilix.content.retention/v1" or root["kind"] not in _RETENTION_KINDS:
        raise U1ContractError("retention schema or kind is not frozen")
    _keys(root, _RETENTION_ALLOWED[root["kind"]], "retention")
    required_by_kind = {
        "intent": ("intent_digest", "nonce", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "reservation_id", "expected_generation", "target_roles"),
        "envelope": ("intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "reservation_id", "generation", "target_roles", "components"),
        "journal": ("transaction_phase", "generation", "intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "reservation_id", "envelope_digest", "capacity_digest", "state_digest", "predecessor_digest", "directory_names", "phase_child_set_digest"),
        "capacity-state": ("capacity_phase", "generation", "intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "reservation_id", "predecessor_digest", "state_digest", "reservation_path", "tombstone_path", "proof_path", "absence"),
        "counts": ("stable_slot_digest", "authority_digest", "output_digest", "counts"),
        "admission": ("stable_slot_digest", "authority_digest", "output_digest", "counts_digest", "account_digest", "admission_closed", "account_quarantined", "pending_relation", "incomplete_representation", "limit_exceeded", "reasons"),
        "directory-phase": ("directory",),
        "accounted": ("intent", "intent_digest", "envelope_digest", "reservation_id", "generation", "state_digest", "stable_slot_digest", "authority_digest", "output_digest", "profile_digest", "ready_journal_generation", "ready_journal_digest", "descriptor_digest", "content_digest", "O_counted", "R_counted", "per_slot_bytes", "per_slot_files", "global_bytes", "global_files", "prospective_bytes", "prospective_files", "capacity_digest", "release_schema_digest", "proof_nonce", "p_path", "p_max_bytes", "p_max_files", "transaction_phase", "capacity_phase"),
        "handoff-proof": ("proof_digest", "release_kind", "permanent", "transaction_phase", "capacity_phase", "handoff_nonce", "intent_digest", "envelope_digest", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "p_path", "m_path", "r_path", "descriptor_digest", "content_digest", "counts", "physical_max", "h_temp_path", "h_final_path", "absence_before", "capacity_predecessor_digest", "journal_predecessor_digest"),
        "terminal-reuse": ("stable_slot_digest", "authority_digest", "output_digest", "state", "permanent", "children", "capacity_names_absent", "journal_anomaly_absent", "provenance", "counts"),
        "impossible": ("reason_code", "state_digest", "observed", "expected"),
    }
    _required(root, required_by_kind[root["kind"]], "retention record")
    _count(root["version"], "retention.version", positive=True)
    _id(root["release_id"], "retention.release_id")
    for name in ("intent_digest", "authority_digest", "output_digest", "proof_digest"):
        if name in root:
            _digest(root[name], f"retention.{name}")
    if "generation" in root:
        _count(root["generation"], "retention.generation", positive=True)
    if "nonce" in root:
        _text(root["nonce"], "retention.nonce", pattern=_HEX)
    if "permanent" in root and type(root["permanent"]) is not bool:
        raise U1ContractError("retention.permanent must be boolean")
    if "release_kind" in root and root["release_kind"] not in {"retention_handoff", "ordinary"}:
        raise U1ContractError("retention.release_kind is not frozen")
    if "admission_closed" in root and type(root["admission_closed"]) is not bool:
        raise U1ContractError("retention.admission_closed must be boolean")
    _validate_phase_fields(root)
    if root["kind"] == "counts":
        _validate_counts(root)
    if root["kind"] in {"intent", "envelope", "journal", "capacity-state", "admission", "accounted", "handoff-proof", "terminal-reuse", "impossible"}:
        _validate_retention_provenance(root)
    if root["kind"] == "directory-phase":
        _validate_directory_phase(root)
    if root["kind"] == "intent":
        _validate_intent_fields({name: root[name] for name in _INTENT_FIELDS}, "retention intent")
    if root["kind"] == "accounted":
        _validate_intent_fields(_object(root["intent"], "accounted intent"), "accounted intent")
    if root["kind"] == "journal":
        _validate_directory_names(root["directory_names"])
    if root["kind"] == "impossible":
        _validate_impossible_state(root)
    if root["kind"] == "handoff-proof" and root.get("permanent") is not True:
        raise U1ContractError("handoff proof must be permanent")
    if root["kind"] == "envelope":
        components = root["components"]
        if type(components) is not list or len(components) != 5 or {item.get("role") for item in components} != {"D", "M", "R", "P", "H"}:
            raise U1ContractError("retention component envelope is incomplete")
        for item in components:
            entry = _object(item, "retention component")
            _keys(entry, {"role", "path", "descriptor_digest", "content_digest", "bytes", "files", "identity"}, "retention component")
            _required(entry, ("role", "path", "descriptor_digest", "content_digest", "bytes", "files", "identity"), "retention component")
            _path(entry["path"], "retention component path")
            _digest(entry["descriptor_digest"], "retention component descriptor")
            _digest(entry["content_digest"], "retention component content")
            _count(entry["bytes"], "retention component bytes")
            _count(entry["files"], "retention component files")
            identity = _object(entry["identity"], "retention component identity")
            _keys(identity, {"type", "uid", "gid", "mode", "fs_magic", "root_id", "mount_id", "role", "path"}, "retention component identity")
            _required(identity, ("type", "uid", "gid", "mode", "fs_magic", "root_id", "mount_id", "role", "path"), "retention component identity")
            if identity["role"] != entry["role"] or identity["path"] != entry["path"]:
                raise U1ContractError("retention component identity is not bound")
            if identity["type"] not in {"directory", "regular"} or (entry["role"] == "D") != (identity["type"] == "directory"):
                raise U1ContractError("retention component type is not frozen")
            for name in ("uid", "gid", "mode", "root_id", "mount_id"):
                _count(identity[name], "retention component identity field")
            _text(identity["fs_magic"], "retention component filesystem")
    if root["kind"] == "admission":
        flags = {name for name in ("account_quarantined", "pending_relation", "incomplete_representation", "limit_exceeded") if root[name]}
        if root["admission_closed"] != bool(flags) or set(root["reasons"]) != flags:
            raise U1ContractError("retention admission flags are inconsistent")
    if root["kind"] == "terminal-reuse":
        if root.get("state") != "TERMINAL_REUSE" or root.get("permanent") is not True or root.get("children") != ["M", "R", "P", "H"]:
            raise U1ContractError("terminal reuse is not a permanent terminal record")
    if root["kind"] == "impossible" and not root.get("reason_code"):
        raise U1ContractError("impossible-state record needs a reason")


def _validate_phase_fields(root: Mapping[str, Any]) -> None:
    transaction = root.get("transaction_phase")
    capacity = root.get("capacity_phase")
    if transaction is not None and transaction not in {"RETENTION_PREPARED", "RETENTION_MARKER_DURABLE", "RETENTION_RELATION_DURABLE", "RETENTION_READY", "RETENTION_ACCOUNTED", "RETENTION_HANDOFF_COMPLETE"}:
        raise U1ContractError("transaction phase is not frozen")
    if capacity is not None and capacity not in {"RETENTION_INTENT_RESERVED", "RETENTION_ACCOUNTED", "RETENTION_HANDOFF_RELEASING", "RETENTION_HANDOFF_PROOFED", "ABSENT"}:
        raise U1ContractError("capacity phase is not frozen")


def _validate_intent_fields(value: Mapping[str, Any], label: str) -> None:
    _keys(value, _INTENT_FIELDS, label)
    _required(value, tuple(_INTENT_FIELDS), label)
    for name in ("intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "nonce"):
        _digest(value[name], f"{label}.{name}")
    _id(value["reservation_id"], f"{label}.reservation_id")
    _count(value["expected_generation"], f"{label}.expected_generation", positive=True)
    if value["target_roles"] != ["D", "M", "R", "P", "H"]:
        raise U1ContractError("retention target roles are not frozen")


def _validate_directory_names(value: Any) -> None:
    names = _object(value, "retention directory names")
    _keys(names, {"D", "M", "R", "P", "H"}, "retention directory names")
    _required(names, ("D", "M", "R", "P", "H"), "retention directory names")
    if type(names["D"]) is not list or any(type(item) is not str for item in names["D"]):
        raise U1ContractError("retention D names are not a canonical list")
    _unique_ids(names["D"], "retention D names")
    for item in names["D"]:
        _path(item, "retention D name")
    for role in ("M", "R", "P", "H"):
        _path(names[role], f"retention {role} name")


def _validate_impossible_state(root: Mapping[str, Any]) -> None:
    for name in ("observed", "expected"):
        state = _object(root[name], f"impossible {name}")
        _keys(state, {"transaction_phase", "capacity_phase", "generation", "names"}, f"impossible {name}")
        _required(state, ("transaction_phase", "capacity_phase", "generation", "names"), f"impossible {name}")
        _validate_phase_fields(state)
        _count(state["generation"], f"impossible {name} generation", positive=True)
        names = state["names"]
        if type(names) is not list or any(type(item) is not str for item in names):
            raise U1ContractError("impossible names are not a canonical list")
        _unique_ids(names, f"impossible {name} names")
        for item in names:
            _text(item, f"impossible {name} name", pattern=re.compile(r"^[a-z0-9][a-z0-9._-]{0,255}$"))


def _validate_counts(root: Mapping[str, Any]) -> None:
    counts = _object(root.get("counts"), "retention.counts")
    _keys(counts, {"R_present", "R_pending", "R_counted", "O_materialized", "O_referenced", "O_counted", "retained_unique_objects", "retained_versions", "global_bytes", "global_files", "per_slot_bytes", "per_slot_files", "prospective_bytes", "prospective_files"}, "retention.counts")
    _required(counts, ("R_present", "R_pending", "R_counted", "O_materialized", "O_referenced", "O_counted", "retained_unique_objects", "retained_versions", "global_bytes", "global_files", "per_slot_bytes", "per_slot_files", "prospective_bytes", "prospective_files"), "retention.counts")
    for name in ("R_present", "R_pending", "R_counted", "O_materialized", "O_referenced", "O_counted"):
        if type(counts[name]) is not list:
            raise U1ContractError(f"{name} must be an array")
    for name in ("retained_unique_objects", "global_bytes", "global_files", "per_slot_bytes", "per_slot_files", "prospective_bytes", "prospective_files"):
        _count(counts[name], name)
    versions = _object(counts["retained_versions"], "retained_versions")
    for key, val in versions.items():
        _id(key, "retained_versions.slot")
        _count(val, "retained_versions.value")


def _validate_directory_phase(root: Mapping[str, Any]) -> None:
    directory = _object(root.get("directory"), "retention.directory")
    _keys(directory, {"directory_id", "role", "parent_path", "path", "final_name", "temp_name", "phase", "baseline_children", "baseline_children_digest", "observed_children", "permitted_children", "phase_child_set_digest", "identity", "absence_evidence"}, "retention.directory")
    _required(directory, ("directory_id", "role", "parent_path", "path", "final_name", "temp_name", "phase", "baseline_children", "baseline_children_digest", "observed_children", "permitted_children", "phase_child_set_digest", "identity", "absence_evidence"), "retention.directory")
    if directory["role"] not in {"D", "M", "R", "P", "H"}:
        raise U1ContractError("directory role is not frozen")
    _path(directory["path"], "directory.path")
    _path(directory["parent_path"], "directory.parent_path")
    _id(directory["directory_id"], "directory.directory_id")
    normal_child_pattern = re.compile(r"^[a-z0-9][a-z0-9._-]{0,255}$")
    temp_child_pattern = re.compile(r"^\.new-retention-[a-z0-9][a-z0-9._-]{0,240}$")
    child_pattern = re.compile(r"^(?:[a-z0-9][a-z0-9._-]{0,255}|\.new-retention-[a-z0-9][a-z0-9._-]{0,240})$")
    _text(directory["final_name"], "directory.final_name", pattern=normal_child_pattern)
    _text(directory["temp_name"], "directory.temp_name", pattern=temp_child_pattern)
    if directory["phase"] not in {"RETENTION_PREPARED", "RETENTION_MARKER_DURABLE", "RETENTION_RELATION_DURABLE", "RETENTION_READY", "RETENTION_ACCOUNTED", "RETENTION_HANDOFF_RELEASING", "RETENTION_HANDOFF_PROOFED", "RETENTION_HANDOFF_COMPLETE", "ABSENT"}:
        raise U1ContractError("directory phase is not frozen")
    identity = _object(directory["identity"], "directory.identity")
    _keys(identity, {"type", "uid", "gid", "mode", "fs_magic", "root_id", "mount_id", "role", "path"}, "directory.identity")
    _required(identity, ("type", "uid", "gid", "mode", "fs_magic", "root_id", "mount_id", "role", "path"), "directory.identity")
    if identity["type"] != "directory" or identity["role"] != directory["role"] or identity["path"] != directory["path"]:
        raise U1ContractError("directory identity does not bind the semantic directory")
    for name in ("uid", "gid", "mode", "root_id", "mount_id"):
        _count(identity[name], "directory identity field")
    _text(identity["fs_magic"], "directory identity filesystem")
    _digest(directory["baseline_children_digest"], "directory baseline digest")
    _digest(directory["phase_child_set_digest"], "directory phase child digest")
    absence = _object(directory["absence_evidence"], "directory absence evidence")
    _keys(absence, {"before_final", "after_parent_fsync"}, "directory absence evidence")
    _required(absence, ("before_final", "after_parent_fsync"), "directory absence evidence")
    if type(absence["before_final"]) is not bool or type(absence["after_parent_fsync"]) is not bool:
        raise U1ContractError("directory absence evidence is not boolean")
    for name in ("baseline_children", "observed_children", "permitted_children"):
        entries = directory[name]
        if type(entries) is not list or any(type(item) is not str for item in entries):
            raise U1ContractError(f"directory.{name} must be string arrays")
        _unique_ids(entries, f"directory.{name}")
        if entries != sorted(entries):
            raise U1ContractError(f"directory.{name} is not sorted")
        for entry in entries:
            _text(entry, "directory child", pattern=child_pattern)
            if name != "observed" and temp_child_pattern.fullmatch(entry):
                raise U1ContractError("directory baseline/final child list contains a temporary name")
    baseline = set(directory["baseline_children"])
    permitted = set(directory["permitted_children"])
    observed = set(directory["observed_children"])
    expected = baseline | permitted
    if not expected <= observed:
        raise U1ContractError("directory child set is missing an expected entry")
    extras = observed - expected
    if len(extras) > 1 or any(not item.startswith(".new-retention-") for item in extras):
        raise U1ContractError("directory child set has an unauthorized entry")
    if extras and next(iter(extras)) != directory["temp_name"]:
        raise U1ContractError("directory temporary child is not the bound name")


def _validate_retention_provenance(root: Mapping[str, Any]) -> None:
    for name in ("intent_digest", "authority_digest", "output_digest", "stable_slot_digest", "profile_digest", "release_schema_digest", "envelope_digest", "capacity_digest", "state_digest", "predecessor_digest", "proof_digest", "counts_digest", "account_digest", "descriptor_digest", "content_digest", "capacity_predecessor_digest", "journal_predecessor_digest", "ready_journal_digest"):
        if name in root:
            _digest(root[name], "retention provenance digest")
    for name in ("generation", "expected_generation", "ready_journal_generation", "p_max_bytes", "p_max_files", "per_slot_bytes", "per_slot_files", "global_bytes", "global_files", "prospective_bytes", "prospective_files"):
        if name in root:
            _count(root[name], "retention provenance count")
    for name in ("reservation_id", "release_id"):
        if name in root:
            _id(root[name], "retention provenance identifier")


def validate_u1(value: Any) -> None:
    """Dispatch a value to its frozen pure U1 semantic validator."""
    root = _object(value, "U1 value")
    schema = root.get("schema")
    if schema == "kilix.content.catalog/v5":
        validate_catalog_v5(value)
    elif schema == "kilix.content.install-authority-binding/v1":
        validate_authority_binding(value)
    elif schema == "kilix.content.output-binding/v1":
        validate_output_binding(value)
    elif schema == "kilix.install.authorization/v2":
        validate_authorization_v2(value)
    elif schema == "kilix.content.capacity-reserve/v2":
        validate_capacity_v2(value)
    elif schema == "kilix.pleb.system-requirements/v1":
        validate_system_requirements(value)
    elif schema == "kilix.content.toolchain-profile/v1":
        validate_toolchain_profile(value)
    elif schema == "kilix.content.sandbox-profile/v1":
        validate_sandbox_profile(value)
    elif schema == "kilix.content.retention/v1":
        validate_retention(value)
    else:
        raise U1ContractError("unknown U1 schema")


def packaged_resource_bytes(name: str) -> bytes:
    if name not in U1_SCHEMA_NAMES and name != U1_LICENSE_NAME and name != U1_MANIFEST_NAME:
        raise U1ContractError("unknown packaged U1 resource")
    package = resources.files("kilix_content")
    resource = package.joinpath("contracts", name)
    if name == U1_LICENSE_NAME:
        resource = package.joinpath("licenses", name)
    try:
        return resource.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise U1ContractError("missing packaged U1 resource") from exc


def packaged_u1_hashes() -> dict[str, str]:
    return {
        name: hashlib.sha256(packaged_resource_bytes(name)).hexdigest()
        for name in (*U1_SCHEMA_NAMES, U1_LICENSE_NAME)
    }


def verify_packaged_u1_resources(expected: Mapping[str, str]) -> None:
    actual = packaged_u1_hashes()
    if dict(expected) != actual:
        raise U1ContractError("packaged U1 resource hash mismatch")


def verify_packaged_u1_manifest() -> None:
    manifest = parse_json_bytes(packaged_resource_bytes(U1_MANIFEST_NAME), label="U1 manifest")
    if type(manifest) is not dict or manifest.get("schema") != "kilix.content.u1-resources/v1":
        raise U1ContractError("invalid packaged U1 resource manifest")
    entries = manifest.get("resources")
    if type(entries) is not list:
        raise U1ContractError("invalid packaged U1 resource manifest")
    expected: dict[str, str] = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"name", "sha256"}:
            raise U1ContractError("invalid packaged U1 resource manifest")
        _text(entry["name"], "resource name")
        _digest(entry["sha256"], "resource digest")
        if entry["name"] in expected:
            raise U1ContractError("invalid packaged U1 resource manifest")
        expected[entry["name"]] = entry["sha256"]
    actual = {name: hashlib.sha256(packaged_resource_bytes(name)).hexdigest() for name in (*U1_SCHEMA_NAMES, U1_LICENSE_NAME)}
    if expected != actual:
        raise U1ContractError("packaged U1 resource manifest mismatch")


__all__ = [
    "U1ContractError",
    "U1_LICENSE_NAME",
    "U1_MANIFEST_NAME",
    "U1_SCHEMA_NAMES",
    "canonical_digest",
    "canonical_json_bytes",
    "packaged_resource_bytes",
    "packaged_u1_hashes",
    "parse_json_bytes",
    "validate_authority_binding",
    "validate_authorization_v2",
    "validate_capacity_v2",
    "validate_catalog_v5",
    "validate_output_binding",
    "validate_retention",
    "validate_sandbox_profile",
    "validate_system_requirements",
    "validate_toolchain_profile",
    "validate_u1",
    "verify_packaged_u1_resources",
    "verify_packaged_u1_manifest",
]
