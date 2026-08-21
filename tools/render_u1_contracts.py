"""Render the reviewed U1 JSON Schemas and externally rooted resource manifest.

This is the sole mechanical writer for the generated contract resources.  The
readable shape declarations live here; emitted JSON is canonical compact UTF-8
without a trailing newline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CONTRACTS = ROOT / "contracts" / "u1"
PACKAGE_CONTRACTS = ROOT / "src" / "kilix_content" / "contracts" / "u1"
MANIFEST_NAME = "kilix.content.u1-resources-v1.json"
RELEASE_ID = "0.2.1"
SCHEMA_BASE = "https://json-schema.org/draft/2020-12/schema"
BASELINE_SCHEMA_NAMES = {
    "kilix.content.asset-v1.schema.json",
    "kilix.install.license-v1.schema.json",
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def closed(
    properties: dict[str, Any], required: tuple[str, ...] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(required if required is not None else properties),
        "properties": properties,
    }


def array(
    items: dict[str, Any],
    *,
    minimum: int = 0,
    maximum: int = 4096,
    unique: bool = True,
) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "array", "items": items, "maxItems": maximum}
    if minimum:
        result["minItems"] = minimum
    if unique:
        result["uniqueItems"] = True
    return result


def ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/$defs/{name}"}


def const(value: Any) -> dict[str, Any]:
    return {"const": value}


def enum(*values: str) -> dict[str, Any]:
    return {"enum": list(values)}


def base_defs() -> dict[str, Any]:
    return {
        "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"},
        "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "hex32": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
        "hex40": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
        "path": {
            "type": "string",
            "pattern": "^[a-z0-9][a-z0-9._/-]{0,255}$",
            "not": {"pattern": "(?:^|/)(?:\\.|\\.\\.)(?:/|$)|//"},
        },
        "resourcePath": {
            "type": "string",
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$",
            "not": {"pattern": "(?:^|/)(?:\\.|\\.\\.)(?:/|$)|//"},
        },
        "absolutePath": {
            "type": "string",
            "pattern": "^/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+$",
        },
        "text": {"type": "string", "minLength": 1, "maxLength": 4096},
        "textMaybeEmpty": {"type": "string", "maxLength": 4096},
        "s64": {"type": "integer", "minimum": 0, "maximum": 9223372036854775807},
        "positive": {"type": "integer", "minimum": 1, "maximum": 9223372036854775807},
        "u32": {"type": "integer", "minimum": 0, "maximum": 4294967295},
        "u64": {"type": "integer", "minimum": 0, "maximum": 18446744073709551615},
        "digestRef": closed({"id": ref("id"), "sha256": ref("digest")}),
        "systemRef": closed({"id": ref("id"), "manifest_sha256": ref("digest")}),
        "licenseRef": closed(
            {
                "id": ref("id"),
                "text_sha256": ref("digest"),
                "decision": enum(
                    "affirmative", "informational", "restricted", "user-supplied"
                ),
            }
        ),
    }


def document(
    schema_id: str, title: str, body: dict[str, Any], defs: dict[str, Any] | None = None
) -> dict[str, Any]:
    result = {"$schema": SCHEMA_BASE, "$id": schema_id, "title": title, **body}
    if defs:
        result["$defs"] = defs
    return result


def source_union() -> dict[str, Any]:
    urls = array(
        {"type": "string", "format": "uri", "pattern": "^https://"},
        minimum=1,
        maximum=16,
    )
    submodule = closed(
        {
            "path": ref("path"),
            "repository": {"type": "string", "format": "uri", "pattern": "^https://"},
            "commit": ref("hex40"),
        }
    )
    return {
        "oneOf": [
            closed(
                {
                    "kind": const("archive"),
                    "urls": urls,
                    "sha256": ref("digest"),
                    "source_bytes": ref("positive"),
                    "source_bytes_max": ref("positive"),
                    "archive_format": enum("tar", "tar.gz", "tar.xz", "zip"),
                }
            ),
            closed(
                {
                    "kind": const("mirrored"),
                    "urls": urls,
                    "sha256": ref("digest"),
                    "source_bytes": ref("positive"),
                    "source_bytes_max": ref("positive"),
                }
            ),
            closed(
                {
                    "kind": const("git"),
                    "repository": {
                        "type": "string",
                        "format": "uri",
                        "pattern": "^https://",
                    },
                    "commit": ref("hex40"),
                    "source_bytes_max": ref("positive"),
                    "submodules": array(submodule, maximum=256),
                }
            ),
            closed(
                {
                    "kind": const("user-supplied"),
                    "input_format": {
                        "type": "string",
                        "pattern": "^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$",
                    },
                    "input_sha256": ref("digest"),
                    "source_bytes": ref("positive"),
                    "source_bytes_max": ref("positive"),
                }
            ),
        ]
    }


def install_shape() -> dict[str, Any]:
    dependency = closed(
        {"id": ref("id"), "role": enum("build", "conversion", "runtime")}
    )
    properties = {
        "schema": const("kilix.content.install-record/v5"),
        "version": {"type": "string", "minLength": 1, "maxLength": 128},
        "source": ref("source"),
        "build_argv": array(ref("textMaybeEmpty"), maximum=128),
        "output_format_version": ref("positive"),
        "source_bytes_max": ref("positive"),
        "temporary_bytes_max": ref("positive"),
        "process_memory_bytes_max": ref("positive"),
        "installed_bytes_max": ref("positive"),
        "temporary_files_max": ref("positive"),
        "installed_files_max": ref("positive"),
        "dependencies": array(dependency, maximum=4096),
        "system_requirements": array(ref("systemRef"), maximum=256),
        "toolchain": ref("digestRef"),
        "sandbox": ref("digestRef"),
        "licenses": array(ref("licenseRef"), minimum=1, maximum=256),
        "output_manifest_sha256": ref("digest"),
    }
    required = tuple(name for name in properties if name != "output_manifest_sha256")
    result = closed(properties, required)
    result["oneOf"] = [
        {
            "properties": {
                "dependencies": {
                    "contains": {
                        "type": "object",
                        "required": ["role"],
                        "properties": {"role": enum("build", "conversion")},
                    }
                },
                "build_argv": {"minItems": 1},
            }
        },
        {
            "properties": {
                "dependencies": {
                    "not": {
                        "contains": {
                            "type": "object",
                            "required": ["role"],
                            "properties": {"role": enum("build", "conversion")},
                        }
                    }
                },
                "build_argv": {"maxItems": 0},
            }
        },
    ]
    return result


def catalog_schemas() -> dict[str, dict[str, Any]]:
    defs = base_defs()
    defs.update({"source": source_union(), "install": install_shape()})
    member = closed(
        {
            "content_id": ref("id"),
            "member_path": ref("path"),
        }
    )
    package = closed(
        {
            "id": ref("id"),
            "stable_slot": ref("id"),
            "install": {
                "allOf": [ref("install"), {"required": ["output_manifest_sha256"]}]
            },
            "members": array(member, minimum=1, maximum=4096),
        }
    )
    content = closed(
        {"id": ref("id"), "stable_slot": ref("id"), "install": ref("install")}
    )
    asset = closed(
        {
            "id": ref("id"),
            "stable_slot": ref("id"),
            "install": ref("install"),
            "output_manifest_sha256": ref("digest"),
        }
    )
    alias = closed(
        {"content_id": ref("id"), "package_id": ref("id"), "member_path": ref("path")}
    )
    profile_ref = closed(
        {"id": ref("id"), "resource_path": ref("path"), "profile_sha256": ref("digest")}
    )
    system_profile_ref = closed(
        {
            "id": ref("id"),
            "resource_path": ref("path"),
            "manifest_sha256": ref("digest"),
        }
    )
    catalog = closed(
        {
            "schema": const("kilix.content.catalog/v5"),
            "release_id": ref("id"),
            "packages": array(package, maximum=4096),
            "contents": array(content, maximum=4096),
            "assets": array(asset, maximum=4096),
            "aliases": array(alias, maximum=4096),
            "system_requirement_profiles": array(system_profile_ref, maximum=256),
            "toolchain_profiles": array(profile_ref, maximum=256),
            "sandbox_profiles": array(profile_ref, maximum=256),
            "license_manifest_id": ref("id"),
        }
    )
    binding_props = {
        "schema": const("kilix.content.install-authority-binding/v1"),
        "kind": enum("asset", "content", "package"),
        "stable_slot": ref("id"),
        "version": {"type": "string", "minLength": 1, "maxLength": 128},
        "release_id": ref("id"),
        "catalog_sha256": ref("digest"),
        "install_record_sha256": ref("digest"),
        "source_identity_sha256": ref("digest"),
        "output_manifest_sha256": ref("digest"),
        "content_ids": array(ref("id"), maximum=4096),
        "alias_members": array(alias, maximum=4096),
    }
    binding = closed(
        binding_props,
        tuple(name for name in binding_props if name != "output_manifest_sha256"),
    )
    binding["oneOf"] = [
        {
            "properties": {
                "kind": const("package"),
                "content_ids": {"minItems": 1},
                "alias_members": {"minItems": 1},
            },
            "required": ["output_manifest_sha256"],
        },
        {
            "properties": {
                "kind": const("asset"),
                "content_ids": {"maxItems": 0},
                "alias_members": {"maxItems": 0},
            },
            "required": ["output_manifest_sha256"],
        },
        {
            "properties": {
                "kind": const("content"),
                "content_ids": {"maxItems": 0},
                "alias_members": {"maxItems": 0},
            },
            "not": {"required": ["output_manifest_sha256"]},
        },
    ]
    output = closed(
        {
            "schema": const("kilix.content.output-binding/v1"),
            "install_authority_sha256": ref("digest"),
            "source_sha256": ref("digest"),
            "input_sha256": ref("digest"),
            "dependency_sha256s": array(ref("digest"), maximum=4096),
            "toolchain_sha256": ref("digest"),
            "sandbox_sha256": ref("digest"),
            "selected_tree_sha256": ref("digest"),
            "selected_bytes": ref("s64"),
            "selected_files": ref("s64"),
            "journal_schema": ref("id"),
            "output_format_version": ref("positive"),
        }
    )
    authorization = closed(
        {
            "schema": const("kilix.install.authorization/v2"),
            "release_id": ref("id"),
            "catalog_sha256": ref("digest"),
            "install_authority_sha256": ref("digest"),
            "output_binding_sha256": ref("digest"),
            "authorization_id": ref("id"),
            "record_sha256": ref("digest"),
        }
    )
    return {
        "kilix.content.catalog-v5.schema.json": document(
            "kilix.content.catalog/v5", "Kilix content catalog v5", catalog, defs
        ),
        "kilix.content.install-record-v5.schema.json": document(
            "kilix.content.install-record/v5",
            "Kilix install record v5",
            install_shape(),
            defs,
        ),
        "kilix.content.install-authority-binding-v1.schema.json": document(
            "kilix.content.install-authority-binding/v1",
            "Kilix install authority binding v1",
            binding,
            defs,
        ),
        "kilix.content.output-binding-v1.schema.json": document(
            "kilix.content.output-binding/v1", "Kilix output binding v1", output, defs
        ),
        "kilix.install.authorization-v2.schema.json": document(
            "kilix.install.authorization/v2",
            "Kilix installation authorization v2",
            authorization,
            defs,
        ),
    }


def profile_schemas() -> dict[str, dict[str, Any]]:
    defs = base_defs()
    snapshot = closed(
        {
            "distribution": const("debian"),
            "suite": const("trixie"),
            "timestamp": {"type": "string", "pattern": "^[0-9]{8}T[0-9]{6}Z$"},
            "release_sha256": ref("digest"),
        }
    )
    package = closed(
        {
            "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9+.-]{0,127}$"},
            "version": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}$",
            },
            "architecture": enum("amd64", "arm64", "riscv64"),
            "sha256": ref("digest"),
        }
    )
    system = closed(
        {
            "schema": const("kilix.content.system-requirements/v1"),
            "id": ref("id"),
            "release_snapshot": snapshot,
            "architecture": enum("amd64", "arm64", "riscv64"),
            "packages": array(package, maximum=1024),
            "manifest_sha256": ref("digest"),
        }
    )
    file_entry = closed(
        {"path": ref("absolutePath"), "mode": ref("s64"), "sha256": ref("digest")}
    )
    entrypoint = closed(
        {
            "id": ref("id"),
            "executable": ref("absolutePath"),
            "argv": array(ref("textMaybeEmpty"), maximum=64),
        }
    )
    wheel = closed({"name": ref("id"), "version": ref("text"), "sha256": ref("digest")})
    offline_python = closed(
        {
            "enabled": {"type": "boolean"},
            "python_version": ref("text"),
            "python_sha256": ref("digest"),
            "uv_version": ref("text"),
            "uv_sha256": ref("digest"),
            "project_sha256": ref("digest"),
            "lock_sha256": ref("digest"),
            "wheels": array(wheel, maximum=1024),
        }
    )
    environment = closed(
        {
            "name": {"type": "string", "pattern": "^[A-Z_][A-Z0-9_]{0,63}$"},
            "value": ref("textMaybeEmpty"),
        }
    )
    abi = closed(
        {
            "libc": const("glibc"),
            "libc_version": ref("text"),
            "kernel_abi": ref("text"),
            "machine": enum("amd64", "arm64", "riscv64"),
            "endianness": enum("big", "little"),
            "pointer_bits": const(64),
        }
    )
    toolchain = closed(
        {
            "schema": const("kilix.content.toolchain-profile/v1"),
            "id": ref("id"),
            "release_snapshot": snapshot,
            "architecture": enum("amd64", "arm64", "riscv64"),
            "packages": array(package, maximum=1024),
            "executables": array(file_entry, maximum=2048),
            "libraries": array(file_entry, maximum=2048),
            "entrypoints": array(entrypoint, minimum=1, maximum=128),
            "offline_python": offline_python,
            "environment": array(environment, maximum=7),
            "abi": abi,
            "profile_sha256": ref("digest"),
        }
    )
    mount = closed(
        {
            "source_role": ref("id"),
            "target": ref("absolutePath"),
            "kind": enum("bind", "proc", "tmpfs"),
            "read_only": {"type": "boolean"},
            "noexec": {"type": "boolean"},
            "nosuid": {"type": "boolean"},
            "nodev": {"type": "boolean"},
        }
    )
    sandbox = closed(
        {
            "schema": const("kilix.content.sandbox-profile/v1"),
            "id": ref("id"),
            "mounts": array(mount, minimum=1, maximum=128),
            "namespaces": closed(
                {
                    name: const("fresh")
                    for name in ("user", "mount", "pid", "network", "ipc")
                }
            ),
            "capabilities": array({"type": "string"}, maximum=0),
            "seccomp": closed(
                {
                    "architecture": enum("amd64", "arm64", "riscv64"),
                    "default_action": const("allow-except-denied"),
                    "denied_syscalls": array(ref("id"), minimum=21, maximum=256),
                }
            ),
            "devices": {
                "type": "array",
                "const": ["/dev/null", "/dev/random", "/dev/urandom", "/dev/zero"],
            },
            "proc_policy": closed(
                {
                    "mounted": const(True),
                    "read_only": const(True),
                    "hidepid": const(2),
                    "mqueue_absent": const(True),
                    "shm_absent": const(True),
                }
            ),
            "resource_limit_shape": closed(
                {
                    name: const("capacity-policy")
                    for name in ("memory", "pids", "cpu", "tmpfs_bytes", "tmpfs_inodes")
                }
            ),
            "quota_backend": closed(
                {
                    "kind": const("tmpfs-cgroup-v2"),
                    "enforced": const(True),
                    "filesystem_accounting": const(True),
                }
            ),
            "profile_sha256": ref("digest"),
        }
    )
    license_entry = closed(
        {
            "id": ref("id"),
            "path": ref("resourcePath"),
            "text_sha256": ref("digest"),
            "decision": enum(
                "affirmative", "informational", "restricted", "user-supplied"
            ),
        }
    )
    licenses = closed(
        {
            "schema": const("kilix.content.license-manifest/v1"),
            "release_id": ref("id"),
            "licenses": array(license_entry, minimum=1, maximum=256),
        }
    )
    return {
        "kilix.content.system-requirements-v1.schema.json": document(
            "kilix.content.system-requirements/v1",
            "Kilix system requirements v1",
            system,
            defs,
        ),
        "kilix.content.toolchain-profile-v1.schema.json": document(
            "kilix.content.toolchain-profile/v1",
            "Kilix toolchain profile v1",
            toolchain,
            defs,
        ),
        "kilix.content.sandbox-profile-v1.schema.json": document(
            "kilix.content.sandbox-profile/v1",
            "Kilix sandbox profile v1",
            sandbox,
            defs,
        ),
        "kilix.content.license-manifest-v1.schema.json": document(
            "kilix.content.license-manifest/v1",
            "Kilix license manifest v1",
            licenses,
            defs,
        ),
    }


def capacity_schemas() -> dict[str, dict[str, Any]]:
    defs = base_defs()
    capacity_phases = (
        "RESERVED",
        "SUBMITTER_ARMING",
        "SUBMITTER_LIVE",
        "UNIT_PREPARED",
        "UNIT_MAYBE_SENT",
        "UNIT_ACKNOWLEDGED",
        "UNIT_OBSERVED",
        "UNIT_BOUND",
        "GO_SENT",
        "STAGE_RETAINED",
        "RELEASING",
        "RELEASE_PROOFED",
        "RETENTION_INTENT_RESERVED",
        "RETENTION_ACCOUNTED",
        "RETENTION_HANDOFF_RELEASING",
        "RETENTION_HANDOFF_PROOFED",
        "RETENTION_PREPARED",
        "RETENTION_MARKER_DURABLE",
        "RETENTION_RELATION_DURABLE",
        "RETENTION_READY",
        "RETENTION_HANDOFF_COMPLETE",
    )
    root = closed(
        {
            "role": enum(
                *sorted(
                    (
                        "install-authorizations-v2",
                        "installed-data",
                        "license-receipts-v1",
                        "resumable-cache",
                        "transaction-state",
                    )
                )
            ),
            "relative_path": ref("path"),
            "descriptor_relative": const(True),
        }
    )
    filesystem = closed(
        {
            "filesystem_type": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9._+-]{0,31}$",
            },
            "filesystem_magic": ref("u64"),
            "allocation_rounding": const("f-frsize-ceil"),
            "stable_block_semantics": const(True),
            "identity_policy": const("r7-capacity-key"),
        }
    )
    floor = closed(
        {
            "hardware_tier": ref("id"),
            "filesystem_type": {
                "type": "string",
                "pattern": "^[a-z0-9][a-z0-9._+-]{0,31}$",
            },
            "fixed_min_bytes": ref("positive"),
            "proportional_numerator": ref("positive"),
            "proportional_denominator": ref("positive"),
            "fixed_min_inodes": ref("positive"),
            "metadata_bytes_per_inode": ref("positive"),
            "overflow_mode": const("checked-s64"),
            "rounding_mode": const("checked-ceil"),
        }
    )
    metrics = closed(
        {
            name: ref("positive")
            for name in (
                "bytes",
                "inodes",
                "files",
                "directory_entries",
                "retained_crash_states",
            )
        }
    )
    phase_maximum = closed(
        {
            "owner_kind": enum("capacity", "retention-capacity", "transaction"),
            "phase": enum(*capacity_phases),
            "root_role": root["properties"]["role"],
            "maximum": metrics,
        }
    )
    helper = closed({"name": ref("id"), "memory_bytes_max": ref("positive")})
    memory = closed(
        {
            "page_size_bytes": ref("positive"),
            "fixed_overhead_bytes": ref("positive"),
            "transaction_process_bytes_max": ref("positive"),
            "tmpfs_bytes_max": ref("positive"),
            "helper_overheads": array(helper, minimum=3, maximum=3),
            "per_transaction_bytes": ref("positive"),
            "simultaneous_transactions_max": ref("positive"),
            "aggregate_reservation_bytes_max": ref("positive"),
            "addition": const("checked-s64"),
            "multiplication": const("checked-s64"),
            "page_rounding": const("checked-ceil"),
        }
    )
    growth = closed(
        {
            "filesystem_type": filesystem["properties"]["filesystem_type"],
            "bytes": ref("positive"),
        }
    )
    retention_limits = closed(
        {
            "retained_unique_objects_max": ref("positive"),
            "retained_allocated_bytes_max": ref("positive"),
            "retained_inodes_max": ref("positive"),
            "retained_versions_per_stable_slot_max": ref("positive"),
            "ambiguous_retained_objects_max": ref("positive"),
            "pending_relations_max": ref("positive"),
            "pending_bytes_max": ref("positive"),
            "pending_inodes_max": ref("positive"),
            "directory_entry_growth_bytes_max": array(growth, minimum=1, maximum=16),
        }
    )
    scan_bounds = closed(
        {
            name: ref("positive")
            for name in (
                "roots_max",
                "filesystems_max",
                "reservations_max",
                "retention_records_max",
                "relations_max",
                "objects_max",
                "journals_max",
                "directory_children_max",
                "graph_nodes_max",
                "graph_edges_max",
                "bytes_max",
                "recursion_depth_max",
            )
        }
    )
    policy = closed(
        {
            "schema": const("kilix.content.capacity-reserve/v2"),
            "release_id": ref("id"),
            "policy_id": ref("id"),
            "policy_version": ref("positive"),
            "hardware_tier": const("test-vector"),
            "tier_selection_inputs": closed(
                {
                    "memory_class": ref("id"),
                    "cpu_class": ref("id"),
                    "storage_class": ref("id"),
                    "selection_rule": const("externally-measured-exact-match"),
                }
            ),
            "ledger_schema": const("kilix.content.capacity-ledger/v2"),
            "reservation_schema": const("kilix.content.capacity-generation/v2"),
            "memory_equation": memory,
            "writable_roots": array(root, minimum=5, maximum=5),
            "supported_filesystems": array(filesystem, minimum=1, maximum=16),
            "filesystem_floor_formulas": array(floor, minimum=1, maximum=64),
            "phase_maxima": array(phase_maximum, minimum=1, maximum=256),
            "retention_limits": retention_limits,
            "scan_bounds": scan_bounds,
        }
    )
    lock = closed(
        {
            "schema": const("kilix.content.capacity-lock/v2"),
            "reservation_id": ref("id"),
            "release_id": ref("id"),
            "policy_sha256": ref("digest"),
            "creator_boot_id": ref("hex32"),
        }
    )
    filesystem_reservation = closed(
        {
            "filesystem_key_sha256": ref("digest"),
            "mount_identity": ref("digest"),
            "bytes": ref("positive"),
            "inodes": ref("positive"),
        }
    )
    root_identity = closed(
        {
            "role": root["properties"]["role"],
            "descriptor_identity_sha256": ref("digest"),
            "mount_identity": ref("digest"),
        }
    )
    deadlines = closed(
        {"submission_monotonic_ns": ref("u64"), "recovery_monotonic_ns": ref("u64")}
    )
    common_generation = {
        "schema": const("kilix.content.capacity-generation/v2"),
        "owner_kind": enum("capacity", "retention"),
        "phase": ref("id"),
        "reservation_id": ref("id"),
        "generation": ref("s64"),
        "predecessor_sha256": ref("digest"),
        "release_id": ref("id"),
        "policy_sha256": ref("digest"),
        "transaction_id": ref("id"),
        "install_authority_sha256": ref("digest"),
        "creator_boot_id": ref("hex32"),
        "owner_pid": ref("u32"),
        "owner_start_time": ref("u64"),
        "memory_reserved_bytes": ref("positive"),
        "filesystem_reservations": array(filesystem_reservation, minimum=1, maximum=32),
        "root_identities": array(root_identity, minimum=5, maximum=5),
        "stable_lock_identity": ref("digest"),
        "deadlines": deadlines,
    }
    capacity_payloads = {
        "RESERVED": ("reservation_name", "filesystem_set_sha256"),
        "SUBMITTER_ARMING": (
            "helper_pid",
            "guard_nonce",
            "socket_identity_sha256",
            "deadline_identity_sha256",
        ),
        "SUBMITTER_LIVE": (
            "helper_pid",
            "guard_nonce",
            "socket_identity_sha256",
            "deadline_identity_sha256",
            "guard_descriptor_sha256",
        ),
        "UNIT_PREPARED": (
            "manager_identity_sha256",
            "job_id",
            "unit_name",
            "cgroup_identity_sha256",
        ),
        "UNIT_MAYBE_SENT": (
            "manager_identity_sha256",
            "job_id",
            "unit_name",
            "cgroup_identity_sha256",
            "request_sha256",
        ),
        "UNIT_ACKNOWLEDGED": (
            "manager_identity_sha256",
            "job_id",
            "unit_name",
            "cgroup_identity_sha256",
            "reply_sha256",
        ),
        "UNIT_OBSERVED": (
            "manager_identity_sha256",
            "job_id",
            "unit_name",
            "cgroup_identity_sha256",
            "observation_sha256",
        ),
        "UNIT_BOUND": (
            "manager_identity_sha256",
            "job_id",
            "unit_name",
            "cgroup_identity_sha256",
            "unit_descriptor_sha256",
        ),
        "GO_SENT": ("unit_descriptor_sha256", "go_message_sha256"),
        "STAGE_RETAINED": (
            "unit_descriptor_sha256",
            "stage_descriptor_sha256",
            "stage_charge_sha256",
        ),
        "RELEASING": ("stage_charge_sha256", "resource_absence_sha256"),
        "RELEASE_PROOFED": ("release_proof_sha256",),
    }
    retention_payloads = {
        "RETENTION_INTENT_RESERVED": (
            "intent_sha256",
            "pre_admission_scan_sha256",
            "component_envelope_sha256",
        ),
        "RETENTION_ACCOUNTED": (
            "intent_sha256",
            "transaction_generation_sha256",
            "accounted_sha256",
        ),
        "RETENTION_HANDOFF_RELEASING": (
            "intent_sha256",
            "transaction_generation_sha256",
            "accounted_sha256",
            "handoff_nonce",
        ),
        "RETENTION_HANDOFF_PROOFED": (
            "intent_sha256",
            "transaction_generation_sha256",
            "accounted_sha256",
            "handoff_sha256",
        ),
    }
    branches = []
    for owner, payloads in (
        ("capacity", capacity_payloads),
        ("retention", retention_payloads),
    ):
        for phase, fields in payloads.items():
            payload_properties = {}
            for field in fields:
                if field == "helper_pid":
                    payload_properties[field] = ref("u32")
                elif field in {"job_id", "unit_name", "reservation_name"}:
                    payload_properties[field] = ref("id")
                else:
                    payload_properties[field] = ref("digest")
            branches.append(
                closed(
                    {
                        **common_generation,
                        "owner_kind": const(owner),
                        "phase": const(phase),
                        "phase_payload": closed(payload_properties),
                    }
                )
            )
    generation = {"oneOf": branches}
    ordinary = closed(
        {
            "schema": const("kilix.content.release-proof/v2"),
            "release_kind": const("ordinary"),
            "permanent": const(False),
            "reservation_id": ref("id"),
            "generation": ref("positive"),
            "releasing_generation_sha256": ref("digest"),
            "resource_absence_sha256": ref("digest"),
            "phase_payload": closed(
                {
                    "next_phase": const("RELEASE_PROOFED"),
                    "tombstone_sha256": ref("digest"),
                }
            ),
        }
    )
    handoff = closed(
        {
            "schema": const("kilix.content.release-proof/v2"),
            "release_kind": const("retention_handoff"),
            "permanent": const(True),
            "reservation_id": ref("id"),
            "generation": ref("positive"),
            "releasing_generation_sha256": ref("digest"),
            "resource_absence_sha256": ref("digest"),
            "phase_payload": closed(
                {
                    "next_phase": const("RETENTION_HANDOFF_PROOFED"),
                    "intent_sha256": ref("digest"),
                    "accounted_sha256": ref("digest"),
                    "handoff_sha256": ref("digest"),
                }
            ),
        }
    )
    return {
        "kilix.content.capacity-reserve-v2.schema.json": document(
            "kilix.content.capacity-reserve/v2",
            "Kilix capacity policy v2",
            policy,
            defs,
        ),
        "kilix.content.capacity-lock-v2.schema.json": document(
            "kilix.content.capacity-lock/v2", "Kilix capacity lock v2", lock, defs
        ),
        "kilix.content.capacity-generation-v2.schema.json": document(
            "kilix.content.capacity-generation/v2",
            "Kilix capacity generation v2",
            generation,
            defs,
        ),
        "kilix.content.release-proof-v2.schema.json": document(
            "kilix.content.release-proof/v2",
            "Kilix capacity release proof v2",
            {"oneOf": [ordinary, handoff]},
            defs,
        ),
    }


def retention_defs() -> dict[str, Any]:
    defs = base_defs()
    defs["objectIdentity"] = closed(
        {
            "install_authority_sha256": ref("digest"),
            "output_binding_sha256": ref("digest"),
        }
    )
    defs["relationIdentity"] = closed(
        {
            "stable_slot_sha256": ref("digest"),
            "install_authority_sha256": ref("digest"),
            "output_binding_sha256": ref("digest"),
        }
    )
    relation_array = array(ref("relationIdentity"), maximum=4096)
    object_array = array(ref("objectIdentity"), maximum=4096)
    version = closed({"stable_slot_sha256": ref("digest"), "count": ref("positive")})
    defs["logicalState"] = closed(
        {
            "schema": const("kilix.content.retention-logical-state/v1"),
            "release_id": ref("id"),
            "O_materialized": object_array,
            "O_referenced": object_array,
            "O_counted": object_array,
            "R_present": relation_array,
            "R_pending": relation_array,
            "R_counted": relation_array,
            "retained_unique_objects": ref("s64"),
            "retained_versions": array(version, maximum=4096),
            "account_retention_quarantined": {"type": "boolean"},
            "quarantine_reasons": array(ref("id"), maximum=32),
            "retention_admission_closed": {"type": "boolean"},
            "admission_closed_reasons": array(ref("id"), maximum=32),
        }
    )
    defs["physicalIdentity"] = closed(
        {
            "component_role": enum(
                "D", "M", "R", "P", "H", "journal", "object", "ambiguity"
            ),
            "root_identity_sha256": ref("digest"),
            "mount_identity_sha256": ref("digest"),
            "device": ref("positive"),
            "inode": ref("positive"),
            "object_type": enum("directory", "regular"),
            "descriptor_identity_sha256": ref("digest"),
        }
    )
    defs["physicalComponent"] = closed(
        {
            "identity": ref("physicalIdentity"),
            "charge_source": enum("actual", "ambiguity", "prospective"),
            "bytes": ref("s64"),
            "inodes": ref("s64"),
            "directory_growth_bytes": ref("s64"),
        }
    )
    defs["filesystemUnion"] = closed(
        {
            "filesystem_key": ref("digest"),
            "components": array(ref("physicalComponent"), maximum=4096),
            "actual_bytes": ref("s64"),
            "actual_inodes": ref("s64"),
            "prospective_bytes": ref("s64"),
            "prospective_inodes": ref("s64"),
            "ambiguity_bytes": ref("s64"),
            "ambiguity_inodes": ref("s64"),
            "directory_growth_bytes": ref("s64"),
            "envelope_sha256": ref("digest"),
        }
    )
    defs["physicalState"] = closed(
        {
            "schema": const("kilix.content.retention-physical-state/v1"),
            "release_id": ref("id"),
            "filesystem_unions": array(ref("filesystemUnion"), maximum=32),
            "scan_complete": {"type": "boolean"},
            "incomplete_representations": array(ref("digest"), maximum=4096),
            "scan_bound_exhausted": {"type": "boolean"},
        }
    )
    semantic = closed(
        {"derivation": ref("id"), "input_sha256s": array(ref("digest"), maximum=32)}
    )
    common_component = {
        "schema": const("kilix.content.retention-component/v1"),
        "role": enum("D", "M", "R", "P", "H"),
        "filesystem_key": ref("digest"),
        "root_identity": ref("digest"),
        "nearest_existing_ancestor": ref("digest"),
        "final_relative_path": ref("path"),
        "temporary_basename": {
            "type": "string",
            "pattern": "^\\.new-retention-[0-9a-f]{64}-(?:dir-[0-9]{1,2}|marker|relation|accounted|handoff)$",
        },
        "uid": ref("s64"),
        "gid": ref("s64"),
        "mode": ref("s64"),
        "object_type": enum("directory", "regular"),
        "max_bytes": ref("positive"),
        "max_inodes": ref("positive"),
        "max_parent_growth": ref("s64"),
        "semantic_input": semantic,
    }
    defs["component"] = {
        "oneOf": [
            closed({**common_component, "role": const("D"), "ordinal": ref("s64")}),
            *[
                closed({**common_component, "role": const(role)})
                for role in ("M", "R", "P", "H")
            ],
        ]
    }
    defs["envelopeEntry"] = closed(
        {
            "role": enum("D", "M", "R", "P", "H"),
            "ordinal": ref("s64"),
            "component_sha256": ref("digest"),
            "max_bytes": ref("positive"),
            "max_inodes": ref("positive"),
            "max_parent_growth": ref("s64"),
        }
    )
    defs["attestation"] = closed(
        {
            "descriptor_sha256": ref("digest"),
            "content_sha256": ref("digest"),
            "bytes": ref("s64"),
            "files": ref("s64"),
        }
    )
    defs["treeAttestation"] = closed(
        {
            "tree_sha256": ref("digest"),
            "content_sha256": ref("digest"),
            "bytes": ref("s64"),
            "files": ref("s64"),
        }
    )
    common_descriptor = {
        "role": enum("D", "M", "R", "P", "H", "object"),
        "filesystem_key": ref("digest"),
        "root_identity": ref("digest"),
        "mount_identity": ref("digest"),
        "descriptor_identity_sha256": ref("digest"),
        "relative_path": ref("path"),
        "uid": ref("s64"),
        "gid": ref("s64"),
        "mode": ref("s64"),
        "object_type": enum("directory", "regular"),
        "content_sha256": ref("digest"),
        "bytes": ref("s64"),
        "inodes": ref("s64"),
    }
    defs["actualDescriptor"] = {
        "oneOf": [
            closed({**common_descriptor, "role": const("object")}),
            closed({**common_descriptor, "role": const("D")}),
            *[
                closed({**common_descriptor, "role": const(role), "nlink": const(1)})
                for role in ("M", "R", "P", "H")
            ],
        ]
    }
    defs["recoverySnapshot"] = closed(
        {
            "transaction_phase": enum(
                "RETENTION_PREPARED",
                "RETENTION_MARKER_DURABLE",
                "RETENTION_RELATION_DURABLE",
                "RETENTION_READY",
                "RETENTION_ACCOUNTED",
                "RETENTION_HANDOFF_COMPLETE",
            ),
            "capacity_phase": enum(
                "RETENTION_INTENT_RESERVED",
                "RETENTION_ACCOUNTED",
                "RETENTION_HANDOFF_RELEASING",
                "RETENTION_HANDOFF_PROOFED",
                "tombstone",
                "absent",
            ),
            "component_states": array(
                closed(
                    {
                        "role": enum("D", "M", "R", "P", "H"),
                        "ordinal": ref("s64"),
                        "state": enum(
                            "both-absent",
                            "complete-temporary-only",
                            "torn-temporary-only",
                            "empty-directory-temporary-only",
                            "final-only-parent-durability-unknown",
                            "recognized-temporary-and-final",
                            "no-replace-collision",
                            "unexpected-or-hostile",
                        ),
                    }
                ),
                minimum=4,
                maximum=36,
            ),
            "capacity_names": closed(
                {
                    "reservation_present": {"type": "boolean"},
                    "tombstone_present": {"type": "boolean"},
                }
            ),
        }
    )
    return defs


def retention_schemas() -> dict[str, dict[str, Any]]:
    defs = retention_defs()
    transaction_phases = (
        "RETENTION_PREPARED",
        "RETENTION_MARKER_DURABLE",
        "RETENTION_RELATION_DURABLE",
        "RETENTION_READY",
        "RETENTION_ACCOUNTED",
        "RETENTION_HANDOFF_COMPLETE",
    )
    target = closed(
        {
            "role": enum("D", "M", "R", "P", "H"),
            "ordinal": ref("s64"),
            "relative_path": ref("path"),
        }
    )
    temporary = closed(
        {
            "role": enum("D", "M", "R", "P", "H"),
            "ordinal": ref("s64"),
            "basename": {"type": "string", "pattern": "^\\.new-retention-"},
        }
    )
    derivation = closed({"role": enum("D", "M", "R", "P", "H"), "rule": ref("id")})
    component_schema = closed(
        {
            "role": enum("D", "M", "R", "P", "H"),
            "schema_id": const("kilix.content.retention-component/v1"),
        }
    )
    maximum = closed(
        {
            "role": enum("D", "M", "R", "P", "H"),
            "ordinal": ref("s64"),
            "bytes": ref("positive"),
            "inodes": ref("positive"),
            "parent_growth": ref("s64"),
        }
    )
    child_rule = closed(
        {
            "ordinal": ref("s64"),
            "phase": enum(*transaction_phases),
            "allowed_final_roles": array(enum("D", "M", "R", "P", "H"), maximum=5),
            "current_temporary_allowed": {"type": "boolean"},
        }
    )
    root_identity = closed({"role": ref("id"), "identity_sha256": ref("digest")})
    intent = closed(
        {
            "schema": const("kilix.content.retention-intent/v1"),
            "transaction_id": ref("id"),
            "reservation_id": ref("id"),
            "creation_nonce": ref("digest"),
            "handoff_nonce": ref("digest"),
            "stable_slot_sha256": ref("digest"),
            "install_authority_sha256": ref("digest"),
            "output_binding_sha256": ref("digest"),
            "release_id": ref("id"),
            "catalog_sha256": ref("digest"),
            "capacity_policy_sha256": ref("digest"),
            "profile_sha256": ref("digest"),
            "object_identity": ref("objectIdentity"),
            "descriptor_attestation": ref("attestation"),
            "selected_tree_attestation": ref("treeAttestation"),
            "filesystem_keys": array(ref("digest"), minimum=1, maximum=32),
            "root_identities": array(root_identity, minimum=1, maximum=32),
            "pre_admission_set_sha256": ref("digest"),
            "pre_admission_scan_sha256": ref("digest"),
            "proposed_logical_state": ref("logicalState"),
            "proposed_physical_state": ref("physicalState"),
            "component_envelope": array(ref("envelopeEntry"), minimum=4, maximum=36),
            "component_envelope_sha256": ref("digest"),
            "components": array(ref("component"), minimum=4, maximum=36),
            "target_names": array(target, minimum=4, maximum=36),
            "temporary_names": array(temporary, minimum=4, maximum=36),
            "derivation_rules": array(derivation, minimum=5, maximum=5),
            "component_schemas": array(component_schema, minimum=5, maximum=5),
            "component_maxima": array(maximum, minimum=4, maximum=36),
            "directory_child_rules": array(child_rule, maximum=192),
        }
    )
    envelope = closed(
        {
            "schema": const("kilix.content.retention-envelope/v1"),
            "intent_identity": closed(
                {
                    "transaction_id": ref("id"),
                    "reservation_id": ref("id"),
                    "creation_nonce": ref("digest"),
                }
            ),
            "entries": array(ref("envelopeEntry"), minimum=4, maximum=36),
            "envelope_sha256": ref("digest"),
        }
    )
    common_mr = {
        "release_id": ref("id"),
        "transaction_id": ref("id"),
        "reservation_id": ref("id"),
        "intent_sha256": ref("digest"),
        "component_envelope_sha256": ref("digest"),
        "intent_capacity_generation_sha256": ref("digest"),
        "stable_slot_sha256": ref("digest"),
        "install_authority_sha256": ref("digest"),
        "output_binding_sha256": ref("digest"),
        "catalog_sha256": ref("digest"),
        "profile_sha256": ref("digest"),
        "predecessor_transaction_generation_sha256": ref("digest"),
        "descriptor": ref("actualDescriptor"),
        "semantic_payload_sha256": ref("digest"),
    }
    marker = closed(
        {
            "schema": const("kilix.content.retention-marker/v1"),
            "record_kind": const("M"),
            **common_mr,
        }
    )
    relation = closed(
        {
            "schema": const("kilix.content.retention-relation/v1"),
            "record_kind": const("R"),
            **common_mr,
            "marker_sha256": ref("digest"),
            "relation_identity": ref("relationIdentity"),
        }
    )
    common_generation = {
        "schema": const("kilix.content.transaction-generation/v1"),
        "owner_kind": const("retention"),
        "phase": ref("id"),
        "generation": ref("positive"),
        "predecessor_sha256": ref("digest"),
        "transaction_id": ref("id"),
        "reservation_id": ref("id"),
        "intent_sha256": ref("digest"),
    }
    transaction_payloads = {
        "RETENTION_PREPARED": (
            "intent_capacity_generation_sha256",
            "component_envelope_sha256",
        ),
        "RETENTION_MARKER_DURABLE": ("marker_sha256",),
        "RETENTION_RELATION_DURABLE": ("marker_sha256", "relation_sha256"),
        "RETENTION_READY": ("marker_sha256", "relation_sha256"),
        "RETENTION_ACCOUNTED": ("accounted_sha256",),
        "RETENTION_HANDOFF_COMPLETE": (
            "accounted_sha256",
            "handoff_sha256",
            "capacity_absence_sha256",
            "fresh_scan_sha256",
        ),
    }
    generation_branches = [
        closed(
            {
                **common_generation,
                "phase": const(phase),
                "phase_payload": closed({field: ref("digest") for field in fields}),
            }
        )
        for phase, fields in transaction_payloads.items()
    ]
    child = closed(
        {
            "name": {
                "type": "string",
                "oneOf": [
                    {"pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
                    {
                        "pattern": "^\\.new-retention-[0-9a-f]{64}-(?:dir-[0-9]{1,2}|marker|relation|accounted|handoff)$"
                    },
                ],
            },
            "role": enum("D", "M", "R", "P", "H", "baseline"),
            "object_type": enum("directory", "regular"),
            "descriptor_sha256": ref("digest"),
        }
    )
    temporary_presence = {
        "oneOf": [
            closed({"present": const(False)}),
            closed({"present": const(True), "child": child}),
        ]
    }
    observation = closed(
        {
            "schema": const("kilix.content.directory-observation/v1"),
            "role": const("D"),
            "relative_path": ref("path"),
            "uid": ref("s64"),
            "gid": ref("s64"),
            "mode": ref("s64"),
            "filesystem_key": ref("digest"),
            "root_identity": ref("digest"),
            "mount_identity": ref("digest"),
            "baseline_children": array(child, maximum=4096),
            "baseline_children_sha256": ref("digest"),
            "phase": enum(*transaction_payloads),
            "permitted_delta": array(child, maximum=4096),
            "current_temporary": temporary_presence,
            "observed_children": array(child, maximum=4096),
        }
    )
    reserved_maximum = closed(
        {
            "bytes": ref("positive"),
            "inodes": ref("positive"),
            "parent_growth": ref("s64"),
        }
    )
    accounted = closed(
        {
            "schema": const("kilix.content.retention-accounted/v1"),
            "owner_kind": const("retention"),
            "record_kind": const("P"),
            "release_id": ref("id"),
            "transaction_id": ref("id"),
            "reservation_id": ref("id"),
            "intent": intent,
            "intent_sha256": ref("digest"),
            "intent_capacity_generation_sha256": ref("digest"),
            "ready_transaction_generation_sha256": ref("digest"),
            "object_descriptor": ref("actualDescriptor"),
            "marker_descriptor": ref("actualDescriptor"),
            "relation_descriptor": ref("actualDescriptor"),
            "object_content_sha256": ref("digest"),
            "marker_content_sha256": ref("digest"),
            "relation_content_sha256": ref("digest"),
            "logical_state": ref("logicalState"),
            "logical_state_sha256": ref("digest"),
            "physical_state": ref("physicalState"),
            "physical_state_sha256": ref("digest"),
            "capacity_policy_sha256": ref("digest"),
            "profile_sha256": ref("digest"),
            "catalog_sha256": ref("digest"),
            "proof_nonce": ref("digest"),
            "p_final_relative_path": ref("path"),
            "p_reserved_maximum": reserved_maximum,
        }
    )
    next_capacity = closed(
        {
            "owner_kind": const("retention"),
            "phase": const("RETENTION_HANDOFF_PROOFED"),
            "generation": ref("positive"),
            "predecessor_sha256": ref("digest"),
        }
    )
    absence = closed(
        {
            "unit_absent": const(True),
            "helper_absent": const(True),
            "cgroup_absent": const(True),
            "stage_absent": const(True),
            "future_writer_absent": const(True),
            "sha256": ref("digest"),
        }
    )
    names = closed(
        {
            "capacity_final": ref("path"),
            "capacity_tombstone": ref("path"),
            "h_temporary_basename": {
                "type": "string",
                "pattern": "^\\.new-retention-[0-9a-f]{64}-handoff$",
            },
            "h_final_relative_path": ref("path"),
        }
    )
    handoff = closed(
        {
            "schema": const("kilix.content.retention-handoff-proof/v1"),
            "owner_kind": const("retention"),
            "record_kind": const("H"),
            "release_kind": const("retention_handoff"),
            "permanent": const(True),
            "release_id": ref("id"),
            "transaction_id": ref("id"),
            "reservation_id": ref("id"),
            "intent_sha256": ref("digest"),
            "handoff_nonce": ref("digest"),
            "accounted_sha256": ref("digest"),
            "object_descriptor": ref("actualDescriptor"),
            "marker_descriptor": ref("actualDescriptor"),
            "relation_descriptor": ref("actualDescriptor"),
            "accounted_descriptor": ref("actualDescriptor"),
            "object_content_sha256": ref("digest"),
            "marker_content_sha256": ref("digest"),
            "relation_content_sha256": ref("digest"),
            "accounted_content_sha256": ref("digest"),
            "ready_transaction_generation_sha256": ref("digest"),
            "accounted_transaction_generation_sha256": ref("digest"),
            "capacity_accounted_generation_sha256": ref("digest"),
            "capacity_releasing_generation_sha256": ref("digest"),
            "next_capacity_fields": next_capacity,
            "logical_state": ref("logicalState"),
            "logical_state_sha256": ref("digest"),
            "physical_state": ref("physicalState"),
            "physical_state_sha256": ref("digest"),
            "absence_evidence": absence,
            "names": names,
            "profile_sha256": ref("digest"),
            "catalog_sha256": ref("digest"),
        }
    )
    component_row = closed(
        {
            "role": enum("D", "M", "R", "P", "H"),
            "observed_state": ref("id"),
            "classification": ref("id"),
            "allowed_next_record": ref("id"),
            "charge_kind": ref("id"),
            "quarantine": {"type": "boolean"},
            "exposure_allowed": {"type": "boolean"},
            "first_result": ref("id"),
            "repeated_result": ref("id"),
        }
    )
    handoff_row = closed(
        {
            "id": ref("id"),
            "transaction_phase": enum(*transaction_payloads),
            "capacity_phase": enum(
                "RETENTION_INTENT_RESERVED",
                "RETENTION_ACCOUNTED",
                "RETENTION_HANDOFF_RELEASING",
                "RETENTION_HANDOFF_PROOFED",
                "tombstone",
                "absent",
            ),
            "h_state": enum("absent", "final", "temporary"),
            "expected_action": ref("id"),
            "charge_kind": ref("id"),
            "quarantine": {"type": "boolean"},
            "selection_allowed": {"type": "boolean"},
            "cleanup_allowed": {"type": "boolean"},
            "first_result": ref("id"),
            "repeated_result": ref("id"),
        }
    )
    impossible_row = closed(
        {
            "reason": ref("id"),
            "observed": ref("recoverySnapshot"),
            "expected": ref("recoverySnapshot"),
            "outcome": closed(
                {
                    "quarantine": const(True),
                    "retain_charge": const(True),
                    "selection": const(False),
                    "return_path": const(False),
                    "cleanup": const(False),
                    "credit": const(False),
                }
            ),
        }
    )
    recovery = closed(
        {
            "schema": const("kilix.content.recovery-vector/v1"),
            "release_id": ref("id"),
            "executable": const(False),
            "component_matrix": array(component_row, minimum=40, maximum=40),
            "handoff_rows": array(handoff_row, minimum=14, maximum=14),
            "impossible_rows": array(impossible_row, minimum=12, maximum=12),
        }
    )
    return {
        "kilix.content.retention-intent-v1.schema.json": document(
            "kilix.content.retention-intent/v1",
            "Kilix retention intent v1",
            intent,
            defs,
        ),
        "kilix.content.retention-component-v1.schema.json": document(
            "kilix.content.retention-component/v1",
            "Kilix retention component v1",
            ref("component"),
            defs,
        ),
        "kilix.content.retention-envelope-v1.schema.json": document(
            "kilix.content.retention-envelope/v1",
            "Kilix retention envelope v1",
            envelope,
            defs,
        ),
        "kilix.content.retention-marker-v1.schema.json": document(
            "kilix.content.retention-marker/v1",
            "Kilix retention marker v1",
            marker,
            defs,
        ),
        "kilix.content.retention-relation-v1.schema.json": document(
            "kilix.content.retention-relation/v1",
            "Kilix retention relation v1",
            relation,
            defs,
        ),
        "kilix.content.retention-accounted-v1.schema.json": document(
            "kilix.content.retention-accounted/v1",
            "Kilix retention accounted proof v1",
            accounted,
            defs,
        ),
        "kilix.content.retention-handoff-proof-v1.schema.json": document(
            "kilix.content.retention-handoff-proof/v1",
            "Kilix retention handoff proof v1",
            handoff,
            defs,
        ),
        "kilix.content.retention-logical-state-v1.schema.json": document(
            "kilix.content.retention-logical-state/v1",
            "Kilix retention logical state v1",
            ref("logicalState"),
            defs,
        ),
        "kilix.content.retention-physical-state-v1.schema.json": document(
            "kilix.content.retention-physical-state/v1",
            "Kilix retention physical state v1",
            ref("physicalState"),
            defs,
        ),
        "kilix.content.transaction-generation-v1.schema.json": document(
            "kilix.content.transaction-generation/v1",
            "Kilix retention transaction generation v1",
            {"oneOf": generation_branches},
            defs,
        ),
        "kilix.content.directory-observation-v1.schema.json": document(
            "kilix.content.directory-observation/v1",
            "Kilix retention directory observation v1",
            observation,
            defs,
        ),
        "kilix.content.recovery-vector-v1.schema.json": document(
            "kilix.content.recovery-vector/v1",
            "Kilix inert retention recovery vectors v1",
            recovery,
            defs,
        ),
    }


def all_schemas() -> dict[str, dict[str, Any]]:
    result = {}
    for group in (
        catalog_schemas(),
        profile_schemas(),
        capacity_schemas(),
        retention_schemas(),
    ):
        overlap = set(result) & set(group)
        if overlap:
            raise SystemExit(f"duplicate schema names: {sorted(overlap)!r}")
        result.update(group)
    if len(result) != 25:
        raise SystemExit(f"expected 25 U1 schemas, found {len(result)}")
    return result


def render() -> tuple[int, str]:
    schemas = all_schemas()
    SOURCE_CONTRACTS.mkdir(parents=True, exist_ok=True)
    PACKAGE_CONTRACTS.mkdir(parents=True, exist_ok=True)
    for directory in (ROOT / "contracts", ROOT / "src" / "kilix_content" / "contracts"):
        for obsolete in directory.glob("*.schema.json"):
            if obsolete.name not in BASELINE_SCHEMA_NAMES:
                obsolete.unlink()
    for directory in (SOURCE_CONTRACTS, PACKAGE_CONTRACTS):
        for stale in directory.glob("*.json"):
            stale.unlink()
    resources = []
    for name, schema in sorted(schemas.items()):
        payload = canonical(schema)
        for directory in (SOURCE_CONTRACTS, PACKAGE_CONTRACTS):
            (directory / name).write_bytes(payload)
        resources.append(
            {
                "role": "schema",
                "schema_id": schema["$id"],
                "path": f"contracts/u1/{name}",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "wheel_disposition": "required",
                "sdist_disposition": "required",
            }
        )
    license_path = ROOT / "src" / "kilix_content" / "licenses" / "MIT.txt"
    license_payload = license_path.read_bytes()
    resources.append(
        {
            "role": "license-text",
            "schema_id": "text/plain; charset=utf-8",
            "path": "licenses/MIT.txt",
            "size": len(license_payload),
            "sha256": hashlib.sha256(license_payload).hexdigest(),
            "wheel_disposition": "required",
            "sdist_disposition": "required",
        }
    )
    resources.sort(key=lambda item: canonical(item))
    manifest = {
        "schema": "kilix.content.u1-resources/v1",
        "release_id": RELEASE_ID,
        "resources": resources,
    }
    manifest_payload = canonical(manifest)
    for path in (
        ROOT / "contracts" / MANIFEST_NAME,
        ROOT / "src" / "kilix_content" / "contracts" / MANIFEST_NAME,
    ):
        path.write_bytes(manifest_payload)
    return len(schemas), hashlib.sha256(manifest_payload).hexdigest()


def main() -> int:
    count, digest = render()
    print(f"schemas={count}")
    print(f"manifest_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
