"""Deterministic constructors for the source-only U1 security corpus.

This module is included in the sdist test surface and excluded from wheels.  It
cannot create the genuine packaged release capability.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

from kilix_content.u1_capacity import OWNER_PHASES, ROOT_ROLES
from kilix_content.u1_catalog import _derive_install_authority_binding
from kilix_content.u1_core import (
    ZERO_DIGEST,
    authorization_record_digest,
    canonical_digest,
    canonical_json_bytes,
    capacity_generation_digest,
    capacity_policy_digest,
    digest_without,
    install_authority_digest,
    output_binding_digest,
    retention_accounted_digest,
    retention_absence_evidence_digest,
    retention_component_digest,
    retention_component_envelope_digest,
    retention_descriptor_digest,
    retention_envelope_digest,
    retention_handoff_digest,
    retention_intent_digest,
    retention_logical_state_digest,
    retention_marker_content_digest,
    retention_marker_digest,
    retention_marker_semantic_bytes,
    retention_marker_semantic_digest,
    retention_physical_envelope_digest,
    retention_physical_state_digest,
    retention_relation_content_digest,
    retention_relation_digest,
    retention_relation_semantic_bytes,
    retention_relation_semantic_digest,
    transaction_generation_digest,
)
from kilix_content.u1_profiles import DEVICE_ENDPOINTS, REQUIRED_IPC_DENIALS
from kilix_content.u1_retention import (
    COMPONENT_ROLES,
    COMPONENT_STATES,
    HANDOFF_ROW_IDS,
    IMPOSSIBLE_REASONS,
    PHASE_FINAL_ROLES,
    TRANSACTION_PAYLOAD_FIELDS,
    TRANSACTION_PHASES,
    component_recovery_expected,
    handoff_recovery_expected,
)


ROOT = Path(__file__).resolve().parents[1]
RELEASE_ID = "0.2.1"
COMPONENT_MAX_BYTES = 262_144


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def ordered(values: list[Any]) -> list[Any]:
    return sorted(values, key=canonical_json_bytes)


def system_profile() -> dict[str, Any]:
    value = {
        "schema": "kilix.content.system-requirements/v1",
        "id": "system.test",
        "release_snapshot": {
            "distribution": "debian",
            "suite": "trixie",
            "timestamp": "20260821T000000Z",
            "release_sha256": sha("debian-release"),
        },
        "architecture": "amd64",
        "packages": [
            {
                "name": "bubblewrap",
                "version": "0.11.0-2",
                "architecture": "amd64",
                "sha256": sha("bubblewrap-deb"),
            }
        ],
        "manifest_sha256": ZERO_DIGEST,
    }
    value["manifest_sha256"] = digest_without(
        "system-requirements", value, ("manifest_sha256",)
    )
    return value


def toolchain_profile() -> dict[str, Any]:
    value = {
        "schema": "kilix.content.toolchain-profile/v1",
        "id": "toolchain.test",
        "release_snapshot": {
            "distribution": "debian",
            "suite": "trixie",
            "timestamp": "20260821T000000Z",
            "release_sha256": sha("debian-release"),
        },
        "architecture": "amd64",
        "packages": [
            {
                "name": "python3",
                "version": "3.12.8-1",
                "architecture": "amd64",
                "sha256": sha("python-deb"),
            }
        ],
        "executables": [
            {
                "path": "/usr/bin/python3",
                "mode": 0o755,
                "sha256": sha("python-executable"),
            }
        ],
        "libraries": [
            {"path": "/usr/lib/libc.so", "mode": 0o644, "sha256": sha("libc-library")}
        ],
        "entrypoints": [
            {"id": "python", "executable": "/usr/bin/python3", "argv": ["-I"]}
        ],
        "offline_python": {
            "enabled": True,
            "python_version": "3.12.8",
            "python_sha256": sha("python-executable"),
            "uv_version": "0.12.3",
            "uv_sha256": sha("uv-executable"),
            "project_sha256": sha("project"),
            "lock_sha256": sha("uv-lock"),
            "wheels": [
                {"name": "demo-wheel", "version": "1.0.0", "sha256": sha("demo-wheel")}
            ],
        },
        "environment": ordered(
            [
                {"name": "LANG", "value": "C.UTF-8"},
                {"name": "LC_ALL", "value": "C.UTF-8"},
                {"name": "PATH", "value": "/usr/bin"},
                {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                {"name": "PYTHONHASHSEED", "value": "0"},
                {"name": "SOURCE_DATE_EPOCH", "value": "1776729600"},
                {"name": "TZ", "value": "UTC"},
            ]
        ),
        "abi": {
            "libc": "glibc",
            "libc_version": "2.41",
            "kernel_abi": "6.12",
            "machine": "amd64",
            "endianness": "little",
            "pointer_bits": 64,
        },
        "profile_sha256": ZERO_DIGEST,
    }
    value["profile_sha256"] = digest_without(
        "toolchain-profile", value, ("profile_sha256",)
    )
    return value


def sandbox_profile() -> dict[str, Any]:
    value = {
        "schema": "kilix.content.sandbox-profile/v1",
        "id": "sandbox.test",
        "mounts": ordered(
            [
                {
                    "source_role": "toolchain",
                    "target": "/usr",
                    "kind": "bind",
                    "read_only": True,
                    "noexec": False,
                    "nosuid": True,
                    "nodev": True,
                },
                {
                    "source_role": "proc",
                    "target": "/proc",
                    "kind": "proc",
                    "read_only": True,
                    "noexec": True,
                    "nosuid": True,
                    "nodev": True,
                },
                {
                    "source_role": "scratch",
                    "target": "/tmp",
                    "kind": "tmpfs",
                    "read_only": False,
                    "noexec": True,
                    "nosuid": True,
                    "nodev": True,
                },
            ]
        ),
        "namespaces": {
            "user": "fresh",
            "mount": "fresh",
            "pid": "fresh",
            "network": "fresh",
            "ipc": "fresh",
        },
        "capabilities": [],
        "seccomp": {
            "architecture": "amd64",
            "default_action": "allow-except-denied",
            "denied_syscalls": sorted(REQUIRED_IPC_DENIALS),
        },
        "devices": list(DEVICE_ENDPOINTS),
        "proc_policy": {
            "mounted": True,
            "read_only": True,
            "hidepid": 2,
            "mqueue_absent": True,
            "shm_absent": True,
        },
        "resource_limit_shape": {
            "memory": "capacity-policy",
            "pids": "capacity-policy",
            "cpu": "capacity-policy",
            "tmpfs_bytes": "capacity-policy",
            "tmpfs_inodes": "capacity-policy",
        },
        "quota_backend": {
            "kind": "tmpfs-cgroup-v2",
            "enforced": True,
            "filesystem_accounting": True,
        },
        "profile_sha256": ZERO_DIGEST,
    }
    value["profile_sha256"] = digest_without(
        "sandbox-profile", value, ("profile_sha256",)
    )
    return value


def license_manifest() -> dict[str, Any]:
    text = (ROOT / "src" / "kilix_content" / "licenses" / "MIT.txt").read_bytes()
    return {
        "schema": "kilix.content.license-manifest/v1",
        "release_id": RELEASE_ID,
        "licenses": [
            {
                "id": "mit",
                "path": "licenses/MIT.txt",
                "text_sha256": hashlib.sha256(text).hexdigest(),
                "decision": "informational",
            }
        ],
    }


def source(kind: str) -> dict[str, Any]:
    common = {"source_bytes": 1024, "source_bytes_max": 2048}
    if kind == "archive":
        return {
            "kind": kind,
            "urls": ["https://example.invalid/demo.tar.gz"],
            "sha256": sha("archive-source"),
            **common,
            "archive_format": "tar.gz",
        }
    if kind == "mirrored":
        return {
            "kind": kind,
            "urls": [
                "https://example.invalid/mirror-a.bin",
                "https://mirror.invalid/mirror-b.bin",
            ],
            "sha256": sha("mirrored-source"),
            **common,
        }
    if kind == "git":
        return {
            "kind": kind,
            "repository": "https://example.invalid/demo.git",
            "commit": "1" * 40,
            "source_bytes_max": 2048,
            "submodules": [
                {
                    "path": "vendor/dependency",
                    "repository": "https://example.invalid/dependency.git",
                    "commit": "2" * 40,
                }
            ],
        }
    if kind == "user-supplied":
        return {
            "kind": kind,
            "input_format": "application/octet-stream",
            "input_sha256": sha("user-input"),
            **common,
        }
    raise AssertionError(kind)


def install_record(kind: str, *, output_manifest: bool = False) -> dict[str, Any]:
    system = system_profile()
    toolchain = toolchain_profile()
    sandbox = sandbox_profile()
    license_record = license_manifest()["licenses"][0]
    declares_build = kind in {"archive", "user-supplied"}
    dependencies = (
        [
            {
                "id": "demo.git",
                "role": "conversion" if kind == "user-supplied" else "build",
            }
        ]
        if declares_build
        else []
    )
    value: dict[str, Any] = {
        "schema": "kilix.content.install-record/v5",
        "version": "1.0.0",
        "source": source(kind),
        "build_argv": ["python3", "-I", "build.py"] if declares_build else [],
        "output_format_version": 1,
        "source_bytes_max": 2048,
        "temporary_bytes_max": 4096,
        "process_memory_bytes_max": 8192,
        "installed_bytes_max": 4096,
        "temporary_files_max": 32,
        "installed_files_max": 16,
        "dependencies": dependencies,
        "system_requirements": [
            {"id": system["id"], "manifest_sha256": system["manifest_sha256"]}
        ],
        "toolchain": {"id": toolchain["id"], "sha256": toolchain["profile_sha256"]},
        "sandbox": {"id": sandbox["id"], "sha256": sandbox["profile_sha256"]},
        "licenses": [
            {
                "id": license_record["id"],
                "text_sha256": license_record["text_sha256"],
                "decision": license_record["decision"],
            }
        ],
    }
    if output_manifest:
        value["output_manifest_sha256"] = sha(f"{kind}-output-manifest")
    return value


def catalog() -> dict[str, Any]:
    system = system_profile()
    toolchain = toolchain_profile()
    sandbox = sandbox_profile()
    package_install = install_record("archive", output_manifest=True)
    mirrored_install = install_record("mirrored")
    mirrored_install["dependencies"] = [{"id": "demo.codec", "role": "runtime"}]
    user_install = install_record("user-supplied", output_manifest=True)
    value = {
        "schema": "kilix.content.catalog/v5",
        "release_id": RELEASE_ID,
        "packages": [
            {
                "id": "demo.package",
                "stable_slot": "demo-package",
                "install": package_install,
                "members": ordered(
                    [
                        {
                            "content_id": "demo.codec",
                            "member_path": "bin/codec",
                        },
                        {
                            "content_id": "demo.model",
                            "member_path": "share/model.bin",
                        },
                    ]
                ),
            }
        ],
        "contents": ordered(
            [
                {
                    "id": "demo.git",
                    "stable_slot": "demo-git",
                    "install": install_record("git"),
                },
                {
                    "id": "demo.mirror",
                    "stable_slot": "demo-mirror",
                    "install": mirrored_install,
                },
            ]
        ),
        "assets": [
            {
                "id": "demo.input",
                "stable_slot": "demo-input",
                "install": user_install,
                "output_manifest_sha256": user_install["output_manifest_sha256"],
            }
        ],
        "aliases": ordered(
            [
                {
                    "content_id": "demo.codec",
                    "package_id": "demo.package",
                    "member_path": "bin/codec",
                },
                {
                    "content_id": "demo.model",
                    "package_id": "demo.package",
                    "member_path": "share/model.bin",
                },
            ]
        ),
        "system_requirement_profiles": [
            {
                "id": system["id"],
                "resource_path": "profiles/system.json",
                "manifest_sha256": system["manifest_sha256"],
            }
        ],
        "toolchain_profiles": [
            {
                "id": toolchain["id"],
                "resource_path": "profiles/toolchain.json",
                "profile_sha256": toolchain["profile_sha256"],
            }
        ],
        "sandbox_profiles": [
            {
                "id": sandbox["id"],
                "resource_path": "profiles/sandbox.json",
                "profile_sha256": sandbox["profile_sha256"],
            }
        ],
        "license_manifest_id": "licenses.test",
    }
    return value


def authority_binding(request_id: str = "demo.codec") -> dict[str, Any]:
    return _derive_install_authority_binding(catalog(), request_id)


def output_binding() -> dict[str, Any]:
    authority = authority_binding()
    value = {
        "schema": "kilix.content.output-binding/v1",
        "install_authority_sha256": install_authority_digest(authority),
        "source_sha256": sha("observed-source"),
        "input_sha256": sha("observed-input"),
        "dependency_sha256s": [sha("dependency")],
        "toolchain_sha256": toolchain_profile()["profile_sha256"],
        "sandbox_sha256": sandbox_profile()["profile_sha256"],
        "selected_tree_sha256": sha("selected-tree"),
        "selected_bytes": 1024,
        "selected_files": 2,
        "journal_schema": "transaction-v5",
        "output_format_version": 1,
    }
    return value


def authorization() -> dict[str, Any]:
    value = {
        "schema": "kilix.install.authorization/v2",
        "release_id": RELEASE_ID,
        "catalog_sha256": canonical_digest("catalog-v5", catalog()),
        "install_authority_sha256": install_authority_digest(authority_binding()),
        "output_binding_sha256": output_binding_digest(output_binding()),
        "authorization_id": "authorization-one",
        "record_sha256": ZERO_DIGEST,
    }
    value["record_sha256"] = authorization_record_digest(value)
    return value


def capacity_policy() -> dict[str, Any]:
    helpers = ordered(
        [
            {"name": "payload-init", "memory_bytes_max": 1024},
            {"name": "supervisor", "memory_bytes_max": 1024},
            {"name": "unit-submit", "memory_bytes_max": 1024},
        ]
    )
    roots = ordered(
        [
            {"role": role, "relative_path": role, "descriptor_relative": True}
            for role in ROOT_ROLES
        ]
    )
    maxima = ordered(
        [
            {
                "owner_kind": owner,
                "phase": phase,
                "root_role": role,
                "maximum": {
                    "bytes": 1024,
                    "inodes": 8,
                    "files": 8,
                    "directory_entries": 8,
                    "retained_crash_states": 2,
                },
            }
            for owner, phase in OWNER_PHASES
            for role in ROOT_ROLES
        ]
    )
    return {
        "schema": "kilix.content.capacity-reserve/v2",
        "release_id": RELEASE_ID,
        "policy_id": "capacity.test",
        "policy_version": 2,
        "hardware_tier": "test-vector",
        "tier_selection_inputs": {
            "memory_class": "test-memory",
            "cpu_class": "test-cpu",
            "storage_class": "test-storage",
            "selection_rule": "externally-measured-exact-match",
        },
        "ledger_schema": "kilix.content.capacity-ledger/v2",
        "reservation_schema": "kilix.content.capacity-generation/v2",
        "memory_equation": {
            "page_size_bytes": 4096,
            "fixed_overhead_bytes": 4096,
            "transaction_process_bytes_max": 8192,
            "tmpfs_bytes_max": 16384,
            "helper_overheads": helpers,
            "per_transaction_bytes": 32768,
            "simultaneous_transactions_max": 2,
            "aggregate_reservation_bytes_max": 65536,
            "addition": "checked-s64",
            "multiplication": "checked-s64",
            "page_rounding": "checked-ceil",
        },
        "writable_roots": roots,
        "supported_filesystems": [
            {
                "filesystem_type": "ext4",
                "filesystem_magic": 0xEF53,
                "allocation_rounding": "f-frsize-ceil",
                "stable_block_semantics": True,
                "identity_policy": "r7-capacity-key",
            }
        ],
        "filesystem_floor_formulas": [
            {
                "hardware_tier": "test-vector",
                "filesystem_type": "ext4",
                "fixed_min_bytes": 4096,
                "proportional_numerator": 1,
                "proportional_denominator": 100,
                "fixed_min_inodes": 8,
                "metadata_bytes_per_inode": 256,
                "overflow_mode": "checked-s64",
                "rounding_mode": "checked-ceil",
            }
        ],
        "phase_maxima": maxima,
        "retention_limits": {
            "retained_unique_objects_max": 8,
            "retained_allocated_bytes_max": 65536,
            "retained_inodes_max": 128,
            "retained_versions_per_stable_slot_max": 4,
            "ambiguous_retained_objects_max": 2,
            "pending_relations_max": 4,
            "pending_bytes_max": 16384,
            "pending_inodes_max": 32,
            "directory_entry_growth_bytes_max": [
                {"filesystem_type": "ext4", "bytes": 4096}
            ],
        },
        "scan_bounds": {
            "roots_max": 5,
            "filesystems_max": 16,
            "reservations_max": 64,
            "retention_records_max": 4096,
            "relations_max": 4096,
            "objects_max": 4096,
            "journals_max": 4096,
            "directory_children_max": 4096,
            "graph_nodes_max": 8192,
            "graph_edges_max": 16384,
            "bytes_max": 4194304,
            "recursion_depth_max": 64,
        },
    }


def capacity_lock() -> dict[str, Any]:
    return {
        "schema": "kilix.content.capacity-lock/v2",
        "reservation_id": "reservation-one",
        "release_id": RELEASE_ID,
        "policy_sha256": capacity_policy_digest(capacity_policy()),
        "creator_boot_id": "1" * 32,
    }


def _capacity_payload(phase: str) -> dict[str, Any]:
    fields = {
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
    }[phase]
    result: dict[str, Any] = {}
    for field in fields:
        if field == "helper_pid":
            result[field] = 1234
        elif field == "reservation_name":
            result[field] = "reservation-one"
        elif field == "job_id":
            result[field] = "job-one"
        elif field == "unit_name":
            result[field] = "unit-one"
        else:
            result[field] = sha(f"capacity-payload-{phase}-{field}")
    return result


def capacity_generation(
    phase: str = "RESERVED",
    *,
    generation: int = 0,
    predecessor: str | None = None,
) -> dict[str, Any]:
    owner = "retention-capacity" if phase.startswith("RETENTION_") else "capacity"
    return {
        "schema": "kilix.content.capacity-generation/v2",
        "owner_kind": owner,
        "phase": phase,
        "reservation_id": "reservation-one",
        "generation": generation,
        "predecessor_sha256": ZERO_DIGEST
        if generation == 0
        else (predecessor or sha("previous-generation")),
        "release_id": RELEASE_ID,
        "policy_sha256": capacity_policy_digest(capacity_policy()),
        "transaction_id": "transaction-one",
        "install_authority_sha256": install_authority_digest(authority_binding()),
        "creator_boot_id": "1" * 32,
        "owner_pid": 1234,
        "owner_start_time": 100,
        "memory_reserved_bytes": 32768,
        "filesystem_reservations": [
            {
                "filesystem_key_sha256": sha("filesystem-key"),
                "mount_identity": sha("mount-identity"),
                "bytes": 8192,
                "inodes": 32,
            }
        ],
        "root_identities": ordered(
            [
                {
                    "role": role,
                    "descriptor_identity_sha256": sha(f"root-{role}"),
                    "mount_identity": sha("mount-identity"),
                }
                for role in ROOT_ROLES
            ]
        ),
        "stable_lock_identity": sha("stable-lock"),
        "deadlines": {
            "submission_monotonic_ns": 100,
            "recovery_monotonic_ns": 200,
        },
        "phase_payload": _capacity_payload(phase),
    }


def capacity_chain(phases: list[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    predecessor = ZERO_DIGEST
    for index, phase in enumerate(phases):
        generation = capacity_generation(
            phase,
            generation=index,
            predecessor=predecessor,
        )
        result.append(generation)
        predecessor = capacity_generation_digest(generation)
    return result


def release_proof(kind: str = "ordinary") -> dict[str, Any]:
    common = {
        "schema": "kilix.content.release-proof/v2",
        "release_kind": kind,
        "permanent": kind == "retention_handoff",
        "reservation_id": "reservation-one",
        "generation": 10,
        "releasing_generation_sha256": sha("releasing-generation"),
        "resource_absence_sha256": sha("resource-absence"),
    }
    if kind == "ordinary":
        common["phase_payload"] = {
            "next_phase": "RELEASE_PROOFED",
            "tombstone_sha256": sha("tombstone"),
        }
    else:
        common["phase_payload"] = {
            "next_phase": "RETENTION_HANDOFF_PROOFED",
            "intent_sha256": sha("intent"),
            "accounted_sha256": sha("accounted"),
            "handoff_sha256": sha("handoff"),
        }
    return common


def logical_state(
    *, pending: bool = False, quarantined: bool = False
) -> dict[str, Any]:
    object_id = {
        "install_authority_sha256": install_authority_digest(authority_binding()),
        "output_binding_sha256": output_binding_digest(output_binding()),
    }
    relation = {
        "stable_slot_sha256": sha("stable-slot"),
        **object_id,
    }
    pending_values = [relation] if pending else []
    reasons = []
    if pending:
        reasons.append("pending-relations")
    if quarantined:
        reasons.append("quarantine")
    return {
        "schema": "kilix.content.retention-logical-state/v1",
        "release_id": RELEASE_ID,
        "O_materialized": [object_id],
        "O_referenced": [object_id],
        "O_counted": [object_id],
        "R_present": [relation],
        "R_pending": pending_values,
        "R_counted": [relation],
        "retained_unique_objects": 1,
        "retained_versions": [{"stable_slot_sha256": sha("stable-slot"), "count": 1}],
        "account_retention_quarantined": quarantined,
        "quarantine_reasons": ["unclassifiable-state"] if quarantined else [],
        "retention_admission_closed": bool(reasons),
        "admission_closed_reasons": sorted(reasons),
    }


def physical_state(
    *,
    charge_source: str | None = None,
    component_role: str = "H",
    component_specs: list[tuple[str, str, dict[str, Any] | None]] | None = None,
) -> dict[str, Any]:
    unions: list[dict[str, Any]] = []
    specs = component_specs
    if specs is None and charge_source is not None:
        specs = [(component_role, charge_source, None)]
    if specs:
        components = []
        totals = {
            "actual_bytes": 0,
            "actual_inodes": 0,
            "prospective_bytes": 0,
            "prospective_inodes": 0,
            "ambiguity_bytes": 0,
            "ambiguity_inodes": 0,
        }
        growth_total = 0
        for index, (role, source_name, descriptor) in enumerate(specs, start=1):
            if descriptor is None:
                root_identity = sha("retention-root")
                mount_identity = sha("mount-identity")
                descriptor_identity = sha(f"prospective-{role}")
                object_type = "directory" if role in {"D", "object"} else "regular"
                byte_count = COMPONENT_MAX_BYTES
                inode_count = 1
            else:
                root_identity = descriptor["root_identity"]
                mount_identity = descriptor["mount_identity"]
                descriptor_identity = descriptor["descriptor_identity_sha256"]
                object_type = descriptor["object_type"]
                byte_count = descriptor["bytes"]
                inode_count = descriptor["inodes"]
            growth = 32
            component = {
                "identity": {
                    "component_role": role,
                    "root_identity_sha256": root_identity,
                    "mount_identity_sha256": mount_identity,
                    "device": 1,
                    "inode": index,
                    "object_type": object_type,
                    "descriptor_identity_sha256": descriptor_identity,
                },
                "charge_source": source_name,
                "bytes": byte_count,
                "inodes": inode_count,
                "directory_growth_bytes": growth,
            }
            components.append(component)
            totals[f"{source_name}_bytes"] += byte_count + growth
            totals[f"{source_name}_inodes"] += inode_count
            growth_total += growth
        components = ordered(components)
        union = {
            "filesystem_key": sha("filesystem-key"),
            "components": components,
            **totals,
            "directory_growth_bytes": growth_total,
            "envelope_sha256": ZERO_DIGEST,
        }
        union["envelope_sha256"] = retention_physical_envelope_digest(union)
        unions = [union]
    return {
        "schema": "kilix.content.retention-physical-state/v1",
        "release_id": RELEASE_ID,
        "filesystem_unions": unions,
        "scan_complete": True,
        "incomplete_representations": [],
        "scan_bound_exhausted": False,
    }


def retention_component(
    role: str,
    *,
    creation_nonce: str,
    handoff_nonce: str,
    ordinal: int = 0,
    path: str | None = None,
) -> dict[str, Any]:
    suffix = {
        "D": f"dir-{ordinal}",
        "M": "marker",
        "R": "relation",
        "P": "accounted",
        "H": "handoff",
    }[role]
    nonce = handoff_nonce if role == "H" else creation_nonce
    result = {
        "schema": "kilix.content.retention-component/v1",
        "role": role,
        "filesystem_key": sha("filesystem-key"),
        "root_identity": sha("retention-root"),
        "nearest_existing_ancestor": sha(f"ancestor-{ordinal}"),
        "final_relative_path": path or f"retention/{role.lower()}",
        "temporary_basename": f".new-retention-{nonce}-{suffix}",
        "uid": 1000,
        "gid": 1000,
        "mode": 0o700 if role == "D" else 0o600,
        "object_type": "directory" if role == "D" else "regular",
        "max_bytes": COMPONENT_MAX_BYTES,
        "max_inodes": 1,
        "max_parent_growth": 32,
        "semantic_input": {
            "derivation": {
                "D": "empty-directory-from-intent",
                "M": "marker-from-intent-and-capacity",
                "R": "relation-from-intent-and-marker",
                "P": "accounted-from-intent-and-ready",
                "H": "handoff-from-intent-and-releasing",
            }[role],
            "input_sha256s": [sha(f"semantic-{role}")],
        },
    }
    if role == "D":
        result["ordinal"] = ordinal
    return result


def retention_intent(*, directory_count: int = 0) -> dict[str, Any]:
    creation_nonce = sha("creation-nonce")
    handoff_nonce = sha("handoff-nonce")
    object_descriptor = actual_descriptor("object")
    components: list[dict[str, Any]] = []
    for ordinal in range(directory_count):
        path = "/".join(["retention", *[f"d{index}" for index in range(ordinal + 1)]])
        components.append(
            retention_component(
                "D",
                creation_nonce=creation_nonce,
                handoff_nonce=handoff_nonce,
                ordinal=ordinal,
                path=path,
            )
        )
    components.extend(
        retention_component(
            role,
            creation_nonce=creation_nonce,
            handoff_nonce=handoff_nonce,
        )
        for role in ("M", "R", "P", "H")
    )
    envelope = ordered(
        [
            {
                "role": item["role"],
                "ordinal": item.get("ordinal", 0),
                "component_sha256": retention_component_digest(item),
                "max_bytes": item["max_bytes"],
                "max_inodes": item["max_inodes"],
                "max_parent_growth": item["max_parent_growth"],
            }
            for item in components
        ]
    )
    value = {
        "schema": "kilix.content.retention-intent/v1",
        "transaction_id": "transaction-one",
        "reservation_id": "reservation-one",
        "creation_nonce": creation_nonce,
        "handoff_nonce": handoff_nonce,
        "stable_slot_sha256": sha("stable-slot"),
        "install_authority_sha256": install_authority_digest(authority_binding()),
        "output_binding_sha256": output_binding_digest(output_binding()),
        "release_id": RELEASE_ID,
        "catalog_sha256": canonical_digest("catalog-v5", catalog()),
        "capacity_policy_sha256": capacity_policy_digest(capacity_policy()),
        "profile_sha256": sandbox_profile()["profile_sha256"],
        "object_identity": {
            "install_authority_sha256": install_authority_digest(authority_binding()),
            "output_binding_sha256": output_binding_digest(output_binding()),
        },
        "descriptor_attestation": {
            "descriptor_sha256": object_descriptor["descriptor_identity_sha256"],
            "content_sha256": object_descriptor["content_sha256"],
            "bytes": object_descriptor["bytes"],
            "files": 2,
        },
        "selected_tree_attestation": {
            "tree_sha256": sha("selected-tree"),
            "content_sha256": object_descriptor["content_sha256"],
            "bytes": object_descriptor["bytes"],
            "files": 2,
        },
        "filesystem_keys": [sha("filesystem-key")],
        "root_identities": [
            {"role": "retention-root", "identity_sha256": sha("retention-root")}
        ],
        "pre_admission_set_sha256": sha("pre-admission-set"),
        "pre_admission_scan_sha256": sha("pre-admission-scan"),
        "proposed_logical_state": logical_state(),
        "proposed_physical_state": physical_state(
            component_specs=[
                (component["role"], "prospective", None) for component in components
            ]
        ),
        "component_envelope": envelope,
        "component_envelope_sha256": retention_component_envelope_digest(
            {
                "transaction_id": "transaction-one",
                "reservation_id": "reservation-one",
                "creation_nonce": creation_nonce,
            },
            envelope,
        ),
        "components": components,
        "target_names": [
            {
                "role": item["role"],
                "ordinal": item.get("ordinal", 0),
                "relative_path": item["final_relative_path"],
            }
            for item in components
        ],
        "temporary_names": [
            {
                "role": item["role"],
                "ordinal": item.get("ordinal", 0),
                "basename": item["temporary_basename"],
            }
            for item in components
        ],
        "derivation_rules": [
            {
                "role": role,
                "rule": {
                    "D": "empty-directory-from-intent",
                    "M": "marker-from-intent-and-capacity",
                    "R": "relation-from-intent-and-marker",
                    "P": "accounted-from-intent-and-ready",
                    "H": "handoff-from-intent-and-releasing",
                }[role],
            }
            for role in COMPONENT_ROLES
        ],
        "component_schemas": [
            {"role": role, "schema_id": "kilix.content.retention-component/v1"}
            for role in COMPONENT_ROLES
        ],
        "component_maxima": [
            {
                "role": item["role"],
                "ordinal": item.get("ordinal", 0),
                "bytes": item["max_bytes"],
                "inodes": item["max_inodes"],
                "parent_growth": item["max_parent_growth"],
            }
            for item in components
        ],
        "directory_child_rules": ordered(
            [
                {
                    "ordinal": ordinal,
                    "phase": phase,
                    "allowed_final_roles": sorted(PHASE_FINAL_ROLES[phase]),
                    "current_temporary_allowed": phase != "RETENTION_HANDOFF_COMPLETE",
                }
                for ordinal in range(directory_count)
                for phase in TRANSACTION_PHASES
            ]
        ),
    }
    return value


def retention_envelope() -> dict[str, Any]:
    intent = retention_intent()
    value = {
        "schema": "kilix.content.retention-envelope/v1",
        "intent_identity": {
            "transaction_id": intent["transaction_id"],
            "reservation_id": intent["reservation_id"],
            "creation_nonce": intent["creation_nonce"],
        },
        "entries": copy.deepcopy(intent["component_envelope"]),
        "envelope_sha256": ZERO_DIGEST,
    }
    value["envelope_sha256"] = retention_envelope_digest(value)
    return value


def actual_descriptor(
    role: str,
    *,
    content_sha256: str | None = None,
    byte_count: int = 100,
    relative_path: str | None = None,
) -> dict[str, Any]:
    value = {
        "role": role,
        "filesystem_key": sha("filesystem-key"),
        "root_identity": sha("retention-root"),
        "mount_identity": sha("mount-identity"),
        "descriptor_identity_sha256": ZERO_DIGEST,
        "relative_path": relative_path or f"retention/{role.lower()}",
        "uid": 1000,
        "gid": 1000,
        "mode": 0o700 if role in {"D", "object"} else 0o600,
        "object_type": "directory" if role in {"D", "object"} else "regular",
        "content_sha256": content_sha256 or sha(f"content-{role}"),
        "bytes": byte_count,
        "inodes": 1,
    }
    if role in {"M", "R", "P", "H"}:
        value["nlink"] = 1
    value["descriptor_identity_sha256"] = retention_descriptor_digest(value)
    return value


def retention_marker(
    *,
    intent_value: dict[str, Any] | None = None,
    intent_capacity_generation_sha256: str | None = None,
    predecessor_transaction_generation_sha256: str | None = None,
) -> dict[str, Any]:
    intent = clone(intent_value) if intent_value is not None else retention_intent()
    value = {
        "schema": "kilix.content.retention-marker/v1",
        "record_kind": "M",
        "release_id": RELEASE_ID,
        "transaction_id": intent["transaction_id"],
        "reservation_id": intent["reservation_id"],
        "intent_sha256": retention_intent_digest(intent),
        "component_envelope_sha256": intent["component_envelope_sha256"],
        "intent_capacity_generation_sha256": (
            intent_capacity_generation_sha256 or sha("intent-capacity-generation")
        ),
        "stable_slot_sha256": intent["stable_slot_sha256"],
        "install_authority_sha256": intent["install_authority_sha256"],
        "output_binding_sha256": intent["output_binding_sha256"],
        "catalog_sha256": intent["catalog_sha256"],
        "profile_sha256": intent["profile_sha256"],
        "predecessor_transaction_generation_sha256": (
            predecessor_transaction_generation_sha256 or sha("prepared-generation")
        ),
        "descriptor": {},
        "semantic_payload_sha256": ZERO_DIGEST,
    }
    value["descriptor"] = actual_descriptor(
        "M",
        content_sha256=retention_marker_content_digest(value),
        byte_count=len(retention_marker_semantic_bytes(value)),
    )
    value["semantic_payload_sha256"] = retention_marker_semantic_digest(value)
    return value


def retention_relation(
    *,
    marker_value: dict[str, Any] | None = None,
    predecessor_transaction_generation_sha256: str | None = None,
) -> dict[str, Any]:
    marker = clone(marker_value) if marker_value is not None else retention_marker()
    value = {
        "schema": "kilix.content.retention-relation/v1",
        "record_kind": "R",
        **{
            key: copy.deepcopy(child)
            for key, child in marker.items()
            if key
            not in {"schema", "record_kind", "descriptor", "semantic_payload_sha256"}
        },
        "marker_sha256": retention_marker_digest(marker),
        "relation_identity": {
            "stable_slot_sha256": marker["stable_slot_sha256"],
            "install_authority_sha256": marker["install_authority_sha256"],
            "output_binding_sha256": marker["output_binding_sha256"],
        },
        "descriptor": {},
        "semantic_payload_sha256": ZERO_DIGEST,
    }
    if predecessor_transaction_generation_sha256 is not None:
        value["predecessor_transaction_generation_sha256"] = (
            predecessor_transaction_generation_sha256
        )
    value["descriptor"] = actual_descriptor(
        "R",
        content_sha256=retention_relation_content_digest(value),
        byte_count=len(retention_relation_semantic_bytes(value)),
    )
    value["semantic_payload_sha256"] = retention_relation_semantic_digest(value)
    return value


def transaction_generation(
    phase: str = "RETENTION_PREPARED",
    *,
    generation: int = 1,
    predecessor: str | None = None,
    intent_value: dict[str, Any] | None = None,
    phase_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    intent = clone(intent_value) if intent_value is not None else retention_intent()
    return {
        "schema": "kilix.content.transaction-generation/v1",
        "owner_kind": "retention",
        "phase": phase,
        "generation": generation,
        "predecessor_sha256": predecessor or sha("transaction-predecessor"),
        "transaction_id": intent["transaction_id"],
        "reservation_id": intent["reservation_id"],
        "intent_sha256": retention_intent_digest(intent),
        "phase_payload": clone(phase_payload)
        if phase_payload is not None
        else {
            field: sha(f"transaction-{phase}-{field}")
            for field in TRANSACTION_PAYLOAD_FIELDS[phase]
        },
    }


def directory_observation() -> dict[str, Any]:
    baseline = [
        {
            "name": "existing",
            "role": "baseline",
            "object_type": "directory",
            "descriptor_sha256": sha("existing-child"),
        }
    ]
    return {
        "schema": "kilix.content.directory-observation/v1",
        "role": "D",
        "relative_path": "retention",
        "uid": 1000,
        "gid": 1000,
        "mode": 0o700,
        "filesystem_key": sha("filesystem-key"),
        "root_identity": sha("retention-root"),
        "mount_identity": sha("mount-identity"),
        "baseline_children": baseline,
        "baseline_children_sha256": canonical_digest("retention-child-set", baseline),
        "phase": "RETENTION_PREPARED",
        "permitted_delta": [],
        "current_temporary": {"present": False},
        "observed_children": baseline,
    }


def retention_accounted(
    *,
    intent_value: dict[str, Any] | None = None,
    marker_value: dict[str, Any] | None = None,
    relation_value: dict[str, Any] | None = None,
    intent_capacity_generation_sha256: str | None = None,
    ready_transaction_generation_sha256: str | None = None,
) -> dict[str, Any]:
    intent = clone(intent_value) if intent_value is not None else retention_intent()
    marker_record = (
        clone(marker_value)
        if marker_value is not None
        else retention_marker(intent_value=intent)
    )
    relation_record = (
        clone(relation_value)
        if relation_value is not None
        else retention_relation(marker_value=marker_record)
    )
    object_descriptor = actual_descriptor("object")
    marker_descriptor = copy.deepcopy(marker_record["descriptor"])
    relation_descriptor = copy.deepcopy(relation_record["descriptor"])
    logical = copy.deepcopy(intent["proposed_logical_state"])
    physical = physical_state(
        component_specs=[
            ("object", "actual", object_descriptor),
            ("M", "actual", marker_descriptor),
            ("R", "actual", relation_descriptor),
            ("P", "prospective", None),
            ("H", "prospective", None),
        ]
    )
    p_component = next(
        component for component in intent["components"] if component["role"] == "P"
    )
    return {
        "schema": "kilix.content.retention-accounted/v1",
        "owner_kind": "retention",
        "record_kind": "P",
        "release_id": RELEASE_ID,
        "transaction_id": intent["transaction_id"],
        "reservation_id": intent["reservation_id"],
        "intent": intent,
        "intent_sha256": retention_intent_digest(intent),
        "intent_capacity_generation_sha256": (
            intent_capacity_generation_sha256 or sha("intent-capacity-generation")
        ),
        "ready_transaction_generation_sha256": (
            ready_transaction_generation_sha256 or sha("ready-transaction-generation")
        ),
        "object_descriptor": object_descriptor,
        "marker_descriptor": marker_descriptor,
        "relation_descriptor": relation_descriptor,
        "object_content_sha256": object_descriptor["content_sha256"],
        "marker_content_sha256": marker_descriptor["content_sha256"],
        "relation_content_sha256": relation_descriptor["content_sha256"],
        "logical_state": logical,
        "logical_state_sha256": retention_logical_state_digest(logical),
        "physical_state": physical,
        "physical_state_sha256": retention_physical_state_digest(physical),
        "capacity_policy_sha256": intent["capacity_policy_sha256"],
        "profile_sha256": intent["profile_sha256"],
        "catalog_sha256": intent["catalog_sha256"],
        "proof_nonce": sha("proof-nonce"),
        "p_final_relative_path": p_component["final_relative_path"],
        "p_reserved_maximum": {
            "bytes": p_component["max_bytes"],
            "inodes": p_component["max_inodes"],
            "parent_growth": p_component["max_parent_growth"],
        },
    }


def retention_handoff(
    *,
    accounted_value: dict[str, Any] | None = None,
    accounted_transaction_generation_sha256: str | None = None,
    capacity_accounted_generation_sha256: str | None = None,
    capacity_releasing_generation_sha256: str | None = None,
    next_capacity_generation: int = 20,
) -> dict[str, Any]:
    accounted = (
        clone(accounted_value) if accounted_value is not None else retention_accounted()
    )
    logical = copy.deepcopy(accounted["logical_state"])
    accounted_bytes = canonical_json_bytes(accounted)
    accounted_content_sha256 = hashlib.sha256(accounted_bytes).hexdigest()
    accounted_descriptor = actual_descriptor(
        "P",
        content_sha256=accounted_content_sha256,
        byte_count=len(accounted_bytes),
        relative_path=accounted["p_final_relative_path"],
    )
    physical = physical_state(
        component_specs=[
            ("object", "actual", accounted["object_descriptor"]),
            ("M", "actual", accounted["marker_descriptor"]),
            ("R", "actual", accounted["relation_descriptor"]),
            ("P", "actual", accounted_descriptor),
            ("H", "prospective", None),
        ]
    )
    absence = {
        "unit_absent": True,
        "helper_absent": True,
        "cgroup_absent": True,
        "stage_absent": True,
        "future_writer_absent": True,
        "sha256": ZERO_DIGEST,
    }
    absence["sha256"] = retention_absence_evidence_digest(absence)
    h_component = next(
        component
        for component in accounted["intent"]["components"]
        if component["role"] == "H"
    )
    return {
        "schema": "kilix.content.retention-handoff-proof/v1",
        "owner_kind": "retention",
        "record_kind": "H",
        "release_kind": "retention_handoff",
        "permanent": True,
        "release_id": accounted["release_id"],
        "transaction_id": accounted["transaction_id"],
        "reservation_id": accounted["reservation_id"],
        "intent_sha256": accounted["intent_sha256"],
        "handoff_nonce": accounted["intent"]["handoff_nonce"],
        "accounted_sha256": retention_accounted_digest(accounted),
        "object_descriptor": copy.deepcopy(accounted["object_descriptor"]),
        "marker_descriptor": copy.deepcopy(accounted["marker_descriptor"]),
        "relation_descriptor": copy.deepcopy(accounted["relation_descriptor"]),
        "accounted_descriptor": accounted_descriptor,
        "object_content_sha256": accounted["object_content_sha256"],
        "marker_content_sha256": accounted["marker_content_sha256"],
        "relation_content_sha256": accounted["relation_content_sha256"],
        "accounted_content_sha256": accounted_content_sha256,
        "ready_transaction_generation_sha256": accounted[
            "ready_transaction_generation_sha256"
        ],
        "accounted_transaction_generation_sha256": (
            accounted_transaction_generation_sha256
            or sha("accounted-transaction-generation")
        ),
        "capacity_accounted_generation_sha256": (
            capacity_accounted_generation_sha256 or sha("capacity-accounted-generation")
        ),
        "capacity_releasing_generation_sha256": (
            capacity_releasing_generation_sha256 or sha("capacity-releasing-generation")
        ),
        "next_capacity_fields": {
            "owner_kind": "retention-capacity",
            "phase": "RETENTION_HANDOFF_PROOFED",
            "generation": next_capacity_generation,
            "predecessor_sha256": (
                capacity_releasing_generation_sha256
                or sha("capacity-releasing-generation")
            ),
        },
        "logical_state": logical,
        "logical_state_sha256": retention_logical_state_digest(logical),
        "physical_state": physical,
        "physical_state_sha256": retention_physical_state_digest(physical),
        "absence_evidence": absence,
        "names": {
            "capacity_final": f"reservations/{accounted['reservation_id']}",
            "capacity_tombstone": (
                f"reservations/.released-{accounted['reservation_id']}-"
                f"{accounted['intent']['handoff_nonce']}"
            ),
            "h_temporary_basename": h_component["temporary_basename"],
            "h_final_relative_path": h_component["final_relative_path"],
        },
        "profile_sha256": accounted["profile_sha256"],
        "catalog_sha256": accounted["catalog_sha256"],
    }


def retention_provenance_bundle() -> dict[str, Any]:
    """Build one internally coherent, acyclic R13 retention provenance graph."""
    intent = retention_intent()
    intent_sha256 = retention_intent_digest(intent)

    capacity_generations = capacity_chain(
        [
            "RESERVED",
            "SUBMITTER_ARMING",
            "SUBMITTER_LIVE",
            "UNIT_PREPARED",
            "UNIT_MAYBE_SENT",
            "UNIT_ACKNOWLEDGED",
            "UNIT_BOUND",
            "GO_SENT",
            "STAGE_RETAINED",
        ]
    )
    intent_capacity = capacity_generation(
        "RETENTION_INTENT_RESERVED",
        generation=len(capacity_generations),
        predecessor=capacity_generation_digest(capacity_generations[-1]),
    )
    intent_capacity["phase_payload"] = {
        "intent_sha256": intent_sha256,
        "pre_admission_scan_sha256": intent["pre_admission_scan_sha256"],
        "component_envelope_sha256": intent["component_envelope_sha256"],
    }
    capacity_generations.append(intent_capacity)
    intent_capacity_sha256 = capacity_generation_digest(intent_capacity)

    prepared = transaction_generation(
        "RETENTION_PREPARED",
        generation=1,
        intent_value=intent,
        phase_payload={
            "intent_capacity_generation_sha256": intent_capacity_sha256,
            "component_envelope_sha256": intent["component_envelope_sha256"],
        },
    )
    prepared_sha256 = transaction_generation_digest(prepared)
    marker = retention_marker(
        intent_value=intent,
        intent_capacity_generation_sha256=intent_capacity_sha256,
        predecessor_transaction_generation_sha256=prepared_sha256,
    )
    marker_sha256 = retention_marker_digest(marker)

    marker_generation = transaction_generation(
        "RETENTION_MARKER_DURABLE",
        generation=2,
        predecessor=prepared_sha256,
        intent_value=intent,
        phase_payload={"marker_sha256": marker_sha256},
    )
    marker_generation_sha256 = transaction_generation_digest(marker_generation)
    relation = retention_relation(
        marker_value=marker,
        predecessor_transaction_generation_sha256=marker_generation_sha256,
    )
    relation_sha256 = retention_relation_digest(relation)

    relation_generation = transaction_generation(
        "RETENTION_RELATION_DURABLE",
        generation=3,
        predecessor=marker_generation_sha256,
        intent_value=intent,
        phase_payload={
            "marker_sha256": marker_sha256,
            "relation_sha256": relation_sha256,
        },
    )
    relation_generation_sha256 = transaction_generation_digest(relation_generation)
    ready_generation = transaction_generation(
        "RETENTION_READY",
        generation=4,
        predecessor=relation_generation_sha256,
        intent_value=intent,
        phase_payload={
            "marker_sha256": marker_sha256,
            "relation_sha256": relation_sha256,
        },
    )
    ready_generation_sha256 = transaction_generation_digest(ready_generation)

    accounted = retention_accounted(
        intent_value=intent,
        marker_value=marker,
        relation_value=relation,
        intent_capacity_generation_sha256=intent_capacity_sha256,
        ready_transaction_generation_sha256=ready_generation_sha256,
    )
    accounted_sha256 = retention_accounted_digest(accounted)
    accounted_generation = transaction_generation(
        "RETENTION_ACCOUNTED",
        generation=5,
        predecessor=ready_generation_sha256,
        intent_value=intent,
        phase_payload={"accounted_sha256": accounted_sha256},
    )
    accounted_generation_sha256 = transaction_generation_digest(accounted_generation)

    capacity_accounted = capacity_generation(
        "RETENTION_ACCOUNTED",
        generation=len(capacity_generations),
        predecessor=intent_capacity_sha256,
    )
    capacity_accounted["phase_payload"] = {
        "intent_sha256": intent_sha256,
        "transaction_generation_sha256": accounted_generation_sha256,
        "accounted_sha256": accounted_sha256,
    }
    capacity_generations.append(capacity_accounted)
    capacity_accounted_sha256 = capacity_generation_digest(capacity_accounted)

    capacity_releasing = capacity_generation(
        "RETENTION_HANDOFF_RELEASING",
        generation=len(capacity_generations),
        predecessor=capacity_accounted_sha256,
    )
    capacity_releasing["phase_payload"] = {
        "intent_sha256": intent_sha256,
        "transaction_generation_sha256": accounted_generation_sha256,
        "accounted_sha256": accounted_sha256,
        "handoff_nonce": intent["handoff_nonce"],
    }
    capacity_generations.append(capacity_releasing)
    capacity_releasing_sha256 = capacity_generation_digest(capacity_releasing)

    handoff = retention_handoff(
        accounted_value=accounted,
        accounted_transaction_generation_sha256=accounted_generation_sha256,
        capacity_accounted_generation_sha256=capacity_accounted_sha256,
        capacity_releasing_generation_sha256=capacity_releasing_sha256,
        next_capacity_generation=capacity_releasing["generation"] + 1,
    )
    handoff_sha256 = retention_handoff_digest(handoff)
    capacity_proofed = capacity_generation(
        "RETENTION_HANDOFF_PROOFED",
        generation=len(capacity_generations),
        predecessor=capacity_releasing_sha256,
    )
    capacity_proofed["phase_payload"] = {
        "intent_sha256": intent_sha256,
        "transaction_generation_sha256": accounted_generation_sha256,
        "accounted_sha256": accounted_sha256,
        "handoff_sha256": handoff_sha256,
    }
    capacity_generations.append(capacity_proofed)

    handoff_complete = transaction_generation(
        "RETENTION_HANDOFF_COMPLETE",
        generation=6,
        predecessor=accounted_generation_sha256,
        intent_value=intent,
        phase_payload={
            "accounted_sha256": accounted_sha256,
            "handoff_sha256": handoff_sha256,
            "capacity_absence_sha256": sha("capacity-absence"),
            "fresh_scan_sha256": sha("fresh-scan"),
        },
    )
    transaction_generations = [
        prepared,
        marker_generation,
        relation_generation,
        ready_generation,
        accounted_generation,
        handoff_complete,
    ]
    return {
        "intent": intent,
        "intent_capacity": intent_capacity,
        "prepared_generation": prepared,
        "marker": marker,
        "marker_generation": marker_generation,
        "relation": relation,
        "relation_generation": relation_generation,
        "ready_generation": ready_generation,
        "accounted": accounted,
        "accounted_generation": accounted_generation,
        "capacity_accounted": capacity_accounted,
        "capacity_releasing": capacity_releasing,
        "handoff": handoff,
        "capacity_proofed": capacity_proofed,
        "handoff_complete_generation": handoff_complete,
        "capacity_chain": capacity_generations,
        "transaction_chain": transaction_generations,
    }


def recovery_snapshot(*, reservation_present: bool) -> dict[str, Any]:
    states = ordered(
        [
            {"role": role, "ordinal": 0, "state": "both-absent"}
            for role in ("M", "R", "P", "H")
        ]
    )
    return {
        "transaction_phase": "RETENTION_PREPARED",
        "capacity_phase": "RETENTION_INTENT_RESERVED",
        "component_states": states,
        "capacity_names": {
            "reservation_present": reservation_present,
            "tombstone_present": False,
        },
    }


def recovery_vector() -> dict[str, Any]:
    component_rows = ordered(
        [
            {
                "role": role,
                "observed_state": state,
                **component_recovery_expected(role, state),
            }
            for role in COMPONENT_ROLES
            for state in COMPONENT_STATES
        ]
    )
    handoff_rows = [
        handoff_recovery_expected(identifier) for identifier in HANDOFF_ROW_IDS
    ]
    impossible_rows = ordered(
        [
            {
                "reason": reason,
                "observed": recovery_snapshot(reservation_present=False),
                "expected": recovery_snapshot(reservation_present=True),
                "outcome": {
                    "quarantine": True,
                    "retain_charge": True,
                    "selection": False,
                    "return_path": False,
                    "cleanup": False,
                    "credit": False,
                },
            }
            for reason in IMPOSSIBLE_REASONS
        ]
    )
    return {
        "schema": "kilix.content.recovery-vector/v1",
        "release_id": RELEASE_ID,
        "executable": False,
        "component_matrix": component_rows,
        "handoff_rows": ordered(handoff_rows),
        "impossible_rows": impossible_rows,
    }


def positive_records() -> dict[str, tuple[str, dict[str, Any]]]:
    records: dict[str, tuple[str, dict[str, Any]]] = {
        "catalog-v5": ("kilix.content.catalog/v5", catalog()),
        "install-archive": (
            "kilix.content.install-record/v5",
            install_record("archive", output_manifest=True),
        ),
        "install-mirrored": (
            "kilix.content.install-record/v5",
            install_record("mirrored"),
        ),
        "install-git": ("kilix.content.install-record/v5", install_record("git")),
        "install-user-supplied": (
            "kilix.content.install-record/v5",
            install_record("user-supplied", output_manifest=True),
        ),
        "system-requirements": (
            "kilix.content.system-requirements/v1",
            system_profile(),
        ),
        "toolchain-profile": (
            "kilix.content.toolchain-profile/v1",
            toolchain_profile(),
        ),
        "sandbox-profile": ("kilix.content.sandbox-profile/v1", sandbox_profile()),
        "license-manifest": ("kilix.content.license-manifest/v1", license_manifest()),
        "install-authority-package": (
            "kilix.content.install-authority-binding/v1",
            authority_binding("demo.codec"),
        ),
        "install-authority-content": (
            "kilix.content.install-authority-binding/v1",
            authority_binding("demo.git"),
        ),
        "install-authority-asset": (
            "kilix.content.install-authority-binding/v1",
            authority_binding("demo.input"),
        ),
        "output-binding": ("kilix.content.output-binding/v1", output_binding()),
        "authorization-v2": ("kilix.install.authorization/v2", authorization()),
        "capacity-policy": ("kilix.content.capacity-reserve/v2", capacity_policy()),
        "capacity-lock": ("kilix.content.capacity-lock/v2", capacity_lock()),
        "release-proof-ordinary": (
            "kilix.content.release-proof/v2",
            release_proof("ordinary"),
        ),
        "release-proof-retention": (
            "kilix.content.release-proof/v2",
            release_proof("retention_handoff"),
        ),
        "retention-component": (
            "kilix.content.retention-component/v1",
            retention_intent()["components"][0],
        ),
        "retention-intent-d0": (
            "kilix.content.retention-intent/v1",
            retention_intent(directory_count=0),
        ),
        "retention-intent-d1": (
            "kilix.content.retention-intent/v1",
            retention_intent(directory_count=1),
        ),
        "retention-intent-d2": (
            "kilix.content.retention-intent/v1",
            retention_intent(directory_count=2),
        ),
        "retention-envelope": (
            "kilix.content.retention-envelope/v1",
            retention_envelope(),
        ),
        "retention-marker": ("kilix.content.retention-marker/v1", retention_marker()),
        "retention-relation": (
            "kilix.content.retention-relation/v1",
            retention_relation(),
        ),
        "retention-accounted": (
            "kilix.content.retention-accounted/v1",
            retention_accounted(),
        ),
        "retention-handoff": (
            "kilix.content.retention-handoff-proof/v1",
            retention_handoff(),
        ),
        "retention-logical-state": (
            "kilix.content.retention-logical-state/v1",
            logical_state(),
        ),
        "retention-physical-state": (
            "kilix.content.retention-physical-state/v1",
            physical_state(charge_source="actual"),
        ),
        "directory-observation": (
            "kilix.content.directory-observation/v1",
            directory_observation(),
        ),
        "recovery-vector": ("kilix.content.recovery-vector/v1", recovery_vector()),
    }
    for phase in (
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
    ):
        generation = 0 if phase == "RESERVED" else 1
        records[f"capacity-generation-{phase.lower().replace('_', '-')}"] = (
            "kilix.content.capacity-generation/v2",
            capacity_generation(phase, generation=generation),
        )
    for phase in TRANSACTION_PHASES:
        records[f"transaction-generation-{phase.lower().replace('_', '-')}"] = (
            "kilix.content.transaction-generation/v1",
            transaction_generation(phase),
        )
    return records


def clone(value: Any) -> Any:
    return copy.deepcopy(value)


__all__ = [
    "ROOT",
    "actual_descriptor",
    "authorization",
    "authority_binding",
    "capacity_chain",
    "capacity_generation",
    "capacity_lock",
    "capacity_policy",
    "catalog",
    "clone",
    "directory_observation",
    "install_record",
    "license_manifest",
    "logical_state",
    "ordered",
    "output_binding",
    "physical_state",
    "positive_records",
    "recovery_vector",
    "release_proof",
    "retention_accounted",
    "retention_envelope",
    "retention_handoff",
    "retention_intent",
    "retention_marker",
    "retention_provenance_bundle",
    "retention_relation",
    "sandbox_profile",
    "sha",
    "source",
    "system_profile",
    "toolchain_profile",
    "transaction_generation",
]
