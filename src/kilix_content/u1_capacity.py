"""Pure capacity-v2 policy, generation, lock, and release-proof semantics."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .u1_core import (
    HEX32_RE,
    ZERO_DIGEST,
    capacity_generation_digest,
    checked_add,
    checked_mul,
    checked_round_up,
    refuse,
    require_array,
    require_digest,
    require_id,
    require_keys,
    require_object,
    require_relative_path,
    require_s64,
    require_sorted_unique,
    require_text,
    require_u32,
    require_u64,
)


ROOT_ROLES = (
    "install-authorizations-v2",
    "installed-data",
    "license-receipts-v1",
    "resumable-cache",
    "transaction-state",
)
CAPACITY_PHASES = (
    "RESERVED",
    "SUBMITTER_ARMING",
    "SUBMITTER_LIVE",
    "UNIT_PREPARED",
    "UNIT_MAYBE_SENT",
    "UNIT_ACKNOWLEDGED",
    "UNIT_BOUND",
    "GO_SENT",
    "STAGE_RETAINED",
    "RELEASING",
    "RELEASE_PROOFED",
)
RECOVERY_PHASE = "UNIT_OBSERVED"
RETENTION_PHASES = (
    "RETENTION_INTENT_RESERVED",
    "RETENTION_ACCOUNTED",
    "RETENTION_HANDOFF_RELEASING",
    "RETENTION_HANDOFF_PROOFED",
)
TRANSACTION_PHASES = (
    "RETENTION_PREPARED",
    "RETENTION_MARKER_DURABLE",
    "RETENTION_RELATION_DURABLE",
    "RETENTION_READY",
    "RETENTION_ACCOUNTED",
    "RETENTION_HANDOFF_COMPLETE",
)
ALL_MAXIMUM_PHASES = tuple(
    sorted({*CAPACITY_PHASES, RECOVERY_PHASE, *RETENTION_PHASES, *TRANSACTION_PHASES})
)
OWNER_PHASES = tuple(
    sorted(
        {
            *(("capacity", phase) for phase in (*CAPACITY_PHASES, RECOVERY_PHASE)),
            *(("retention-capacity", phase) for phase in RETENTION_PHASES),
            *(("transaction", phase) for phase in TRANSACTION_PHASES),
        }
    )
)
FS_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}$")

CAPACITY_PAYLOAD_FIELDS: dict[str, tuple[str, ...]] = {
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
RETENTION_PAYLOAD_FIELDS: dict[str, tuple[str, ...]] = {
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


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _validate_metric_set(value: Any) -> None:
    metrics = require_object(value)
    require_keys(
        metrics,
        required=(
            "bytes",
            "inodes",
            "files",
            "directory_entries",
            "retained_crash_states",
        ),
    )
    for item in metrics.values():
        require_s64(item, positive=True)


def validate_capacity_policy(value: Any) -> None:
    policy = require_object(value)
    require_keys(
        policy,
        required=(
            "schema",
            "release_id",
            "policy_id",
            "policy_version",
            "hardware_tier",
            "tier_selection_inputs",
            "ledger_schema",
            "reservation_schema",
            "memory_equation",
            "writable_roots",
            "supported_filesystems",
            "filesystem_floor_formulas",
            "phase_maxima",
            "retention_limits",
            "scan_bounds",
        ),
    )
    if policy["schema"] != "kilix.content.capacity-reserve/v2":
        refuse("capacity policy schema is not v2")
    require_id(policy["release_id"])
    require_id(policy["policy_id"])
    require_s64(policy["policy_version"], positive=True)
    tier = require_id(policy["hardware_tier"])
    if tier != "test-vector":
        refuse("U1 cannot package production capacity values before F100-C0")
    if policy["ledger_schema"] != "kilix.content.capacity-ledger/v2":
        refuse("capacity ledger schema is not frozen")
    if policy["reservation_schema"] != "kilix.content.capacity-generation/v2":
        refuse("capacity reservation schema is not frozen")

    tier_inputs = require_object(policy["tier_selection_inputs"])
    require_keys(
        tier_inputs,
        required=("memory_class", "cpu_class", "storage_class", "selection_rule"),
    )
    for name in ("memory_class", "cpu_class", "storage_class"):
        require_id(tier_inputs[name])
    if tier_inputs["selection_rule"] != "externally-measured-exact-match":
        refuse("capacity tier selection rule is not frozen")

    equation = require_object(policy["memory_equation"])
    require_keys(
        equation,
        required=(
            "page_size_bytes",
            "fixed_overhead_bytes",
            "transaction_process_bytes_max",
            "tmpfs_bytes_max",
            "helper_overheads",
            "per_transaction_bytes",
            "simultaneous_transactions_max",
            "aggregate_reservation_bytes_max",
            "addition",
            "multiplication",
            "page_rounding",
        ),
    )
    page_size = require_s64(equation["page_size_bytes"], positive=True)
    if not _power_of_two(page_size):
        refuse("capacity page size is not a power of two")
    for name in (
        "fixed_overhead_bytes",
        "transaction_process_bytes_max",
        "tmpfs_bytes_max",
    ):
        require_s64(equation[name], positive=True)
    helpers = require_array(equation["helper_overheads"], minimum=3, maximum=3)
    helper_names: set[str] = set()
    for raw_helper in helpers:
        helper = require_object(raw_helper)
        require_keys(helper, required=("name", "memory_bytes_max"))
        helper_names.add(require_id(helper["name"]))
        require_s64(helper["memory_bytes_max"], positive=True)
    require_sorted_unique(helpers)
    if helper_names != {"payload-init", "supervisor", "unit-submit"}:
        refuse("capacity helper overhead set is incomplete")
    unrounded = checked_add(
        (
            equation["fixed_overhead_bytes"],
            equation["transaction_process_bytes_max"],
            equation["tmpfs_bytes_max"],
            *(entry["memory_bytes_max"] for entry in helpers),
        )
    )
    per_transaction = checked_round_up(unrounded, page_size)
    if (
        equation["addition"] != "checked-s64"
        or equation["multiplication"] != "checked-s64"
        or equation["page_rounding"] != "checked-ceil"
        or equation["per_transaction_bytes"] != per_transaction
    ):
        refuse("capacity memory equation is inconsistent")
    simultaneous = require_s64(equation["simultaneous_transactions_max"], positive=True)
    if equation["aggregate_reservation_bytes_max"] != checked_mul(
        per_transaction, simultaneous
    ):
        refuse("capacity aggregate reservation equation is inconsistent")

    roots = require_array(
        policy["writable_roots"], minimum=len(ROOT_ROLES), maximum=len(ROOT_ROLES)
    )
    observed_roles: set[str] = set()
    for raw_root in roots:
        root = require_object(raw_root)
        require_keys(root, required=("role", "relative_path", "descriptor_relative"))
        role = root["role"]
        if role not in ROOT_ROLES or role in observed_roles:
            refuse("capacity writable root role is unknown or duplicated")
        observed_roles.add(role)
        require_relative_path(root["relative_path"])
        if root["descriptor_relative"] is not True:
            refuse("capacity writable root is not descriptor-relative")
    require_sorted_unique(roots)
    if observed_roles != set(ROOT_ROLES):
        refuse("capacity writable root set is incomplete")

    filesystems = require_array(policy["supported_filesystems"], minimum=1, maximum=16)
    supported: set[tuple[str, int]] = set()
    for raw_filesystem in filesystems:
        filesystem = require_object(raw_filesystem)
        require_keys(
            filesystem,
            required=(
                "filesystem_type",
                "filesystem_magic",
                "allocation_rounding",
                "stable_block_semantics",
                "identity_policy",
            ),
        )
        fs_type = require_text(filesystem["filesystem_type"], FS_TYPE_RE, maximum=32)
        magic = require_u64(filesystem["filesystem_magic"], nonzero=True)
        if (fs_type, magic) in supported:
            refuse("supported filesystem identity is duplicated")
        supported.add((fs_type, magic))
        if (
            filesystem["allocation_rounding"] != "f-frsize-ceil"
            or filesystem["stable_block_semantics"] is not True
            or filesystem["identity_policy"] != "r7-capacity-key"
        ):
            refuse("supported filesystem semantics are not frozen")
    require_sorted_unique(filesystems)

    floors = require_array(
        policy["filesystem_floor_formulas"], minimum=len(supported), maximum=64
    )
    floor_keys: set[tuple[str, str]] = set()
    for raw_floor in floors:
        floor = require_object(raw_floor)
        require_keys(
            floor,
            required=(
                "hardware_tier",
                "filesystem_type",
                "fixed_min_bytes",
                "proportional_numerator",
                "proportional_denominator",
                "fixed_min_inodes",
                "metadata_bytes_per_inode",
                "overflow_mode",
                "rounding_mode",
            ),
        )
        key = (
            require_id(floor["hardware_tier"]),
            require_text(floor["filesystem_type"], FS_TYPE_RE, maximum=32),
        )
        if (
            key in floor_keys
            or key[0] != tier
            or key[1] not in {item[0] for item in supported}
        ):
            refuse("filesystem floor selector is unknown or duplicated")
        floor_keys.add(key)
        for name in (
            "fixed_min_bytes",
            "proportional_numerator",
            "proportional_denominator",
            "fixed_min_inodes",
            "metadata_bytes_per_inode",
        ):
            require_s64(floor[name], positive=True)
        if floor["proportional_numerator"] > floor["proportional_denominator"]:
            refuse("filesystem proportional floor exceeds one")
        if (
            floor["overflow_mode"] != "checked-s64"
            or floor["rounding_mode"] != "checked-ceil"
        ):
            refuse("filesystem floor arithmetic mode is not frozen")
    require_sorted_unique(floors)
    if {item[1] for item in floor_keys} != {item[0] for item in supported}:
        refuse("filesystem floor formula set is incomplete")

    maxima = require_array(
        policy["phase_maxima"],
        minimum=len(ROOT_ROLES) * len(OWNER_PHASES),
        maximum=len(ROOT_ROLES) * len(OWNER_PHASES),
    )
    maximum_keys: set[tuple[str, str, str]] = set()
    for raw_maximum in maxima:
        maximum = require_object(raw_maximum)
        require_keys(maximum, required=("owner_kind", "phase", "root_role", "maximum"))
        owner = maximum["owner_kind"]
        phase = maximum["phase"]
        role = maximum["root_role"]
        key = (owner, phase, role)
        if (
            (owner, phase) not in OWNER_PHASES
            or role not in ROOT_ROLES
            or key in maximum_keys
        ):
            refuse("capacity phase maximum selector is unknown or duplicated")
        maximum_keys.add(key)
        _validate_metric_set(maximum["maximum"])
    require_sorted_unique(maxima)
    expected_maxima = {
        (owner, phase, role) for owner, phase in OWNER_PHASES for role in ROOT_ROLES
    }
    if maximum_keys != expected_maxima:
        refuse("capacity phase maximum matrix is incomplete")

    limits = require_object(policy["retention_limits"])
    require_keys(
        limits,
        required=(
            "retained_unique_objects_max",
            "retained_allocated_bytes_max",
            "retained_inodes_max",
            "retained_versions_per_stable_slot_max",
            "ambiguous_retained_objects_max",
            "pending_relations_max",
            "pending_bytes_max",
            "pending_inodes_max",
            "directory_entry_growth_bytes_max",
        ),
    )
    for name, raw_value in limits.items():
        if name == "directory_entry_growth_bytes_max":
            values = require_array(
                raw_value, minimum=len(supported), maximum=len(supported)
            )
            seen: set[str] = set()
            for raw_entry in values:
                entry = require_object(raw_entry)
                require_keys(entry, required=("filesystem_type", "bytes"))
                fs_type = require_text(entry["filesystem_type"], FS_TYPE_RE, maximum=32)
                if fs_type in seen:
                    refuse("directory growth filesystem is duplicated")
                seen.add(fs_type)
                require_s64(entry["bytes"], positive=True)
            require_sorted_unique(values)
            if seen != {item[0] for item in supported}:
                refuse("directory growth filesystem set is incomplete")
        else:
            require_s64(raw_value, positive=True)

    bounds = require_object(policy["scan_bounds"])
    require_keys(
        bounds,
        required=(
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
        ),
    )
    for raw_value in bounds.values():
        require_s64(raw_value, positive=True)


def validate_capacity_lock(value: Any) -> None:
    lock = require_object(value)
    require_keys(
        lock,
        required=(
            "schema",
            "reservation_id",
            "release_id",
            "policy_sha256",
            "creator_boot_id",
        ),
    )
    if lock["schema"] != "kilix.content.capacity-lock/v2":
        refuse("capacity lock schema is not v2")
    require_id(lock["reservation_id"])
    require_id(lock["release_id"])
    require_digest(lock["policy_sha256"])
    boot_id = require_text(lock["creator_boot_id"], HEX32_RE, maximum=32)
    if boot_id == "0" * 32:
        refuse("capacity lock creator boot identity is zero")


def _validate_filesystem_reservations(value: Any) -> list[dict[str, Any]]:
    reservations = require_array(value, minimum=1, maximum=32)
    keys: set[str] = set()
    for raw_reservation in reservations:
        reservation = require_object(raw_reservation)
        require_keys(
            reservation,
            required=("filesystem_key_sha256", "mount_identity", "bytes", "inodes"),
        )
        key = require_digest(reservation["filesystem_key_sha256"])
        if key in keys:
            refuse("filesystem reservation key is duplicated")
        keys.add(key)
        require_digest(reservation["mount_identity"])
        require_s64(reservation["bytes"], positive=True)
        require_s64(reservation["inodes"], positive=True)
    require_sorted_unique(reservations)
    return reservations


def _validate_root_identities(value: Any) -> list[dict[str, Any]]:
    roots = require_array(value, minimum=len(ROOT_ROLES), maximum=len(ROOT_ROLES))
    roles: set[str] = set()
    for raw_root in roots:
        root = require_object(raw_root)
        require_keys(
            root, required=("role", "descriptor_identity_sha256", "mount_identity")
        )
        role = root["role"]
        if role not in ROOT_ROLES or role in roles:
            refuse("capacity generation root role is unknown or duplicated")
        roles.add(role)
        require_digest(root["descriptor_identity_sha256"])
        require_digest(root["mount_identity"])
    require_sorted_unique(roots)
    if roles != set(ROOT_ROLES):
        refuse("capacity generation root identity set is incomplete")
    return roots


def _validate_phase_payload(value: Any, *, owner_kind: str, phase: str) -> None:
    payload = require_object(value)
    fields = (
        CAPACITY_PAYLOAD_FIELDS.get(phase)
        if owner_kind == "capacity"
        else RETENTION_PAYLOAD_FIELDS.get(phase)
    )
    if fields is None:
        refuse("capacity generation owner and phase are inconsistent")
    require_keys(payload, required=fields)
    for name, raw_value in payload.items():
        if name == "helper_pid":
            require_u32(raw_value, nonzero=True)
        elif name in {"job_id", "unit_name", "reservation_name"}:
            require_id(raw_value)
        else:
            require_digest(raw_value)


def validate_capacity_generation(value: Any) -> None:
    generation = require_object(value)
    require_keys(
        generation,
        required=(
            "schema",
            "owner_kind",
            "phase",
            "reservation_id",
            "generation",
            "predecessor_sha256",
            "release_id",
            "policy_sha256",
            "transaction_id",
            "install_authority_sha256",
            "creator_boot_id",
            "owner_pid",
            "owner_start_time",
            "memory_reserved_bytes",
            "filesystem_reservations",
            "root_identities",
            "stable_lock_identity",
            "deadlines",
            "phase_payload",
        ),
    )
    if generation["schema"] != "kilix.content.capacity-generation/v2":
        refuse("capacity generation schema is not v2")
    owner_kind = generation["owner_kind"]
    phase = generation["phase"]
    if owner_kind not in {"capacity", "retention"}:
        refuse("capacity generation owner is outside the frozen enum")
    _validate_phase_payload(
        generation["phase_payload"], owner_kind=owner_kind, phase=phase
    )
    number = require_s64(generation["generation"])
    require_digest(generation["predecessor_sha256"])
    if number == 0:
        if (
            owner_kind != "capacity"
            or phase != "RESERVED"
            or generation["predecessor_sha256"] != ZERO_DIGEST
        ):
            refuse("generation zero is not the accepted capacity RESERVED root")
    elif generation["predecessor_sha256"] == ZERO_DIGEST:
        refuse("mutable capacity generation lacks a predecessor")
    require_id(generation["reservation_id"])
    require_id(generation["release_id"])
    require_digest(generation["policy_sha256"])
    require_id(generation["transaction_id"])
    require_digest(generation["install_authority_sha256"])
    boot_id = require_text(generation["creator_boot_id"], HEX32_RE, maximum=32)
    if boot_id == "0" * 32:
        refuse("capacity generation creator boot identity is zero")
    require_u32(generation["owner_pid"], nonzero=True)
    require_u64(generation["owner_start_time"], nonzero=True)
    require_s64(generation["memory_reserved_bytes"], positive=True)
    _validate_filesystem_reservations(generation["filesystem_reservations"])
    _validate_root_identities(generation["root_identities"])
    require_digest(generation["stable_lock_identity"])
    deadlines = require_object(generation["deadlines"])
    require_keys(
        deadlines, required=("submission_monotonic_ns", "recovery_monotonic_ns")
    )
    submission = require_u64(deadlines["submission_monotonic_ns"], nonzero=True)
    recovery = require_u64(deadlines["recovery_monotonic_ns"], nonzero=True)
    if recovery < submission:
        refuse("capacity recovery deadline precedes submission deadline")


def _next_phase(previous: str, current: str, *, recovery: bool) -> bool:
    if recovery and (previous, current) in {
        ("UNIT_MAYBE_SENT", RECOVERY_PHASE),
        (RECOVERY_PHASE, "RELEASING"),
    }:
        return True
    if previous in CAPACITY_PHASES and current in CAPACITY_PHASES:
        return CAPACITY_PHASES.index(current) == CAPACITY_PHASES.index(previous) + 1
    if previous in RETENTION_PHASES and current in RETENTION_PHASES:
        return RETENTION_PHASES.index(current) == RETENTION_PHASES.index(previous) + 1
    return previous == "STAGE_RETAINED" and current == "RETENTION_INTENT_RESERVED"


def validate_capacity_generation_chain(value: Any, *, recovery: bool = False) -> None:
    generations = require_array(value, minimum=1, maximum=64)
    previous: Mapping[str, Any] | None = None
    for index, raw_generation in enumerate(generations):
        validate_capacity_generation(raw_generation)
        generation = require_object(raw_generation)
        if index == 0 and (
            generation["generation"] != 0
            or generation["owner_kind"] != "capacity"
            or generation["phase"] != "RESERVED"
        ):
            refuse("capacity generation chain lacks its generation-zero root")
        if previous is not None:
            if generation["generation"] != previous["generation"] + 1:
                refuse("capacity generation chain skips or replays a generation")
            if generation["predecessor_sha256"] != capacity_generation_digest(previous):
                refuse(
                    "capacity generation predecessor does not bind exact prior bytes"
                )
            if not _next_phase(
                previous["phase"], generation["phase"], recovery=recovery
            ):
                refuse(
                    "capacity generation chain skips, regresses, or changes owner illegally"
                )
            for field in (
                "reservation_id",
                "release_id",
                "policy_sha256",
                "transaction_id",
                "install_authority_sha256",
                "creator_boot_id",
                "memory_reserved_bytes",
                "filesystem_reservations",
                "root_identities",
                "stable_lock_identity",
            ):
                if generation[field] != previous[field]:
                    refuse("immutable capacity authority changed across generations")
        previous = generation


def validate_release_proof(value: Any) -> None:
    proof = require_object(value)
    require_keys(
        proof,
        required=(
            "schema",
            "release_kind",
            "permanent",
            "reservation_id",
            "generation",
            "releasing_generation_sha256",
            "resource_absence_sha256",
            "phase_payload",
        ),
    )
    if proof["schema"] != "kilix.content.release-proof/v2":
        refuse("release proof schema is not v2")
    kind = proof["release_kind"]
    payload = require_object(proof["phase_payload"])
    if kind == "ordinary":
        if proof["permanent"] is not False:
            refuse("ordinary release proof cannot be permanent")
        require_keys(payload, required=("next_phase", "tombstone_sha256"))
        if payload["next_phase"] != "RELEASE_PROOFED":
            refuse("ordinary release proof next phase is not frozen")
        require_digest(payload["tombstone_sha256"])
    elif kind == "retention_handoff":
        if proof["permanent"] is not True:
            refuse("retention handoff proof is not permanent")
        require_keys(
            payload,
            required=(
                "next_phase",
                "intent_sha256",
                "accounted_sha256",
                "handoff_sha256",
            ),
        )
        if payload["next_phase"] != "RETENTION_HANDOFF_PROOFED":
            refuse("retention release proof next phase is not frozen")
        for name in ("intent_sha256", "accounted_sha256", "handoff_sha256"):
            require_digest(payload[name])
    else:
        refuse("release proof kind is outside the frozen enum")
    require_id(proof["reservation_id"])
    require_s64(proof["generation"], positive=True)
    require_digest(proof["releasing_generation_sha256"])
    require_digest(proof["resource_absence_sha256"])


def production_capacity_policy_available() -> bool:
    """No production H0-H3 values exist before the separate F100-C0 gate."""
    return False


CAPACITY_VALIDATORS = {
    "kilix.content.capacity-reserve/v2": validate_capacity_policy,
    "kilix.content.capacity-lock/v2": validate_capacity_lock,
    "kilix.content.capacity-generation/v2": validate_capacity_generation,
    "kilix.content.release-proof/v2": validate_release_proof,
}


__all__ = [
    "ALL_MAXIMUM_PHASES",
    "CAPACITY_PHASES",
    "CAPACITY_VALIDATORS",
    "OWNER_PHASES",
    "RECOVERY_PHASE",
    "RETENTION_PHASES",
    "ROOT_ROLES",
    "TRANSACTION_PHASES",
    "production_capacity_policy_available",
    "validate_capacity_generation",
    "validate_capacity_generation_chain",
    "validate_capacity_lock",
    "validate_capacity_policy",
    "validate_release_proof",
]
