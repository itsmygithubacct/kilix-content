"""Pure R10-R13 retention records, equations, and inert recovery oracles."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .u1_core import (
    ZERO_DIGEST,
    capacity_generation_digest,
    canonical_digest,
    canonical_json_bytes,
    checked_add,
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
    retention_accounted_digest,
    retention_absence_evidence_digest,
    retention_component_digest,
    retention_component_envelope_digest,
    retention_descriptor_digest,
    retention_envelope_digest,
    retention_intent_digest,
    retention_logical_state_digest,
    retention_marker_digest,
    retention_marker_content_digest,
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


TRANSACTION_PHASES = (
    "RETENTION_PREPARED",
    "RETENTION_MARKER_DURABLE",
    "RETENTION_RELATION_DURABLE",
    "RETENTION_READY",
    "RETENTION_ACCOUNTED",
    "RETENTION_HANDOFF_COMPLETE",
)
CAPACITY_PHASES = (
    "RETENTION_INTENT_RESERVED",
    "RETENTION_ACCOUNTED",
    "RETENTION_HANDOFF_RELEASING",
    "RETENTION_HANDOFF_PROOFED",
    "tombstone",
    "absent",
)
COMPONENT_ROLES = ("D", "M", "R", "P", "H")
FILE_ROLES = ("M", "R", "P", "H")
COMPONENT_STATES = (
    "both-absent",
    "complete-temporary-only",
    "torn-temporary-only",
    "empty-directory-temporary-only",
    "final-only-parent-durability-unknown",
    "recognized-temporary-and-final",
    "no-replace-collision",
    "unexpected-or-hostile",
)
HANDOFF_ROW_IDS = (
    "capacity-absent-journal-accounted",
    "capacity-absent-journal-complete",
    "capacity-accounted-h-absent",
    "capacity-proofed-final-reservation",
    "capacity-releasing-h-absent",
    "capacity-releasing-h-final",
    "capacity-releasing-h-temporary",
    "impossible-owner-phase",
    "intent-accounted-p",
    "intent-prepared-partial-components",
    "intent-ready-final-p",
    "later-journal-terminal",
    "terminal-before-new-intent",
    "tombstone-plus-h",
)
IMPOSSIBLE_REASONS = {
    "capacity-absent-without-h",
    "component-conflict",
    "digest-direction-mismatch",
    "duplicate-h",
    "h-before-releasing",
    "h-missing-after-proofed",
    "identity-alias",
    "new-intent-over-pending-terminal",
    "owner-phase-mismatch",
    "predecessor-mismatch",
    "target-mutation-without-prepared-intent",
    "unexpected-directory-entry",
}
COMPONENT_RECOVERY_EXPECTATIONS = {
    "both-absent": {
        "classification": "ordinary-absent",
        "allowed_next_record": "start-component",
        "charge_kind": "live-envelope",
        "quarantine": False,
        "exposure_allowed": False,
        "first_result": "start-component",
        "repeated_result": "start-component",
    },
    "complete-temporary-only": {
        "classification": "ordinary-complete-temporary",
        "allowed_next_record": "finish-publication",
        "charge_kind": "live-envelope",
        "quarantine": False,
        "exposure_allowed": False,
        "first_result": "canonical-final",
        "repeated_result": "canonical-final",
    },
    "final-only-parent-durability-unknown": {
        "classification": "ordinary-final-durability-unknown",
        "allowed_next_record": "repeat-parent-durability",
        "charge_kind": "actual-plus-live",
        "quarantine": False,
        "exposure_allowed": False,
        "first_result": "canonical-final",
        "repeated_result": "canonical-final",
    },
    "recognized-temporary-and-final": {
        "classification": "ordinary-recognized-both",
        "allowed_next_record": "validate-final-clean-temporary",
        "charge_kind": "actual-plus-live",
        "quarantine": False,
        "exposure_allowed": False,
        "first_result": "canonical-final",
        "repeated_result": "canonical-final",
    },
    "no-replace-collision": {
        "classification": "conditional-final-collision",
        "allowed_next_record": "validate-final-or-quarantine",
        "charge_kind": "actual-plus-ambiguity",
        "quarantine": False,
        "exposure_allowed": False,
        "first_result": "validated-final",
        "repeated_result": "validated-final",
    },
    "unexpected-or-hostile": {
        "classification": "hostile-or-unclassifiable",
        "allowed_next_record": "quarantine",
        "charge_kind": "actual-plus-envelope-plus-ambiguity",
        "quarantine": True,
        "exposure_allowed": False,
        "first_result": "quarantine",
        "repeated_result": "quarantine",
    },
}


def component_recovery_expected(role: str, state: str) -> dict[str, Any]:
    """Return the exact inert expected result for one R12/R13 component row."""
    if role not in COMPONENT_ROLES or state not in COMPONENT_STATES:
        refuse("recovery component selector is outside the frozen matrix")
    if state == "torn-temporary-only":
        if role == "D":
            return {
                "classification": "incompatible-file-temporary",
                "allowed_next_record": "quarantine",
                "charge_kind": "actual-plus-envelope-plus-ambiguity",
                "quarantine": True,
                "exposure_allowed": False,
                "first_result": "quarantine",
                "repeated_result": "quarantine",
            }
        return {
            "classification": "ordinary-torn-file-temporary",
            "allowed_next_record": "discard-and-recreate",
            "charge_kind": "live-envelope",
            "quarantine": False,
            "exposure_allowed": False,
            "first_result": "recreate-component",
            "repeated_result": "recreate-component",
        }
    if state == "empty-directory-temporary-only":
        if role == "D":
            return {
                "classification": "ordinary-empty-directory-temporary",
                "allowed_next_record": "finish-or-recreate-directory",
                "charge_kind": "live-envelope",
                "quarantine": False,
                "exposure_allowed": False,
                "first_result": "canonical-final",
                "repeated_result": "canonical-final",
            }
        return {
            "classification": "incompatible-directory-temporary",
            "allowed_next_record": "quarantine",
            "charge_kind": "actual-plus-envelope-plus-ambiguity",
            "quarantine": True,
            "exposure_allowed": False,
            "first_result": "quarantine",
            "repeated_result": "quarantine",
        }
    return dict(COMPONENT_RECOVERY_EXPECTATIONS[state])


HANDOFF_RECOVERY_EXPECTATIONS = {
    "intent-prepared-partial-components": (
        "RETENTION_PREPARED",
        "RETENTION_INTENT_RESERVED",
        "absent",
        "resume-component-automaton",
        "live-envelope",
        False,
        False,
        False,
        "in-progress",
    ),
    "intent-ready-final-p": (
        "RETENTION_READY",
        "RETENTION_INTENT_RESERVED",
        "absent",
        "commit-journal-accounted",
        "live-plus-permanent",
        False,
        False,
        False,
        "journal-accounted",
    ),
    "intent-accounted-p": (
        "RETENTION_ACCOUNTED",
        "RETENTION_INTENT_RESERVED",
        "absent",
        "commit-capacity-accounted",
        "live-plus-permanent",
        False,
        False,
        False,
        "capacity-accounted",
    ),
    "capacity-accounted-h-absent": (
        "RETENTION_ACCOUNTED",
        "RETENTION_ACCOUNTED",
        "absent",
        "commit-handoff-releasing",
        "live-plus-permanent",
        False,
        False,
        False,
        "handoff-releasing",
    ),
    "capacity-releasing-h-absent": (
        "RETENTION_ACCOUNTED",
        "RETENTION_HANDOFF_RELEASING",
        "absent",
        "create-intent-bound-h",
        "live-plus-permanent",
        False,
        False,
        False,
        "handoff-in-progress",
    ),
    "capacity-releasing-h-temporary": (
        "RETENTION_ACCOUNTED",
        "RETENTION_HANDOFF_RELEASING",
        "temporary",
        "resume-intent-bound-h",
        "live-plus-permanent",
        False,
        False,
        False,
        "handoff-in-progress",
    ),
    "capacity-releasing-h-final": (
        "RETENTION_ACCOUNTED",
        "RETENTION_HANDOFF_RELEASING",
        "final",
        "commit-handoff-proofed",
        "live-plus-permanent",
        False,
        False,
        False,
        "handoff-proofed",
    ),
    "capacity-proofed-final-reservation": (
        "RETENTION_ACCOUNTED",
        "RETENTION_HANDOFF_PROOFED",
        "final",
        "retire-reservation",
        "live-plus-permanent",
        False,
        False,
        True,
        "reservation-retiring",
    ),
    "tombstone-plus-h": (
        "RETENTION_ACCOUNTED",
        "tombstone",
        "final",
        "finish-tombstone-cleanup",
        "permanent",
        False,
        False,
        True,
        "capacity-absent",
    ),
    "capacity-absent-journal-accounted": (
        "RETENTION_ACCOUNTED",
        "absent",
        "final",
        "commit-journal-handoff-complete",
        "permanent",
        False,
        False,
        False,
        "journal-handoff-complete",
    ),
    "capacity-absent-journal-complete": (
        "RETENTION_HANDOFF_COMPLETE",
        "absent",
        "final",
        "fresh-admission-scan",
        "permanent",
        False,
        True,
        False,
        "terminal",
    ),
    "later-journal-terminal": (
        "RETENTION_HANDOFF_COMPLETE",
        "absent",
        "final",
        "fresh-admission-scan",
        "permanent",
        False,
        True,
        False,
        "terminal",
    ),
    "terminal-before-new-intent": (
        "RETENTION_HANDOFF_COMPLETE",
        "absent",
        "final",
        "reuse-terminal",
        "permanent",
        False,
        True,
        False,
        "terminal-reused",
    ),
    "impossible-owner-phase": (
        "RETENTION_PREPARED",
        "RETENTION_HANDOFF_PROOFED",
        "absent",
        "quarantine",
        "live-plus-permanent-plus-ambiguity",
        True,
        False,
        False,
        "quarantine",
    ),
}


def handoff_recovery_expected(identifier: str) -> dict[str, Any]:
    values = HANDOFF_RECOVERY_EXPECTATIONS.get(identifier)
    if values is None:
        refuse("handoff recovery row is outside the frozen matrix")
    (
        transaction_phase,
        capacity_phase,
        h_state,
        expected_action,
        charge_kind,
        quarantine,
        selection_allowed,
        cleanup_allowed,
        result,
    ) = values
    return {
        "id": identifier,
        "transaction_phase": transaction_phase,
        "capacity_phase": capacity_phase,
        "h_state": h_state,
        "expected_action": expected_action,
        "charge_kind": charge_kind,
        "quarantine": quarantine,
        "selection_allowed": selection_allowed,
        "cleanup_allowed": cleanup_allowed,
        "first_result": result,
        "repeated_result": result,
    }


TEMP_NAME_RE = re.compile(
    r"^\.new-retention-[0-9a-f]{64}-(?:dir-[0-9]{1,2}|marker|relation|accounted|handoff)$"
)
CHILD_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DERIVATIONS = {
    "D": "empty-directory-from-intent",
    "M": "marker-from-intent-and-capacity",
    "R": "relation-from-intent-and-marker",
    "P": "accounted-from-intent-and-ready",
    "H": "handoff-from-intent-and-releasing",
}
PHASE_FINAL_ROLES = {
    "RETENTION_PREPARED": set(),
    "RETENTION_MARKER_DURABLE": {"D", "M"},
    "RETENTION_RELATION_DURABLE": {"D", "M", "R"},
    "RETENTION_READY": {"D", "M", "R"},
    "RETENTION_ACCOUNTED": {"D", "M", "R", "P"},
    "RETENTION_HANDOFF_COMPLETE": {"D", "M", "R", "P", "H"},
}


def _canonical_set(values: Sequence[Mapping[str, Any]]) -> set[bytes]:
    return {canonical_json_bytes(value) for value in values}


def _validate_object_identity(value: Any) -> dict[str, Any]:
    identity = require_object(value)
    require_keys(
        identity, required=("install_authority_sha256", "output_binding_sha256")
    )
    require_digest(identity["install_authority_sha256"])
    require_digest(identity["output_binding_sha256"])
    return identity


def _validate_relation_identity(value: Any) -> dict[str, Any]:
    identity = require_object(value)
    require_keys(
        identity,
        required=(
            "stable_slot_sha256",
            "install_authority_sha256",
            "output_binding_sha256",
        ),
    )
    require_digest(identity["stable_slot_sha256"])
    require_digest(identity["install_authority_sha256"])
    require_digest(identity["output_binding_sha256"])
    return identity


def _temporary_name(
    role: str, ordinal: int, creation_nonce: str, handoff_nonce: str
) -> str:
    if role == "D":
        return f".new-retention-{creation_nonce}-dir-{ordinal}"
    suffix = {"M": "marker", "R": "relation", "P": "accounted", "H": "handoff"}[role]
    nonce = handoff_nonce if role == "H" else creation_nonce
    return f".new-retention-{nonce}-{suffix}"


def validate_retention_component(value: Any) -> None:
    component = require_object(value)
    role = component.get("role")
    required = (
        "schema",
        "role",
        "filesystem_key",
        "root_identity",
        "nearest_existing_ancestor",
        "final_relative_path",
        "temporary_basename",
        "uid",
        "gid",
        "mode",
        "object_type",
        "max_bytes",
        "max_inodes",
        "max_parent_growth",
        "semantic_input",
    )
    if role == "D":
        required = (*required, "ordinal")
    require_keys(component, required=required)
    if (
        component["schema"] != "kilix.content.retention-component/v1"
        or role not in COMPONENT_ROLES
    ):
        refuse("retention component schema or role is not frozen")
    ordinal = require_s64(component["ordinal"]) if role == "D" else 0
    for name in ("filesystem_key", "root_identity", "nearest_existing_ancestor"):
        require_digest(component[name])
    require_relative_path(component["final_relative_path"])
    require_text(component["temporary_basename"], TEMP_NAME_RE, maximum=128)
    for name in ("uid", "gid"):
        require_s64(component[name])
    expected_type = "directory" if role == "D" else "regular"
    expected_mode = 0o700 if role == "D" else 0o600
    if component["object_type"] != expected_type or component["mode"] != expected_mode:
        refuse("retention component type or mode diverges from its role")
    require_s64(component["max_bytes"], positive=True)
    if require_s64(component["max_inodes"], positive=True) != 1:
        refuse("retention component inode maximum is not one")
    require_s64(component["max_parent_growth"])
    semantic = require_object(component["semantic_input"])
    require_keys(semantic, required=("derivation", "input_sha256s"))
    if semantic["derivation"] != DERIVATIONS[role]:
        refuse("retention component derivation is not frozen")
    inputs = require_array(semantic["input_sha256s"], maximum=32)
    for digest in inputs:
        require_digest(digest)
    if inputs != sorted(inputs) or len(inputs) != len(set(inputs)):
        refuse("retention component semantic inputs are not sorted unique data")
    if role != "D" and ordinal != 0:
        refuse("non-directory component has an ordinal")


def _validate_component_vector(
    value: Any,
    *,
    creation_nonce: str,
    handoff_nonce: str,
) -> list[dict[str, Any]]:
    components = require_array(value, minimum=4, maximum=36)
    for raw_component in components:
        validate_retention_component(raw_component)
    roles = [item["role"] for item in components]
    d_count = len(roles) - 4
    if roles != ["D"] * d_count + ["M", "R", "P", "H"]:
        refuse("retention components are not ordered D zero-to-n then M R P H")
    if [item["ordinal"] for item in components[:d_count]] != list(range(d_count)):
        refuse("retention directory ordinals are not contiguous")
    paths = [item["final_relative_path"] for item in components]
    if len(paths) != len(set(paths)):
        refuse("retention component final path is duplicated")
    for index, component in enumerate(components):
        ordinal = component.get("ordinal", 0)
        expected = _temporary_name(
            component["role"], ordinal, creation_nonce, handoff_nonce
        )
        if component["temporary_basename"] != expected:
            refuse("retention component temporary name is not nonce derived")
        if index and component["role"] == "D":
            parent = components[index - 1]["final_relative_path"]
            if not component["final_relative_path"].startswith(parent + "/"):
                refuse("retention directory chain is not outermost first")
    return components


def _validate_logical_state(value: Any) -> dict[str, Any]:
    state = require_object(value)
    require_keys(
        state,
        required=(
            "schema",
            "release_id",
            "O_materialized",
            "O_referenced",
            "O_counted",
            "R_present",
            "R_pending",
            "R_counted",
            "retained_unique_objects",
            "retained_versions",
            "account_retention_quarantined",
            "quarantine_reasons",
            "retention_admission_closed",
            "admission_closed_reasons",
        ),
    )
    if state["schema"] != "kilix.content.retention-logical-state/v1":
        refuse("retention logical-state schema is not frozen")
    require_id(state["release_id"])
    relations: dict[str, list[dict[str, Any]]] = {}
    for name in ("R_present", "R_pending", "R_counted"):
        entries = require_array(state[name], maximum=4_096)
        for entry in entries:
            _validate_relation_identity(entry)
        require_sorted_unique(entries)
        relations[name] = entries
    if _canonical_set(relations["R_counted"]) != (
        _canonical_set(relations["R_present"]) | _canonical_set(relations["R_pending"])
    ):
        refuse("R counted is not the union of present and pending relations")

    objects: dict[str, list[dict[str, Any]]] = {}
    for name in ("O_materialized", "O_referenced", "O_counted"):
        entries = require_array(state[name], maximum=4_096)
        for entry in entries:
            _validate_object_identity(entry)
        require_sorted_unique(entries)
        objects[name] = entries
    projected = [
        {
            "install_authority_sha256": relation["install_authority_sha256"],
            "output_binding_sha256": relation["output_binding_sha256"],
        }
        for relation in relations["R_counted"]
    ]
    if _canonical_set(objects["O_referenced"]) != _canonical_set(projected):
        refuse("O referenced is not the projection of R counted")
    counted = _canonical_set(objects["O_materialized"]) | _canonical_set(
        objects["O_referenced"]
    )
    if _canonical_set(objects["O_counted"]) != counted:
        refuse("O counted is not the materialized and referenced union")
    if require_s64(state["retained_unique_objects"]) != len(counted):
        refuse("retained unique object cardinality is inconsistent")

    expected_versions: dict[str, int] = {}
    for relation in relations["R_counted"]:
        slot = relation["stable_slot_sha256"]
        expected_versions[slot] = expected_versions.get(slot, 0) + 1
    versions = require_array(state["retained_versions"], maximum=4_096)
    observed_versions: dict[str, int] = {}
    for raw_version in versions:
        version = require_object(raw_version)
        require_keys(version, required=("stable_slot_sha256", "count"))
        slot = require_digest(version["stable_slot_sha256"])
        if slot in observed_versions:
            refuse("retained version slot is duplicated")
        observed_versions[slot] = require_s64(version["count"], positive=True)
    require_sorted_unique(versions)
    if observed_versions != expected_versions:
        refuse("retained per-slot version cardinality is inconsistent")

    if type(state["account_retention_quarantined"]) is not bool:
        refuse("retention quarantine flag is not boolean")
    quarantine = require_array(state["quarantine_reasons"], maximum=32)
    for reason in quarantine:
        require_id(reason)
    if quarantine != sorted(quarantine) or len(quarantine) != len(set(quarantine)):
        refuse("retention quarantine reasons are not sorted unique data")
    if state["account_retention_quarantined"] != bool(quarantine):
        refuse("retention quarantine flag and reasons diverge")
    closed_reasons = require_array(state["admission_closed_reasons"], maximum=32)
    for reason in closed_reasons:
        require_id(reason)
    if closed_reasons != sorted(closed_reasons) or len(closed_reasons) != len(
        set(closed_reasons)
    ):
        refuse("retention admission reasons are not sorted unique data")
    required_reasons = set()
    if quarantine:
        required_reasons.add("quarantine")
    if relations["R_pending"]:
        required_reasons.add("pending-relations")
    if not required_reasons <= set(closed_reasons):
        refuse("retention admission reasons omit a known closed condition")
    if type(state["retention_admission_closed"]) is not bool or state[
        "retention_admission_closed"
    ] != bool(closed_reasons):
        refuse("retention admission closure and reasons diverge")
    return state


def validate_retention_logical_state(value: Any) -> None:
    _validate_logical_state(value)


def _validate_component_identity(value: Any) -> dict[str, Any]:
    identity = require_object(value)
    require_keys(
        identity,
        required=(
            "component_role",
            "root_identity_sha256",
            "mount_identity_sha256",
            "device",
            "inode",
            "object_type",
            "descriptor_identity_sha256",
        ),
    )
    if identity["component_role"] not in {
        *COMPONENT_ROLES,
        "journal",
        "object",
        "ambiguity",
    }:
        refuse("physical component role is outside the frozen enum")
    for name in (
        "root_identity_sha256",
        "mount_identity_sha256",
        "descriptor_identity_sha256",
    ):
        require_digest(identity[name])
    require_s64(identity["device"], positive=True)
    require_s64(identity["inode"], positive=True)
    if identity["object_type"] not in {"directory", "regular"}:
        refuse("physical component object type is outside the frozen enum")
    return identity


def _validate_filesystem_union(value: Any) -> dict[str, Any]:
    union = require_object(value)
    require_keys(
        union,
        required=(
            "filesystem_key",
            "components",
            "actual_bytes",
            "actual_inodes",
            "prospective_bytes",
            "prospective_inodes",
            "ambiguity_bytes",
            "ambiguity_inodes",
            "directory_growth_bytes",
            "envelope_sha256",
        ),
    )
    require_digest(union["filesystem_key"])
    require_digest(union["envelope_sha256"])
    components = require_array(union["components"], maximum=4_096)
    seen: set[bytes] = set()
    totals = {
        "actual_bytes": 0,
        "actual_inodes": 0,
        "prospective_bytes": 0,
        "prospective_inodes": 0,
        "ambiguity_bytes": 0,
        "ambiguity_inodes": 0,
        "directory_growth_bytes": 0,
    }
    for raw_component in components:
        component = require_object(raw_component)
        require_keys(
            component,
            required=(
                "identity",
                "charge_source",
                "bytes",
                "inodes",
                "directory_growth_bytes",
            ),
        )
        identity = _validate_component_identity(component["identity"])
        encoded = canonical_json_bytes(identity)
        if encoded in seen:
            refuse("physical component identity is duplicated")
        seen.add(encoded)
        source = component["charge_source"]
        if source not in {"actual", "ambiguity", "prospective"}:
            refuse("physical component charge source is outside the frozen enum")
        byte_count = require_s64(component["bytes"])
        inode_count = require_s64(component["inodes"])
        growth = require_s64(component["directory_growth_bytes"])
        totals[f"{source}_bytes"] = checked_add(
            (totals[f"{source}_bytes"], byte_count, growth)
        )
        totals[f"{source}_inodes"] = checked_add(
            (totals[f"{source}_inodes"], inode_count)
        )
        totals["directory_growth_bytes"] = checked_add(
            (totals["directory_growth_bytes"], growth)
        )
    require_sorted_unique(components)
    for name, expected in totals.items():
        if require_s64(union[name]) != expected:
            refuse("physical filesystem union totals are inconsistent")
    if union["envelope_sha256"] != retention_physical_envelope_digest(union):
        refuse("physical filesystem envelope digest is inconsistent")
    return union


def _validate_physical_state(value: Any) -> dict[str, Any]:
    state = require_object(value)
    require_keys(
        state,
        required=(
            "schema",
            "release_id",
            "filesystem_unions",
            "scan_complete",
            "incomplete_representations",
            "scan_bound_exhausted",
        ),
    )
    if state["schema"] != "kilix.content.retention-physical-state/v1":
        refuse("retention physical-state schema is not frozen")
    require_id(state["release_id"])
    unions = require_array(state["filesystem_unions"], maximum=32)
    keys: set[str] = set()
    identities: set[bytes] = set()
    for raw_union in unions:
        union = _validate_filesystem_union(raw_union)
        key = union["filesystem_key"]
        if key in keys:
            refuse("physical state repeats a filesystem union")
        keys.add(key)
        for component in union["components"]:
            identity = canonical_json_bytes(component["identity"])
            if identity in identities:
                refuse("physical identity aliases across filesystem unions")
            identities.add(identity)
    require_sorted_unique(unions)
    if (
        type(state["scan_complete"]) is not bool
        or type(state["scan_bound_exhausted"]) is not bool
    ):
        refuse("physical scan state is not boolean")
    incomplete = require_array(state["incomplete_representations"], maximum=4_096)
    for entry in incomplete:
        require_digest(entry)
    if incomplete != sorted(incomplete) or len(incomplete) != len(set(incomplete)):
        refuse("incomplete physical identities are not sorted unique data")
    if state["scan_complete"] == bool(incomplete or state["scan_bound_exhausted"]):
        refuse("physical scan completeness is inconsistent")
    return state


def validate_retention_physical_state(value: Any) -> None:
    _validate_physical_state(value)


def validate_retention_admission(
    logical_value: Any,
    physical_value: Any,
    limits_value: Any,
) -> None:
    """Cross-check capacity limits and the fail-closed admission bit."""
    logical = _validate_logical_state(logical_value)
    physical = _validate_physical_state(physical_value)
    limits = require_object(limits_value)
    require_keys(
        limits,
        required=(
            "retained_unique_objects_max",
            "retained_allocated_bytes_max",
            "retained_inodes_max",
            "retained_versions_per_stable_slot_max",
            "ambiguous_retained_objects_max",
        ),
    )
    for raw_limit in limits.values():
        require_s64(raw_limit, positive=True)
    totals = {"bytes": 0, "inodes": 0, "ambiguity": 0}
    for union in physical["filesystem_unions"]:
        totals["bytes"] = checked_add(
            (
                totals["bytes"],
                union["actual_bytes"],
                union["prospective_bytes"],
                union["ambiguity_bytes"],
            )
        )
        totals["inodes"] = checked_add(
            (
                totals["inodes"],
                union["actual_inodes"],
                union["prospective_inodes"],
                union["ambiguity_inodes"],
            )
        )
        totals["ambiguity"] = checked_add(
            (
                totals["ambiguity"],
                sum(
                    1
                    for item in union["components"]
                    if item["charge_source"] == "ambiguity"
                ),
            )
        )
    exceeded = (
        logical["retained_unique_objects"] > limits["retained_unique_objects_max"]
        or any(
            item["count"] > limits["retained_versions_per_stable_slot_max"]
            for item in logical["retained_versions"]
        )
        or totals["bytes"] > limits["retained_allocated_bytes_max"]
        or totals["inodes"] > limits["retained_inodes_max"]
        or totals["ambiguity"] > limits["ambiguous_retained_objects_max"]
    )
    reasons = set(logical["admission_closed_reasons"])
    expected = set()
    if logical["account_retention_quarantined"]:
        expected.add("quarantine")
    if logical["R_pending"]:
        expected.add("pending-relations")
    if physical["incomplete_representations"] or not physical["scan_complete"]:
        expected.add("incomplete-representation")
    if physical["scan_bound_exhausted"]:
        expected.add("scan-bound-exhausted")
    if exceeded:
        expected.add("limit-exceeded")
    if reasons != expected or logical["retention_admission_closed"] != bool(expected):
        refuse("retention admission result is not the recomputed fail-closed state")


def _validate_attestation(value: Any, *, selected_tree: bool) -> None:
    attestation = require_object(value)
    digest_name = "tree_sha256" if selected_tree else "descriptor_sha256"
    require_keys(
        attestation, required=(digest_name, "content_sha256", "bytes", "files")
    )
    require_digest(attestation[digest_name])
    require_digest(attestation["content_sha256"])
    require_s64(attestation["bytes"])
    require_s64(attestation["files"])


def _validate_component_envelope_entries(value: Any) -> list[dict[str, Any]]:
    entries = require_array(value, minimum=4, maximum=36)
    for raw_entry in entries:
        entry = require_object(raw_entry)
        require_keys(
            entry,
            required=(
                "role",
                "ordinal",
                "component_sha256",
                "max_bytes",
                "max_inodes",
                "max_parent_growth",
            ),
        )
        if entry["role"] not in COMPONENT_ROLES:
            refuse("component envelope role is outside the frozen enum")
        require_s64(entry["ordinal"])
        require_digest(entry["component_sha256"])
        require_s64(entry["max_bytes"], positive=True)
        require_s64(entry["max_inodes"], positive=True)
        require_s64(entry["max_parent_growth"])
    require_sorted_unique(entries)
    return entries


def validate_retention_intent(value: Any) -> None:
    intent = require_object(value)
    require_keys(
        intent,
        required=(
            "schema",
            "transaction_id",
            "reservation_id",
            "creation_nonce",
            "handoff_nonce",
            "stable_slot_sha256",
            "install_authority_sha256",
            "output_binding_sha256",
            "release_id",
            "catalog_sha256",
            "capacity_policy_sha256",
            "profile_sha256",
            "object_identity",
            "descriptor_attestation",
            "selected_tree_attestation",
            "filesystem_keys",
            "root_identities",
            "pre_admission_set_sha256",
            "pre_admission_scan_sha256",
            "proposed_logical_state",
            "proposed_physical_state",
            "component_envelope",
            "component_envelope_sha256",
            "components",
            "target_names",
            "temporary_names",
            "derivation_rules",
            "component_schemas",
            "component_maxima",
            "directory_child_rules",
        ),
    )
    if intent["schema"] != "kilix.content.retention-intent/v1":
        refuse("retention intent schema is not frozen")
    require_id(intent["transaction_id"])
    require_id(intent["reservation_id"])
    creation_nonce = require_digest(intent["creation_nonce"])
    handoff_nonce = require_digest(intent["handoff_nonce"])
    if creation_nonce == handoff_nonce:
        refuse("retention creation and handoff nonces are not distinct")
    for name in (
        "stable_slot_sha256",
        "install_authority_sha256",
        "output_binding_sha256",
        "catalog_sha256",
        "capacity_policy_sha256",
        "profile_sha256",
        "pre_admission_set_sha256",
        "pre_admission_scan_sha256",
        "component_envelope_sha256",
    ):
        require_digest(intent[name])
    require_id(intent["release_id"])
    if _validate_object_identity(intent["object_identity"]) != {
        "install_authority_sha256": intent["install_authority_sha256"],
        "output_binding_sha256": intent["output_binding_sha256"],
    }:
        refuse("retention intent object identity diverges from authority")
    _validate_attestation(intent["descriptor_attestation"], selected_tree=False)
    _validate_attestation(intent["selected_tree_attestation"], selected_tree=True)
    filesystems = require_array(intent["filesystem_keys"], minimum=1, maximum=32)
    for digest in filesystems:
        require_digest(digest)
    if filesystems != sorted(filesystems) or len(filesystems) != len(set(filesystems)):
        refuse("retention intent filesystem keys are not sorted unique data")
    roots = require_array(intent["root_identities"], minimum=1, maximum=32)
    for raw_root in roots:
        root = require_object(raw_root)
        require_keys(root, required=("role", "identity_sha256"))
        require_id(root["role"])
        require_digest(root["identity_sha256"])
    require_sorted_unique(roots)
    logical = _validate_logical_state(intent["proposed_logical_state"])
    physical = _validate_physical_state(intent["proposed_physical_state"])
    if (
        logical["release_id"] != intent["release_id"]
        or physical["release_id"] != intent["release_id"]
    ):
        refuse("retention intent proposed states diverge from release authority")

    components = _validate_component_vector(
        intent["components"], creation_nonce=creation_nonce, handoff_nonce=handoff_nonce
    )
    if {item["filesystem_key"] for item in components} - set(filesystems):
        refuse("retention component references an undeclared filesystem key")
    if {item["root_identity"] for item in components} - {
        item["identity_sha256"] for item in roots
    }:
        refuse("retention component references an undeclared root identity")

    envelope = _validate_component_envelope_entries(intent["component_envelope"])
    expected_envelope = [
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
    expected_envelope.sort(key=canonical_json_bytes)
    if envelope != expected_envelope:
        refuse("retention component envelope does not match components")
    envelope_identity = {
        "transaction_id": intent["transaction_id"],
        "reservation_id": intent["reservation_id"],
        "creation_nonce": intent["creation_nonce"],
    }
    if intent["component_envelope_sha256"] != retention_component_envelope_digest(
        envelope_identity, envelope
    ):
        refuse("retention component envelope digest is inconsistent")

    projections = {
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
            {"role": role, "rule": DERIVATIONS[role]} for role in COMPONENT_ROLES
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
    }
    for name, expected in projections.items():
        if intent[name] != expected:
            refuse("retention intent projection is inconsistent")
    rules = require_array(
        intent["directory_child_rules"], maximum=32 * len(TRANSACTION_PHASES)
    )
    d_count = len(components) - 4
    expected_rule_keys = {
        (ordinal, phase) for ordinal in range(d_count) for phase in TRANSACTION_PHASES
    }
    observed_rule_keys: set[tuple[int, str]] = set()
    for raw_rule in rules:
        rule = require_object(raw_rule)
        require_keys(
            rule,
            required=(
                "ordinal",
                "phase",
                "allowed_final_roles",
                "current_temporary_allowed",
            ),
        )
        ordinal = require_s64(rule["ordinal"])
        phase = rule["phase"]
        if (ordinal, phase) not in expected_rule_keys:
            refuse("directory child rule selector is outside the intent")
        observed_rule_keys.add((ordinal, phase))
        allowed = require_array(
            rule["allowed_final_roles"], maximum=len(COMPONENT_ROLES)
        )
        if allowed != sorted(PHASE_FINAL_ROLES[phase]):
            refuse("directory child rule final-role set is inconsistent")
        if type(rule["current_temporary_allowed"]) is not bool:
            refuse("directory current-temporary allowance is not boolean")
    require_sorted_unique(rules)
    if observed_rule_keys != expected_rule_keys:
        refuse("directory child rule matrix is incomplete")


def validate_retention_envelope(value: Any) -> None:
    envelope = require_object(value)
    require_keys(
        envelope, required=("schema", "intent_identity", "entries", "envelope_sha256")
    )
    if envelope["schema"] != "kilix.content.retention-envelope/v1":
        refuse("retention envelope schema is not frozen")
    identity = require_object(envelope["intent_identity"])
    require_keys(
        identity, required=("transaction_id", "reservation_id", "creation_nonce")
    )
    require_id(identity["transaction_id"])
    require_id(identity["reservation_id"])
    require_digest(identity["creation_nonce"])
    _validate_component_envelope_entries(envelope["entries"])
    require_digest(envelope["envelope_sha256"])
    if envelope["envelope_sha256"] != retention_envelope_digest(envelope):
        refuse("retention envelope digest is inconsistent")


def validate_intent_envelope(intent_value: Any, envelope_value: Any) -> None:
    validate_retention_intent(intent_value)
    validate_retention_envelope(envelope_value)
    intent = require_object(intent_value)
    envelope = require_object(envelope_value)
    expected_identity = {
        "transaction_id": intent["transaction_id"],
        "reservation_id": intent["reservation_id"],
        "creation_nonce": intent["creation_nonce"],
    }
    if (
        envelope["intent_identity"] != expected_identity
        or envelope["entries"] != intent["component_envelope"]
    ):
        refuse("retention envelope diverges from its intent")
    if envelope["envelope_sha256"] != intent["component_envelope_sha256"]:
        refuse("retention intent and envelope digests diverge")


def _validate_actual_descriptor(value: Any, *, expected_role: str) -> dict[str, Any]:
    descriptor = require_object(value)
    required = (
        "role",
        "filesystem_key",
        "root_identity",
        "mount_identity",
        "descriptor_identity_sha256",
        "relative_path",
        "uid",
        "gid",
        "mode",
        "object_type",
        "content_sha256",
        "bytes",
        "inodes",
    )
    if expected_role in FILE_ROLES:
        required = (*required, "nlink")
    require_keys(descriptor, required=required)
    if descriptor["role"] != expected_role:
        refuse("retention descriptor role is not expected")
    expected_type = "directory" if expected_role in {"D", "object"} else "regular"
    if descriptor["object_type"] != expected_type:
        refuse("retention descriptor type diverges from its role")
    for name in (
        "filesystem_key",
        "root_identity",
        "mount_identity",
        "descriptor_identity_sha256",
        "content_sha256",
    ):
        require_digest(descriptor[name])
    require_relative_path(descriptor["relative_path"])
    for name in ("uid", "gid", "bytes"):
        require_s64(descriptor[name])
    if require_s64(descriptor["inodes"], positive=True) != 1:
        refuse("retention descriptor inode cardinality is not one")
    expected_mode = 0o700 if expected_type == "directory" else 0o600
    if descriptor["mode"] != expected_mode:
        refuse("retention descriptor mode diverges from its role")
    if expected_role in FILE_ROLES and descriptor["nlink"] != 1:
        refuse("retention regular file link count is not one")
    if descriptor["descriptor_identity_sha256"] != retention_descriptor_digest(
        descriptor
    ):
        refuse("retention descriptor identity digest is inconsistent")
    return descriptor


def _intent_component(intent: Mapping[str, Any], role: str) -> dict[str, Any]:
    matches = [
        component for component in intent["components"] if component["role"] == role
    ]
    if len(matches) != 1:
        refuse("retention intent does not contain one required file component")
    return matches[0]


def _validate_descriptor_against_component(
    descriptor: Mapping[str, Any], component: Mapping[str, Any]
) -> None:
    for descriptor_field, component_field in (
        ("role", "role"),
        ("filesystem_key", "filesystem_key"),
        ("root_identity", "root_identity"),
        ("relative_path", "final_relative_path"),
        ("uid", "uid"),
        ("gid", "gid"),
        ("mode", "mode"),
        ("object_type", "object_type"),
    ):
        if descriptor[descriptor_field] != component[component_field]:
            refuse("retention descriptor diverges from its intent component")
    if (
        descriptor["bytes"] > component["max_bytes"]
        or descriptor["inodes"] > component["max_inodes"]
    ):
        refuse("retention descriptor exceeds its intent component maximum")


def _physical_components_by_source(
    state: Mapping[str, Any], source: str
) -> list[dict[str, Any]]:
    return [
        component
        for union in state["filesystem_unions"]
        for component in union["components"]
        if component["charge_source"] == source
    ]


def _require_physical_descriptor(
    state: Mapping[str, Any], descriptor: Mapping[str, Any], source: str
) -> None:
    matches = [
        component
        for component in _physical_components_by_source(state, source)
        if component["identity"]["component_role"] == descriptor["role"]
        and component["identity"]["root_identity_sha256"] == descriptor["root_identity"]
        and component["identity"]["mount_identity_sha256"]
        == descriptor["mount_identity"]
        and component["identity"]["descriptor_identity_sha256"]
        == descriptor["descriptor_identity_sha256"]
    ]
    if len(matches) != 1:
        refuse("retention physical state does not bind one exact descriptor")


def _require_one_prospective_role(state: Mapping[str, Any], role: str) -> None:
    matches = [
        component
        for component in _physical_components_by_source(state, "prospective")
        if component["identity"]["component_role"] == role
    ]
    if len(matches) != 1:
        refuse("retention physical state lacks one prospective component maximum")


def _validate_marker_relation_common(record: Mapping[str, Any]) -> None:
    require_id(record["release_id"])
    require_id(record["transaction_id"])
    require_id(record["reservation_id"])
    for name in (
        "intent_sha256",
        "component_envelope_sha256",
        "intent_capacity_generation_sha256",
        "stable_slot_sha256",
        "install_authority_sha256",
        "output_binding_sha256",
        "catalog_sha256",
        "profile_sha256",
        "predecessor_transaction_generation_sha256",
        "semantic_payload_sha256",
    ):
        require_digest(record[name])


def validate_retention_marker(value: Any) -> None:
    marker = require_object(value)
    require_keys(
        marker,
        required=(
            "schema",
            "record_kind",
            "release_id",
            "transaction_id",
            "reservation_id",
            "intent_sha256",
            "component_envelope_sha256",
            "intent_capacity_generation_sha256",
            "stable_slot_sha256",
            "install_authority_sha256",
            "output_binding_sha256",
            "catalog_sha256",
            "profile_sha256",
            "predecessor_transaction_generation_sha256",
            "descriptor",
            "semantic_payload_sha256",
        ),
    )
    if (
        marker["schema"] != "kilix.content.retention-marker/v1"
        or marker["record_kind"] != "M"
    ):
        refuse("retention marker schema or kind is not frozen")
    _validate_marker_relation_common(marker)
    descriptor = _validate_actual_descriptor(marker["descriptor"], expected_role="M")
    if marker["semantic_payload_sha256"] != retention_marker_semantic_digest(marker):
        refuse("retention marker semantic payload digest is inconsistent")
    if descriptor["content_sha256"] != retention_marker_content_digest(
        marker
    ) or descriptor["bytes"] != len(retention_marker_semantic_bytes(marker)):
        refuse("retention marker content digest is inconsistent")


def validate_retention_relation(value: Any) -> None:
    relation = require_object(value)
    require_keys(
        relation,
        required=(
            "schema",
            "record_kind",
            "release_id",
            "transaction_id",
            "reservation_id",
            "intent_sha256",
            "component_envelope_sha256",
            "intent_capacity_generation_sha256",
            "stable_slot_sha256",
            "install_authority_sha256",
            "output_binding_sha256",
            "catalog_sha256",
            "profile_sha256",
            "predecessor_transaction_generation_sha256",
            "marker_sha256",
            "relation_identity",
            "descriptor",
            "semantic_payload_sha256",
        ),
    )
    if (
        relation["schema"] != "kilix.content.retention-relation/v1"
        or relation["record_kind"] != "R"
    ):
        refuse("retention relation schema or kind is not frozen")
    _validate_marker_relation_common(relation)
    require_digest(relation["marker_sha256"])
    identity = _validate_relation_identity(relation["relation_identity"])
    if identity != {
        "stable_slot_sha256": relation["stable_slot_sha256"],
        "install_authority_sha256": relation["install_authority_sha256"],
        "output_binding_sha256": relation["output_binding_sha256"],
    }:
        refuse("retention relation identity diverges from its authority")
    descriptor = _validate_actual_descriptor(relation["descriptor"], expected_role="R")
    if relation["semantic_payload_sha256"] != retention_relation_semantic_digest(
        relation
    ):
        refuse("retention relation semantic payload digest is inconsistent")
    if descriptor["content_sha256"] != retention_relation_content_digest(
        relation
    ) or descriptor["bytes"] != len(retention_relation_semantic_bytes(relation)):
        refuse("retention relation content digest is inconsistent")


TRANSACTION_PAYLOAD_FIELDS = {
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


def validate_transaction_generation(value: Any) -> None:
    generation = require_object(value)
    require_keys(
        generation,
        required=(
            "schema",
            "owner_kind",
            "phase",
            "generation",
            "predecessor_sha256",
            "transaction_id",
            "reservation_id",
            "intent_sha256",
            "phase_payload",
        ),
    )
    if (
        generation["schema"] != "kilix.content.transaction-generation/v1"
        or generation["owner_kind"] != "retention"
    ):
        refuse("transaction generation schema or owner is not frozen")
    phase = generation["phase"]
    fields = TRANSACTION_PAYLOAD_FIELDS.get(phase)
    if fields is None:
        refuse("transaction generation phase is outside the frozen enum")
    require_s64(generation["generation"], positive=True)
    require_digest(generation["predecessor_sha256"])
    require_id(generation["transaction_id"])
    require_id(generation["reservation_id"])
    require_digest(generation["intent_sha256"])
    payload = require_object(generation["phase_payload"])
    require_keys(payload, required=fields)
    for raw_digest in payload.values():
        require_digest(raw_digest)


def validate_transaction_generation_chain(value: Any) -> None:
    generations = require_array(value, minimum=1, maximum=len(TRANSACTION_PHASES))
    previous: Mapping[str, Any] | None = None
    for index, raw_generation in enumerate(generations):
        validate_transaction_generation(raw_generation)
        generation = require_object(raw_generation)
        if index == 0 and generation["phase"] != "RETENTION_PREPARED":
            refuse("transaction generation chain lacks its PREPARED root")
        if previous is not None:
            if generation["generation"] != previous["generation"] + 1:
                refuse("transaction generation skips or replays a generation")
            if generation["predecessor_sha256"] != transaction_generation_digest(
                previous
            ):
                refuse("transaction predecessor does not bind exact prior bytes")
            if (
                TRANSACTION_PHASES.index(generation["phase"])
                != TRANSACTION_PHASES.index(previous["phase"]) + 1
            ):
                refuse("transaction phase skips or regresses")
            for field in (
                "transaction_id",
                "reservation_id",
                "intent_sha256",
                "owner_kind",
            ):
                if generation[field] != previous[field]:
                    refuse("immutable transaction authority changes across generations")
        previous = generation


def validate_directory_observation(value: Any) -> None:
    observation = require_object(value)
    require_keys(
        observation,
        required=(
            "schema",
            "role",
            "relative_path",
            "uid",
            "gid",
            "mode",
            "filesystem_key",
            "root_identity",
            "mount_identity",
            "baseline_children",
            "baseline_children_sha256",
            "phase",
            "permitted_delta",
            "current_temporary",
            "observed_children",
        ),
    )
    if (
        observation["schema"] != "kilix.content.directory-observation/v1"
        or observation["role"] != "D"
    ):
        refuse("directory observation schema or role is not frozen")
    require_relative_path(observation["relative_path"])
    for name in ("uid", "gid", "mode"):
        require_s64(observation[name])
    for name in ("filesystem_key", "root_identity", "mount_identity"):
        require_digest(observation[name])
    phase = observation["phase"]
    if phase not in TRANSACTION_PHASES:
        refuse("directory observation phase is outside the frozen enum")

    def children(
        raw_value: Any, *, allow_temporary_name: bool = False
    ) -> list[dict[str, Any]]:
        entries = require_array(raw_value, maximum=4_096)
        names: set[str] = set()
        for raw_entry in entries:
            entry = require_object(raw_entry)
            require_keys(
                entry, required=("name", "role", "object_type", "descriptor_sha256")
            )
            name = require_text(entry["name"], maximum=128)
            ordinary_name = CHILD_NAME_RE.fullmatch(name) is not None
            temporary_name = (
                allow_temporary_name and TEMP_NAME_RE.fullmatch(name) is not None
            )
            if not ordinary_name and not temporary_name:
                refuse("directory child name is outside its frozen grammar")
            if name in names:
                refuse("directory child name is duplicated")
            names.add(name)
            if entry["role"] not in {*COMPONENT_ROLES, "baseline"}:
                refuse("directory child role is outside the frozen enum")
            if entry["object_type"] not in {"directory", "regular"}:
                refuse("directory child type is outside the frozen enum")
            if entry["role"] == "D" and entry["object_type"] != "directory":
                refuse("directory child D role is not a directory")
            if entry["role"] in FILE_ROLES and entry["object_type"] != "regular":
                refuse("directory child file role is not a regular file")
            require_digest(entry["descriptor_sha256"])
        require_sorted_unique(entries)
        return entries

    baseline = children(observation["baseline_children"])
    if observation["baseline_children_sha256"] != canonical_digest(
        "retention-child-set", baseline
    ):
        refuse("directory baseline child-set digest is inconsistent")
    permitted = children(observation["permitted_delta"])
    if any(entry["role"] not in PHASE_FINAL_ROLES[phase] for entry in permitted):
        refuse("directory phase permits a future component")
    current = require_object(observation["current_temporary"])
    present = current.get("present")
    if present is False:
        require_keys(current, required=("present",))
        current_entries: list[dict[str, Any]] = []
    elif present is True:
        require_keys(current, required=("present", "child"))
        current_entries = children([current["child"]], allow_temporary_name=True)
    else:
        refuse("directory current temporary presence is not boolean")
    # The observed set may contain only the one separately validated current
    # temporary entry; set equality below rejects every other `.new-*` name.
    observed = children(observation["observed_children"], allow_temporary_name=True)
    expected = (
        _canonical_set(baseline)
        | _canonical_set(permitted)
        | _canonical_set(current_entries)
    )
    if _canonical_set(observed) != expected:
        refuse("directory observed child set is outside baseline plus phase delta")


def validate_retention_accounted(value: Any) -> None:
    proof = require_object(value)
    require_keys(
        proof,
        required=(
            "schema",
            "owner_kind",
            "record_kind",
            "release_id",
            "transaction_id",
            "reservation_id",
            "intent",
            "intent_sha256",
            "intent_capacity_generation_sha256",
            "ready_transaction_generation_sha256",
            "object_descriptor",
            "marker_descriptor",
            "relation_descriptor",
            "object_content_sha256",
            "marker_content_sha256",
            "relation_content_sha256",
            "logical_state",
            "logical_state_sha256",
            "physical_state",
            "physical_state_sha256",
            "capacity_policy_sha256",
            "profile_sha256",
            "catalog_sha256",
            "proof_nonce",
            "p_final_relative_path",
            "p_reserved_maximum",
        ),
    )
    if (
        proof["schema"] != "kilix.content.retention-accounted/v1"
        or proof["owner_kind"] != "retention"
        or proof["record_kind"] != "P"
    ):
        refuse("retention accounted schema owner or kind is not frozen")
    require_id(proof["release_id"])
    require_id(proof["transaction_id"])
    require_id(proof["reservation_id"])
    validate_retention_intent(proof["intent"])
    intent = require_object(proof["intent"])
    if proof["intent_sha256"] != retention_intent_digest(intent):
        refuse("P does not bind exact acyclic intent bytes")
    if (
        proof["transaction_id"] != intent["transaction_id"]
        or proof["reservation_id"] != intent["reservation_id"]
        or proof["release_id"] != intent["release_id"]
    ):
        refuse("P identity diverges from its intent")
    for name in (
        "intent_capacity_generation_sha256",
        "ready_transaction_generation_sha256",
        "object_content_sha256",
        "marker_content_sha256",
        "relation_content_sha256",
        "logical_state_sha256",
        "physical_state_sha256",
        "capacity_policy_sha256",
        "profile_sha256",
        "catalog_sha256",
        "proof_nonce",
    ):
        require_digest(proof[name])
    object_descriptor = _validate_actual_descriptor(
        proof["object_descriptor"], expected_role="object"
    )
    marker = _validate_actual_descriptor(proof["marker_descriptor"], expected_role="M")
    relation = _validate_actual_descriptor(
        proof["relation_descriptor"], expected_role="R"
    )
    _validate_descriptor_against_component(marker, _intent_component(intent, "M"))
    _validate_descriptor_against_component(relation, _intent_component(intent, "R"))
    object_attestation = intent["descriptor_attestation"]
    tree_attestation = intent["selected_tree_attestation"]
    if (
        object_descriptor["descriptor_identity_sha256"]
        != object_attestation["descriptor_sha256"]
        or object_descriptor["content_sha256"] != object_attestation["content_sha256"]
        or object_descriptor["content_sha256"] != tree_attestation["content_sha256"]
        or object_descriptor["bytes"] != tree_attestation["bytes"]
    ):
        refuse("P object descriptor diverges from intent attestations")
    if object_descriptor["content_sha256"] != proof["object_content_sha256"]:
        refuse("P object content digest diverges from descriptor")
    if (
        marker["content_sha256"] != proof["marker_content_sha256"]
        or relation["content_sha256"] != proof["relation_content_sha256"]
    ):
        refuse("P component content digests diverge from descriptors")
    logical = _validate_logical_state(proof["logical_state"])
    physical = _validate_physical_state(proof["physical_state"])
    if proof["logical_state_sha256"] != retention_logical_state_digest(logical):
        refuse("P logical-state digest is inconsistent")
    if proof["physical_state_sha256"] != retention_physical_state_digest(physical):
        refuse("P physical-state digest is inconsistent")
    if logical != intent["proposed_logical_state"]:
        refuse("P logical state diverges from the accepted intent result")
    expected_object = intent["object_identity"]
    expected_relation = {
        "stable_slot_sha256": intent["stable_slot_sha256"],
        **expected_object,
    }
    if canonical_json_bytes(expected_object) not in _canonical_set(
        logical["O_counted"]
    ) or canonical_json_bytes(expected_relation) not in _canonical_set(
        logical["R_counted"]
    ):
        refuse("P logical state omits the intent object or relation")
    for descriptor in (object_descriptor, marker, relation):
        _require_physical_descriptor(physical, descriptor, "actual")
    _require_one_prospective_role(physical, "P")
    _require_one_prospective_role(physical, "H")
    if any(
        component["identity"]["component_role"] == "H"
        for component in _physical_components_by_source(physical, "actual")
    ):
        refuse("P physical state contains future actual H authority")
    if proof["capacity_policy_sha256"] != intent["capacity_policy_sha256"]:
        refuse("P capacity policy diverges from intent")
    if (
        proof["profile_sha256"] != intent["profile_sha256"]
        or proof["catalog_sha256"] != intent["catalog_sha256"]
    ):
        refuse("P profile or catalog authority diverges from intent")
    p_component = _intent_component(intent, "P")
    if (
        require_relative_path(proof["p_final_relative_path"])
        != p_component["final_relative_path"]
    ):
        refuse("P final path diverges from its intent component")
    maximum = require_object(proof["p_reserved_maximum"])
    require_keys(maximum, required=("bytes", "inodes", "parent_growth"))
    for name in maximum:
        require_s64(maximum[name], positive=name != "parent_growth")
    if maximum != {
        "bytes": p_component["max_bytes"],
        "inodes": p_component["max_inodes"],
        "parent_growth": p_component["max_parent_growth"],
    }:
        refuse("P reserved maximum diverges from its intent component")


def validate_retention_handoff_proof(value: Any) -> None:
    proof = require_object(value)
    require_keys(
        proof,
        required=(
            "schema",
            "owner_kind",
            "record_kind",
            "release_kind",
            "permanent",
            "release_id",
            "transaction_id",
            "reservation_id",
            "intent_sha256",
            "handoff_nonce",
            "accounted_sha256",
            "object_descriptor",
            "marker_descriptor",
            "relation_descriptor",
            "accounted_descriptor",
            "object_content_sha256",
            "marker_content_sha256",
            "relation_content_sha256",
            "accounted_content_sha256",
            "ready_transaction_generation_sha256",
            "accounted_transaction_generation_sha256",
            "capacity_accounted_generation_sha256",
            "capacity_releasing_generation_sha256",
            "next_capacity_fields",
            "logical_state",
            "logical_state_sha256",
            "physical_state",
            "physical_state_sha256",
            "absence_evidence",
            "names",
            "profile_sha256",
            "catalog_sha256",
        ),
    )
    if (
        proof["schema"] != "kilix.content.retention-handoff-proof/v1"
        or proof["owner_kind"] != "retention"
        or proof["record_kind"] != "H"
        or proof["release_kind"] != "retention_handoff"
        or proof["permanent"] is not True
    ):
        refuse("retention handoff schema owner kind or permanence is not frozen")
    require_id(proof["release_id"])
    require_id(proof["transaction_id"])
    require_id(proof["reservation_id"])
    for name in (
        "intent_sha256",
        "handoff_nonce",
        "accounted_sha256",
        "object_content_sha256",
        "marker_content_sha256",
        "relation_content_sha256",
        "accounted_content_sha256",
        "ready_transaction_generation_sha256",
        "accounted_transaction_generation_sha256",
        "capacity_accounted_generation_sha256",
        "capacity_releasing_generation_sha256",
        "logical_state_sha256",
        "physical_state_sha256",
        "profile_sha256",
        "catalog_sha256",
    ):
        require_digest(proof[name])
    object_descriptor = _validate_actual_descriptor(
        proof["object_descriptor"], expected_role="object"
    )
    if object_descriptor["content_sha256"] != proof["object_content_sha256"]:
        refuse("H object content digest diverges from descriptor")
    retained_descriptors = [object_descriptor]
    for role, field, digest_field in (
        ("M", "marker_descriptor", "marker_content_sha256"),
        ("R", "relation_descriptor", "relation_content_sha256"),
        ("P", "accounted_descriptor", "accounted_content_sha256"),
    ):
        descriptor = _validate_actual_descriptor(proof[field], expected_role=role)
        retained_descriptors.append(descriptor)
        if descriptor["content_sha256"] != proof[digest_field]:
            refuse("H component content digest diverges from descriptor")
    file_descriptors = retained_descriptors[1:]
    if len({descriptor["uid"] for descriptor in file_descriptors}) != 1:
        refuse("H retained regular files do not share one UID")
    if len({descriptor["relative_path"] for descriptor in retained_descriptors}) != len(
        retained_descriptors
    ):
        refuse("H retained descriptor paths collide")
    next_fields = require_object(proof["next_capacity_fields"])
    require_keys(
        next_fields,
        required=("owner_kind", "phase", "generation", "predecessor_sha256"),
    )
    if (
        next_fields["owner_kind"] != "retention"
        or next_fields["phase"] != "RETENTION_HANDOFF_PROOFED"
    ):
        refuse("H deterministic next capacity owner or phase is inconsistent")
    require_s64(next_fields["generation"], positive=True)
    if (
        next_fields["predecessor_sha256"]
        != proof["capacity_releasing_generation_sha256"]
    ):
        refuse("H deterministic next capacity predecessor is inconsistent")
    logical = _validate_logical_state(proof["logical_state"])
    physical = _validate_physical_state(proof["physical_state"])
    if proof["logical_state_sha256"] != retention_logical_state_digest(logical):
        refuse("H logical-state digest is inconsistent")
    if proof["physical_state_sha256"] != retention_physical_state_digest(physical):
        refuse("H physical-state digest is inconsistent")
    for descriptor in retained_descriptors:
        _require_physical_descriptor(physical, descriptor, "actual")
    _require_one_prospective_role(physical, "H")
    if any(
        component["identity"]["component_role"] == "H"
        for component in _physical_components_by_source(physical, "actual")
    ):
        refuse("H semantic core contains future actual H authority")
    absence = require_object(proof["absence_evidence"])
    require_keys(
        absence,
        required=(
            "unit_absent",
            "helper_absent",
            "cgroup_absent",
            "stage_absent",
            "future_writer_absent",
            "sha256",
        ),
    )
    if any(
        absence[name] is not True
        for name in (
            "unit_absent",
            "helper_absent",
            "cgroup_absent",
            "stage_absent",
            "future_writer_absent",
        )
    ):
        refuse("H nonretained resource absence evidence is incomplete")
    require_digest(absence["sha256"])
    if absence["sha256"] != retention_absence_evidence_digest(absence):
        refuse("H absence-evidence digest is inconsistent")
    names = require_object(proof["names"])
    require_keys(
        names,
        required=(
            "capacity_final",
            "capacity_tombstone",
            "h_temporary_basename",
            "h_final_relative_path",
        ),
    )
    capacity_final = require_relative_path(names["capacity_final"])
    capacity_tombstone = require_relative_path(names["capacity_tombstone"])
    require_text(names["h_temporary_basename"], TEMP_NAME_RE, maximum=128)
    require_relative_path(names["h_final_relative_path"])
    if names["h_temporary_basename"] != _temporary_name(
        "H", 0, ZERO_DIGEST, proof["handoff_nonce"]
    ):
        refuse("H temporary name is not handoff-nonce derived")
    if capacity_final != f"reservations/{proof['reservation_id']}" or (
        capacity_tombstone
        != f"reservations/.released-{proof['reservation_id']}-{proof['handoff_nonce']}"
    ):
        refuse("H capacity final or tombstone name is not identity derived")
    if names["h_final_relative_path"] in {
        descriptor["relative_path"] for descriptor in retained_descriptors
    }:
        refuse("H final path aliases a retained predecessor")


def validate_handoff_against_accounted(h_value: Any, p_value: Any) -> None:
    validate_retention_handoff_proof(h_value)
    validate_retention_accounted(p_value)
    handoff = require_object(h_value)
    accounted = require_object(p_value)
    if handoff["accounted_sha256"] != retention_accounted_digest(accounted):
        refuse("H does not bind exact permanent P bytes")
    for field in (
        "transaction_id",
        "reservation_id",
        "intent_sha256",
        "profile_sha256",
        "catalog_sha256",
    ):
        if handoff[field] != accounted[field]:
            refuse("H provenance diverges from P")
    if handoff["handoff_nonce"] != accounted["intent"]["handoff_nonce"]:
        refuse("H handoff nonce diverges from original intent")
    for h_field, p_field in (
        ("object_descriptor", "object_descriptor"),
        ("marker_descriptor", "marker_descriptor"),
        ("relation_descriptor", "relation_descriptor"),
        ("logical_state", "logical_state"),
        ("ready_transaction_generation_sha256", "ready_transaction_generation_sha256"),
    ):
        if handoff[h_field] != accounted[p_field]:
            refuse("H retained provenance diverges from permanent P")
    accounted_bytes = canonical_json_bytes(accounted)
    if (
        handoff["accounted_content_sha256"]
        != hashlib.sha256(accounted_bytes).hexdigest()
        or handoff["accounted_descriptor"]["content_sha256"]
        != hashlib.sha256(accounted_bytes).hexdigest()
        or handoff["accounted_descriptor"]["bytes"] != len(accounted_bytes)
        or handoff["accounted_descriptor"]["relative_path"]
        != accounted["p_final_relative_path"]
    ):
        refuse("H accounted descriptor does not bind exact P bytes")
    h_component = _intent_component(accounted["intent"], "H")
    if (
        handoff["names"]["h_final_relative_path"] != h_component["final_relative_path"]
        or handoff["names"]["h_temporary_basename"] != h_component["temporary_basename"]
    ):
        refuse("H names diverge from the original intent component")


def validate_marker_against_intent(
    marker_value: Any,
    intent_value: Any,
    intent_capacity_generation_value: Any,
    prepared_transaction_generation_value: Any,
) -> None:
    """Recompute every already-durable edge entering canonical M."""
    from .u1_capacity import validate_capacity_generation

    validate_retention_marker(marker_value)
    validate_retention_intent(intent_value)
    validate_capacity_generation(intent_capacity_generation_value)
    validate_transaction_generation(prepared_transaction_generation_value)
    marker = require_object(marker_value)
    intent = require_object(intent_value)
    capacity = require_object(intent_capacity_generation_value)
    prepared = require_object(prepared_transaction_generation_value)
    intent_digest = retention_intent_digest(intent)
    capacity_digest = capacity_generation_digest(capacity)
    prepared_digest = transaction_generation_digest(prepared)
    if (
        capacity["owner_kind"] != "retention"
        or capacity["phase"] != "RETENTION_INTENT_RESERVED"
        or capacity["transaction_id"] != intent["transaction_id"]
        or capacity["reservation_id"] != intent["reservation_id"]
        or capacity["phase_payload"]
        != {
            "intent_sha256": intent_digest,
            "pre_admission_scan_sha256": intent["pre_admission_scan_sha256"],
            "component_envelope_sha256": intent["component_envelope_sha256"],
        }
    ):
        refuse("intent capacity generation diverges from the retention intent")
    if (
        prepared["phase"] != "RETENTION_PREPARED"
        or prepared["transaction_id"] != intent["transaction_id"]
        or prepared["reservation_id"] != intent["reservation_id"]
        or prepared["intent_sha256"] != intent_digest
        or prepared["phase_payload"]
        != {
            "intent_capacity_generation_sha256": capacity_digest,
            "component_envelope_sha256": intent["component_envelope_sha256"],
        }
    ):
        refuse("prepared transaction generation diverges from intent authority")
    expected = {
        "release_id": intent["release_id"],
        "transaction_id": intent["transaction_id"],
        "reservation_id": intent["reservation_id"],
        "intent_sha256": intent_digest,
        "component_envelope_sha256": intent["component_envelope_sha256"],
        "intent_capacity_generation_sha256": capacity_digest,
        "stable_slot_sha256": intent["stable_slot_sha256"],
        "install_authority_sha256": intent["install_authority_sha256"],
        "output_binding_sha256": intent["output_binding_sha256"],
        "catalog_sha256": intent["catalog_sha256"],
        "profile_sha256": intent["profile_sha256"],
        "predecessor_transaction_generation_sha256": prepared_digest,
    }
    if any(
        marker[field] != expected_value for field, expected_value in expected.items()
    ):
        refuse("retention marker provenance diverges from intent predecessors")
    _validate_descriptor_against_component(
        marker["descriptor"], _intent_component(intent, "M")
    )


def validate_relation_against_marker(
    relation_value: Any,
    marker_value: Any,
    marker_transaction_generation_value: Any,
    intent_value: Any,
) -> None:
    """Recompute the M-to-R semantic and transaction-generation edges."""
    validate_retention_relation(relation_value)
    validate_retention_marker(marker_value)
    validate_transaction_generation(marker_transaction_generation_value)
    validate_retention_intent(intent_value)
    relation = require_object(relation_value)
    marker = require_object(marker_value)
    generation = require_object(marker_transaction_generation_value)
    intent = require_object(intent_value)
    marker_digest = retention_marker_digest(marker)
    if (
        relation["marker_sha256"] != marker_digest
        or generation["phase"] != "RETENTION_MARKER_DURABLE"
        or generation["phase_payload"] != {"marker_sha256": marker_digest}
        or relation["predecessor_transaction_generation_sha256"]
        != transaction_generation_digest(generation)
    ):
        refuse("retention relation does not bind exact marker provenance")
    for field in (
        "release_id",
        "transaction_id",
        "reservation_id",
        "intent_sha256",
        "component_envelope_sha256",
        "intent_capacity_generation_sha256",
        "stable_slot_sha256",
        "install_authority_sha256",
        "output_binding_sha256",
        "catalog_sha256",
        "profile_sha256",
    ):
        if relation[field] != marker[field]:
            refuse("retention relation authority diverges from its marker")
    _validate_descriptor_against_component(
        relation["descriptor"], _intent_component(intent, "R")
    )


def validate_accounted_provenance(
    accounted_value: Any,
    marker_value: Any,
    relation_value: Any,
    ready_transaction_generation_value: Any,
    intent_capacity_generation_value: Any,
) -> None:
    """Recompute P's exact M/R, READY, and original-capacity provenance."""
    from .u1_capacity import validate_capacity_generation

    validate_retention_accounted(accounted_value)
    validate_retention_marker(marker_value)
    validate_retention_relation(relation_value)
    validate_transaction_generation(ready_transaction_generation_value)
    validate_capacity_generation(intent_capacity_generation_value)
    accounted = require_object(accounted_value)
    marker = require_object(marker_value)
    relation = require_object(relation_value)
    ready = require_object(ready_transaction_generation_value)
    capacity = require_object(intent_capacity_generation_value)
    marker_digest = retention_marker_digest(marker)
    relation_digest = retention_relation_digest(relation)
    if (
        ready["phase"] != "RETENTION_READY"
        or ready["phase_payload"]
        != {"marker_sha256": marker_digest, "relation_sha256": relation_digest}
        or accounted["ready_transaction_generation_sha256"]
        != transaction_generation_digest(ready)
        or accounted["intent_capacity_generation_sha256"]
        != capacity_generation_digest(capacity)
    ):
        refuse("P durable generation provenance is inconsistent")
    if (
        accounted["marker_descriptor"] != marker["descriptor"]
        or accounted["relation_descriptor"] != relation["descriptor"]
        or accounted["marker_content_sha256"] != marker["descriptor"]["content_sha256"]
        or accounted["relation_content_sha256"]
        != relation["descriptor"]["content_sha256"]
    ):
        refuse("P M/R descriptor provenance is inconsistent")


def validate_handoff_provenance(
    handoff_value: Any,
    accounted_value: Any,
    accounted_transaction_generation_value: Any,
    capacity_accounted_generation_value: Any,
    capacity_releasing_generation_value: Any,
) -> None:
    """Recompute H's complete acyclic P/journal/capacity predecessor graph."""
    from .u1_capacity import validate_capacity_generation

    validate_handoff_against_accounted(handoff_value, accounted_value)
    validate_transaction_generation(accounted_transaction_generation_value)
    validate_capacity_generation(capacity_accounted_generation_value)
    validate_capacity_generation(capacity_releasing_generation_value)
    handoff = require_object(handoff_value)
    accounted = require_object(accounted_value)
    transaction = require_object(accounted_transaction_generation_value)
    capacity_accounted = require_object(capacity_accounted_generation_value)
    capacity_releasing = require_object(capacity_releasing_generation_value)
    accounted_digest = retention_accounted_digest(accounted)
    transaction_digest = transaction_generation_digest(transaction)
    if (
        transaction["phase"] != "RETENTION_ACCOUNTED"
        or transaction["phase_payload"] != {"accounted_sha256": accounted_digest}
        or transaction["predecessor_sha256"]
        != accounted["ready_transaction_generation_sha256"]
        or handoff["accounted_transaction_generation_sha256"] != transaction_digest
    ):
        refuse("H transaction ACCOUNTED provenance is inconsistent")
    if (
        capacity_accounted["owner_kind"] != "retention"
        or capacity_accounted["phase"] != "RETENTION_ACCOUNTED"
        or capacity_accounted["phase_payload"]
        != {
            "intent_sha256": accounted["intent_sha256"],
            "transaction_generation_sha256": transaction_digest,
            "accounted_sha256": accounted_digest,
        }
        or handoff["capacity_accounted_generation_sha256"]
        != capacity_generation_digest(capacity_accounted)
    ):
        refuse("H capacity ACCOUNTED provenance is inconsistent")
    capacity_accounted_digest = capacity_generation_digest(capacity_accounted)
    if (
        capacity_releasing["owner_kind"] != "retention"
        or capacity_releasing["phase"] != "RETENTION_HANDOFF_RELEASING"
        or capacity_releasing["predecessor_sha256"] != capacity_accounted_digest
        or capacity_releasing["phase_payload"]
        != {
            "intent_sha256": accounted["intent_sha256"],
            "transaction_generation_sha256": transaction_digest,
            "accounted_sha256": accounted_digest,
            "handoff_nonce": accounted["intent"]["handoff_nonce"],
        }
        or handoff["capacity_releasing_generation_sha256"]
        != capacity_generation_digest(capacity_releasing)
    ):
        refuse("H capacity HANDOFF_RELEASING provenance is inconsistent")
    if handoff["next_capacity_fields"]["generation"] != capacity_releasing[
        "generation"
    ] + 1 or handoff["next_capacity_fields"][
        "predecessor_sha256"
    ] != capacity_generation_digest(capacity_releasing):
        refuse("H deterministic HANDOFF_PROOFED fields are inconsistent")


def _validate_recovery_snapshot(value: Any) -> None:
    snapshot = require_object(value)
    require_keys(
        snapshot,
        required=(
            "transaction_phase",
            "capacity_phase",
            "component_states",
            "capacity_names",
        ),
    )
    if (
        snapshot["transaction_phase"] not in TRANSACTION_PHASES
        or snapshot["capacity_phase"] not in CAPACITY_PHASES
    ):
        refuse("recovery snapshot owner phase is outside the frozen enum")
    states = require_array(snapshot["component_states"], minimum=4, maximum=36)
    for raw_state in states:
        state = require_object(raw_state)
        require_keys(state, required=("role", "ordinal", "state"))
        if (
            state["role"] not in COMPONENT_ROLES
            or state["state"] not in COMPONENT_STATES
        ):
            refuse("recovery component state is outside the frozen enum")
        require_s64(state["ordinal"])
    require_sorted_unique(states)
    names = require_object(snapshot["capacity_names"])
    require_keys(names, required=("reservation_present", "tombstone_present"))
    if any(type(item) is not bool for item in names.values()):
        refuse("recovery capacity-name state is not boolean")


def validate_recovery_vector(value: Any) -> None:
    oracle = require_object(value)
    require_keys(
        oracle,
        required=(
            "schema",
            "release_id",
            "executable",
            "component_matrix",
            "handoff_rows",
            "impossible_rows",
        ),
    )
    if (
        oracle["schema"] != "kilix.content.recovery-vector/v1"
        or oracle["executable"] is not False
    ):
        refuse("recovery vector is not frozen inert data")
    require_id(oracle["release_id"])
    matrix = require_array(
        oracle["component_matrix"],
        minimum=len(COMPONENT_ROLES) * len(COMPONENT_STATES),
        maximum=len(COMPONENT_ROLES) * len(COMPONENT_STATES),
    )
    observed: set[tuple[str, str]] = set()
    for raw_row in matrix:
        row = require_object(raw_row)
        require_keys(
            row,
            required=(
                "role",
                "observed_state",
                "classification",
                "allowed_next_record",
                "charge_kind",
                "quarantine",
                "exposure_allowed",
                "first_result",
                "repeated_result",
            ),
        )
        role = row["role"]
        state = row["observed_state"]
        if role not in COMPONENT_ROLES or state not in COMPONENT_STATES:
            refuse("recovery component row is outside the frozen matrix")
        observed.add((role, state))
        for name in (
            "classification",
            "allowed_next_record",
            "charge_kind",
            "first_result",
            "repeated_result",
        ):
            require_id(row[name])
        if (
            type(row["quarantine"]) is not bool
            or type(row["exposure_allowed"]) is not bool
        ):
            refuse("recovery component decision is not boolean")
        if row["quarantine"] and row["exposure_allowed"]:
            refuse("quarantined recovery row allows exposure")
        if row != {
            "role": role,
            "observed_state": state,
            **component_recovery_expected(role, state),
        }:
            refuse("recovery component row diverges from the frozen oracle")
    require_sorted_unique(matrix)
    if observed != {
        (role, state) for role in COMPONENT_ROLES for state in COMPONENT_STATES
    }:
        refuse("recovery component matrix is incomplete or duplicated")

    rows = require_array(
        oracle["handoff_rows"],
        minimum=len(HANDOFF_ROW_IDS),
        maximum=len(HANDOFF_ROW_IDS),
    )
    observed_ids: set[str] = set()
    for raw_row in rows:
        row = require_object(raw_row)
        require_keys(
            row,
            required=(
                "id",
                "transaction_phase",
                "capacity_phase",
                "h_state",
                "expected_action",
                "charge_kind",
                "quarantine",
                "selection_allowed",
                "cleanup_allowed",
                "first_result",
                "repeated_result",
            ),
        )
        identifier = require_id(row["id"])
        if identifier not in HANDOFF_ROW_IDS or identifier in observed_ids:
            refuse("handoff recovery row is unknown or duplicated")
        observed_ids.add(identifier)
        if (
            row["transaction_phase"] not in TRANSACTION_PHASES
            or row["capacity_phase"] not in CAPACITY_PHASES
        ):
            refuse("handoff recovery owner phase is outside the frozen matrix")
        if row["h_state"] not in {"absent", "final", "temporary"}:
            refuse("handoff recovery H state is outside the frozen enum")
        for name in (
            "expected_action",
            "charge_kind",
            "first_result",
            "repeated_result",
        ):
            require_id(row[name])
        if any(
            type(row[name]) is not bool
            for name in ("quarantine", "selection_allowed", "cleanup_allowed")
        ):
            refuse("handoff recovery decision is not boolean")
        if row["quarantine"] and (row["selection_allowed"] or row["cleanup_allowed"]):
            refuse("quarantined handoff recovery authorizes mutation or exposure")
        if row != handoff_recovery_expected(identifier):
            refuse("handoff recovery row diverges from the frozen oracle")
    require_sorted_unique(rows)
    if observed_ids != set(HANDOFF_ROW_IDS):
        refuse("handoff recovery matrix is incomplete")

    impossible = require_array(
        oracle["impossible_rows"],
        minimum=len(IMPOSSIBLE_REASONS),
        maximum=len(IMPOSSIBLE_REASONS),
    )
    reasons: set[str] = set()
    for raw_row in impossible:
        row = require_object(raw_row)
        require_keys(row, required=("reason", "observed", "expected", "outcome"))
        reason = row["reason"]
        if reason not in IMPOSSIBLE_REASONS or reason in reasons:
            refuse("impossible recovery reason is unknown or duplicated")
        reasons.add(reason)
        _validate_recovery_snapshot(row["observed"])
        _validate_recovery_snapshot(row["expected"])
        if row["observed"] == row["expected"]:
            refuse("impossible recovery row is not contradictory")
        outcome = require_object(row["outcome"])
        require_keys(
            outcome,
            required=(
                "quarantine",
                "retain_charge",
                "selection",
                "return_path",
                "cleanup",
                "credit",
            ),
        )
        if outcome != {
            "quarantine": True,
            "retain_charge": True,
            "selection": False,
            "return_path": False,
            "cleanup": False,
            "credit": False,
        }:
            refuse("impossible recovery outcome is not fail closed")
    require_sorted_unique(impossible)
    if reasons != IMPOSSIBLE_REASONS:
        refuse("impossible recovery matrix is incomplete")


RETENTION_VALIDATORS = {
    "kilix.content.retention-intent/v1": validate_retention_intent,
    "kilix.content.retention-component/v1": validate_retention_component,
    "kilix.content.retention-envelope/v1": validate_retention_envelope,
    "kilix.content.retention-marker/v1": validate_retention_marker,
    "kilix.content.retention-relation/v1": validate_retention_relation,
    "kilix.content.retention-accounted/v1": validate_retention_accounted,
    "kilix.content.retention-handoff-proof/v1": validate_retention_handoff_proof,
    "kilix.content.retention-logical-state/v1": validate_retention_logical_state,
    "kilix.content.retention-physical-state/v1": validate_retention_physical_state,
    "kilix.content.transaction-generation/v1": validate_transaction_generation,
    "kilix.content.directory-observation/v1": validate_directory_observation,
    "kilix.content.recovery-vector/v1": validate_recovery_vector,
}


__all__ = [
    "CAPACITY_PHASES",
    "COMPONENT_ROLES",
    "COMPONENT_STATES",
    "HANDOFF_ROW_IDS",
    "IMPOSSIBLE_REASONS",
    "RETENTION_VALIDATORS",
    "TRANSACTION_PHASES",
    "validate_directory_observation",
    "validate_accounted_provenance",
    "validate_handoff_against_accounted",
    "validate_handoff_provenance",
    "validate_intent_envelope",
    "validate_marker_against_intent",
    "validate_recovery_vector",
    "validate_retention_accounted",
    "validate_retention_admission",
    "validate_retention_component",
    "validate_retention_envelope",
    "validate_retention_handoff_proof",
    "validate_retention_intent",
    "validate_retention_logical_state",
    "validate_retention_marker",
    "validate_retention_physical_state",
    "validate_retention_relation",
    "validate_relation_against_marker",
    "validate_transaction_generation",
    "validate_transaction_generation_chain",
]
