"""Render the deterministic, source-only F100 U1 security corpus.

The corpus is included in the sdist and deliberately excluded from wheels.  It
contains inert bytes and expected validation dispositions only; it has no store,
filesystem-recovery, acquisition, or authorization behavior.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from kilix_content import U1ContractError, canonical_json_bytes
from kilix_content.u1_core import (
    MAX_ARRAY_ITEMS,
    MAX_JSON_BYTES,
    MAX_JSON_NODES,
    MAX_OBJECT_PROPERTIES,
    MAX_STRING_CODEPOINTS,
    MAX_TOTAL_ARRAY_ITEMS,
    MAX_TOTAL_PROPERTIES,
    MAX_TOTAL_STRING_BYTES,
    MAX_TOTAL_STRING_CODEPOINTS,
    S64_MAX,
    U64_MAX,
)
from kilix_content.u1_capacity import OWNER_PHASES, ROOT_ROLES
from tests.u1_vectors import (
    authority_binding,
    authorization,
    capacity_generation,
    capacity_policy,
    catalog,
    clone,
    directory_observation,
    install_record,
    license_manifest,
    logical_state,
    ordered,
    output_binding,
    physical_state,
    positive_records,
    recovery_vector,
    retention_envelope,
    retention_handoff,
    retention_intent,
    retention_marker,
    retention_relation,
    retention_accounted,
    sandbox_profile,
    sha,
    system_profile,
    toolchain_profile,
    transaction_generation,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "u1"
CORPUS_ROOT = FIXTURE_ROOT / "corpus"
INDEX_PATH = FIXTURE_ROOT / "index.json"
SUMS_PATH = FIXTURE_ROOT / "SHA256SUMS"
LEDGER_PATH = FIXTURE_ROOT / "requirements-ledger.json"
RELEASE_ID = "0.2.1"

# These anchors are intentionally handwritten.  Dynamic generation and index
# equality catch every rendered row; this set additionally prevents accidental
# deletion of a mandatory security category while editing the renderer itself.
REQUIRED_VECTOR_IDS = (
    "positive-catalog-v5",
    "positive-install-archive",
    "positive-install-mirrored",
    "positive-install-git",
    "positive-install-user-supplied",
    "positive-install-authority-package",
    "positive-install-authority-content",
    "positive-install-authority-asset",
    "positive-capacity-generation-reserved",
    "positive-capacity-generation-unit-observed",
    "positive-capacity-generation-retention-handoff-proofed",
    "positive-retention-intent-d0",
    "positive-retention-intent-d1",
    "positive-retention-intent-d2",
    "positive-retention-accounted",
    "positive-retention-handoff",
    "recovery-oracle-complete-r13",
    "invalid-catalog-v5-unknown-field",
    "mutation-catalog-member-alias-set-mismatch",
    "mutation-catalog-alias-targets-direct-asset",
    "mutation-catalog-stable-slot-collision",
    "cycle-catalog-alias-normalized-self-edge",
    "mutation-system-profile-self-digest",
    "mutation-toolchain-profile-self-digest",
    "mutation-sandbox-profile-self-digest",
    "mutation-capacity-memory-equation",
    "mutation-capacity-phase-maximum-missing",
    "mutation-capacity-generation-zero-predecessor",
    "mutation-retention-envelope-digest",
    "mutation-retention-marker-semantic-digest",
    "mutation-retention-relation-semantic-digest",
    "mutation-retention-logical-r-union",
    "mutation-retention-logical-object-cardinality",
    "mutation-retention-physical-total",
    "mutation-retention-physical-envelope-digest",
    "mutation-retention-intent-component-envelope-digest",
    "cycle-retention-directory-ancestry",
    "mutation-retention-handoff-absence-digest",
    "mutation-recovery-oracle-action",
    "duplicate-key-root-printable",
    "duplicate-key-nested-printable",
    "duplicate-key-control-escape",
    "duplicate-key-bidi-format",
    "duplicate-key-normalization-confusable",
    "invalid-parser-bom",
    "invalid-parser-invalid-utf8",
    "invalid-parser-trailing-data",
    "invalid-parser-whitespace",
    "invalid-parser-float",
    "invalid-parser-exponent",
    "invalid-parser-nonfinite",
    "invalid-parser-negative-zero",
    "invalid-parser-alternate-escape",
    "invalid-parser-key-order",
    "boundary-s64-maximum-accepted",
    "boundary-s64-maximum-plus-one",
    "boundary-u64-maximum-parser-control",
    "boundary-integer-token-maximum-plus-one",
    "boundary-retention-directory-count-32",
    "boundary-retention-directory-count-33",
    "boundary-source-url-count-16",
    "boundary-source-url-count-17",
    "boundary-json-depth-64-parser-control",
    "boundary-json-depth-65",
    "boundary-json-bytes-maximum-plus-one",
)


def error_code(message: str) -> str:
    return U1ContractError(message).code


SCHEMA_FAILURE = error_code("U1 JSON Schema validation refused the record")


def _safe_id(value: str) -> str:
    result = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    if not result:
        raise ValueError("empty vector ID")
    return result


def _replace_digest(value: str) -> str:
    return ("1" if value[0] != "1" else "2") + value[1:]


def _canonical(value: Any) -> bytes:
    return canonical_json_bytes(value)


def _ledger_vector_ids() -> set[str]:
    """Read the hand-authored ledger only as a coverage requirement.

    The renderer never creates, edits, or infers ledger rows.  The independent
    test freezes the ledger bytes and its row/ID grammar.
    """
    raw = LEDGER_PATH.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if raw != _canonical(value) + b"\n":
        raise SystemExit("requirements ledger is not one canonical JSON line")
    rows = value.get("requirements")
    if (
        value.get("schema") != "kilix.content.u1-requirements-ledger/v1"
        or value.get("release_id") != RELEASE_ID
        or type(rows) is not list
    ):
        raise SystemExit("requirements ledger has an invalid envelope")
    result: set[str] = set()
    for row in rows:
        if type(row) is not dict or type(row.get("requirement_id")) is not str:
            raise SystemExit("requirements ledger has an invalid requirement row")
        ids = row.get("fixture_ids")
        if type(ids) is not list or any(type(identifier) is not str for identifier in ids):
            raise SystemExit("requirements ledger has invalid fixture IDs")
        result.update(ids)
    return result


def build_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []

    def add_raw(
        identifier: str,
        vector_class: str,
        schema_id: str,
        raw: bytes,
        stage: str,
        code: str,
        disposition: dict[str, Any] | None = None,
    ) -> None:
        entry = {
                "id": _safe_id(identifier),
                "class": vector_class,
                "schema_id": schema_id,
                "raw": raw,
                "expected_stage": stage,
                "expected_code": code,
            }
        if disposition is not None:
            entry["disposition"] = disposition
        vectors.append(entry)

    def add_value(
        identifier: str,
        vector_class: str,
        schema_id: str,
        value: Any,
        stage: str,
        code: str,
        disposition: dict[str, Any] | None = None,
    ) -> None:
        add_raw(
            identifier,
            vector_class,
            schema_id,
            _canonical(value),
            stage,
            code,
            disposition,
        )

    records = positive_records()
    for name, (schema_id, value) in records.items():
        if name == "recovery-vector":
            continue
        add_value(
            f"positive-{name}",
            "positive",
            schema_id,
            value,
            "accepted",
            "accepted",
        )
    add_value(
        "recovery-oracle-complete-r13",
        "recovery-oracle",
        "kilix.content.recovery-vector/v1",
        recovery_vector(),
        "accepted",
        "accepted",
    )

    # Every production route has paired missing/unknown-field schema controls.
    representative: dict[str, tuple[str, dict[str, Any]]] = {}
    for name, (schema_id, value) in records.items():
        representative.setdefault(schema_id, (name, value))
    for schema_id, (name, value) in sorted(representative.items()):
        missing = clone(value)
        missing.pop("schema")
        add_value(
            f"invalid-{name}-missing-schema",
            "invalid",
            schema_id,
            missing,
            "routing",
            error_code("U1 admission schema does not match the expected resource role"),
        )
        extra = clone(value)
        extra["unknown_field"] = "forbidden"
        add_value(
            f"invalid-{name}-unknown-field",
            "invalid",
            schema_id,
            extra,
            "schema",
            SCHEMA_FAILURE,
        )

    def add_schema_mutation(
        identifier: str, schema_id: str, value: Any, vector_class: str = "mutation"
    ) -> None:
        add_value(identifier, vector_class, schema_id, value, "schema", SCHEMA_FAILURE)

    def add_semantic_mutation(
        identifier: str, schema_id: str, value: Any, message: str,
        vector_class: str = "mutation",
    ) -> None:
        add_value(identifier, vector_class, schema_id, value, "semantic", error_code(message))

    def add_join_oracle(identifier: str, value: Any, expected: str) -> None:
        add_value(
            identifier,
            "join",
            "test-only.capacity-policy-join/v1",
            value,
            "join",
            expected,
            disposition={
                "operation": "validate_capacity_generation_against_policy",
                "paired_positive_id": value["paired_positive_id"],
                "source_only": True,
            },
        )

    def add_admission_oracle(identifier: str, value: Any, expected: str) -> None:
        add_value(
            identifier,
            "admission-oracle",
            "test-only.retention-admission-oracle/v1",
            value,
            "admission",
            expected,
            disposition={
                "operation": "validate_retention_admission",
                "paired_positive_id": value["paired_positive_id"],
                "source_only": True,
            },
        )

    def add_causal_oracle(
        identifier: str,
        value: dict[str, Any],
        expected: str,
        paired_positive_id: str,
    ) -> None:
        add_value(
            identifier,
            "operation",
            "test-only.u1-causal-oracle/v1",
            {
                "schema": "test-only.u1-causal-oracle/v1",
                **value,
            },
            "operation",
            expected,
            disposition={
                "operation": "causal_oracle",
                "paired_positive_id": paired_positive_id,
                "source_only": True,
            },
        )

    # H1 catalog/source/package/profile authority mutations.
    value = catalog()
    value["aliases"].pop()
    add_value(
        "mutation-catalog-member-alias-set-mismatch",
        "mutation",
        "kilix.content.catalog/v5",
        value,
        "semantic",
        error_code("package members and aliases are not set-equal"),
    )
    value = catalog()
    value["aliases"][0]["package_id"] = "demo.input"
    value["aliases"] = ordered(value["aliases"])
    add_value(
        "mutation-catalog-alias-targets-direct-asset",
        "mutation",
        "kilix.content.catalog/v5",
        value,
        "semantic",
        error_code("alias target is not a package"),
    )
    value = catalog()
    value["assets"][0]["stable_slot"] = value["packages"][0]["stable_slot"]
    add_value(
        "mutation-catalog-stable-slot-collision",
        "mutation",
        "kilix.content.catalog/v5",
        value,
        "semantic",
        error_code("direct identity or stable slot collides"),
    )
    value = catalog()
    value["packages"][0]["install"]["dependencies"] = [
        {"id": "demo.codec", "role": "runtime"}
    ]
    value["packages"][0]["install"]["build_argv"] = []
    add_value(
        "cycle-catalog-alias-normalized-self-edge",
        "cycle",
        "kilix.content.catalog/v5",
        value,
        "semantic",
        error_code("dependency graph contains a cycle or exceeds its depth bound"),
    )
    value = install_record("archive", output_manifest=True)
    value["source"]["source_bytes_max"] = 1
    value["source_bytes_max"] = 1
    add_value(
        "mutation-install-source-length-over-maximum",
        "mutation",
        "kilix.content.install-record/v5",
        value,
        "semantic",
        error_code("source length exceeds its frozen maximum"),
    )
    value = catalog()
    value["packages"][0]["members"][0]["member_path"] = "../escape"
    add_schema_mutation("mutation-catalog-member-path", "kilix.content.catalog/v5", value)
    value = catalog()
    value["system_requirement_profiles"][0]["manifest_sha256"] = 1
    add_schema_mutation(
        "mutation-catalog-system-profile-reference",
        "kilix.content.catalog/v5",
        value,
    )
    value = catalog()
    value["toolchain_profiles"][0]["profile_sha256"] = 1
    add_schema_mutation(
        "mutation-catalog-toolchain-profile-reference",
        "kilix.content.catalog/v5",
        value,
    )
    value = catalog()
    value["license_manifest_id"] = ""
    add_schema_mutation("mutation-catalog-license-manifest", "kilix.content.catalog/v5", value)
    value = install_record("archive", output_manifest=True)
    value["version"] = 1
    add_schema_mutation("mutation-install-version", "kilix.content.install-record/v5", value)
    value = install_record("archive", output_manifest=True)
    value["source"]["sha256"] = 1
    add_schema_mutation("mutation-install-source-digest", "kilix.content.install-record/v5", value)
    value = install_record("archive", output_manifest=True)
    value["source_bytes_max"] = 1
    add_semantic_mutation(
        "mutation-install-source-bytes-max",
        "kilix.content.install-record/v5",
        value,
        "install and source maximums diverge",
    )
    value = install_record("archive", output_manifest=True)
    value["dependencies"][0]["role"] = "runtime+build"
    add_schema_mutation("mutation-install-dependency-role", "kilix.content.install-record/v5", value)
    value = install_record("archive", output_manifest=True)
    value["build_argv"] = [1]
    add_schema_mutation("mutation-install-build-argv", "kilix.content.install-record/v5", value)
    value = authority_binding()
    value["install_record_sha256"] = 1
    add_schema_mutation(
        "mutation-authority-install-record-digest",
        "kilix.content.install-authority-binding/v1",
        value,
    )
    value = output_binding()
    value["selected_bytes"] = -1
    add_schema_mutation("mutation-output-binding-selected-bytes", "kilix.content.output-binding/v1", value)
    value = authorization()
    value["record_sha256"] = _replace_digest(value["record_sha256"])
    add_semantic_mutation(
        "mutation-authorization-record-digest",
        "kilix.install.authorization/v2",
        value,
        "authorization record digest is inconsistent",
    )
    value = system_profile()
    value["packages"][0]["sha256"] = 1
    add_schema_mutation(
        "mutation-system-profile-package-digest",
        "kilix.content.system-requirements/v1",
        value,
    )
    value = toolchain_profile()
    value["entrypoints"][0]["executable"] = 1
    add_schema_mutation(
        "mutation-toolchain-entrypoint",
        "kilix.content.toolchain-profile/v1",
        value,
    )
    value = sandbox_profile()
    value["devices"][0] = "/dev/does-not-exist"
    add_schema_mutation(
        "mutation-sandbox-device",
        "kilix.content.sandbox-profile/v1",
        value,
    )
    value = license_manifest()
    value["licenses"][0]["text_sha256"] = 1
    add_schema_mutation(
        "mutation-license-text-digest",
        "kilix.content.license-manifest/v1",
        value,
    )

    # These records model meaningful packaging/test-authority claims as inert,
    # rejected data.  The disposition metadata is carried in the fixture index
    # and is tested independently; the payload itself is deliberately rejected
    # by the production catalog schema and can never mint authority.
    disposition_payload = {
        "schema": "kilix.content.catalog/v5",
        "release_id": RELEASE_ID,
        "packages": [],
        "contents": [],
        "assets": [],
        "aliases": [],
        "system_requirement_profiles": [],
        "toolchain_profiles": [],
        "sandbox_profiles": [],
        "license_manifest_id": "licenses.test",
    }
    for identifier, disposition, claim in (
        (
            "disposition-resource-only",
            "resource-only",
            "a schema/resource member must not be treated as catalog authority",
        ),
        (
            "disposition-manifest-only",
            "manifest-only",
            "a resource manifest entry without catalog membership is inert",
        ),
        (
            "disposition-wheel-test-authority",
            "wheel-test-authority",
            "wheel tests and golden fixtures cannot mint installed authority",
        ),
        (
            "disposition-sdist-test-authority",
            "sdist-test-authority",
            "sdist test authority is development-only and cannot authorize install",
        ),
    ):
        value = clone(disposition_payload)
        value["disposition_claim"] = {
            "claim": claim,
            "paired_positive_id": "positive-catalog-v5",
            "source_only": True,
            "installed_authority": False,
        }
        add_value(
            identifier,
            "invalid",
            "kilix.content.catalog/v5",
            value,
            "schema",
            SCHEMA_FAILURE,
            disposition={
                "kind": disposition,
                "paired_positive_id": "positive-catalog-v5",
                "claim": claim,
                "expected_authority": "refuse",
            },
        )
    for name, schema_id, constructor, field, message in (
        (
            "system-profile-self-digest",
            "kilix.content.system-requirements/v1",
            system_profile,
            "manifest_sha256",
            "system requirement manifest digest is inconsistent",
        ),
        (
            "toolchain-profile-self-digest",
            "kilix.content.toolchain-profile/v1",
            toolchain_profile,
            "profile_sha256",
            "toolchain profile digest is inconsistent",
        ),
        (
            "sandbox-profile-self-digest",
            "kilix.content.sandbox-profile/v1",
            sandbox_profile,
            "profile_sha256",
            "sandbox profile digest is inconsistent",
        ),
    ):
        value = constructor()
        value[field] = _replace_digest(value[field])
        add_value(
            f"mutation-{name}",
            "mutation",
            schema_id,
            value,
            "semantic",
            error_code(message),
        )

    # H2 capacity equations, complete maxima, and generation-zero authority.
    value = capacity_policy()
    value["memory_equation"]["aggregate_reservation_bytes_max"] += 1
    add_value(
        "mutation-capacity-memory-equation",
        "mutation",
        "kilix.content.capacity-reserve/v2",
        value,
        "semantic",
        error_code("capacity aggregate reservation equation is inconsistent"),
    )
    value = capacity_policy()
    value["phase_maxima"].pop()
    add_value(
        "mutation-capacity-phase-maximum-missing",
        "mutation",
        "kilix.content.capacity-reserve/v2",
        value,
        "semantic",
        error_code("array field is outside the frozen bound"),
    )
    value = capacity_generation("RESERVED", generation=0)
    value["predecessor_sha256"] = sha("illegal-root-predecessor")
    add_value(
        "mutation-capacity-generation-zero-predecessor",
        "mutation",
        "kilix.content.capacity-generation/v2",
        value,
        "semantic",
        error_code("generation zero is not the accepted capacity RESERVED root"),
    )
    value = capacity_generation("RESERVED", generation=0)
    value["owner_kind"] = "unknown-owner"
    add_schema_mutation(
        "mutation-capacity-owner-kind",
        "kilix.content.capacity-generation/v2",
        value,
    )
    value = capacity_generation("RESERVED", generation=0)
    value["phase_payload"]["reservation_name"] = 1
    add_schema_mutation(
        "mutation-capacity-phase-payload",
        "kilix.content.capacity-generation/v2",
        value,
    )
    value = capacity_generation("RESERVED", generation=0)
    value["root_identities"][0]["descriptor_identity_sha256"] = 1
    add_schema_mutation(
        "mutation-capacity-root-identity",
        "kilix.content.capacity-generation/v2",
        value,
    )
    value = capacity_generation("RESERVED", generation=0)
    value["policy_sha256"] = 1
    add_schema_mutation(
        "mutation-capacity-policy-digest",
        "kilix.content.capacity-generation/v2",
        value,
    )
    policy = capacity_policy()
    generation = capacity_generation("RESERVED", generation=0)
    add_join_oracle(
        "join-capacity-owner-phase-five-roots-positive",
        {
            "schema": "test-only.capacity-policy-join/v1",
            "policy": policy,
            "generation": generation,
            "paired_positive_id": "positive-capacity-generation-reserved",
        },
        "accepted",
    )
    wrong_policy = clone(policy)
    wrong_policy["phase_maxima"].pop()
    add_join_oracle(
        "join-capacity-owner-phase-missing-root",
        {
            "schema": "test-only.capacity-policy-join/v1",
            "policy": wrong_policy,
            "generation": generation,
            "paired_positive_id": "positive-capacity-generation-reserved",
        },
        "refused",
    )
    wrong_generation = clone(generation)
    wrong_generation["policy_sha256"] = sha("wrong-capacity-policy")
    add_join_oracle(
        "join-capacity-policy-digest-mismatch",
        {
            "schema": "test-only.capacity-policy-join/v1",
            "policy": policy,
            "generation": wrong_generation,
            "paired_positive_id": "positive-capacity-generation-reserved",
        },
        "refused",
    )
    wrong_owner = clone(generation)
    wrong_owner["owner_kind"] = "retention-capacity"
    wrong_owner["phase"] = "RETENTION_ACCOUNTED"
    wrong_owner["generation"] = 1
    wrong_owner["predecessor_sha256"] = sha("previous-generation")
    add_join_oracle(
        "join-capacity-owner-phase-mismatch",
        {
            "schema": "test-only.capacity-policy-join/v1",
            "policy": policy,
            "generation": wrong_owner,
            "paired_positive_id": "positive-capacity-generation-reserved",
        },
        "refused",
    )
    def two_object_logical() -> dict[str, Any]:
        value = logical_state()
        first = clone(value["O_materialized"][0])
        second = clone(first)
        second["output_binding_sha256"] = sha("second-output-binding")
        objects = ordered([first, second])
        first_relation = clone(value["R_present"][0])
        second_relation = clone(first_relation)
        second_relation["output_binding_sha256"] = second["output_binding_sha256"]
        relations = ordered([first_relation, second_relation])
        value["O_materialized"] = objects
        value["O_referenced"] = objects
        value["O_counted"] = objects
        value["R_present"] = relations
        value["R_counted"] = relations
        value["retained_unique_objects"] = 2
        value["retained_versions"] = [
            {"stable_slot_sha256": sha("stable-slot"), "count": 2}
        ]
        return value

    for field, observed, suffixes in (
        ("retained_unique_objects_max", 2, (1, 2, 3)),
        ("retained_versions_per_stable_slot_max", 2, (1, 2, 3)),
    ):
        for suffix, limit in zip(("limit-minus-one", "exact", "limit-plus-one"), suffixes):
            logical = two_object_logical()
            closed = limit < observed
            logical["retention_admission_closed"] = closed
            logical["admission_closed_reasons"] = ["limit-exceeded"] if closed else []
            limits = {
                "retained_unique_objects_max": 2,
                "retained_allocated_bytes_max": 1_000_000,
                "retained_inodes_max": 10,
                "retained_versions_per_stable_slot_max": 2,
                "ambiguous_retained_objects_max": 2,
            }
            limits[field] = limit
            add_admission_oracle(
                f"boundary-retention-admission-{field}-{suffix}",
                {
                    "schema": "test-only.retention-admission-oracle/v1",
                    "logical": logical,
                    "physical": physical_state(),
                    "limits": limits,
                    "paired_positive_id": "positive-retention-intent-d0",
                },
                "refused" if closed else "accepted",
            )

    # M01: the declared retention-record scan budget is exercised by a causal
    # operation recipe.  The recipe carries only a delta; the test derives the
    # frozen budget from the production capacity policy and calls the real
    # retention-admission oracle.  The extra open-over-budget case proves the
    # fail-closed bit is not merely a label.
    scan_positive = "boundary-retention-scan-budget-exact"
    for suffix, delta, expected in (
        ("minus-one", -1, "accepted"),
        ("exact", 0, "accepted"),
        ("plus-one-closed", 1, "accepted"),
        (
            "plus-one-open",
            1,
            error_code("retention admission result is not the recomputed fail-closed state"),
        ),
    ):
        add_causal_oracle(
            f"boundary-retention-scan-budget-{suffix}",
            {
                "operation": "retention_scan",
                "case": suffix,
                "bound": "scan_bounds.retention_records_max",
                "delta": delta,
            },
            expected,
            scan_positive,
        )

    # The policy has several independent scan dimensions.  The graph, depth,
    # and encoded-byte dimensions deliberately reuse the already-rendered
    # causal triples below/above; these remaining dimensions get their own
    # operation triplets so no field is hidden behind a coupled label.
    for field in (
        "roots_max",
        "filesystems_max",
        "reservations_max",
        "relations_max",
        "objects_max",
        "journals_max",
        "directory_children_max",
    ):
        positive = f"boundary-scan-{field}-exact"
        for suffix, delta, expected in (
            ("minus-one", -1, "accepted"),
            ("exact", 0, "accepted"),
            (
                "plus-one",
                1,
                error_code("array field is outside the frozen bound"),
            ),
        ):
            add_causal_oracle(
                f"boundary-scan-{field}-{suffix}",
                {
                    "operation": "scan_bound",
                    "field": field,
                    "delta": delta,
                },
                expected,
                positive,
            )

    # M02: every frozen owner/phase pair gets a five-root join recipe.  The
    # transaction owner is intentionally retained as a policy-only recipe:
    # capacity-generation/v2 cannot structurally represent that owner, so the
    # test invokes validate_capacity_policy and independently checks the exact
    # five selector join.  Capacity and retention-capacity pairs additionally
    # pass through the production generation/policy join helper.
    for owner, phase in OWNER_PHASES:
        identifier = f"join-owner-phase-{owner}-{phase}".lower()
        add_causal_oracle(
            identifier,
            {
                "operation": "owner_phase_join",
                "case": "positive",
                "owner": owner,
                "phase": phase,
                "root_selectors": len(ROOT_ROLES),
            },
            "accepted",
            identifier,
        )
    join_mutation_cases = (
        ("missing-root", "U1_ARRAY_FIELD_IS_OUTSIDE_THE_FROZEN_BOUND"),
        (
            "duplicate-root",
            error_code("capacity phase maximum selector is unknown or duplicated"),
        ),
        (
            "alias-root",
            error_code("capacity phase maximum selector is unknown or duplicated"),
        ),
        (
            "wrong-phase",
            error_code("capacity phase maximum selector is unknown or duplicated"),
        ),
        (
            "cross-owner",
            error_code("capacity phase maximum selector is unknown or duplicated"),
        ),
        (
            "root-set",
            error_code("capacity generation root role is unknown or duplicated"),
        ),
    )
    for case, expected in join_mutation_cases:
        add_causal_oracle(
            f"join-owner-phase-{case}",
            {
                "operation": "owner_phase_join",
                "case": case,
                "owner": "capacity",
                "phase": "RESERVED",
                "root_selectors": len(ROOT_ROLES),
            },
            expected,
            "join-owner-phase-capacity-reserved",
        )

    value = capacity_policy()
    value["scan_bounds"]["graph_nodes_max"] = 0
    add_schema_mutation(
        "mutation-capacity-scan-bound",
        "kilix.content.capacity-reserve/v2",
        value,
    )
    value = capacity_policy()
    value["retention_limits"]["retained_unique_objects_max"] = 0
    add_schema_mutation(
        "boundary-retention-global-limit-minus-one",
        "kilix.content.capacity-reserve/v2",
        value,
        vector_class="boundary",
    )
    value = capacity_policy()
    value["retention_limits"]["retained_versions_per_stable_slot_max"] = 0
    add_schema_mutation(
        "boundary-retention-per-slot-limit-minus-one",
        "kilix.content.capacity-reserve/v2",
        value,
        vector_class="boundary",
    )
    value = catalog()
    value["packages"][0]["install"]["build_argv"] = []
    value["packages"][0]["install"]["dependencies"] = [
        {"id": "demo.git", "role": "runtime"}
    ]
    value["contents"][0]["install"]["dependencies"] = [
        {"id": "demo.package", "role": "runtime"}
    ]
    add_semantic_mutation(
        "cycle-catalog-dependency-two-node",
        "kilix.content.catalog/v5",
        value,
        "dependency graph contains a cycle or exceeds its depth bound",
        vector_class="cycle",
    )
    value = catalog()
    value["packages"][0]["install"]["build_argv"] = []
    value["packages"][0]["install"]["dependencies"] = [
        {"id": "demo.git", "role": "runtime"}
    ]
    value["contents"][0]["install"]["dependencies"] = [
        {"id": "demo.codec", "role": "runtime"}
    ]
    add_semantic_mutation(
        "cycle-catalog-alias-normalized-two-node",
        "kilix.content.catalog/v5",
        value,
        "dependency graph contains a cycle or exceeds its depth bound",
        vector_class="cycle",
    )

    # H3-H5 acyclic digest, descriptor, set, physical, intent, and H mutations.
    value = retention_envelope()
    value["envelope_sha256"] = _replace_digest(value["envelope_sha256"])
    add_value(
        "mutation-retention-envelope-digest",
        "mutation",
        "kilix.content.retention-envelope/v1",
        value,
        "semantic",
        error_code("retention envelope digest is inconsistent"),
    )
    value = retention_marker()
    value["semantic_payload_sha256"] = _replace_digest(value["semantic_payload_sha256"])
    add_value(
        "mutation-retention-marker-semantic-digest",
        "mutation",
        "kilix.content.retention-marker/v1",
        value,
        "semantic",
        error_code("retention marker semantic payload digest is inconsistent"),
    )
    value = retention_relation()
    value["semantic_payload_sha256"] = _replace_digest(value["semantic_payload_sha256"])
    add_value(
        "mutation-retention-relation-semantic-digest",
        "mutation",
        "kilix.content.retention-relation/v1",
        value,
        "semantic",
        error_code("retention relation semantic payload digest is inconsistent"),
    )
    value = logical_state()
    value["R_counted"] = []
    add_value(
        "mutation-retention-logical-r-union",
        "mutation",
        "kilix.content.retention-logical-state/v1",
        value,
        "semantic",
        error_code("R counted is not the union of present and pending relations"),
    )
    value = logical_state()
    value["retained_unique_objects"] = 2
    add_value(
        "mutation-retention-logical-object-cardinality",
        "mutation",
        "kilix.content.retention-logical-state/v1",
        value,
        "semantic",
        error_code("retained unique object cardinality is inconsistent"),
    )
    value = physical_state(charge_source="actual", component_role="M")
    value["filesystem_unions"][0]["actual_bytes"] += 1
    add_value(
        "mutation-retention-physical-total",
        "mutation",
        "kilix.content.retention-physical-state/v1",
        value,
        "semantic",
        error_code("physical filesystem union totals are inconsistent"),
    )
    value = physical_state(charge_source="actual", component_role="M")
    value["filesystem_unions"][0]["envelope_sha256"] = sha("wrong-envelope")
    add_value(
        "mutation-retention-physical-envelope-digest",
        "mutation",
        "kilix.content.retention-physical-state/v1",
        value,
        "semantic",
        error_code("physical filesystem envelope digest is inconsistent"),
    )
    value = retention_intent(directory_count=1)
    value["component_envelope_sha256"] = _replace_digest(
        value["component_envelope_sha256"]
    )
    add_value(
        "mutation-retention-intent-component-envelope-digest",
        "mutation",
        "kilix.content.retention-intent/v1",
        value,
        "semantic",
        error_code("retention component envelope digest is inconsistent"),
    )
    value = retention_intent(directory_count=2)
    value["components"][1]["final_relative_path"] = "other/d1"
    add_value(
        "cycle-retention-directory-ancestry",
        "cycle",
        "kilix.content.retention-intent/v1",
        value,
        "semantic",
        error_code("retention directory chain is not outermost first"),
    )
    value = retention_handoff()
    value["absence_evidence"]["sha256"] = _replace_digest(
        value["absence_evidence"]["sha256"]
    )
    add_value(
        "mutation-retention-handoff-absence-digest",
        "mutation",
        "kilix.content.retention-handoff-proof/v1",
        value,
        "semantic",
        error_code("H absence-evidence digest is inconsistent"),
    )
    value = recovery_vector()
    value["handoff_rows"][0]["expected_action"] = "unsafe-action"
    add_value(
        "mutation-recovery-oracle-action",
        "mutation",
        "kilix.content.recovery-vector/v1",
        value,
        "semantic",
        error_code("handoff recovery row diverges from the frozen oracle"),
    )
    value = retention_intent()
    value["object_identity"]["install_authority_sha256"] = 1
    add_schema_mutation(
        "mutation-retention-intent-authority-binding",
        "kilix.content.retention-intent/v1",
        value,
    )
    value = retention_intent(directory_count=1)
    value["directory_child_rules"][0]["phase"] = "FUTURE"
    add_schema_mutation(
        "mutation-retention-directory-phase",
        "kilix.content.retention-intent/v1",
        value,
    )
    value = retention_envelope()
    value["entries"][0]["max_bytes"] += 1
    add_semantic_mutation(
        "mutation-retention-envelope-component-maximum",
        "kilix.content.retention-envelope/v1",
        value,
        "retention envelope digest is inconsistent",
    )
    value = retention_marker()
    value["predecessor_transaction_generation_sha256"] = _replace_digest(
        value["predecessor_transaction_generation_sha256"]
    )
    add_semantic_mutation(
        "mutation-retention-marker-predecessor",
        "kilix.content.retention-marker/v1",
        value,
        "retention marker semantic payload digest is inconsistent",
    )
    value = retention_relation()
    value["relation_identity"]["stable_slot_sha256"] = 1
    add_schema_mutation(
        "mutation-retention-relation-authority",
        "kilix.content.retention-relation/v1",
        value,
    )
    value = retention_accounted()
    value["logical_state_sha256"] = _replace_digest(value["logical_state_sha256"])
    add_semantic_mutation(
        "mutation-retention-accounted-logical-digest",
        "kilix.content.retention-accounted/v1",
        value,
        "P logical-state digest is inconsistent",
    )
    value = retention_accounted()
    value["p_final_relative_path"] = "other/path"
    add_semantic_mutation(
        "mutation-retention-accounted-final-path",
        "kilix.content.retention-accounted/v1",
        value,
        "P final path diverges from its intent component",
    )
    value = retention_handoff()
    value["handoff_nonce"] = 1
    add_schema_mutation(
        "mutation-retention-handoff-nonce",
        "kilix.content.retention-handoff-proof/v1",
        value,
    )
    value = retention_handoff()
    value["next_capacity_fields"]["phase"] = "RETENTION_ACCOUNTED"
    add_schema_mutation(
        "mutation-retention-handoff-next-phase",
        "kilix.content.retention-handoff-proof/v1",
        value,
    )
    value = directory_observation()
    value["filesystem_key"] = 1
    add_schema_mutation(
        "mutation-directory-filesystem-key",
        "kilix.content.directory-observation/v1",
        value,
    )
    value = directory_observation()
    value["phase"] = "UNIT_MAYBE_SENT"
    add_schema_mutation(
        "mutation-directory-phase",
        "kilix.content.directory-observation/v1",
        value,
    )
    value = directory_observation()
    value["observed_children"] = []
    add_semantic_mutation(
        "mutation-directory-observed-child-set",
        "kilix.content.directory-observation/v1",
        value,
        "directory observed child set is outside baseline plus phase delta",
    )
    value = transaction_generation("RETENTION_PREPARED")
    value["phase_payload"]["component_envelope_sha256"] = 1
    add_schema_mutation(
        "mutation-transaction-phase-payload",
        "kilix.content.transaction-generation/v1",
        value,
    )
    value = transaction_generation("RETENTION_PREPARED")
    value["phase"] = "FUTURE"
    add_schema_mutation(
        "cycle-transaction-future-phase",
        "kilix.content.transaction-generation/v1",
        value,
        vector_class="cycle",
    )

    # M03: causal cycle families whose hostile references are either rejected
    # by a pure chain/provenance validator or cannot be represented by a
    # production schema and therefore use a source-only recipe.
    cycle_cases = (
        (
            "cycle-transaction-predecessor-two-node",
            "transaction-predecessor-cycle",
            error_code("transaction predecessor does not bind exact prior bytes"),
            "cycle-transaction-predecessor-positive",
        ),
        (
            "cycle-transaction-replay-two-node",
            "transaction-replay-cycle",
            error_code("transaction generation skips or replays a generation"),
            "cycle-transaction-replay-positive",
        ),
        (
            "cycle-capacity-self-digest",
            "capacity-self-digest",
            error_code("capacity generation predecessor does not bind exact prior bytes"),
            "cycle-capacity-self-digest-positive",
        ),
        (
            "cycle-capacity-future-digest",
            "capacity-future-digest",
            error_code("capacity generation predecessor does not bind exact prior bytes"),
            "cycle-capacity-future-digest-positive",
        ),
        (
            "cycle-retention-envelope-component",
            "retention-envelope-component-cycle",
            error_code("retention envelope diverges from its intent"),
            "cycle-retention-envelope-component-positive",
        ),
        (
            "cycle-cross-journal-envelope",
            "cross-journal-envelope-cycle",
            error_code("physical identity aliases across filesystem unions"),
            "cycle-cross-journal-envelope-positive",
        ),
    )
    for identifier, case, expected, positive_id in cycle_cases:
        add_causal_oracle(
            identifier,
            {"operation": "provenance_cycle", "case": case},
            expected,
            positive_id,
        )
        add_causal_oracle(
            positive_id,
            {"operation": "provenance_cycle", "case": f"{case}-positive"},
            "accepted",
            positive_id,
        )

    # M04: atomic field-edge recipes.  Each row names one semantic edge from
    # the R3-5 sentence; the test constructs the matching production record,
    # mutates only that edge, and invokes its real pure validator.
    edge_positives = {
        "install": "edge-install-positive",
        "filesystem": "edge-filesystem-key-positive",
        "capacity": "edge-capacity-positive",
        "intent": "edge-intent-positive",
        "provenance": "edge-provenance-positive",
        "admission": "edge-admission-positive",
    }
    for group, identifier in edge_positives.items():
        add_causal_oracle(
            identifier,
            {"operation": "named_edge", "case": "positive", "group": group},
            "accepted",
            identifier,
        )
    edge_cases = (
        ("install-source-url", "install", SCHEMA_FAILURE),
        ("install-source-kind", "install", SCHEMA_FAILURE),
        ("install-git-commit", "install", SCHEMA_FAILURE),
        ("install-license-decision", "install", SCHEMA_FAILURE),
        ("filesystem-boot-id", "filesystem", error_code("filesystem identity is zero")),
        ("filesystem-magic", "filesystem", error_code("integer field is outside the unsigned-64 bound")),
        ("filesystem-type", "filesystem", error_code("text field is outside the frozen grammar")),
        ("filesystem-device-major", "filesystem", error_code("integer field is outside the unsigned-32 bound")),
        ("filesystem-device-minor", "filesystem", error_code("integer field is outside the unsigned-32 bound")),
        ("filesystem-fsid-word-0", "filesystem", error_code("integer field is outside the unsigned-64 bound")),
        ("filesystem-fsid-word-1", "filesystem", error_code("integer field is outside the unsigned-64 bound")),
        ("capacity-phase", "capacity", error_code("capacity generation owner and phase are inconsistent")),
        ("capacity-generation", "capacity", error_code("integer field is outside the signed-64 bound")),
        ("capacity-predecessor", "capacity", error_code("text field is outside the frozen bound")),
        ("intent-nonce", "intent", SCHEMA_FAILURE),
        ("intent-object-descriptor", "intent", SCHEMA_FAILURE),
        ("intent-component-descriptor", "intent", error_code("retention component envelope does not match components")),
        ("marker-predecessor", "provenance", error_code("text field is outside the frozen bound")),
        ("marker-digest", "provenance", error_code("retention marker semantic payload digest is inconsistent")),
        ("marker-semantic-core", "provenance", error_code("retention marker semantic payload digest is inconsistent")),
        ("relation-predecessor", "provenance", error_code("text field is outside the frozen bound")),
        ("relation-digest", "provenance", error_code("retention relation semantic payload digest is inconsistent")),
        ("relation-semantic-core", "provenance", error_code("retention relation identity diverges from its authority")),
        ("accounted-predecessor", "provenance", error_code("P durable generation provenance is inconsistent")),
        ("accounted-digest", "provenance", error_code("P logical-state digest is inconsistent")),
        ("accounted-semantic-core", "provenance", error_code("P final path diverges from its intent component")),
        ("handoff-predecessor", "provenance", error_code("H transaction ACCOUNTED provenance is inconsistent")),
        ("handoff-digest", "provenance", error_code("H physical-state digest is inconsistent")),
        ("handoff-semantic-core", "provenance", error_code("H names diverge from the original intent component")),
        ("journal-predecessor", "provenance", error_code("transaction predecessor does not bind exact prior bytes")),
        ("journal-digest", "provenance", error_code("transaction predecessor does not bind exact prior bytes")),
        ("journal-semantic-core", "provenance", error_code("transaction phase skips or regresses")),
        ("logical-set", "admission", error_code("O referenced is not the projection of R counted")),
        ("logical-count", "admission", error_code("retained unique object cardinality is inconsistent")),
        ("logical-admission", "admission", error_code("retention admission closure and reasons diverge")),
        ("physical-set", "admission", error_code("physical component identity is duplicated")),
        ("physical-count", "admission", error_code("physical filesystem union totals are inconsistent")),
        ("physical-charge", "admission", error_code("physical filesystem union totals are inconsistent")),
    )
    for field, group, expected in edge_cases:
        add_causal_oracle(
            f"mutation-edge-{field}",
            {"operation": "named_edge", "case": field, "group": group},
            expected,
            edge_positives[group],
        )

    value = logical_state()
    value["retained_unique_objects"] = -1
    add_schema_mutation(
        "boundary-retention-logical-global-minus-one",
        "kilix.content.retention-logical-state/v1",
        value,
        vector_class="boundary",
    )
    value = physical_state(charge_source="actual", component_role="M")
    value["filesystem_unions"][0]["filesystem_key"] = 1
    add_schema_mutation(
        "mutation-retention-physical-filesystem-key",
        "kilix.content.retention-physical-state/v1",
        value,
    )

    # M1 duplicate, Unicode, lexical-number, and canonical-byte attacks.
    catalog_schema = "kilix.content.catalog/v5"
    duplicate_code = error_code("duplicate JSON key")
    add_raw(
        "duplicate-key-root-printable",
        "duplicate-key",
        catalog_schema,
        b'{"schema":"kilix.content.catalog/v5","schema":"kilix.content.catalog/v5"}',
        "parser",
        duplicate_code,
    )
    add_raw(
        "duplicate-key-nested-printable",
        "duplicate-key",
        catalog_schema,
        b'{"schema":"kilix.content.catalog/v5","x":{"a":1,"a":2}}',
        "parser",
        duplicate_code,
    )
    add_raw(
        "duplicate-key-control-escape",
        "duplicate-key",
        catalog_schema,
        b'{"\\u001b":1,"\\u001b":2}',
        "parser",
        duplicate_code,
    )
    add_raw(
        "duplicate-key-bidi-format",
        "duplicate-key",
        catalog_schema,
        b'{"\\u202e":1,"\\u202e":2}',
        "parser",
        duplicate_code,
    )
    add_raw(
        "duplicate-key-normalization-confusable",
        "duplicate-key",
        catalog_schema,
        '{"é":1,"é":2}'.encode(),
        "parser",
        error_code("JSON text is outside the canonical Unicode bound"),
    )
    for identifier, raw, message, stage in (
        (
            "invalid-parser-bom",
            b'\xef\xbb\xbf{"schema":"kilix.content.catalog/v5"}',
            "JSON input is not valid bounded UTF-8 JSON",
            "parser",
        ),
        (
            "invalid-parser-invalid-utf8",
            b'{"schema":"kilix.content.catalog/v5","x":"\xff"}',
            "JSON input is not valid bounded UTF-8 JSON",
            "parser",
        ),
        (
            "invalid-parser-trailing-data",
            b'{"schema":"kilix.content.catalog/v5"}{}',
            "JSON input is not valid bounded UTF-8 JSON",
            "parser",
        ),
        (
            "invalid-parser-whitespace",
            b'{ "schema": "kilix.content.catalog/v5" }',
            "JSON input is not the canonical byte representation",
            "canonical",
        ),
        (
            "invalid-parser-float",
            b'{"schema":"kilix.content.catalog/v5","x":1.0}',
            "floating-point JSON value is forbidden",
            "parser",
        ),
        (
            "invalid-parser-exponent",
            b'{"schema":"kilix.content.catalog/v5","x":1e2}',
            "floating-point JSON value is forbidden",
            "parser",
        ),
        (
            "invalid-parser-nonfinite",
            b'{"schema":"kilix.content.catalog/v5","x":NaN}',
            "non-standard JSON constant",
            "parser",
        ),
        (
            "invalid-parser-negative-zero",
            b'{"schema":"kilix.content.catalog/v5","x":-0}',
            "JSON input is not the canonical byte representation",
            "canonical",
        ),
        (
            "invalid-parser-alternate-escape",
            b'{"schema":"kilix.content.catalog/v5","x":"\\u0061"}',
            "JSON input is not the canonical byte representation",
            "canonical",
        ),
        (
            "invalid-parser-key-order",
            b'{"schema":"kilix.content.catalog/v5","release_id":"x","aliases":[]}',
            "JSON input is not the canonical byte representation",
            "canonical",
        ),
    ):
        add_raw(
            identifier,
            "invalid",
            catalog_schema,
            raw,
            stage,
            error_code(message),
        )

    # Numeric/list/depth/encoded-byte limit controls.
    value = install_record("archive", output_manifest=True)
    value["source"]["source_bytes_max"] = S64_MAX
    value["source_bytes_max"] = S64_MAX
    add_value(
        "boundary-s64-maximum-accepted",
        "boundary",
        "kilix.content.install-record/v5",
        value,
        "accepted",
        "accepted",
    )
    value = install_record("archive", output_manifest=True)
    value["source"]["source_bytes_max"] = S64_MAX + 1
    value["source_bytes_max"] = S64_MAX + 1
    add_value(
        "boundary-s64-maximum-plus-one",
        "boundary",
        "kilix.content.install-record/v5",
        value,
        "schema",
        SCHEMA_FAILURE,
    )
    add_raw(
        "boundary-u64-maximum-parser-control",
        "boundary",
        catalog_schema,
        f'{{"schema":"kilix.content.catalog/v5","x":{U64_MAX}}}'.encode(),
        "schema",
        SCHEMA_FAILURE,
    )
    add_raw(
        "boundary-integer-token-maximum-plus-one",
        "boundary",
        catalog_schema,
        b'{"schema":"kilix.content.catalog/v5","x":100000000000000000000}',
        "parser",
        error_code("JSON integer is outside the token bound"),
    )
    add_value(
        "boundary-retention-directory-count-32",
        "boundary",
        "kilix.content.retention-intent/v1",
        retention_intent(directory_count=32),
        "accepted",
        "accepted",
    )
    add_value(
        "boundary-retention-directory-count-33",
        "boundary",
        "kilix.content.retention-intent/v1",
        retention_intent(directory_count=33),
        "schema",
        SCHEMA_FAILURE,
    )
    value = install_record("archive", output_manifest=True)
    value["source"]["urls"] = [
        f"https://example.invalid/{index:02d}.tar" for index in range(16)
    ]
    add_value(
        "boundary-source-url-count-16",
        "boundary",
        "kilix.content.install-record/v5",
        value,
        "accepted",
        "accepted",
    )
    value = clone(value)
    value["source"]["urls"].append("https://example.invalid/16.tar")
    add_value(
        "boundary-source-url-count-17",
        "boundary",
        "kilix.content.install-record/v5",
        value,
        "schema",
        SCHEMA_FAILURE,
    )

    def nested(depth: int) -> bytes:
        value = "0"
        for _ in range(depth):
            value = f"[{value}]"
        return f'{{"schema":"kilix.content.catalog/v5","x":{value}}}'.encode()

    add_raw(
        "boundary-json-depth-64-parser-control",
        "boundary",
        catalog_schema,
        nested(63),
        "schema",
        SCHEMA_FAILURE,
    )
    add_raw(
        "boundary-json-depth-65",
        "boundary",
        catalog_schema,
        nested(65),
        "parser",
        error_code("JSON value exceeds the nesting bound"),
    )
    oversized = (
        b'{"schema":"kilix.content.catalog/v5","x":"' + b"a" * MAX_JSON_BYTES + b'"}'
    )
    add_raw(
        "boundary-json-bytes-maximum-plus-one",
        "boundary",
        catalog_schema,
        oversized,
        "parser",
        error_code("JSON input is outside the encoded-byte bound"),
    )

    def raw_byte_budget(target: int) -> bytes:
        count = 16
        prefix = b'{"x":['
        suffix = b"]}"
        overhead = len(prefix) + len(suffix) + count * 2 + (count - 1)
        remaining = target - overhead
        quotient, remainder = divmod(remaining, count)
        chunks: list[bytes] = []
        for index in range(count):
            length = quotient + (1 if index < remainder else 0)
            emoji_count, ascii_count = divmod(length, 4)
            chunks.append(("\U0001f600" * emoji_count + "a" * ascii_count).encode())
        return prefix + b",".join(b'"' + chunk + b'"' for chunk in chunks) + suffix

    raw_bytes_minus_one = raw_byte_budget(MAX_JSON_BYTES - 1)
    raw_bytes_exact = raw_byte_budget(MAX_JSON_BYTES)
    add_raw(
        "boundary-json-bytes-limit-minus-one",
        "boundary",
        catalog_schema,
        raw_bytes_minus_one,
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-json-bytes-limit-exact",
        "boundary",
        catalog_schema,
        raw_bytes_exact,
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-json-bytes-limit-plus-one",
        "boundary",
        catalog_schema,
        raw_bytes_exact + b" ",
        "parser",
        error_code("JSON input is outside the encoded-byte bound"),
    )

    # R3-5 parser and aggregate-bound corpus.  Large aggregate cases are
    # source-only operation recipes: the boundary test patches only sibling
    # earlier limits, then invokes the real walker for the named bound.  The
    # ordinary production-admission loop must refuse these test-only schemas.
    def object_with_properties(count: int) -> bytes:
        fields = [f'"k{index:04d}":0'.encode() for index in range(count)]
        return b"{" + b",".join(fields) + b"}"

    add_raw(
        "boundary-object-properties-limit-minus-one",
        "boundary",
        catalog_schema,
        object_with_properties(MAX_OBJECT_PROPERTIES - 1),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-object-properties-limit-exact",
        "boundary",
        catalog_schema,
        object_with_properties(MAX_OBJECT_PROPERTIES),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-object-properties-limit-plus-one",
        "boundary",
        catalog_schema,
        object_with_properties(MAX_OBJECT_PROPERTIES + 1),
        "parser",
        error_code("JSON object exceeds the property bound"),
    )

    def array_with_items(count: int) -> bytes:
        return b"[" + b",".join(b"0" for _ in range(count)) + b"]"

    add_raw(
        "boundary-array-items-limit-minus-one",
        "boundary",
        catalog_schema,
        array_with_items(MAX_ARRAY_ITEMS - 1),
        "schema",
        error_code("value must be an object"),
    )
    add_raw(
        "boundary-array-items-limit-exact",
        "boundary",
        catalog_schema,
        array_with_items(MAX_ARRAY_ITEMS),
        "schema",
        error_code("value must be an object"),
    )
    add_raw(
        "boundary-array-items-limit-plus-one",
        "boundary",
        catalog_schema,
        array_with_items(MAX_ARRAY_ITEMS + 1),
        "parser",
        error_code("JSON array exceeds the item bound"),
    )

    property_count = 32_763
    object_count = 9
    token_objects: list[dict[str, int]] = []
    quotient, remainder = divmod(property_count, object_count)
    for ordinal in range(object_count):
        count = quotient + (1 if ordinal < remainder else 0)
        token_objects.append({f"k{index:04d}": 0 for index in range(count)})
    token_minus_one = _canonical(token_objects)
    token_exact = _canonical([dict(token_objects[0], k0000="\\"), *token_objects[1:]])
    token_plus_one = _canonical([dict(token_objects[0], k0000="\\\\"), *token_objects[1:]])
    add_raw(
        "boundary-lexical-tokens-limit-minus-one",
        "boundary",
        catalog_schema,
        token_minus_one,
        "schema",
        error_code("value must be an object"),
    )
    add_raw(
        "boundary-lexical-tokens-limit-exact",
        "boundary",
        catalog_schema,
        token_exact,
        "schema",
        error_code("value must be an object"),
    )
    add_raw(
        "boundary-lexical-tokens-limit-plus-one",
        "boundary",
        catalog_schema,
        token_plus_one,
        "parser",
        error_code("JSON input exceeds the lexical token bound"),
    )

    def string_value(character: str, count: int) -> bytes:
        return _canonical({"x": character * count})

    add_raw(
        "boundary-string-codepoints-limit-minus-one",
        "boundary",
        catalog_schema,
        string_value("a", MAX_STRING_CODEPOINTS - 1),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-string-codepoints-limit-exact",
        "boundary",
        catalog_schema,
        string_value("a", MAX_STRING_CODEPOINTS),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-string-codepoints-limit-plus-one",
        "boundary",
        catalog_schema,
        b'{"x":"' + b"a" * (MAX_STRING_CODEPOINTS + 1) + b'"}',
        "parser",
        error_code("JSON text is outside the canonical Unicode bound"),
    )
    four_byte = "\U0001f600"
    add_raw(
        "boundary-string-bytes-limit-exact",
        "boundary",
        catalog_schema,
        string_value(four_byte, MAX_STRING_CODEPOINTS),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-string-bytes-limit-minus-one",
        "boundary",
        catalog_schema,
        string_value(four_byte, MAX_STRING_CODEPOINTS - 1)[:-2]
        + "€\"}".encode(),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-string-bytes-limit-plus-one",
        "boundary",
        catalog_schema,
        b'{"x":"'
        + (four_byte * MAX_STRING_CODEPOINTS + "a").encode("utf-8")
        + b'"}',
        "parser",
        error_code("JSON text is outside the canonical Unicode bound"),
    )

    def ascii_string_array(total_codepoints: int) -> bytes:
        count = 33
        quotient, remainder = divmod(total_codepoints, count)
        values = [
            "a" * (quotient + (1 if index < remainder else 0))
            for index in range(count)
        ]
        return b'{"x":[' + b",".join(b'"' + value.encode() + b'"' for value in values) + b"]}"

    for suffix, codepoint_count in (
        ("minus-one", MAX_TOTAL_STRING_CODEPOINTS - 2),
        ("exact", MAX_TOTAL_STRING_CODEPOINTS - 1),
    ):
        add_raw(
            f"boundary-total-string-codepoints-{suffix}",
            "boundary",
            catalog_schema,
            ascii_string_array(codepoint_count),
            "schema",
            error_code("U1 admission schema does not match the expected resource role"),
        )
    add_raw(
        "boundary-total-string-codepoints-plus-one",
        "boundary",
        catalog_schema,
        ascii_string_array(MAX_TOTAL_STRING_CODEPOINTS),
        "parser",
        error_code("JSON value exceeds the aggregate string bound"),
    )

    add_raw(
        "boundary-integer-digits-limit-minus-one",
        "boundary",
        catalog_schema,
        b'{"x":1234567890123456789}',
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-integer-digits-limit-exact",
        "boundary",
        catalog_schema,
        f"{{\"x\":{U64_MAX}}}".encode(),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-integer-digits-limit-plus-one",
        "boundary",
        catalog_schema,
        b'{"x":100000000000000000000}',
        "parser",
        error_code("JSON integer is outside the token bound"),
    )
    add_raw(
        "boundary-integer-domain-limit-minus-one",
        "boundary",
        catalog_schema,
        f"{{\"x\":{U64_MAX - 1}}}".encode(),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-integer-domain-limit-exact",
        "boundary",
        catalog_schema,
        f"{{\"x\":{U64_MAX}}}".encode(),
        "schema",
        error_code("U1 admission schema does not match the expected resource role"),
    )
    add_raw(
        "boundary-integer-domain-limit-plus-one",
        "boundary",
        catalog_schema,
        b'{"x":18446744073709551616}',
        "parser",
        error_code("JSON integer is outside the representation bound"),
    )
    add_raw(
        "boundary-json-depth-63-limit-minus-one",
        "boundary",
        catalog_schema,
        nested(62),
        "schema",
        SCHEMA_FAILURE,
    )

    def graph_catalog(chain_nodes: int) -> dict[str, Any]:
        value = catalog()
        for index in range(chain_nodes):
            install = install_record("mirrored")
            if index + 1 < chain_nodes:
                install["dependencies"] = [
                    {"id": f"graph-{index + 1:03d}", "role": "runtime"}
                ]
            value["contents"].append(
                {
                    "id": f"graph-{index:03d}",
                    "stable_slot": f"graph-slot-{index:03d}",
                    "install": install,
                }
            )
        value["contents"] = ordered(value["contents"])
        return value

    for suffix, nodes in (("limit-minus-one", 64), ("exact", 65)):
        add_value(
            f"boundary-graph-depth-{suffix}",
            "boundary",
            catalog_schema,
            graph_catalog(nodes),
            "accepted",
            "accepted",
        )
    add_value(
        "boundary-graph-depth-limit-plus-one",
        "boundary",
        catalog_schema,
        graph_catalog(66),
        "semantic",
        error_code("dependency graph contains a cycle or exceeds its depth bound"),
    )

    def operation_raw(identifier: str, raw: bytes, disposition: dict[str, Any]) -> None:
        add_raw(
            identifier,
            "operation",
            disposition["schema_id"],
            raw,
            "operation",
            disposition["expected"],
            disposition,
        )

    operation_schema = "test-only.u1-boundary-operation/v1"
    for suffix, count, expected in (
        ("minus-one", MAX_TOTAL_PROPERTIES - 1, "accepted"),
        ("exact", MAX_TOTAL_PROPERTIES, "accepted"),
        ("plus-one", MAX_TOTAL_PROPERTIES + 1, error_code("JSON value exceeds the aggregate property bound")),
    ):
        operation_raw(
            f"boundary-aggregate-properties-{suffix}",
            object_with_properties(count),
            {
                "schema_id": operation_schema,
                "operation": "walk_json",
                "bound": "MAX_TOTAL_PROPERTIES",
                "expected": expected,
                "patch_siblings": ["MAX_OBJECT_PROPERTIES", "MAX_JSON_NODES"],
                "paired_positive_id": "boundary-aggregate-properties-exact",
                "source_only": True,
            },
        )
    for suffix, count, expected in (
        ("minus-one", MAX_TOTAL_ARRAY_ITEMS - 1, "accepted"),
        ("exact", MAX_TOTAL_ARRAY_ITEMS, "accepted"),
        ("plus-one", MAX_TOTAL_ARRAY_ITEMS + 1, error_code("JSON value exceeds the aggregate array-item bound")),
    ):
        operation_raw(
            f"boundary-aggregate-items-{suffix}",
            array_with_items(count),
            {
                "schema_id": operation_schema,
                "operation": "walk_json",
                "bound": "MAX_TOTAL_ARRAY_ITEMS",
                "expected": expected,
                "patch_siblings": ["MAX_ARRAY_ITEMS", "MAX_JSON_NODES"],
                "paired_positive_id": "boundary-aggregate-items-exact",
                "source_only": True,
            },
        )
    for suffix, count, expected in (
        ("minus-one", MAX_JSON_NODES - 1, "accepted"),
        ("exact", MAX_JSON_NODES, "accepted"),
        ("plus-one", MAX_JSON_NODES + 1, error_code("JSON value exceeds the aggregate node bound")),
    ):
        operation_raw(
            f"boundary-aggregate-nodes-{suffix}",
            array_with_items(count - 1),
            {
                "schema_id": operation_schema,
                "operation": "walk_json",
                "bound": "MAX_JSON_NODES",
                "expected": expected,
                "patch_siblings": [
                    "MAX_ARRAY_ITEMS",
                    "MAX_TOTAL_ARRAY_ITEMS",
                ],
                "paired_positive_id": "boundary-aggregate-nodes-exact",
                "source_only": True,
            },
        )

    def total_string_bytes_raw(total: int) -> bytes:
        count = 16
        quotient, remainder = divmod(total, count)
        values = [
            "a" * (quotient + (1 if index < remainder else 0))
            for index in range(count)
        ]
        return b'{"x":[' + b",".join(b'"' + value.encode() + b'"' for value in values) + b"]}"

    for suffix, value_bytes, expected in (
        ("minus-one", MAX_TOTAL_STRING_BYTES - 2, "accepted"),
        ("exact", MAX_TOTAL_STRING_BYTES - 1, "accepted"),
        ("plus-one", MAX_TOTAL_STRING_BYTES, error_code("JSON value exceeds the aggregate string bound")),
    ):
        operation_raw(
            f"boundary-total-string-bytes-{suffix}",
            total_string_bytes_raw(value_bytes),
            {
                "schema_id": operation_schema,
                "operation": "walk_json",
                "bound": "MAX_TOTAL_STRING_BYTES",
                "expected": expected,
                "patch_siblings": ["MAX_STRING_BYTES", "MAX_STRING_CODEPOINTS", "MAX_TOTAL_STRING_CODEPOINTS"],
                "paired_positive_id": "boundary-total-string-bytes-exact",
                "source_only": True,
            },
        )

    graph_recipe_schema = "test-only.catalog-graph-recipe/v1"
    for suffix, nodes, expected in (
        ("minus-one", 8_191, "accepted"),
        ("exact", 8_192, "accepted"),
        ("plus-one", 8_193, error_code("dependency graph exceeds the node bound")),
    ):
        operation_raw(
            f"boundary-graph-nodes-{suffix}",
            _canonical({"schema": graph_recipe_schema, "nodes": nodes, "edges": 3}),
            {
                "schema_id": graph_recipe_schema,
                "operation": "catalog_graph",
                "bound": "MAX_GRAPH_NODES",
                "expected": expected,
                "paired_positive_id": "boundary-graph-nodes-exact",
                "source_only": True,
            },
        )
    for suffix, edges, expected in (
        ("minus-one", 16_383, "accepted"),
        ("exact", 16_384, "accepted"),
        ("plus-one", 16_385, error_code("dependency graph exceeds the edge bound")),
    ):
        operation_raw(
            f"boundary-graph-edges-{suffix}",
            _canonical({"schema": graph_recipe_schema, "nodes": 4_099, "edges": edges}),
            {
                "schema_id": graph_recipe_schema,
                "operation": "catalog_graph",
                "bound": "MAX_GRAPH_EDGES",
                "expected": expected,
                "paired_positive_id": "boundary-graph-edges-exact",
                "source_only": True,
            },
        )

    admission_authority_schema = "test-only.u1-admission-authority/v1"
    admission_authority_cases = (
        ("genuine-capability", "accepted"),
        (
            "missing-capability",
            error_code("U1 admission lacks the genuine packaged release capability"),
        ),
        (
            "caller-dict",
            error_code("U1 admission lacks the genuine packaged release capability"),
        ),
        (
            "test-authority",
            error_code("U1 admission lacks the genuine packaged release capability"),
        ),
        (
            "unknown-route",
            error_code(
                "U1 admission expected schema is outside the frozen route table"
            ),
        ),
    )
    for case, expected in admission_authority_cases:
        operation_raw(
            f"admission-authority-{case}",
            _canonical(
                {
                    "case": case,
                    "schema": admission_authority_schema,
                }
            ),
            {
                "schema_id": admission_authority_schema,
                "operation": "admission_authority",
                "bound": "sole-packaged-capability-and-route",
                "expected": expected,
                "paired_positive_id": "positive-catalog-v5",
                "source_only": True,
            },
        )

    ids = [entry["id"] for entry in vectors]
    if len(ids) != len(set(ids)):
        raise SystemExit("fixture vector IDs are duplicated")
    missing = (set(REQUIRED_VECTOR_IDS) | _ledger_vector_ids()) - set(ids)
    if missing:
        raise SystemExit(f"mandatory fixture vectors are absent: {sorted(missing)!r}")
    return sorted(vectors, key=lambda entry: entry["id"])


def render() -> tuple[int, str]:
    vectors = build_vectors()
    if CORPUS_ROOT.exists():
        for path in sorted(CORPUS_ROOT.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    CORPUS_ROOT.mkdir(parents=True, exist_ok=True)
    entries = []
    for vector in vectors:
        directory = CORPUS_ROOT / vector["class"]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{vector['id']}.json"
        path.write_bytes(vector["raw"])
        relative = path.relative_to(FIXTURE_ROOT).as_posix()
        entry = {
                "id": vector["id"],
                "class": vector["class"],
                "schema_id": vector["schema_id"],
                "path": relative,
                "size": len(vector["raw"]),
                "sha256": hashlib.sha256(vector["raw"]).hexdigest(),
                "expected_stage": vector["expected_stage"],
                "expected_code": vector["expected_code"],
            }
        if "disposition" in vector:
            entry["disposition"] = vector["disposition"]
        entries.append(entry)
    entries = ordered(entries)
    index = {
        "schema": "kilix.content.u1-fixture-index/v1",
        "release_id": RELEASE_ID,
        "entries": entries,
    }
    index_payload = _canonical(index)
    INDEX_PATH.write_bytes(index_payload)
    paths = sorted(
        [INDEX_PATH, *CORPUS_ROOT.rglob("*.json")],
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    sums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(ROOT).as_posix()}\n"
        for path in paths
    )
    SUMS_PATH.write_text(sums, encoding="ascii", newline="")
    return len(entries), hashlib.sha256(index_payload).hexdigest()


def main() -> int:
    count, digest = render()
    print(f"vectors={count}")
    print(f"index_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
