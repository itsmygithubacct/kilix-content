"""Render the deterministic, source-only F100 U1 security corpus.

The corpus is included in the sdist and deliberately excluded from wheels.  It
contains inert bytes and expected validation dispositions only; it has no store,
filesystem-recovery, acquisition, or authorization behavior.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from kilix_content import U1ContractError, canonical_json_bytes
from kilix_content.u1_core import MAX_JSON_BYTES, S64_MAX, U64_MAX
from tests.u1_vectors import (
    capacity_generation,
    capacity_policy,
    catalog,
    clone,
    install_record,
    logical_state,
    ordered,
    physical_state,
    positive_records,
    recovery_vector,
    retention_envelope,
    retention_handoff,
    retention_intent,
    retention_marker,
    retention_relation,
    sandbox_profile,
    sha,
    system_profile,
    toolchain_profile,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "u1"
CORPUS_ROOT = FIXTURE_ROOT / "corpus"
INDEX_PATH = FIXTURE_ROOT / "index.json"
SUMS_PATH = FIXTURE_ROOT / "SHA256SUMS"
RELEASE_ID = "0.2.1"
SCHEMA_FAILURE = "U1_U1_JSON_SCHEMA_VALIDATION_REFUSED_THE_RECORD"

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


def _safe_id(value: str) -> str:
    result = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    if not result:
        raise ValueError("empty vector ID")
    return result


def _replace_digest(value: str) -> str:
    return ("1" if value[0] != "1" else "2") + value[1:]


def _canonical(value: Any) -> bytes:
    return canonical_json_bytes(value)


def build_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []

    def add_raw(
        identifier: str,
        vector_class: str,
        schema_id: str,
        raw: bytes,
        stage: str,
        code: str,
    ) -> None:
        vectors.append(
            {
                "id": _safe_id(identifier),
                "class": vector_class,
                "schema_id": schema_id,
                "raw": raw,
                "expected_stage": stage,
                "expected_code": code,
            }
        )

    def add_value(
        identifier: str,
        vector_class: str,
        schema_id: str,
        value: Any,
        stage: str,
        code: str,
    ) -> None:
        add_raw(identifier, vector_class, schema_id, _canonical(value), stage, code)

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
    value = retention_intent()
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

    ids = [entry["id"] for entry in vectors]
    if len(ids) != len(set(ids)):
        raise SystemExit("fixture vector IDs are duplicated")
    missing = set(REQUIRED_VECTOR_IDS) - set(ids)
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
        entries.append(
            {
                "id": vector["id"],
                "class": vector["class"],
                "schema_id": vector["schema_id"],
                "path": relative,
                "size": len(vector["raw"]),
                "sha256": hashlib.sha256(vector["raw"]).hexdigest(),
                "expected_stage": vector["expected_stage"],
                "expected_code": vector["expected_code"],
            }
        )
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
