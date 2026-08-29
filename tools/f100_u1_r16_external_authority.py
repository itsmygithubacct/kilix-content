#!/usr/bin/env python3
"""Verify F100 U1 evidence against an authority outside the candidate export.

This program deliberately does not import or execute candidate code.  It parses
the candidate gate as data, derives a complete static call-site population from
``main`` and compares that result with a separately supplied, digest-pinned
authority bundle.  A copy shipped inside a candidate export is never authority.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn


SCHEMA = "kilix.content.f100-u1-r16-external-authority/v1"
RESULT_SCHEMA = "kilix.content.f100-u1-r16-external-authority-result/v1"
AUTHORITY_NAME = "authority.json"
GATE_PATH = Path("tests/check_reproducible_build.py")
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
LANE_DISPOSITION_STATES: dict[str, tuple[bool, int | None]] = {
    "candidate-defect-cross-control-refusal": (True, 1),
    "candidate-defect-unhandled-exception": (True, 1),
    "candidate-defect-wrong-reason": (True, 1),
    "harness-invalid-archive-setup": (False, None),
    "harness-invalid-in-export-log": (True, 1),
    "harness-invalid-in-export-tmpdir": (True, 1),
    "harness-invalid-wrong-cwd": (False, 2),
    "retired-rc-not-authoritatively-bound-superseded-by-p1": (True, None),
    "valid-clean": (True, 0),
    "valid-clean-diagnostic-skip": (True, 0),
    "valid-expected-refusal": (True, 1),
    "valid-parent-baseline": (True, 0),
    "valid-work-asymmetric-pair": (True, 0),
}


class AuthorityRefusal(Exception):
    """A named, fail-closed external-authority refusal."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def canonical_json(value: Any, *, newline: bool = True) -> bytes:
    suffix = "\n" if newline else ""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + suffix
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise AuthorityRefusal("AUTHORITY_INPUT_UNREADABLE", f"{path}: {exc}") from exc


def refuse(code: str, detail: str) -> NoReturn:
    raise AuthorityRefusal(code, detail)


def load_canonical_object(path: Path, *, code: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        refuse(code, f"{path}: {exc}")
    if type(value) is not dict or raw != canonical_json(value):
        refuse(code, f"{path}: input is not a canonical JSON object")
    return value, raw


def require_closed_object(
    value: Any,
    keys: set[str],
    *,
    code: str,
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        refuse(code, f"{label}: expected keys={sorted(keys)!r}")
    return value


def require_sha256(value: Any, *, code: str, label: str) -> str:
    if type(value) is not str or HEX_256.fullmatch(value) is None:
        refuse(code, f"{label}: expected lowercase SHA-256")
    return value


def parse_gate(raw: bytes, path: Path) -> ast.Module:
    try:
        return ast.parse(raw, filename=str(path))
    except (UnicodeDecodeError, SyntaxError) as exc:
        refuse("CANDIDATE_GATE_NOT_PARSEABLE", f"{path}: {exc}")


def structural_ast_dump(node: ast.AST) -> str:
    """Return a complete AST shape under both Python 3.12 and 3.13.

    Python 3.13 added ``show_empty`` and changed ``ast.dump`` to omit optional
    empty fields by default.  Python 3.12 always emits those fields.  Asking
    3.13 explicitly for them preserves the 3.12 representation and keeps the
    external authority's structural digests independent of those interpreters.
    """

    keywords = {"annotate_fields": True, "include_attributes": False}
    if "show_empty" in inspect.signature(ast.dump).parameters:
        keywords["show_empty"] = True
    return ast.dump(node, **keywords)


def module_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    result: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name in result:
            refuse("CANDIDATE_DUPLICATE_FUNCTION", node.name)
        result[node.name] = node
    return result


def module_constant(tree: ast.Module, name: str) -> Any:
    matches: list[ast.expr] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if value is not None and any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            matches.append(value)
    if len(matches) != 1:
        refuse(
            "CANDIDATE_CONSTANT_CARDINALITY",
            f"{name}: observed assignments={len(matches)}",
        )
    try:
        return ast.literal_eval(matches[0])
    except (TypeError, ValueError) as exc:
        refuse("CANDIDATE_CONSTANT_NOT_LITERAL", f"{name}: {exc}")


def ast_sha256(node: ast.AST) -> str:
    raw = structural_ast_dump(node).encode("utf-8")
    return sha256_bytes(raw)


class Calls(ast.NodeVisitor):
    """Collect calls, including lambda and nested-function bodies.

    Including syntactically nested bodies intentionally over-approximates static
    reachability.  It cannot silently omit a candidate call merely because the
    candidate moved it into a local callback.
    """

    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - AST API name
        self.calls.append(node)
        self.generic_visit(node)


def called_module_functions(node: ast.AST, names: set[str]) -> set[str]:
    visitor = Calls()
    visitor.visit(node)
    result: set[str] = set()
    for call in visitor.calls:
        if isinstance(call.func, ast.Name) and call.func.id in names:
            result.add(call.func.id)
        # A local function can also be passed as a callback rather than called
        # at this site.  Treat every referenced module function in call arguments
        # as a graph edge so callback indirection cannot shrink the population.
        for argument in [*call.args, *call.keywords]:
            value = argument.value if isinstance(argument, ast.keyword) else argument
            for candidate in ast.walk(value):
                if isinstance(candidate, ast.Name) and candidate.id in names:
                    result.add(candidate.id)
    return result


def reachable_functions(tree: ast.Module, entrypoint: str) -> tuple[dict[str, ast.FunctionDef], list[str]]:
    functions = module_functions(tree)
    if entrypoint not in functions:
        refuse("P3_ENTRYPOINT_ABSENT", entrypoint)
    names = set(functions)
    reached: set[str] = set()
    pending = [entrypoint]
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(sorted(called_module_functions(functions[current], names) - reached))
    return functions, sorted(reached)


def call_target(node: ast.expr) -> str:
    return structural_ast_dump(node)


def derive_call_inventory(tree: ast.Module, entrypoint: str) -> list[dict[str, Any]]:
    functions, reached = reachable_functions(tree, entrypoint)
    inventory: list[dict[str, Any]] = []
    for owner in reached:
        visitor = Calls()
        visitor.visit(functions[owner])
        call_dumps = [structural_ast_dump(call) for call in visitor.calls]
        occurrences: Counter[str] = Counter()
        for call, call_dump in zip(visitor.calls, call_dumps, strict=True):
            occurrence = occurrences[call_dump]
            occurrences[call_dump] += 1
            identity = {
                "call": call_dump,
                "callee": call_target(call.func),
                "occurrence": occurrence,
                "owner": owner,
            }
            inventory.append(
                {
                    **identity,
                    "structural_sha256": sha256_bytes(canonical_json(identity, newline=False)),
                }
            )
    return sorted(
        inventory,
        key=lambda item: (
            item["owner"],
            item["structural_sha256"],
            item["occurrence"],
        ),
    )


def registry_rows(tree: ast.Module) -> list[dict[str, str]]:
    value = module_constant(tree, "PROPERTY_MUTATION_REGISTRY")
    if type(value) not in {tuple, list}:
        refuse("HISTORY_REGISTRY_NOT_SEQUENCE", type(value).__name__)
    required = {
        "artifact_family",
        "audit_kind",
        "expected_refusal",
        "id",
        "mutation",
        "property",
    }
    rows: list[dict[str, str]] = []
    for index, row in enumerate(value):
        if type(row) is not dict or set(row) != required or any(
            type(item) is not str or not item for item in row.values()
        ):
            refuse("HISTORY_REGISTRY_ROW_INVALID", f"index={index}")
        rows.append(dict(row))
    return rows


def validate_authority_shape(authority: dict[str, Any]) -> None:
    require_closed_object(
        authority,
        {
            "candidate",
            "evidence",
            "history",
            "implementation",
            "production_population",
            "schema",
            "scope_rows",
        },
        code="AUTHORITY_SHAPE",
        label="authority",
    )
    if authority["schema"] != SCHEMA:
        refuse("AUTHORITY_SCHEMA", repr(authority["schema"]))
    if authority["scope_rows"] != ["R16-6", "R16-7", "R16-9", "R16-12", "R16-13"]:
        refuse("AUTHORITY_SCOPE", repr(authority["scope_rows"]))


def verify_implementation(value: Any) -> dict[str, Any]:
    implementation = require_closed_object(
        value,
        {"verifier"},
        code="IMPLEMENTATION_AUTHORITY_SHAPE",
        label="implementation",
    )
    verifier = require_closed_object(
        implementation["verifier"],
        {"bytes", "path", "sha256"},
        code="IMPLEMENTATION_AUTHORITY_SHAPE",
        label="implementation.verifier",
    )
    if verifier["path"] != "tools/f100_u1_r16_external_authority.py":
        refuse("IMPLEMENTATION_VERIFIER_PATH", repr(verifier["path"]))
    expected = require_sha256(
        verifier["sha256"],
        code="IMPLEMENTATION_AUTHORITY_SHAPE",
        label="implementation.verifier.sha256",
    )
    try:
        raw = Path(__file__).read_bytes()
    except OSError as exc:
        refuse("IMPLEMENTATION_VERIFIER_UNREADABLE", str(exc))
    observed = sha256_bytes(raw)
    if type(verifier["bytes"]) is not int or len(raw) != verifier["bytes"] or observed != expected:
        refuse(
            "IMPLEMENTATION_VERIFIER_DRIFT",
            f"bytes={len(raw)} sha256={observed}",
        )
    return {"verifier_bytes": len(raw), "verifier_sha256": observed}


def verify_external_roots(candidate_root: Path, authority_root: Path) -> None:
    try:
        candidate = candidate_root.resolve(strict=True)
        authority = authority_root.resolve(strict=True)
    except OSError as exc:
        refuse("AUTHORITY_ROOT_UNREADABLE", str(exc))
    if candidate == authority or candidate in authority.parents or authority in candidate.parents:
        refuse(
            "AUTHORITY_NOT_EXTERNAL",
            f"candidate={candidate} authority={authority}",
        )
    if (candidate / ".git").exists():
        refuse("CANDIDATE_NOT_EXPORT", f"{candidate}/.git exists")


def verify_history(tree: ast.Module, history: Any) -> dict[str, Any]:
    value = require_closed_object(
        history,
        {"order_semantic", "protected_definitions", "required_prefix", "snapshots"},
        code="HISTORY_AUTHORITY_SHAPE",
        label="history",
    )
    if value["order_semantic"] is not True:
        refuse("HISTORY_ORDER_POLICY", "order_semantic must be true")
    protected = value["protected_definitions"]
    if type(protected) is not list or not protected:
        refuse("HISTORY_AUTHORITY_SHAPE", "protected_definitions must be nonempty")
    functions = module_functions(tree)
    protected_names: list[str] = []
    for index, definition in enumerate(protected):
        item = require_closed_object(
            definition,
            {"definition_sha256", "function", "role"},
            code="HISTORY_PROTECTED_DEFINITION_SHAPE",
            label=f"history.protected_definitions[{index}]",
        )
        function_name = item["function"]
        if type(function_name) is not str or not function_name:
            refuse("HISTORY_PROTECTED_DEFINITION_SHAPE", f"index={index} function")
        if function_name in protected_names:
            refuse("HISTORY_PROTECTED_DEFINITION_DUPLICATE", function_name)
        protected_names.append(function_name)
        if function_name not in functions:
            refuse("HISTORY_PROTECTED_DEFINITION_ABSENT", function_name)
        expected = require_sha256(
            item["definition_sha256"],
            code="HISTORY_PROTECTED_DEFINITION_SHAPE",
            label=f"history.protected_definitions[{index}].definition_sha256",
        )
        observed = ast_sha256(functions[function_name])
        if observed != expected:
            refuse(
                "HISTORY_PROTECTED_DEFINITION_DRIFT",
                f"function={function_name} expected={expected} observed={observed}",
            )

    prefix = value["required_prefix"]
    snapshots = value["snapshots"]
    if type(prefix) is not list or not prefix or type(snapshots) is not list or not snapshots:
        refuse("HISTORY_AUTHORITY_SHAPE", "required_prefix/snapshots must be nonempty lists")
    rows = registry_rows(tree)
    row_ids = [row["id"] for row in rows]
    prefix_ids = [row.get("id") if type(row) is dict else None for row in prefix]
    missing = [
        {
            "family": row.get("artifact_family"),
            "id": row.get("id"),
            "kind": row.get("audit_kind"),
        }
        for row in prefix
        if type(row) is dict and row.get("id") not in row_ids
    ]
    if missing:
        refuse("HISTORY_REQUIRED_ROW_REMOVED", repr(missing))
    if len(row_ids) != len(set(row_ids)):
        refuse("HISTORY_DUPLICATE_ROW_ID", repr(row_ids))
    if len(rows) < len(prefix):
        refuse("HISTORY_ROW_COUNT_SHRANK", f"rows={len(rows)} floor={len(prefix)}")
    if rows[: len(prefix)] != prefix:
        refuse("HISTORY_PREFIX_CHANGED", "historical row order or semantics differs")

    previous_ids: list[str] = []
    for index, snapshot in enumerate(snapshots):
        item = require_closed_object(
            snapshot,
            {"commit", "gate_sha256", "registry_sha256", "row_count", "row_ids", "tree"},
            code="HISTORY_SNAPSHOT_SHAPE",
            label=f"history.snapshots[{index}]",
        )
        for key in ("commit", "tree"):
            if type(item[key]) is not str or re.fullmatch(r"[0-9a-f]{40}", item[key]) is None:
                refuse("HISTORY_SNAPSHOT_IDENTITY", f"index={index} field={key}")
        require_sha256(item["gate_sha256"], code="HISTORY_SNAPSHOT_IDENTITY", label="gate_sha256")
        require_sha256(item["registry_sha256"], code="HISTORY_SNAPSHOT_IDENTITY", label="registry_sha256")
        if (
            type(item["row_ids"]) is not list
            or any(type(row_id) is not str or not row_id for row_id in item["row_ids"])
            or len(item["row_ids"]) != len(set(item["row_ids"]))
            or type(item["row_count"]) is not int
            or item["row_count"] != len(item["row_ids"])
        ):
            refuse("HISTORY_SNAPSHOT_COUNT", f"index={index}")
        if item["row_ids"][: len(previous_ids)] != previous_ids:
            refuse("HISTORY_SNAPSHOT_NOT_APPEND_ONLY", f"index={index}")
        previous_ids = list(item["row_ids"])
    if previous_ids != prefix_ids:
        refuse("HISTORY_FINAL_SNAPSHOT_DIFFERS", "final snapshot is not required_prefix")
    return {
        "required_prefix_rows": len(prefix),
        "current_rows": len(rows),
        "protected_definition_count": len(protected_names),
        "snapshot_count": len(snapshots),
    }


def verify_population(
    tree: ast.Module,
    gate_raw: bytes,
    candidate: Any,
    population: Any,
) -> dict[str, Any]:
    candidate_value = require_closed_object(
        candidate,
        {"commit", "gate_path", "gate_sha256", "tree"},
        code="CANDIDATE_AUTHORITY_SHAPE",
        label="candidate",
    )
    if candidate_value["gate_path"] != GATE_PATH.as_posix():
        refuse("CANDIDATE_GATE_PATH", repr(candidate_value["gate_path"]))
    expected_gate = require_sha256(
        candidate_value["gate_sha256"],
        code="CANDIDATE_AUTHORITY_SHAPE",
        label="candidate.gate_sha256",
    )
    observed_gate = sha256_bytes(gate_raw)

    value = require_closed_object(
        population,
        {
            "audit_count",
            "audits",
            "entrypoint",
            "enumeration_rule",
            "reachable_call_site_count",
            "reachable_call_sites_sha256",
            "reachable_owner_count",
            "registry_pair_count",
        },
        code="P3_AUTHORITY_SHAPE",
        label="production_population",
    )
    entrypoint = value["entrypoint"]
    if type(entrypoint) is not str or not entrypoint:
        refuse("P3_ENTRYPOINT", repr(entrypoint))
    inventory = derive_call_inventory(tree, entrypoint)
    inventory_raw = canonical_json(inventory)
    observed_inventory_digest = sha256_bytes(inventory_raw)
    observed_owner_count = len({item["owner"] for item in inventory})

    audits = value["audits"]
    if type(audits) is not list or len(audits) != value["audit_count"]:
        refuse("P3_AUDIT_COUNT", repr(value["audit_count"]))
    functions = module_functions(tree)
    pairs: list[tuple[str, str]] = []
    for index, audit in enumerate(audits):
        item = require_closed_object(
            audit,
            {
                "definition_sha256",
                "family",
                "function",
                "kind",
                "main_call_site_sha256s",
            },
            code="P3_AUDIT_SHAPE",
            label=f"production_population.audits[{index}]",
        )
        function_name = item["function"]
        if type(function_name) is not str or function_name not in functions:
            refuse("P3_AUDIT_FUNCTION_ABSENT", repr(function_name))
        for label in ("family", "kind"):
            if type(item[label]) is not str or not item[label]:
                refuse("P3_AUDIT_SHAPE", f"index={index} field={label}")
        observed = ast_sha256(functions[function_name])
        if observed != item["definition_sha256"]:
            refuse(
                "P3_AUDIT_DEFINITION_DRIFT",
                f"function={function_name} expected={item['definition_sha256']} observed={observed}",
            )
        expected_sites = item["main_call_site_sha256s"]
        if type(expected_sites) is not list or not expected_sites:
            refuse("P3_AUDIT_SHAPE", f"function={function_name} main call sites")
        for site_index, site_digest in enumerate(expected_sites):
            require_sha256(
                site_digest,
                code="P3_AUDIT_SHAPE",
                label=f"{function_name}.main_call_site_sha256s[{site_index}]",
            )
        callee = structural_ast_dump(ast.Name(id=function_name, ctx=ast.Load()))
        observed_sites = sorted(
            item["structural_sha256"]
            for item in inventory
            if item["owner"] == "main" and item["callee"] == callee
        )
        if observed_sites != expected_sites:
            refuse(
                "P3_AUDIT_CALL_SITE_DRIFT",
                f"function={function_name} expected={expected_sites!r} observed={observed_sites!r}",
            )
        pairs.append((item["family"], item["kind"]))

    if len(inventory) != value["reachable_call_site_count"]:
        refuse(
            "P3_CALL_POPULATION_COUNT_DRIFT",
            f"expected={value['reachable_call_site_count']} observed={len(inventory)}",
        )
    if observed_owner_count != value["reachable_owner_count"]:
        refuse(
            "P3_OWNER_POPULATION_COUNT_DRIFT",
            f"expected={value['reachable_owner_count']} observed={observed_owner_count}",
        )
    if observed_inventory_digest != value["reachable_call_sites_sha256"]:
        refuse(
            "P3_CALL_POPULATION_DRIFT",
            f"expected={value['reachable_call_sites_sha256']} observed={observed_inventory_digest}",
        )

    if len(pairs) != len(set(pairs)):
        refuse("P3_DUPLICATE_AUDIT_PAIR", repr(pairs))

    registry_pairs = sorted(
        {(row["artifact_family"], row["audit_kind"]) for row in registry_rows(tree)}
    )
    if sorted(pairs) != registry_pairs:
        refuse(
            "P3_REGISTRY_JOIN_MISMATCH",
            f"p3_only={sorted(set(pairs) - set(registry_pairs))!r} "
            f"registry_only={sorted(set(registry_pairs) - set(pairs))!r}",
        )
    if len(registry_pairs) != value["registry_pair_count"]:
        refuse(
            "P3_REGISTRY_PAIR_COUNT",
            f"expected={value['registry_pair_count']} observed={len(registry_pairs)}",
        )
    # Identity is checked after the structural authorities so a controlled
    # population/history mutation receives the narrow refusal that identified
    # it.  Source drift that changes no enumerated authority still fails here.
    if observed_gate != expected_gate:
        refuse(
            "P3_AUTHORITY_SOURCE_DRIFT",
            f"expected={expected_gate} observed={observed_gate}",
        )
    return {
        "audit_count": len(audits),
        "reachable_call_site_count": len(inventory),
        "reachable_call_sites_sha256": observed_inventory_digest,
        "reachable_owner_count": observed_owner_count,
        "registry_pair_count": len(registry_pairs),
    }


def verify_candidate_lane_census(value: dict[str, Any]) -> dict[str, int]:
    require_closed_object(
        value,
        {
            "conflicts",
            "enumeration_method",
            "gate_started_count",
            "lane_execution_count",
            "lanes",
            "limitations",
            "population_definition",
            "schema",
        },
        code="EVIDENCE_CENSUS_SHAPE",
        label="candidate lane census",
    )
    if value["schema"] != "kilix.content.f100-u1-r16-candidate-lane-census/v1":
        refuse("EVIDENCE_CENSUS_SCHEMA", repr(value["schema"]))
    for label in ("enumeration_method", "limitations"):
        rows = value[label]
        if type(rows) is not list or not rows or any(
            type(row) is not str or not row for row in rows
        ):
            refuse("EVIDENCE_CENSUS_SHAPE", f"{label} is not a nonempty text list")
    if type(value["population_definition"]) is not str or not value["population_definition"]:
        refuse("EVIDENCE_CENSUS_SHAPE", "population_definition is absent")

    lanes = value["lanes"]
    if type(lanes) is not list:
        refuse("EVIDENCE_CENSUS_SHAPE", "lanes is not a list")
    run_ids: list[str] = []
    for index, lane in enumerate(lanes):
        item = require_closed_object(
            lane,
            {
                "candidate_commit",
                "disposition",
                "experiment_id",
                "gate_started",
                "lane",
                "rc",
                "run_id",
            },
            code="EVIDENCE_CENSUS_LANE_SHAPE",
            label=f"candidate lane census.lanes[{index}]",
        )
        for label in ("disposition", "experiment_id", "lane", "run_id"):
            if type(item[label]) is not str or not item[label]:
                refuse("EVIDENCE_CENSUS_LANE_SHAPE", f"index={index} field={label}")
        if re.fullmatch(r"[0-9a-f]{40}", item["candidate_commit"] or "") is None:
            refuse("EVIDENCE_CENSUS_LANE_SHAPE", f"index={index} candidate_commit")
        if type(item["gate_started"]) is not bool:
            refuse("EVIDENCE_CENSUS_LANE_SHAPE", f"index={index} gate_started")
        if item["rc"] is not None and type(item["rc"]) is not int:
            refuse("EVIDENCE_CENSUS_LANE_SHAPE", f"index={index} rc")
        disposition = item["disposition"]
        if disposition not in LANE_DISPOSITION_STATES:
            refuse(
                "EVIDENCE_LANE_DISPOSITION_UNKNOWN",
                f"run_id={item['run_id']!r} disposition={disposition!r}",
            )
        expected_gate_started, expected_rc = LANE_DISPOSITION_STATES[disposition]
        observed_state = (item["gate_started"], item["rc"])
        if observed_state != (expected_gate_started, expected_rc):
            refuse(
                "EVIDENCE_LANE_DISPOSITION_CONTRADICTION",
                f"run_id={item['run_id']!r} disposition={disposition!r} "
                f"expected={(expected_gate_started, expected_rc)!r} "
                f"observed={observed_state!r}",
            )
        run_ids.append(item["run_id"])
    if len(run_ids) != len(set(run_ids)):
        refuse("EVIDENCE_CENSUS_DUPLICATE_RUN_ID", repr(run_ids))
    if type(value["lane_execution_count"]) is not int or value["lane_execution_count"] != len(lanes):
        refuse("EVIDENCE_CENSUS_COUNT", repr(value["lane_execution_count"]))
    gate_started = sum(item["gate_started"] for item in lanes)
    if type(value["gate_started_count"]) is not int or value["gate_started_count"] != gate_started:
        refuse("EVIDENCE_GATE_STARTED_COUNT", f"observed={gate_started}")

    conflicts = value["conflicts"]
    if type(conflicts) is not list:
        refuse("EVIDENCE_CENSUS_CONFLICT_SHAPE", "conflicts is not a list")
    conflict_ids: list[str] = []
    for index, conflict in enumerate(conflicts):
        item = require_closed_object(
            conflict,
            {
                "census_value",
                "conflict_id",
                "disposition",
                "transcript_claim",
                "transcript_lines",
            },
            code="EVIDENCE_CENSUS_CONFLICT_SHAPE",
            label=f"candidate lane census.conflicts[{index}]",
        )
        if any(type(field) is not str or not field for field in item.values()):
            refuse("EVIDENCE_CENSUS_CONFLICT_SHAPE", f"index={index}")
        conflict_ids.append(item["conflict_id"])
    if len(conflict_ids) != len(set(conflict_ids)):
        refuse("EVIDENCE_CENSUS_CONFLICT_DUPLICATE", repr(conflict_ids))
    arm12 = [item for item in lanes if item["run_id"] == "arm12"]
    if (
        len(arm12) != 1
        or arm12[0]["rc"] is not None
        or "arm12-exit-status" not in conflict_ids
    ):
        refuse(
            "EVIDENCE_ARM12_CONFLICT_UNRECORDED",
            "arm12 must remain rc=null with the transcript conflict explicit",
        )
    return {
        "candidate_lane_execution_count": len(lanes),
        "evidence_conflict_count": len(conflicts),
        "gate_started_count": gate_started,
        "lane_semantic_binding_count": len(lanes),
    }


def verify_pair_case(value: Any, *, label: str) -> dict[str, Any]:
    item = require_closed_object(
        value,
        {
            "case",
            "control_role",
            "expected_exit_code",
            "expected_terminal_fragment",
            "forbidden_terminal_fragment",
            "mutation_json_sha256",
            "output_gate_sha256",
            "patch_sha256",
            "preserved_condition",
            "removed_condition",
        },
        code="EVIDENCE_PAIR_CASE_SHAPE",
        label=label,
    )
    for key in (
        "case",
        "control_role",
        "expected_terminal_fragment",
        "forbidden_terminal_fragment",
        "preserved_condition",
        "removed_condition",
    ):
        if type(item[key]) is not str or not item[key]:
            refuse("EVIDENCE_PAIR_CASE_SHAPE", f"{label}.{key}")
    if type(item["expected_exit_code"]) is not int:
        refuse("EVIDENCE_PAIR_CASE_SHAPE", f"{label}.expected_exit_code")
    for key in ("mutation_json_sha256", "output_gate_sha256", "patch_sha256"):
        require_sha256(
            item[key],
            code="EVIDENCE_PAIR_CASE_SHAPE",
            label=f"{label}.{key}",
        )
    return item


def verify_pair_plan(value: dict[str, Any]) -> dict[str, int]:
    require_closed_object(
        value,
        {"cases", "enumeration", "input", "schema", "status"},
        code="EVIDENCE_PAIR_PLAN_SHAPE",
        label="R15-3 pair plan",
    )
    if value["schema"] != "kilix.content.f100-u1-r16-r15-3-pair-plan/v1":
        refuse("EVIDENCE_PAIR_PLAN_SCHEMA", repr(value["schema"]))
    if value["status"] != "PRE_REGISTERED_NOT_RUN":
        refuse("EVIDENCE_PAIR_PLAN_STATUS", repr(value["status"]))
    enumeration = require_closed_object(
        value["enumeration"],
        {"case_count", "method"},
        code="EVIDENCE_PAIR_PLAN_SHAPE",
        label="R15-3 pair plan.enumeration",
    )
    cases = value["cases"]
    if (
        type(cases) is not list
        or type(enumeration["case_count"]) is not int
        or enumeration["case_count"] != len(cases)
        or len(cases) != 2
        or type(enumeration["method"]) is not str
        or not enumeration["method"]
    ):
        refuse("EVIDENCE_PAIR_PLAN_COUNT", repr(enumeration.get("case_count")))
    parsed = [
        verify_pair_case(case, label=f"R15-3 pair plan.cases[{index}]")
        for index, case in enumerate(cases)
    ]
    if {case["control_role"] for case in parsed} != {"necessity", "sufficiency"}:
        refuse("EVIDENCE_PAIR_PLAN_ROLES", repr([case["control_role"] for case in parsed]))
    if {case["case"] for case in parsed} != {
        "audit-present-label-absent",
        "hollow-label-present",
    }:
        refuse("EVIDENCE_PAIR_PLAN_CASES", repr([case["case"] for case in parsed]))
    plan_input = require_closed_object(
        value["input"],
        {"candidate_commit", "candidate_tree", "gate_path", "gate_sha256"},
        code="EVIDENCE_PAIR_PLAN_SHAPE",
        label="R15-3 pair plan.input",
    )
    for key in ("candidate_commit", "candidate_tree"):
        if (
            type(plan_input[key]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", plan_input[key]) is None
        ):
            refuse("EVIDENCE_PAIR_PLAN_INPUT", key)
    require_sha256(
        plan_input["gate_sha256"],
        code="EVIDENCE_PAIR_PLAN_INPUT",
        label="gate_sha256",
    )
    if plan_input["gate_path"] != GATE_PATH.as_posix():
        refuse("EVIDENCE_PAIR_PLAN_INPUT", repr(plan_input["gate_path"]))
    return {"pair_obligation_count": len(cases)}


def verify_pair_plan_amendment(
    value: dict[str, Any],
    *,
    initial_plan_sha256: str,
) -> dict[str, int]:
    require_closed_object(
        value,
        {
            "amends_plan_sha256",
            "discarded_execution",
            "replacement_case",
            "schema",
            "status",
        },
        code="EVIDENCE_PAIR_AMENDMENT_SHAPE",
        label="R15-3 pair plan amendment",
    )
    if value["schema"] != "kilix.content.f100-u1-r16-r15-3-pair-plan-amendment/v1":
        refuse("EVIDENCE_PAIR_AMENDMENT_SCHEMA", repr(value["schema"]))
    if value["status"] != "PRE_REGISTERED_NOT_RUN":
        refuse("EVIDENCE_PAIR_AMENDMENT_STATUS", repr(value["status"]))
    if value["amends_plan_sha256"] != initial_plan_sha256:
        refuse(
            "EVIDENCE_PAIR_AMENDMENT_PARENT",
            f"expected={initial_plan_sha256} observed={value['amends_plan_sha256']}",
        )
    discarded = require_closed_object(
        value["discarded_execution"],
        {
            "case",
            "disposition",
            "end_utc",
            "exit_code",
            "log_sha256",
            "reason",
            "start_utc",
            "terminal_fragment",
        },
        code="EVIDENCE_PAIR_AMENDMENT_SHAPE",
        label="R15-3 pair plan amendment.discarded_execution",
    )
    if discarded["disposition"] != "INVALID_MUTATION_CONSTRUCTION" or discarded["exit_code"] != 1:
        refuse("EVIDENCE_PAIR_AMENDMENT_DISCARD", repr(discarded))
    require_sha256(
        discarded["log_sha256"],
        code="EVIDENCE_PAIR_AMENDMENT_SHAPE",
        label="discarded_execution.log_sha256",
    )
    replacement = verify_pair_case(
        value["replacement_case"],
        label="R15-3 pair plan amendment.replacement_case",
    )
    if replacement["case"] != "audit-present-label-absent-v2":
        refuse("EVIDENCE_PAIR_AMENDMENT_REPLACEMENT", repr(replacement["case"]))
    return {"pair_discarded_execution_count": 1, "pair_replacement_count": 1}


def read_pinned_evidence(
    authority_root: Path,
    value: Any,
    *,
    label: str,
) -> tuple[bytes, str]:
    item = require_closed_object(
        value,
        {"bytes", "path", "sha256"},
        code="EVIDENCE_AUTHORITY_SHAPE",
        label=label,
    )
    if type(item["path"]) is not str:
        refuse("EVIDENCE_PATH", f"{label}: path is not text")
    relative = Path(item["path"])
    if relative.is_absolute() or ".." in relative.parts:
        refuse("EVIDENCE_PATH", repr(item["path"]))
    path = authority_root / relative
    try:
        raw = path.read_bytes()
    except OSError as exc:
        refuse("EVIDENCE_UNREADABLE", f"{path}: {exc}")
    expected_digest = require_sha256(
        item["sha256"],
        code="EVIDENCE_AUTHORITY_SHAPE",
        label=f"{label}.sha256",
    )
    if type(item["bytes"]) is not int or item["bytes"] < 0:
        refuse("EVIDENCE_AUTHORITY_SHAPE", f"{label}.bytes")
    if len(raw) != item["bytes"] or sha256_bytes(raw) != expected_digest:
        refuse(
            "EVIDENCE_DIGEST_MISMATCH",
            f"label={label} bytes={len(raw)} sha256={sha256_bytes(raw)}",
        )
    return raw, expected_digest


def verify_pair_results(
    authority_root: Path,
    value: dict[str, Any],
    *,
    initial_plan: dict[str, Any],
    initial_plan_sha256: str,
    amendment: dict[str, Any],
    amendment_sha256: str,
) -> dict[str, int]:
    require_closed_object(
        value,
        {"executions", "obligation_population", "plan_pins", "schema", "status"},
        code="EVIDENCE_PAIR_RESULTS_SHAPE",
        label="R15-3 pair results",
    )
    if value["schema"] != "kilix.content.f100-u1-r16-r15-3-pair-results/v1":
        refuse("EVIDENCE_PAIR_RESULTS_SCHEMA", repr(value["schema"]))
    if value["status"] != "BUILDER_OBSERVED_NOT_GRADED":
        refuse("EVIDENCE_PAIR_RESULTS_STATUS", repr(value["status"]))
    plan_pins = require_closed_object(
        value["plan_pins"],
        {"amendment_1_sha256", "initial_sha256"},
        code="EVIDENCE_PAIR_RESULTS_SHAPE",
        label="R15-3 pair results.plan_pins",
    )
    if plan_pins != {
        "amendment_1_sha256": amendment_sha256,
        "initial_sha256": initial_plan_sha256,
    }:
        refuse("EVIDENCE_PAIR_RESULTS_PLAN_PINS", repr(plan_pins))
    population = require_closed_object(
        value["obligation_population"],
        {"count", "enumeration_method", "necessity_case", "sufficiency_case"},
        code="EVIDENCE_PAIR_RESULTS_SHAPE",
        label="R15-3 pair results.obligation_population",
    )
    if (
        population["count"] != 2
        or population["necessity_case"] != "hollow-label-present"
        or population["sufficiency_case"] != "audit-present-label-absent-v2"
        or type(population["enumeration_method"]) is not str
        or not population["enumeration_method"]
    ):
        refuse("EVIDENCE_PAIR_RESULTS_POPULATION", repr(population))

    planned = {case["case"]: case for case in initial_plan["cases"]}
    replacement = amendment["replacement_case"]
    planned[replacement["case"]] = replacement
    executions = value["executions"]
    if type(executions) is not list or len(executions) != 3:
        refuse("EVIDENCE_PAIR_RESULTS_COUNT", repr(len(executions)))
    cases: list[str] = []
    matched = 0
    discarded = 0
    expected_dispositions = {
        "audit-present-label-absent": "INVALID_MUTATION_CONSTRUCTION",
        "audit-present-label-absent-v2": "EXPECTED_SUFFICIENCY_PASS_OBSERVED",
        "hollow-label-present": "EXPECTED_NECESSITY_REFUSAL_OBSERVED",
    }
    for index, execution in enumerate(executions):
        item = require_closed_object(
            execution,
            {
                "case",
                "control_role",
                "disposition",
                "end_utc",
                "exit_code",
                "expected_exit_code",
                "expected_outcome_observed",
                "gate_log",
                "mutation_json",
                "output_gate_sha256",
                "patch",
                "start_utc",
                "terminal_fragment",
            },
            code="EVIDENCE_PAIR_RESULT_SHAPE",
            label=f"R15-3 pair results.executions[{index}]",
        )
        case = item["case"]
        if type(case) is not str or case not in planned:
            refuse("EVIDENCE_PAIR_RESULT_CASE", repr(case))
        cases.append(case)
        expected = planned[case]
        if (
            item["control_role"] != expected["control_role"]
            or item["expected_exit_code"] != expected["expected_exit_code"]
            or item["output_gate_sha256"] != expected["output_gate_sha256"]
            or item["disposition"] != expected_dispositions[case]
        ):
            refuse("EVIDENCE_PAIR_RESULT_PLAN_DRIFT", case)
        if type(item["exit_code"]) is not int or type(item["expected_outcome_observed"]) is not bool:
            refuse("EVIDENCE_PAIR_RESULT_SHAPE", f"{case}: exit/outcome")
        outcome_matches = item["exit_code"] == item["expected_exit_code"]
        if item["expected_outcome_observed"] != outcome_matches:
            refuse("EVIDENCE_PAIR_RESULT_OUTCOME", case)
        if outcome_matches:
            matched += 1
        if item["disposition"] == "INVALID_MUTATION_CONSTRUCTION":
            discarded += 1
        for key in ("start_utc", "end_utc", "terminal_fragment", "disposition"):
            if type(item[key]) is not str or not item[key]:
                refuse("EVIDENCE_PAIR_RESULT_SHAPE", f"{case}: {key}")
        require_sha256(
            item["output_gate_sha256"],
            code="EVIDENCE_PAIR_RESULT_SHAPE",
            label=f"{case}.output_gate_sha256",
        )

        log_raw, _ = read_pinned_evidence(
            authority_root,
            item["gate_log"],
            label=f"R15-3 pair results.{case}.gate_log",
        )
        try:
            log_text = log_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            refuse("EVIDENCE_PAIR_RESULT_LOG_ENCODING", f"{case}: {exc}")
        if item["terminal_fragment"] not in log_text:
            refuse("EVIDENCE_PAIR_RESULT_TERMINAL_ABSENT", case)
        if (
            case != "audit-present-label-absent"
            and item["terminal_fragment"] != expected["expected_terminal_fragment"]
        ):
            refuse("EVIDENCE_PAIR_RESULT_TERMINAL_DRIFT", case)
        forbidden = expected["forbidden_terminal_fragment"]
        if forbidden in log_text:
            refuse(
                "EVIDENCE_PAIR_RESULT_FORBIDDEN_FRAGMENT",
                f"case={case!r} fragment={forbidden!r}",
            )
        if "Traceback" in log_text:
            refuse("EVIDENCE_PAIR_RESULT_TRACEBACK", f"case={case!r}")
        terminal_count = log_text.count(item["terminal_fragment"])
        if terminal_count != 1:
            refuse(
                "EVIDENCE_PAIR_RESULT_TERMINAL_COUNT",
                f"case={case!r} count={terminal_count}",
            )
        nonempty_lines = [line for line in log_text.splitlines() if line.strip()]
        if not nonempty_lines or nonempty_lines[-1] != item["terminal_fragment"]:
            refuse(
                "EVIDENCE_PAIR_RESULT_TERMINAL_NOT_FINAL",
                f"case={case!r}",
            )

        mutation_raw, mutation_digest = read_pinned_evidence(
            authority_root,
            item["mutation_json"],
            label=f"R15-3 pair results.{case}.mutation_json",
        )
        try:
            mutation = json.loads(mutation_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            refuse("EVIDENCE_PAIR_RESULT_MUTATION", f"{case}: {exc}")
        if type(mutation) is not dict or mutation_raw != canonical_json(mutation):
            refuse("EVIDENCE_PAIR_RESULT_MUTATION", f"{case}: not canonical")
        if (
            mutation.get("schema") != "kilix.content.f100-u1-r16-r15-3-mutation/v1"
            or mutation.get("case") != case
            or mutation.get("before_gate_sha256")
            != initial_plan["input"]["gate_sha256"]
            or mutation.get("after_gate_sha256") != item["output_gate_sha256"]
            or mutation_digest != expected["mutation_json_sha256"]
        ):
            refuse("EVIDENCE_PAIR_RESULT_MUTATION", case)
        _, patch_digest = read_pinned_evidence(
            authority_root,
            item["patch"],
            label=f"R15-3 pair results.{case}.patch",
        )
        if patch_digest != expected["patch_sha256"]:
            refuse("EVIDENCE_PAIR_RESULT_PATCH", case)

    if len(cases) != len(set(cases)) or set(cases) != set(planned):
        refuse("EVIDENCE_PAIR_RESULTS_CASE_SET", repr(cases))
    if matched != 2 or discarded != 1:
        refuse(
            "EVIDENCE_PAIR_RESULTS_DISPOSITION_COUNT",
            f"matched={matched} discarded={discarded}",
        )
    invalid = next(item for item in executions if item["case"] == "audit-present-label-absent")
    if (
        invalid["disposition"] != "INVALID_MUTATION_CONSTRUCTION"
        or invalid["terminal_fragment"]
        != amendment["discarded_execution"]["terminal_fragment"]
        or invalid["gate_log"]["sha256"]
        != amendment["discarded_execution"]["log_sha256"]
    ):
        refuse("EVIDENCE_PAIR_RESULTS_DISCARD_DRIFT", repr(invalid))
    return {
        "pair_discarded_execution_count": discarded,
        "pair_execution_count": len(executions),
        "pair_expected_outcome_count": matched,
        "pair_log_semantic_check_count": len(executions),
    }


def verify_evidence(authority_root: Path, evidence: Any) -> dict[str, Any]:
    value = require_closed_object(
        evidence,
        {
            "candidate_lane_census",
            "mutation_transcript",
            "r15_3_pair_plan",
            "r15_3_pair_plan_amendment_1",
            "r15_3_pair_results",
        },
        code="EVIDENCE_AUTHORITY_SHAPE",
        label="evidence",
    )
    observed: dict[str, Any] = {}
    parsed_evidence: dict[str, dict[str, Any]] = {}
    for label in (
        "candidate_lane_census",
        "mutation_transcript",
        "r15_3_pair_plan",
        "r15_3_pair_plan_amendment_1",
        "r15_3_pair_results",
    ):
        raw, expected_digest = read_pinned_evidence(
            authority_root,
            value[label],
            label=f"evidence.{label}",
        )
        if label == "candidate_lane_census":
            try:
                parsed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                refuse("EVIDENCE_CENSUS_NOT_CANONICAL", str(exc))
            if type(parsed) is not dict or raw != canonical_json(parsed):
                refuse("EVIDENCE_CENSUS_NOT_CANONICAL", label)
            observed.update(verify_candidate_lane_census(parsed))
        elif label != "mutation_transcript":
            try:
                parsed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                refuse("EVIDENCE_PAIR_NOT_CANONICAL", str(exc))
            if type(parsed) is not dict or raw != canonical_json(parsed):
                refuse("EVIDENCE_PAIR_NOT_CANONICAL", label)
            parsed_evidence[label] = parsed
        observed[f"{label}_sha256"] = expected_digest
    observed.update(verify_pair_plan(parsed_evidence["r15_3_pair_plan"]))
    observed.update(
        verify_pair_plan_amendment(
            parsed_evidence["r15_3_pair_plan_amendment_1"],
            initial_plan_sha256=observed["r15_3_pair_plan_sha256"],
        )
    )
    observed.update(
        verify_pair_results(
            authority_root,
            parsed_evidence["r15_3_pair_results"],
            initial_plan=parsed_evidence["r15_3_pair_plan"],
            initial_plan_sha256=observed["r15_3_pair_plan_sha256"],
            amendment=parsed_evidence["r15_3_pair_plan_amendment_1"],
            amendment_sha256=observed["r15_3_pair_plan_amendment_1_sha256"],
        )
    )
    return observed


def verify(arguments: argparse.Namespace) -> dict[str, Any]:
    candidate_root = Path(arguments.candidate_root)
    authority_root = Path(arguments.authority_root)
    verify_external_roots(candidate_root, authority_root)
    authority_path = authority_root / AUTHORITY_NAME
    authority, authority_raw = load_canonical_object(
        authority_path, code="AUTHORITY_NOT_CANONICAL"
    )
    expected_authority = require_sha256(
        arguments.authority_sha256,
        code="AUTHORITY_PIN_INVALID",
        label="--authority-sha256",
    )
    observed_authority = sha256_bytes(authority_raw)
    if observed_authority != expected_authority:
        refuse(
            "AUTHORITY_PIN_MISMATCH",
            f"expected={expected_authority} observed={observed_authority}",
        )
    validate_authority_shape(authority)
    implementation = verify_implementation(authority["implementation"])
    gate = candidate_root / GATE_PATH
    try:
        gate_raw = gate.read_bytes()
    except OSError as exc:
        refuse("CANDIDATE_GATE_UNREADABLE", f"{gate}: {exc}")
    tree = parse_gate(gate_raw, gate)
    history = verify_history(tree, authority["history"])
    population = verify_population(
        tree,
        gate_raw,
        authority["candidate"],
        authority["production_population"],
    )
    evidence = verify_evidence(authority_root, authority["evidence"])
    return {
        "authority_sha256": observed_authority,
        "candidate_gate_sha256": sha256_bytes(gate_raw),
        "evidence": evidence,
        "history": history,
        "implementation": implementation,
        "population": population,
        "schema": RESULT_SCHEMA,
        "status": "VERIFIED_NOT_GRADED",
    }


def inventory(arguments: argparse.Namespace) -> list[dict[str, Any]]:
    gate = Path(arguments.candidate_root) / GATE_PATH
    try:
        raw = gate.read_bytes()
    except OSError as exc:
        refuse("CANDIDATE_GATE_UNREADABLE", f"{gate}: {exc}")
    return derive_call_inventory(parse_gate(raw, gate), arguments.entrypoint)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--candidate-root", required=True)
    verify_parser.add_argument("--authority-root", required=True)
    verify_parser.add_argument("--authority-sha256", required=True)
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("--candidate-root", required=True)
    inventory_parser.add_argument("--entrypoint", default="main")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "verify":
            result: Any = verify(arguments)
        else:
            result = inventory(arguments)
    except AuthorityRefusal as exc:
        result = {
            "code": exc.code,
            "detail": exc.detail,
            "schema": RESULT_SCHEMA,
            "status": "REFUSED",
        }
        sys.stdout.buffer.write(canonical_json(result))
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
