#!/usr/bin/env python3
"""Create R16 history/P3 controls in an exact disposable candidate export."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any, NoReturn


EXPECTED_GATE_SHA256 = "14e141c39f081bedc4af20d304dccf0e3d4b8d66eebf9906c7fb75e7b08b44fd"
SCHEMA = "kilix.content.f100-u1-r16-authority-mutation/v1"
HISTORY_CASES = (
    "history-old-r14-row-removed",
    "history-new-r15-row-removed",
    "history-row-reordered",
    "history-row-aliased",
    "history-duplicate-id",
    "history-same-id-semantics",
    "history-executor-noop",
)
P3_CASES = ("p3-audit-unreachable-label-retained", "p3-assignment-absent-audit-retained")
P3_AUDITS = {
    "assert_sdist_enumerator_agreement": ("sdist", "enumerator"),
    "installed_wheel_audit": ("wheel", "installed"),
    "record_audit": ("wheel", "record"),
    "resource_audit": ("wheel", "resource-authority"),
    "sdist_container_audit": ("sdist", "container"),
    "sdist_generated_metadata_audit": ("sdist", "generated-metadata"),
    "sdist_member_closure_audit": ("sdist", "closure"),
    "sdist_payload_audit": ("sdist", "payload"),
    "wheel_archive_audit": ("wheel", "archive"),
    "wheel_container_audit": ("wheel", "container"),
    "wheel_module_source_audit": ("wheel", "module"),
    "wheel_resource_audit": ("wheel", "resource"),
}


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


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def assignment(tree: ast.Module, name: str) -> ast.Assign | ast.AnnAssign:
    matches: list[ast.Assign | ast.AnnAssign] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            matches.append(node)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            matches.append(node)
    if len(matches) != 1:
        fail(f"{name}: assignment count={len(matches)}")
    return matches[0]


def assignment_value(node: ast.Assign | ast.AnnAssign) -> ast.expr:
    if node.value is None:
        fail("assignment value is absent")
    return node.value


def registry(tree: ast.Module) -> list[dict[str, str]]:
    value = ast.literal_eval(assignment_value(assignment(tree, "PROPERTY_MUTATION_REGISTRY")))
    if type(value) not in {list, tuple} or any(type(row) is not dict for row in value):
        fail("registry is not a literal sequence of objects")
    return [dict(row) for row in value]


def set_assignment(tree: ast.Module, name: str, value: ast.expr) -> None:
    assignment(tree, name).value = value


def literal(value: Any) -> ast.expr:
    return ast.parse(repr(value), mode="eval").body


def frozen_set_items(value: ast.expr) -> set[str]:
    if (
        not isinstance(value, ast.Call)
        or not isinstance(value.func, ast.Name)
        or value.func.id != "frozenset"
        or len(value.args) != 1
        or value.keywords
    ):
        fail("required row IDs are not a one-argument frozenset")
    items = ast.literal_eval(value.args[0])
    if type(items) not in {set, list, tuple} or any(type(item) is not str for item in items):
        fail("required row IDs are not a literal text collection")
    return set(items)


def restate_candidate_anchors(
    tree: ast.Module,
    rows: list[dict[str, str]],
    *,
    replace_required_id: tuple[str, str] | None = None,
) -> None:
    set_assignment(tree, "PROPERTY_MUTATION_REGISTRY", literal(tuple(rows)))
    set_assignment(
        tree,
        "FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256",
        ast.Constant(digest(canonical_json(rows, newline=False))),
    )
    set_assignment(tree, "FROZEN_MINIMUM_ROW_COUNT", ast.Constant(len(rows)))
    if replace_required_id is None:
        required = {row["id"] for row in rows}
    else:
        old, new = replace_required_id
        current = frozen_set_items(
            assignment_value(assignment(tree, "FROZEN_REQUIRED_ROW_IDS"))
        )
        required = {new if item == old else item for item in current}
    set_assignment(tree, "FROZEN_REQUIRED_ROW_IDS", literal(frozenset(required)))


def remove_decorator_and_hollow(tree: ast.Module, function_name: str) -> None:
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    ]
    if len(matches) != 1:
        fail(f"{function_name}: definition count={len(matches)}")
    function = matches[0]
    before = len(function.decorator_list)
    function.decorator_list = [
        decorator
        for decorator in function.decorator_list
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "records_audit_effect"
        )
    ]
    if len(function.decorator_list) != before - 1:
        fail(f"{function_name}: records_audit_effect decorator was not unique")
    function.body = [ast.Return(ast.Constant(None))]


def remove_production_audit_definition(tree: ast.Module, target: str) -> int:
    """Make the named audit absent while retaining its calls and assignment."""
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == target
    ]
    if len(matches) != 1:
        fail(f"{target}: definition count={len(matches)}")
    matches[0].name = target + "_removed_by_r16_control"
    return 1


class ExecutorNoop(ast.NodeTransformer):
    def __init__(self) -> None:
        self.in_executor = False
        self.replacements = 0

    def visit_FunctionDef(self, node: ast.FunctionDef):  # noqa: N802 - AST API name
        previous = self.in_executor
        if not previous:
            self.in_executor = node.name == "run_property_mutation_registry"
        self.generic_visit(node)
        self.in_executor = previous
        return node

    def visit_Call(self, node: ast.Call):  # noqa: N802 - AST API name
        self.generic_visit(node)
        if (
            self.in_executor
            and isinstance(node.func, ast.Name)
            and node.func.id == "rewrite_sdist_with_gzip_trailing_bytes"
        ):
            self.replacements += 1
            node.func = ast.Attribute(
                value=ast.Name("shutil", ast.Load()),
                attr="copy2",
                ctx=ast.Load(),
            )
        return node


def history_mutation(tree: ast.Module, case: str) -> dict[str, Any]:
    rows = registry(tree)
    before = len(rows)
    if case in {"history-old-r14-row-removed", "history-new-r15-row-removed"}:
        target = (
            "wheel.container.trailing"
            if case == "history-old-r14-row-removed"
            else "wheel.module.source-byte"
        )
        rows = [row for row in rows if row["id"] != target]
        if len(rows) != before - 1:
            fail(f"{case}: target row count was not one")
        restate_candidate_anchors(tree, rows)
        if case == "history-new-r15-row-removed":
            remove_decorator_and_hollow(tree, "wheel_module_source_audit")
        return {"registry_after": len(rows), "registry_before": before, "target": target}
    if case == "history-row-reordered":
        rows[0], rows[1] = rows[1], rows[0]
        restate_candidate_anchors(tree, rows)
    elif case == "history-row-aliased":
        old = rows[0]["id"]
        rows[0]["id"] = old + "-alias"
        restate_candidate_anchors(tree, rows, replace_required_id=(old, rows[0]["id"]))
    elif case == "history-duplicate-id":
        rows.append(dict(rows[0]))
        restate_candidate_anchors(tree, rows)
    elif case == "history-same-id-semantics":
        rows[0]["property"] = "restated semantics"
        restate_candidate_anchors(tree, rows)
    elif case == "history-executor-noop":
        transformer = ExecutorNoop()
        transformer.visit(tree)
        if transformer.replacements != 1:
            fail(f"history-executor-noop: replacements={transformer.replacements}")
    else:
        fail(f"unknown history case: {case}")
    return {"registry_after": len(registry(tree)), "registry_before": before, "target": None}


def p3_mutation(tree: ast.Module, case: str, audit: str) -> dict[str, Any]:
    if audit not in P3_AUDITS:
        fail(f"unknown P3 audit: {audit}")
    family, kind = P3_AUDITS[audit]
    before = len(registry(tree))
    if case == "p3-audit-unreachable-label-retained":
        replacements = remove_production_audit_definition(tree, audit)
    elif case == "p3-assignment-absent-audit-retained":
        rows = [
            row
            for row in registry(tree)
            if (row["artifact_family"], row["audit_kind"]) != (family, kind)
        ]
        if len(rows) == before:
            fail(f"{audit}: no assignment was removed")
        set_assignment(tree, "PROPERTY_MUTATION_REGISTRY", literal(tuple(rows)))
        replacements = before - len(rows)
    else:
        fail(f"unknown P3 case: {case}")
    return {
        "audit": audit,
        "family": family,
        "kind": kind,
        "registry_after": len(registry(tree)),
        "registry_before": before,
        "replacements": replacements,
    }


def verify_disposable_gate(path: Path) -> bytes:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"gate is not readable: {exc}")
    root = resolved.parents[1]
    if (root / ".git").exists():
        fail(f"refusing to mutate a Git worktree: {root}")
    raw = resolved.read_bytes()
    observed = digest(raw)
    if observed != EXPECTED_GATE_SHA256:
        fail(
            "input gate identity differs: "
            f"expected={EXPECTED_GATE_SHA256} observed={observed}"
        )
    return raw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--case", choices=(*HISTORY_CASES, *P3_CASES), required=True)
    parser.add_argument("--audit", choices=sorted(P3_AUDITS))
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    path = Path(arguments.gate)
    before = verify_disposable_gate(path)
    tree = ast.parse(before)
    if arguments.case in HISTORY_CASES:
        if arguments.audit is not None:
            fail("--audit is valid only for a P3 case")
        detail = history_mutation(tree, arguments.case)
    else:
        if arguments.audit is None:
            fail("P3 cases require --audit")
        detail = p3_mutation(tree, arguments.case, arguments.audit)
    ast.fix_missing_locations(tree)
    after = (ast.unparse(tree) + "\n").encode("utf-8")
    path.write_bytes(after)
    result = {
        "after_gate_sha256": digest(after),
        "before_gate_sha256": digest(before),
        "case": arguments.case,
        "detail": detail,
        "schema": SCHEMA,
    }
    print(canonical_json(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
