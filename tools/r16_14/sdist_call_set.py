#!/usr/bin/env python3
"""Enumerate and verify R16-14 sdist audit calls without executing the subject.

This module is deliberately a leaf.  It parses the requested gate source as
data, compares the observed call topology with a separately supplied ledger,
and can verify a separately captured runtime-effect trace.  It does not import
the gate, modify the gate, or install itself into the release path.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, NoReturn


SCHEMA_VERSION = "r16-14-sdist-call-ledger-v1"
TRACE_SCHEMA_VERSION = "r16-14-sdist-effect-trace-v1"
AUTHORITY_STATUSES = frozenset(
    {"candidate-mirror-not-final-authority", "external-frozen-authority"}
)
LEDGER_KEYS = frozenset(
    {
        "authority_status",
        "calls",
        "required_call_count",
        "schema_version",
        "scope",
    }
)
CALL_KEYS = frozenset(
    {
        "artifact_presentation",
        "effect_family",
        "effect_kind",
        "enclosing_function",
        "identity",
        "phase",
        "role",
        "structural_locator",
        "target_function",
    }
)
TRACE_KEYS = frozenset({"events", "schema_version"})
EVENT_KEYS = frozenset(
    {
        "artifact_presentation",
        "effect_family",
        "effect_kind",
        "identity",
        "phase",
        "target_function",
    }
)


class VerificationError(ValueError):
    """A stable refusal code suitable for gate diagnostics."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True, order=True)
class ObservedCall:
    identity: str
    enclosing_function: str
    target_function: str
    effect_family: str | None
    effect_kind: str | None
    structural_locator: str


@dataclasses.dataclass(frozen=True)
class LedgerCall:
    identity: str
    enclosing_function: str
    target_function: str
    effect_family: str
    effect_kind: str
    structural_locator: str
    artifact_presentation: str
    phase: str
    role: str


@dataclasses.dataclass(frozen=True)
class Ledger:
    authority_status: str
    required_call_count: int
    calls: tuple[LedgerCall, ...]
    canonical_bytes: bytes


def _refuse(code: str) -> NoReturn:
    raise VerificationError(code)


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse(f"SDIST_CALL_LEDGER_DUPLICATE_KEY:{key}")
        result[key] = value
    return result


def _load_canonical_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except VerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _refuse(f"SDIST_CALL_LEDGER_INVALID_JSON:{type(exc).__name__}")
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        _refuse(f"SDIST_CALL_LEDGER_INVALID_VALUE:{type(exc).__name__}")
    if raw != canonical:
        _refuse("SDIST_CALL_LEDGER_NONCANONICAL")
    return value, canonical


def _exact_keys(value: Any, expected: frozenset[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        _refuse(f"SDIST_CALL_LEDGER_TYPE:{context}")
    observed = frozenset(value)
    if observed != expected:
        missing = ",".join(sorted(expected - observed)) or "NONE"
        extra = ",".join(sorted(observed - expected)) or "NONE"
        _refuse(
            f"SDIST_CALL_LEDGER_KEYS:{context}:missing={missing}:extra={extra}"
        )
    return value


def _required_text(row: dict[str, Any], key: str, context: str) -> str:
    value = row[key]
    if type(value) is not str or not value:
        _refuse(f"SDIST_CALL_LEDGER_TYPE:{context}.{key}")
    return value


def load_ledger(path: Path) -> Ledger:
    value, canonical = _load_canonical_json(path)
    root = _exact_keys(value, LEDGER_KEYS, "root")
    if root["schema_version"] != SCHEMA_VERSION:
        _refuse("SDIST_CALL_LEDGER_SCHEMA")
    if root["scope"] != "R16-14":
        _refuse("SDIST_CALL_LEDGER_SCOPE")
    if root["authority_status"] not in AUTHORITY_STATUSES:
        _refuse("SDIST_CALL_LEDGER_AUTHORITY_STATUS")
    required_count = root["required_call_count"]
    if type(required_count) is not int or required_count < 1:
        _refuse("SDIST_CALL_LEDGER_REQUIRED_COUNT")
    rows = root["calls"]
    if type(rows) is not list:
        _refuse("SDIST_CALL_LEDGER_TYPE:calls")
    calls: list[LedgerCall] = []
    seen: set[str] = set()
    for index, candidate in enumerate(rows):
        context = f"calls[{index}]"
        row = _exact_keys(candidate, CALL_KEYS, context)
        identity = _required_text(row, "identity", context)
        if identity in seen:
            _refuse(f"SDIST_CALL_LEDGER_DUPLICATE_ID:{identity}")
        seen.add(identity)
        role = _required_text(row, "role", context)
        if role not in {"production-authority", "named-differential-control"}:
            _refuse(f"SDIST_CALL_LEDGER_ROLE:{identity}")
        calls.append(
            LedgerCall(
                identity=identity,
                enclosing_function=_required_text(
                    row, "enclosing_function", context
                ),
                target_function=_required_text(row, "target_function", context),
                effect_family=_required_text(row, "effect_family", context),
                effect_kind=_required_text(row, "effect_kind", context),
                structural_locator=_required_text(
                    row, "structural_locator", context
                ),
                artifact_presentation=_required_text(
                    row, "artifact_presentation", context
                ),
                phase=_required_text(row, "phase", context),
                role=role,
            )
        )
    if len(calls) != required_count:
        _refuse(
            "SDIST_CALL_LEDGER_COUNT:"
            f"observed={len(calls)}:required={required_count}"
        )
    return Ledger(
        authority_status=root["authority_status"],
        required_call_count=required_count,
        calls=tuple(calls),
        canonical_bytes=canonical,
    )


def _callable_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _callable_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return None


def _canonical_ast(node: Any) -> Any:
    """Serialize all declared AST fields consistently across Python minors."""

    if isinstance(node, ast.AST):
        return {
            "fields": {
                field: _canonical_ast(getattr(node, field))
                for field in node._fields
            },
            "type": type(node).__name__,
        }
    if isinstance(node, list):
        return [_canonical_ast(item) for item in node]
    return node


def _decorated_effects(tree: ast.AST) -> dict[str, tuple[str, str]]:
    effects: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if _callable_name(decorator.func) != "records_audit_effect":
                continue
            if (
                len(decorator.args) < 2
                or not isinstance(decorator.args[0], ast.Constant)
                or type(decorator.args[0].value) is not str
                or not isinstance(decorator.args[1], ast.Constant)
                or type(decorator.args[1].value) is not str
            ):
                continue
            effects[node.name] = (
                decorator.args[0].value,
                decorator.args[1].value,
            )
    return effects


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, effects: dict[str, tuple[str, str]]) -> None:
        self.effects = effects
        self.function_stack: list[str] = []
        self.calls: list[ObservedCall] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef
    ) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if _callable_name(node.func) == "run_sdist_audit":
            enclosing = self.function_stack[-1] if self.function_stack else "<module>"
            if (
                len(node.args) < 2
                or not isinstance(node.args[0], ast.Constant)
                or type(node.args[0].value) is not str
            ):
                identity = "<nonliteral-label>"
            else:
                identity = node.args[0].value
            action = node.args[1] if len(node.args) >= 2 else None
            if isinstance(action, ast.Lambda) and isinstance(action.body, ast.Call):
                target = _callable_name(action.body.func) or "<dynamic-target>"
            else:
                target = "<dynamic-target>"
            effect = self.effects.get(target)
            call_hash = hashlib.sha256(
                canonical_json_bytes(_canonical_ast(node))
            ).hexdigest()
            locator = (
                f"function={enclosing};target={target};call-sha256={call_hash}"
            )
            self.calls.append(
                ObservedCall(
                    identity=identity,
                    enclosing_function=enclosing,
                    target_function=target,
                    effect_family=effect[0] if effect else None,
                    effect_kind=effect[1] if effect else None,
                    structural_locator=locator,
                )
            )
        self.generic_visit(node)


def enumerate_sdist_calls(source: str, *, filename: str = "<source>") -> tuple[ObservedCall, ...]:
    """Return every literal ``run_sdist_audit`` call without running source."""

    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as exc:
        _refuse(f"SDIST_CALL_SOURCE_INVALID:{type(exc).__name__}")
    direct_runner_nodes = {
        id(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _callable_name(node.func) == "run_sdist_audit"
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id == "run_sdist_audit"
            and id(node) not in direct_runner_nodes
        ):
            _refuse(
                "SDIST_CALL_RUNNER_ALIAS_UNRESOLVED:"
                f"line={node.lineno}:column={node.col_offset}"
            )
    visitor = _CallVisitor(_decorated_effects(tree))
    visitor.visit(tree)
    return tuple(sorted(visitor.calls))


def verify_call_set(ledger: Ledger, observed: Iterable[ObservedCall]) -> dict[str, Any]:
    actual = tuple(observed)
    by_id: dict[str, list[ObservedCall]] = {}
    for call in actual:
        by_id.setdefault(call.identity, []).append(call)
    for identity in sorted(by_id):
        if len(by_id[identity]) > 1:
            _refuse(f"SDIST_CALL_DUPLICATE:{identity}")

    expected_by_id = {call.identity: call for call in ledger.calls}
    actual_ids = frozenset(by_id)
    expected_ids = frozenset(expected_by_id)
    missing = sorted(expected_ids - actual_ids)
    if missing:
        _refuse(f"SDIST_CALL_MISSING:{missing[0]}")
    extra = sorted(actual_ids - expected_ids)
    if extra:
        unexpected = by_id[extra[0]][0]
        aliases = sorted(
            expected.identity
            for expected in ledger.calls
            if (
                unexpected.enclosing_function == expected.enclosing_function
                and unexpected.target_function == expected.target_function
                and unexpected.effect_family == expected.effect_family
                and unexpected.effect_kind == expected.effect_kind
            )
        )
        if aliases:
            _refuse(f"SDIST_CALL_DUPLICATE:{aliases[0]}")
        _refuse(f"SDIST_CALL_EXTRA:{unexpected.structural_locator}")

    for identity in sorted(expected_ids):
        expected = expected_by_id[identity]
        found = by_id[identity][0]
        if (
            found.target_function != expected.target_function
            or found.effect_family != expected.effect_family
            or found.effect_kind != expected.effect_kind
        ):
            _refuse(f"SDIST_CALL_TARGET_MISMATCH:{identity}")
        if (
            found.enclosing_function != expected.enclosing_function
            or found.structural_locator != expected.structural_locator
        ):
            _refuse(f"SDIST_CALL_LOCATOR_MISMATCH:{identity}")

    observed_records = [dataclasses.asdict(call) for call in sorted(actual)]
    observed_bytes = canonical_json_bytes(observed_records)
    return {
        "authority_status": ledger.authority_status,
        "ledger_sha256": hashlib.sha256(ledger.canonical_bytes).hexdigest(),
        "observed_call_count": len(actual),
        "observed_call_ids": sorted(actual_ids),
        "observed_set_sha256": hashlib.sha256(observed_bytes).hexdigest(),
        "required_call_count": ledger.required_call_count,
        "required_call_ids": sorted(expected_ids),
        "status": "PASS",
    }


def expected_effect_events(ledger: Ledger) -> list[dict[str, str]]:
    """Return the exact event shape the integration lane must observe."""

    return [
        {
            "artifact_presentation": call.artifact_presentation,
            "effect_family": call.effect_family,
            "effect_kind": call.effect_kind,
            "identity": call.identity,
            "phase": call.phase,
            "target_function": call.target_function,
        }
        for call in sorted(ledger.calls, key=lambda row: row.identity)
    ]


def verify_effect_trace(ledger: Ledger, trace: Any) -> dict[str, Any]:
    root = _exact_keys(trace, TRACE_KEYS, "trace")
    if root["schema_version"] != TRACE_SCHEMA_VERSION:
        _refuse("SDIST_CALL_EFFECT_TRACE_SCHEMA")
    if type(root["events"]) is not list:
        _refuse("SDIST_CALL_EFFECT_TRACE_TYPE")
    events: list[dict[str, str]] = []
    for index, candidate in enumerate(root["events"]):
        context = f"events[{index}]"
        event = _exact_keys(candidate, EVENT_KEYS, context)
        events.append(
            {key: _required_text(event, key, context) for key in sorted(EVENT_KEYS)}
        )
    expected = expected_effect_events(ledger)
    for row in expected:
        if row not in events:
            _refuse(f"SDIST_CALL_EFFECT_UNOBSERVED:{row['identity']}")
    return {
        "observed_effect_count": len(expected),
        "required_effect_count": len(expected),
        "status": "PASS",
    }


def _load_trace(path: Path) -> Any:
    value, _ = _load_canonical_json(path)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--effect-trace", type=Path)
    args = parser.parse_args(argv)
    try:
        ledger = load_ledger(args.ledger)
        source = args.source.read_text(encoding="utf-8")
        observed = enumerate_sdist_calls(source, filename=str(args.source))
        result = verify_call_set(ledger, observed)
        if args.effect_trace is not None:
            result.update(verify_effect_trace(ledger, _load_trace(args.effect_trace)))
    except (OSError, VerificationError) as exc:
        message = exc.code if isinstance(exc, VerificationError) else str(exc)
        print(message, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
