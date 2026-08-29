#!/usr/bin/env python3
"""Apply the pre-registered R15-3 pair only to a disposable exact export."""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, NoReturn


EXPECTED_GATE_SHA256 = "b6688d289db61d2c2dabe0e0a4a6a65a6ed5cb4c8d214600ca8a984fc8d20386"
SCHEMA = "kilix.content.f100-u1-r16-r15-3-mutation/v1"


def canonical_json(value: Any) -> bytes:
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


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        fail(f"{label}: expected exactly one source block, observed {count}")
    return source.replace(old, new, 1)


def structural_ast_dump(node: ast.AST) -> str:
    """Return the complete AST shape under the credited interpreters."""

    keywords = {"annotate_fields": True, "include_attributes": False}
    if "show_empty" in inspect.signature(ast.dump).parameters:
        keywords["show_empty"] = True
    return ast.dump(node, **keywords)


def record_definition_sha256(source: str) -> str:
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "record_audit"
    ]
    if len(matches) != 1:
        fail(f"record_audit definition count={len(matches)}")
    raw = structural_ast_dump(matches[0]).encode()
    return digest(raw)


def hollow_label_present(source: str) -> str:
    old = '''@records_audit_effect("wheel", "record")
def record_audit(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
'''
    new = '''@records_audit_effect("wheel", "record")
def record_audit(wheel: Path) -> None:
    if _COMPLETE_GATE_REGRESSIONS_OBSERVED:
        return
    with zipfile.ZipFile(wheel) as archive:
'''
    return replace_once(source, old, new, "hollow-label-present")


def audit_present_label_absent_v1(source: str) -> str:
    production_old = '''            register_production_audit(
                "wheel",
                label,
                "record",
                lambda wheel=wheel: record_audit(wheel),
            )'''
    production_new = '''            record_audit(wheel)'''
    source = replace_once(
        source,
        production_old,
        production_new,
        "audit-present-label-absent production call",
    )
    census_old = '''        "wheel-record-audit": (
            '            register_production_audit(\\n'
            '                "wheel",\\n'
            '                label,\\n'
            '                "record",\\n'
            '                lambda wheel=wheel: record_audit(wheel),\\n'
            '            )'
        ),'''
    census_new = '''        "wheel-record-audit": '            record_audit(wheel)','''
    return replace_once(
        source,
        census_old,
        census_new,
        "audit-present-label-absent source census",
    )


def audit_present_label_absent_v2(source: str) -> str:
    """Remove the record label without duplicating R13's literal source needle.

    The first construction wrote the new one-line call literally into the R13
    source census, so the R13 parent saw its needle twice before its child ran.
    Splitting the census literal retains the same runtime expected bytes while
    keeping exactly one literal production call in the checker source.
    """
    production_old = '''            register_production_audit(
                "wheel",
                label,
                "record",
                lambda wheel=wheel: record_audit(wheel),
            )'''
    production_new = '''            record_audit(wheel)'''
    source = replace_once(
        source,
        production_old,
        production_new,
        "audit-present-label-absent-v2 production call",
    )
    census_old = '''        "wheel-record-audit": (
            '            register_production_audit(\\n'
            '                "wheel",\\n'
            '                label,\\n'
            '                "record",\\n'
            '                lambda wheel=wheel: record_audit(wheel),\\n'
            '            )'
        ),'''
    census_new = '''        "wheel-record-audit": "            record_audit" + "(wheel)",'''
    return replace_once(
        source,
        census_old,
        census_new,
        "audit-present-label-absent-v2 source census",
    )


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "case",
        choices=(
            "hollow-label-present",
            "audit-present-label-absent",
            "audit-present-label-absent-v2",
        ),
    )
    parser.add_argument("--gate", required=True)
    arguments = parser.parse_args()
    path = Path(arguments.gate)
    before = verify_disposable_gate(path)
    try:
        source = before.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"gate is not UTF-8: {exc}")
    before_definition = record_definition_sha256(source)
    if arguments.case == "hollow-label-present":
        mutated = hollow_label_present(source)
    elif arguments.case == "audit-present-label-absent":
        mutated = audit_present_label_absent_v1(source)
    else:
        mutated = audit_present_label_absent_v2(source)
    ast.parse(mutated)
    after_definition = record_definition_sha256(mutated)
    after = mutated.encode("utf-8")
    path.write_bytes(after)
    result = {
        "after_gate_sha256": digest(after),
        "before_gate_sha256": digest(before),
        "case": arguments.case,
        "record_audit_after_sha256": after_definition,
        "record_audit_before_sha256": before_definition,
        "schema": SCHEMA,
    }
    print(canonical_json(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
