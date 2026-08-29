"""Structural tests for the pre-registered R15-3 mutation pair."""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
GATE = PROJECT / "tests" / "check_reproducible_build.py"
TOOL = PROJECT / "tools" / "f100_u1_r16_pair_mutations.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("f100_u1_r16_pair_mutations", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load mutation tool")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MUTATIONS = load_tool()


def function(source: str, name: str) -> ast.FunctionDef:
    matches = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"{name}: definition count={len(matches)}")
    return matches[0]


class R16PairMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = GATE.read_text()

    def test_hollow_keeps_decorator_and_production_label(self) -> None:
        mutated = MUTATIONS.hollow_label_present(self.source)
        record = function(mutated, "record_audit")
        self.assertEqual(len(record.decorator_list), 1)
        self.assertEqual(ast.unparse(record.decorator_list[0]), "records_audit_effect('wheel', 'record')")
        self.assertIn('lambda wheel=wheel: record_audit(wheel)', mutated)
        self.assertIn("if _COMPLETE_GATE_REGRESSIONS_OBSERVED:\n        return", mutated)

    def test_structural_dump_includes_interpreter_specific_empty_fields(self) -> None:
        node = ast.parse("def empty():\n    return target()\n").body[0]
        self.assertEqual(
            MUTATIONS.structural_ast_dump(node),
            "FunctionDef(name='empty', args=arguments(posonlyargs=[], args=[], "
            "kwonlyargs=[], kw_defaults=[], defaults=[]), "
            "body=[Return(value=Call(func=Name(id='target', ctx=Load()), "
            "args=[], keywords=[]))], decorator_list=[], type_params=[])",
        )

    def test_sufficiency_keeps_exact_audit_and_removes_label_call(self) -> None:
        mutated = MUTATIONS.audit_present_label_absent_v1(self.source)
        self.assertEqual(
            MUTATIONS.record_definition_sha256(mutated),
            MUTATIONS.record_definition_sha256(self.source),
        )
        self.assertEqual(mutated.count('lambda wheel=wheel: record_audit(wheel)'), 0)
        self.assertEqual(mutated.count("            record_audit(wheel)"), 2)

    def test_sufficiency_v2_keeps_one_literal_r13_needle(self) -> None:
        mutated = MUTATIONS.audit_present_label_absent_v2(self.source)
        self.assertEqual(
            MUTATIONS.record_definition_sha256(mutated),
            MUTATIONS.record_definition_sha256(self.source),
        )
        self.assertEqual(mutated.count('lambda wheel=wheel: record_audit(wheel)'), 0)
        self.assertEqual(mutated.count("            record_audit(wheel)"), 1)
        census_expression = '"wheel-record-audit": "            record_audit" + "(wheel)"'
        self.assertEqual(mutated.count(census_expression), 1)

    def test_input_identity_is_exact_and_worktree_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kilix-r16-mutation-") as name:
            root = Path(name)
            worktree = root / "worktree"
            target = worktree / "tests" / GATE.name
            target.parent.mkdir(parents=True)
            (worktree / ".git").mkdir()
            shutil.copy2(GATE, target)
            with self.assertRaises(SystemExit) as raised:
                MUTATIONS.verify_disposable_gate(target)
            self.assertIn("Git worktree", str(raised.exception))
            target = root / "candidate" / "tests" / GATE.name
            target.parent.mkdir(parents=True)
            shutil.copy2(GATE, target)
            with self.assertRaises(SystemExit) as drifted:
                MUTATIONS.verify_disposable_gate(target)
            self.assertIn("input gate identity differs", str(drifted.exception))

    def test_input_identity_remains_the_frozen_r15_pair_subject(self) -> None:
        plan = json.loads(
            (PROJECT / "authority" / "f100-u1-r16" / "r15-3-pair-plan.json")
            .read_bytes()
        )
        self.assertEqual(
            MUTATIONS.EXPECTED_GATE_SHA256,
            plan["input"]["gate_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
