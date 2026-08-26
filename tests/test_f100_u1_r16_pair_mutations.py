"""Structural tests for the pre-registered R15-3 mutation pair."""

from __future__ import annotations

import ast
import importlib.util
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
        self.assertEqual(
            MUTATIONS.digest(self.source.encode()),
            MUTATIONS.EXPECTED_GATE_SHA256,
        )

    def test_hollow_keeps_decorator_and_production_label(self) -> None:
        mutated = MUTATIONS.hollow_label_present(self.source)
        record = function(mutated, "record_audit")
        self.assertEqual(len(record.decorator_list), 1)
        self.assertEqual(ast.unparse(record.decorator_list[0]), "records_audit_effect('wheel', 'record')")
        self.assertIn('lambda wheel=wheel: record_audit(wheel)', mutated)
        self.assertIn("if _COMPLETE_GATE_REGRESSIONS_OBSERVED:\n        return", mutated)
        self.assertEqual(
            MUTATIONS.digest(mutated.encode()),
            "dda7e2b072a5a8d62415509dc46ceeed377d4826468c4b098753a1df511dc176",
        )

    def test_sufficiency_keeps_exact_audit_and_removes_label_call(self) -> None:
        mutated = MUTATIONS.audit_present_label_absent_v1(self.source)
        self.assertEqual(
            MUTATIONS.record_definition_sha256(mutated),
            MUTATIONS.record_definition_sha256(self.source),
        )
        self.assertEqual(mutated.count('lambda wheel=wheel: record_audit(wheel)'), 0)
        self.assertEqual(mutated.count("            record_audit(wheel)"), 2)
        self.assertEqual(
            MUTATIONS.digest(mutated.encode()),
            "1b5d295bd8f28cff981cab0aa129b2e7c3b6c5a98899c0c9d28e66a96d2a9835",
        )

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
        self.assertEqual(
            MUTATIONS.digest(mutated.encode()),
            "8256c8781fd1b7e82f0446130411eb7574803b9a855dc646f15d07093a7dae39",
        )

    def test_input_identity_is_exact_and_worktree_is_refused(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            MUTATIONS.verify_disposable_gate(GATE)
        self.assertIn("Git worktree", str(raised.exception))
        with tempfile.TemporaryDirectory(prefix="kilix-r16-mutation-") as name:
            root = Path(name)
            target = root / "tests" / GATE.name
            target.parent.mkdir()
            shutil.copy2(GATE, target)
            observed = MUTATIONS.verify_disposable_gate(target)
            self.assertEqual(MUTATIONS.digest(observed), MUTATIONS.EXPECTED_GATE_SHA256)
            target.write_bytes(observed + b"\n")
            with self.assertRaises(SystemExit) as drifted:
                MUTATIONS.verify_disposable_gate(target)
            self.assertIn("input gate identity differs", str(drifted.exception))


if __name__ == "__main__":
    unittest.main()
