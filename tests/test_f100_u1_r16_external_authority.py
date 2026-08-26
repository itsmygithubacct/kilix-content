"""Builder tests for the separately pinned F100 U1 R16 authority."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


PROJECT = Path(__file__).resolve().parents[1]
TOOL_PATH = PROJECT / "tools" / "f100_u1_r16_external_authority.py"
AUTHORITY_SOURCE = PROJECT / "authority" / "f100-u1-r16"
GATE_RELATIVE = Path("tests/check_reproducible_build.py")


def load_tool():
    spec = importlib.util.spec_from_file_location("f100_u1_r16_external_authority", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load external-authority tool")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTHORITY = load_tool()


class RegistryTransformer(ast.NodeTransformer):
    def __init__(self, action):
        self.action = action

    def visit_Assign(self, node: ast.Assign):  # noqa: N802 - AST API name
        self.generic_visit(node)
        if any(
            isinstance(target, ast.Name) and target.id == "PROPERTY_MUTATION_REGISTRY"
            for target in node.targets
        ):
            node.value = self.action(node.value)
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign):  # noqa: N802 - AST API name
        self.generic_visit(node)
        if (
            isinstance(node.target, ast.Name)
            and node.target.id == "PROPERTY_MUTATION_REGISTRY"
            and node.value is not None
        ):
            node.value = self.action(node.value)
        return node


class MainCallNeutralizer(ast.NodeTransformer):
    def __init__(self, target: str):
        self.target = target
        self.replacements = 0
        self.in_main = False

    def visit_FunctionDef(self, node: ast.FunctionDef):  # noqa: N802 - AST API name
        previous = self.in_main
        if not previous:
            self.in_main = node.name == "main"
        self.generic_visit(node)
        self.in_main = previous
        return node

    def visit_Call(self, node: ast.Call):  # noqa: N802 - AST API name
        self.generic_visit(node)
        if self.in_main and isinstance(node.func, ast.Name) and node.func.id == self.target:
            self.replacements += 1
            return ast.copy_location(ast.Constant(None), node)
        return node


class R16ExternalAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kilix-r16-authority-test-")
        root = Path(self.temporary.name)
        self.candidate = root / "candidate"
        self.authority = root / "authority"
        (self.candidate / "tests").mkdir(parents=True)
        shutil.copy2(PROJECT / GATE_RELATIVE, self.candidate / GATE_RELATIVE)
        shutil.copytree(AUTHORITY_SOURCE, self.authority)
        self.original_gate = (self.candidate / GATE_RELATIVE).read_bytes()
        self.authority_value = json.loads((self.authority / "authority.json").read_bytes())
        self.authority_sha256 = hashlib.sha256(
            (self.authority / "authority.json").read_bytes()
        ).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self, **changes):
        values = {
            "authority_root": str(self.authority),
            "authority_sha256": self.authority_sha256,
            "candidate_root": str(self.candidate),
        }
        values.update(changes)
        return SimpleNamespace(**values)

    def assert_refusal(self, code: str, **changes):
        with self.assertRaises(AUTHORITY.AuthorityRefusal) as raised:
            AUTHORITY.verify(self.arguments(**changes))
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def rewrite_registry(self, action) -> None:
        gate = self.candidate / GATE_RELATIVE
        tree = ast.parse(gate.read_bytes())
        tree = RegistryTransformer(action).visit(tree)
        ast.fix_missing_locations(tree)
        gate.write_text(ast.unparse(tree) + "\n")

    def reset_gate(self) -> None:
        (self.candidate / GATE_RELATIVE).write_bytes(self.original_gate)

    def test_exact_export_verifies_without_grade(self) -> None:
        result = AUTHORITY.verify(self.arguments())
        self.assertEqual(result["status"], "VERIFIED_NOT_GRADED")
        self.assertEqual(result["history"]["current_rows"], 12)
        self.assertEqual(result["history"]["protected_definition_count"], 5)
        self.assertEqual(result["population"]["audit_count"], 10)
        self.assertEqual(result["population"]["reachable_call_site_count"], 1603)
        self.assertEqual(result["population"]["reachable_owner_count"], 94)
        self.assertEqual(result["evidence"]["candidate_lane_execution_count"], 17)
        self.assertEqual(result["evidence"]["gate_started_count"], 14)
        self.assertEqual(result["evidence"]["evidence_conflict_count"], 1)
        self.assertEqual(result["evidence"]["pair_obligation_count"], 2)
        self.assertEqual(result["evidence"]["pair_execution_count"], 3)
        self.assertEqual(result["evidence"]["pair_expected_outcome_count"], 2)
        self.assertEqual(result["evidence"]["pair_discarded_execution_count"], 1)

    def test_structural_ast_dump_normalizes_interpreter_specific_empty_fields(self) -> None:
        node = ast.parse("def empty():\n    return target()\n").body[0]
        self.assertEqual(
            AUTHORITY.structural_ast_dump(node),
            "FunctionDef(name='empty', args=arguments(posonlyargs=[], args=[], "
            "kwonlyargs=[], kw_defaults=[], defaults=[]), "
            "body=[Return(value=Call(func=Name(id='target', ctx=Load()), "
            "args=[], keywords=[]))], decorator_list=[], type_params=[])",
        )

    def test_candidate_local_authority_is_rejected(self) -> None:
        local = self.candidate / "authority"
        shutil.copytree(self.authority, local)
        self.assert_refusal("AUTHORITY_NOT_EXTERNAL", authority_root=str(local))

    def test_manifest_requires_external_digest_pin(self) -> None:
        self.assert_refusal("AUTHORITY_PIN_MISMATCH", authority_sha256="0" * 64)

    def test_manifest_pins_the_verifier_bytes(self) -> None:
        manifest = self.authority / "authority.json"
        value = json.loads(manifest.read_bytes())
        value["implementation"]["verifier"]["sha256"] = "0" * 64
        manifest.write_bytes(AUTHORITY.canonical_json(value))
        self.authority_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.assert_refusal("IMPLEMENTATION_VERIFIER_DRIFT")

    def test_old_r14_row_removal_is_named(self) -> None:
        def remove(value: ast.expr) -> ast.expr:
            assert isinstance(value, (ast.Tuple, ast.List))
            value.elts = value.elts[1:]
            return value

        self.rewrite_registry(remove)
        self.assert_refusal("HISTORY_REQUIRED_ROW_REMOVED")

    def test_new_r15_row_removal_is_named(self) -> None:
        def remove(value: ast.expr) -> ast.expr:
            assert isinstance(value, (ast.Tuple, ast.List))
            value.elts = [
                row
                for row in value.elts
                if not (
                    isinstance(row, ast.Dict)
                    and any(
                        isinstance(key, ast.Constant)
                        and key.value == "id"
                        and isinstance(item, ast.Constant)
                        and item.value == "wheel.module.source-byte"
                        for key, item in zip(row.keys, row.values, strict=True)
                    )
                )
            ]
            return value

        self.rewrite_registry(remove)
        self.assert_refusal("HISTORY_REQUIRED_ROW_REMOVED")

    def test_historical_reorder_is_named(self) -> None:
        def reorder(value: ast.expr) -> ast.expr:
            assert isinstance(value, (ast.Tuple, ast.List))
            value.elts[0], value.elts[1] = value.elts[1], value.elts[0]
            return value

        self.rewrite_registry(reorder)
        self.assert_refusal("HISTORY_PREFIX_CHANGED")

    def test_historical_semantics_change_is_named(self) -> None:
        def change(value: ast.expr) -> ast.expr:
            assert isinstance(value, (ast.Tuple, ast.List))
            row = value.elts[0]
            assert isinstance(row, ast.Dict)
            for index, key in enumerate(row.keys):
                if isinstance(key, ast.Constant) and key.value == "property":
                    row.values[index] = ast.Constant("restated semantics")
            return value

        self.rewrite_registry(change)
        self.assert_refusal("HISTORY_PREFIX_CHANGED")

    def test_historical_id_alias_is_named(self) -> None:
        def alias(value: ast.expr) -> ast.expr:
            assert isinstance(value, (ast.Tuple, ast.List))
            row = value.elts[0]
            assert isinstance(row, ast.Dict)
            for index, key in enumerate(row.keys):
                if isinstance(key, ast.Constant) and key.value == "id":
                    row.values[index] = ast.Constant("sdist.container.gzip-trailing-alias")
            return value

        self.rewrite_registry(alias)
        self.assert_refusal("HISTORY_REQUIRED_ROW_REMOVED")

    def test_appended_duplicate_id_is_named(self) -> None:
        def duplicate(value: ast.expr) -> ast.expr:
            assert isinstance(value, (ast.Tuple, ast.List))
            value.elts.append(value.elts[0])
            return value

        self.rewrite_registry(duplicate)
        self.assert_refusal("HISTORY_DUPLICATE_ROW_ID")

    def test_historical_executor_noop_is_named(self) -> None:
        gate = self.candidate / GATE_RELATIVE
        source = gate.read_text()
        old = "            rewrite_sdist_with_gzip_trailing_bytes(archive, mutated)"
        new = "            shutil.copy2(archive, mutated)"
        self.assertEqual(source.count(old), 1)
        gate.write_text(source.replace(old, new, 1))
        self.assert_refusal("HISTORY_PROTECTED_DEFINITION_DRIFT")

    def test_all_frozen_p3_audits_have_both_structural_directions(self) -> None:
        audits = self.authority_value["production_population"]["audits"]
        self.assertEqual(len(audits), 10)
        for audit in audits:
            with self.subTest(direction="audit-unreachable-label-retained", audit=audit):
                self.reset_gate()
                gate = self.candidate / GATE_RELATIVE
                tree = ast.parse(gate.read_bytes())
                transformer = MainCallNeutralizer(audit["function"])
                tree = transformer.visit(tree)
                self.assertGreater(transformer.replacements, 0)
                ast.fix_missing_locations(tree)
                gate.write_text(ast.unparse(tree) + "\n")
                self.assert_refusal("P3_AUDIT_CALL_SITE_DRIFT")

            with self.subTest(direction="assignment-absent-audit-retained", audit=audit):
                self.reset_gate()

                def remove_pair(value: ast.expr, audit=audit) -> ast.expr:
                    assert isinstance(value, (ast.Tuple, ast.List))
                    kept: list[ast.expr] = []
                    for row in value.elts:
                        assert isinstance(row, ast.Dict)
                        materialized = {
                            key.value: item.value
                            for key, item in zip(row.keys, row.values, strict=True)
                            if isinstance(key, ast.Constant) and isinstance(item, ast.Constant)
                        }
                        if (
                            materialized.get("artifact_family"),
                            materialized.get("audit_kind"),
                        ) != (audit["family"], audit["kind"]):
                            kept.append(row)
                    value.elts = kept
                    return value

                self.rewrite_registry(remove_pair)
                refusal = self.assert_refusal("HISTORY_REQUIRED_ROW_REMOVED")
                self.assertIn(repr(audit["family"]), refusal.detail)
                self.assertIn(repr(audit["kind"]), refusal.detail)

    def test_unratified_undecorated_production_call_is_named(self) -> None:
        gate = self.candidate / GATE_RELATIVE
        tree = ast.parse(gate.read_bytes())
        function = ast.parse(
            "def unregistered_production_audit(artifact: Path) -> None:\n"
            "    if not artifact.exists():\n"
            "        fail('unregistered production audit')\n"
        ).body[0]
        assert isinstance(function, ast.FunctionDef)
        main = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        main.body.insert(
            0,
            ast.Expr(
                ast.Call(
                    func=ast.Name("unregistered_production_audit", ast.Load()),
                    args=[ast.Name("PROJECT", ast.Load())],
                    keywords=[],
                )
            ),
        )
        tree.body.insert(-1, function)
        ast.fix_missing_locations(tree)
        gate.write_text(ast.unparse(tree) + "\n")
        self.assert_refusal("P3_CALL_POPULATION_COUNT_DRIFT")

    def test_unmodelled_source_change_is_still_fail_closed(self) -> None:
        gate = self.candidate / GATE_RELATIVE
        gate.write_bytes(gate.read_bytes() + b"\n# unratified but AST-inert change\n")
        self.assert_refusal("P3_AUTHORITY_SOURCE_DRIFT")

    def test_evidence_snapshot_tamper_is_named(self) -> None:
        transcript = self.authority / "r15-mutation-transcripts.snapshot.md"
        transcript.write_bytes(transcript.read_bytes() + b"drift\n")
        self.assert_refusal("EVIDENCE_DIGEST_MISMATCH")

    def test_pair_log_tamper_is_named(self) -> None:
        log = self.authority / "evidence" / "sufficient-v2-gate.log"
        log.write_bytes(log.read_bytes() + b"drift\n")
        self.assert_refusal("EVIDENCE_DIGEST_MISMATCH")

    def test_lane_population_is_unique_and_closed(self) -> None:
        raw = (self.authority / "candidate-lane-census.json").read_bytes()
        census = json.loads(raw)
        self.assertEqual(
            raw,
            AUTHORITY.canonical_json(census),
        )
        identifiers = [row["run_id"] for row in census["lanes"]]
        self.assertEqual(len(identifiers), 17)
        self.assertEqual(len(set(identifiers)), 17)
        self.assertEqual(sum(row["gate_started"] for row in census["lanes"]), 14)
        self.assertEqual([row["conflict_id"] for row in census["conflicts"]], ["arm12-exit-status"])


if __name__ == "__main__":
    unittest.main()
