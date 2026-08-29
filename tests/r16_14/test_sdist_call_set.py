from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.r16_14.sdist_call_set import (
    TRACE_SCHEMA_VERSION,
    VerificationError,
    canonical_json_bytes,
    enumerate_sdist_calls,
    expected_effect_events,
    load_ledger,
    verify_call_set,
    verify_effect_trace,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / "tests" / "check_reproducible_build.py"
LEDGER_PATH = ROOT / "tools" / "r16_14" / "fixtures" / "sdist-call-ledger.json"
CONTROL_PATH = Path(__file__).parent / "fixtures" / "causal-controls.json"


def call_identity(node: ast.Call) -> str | None:
    if not isinstance(node.func, ast.Name) or node.func.id != "run_sdist_audit":
        return None
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    return node.args[0].value if type(node.args[0].value) is str else None


def transformed_source(source: str, transformer: ast.NodeTransformer) -> str:
    tree = transformer.visit(ast.parse(source))
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


class RemoveCall(ast.NodeTransformer):
    def __init__(self, identity: str) -> None:
        self.identity = identity
        self.removed = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
        node = self.generic_visit(node)
        if isinstance(node, ast.Call) and call_identity(node) == self.identity:
            self.removed += 1
            return ast.copy_location(ast.Constant(value=None), node)
        return node


class RetargetCall(ast.NodeTransformer):
    def __init__(self, identity: str, target: str) -> None:
        self.identity = identity
        self.target = target
        self.changed = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
        node = self.generic_visit(node)
        if not isinstance(node, ast.Call) or call_identity(node) != self.identity:
            return node
        action = node.args[1]
        if not isinstance(action, ast.Lambda) or not isinstance(action.body, ast.Call):
            raise AssertionError("control target is not a literal lambda call")
        action.body.func = ast.copy_location(ast.Name(id=self.target), action.body.func)
        self.changed += 1
        return node


class DuplicateCall(ast.NodeTransformer):
    def __init__(self, identity: str, *, alias: str | None = None) -> None:
        self.identity = identity
        self.alias = alias
        self.changed = 0

    def visit_Expr(self, node: ast.Expr) -> ast.AST | list[ast.AST]:  # noqa: N802
        node = self.generic_visit(node)
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and call_identity(node.value) == self.identity
        ):
            self.changed += 1
            duplicate = copy.deepcopy(node)
            if self.alias is not None:
                assert isinstance(duplicate.value, ast.Call)
                duplicate.value.args[0] = ast.copy_location(
                    ast.Constant(value=self.alias), duplicate.value.args[0]
                )
            return [node, duplicate]
        return node


class AddExtraCall(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changed = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:  # noqa: N802
        node = self.generic_visit(node)
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            extra = ast.parse(
                'run_sdist_audit("unreviewed-extra", '
                "lambda: sdist_member_closure_audit(archive))"
            ).body[0]
            node.body.append(extra)
            self.changed += 1
        return node


class RestateCandidateMirror(ast.NodeTransformer):
    """Lower the candidate-owned mirror and floor after deleting one call."""

    def __init__(self) -> None:
        self.set_changed = 0
        self.floor_changed = 0

    def visit_Assign(self, node: ast.Assign) -> ast.AST:  # noqa: N802
        node = self.generic_visit(node)
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if "FROZEN_REQUIRED_SDIST_AUDIT_CALL_COUNT" in names:
            node.value = ast.copy_location(ast.Constant(value=8), node.value)
            self.floor_changed += 1
        if "_REQUIRED_SDIST_AUDIT_CALLS" not in names:
            return node
        if not isinstance(node.value, ast.Call) or not node.value.args:
            raise AssertionError("candidate call set changed shape")
        members = node.value.args[0]
        if not isinstance(members, ast.Set):
            raise AssertionError("candidate call set is not a set literal")
        before = len(members.elts)
        members.elts = [
            item
            for item in members.elts
            if not (
                isinstance(item, ast.Constant)
                and item.value == "direct-payload"
            )
        ]
        self.set_changed += before - len(members.elts)
        return node


class SdistCallSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.ledger = load_ledger(LEDGER_PATH)
        cls.control_manifest = json.loads(CONTROL_PATH.read_bytes())

    def refusal(self, source: str) -> str:
        with self.assertRaises(VerificationError) as caught:
            verify_call_set(self.ledger, enumerate_sdist_calls(source))
        return caught.exception.code

    def ledger_refusal(self, payload: bytes) -> str:
        with tempfile.TemporaryDirectory(prefix="r16-14-ledger-") as directory:
            path = Path(directory) / "ledger.json"
            path.write_bytes(payload)
            with self.assertRaises(VerificationError) as caught:
                load_ledger(path)
        return caught.exception.code

    def test_positive_population_is_exactly_nine_of_nine(self) -> None:
        result = verify_call_set(
            self.ledger,
            enumerate_sdist_calls(self.source, filename=str(SOURCE_PATH)),
        )
        self.assertEqual(result["observed_call_count"], 9)
        self.assertEqual(result["required_call_count"], 9)
        self.assertEqual(
            result["observed_call_ids"], result["required_call_ids"]
        )

    def test_enumerator_never_executes_the_subject(self) -> None:
        hostile = """
raise AssertionError("the parser executed its subject")
def records_audit_effect(*args):
    return lambda function: function
@records_audit_effect("sdist", "payload")
def target(archive):
    raise AssertionError("the parser called an audit")
def carrier(archive):
    run_sdist_audit("probe", lambda: target(archive))
"""
        rows = enumerate_sdist_calls(hostile)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].target_function, "target")
        self.assertEqual(rows[0].effect_kind, "payload")

    def test_nine_deletion_controls_refuse_by_exact_identity(self) -> None:
        identities = sorted(call.identity for call in self.ledger.calls)
        self.assertEqual(len(identities), 9)
        for identity in identities:
            with self.subTest(control=f"SCALL-DEL-{identity}"):
                mutation = RemoveCall(identity)
                mutated = transformed_source(self.source, mutation)
                self.assertEqual(mutation.removed, 1)
                self.assertEqual(
                    self.refusal(mutated), f"SDIST_CALL_MISSING:{identity}"
                )

    def test_restatement_cannot_shrink_the_separate_ledger(self) -> None:
        deletion = RemoveCall("direct-payload")
        mutated = transformed_source(self.source, deletion)
        restatement = RestateCandidateMirror()
        mutated = transformed_source(mutated, restatement)
        self.assertEqual(deletion.removed, 1)
        self.assertEqual(restatement.set_changed, 1)
        self.assertEqual(restatement.floor_changed, 1)
        self.assertEqual(
            self.refusal(mutated), "SDIST_CALL_MISSING:direct-payload"
        )

    def test_extra_call_refuses_by_structural_identity(self) -> None:
        mutation = AddExtraCall()
        mutated = transformed_source(self.source, mutation)
        self.assertEqual(mutation.changed, 1)
        refusal = self.refusal(mutated)
        self.assertTrue(refusal.startswith("SDIST_CALL_EXTRA:function=main;"))
        self.assertIn("target=sdist_member_closure_audit", refusal)

    def test_retarget_refuses_by_exact_identity(self) -> None:
        mutation = RetargetCall("direct-payload", "sdist_container_audit")
        mutated = transformed_source(self.source, mutation)
        self.assertEqual(mutation.changed, 1)
        self.assertEqual(
            self.refusal(mutated),
            "SDIST_CALL_TARGET_MISMATCH:direct-payload",
        )

    def test_duplicate_refuses_by_exact_identity(self) -> None:
        mutation = DuplicateCall("relative-enumerator")
        mutated = transformed_source(self.source, mutation)
        self.assertEqual(mutation.changed, 1)
        self.assertEqual(
            self.refusal(mutated),
            "SDIST_CALL_DUPLICATE:relative-enumerator",
        )

    def test_alias_duplicate_refuses_by_required_structural_identity(self) -> None:
        mutation = DuplicateCall(
            "relative-enumerator", alias="relative-enumerator-alias"
        )
        mutated = transformed_source(self.source, mutation)
        self.assertEqual(mutation.changed, 1)
        self.assertEqual(
            self.refusal(mutated),
            "SDIST_CALL_DUPLICATE:relative-enumerator",
        )

    def test_unobserved_runtime_effect_refuses_by_exact_identity(self) -> None:
        events = expected_effect_events(self.ledger)
        events = [row for row in events if row["identity"] != "direct-payload"]
        trace = {"events": events, "schema_version": TRACE_SCHEMA_VERSION}
        with self.assertRaises(VerificationError) as caught:
            verify_effect_trace(self.ledger, trace)
        self.assertEqual(
            caught.exception.code,
            "SDIST_CALL_EFFECT_UNOBSERVED:direct-payload",
        )

    def test_complete_runtime_effect_trace_is_nine_of_nine(self) -> None:
        trace = {
            "events": expected_effect_events(self.ledger),
            "schema_version": TRACE_SCHEMA_VERSION,
        }
        result = verify_effect_trace(self.ledger, trace)
        self.assertEqual(result["observed_effect_count"], 9)
        self.assertEqual(result["required_effect_count"], 9)

    def test_ledger_refuses_noncanonical_unknown_duplicate_and_truncation(self) -> None:
        value = json.loads(LEDGER_PATH.read_bytes())

        pretty = json.dumps(value, indent=2).encode("utf-8") + b"\n"
        self.assertEqual(
            self.ledger_refusal(pretty), "SDIST_CALL_LEDGER_NONCANONICAL"
        )

        unknown = copy.deepcopy(value)
        unknown["unreviewed"] = True
        self.assertIn(
            "extra=unreviewed", self.ledger_refusal(canonical_json_bytes(unknown))
        )

        raw = LEDGER_PATH.read_bytes()
        duplicate = raw.replace(
            b'{"authority_status":',
            b'{"scope":"R16-14","authority_status":',
            1,
        )
        self.assertEqual(
            self.ledger_refusal(duplicate),
            "SDIST_CALL_LEDGER_DUPLICATE_KEY:scope",
        )

        wrong_type = copy.deepcopy(value)
        wrong_type["required_call_count"] = True
        self.assertEqual(
            self.ledger_refusal(canonical_json_bytes(wrong_type)),
            "SDIST_CALL_LEDGER_REQUIRED_COUNT",
        )

        truncated = copy.deepcopy(value)
        truncated["calls"] = truncated["calls"][:-1]
        self.assertEqual(
            self.ledger_refusal(canonical_json_bytes(truncated)),
            "SDIST_CALL_LEDGER_COUNT:observed=8:required=9",
        )

    def test_control_manifest_closes_fourteen_of_fourteen(self) -> None:
        rows = self.control_manifest["controls"]
        self.assertEqual(self.control_manifest["control_count"], 14)
        self.assertEqual(len(rows), 14)
        self.assertEqual(len({row["id"] for row in rows}), 14)
        deletion_ids = {row["id"] for row in rows if row["id"].startswith("SCALL-DEL-")}
        self.assertEqual(len(deletion_ids), 9)


if __name__ == "__main__":
    unittest.main()
