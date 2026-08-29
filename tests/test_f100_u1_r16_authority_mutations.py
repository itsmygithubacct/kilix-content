"""Builder tests for the reusable R16 history/P3 mutation population."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


PROJECT = Path(__file__).resolve().parents[1]
GATE_RELATIVE = Path("tests/check_reproducible_build.py")
AUTHORITY_SOURCE = PROJECT / "authority" / "f100-u1-r16"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MUTATIONS = load(
    "f100_u1_r16_authority_mutations",
    PROJECT / "tools" / "f100_u1_r16_authority_mutations.py",
)
AUTHORITY = load(
    "f100_u1_r16_external_authority_for_mutations",
    PROJECT / "tools" / "f100_u1_r16_external_authority.py",
)


class R16AuthorityMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kilix-r16-matrix-test-")
        root = Path(self.temporary.name)
        self.candidate = root / "candidate"
        self.authority = root / "authority"
        (self.candidate / "tests").mkdir(parents=True)
        self.original = (PROJECT / GATE_RELATIVE).read_bytes()
        shutil.copytree(AUTHORITY_SOURCE, self.authority)
        self.authority_sha256 = hashlib.sha256(
            (self.authority / "authority.json").read_bytes()
        ).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mutate(self, case: str, audit: str | None = None) -> None:
        tree = ast.parse(self.original)
        if case in MUTATIONS.HISTORY_CASES:
            MUTATIONS.history_mutation(tree, case)
        else:
            assert audit is not None
            MUTATIONS.p3_mutation(tree, case, audit)
        ast.fix_missing_locations(tree)
        (self.candidate / GATE_RELATIVE).write_text(ast.unparse(tree) + "\n")

    def refusal_code(self) -> str:
        arguments = SimpleNamespace(
            authority_root=str(self.authority),
            authority_sha256=self.authority_sha256,
            candidate_root=str(self.candidate),
        )
        with self.assertRaises(AUTHORITY.AuthorityRefusal) as raised:
            AUTHORITY.verify(arguments)
        return raised.exception.code

    def test_all_thirty_one_preflight_cases_refuse_by_registered_code(self) -> None:
        history_codes = {
            "history-old-r14-row-removed": "HISTORY_REQUIRED_ROW_REMOVED",
            "history-new-r15-row-removed": "HISTORY_REQUIRED_ROW_REMOVED",
            "history-row-reordered": "HISTORY_PREFIX_CHANGED",
            "history-row-aliased": "HISTORY_REQUIRED_ROW_REMOVED",
            "history-duplicate-id": "HISTORY_DUPLICATE_ROW_ID",
            "history-same-id-semantics": "HISTORY_PREFIX_CHANGED",
            "history-executor-noop": "HISTORY_PROTECTED_DEFINITION_DRIFT",
        }
        cases: list[tuple[str, str | None, str]] = [
            (case, None, history_codes[case]) for case in MUTATIONS.HISTORY_CASES
        ]
        for audit in MUTATIONS.P3_AUDITS:
            cases.extend(
                [
                    (
                        "p3-audit-unreachable-label-retained",
                        audit,
                        "P3_AUDIT_FUNCTION_ABSENT",
                    ),
                    (
                        "p3-assignment-absent-audit-retained",
                        audit,
                        "HISTORY_REQUIRED_ROW_REMOVED",
                    ),
                ]
            )
        self.assertEqual(len(cases), 31)
        for case, audit, expected in cases:
            with self.subTest(case=case, audit=audit):
                self.mutate(case, audit)
                self.assertEqual(self.refusal_code(), expected)

    def test_old_and_new_row_removals_restate_candidate_local_anchors(self) -> None:
        expected_removed = {
            "history-old-r14-row-removed": "wheel.container.trailing",
            "history-new-r15-row-removed": "wheel.module.source-byte",
        }
        for case, removed in expected_removed.items():
            with self.subTest(case=case):
                tree = ast.parse(self.original)
                MUTATIONS.history_mutation(tree, case)
                rows = MUTATIONS.registry(tree)
                identifiers = {row["id"] for row in rows}
                self.assertEqual(len(rows), 13)
                self.assertNotIn(removed, identifiers)
                required = MUTATIONS.frozen_set_items(
                    MUTATIONS.assignment_value(
                        MUTATIONS.assignment(tree, "FROZEN_REQUIRED_ROW_IDS")
                    )
                )
                self.assertEqual(required, identifiers)
                floor = ast.literal_eval(
                    MUTATIONS.assignment_value(
                        MUTATIONS.assignment(tree, "FROZEN_MINIMUM_ROW_COUNT")
                    )
                )
                self.assertEqual(floor, 13)
                observed_digest = MUTATIONS.digest(
                    MUTATIONS.canonical_json(rows, newline=False)
                )
                frozen_digest = ast.literal_eval(
                    MUTATIONS.assignment_value(
                        MUTATIONS.assignment(
                            tree, "FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256"
                        )
                    )
                )
                self.assertEqual(frozen_digest, observed_digest)

    def test_generator_requires_exact_disposable_input(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            MUTATIONS.verify_disposable_gate(PROJECT / GATE_RELATIVE)
        self.assertIn("Git worktree", str(raised.exception))
        target = self.candidate / GATE_RELATIVE
        target.write_bytes(self.original)
        self.assertEqual(MUTATIONS.verify_disposable_gate(target), self.original)
        target.write_bytes(self.original + b"\n")
        with self.assertRaises(SystemExit) as drifted:
            MUTATIONS.verify_disposable_gate(target)
        self.assertIn("input gate identity differs", str(drifted.exception))


if __name__ == "__main__":
    unittest.main()
