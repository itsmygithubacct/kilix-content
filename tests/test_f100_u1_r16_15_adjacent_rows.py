from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "f100_u1_r16_15_adjacent_rows.py"
SPEC = importlib.util.spec_from_file_location("r16_15_adjacent_rows", TOOL)
assert SPEC is not None and SPEC.loader is not None
adjacent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adjacent)


def statement_digest(value: str) -> str:
    return hashlib.sha256(" ".join(value.split()).encode("utf-8")).hexdigest()


STATEMENT = "Measured by the named test mechanism."
ROW = {
    "authority_sources": ["tests/example.py::check"],
    "disposition": "ENFORCED",
    "normalized_claim": "Example claim",
    "population": ["examples:1/1"],
    "row_id": "ADJ-R14-R6-01-EXAMPLE",
    "source_table": "r14-r6-adjacent-property",
    "statement_sha256": statement_digest(STATEMENT),
}
TEST_TABLE_POPULATIONS = {
    "r14-r6-adjacent-property": 13,
    "r14-r9-wheel-sdist-parity": 19,
    "r15-registry-boundary": 6,
}


def ledger() -> dict[str, object]:
    rows = []
    for table, count in TEST_TABLE_POPULATIONS.items():
        prefix = {
            "r14-r6-adjacent-property": "ADJ-R14-R6",
            "r14-r9-wheel-sdist-parity": "ADJ-R14-R9",
            "r15-registry-boundary": "ADJ-R15-B",
        }[table]
        for number in range(1, count + 1):
            row = dict(ROW)
            separator = "" if prefix == "ADJ-R15-B" else "-"
            row["row_id"] = f"{prefix}{separator}{number:02d}-EXAMPLE-{number:02d}"
            row["normalized_claim"] = f"Example claim {table} {number}"
            row["source_table"] = table
            if table == "r14-r6-adjacent-property" and number == 1:
                row["disposition"] = "LIMITATION"
            if table == "r14-r6-adjacent-property" and number == 4:
                row["authority_sources"] = [
                    "tests/check_reproducible_build.py::record_audit"
                ]
                row["row_id"] = "ADJ-R14-R6-04-WHEEL-RECORD"
            rows.append(row)
    return {
        "basis": {"fixture": "unit-only-not-authority"},
        "row_count": len(rows),
        "rows": rows,
        "schema": adjacent.SCHEMA,
        "status": adjacent.STATUS,
    }


def readme(value: dict[str, object]) -> str:
    lines = [
        adjacent.BEGIN,
        "R6 adjacent-property disposition (13/13 inherited R14 rows):",
    ]
    for row in value["rows"]:
        authorities = "<br>".join(
            f"`{locator}`" for locator in row["authority_sources"]
        )
        lines.append(
            f"| {row['row_id']} | {row['disposition']} | "
            f"{row['normalized_claim']} | {authorities} | "
            f"`examples:1/1` | {STATEMENT} |"
        )
    lines.append(adjacent.END)
    return "\n".join(lines) + "\n"


class AdjacentRowParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kilix-r16-15-test-")
        self.source_root = Path(self.temporary.name)
        example = self.source_root / "tests" / "example.py"
        example.parent.mkdir(parents=True)
        example.write_text("def check():\n    return True\n", encoding="utf-8")
        mechanism = self.source_root / "tests" / "check_reproducible_build.py"
        mechanism.write_text("def record_audit():\n    return True\n", encoding="utf-8")
        self.ledger = ledger()
        self.readme = readme(self.ledger)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_38_row_fixture_matches(self) -> None:
        observed = adjacent.validate(
            self.ledger, self.readme, source_root=self.source_root
        )
        self.assertEqual(len(observed), 38)
        report = adjacent.summary(self.ledger, observed)
        expected_digest = hashlib.sha256(
            adjacent._canonical_json(self.ledger)
        ).hexdigest()
        self.assertIn(f"external-ledger-sha256={expected_digest}", report)
        observed_report = report.split("observed-row-ids=", 1)[1]
        self.assertEqual(
            observed_report.split(","),
            [row["row_id"] for row in observed],
        )

    def test_each_of_38_deletions_is_named(self) -> None:
        controls = adjacent.run_self_test(self.ledger, self.readme, self.source_root)
        self.assertEqual(controls["deletion_controls"], 38)
        self.assertEqual(controls["boundary_controls"], 5)
        self.assertEqual(controls["authority_locators"], 38)
        self.assertEqual(controls["authority_locators_required"], 38)

    def test_local_count_restatement_cannot_hide_deleted_row(self) -> None:
        target = self.ledger["rows"][0]["row_id"]
        mutated_ledger = dict(self.ledger)
        mutated_ledger["row_count"] = 37
        mutated_readme = adjacent._replace_row(self.readme, target, None)
        with self.assertRaisesRegex(
            adjacent.AdjacentRowError,
            f"ADJACENT_ROW_MISSING:{target}",
        ):
            adjacent.validate(self.ledger, mutated_readme, source_root=self.source_root)
        with self.assertRaisesRegex(adjacent.AdjacentRowError, "LEDGER_COUNT_MISMATCH"):
            adjacent.validate(
                mutated_ledger, mutated_readme, source_root=self.source_root
            )

    def test_table_denominators_come_from_the_external_ledger(self) -> None:
        self.assertFalse(hasattr(adjacent, "TABLE_POPULATIONS"))
        observed = adjacent.validate(
            self.ledger, self.readme, source_root=self.source_root
        )
        self.assertEqual(len(observed), 38)

    def test_missing_enforced_mechanism_is_named(self) -> None:
        self.ledger["rows"][0]["authority_sources"] = [
            "tests/example.py::missing_check"
        ]
        self.readme = self.readme.replace(
            "`tests/example.py::check`", "`tests/example.py::missing_check`", 1
        )
        row_id = self.ledger["rows"][0]["row_id"]
        self.ledger["rows"][0]["disposition"] = "ENFORCED"
        self.readme = self.readme.replace("| LIMITATION |", "| ENFORCED |", 1)
        with self.assertRaisesRegex(
            adjacent.AdjacentRowError,
            f"ADJACENT_ROW_EFFECT_UNOBSERVED:{row_id}",
        ):
            adjacent.validate(self.ledger, self.readme, source_root=self.source_root)


if __name__ == "__main__":
    unittest.main()
