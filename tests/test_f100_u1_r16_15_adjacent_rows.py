from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
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


def ledger() -> dict[str, object]:
    rows = []
    for table, count in adjacent.TABLE_POPULATIONS.items():
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
            rows.append(row)
    return {
        "basis": {"fixture": "unit-only-not-authority"},
        "row_count": len(rows),
        "rows": rows,
        "schema": adjacent.SCHEMA,
        "status": adjacent.STATUS,
    }


def readme(value: dict[str, object]) -> str:
    lines = [adjacent.BEGIN]
    for row in value["rows"]:
        lines.append(
            f"| {row['row_id']} | {row['disposition']} | "
            f"{row['normalized_claim']} | `tests/example.py::check` | "
            f"`examples:1/1` | {STATEMENT} |"
        )
    lines.append(adjacent.END)
    return "\n".join(lines) + "\n"


class AdjacentRowParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = ledger()
        self.readme = readme(self.ledger)

    def test_exact_38_row_fixture_matches(self) -> None:
        observed = adjacent.validate(self.ledger, self.readme)
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
        controls = adjacent.run_self_test(self.ledger, self.readme)
        self.assertEqual(controls["deletion_controls"], 38)
        self.assertEqual(controls["boundary_controls"], 5)

    def test_local_count_restatement_cannot_hide_deleted_row(self) -> None:
        target = self.ledger["rows"][0]["row_id"]
        mutated_ledger = dict(self.ledger)
        mutated_ledger["row_count"] = 37
        mutated_readme = adjacent._replace_row(self.readme, target, None)
        with self.assertRaisesRegex(
            adjacent.AdjacentRowError,
            f"ADJACENT_ROW_MISSING:{target}",
        ):
            adjacent.validate(self.ledger, mutated_readme)
        with self.assertRaisesRegex(adjacent.AdjacentRowError, "LEDGER_COUNT_MISMATCH"):
            adjacent.validate(mutated_ledger, mutated_readme)


if __name__ == "__main__":
    unittest.main()
