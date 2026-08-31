#!/usr/bin/env python3
"""Compare R16-15 README rows with a separately supplied frozen ledger.

This is a leaf checker.  It does not locate an authority ledger inside the
candidate, run the release gate, or promote its result to acceptance.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_README = ROOT / "contracts" / "README.md"
SCHEMA = "kilix.f100.r16-15.adjacent-row-ledger/v1"
STATUS = "external-preimplementation-freeze"
BEGIN = "<!-- R16-15-ADJACENT-ROWS:BEGIN -->"
END = "<!-- R16-15-ADJACENT-ROWS:END -->"
DISPOSITIONS = {"ENFORCED", "LIMITATION", "OUT_OF_SCOPE", "NOT_TRANSFERABLE"}
ROW_KEYS = {
    "authority_sources",
    "disposition",
    "normalized_claim",
    "population",
    "row_id",
    "source_table",
    "statement_sha256",
}
SOURCE_TABLES = (
    "r14-r6-adjacent-property",
    "r14-r9-wheel-sdist-parity",
    "r15-registry-boundary",
)
ROW_ID = re.compile(r"^ADJ-(?:R14-R[69]-\d{2}|R15-B\d{2})-[A-Z0-9-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdjacentRowError(ValueError):
    """The candidate row population disagrees with external authority."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdjacentRowError(f"LEDGER_DUPLICATE_KEY:{key}")
        value[key] = item
    return value


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def load_ledger(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AdjacentRowError(f"LEDGER_INVALID:{error}") from error
    if not isinstance(value, dict):
        raise AdjacentRowError("LEDGER_SHAPE:top-level-not-object")
    if raw != _canonical_json(value):
        raise AdjacentRowError("LEDGER_NONCANONICAL")
    validate_ledger(value)
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise AdjacentRowError(f"LEDGER_SHAPE:{label}")
    return value


def validate_ledger(value: dict[str, Any]) -> None:
    if set(value) != {"basis", "row_count", "rows", "schema", "status"}:
        raise AdjacentRowError("LEDGER_SHAPE:top-level-keys")
    if value["schema"] != SCHEMA or value["status"] != STATUS:
        raise AdjacentRowError("LEDGER_IDENTITY")
    if not isinstance(value["basis"], dict) or not value["basis"]:
        raise AdjacentRowError("LEDGER_SHAPE:basis")
    if type(value["row_count"]) is not int or value["row_count"] <= 0:
        raise AdjacentRowError("LEDGER_SHAPE:row-count")
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) != value["row_count"]:
        raise AdjacentRowError("LEDGER_COUNT_MISMATCH")
    identifiers: list[str] = []
    claims: list[tuple[str, str]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != ROW_KEYS:
            raise AdjacentRowError(f"LEDGER_SHAPE:row-{index + 1}")
        row_id = row["row_id"]
        if not isinstance(row_id, str) or not ROW_ID.fullmatch(row_id):
            raise AdjacentRowError(f"LEDGER_ROW_ID:{row_id!r}")
        if row["disposition"] not in DISPOSITIONS:
            raise AdjacentRowError(f"LEDGER_DISPOSITION:{row_id}")
        if not isinstance(row["normalized_claim"], str) or not row["normalized_claim"]:
            raise AdjacentRowError(f"LEDGER_CLAIM:{row_id}")
        if row["source_table"] not in SOURCE_TABLES:
            raise AdjacentRowError(f"LEDGER_SOURCE_TABLE:{row_id}")
        if row["source_table"] != _source_table(row_id):
            raise AdjacentRowError(f"LEDGER_SOURCE_TABLE:{row_id}")
        if not isinstance(row["statement_sha256"], str) or not SHA256.fullmatch(
            row["statement_sha256"]
        ):
            raise AdjacentRowError(f"LEDGER_STATEMENT_DIGEST:{row_id}")
        _string_list(row["authority_sources"], f"authority-sources:{row_id}")
        _string_list(row["population"], f"population:{row_id}")
        identifiers.append(row_id)
        claims.append((row["source_table"], row["normalized_claim"]))
    if len(identifiers) != len(set(identifiers)):
        raise AdjacentRowError("LEDGER_DUPLICATE_ROW_ID")
    if len(claims) != len(set(claims)):
        raise AdjacentRowError("LEDGER_DUPLICATE_CLAIM")


def _source_table(row_id: str) -> str:
    if row_id.startswith("ADJ-R14-R6-"):
        return "r14-r6-adjacent-property"
    if row_id.startswith("ADJ-R14-R9-"):
        return "r14-r9-wheel-sdist-parity"
    if row_id.startswith("ADJ-R15-B"):
        return "r15-registry-boundary"
    raise AdjacentRowError(f"README_ROW_ID:{row_id}")


def _tokens(cell: str, row_id: str, label: str) -> list[str]:
    values: list[str] = []
    for raw in cell.split("<br>"):
        token = raw.strip()
        if len(token) < 3 or token[0] != "`" or token[-1] != "`":
            raise AdjacentRowError(f"README_{label}_SHAPE:{row_id}")
        values.append(token[1:-1])
    if (
        not values
        or len(values) != len(set(values))
        or any(not value for value in values)
    ):
        raise AdjacentRowError(f"README_{label}_SHAPE:{row_id}")
    return values


def _statement_digest(cell: str) -> str:
    normalized = " ".join(cell.split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def parse_readme_text(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    if lines.count(BEGIN) != 1 or lines.count(END) != 1:
        raise AdjacentRowError("README_BOUNDARY_COUNT")
    begin = lines.index(BEGIN)
    end = lines.index(END)
    if begin >= end:
        raise AdjacentRowError("README_BOUNDARY_ORDER")
    rows: list[dict[str, Any]] = []
    for line in lines[begin + 1 : end]:
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        first = cells[0]
        if first == "Row ID" or all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        if not first.startswith("ADJ-"):
            raise AdjacentRowError(f"README_UNIDENTIFIED_ROW:{first}")
        if len(cells) != 6:
            raise AdjacentRowError(f"README_ROW_SHAPE:{first}")
        row_id, disposition, claim, authority, population, statement = cells
        rows.append(
            {
                "authority_sources": _tokens(authority, row_id, "AUTHORITY"),
                "disposition": disposition,
                "normalized_claim": claim,
                "population": _tokens(population, row_id, "POPULATION"),
                "row_id": row_id,
                "source_table": _source_table(row_id),
                "statement_sha256": _statement_digest(statement),
            }
        )
    return rows


def parse_readme(path: Path) -> list[dict[str, Any]]:
    try:
        return parse_readme_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise AdjacentRowError(f"README_INVALID:{error}") from error


def _top_level_symbols(raw: bytes, relative: str) -> set[str]:
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=relative)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise AdjacentRowError(
            f"AUTHORITY_SOURCE_INVALID:{relative}:{error}"
        ) from error
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef)):
            symbols.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    symbols.add(target.id)
    return symbols


def verify_authority_sources(
    ledger: dict[str, Any],
    source_root: Path,
    *,
    source_overrides: dict[str, bytes] | None = None,
) -> dict[str, int]:
    """Resolve every frozen source locator without importing the candidate."""
    root = source_root.resolve(strict=True)
    overrides = source_overrides or {}
    cache: dict[str, tuple[bytes, set[str] | None]] = {}
    resolved = 0
    required = sum(len(row["authority_sources"]) for row in ledger["rows"])
    for row in ledger["rows"]:
        row_id = row["row_id"]
        for locator in row["authority_sources"]:
            relative, separator, symbol = locator.partition("::")
            relative_path = Path(relative)
            if (
                not relative
                or relative_path.is_absolute()
                or ".." in relative_path.parts
                or (separator and not symbol)
            ):
                raise AdjacentRowError(
                    f"ADJACENT_ROW_AUTHORITY_UNRESOLVED:{row_id}:{locator}"
                )
            if relative not in cache:
                target = (root / relative_path).resolve(strict=False)
                try:
                    target.relative_to(root)
                except ValueError as error:
                    raise AdjacentRowError(
                        f"ADJACENT_ROW_AUTHORITY_UNRESOLVED:{row_id}:{locator}"
                    ) from error
                try:
                    raw = overrides.get(relative, target.read_bytes())
                except OSError as error:
                    code = (
                        "ADJACENT_ROW_EFFECT_UNOBSERVED"
                        if row["disposition"] == "ENFORCED"
                        else "ADJACENT_ROW_AUTHORITY_UNRESOLVED"
                    )
                    raise AdjacentRowError(f"{code}:{row_id}") from error
                cache[relative] = (raw, None)
            raw, symbols = cache[relative]
            if separator:
                if symbols is None:
                    symbols = _top_level_symbols(raw, relative)
                    cache[relative] = (raw, symbols)
                if symbol not in symbols:
                    code = (
                        "ADJACENT_ROW_EFFECT_UNOBSERVED"
                        if row["disposition"] == "ENFORCED"
                        else "ADJACENT_ROW_AUTHORITY_UNRESOLVED"
                    )
                    suffix = f":{locator}" if code.endswith("UNRESOLVED") else ""
                    raise AdjacentRowError(f"{code}:{row_id}{suffix}")
            resolved += 1
    if resolved != required:
        raise AdjacentRowError(
            f"AUTHORITY_SOURCE_POPULATION:expected={required}:observed={resolved}"
        )
    return {"required": required, "resolved": resolved}


def compare_rows(ledger: dict[str, Any], observed: list[dict[str, Any]]) -> None:
    expected_rows = ledger["rows"]
    expected = {row["row_id"]: row for row in expected_rows}
    observed_map: dict[str, dict[str, Any]] = {}
    for row in observed:
        row_id = row["row_id"]
        if row_id in observed_map:
            raise AdjacentRowError(f"ADJACENT_ROW_DUPLICATE:{row_id}")
        observed_map[row_id] = row
    missing = [
        row["row_id"] for row in expected_rows if row["row_id"] not in observed_map
    ]
    if missing:
        raise AdjacentRowError(f"ADJACENT_ROW_MISSING:{missing[0]}")
    extra = [row["row_id"] for row in observed if row["row_id"] not in expected]
    if extra:
        raise AdjacentRowError(f"ADJACENT_ROW_UNEXPECTED:{extra[0]}")
    checks = (
        ("disposition", "ADJACENT_ROW_DISPOSITION_MISMATCH"),
        ("normalized_claim", "ADJACENT_ROW_CLAIM_MISMATCH"),
        ("authority_sources", "ADJACENT_ROW_AUTHORITY_MISMATCH"),
        ("population", "ADJACENT_ROW_POPULATION_MISMATCH"),
        ("source_table", "ADJACENT_ROW_TABLE_MISMATCH"),
        ("statement_sha256", "ADJACENT_ROW_STATEMENT_MISMATCH"),
    )
    for row in expected_rows:
        row_id = row["row_id"]
        for field, code in checks:
            if observed_map[row_id][field] != row[field]:
                raise AdjacentRowError(f"{code}:{row_id}")
    if len(observed) != ledger["row_count"]:
        raise AdjacentRowError(
            f"ADJACENT_ROW_COUNT_MISMATCH:expected={ledger['row_count']}:observed={len(observed)}"
        )


def validate(
    ledger: dict[str, Any],
    readme_text: str,
    *,
    source_root: Path | None = None,
    source_overrides: dict[str, bytes] | None = None,
) -> list[dict[str, Any]]:
    validate_ledger(ledger)
    rows = parse_readme_text(readme_text)
    compare_rows(ledger, rows)
    if source_root is not None:
        verify_authority_sources(
            ledger,
            source_root,
            source_overrides=source_overrides,
        )
    return rows


def _replace_row(text: str, row_id: str, replacement: str | None) -> str:
    lines = text.splitlines(keepends=True)
    matches = [
        index for index, line in enumerate(lines) if line.startswith(f"| {row_id} |")
    ]
    if len(matches) != 1:
        raise AdjacentRowError(f"SELF_TEST_TARGET_COUNT:{row_id}:{len(matches)}")
    index = matches[0]
    if replacement is None:
        del lines[index]
    else:
        lines[index] = replacement
    return "".join(lines)


def run_self_test(
    ledger: dict[str, Any], readme_text: str, source_root: Path
) -> dict[str, int]:
    baseline = validate(ledger, readme_text, source_root=source_root)
    authority_sources = verify_authority_sources(ledger, source_root)

    def refuses(
        expected: str,
        mutated_readme: str,
        *,
        source_overrides: dict[str, bytes] | None = None,
    ) -> bool:
        try:
            validate(
                ledger,
                mutated_readme,
                source_root=source_root,
                source_overrides=source_overrides,
            )
        except AdjacentRowError as error:
            return str(error) == expected
        return False

    deletion_rejections = 0
    for row in ledger["rows"]:
        row_id = row["row_id"]
        mutated = _replace_row(readme_text, row_id, None)
        if refuses(f"ADJACENT_ROW_MISSING:{row_id}", mutated):
            deletion_rejections += 1
    if deletion_rejections != ledger["row_count"]:
        raise AdjacentRowError(
            "SELF_TEST_DELETION_CONTROLS:"
            f"expected={ledger['row_count']}:observed={deletion_rejections}"
        )

    control_families: set[str] = set()
    local_row_id = baseline[0]["row_id"]
    r6_count = sum(
        row["source_table"] == "r14-r6-adjacent-property" for row in ledger["rows"]
    )
    local_anchor = f"{r6_count}/{r6_count} inherited R14 rows"
    restated_anchor = f"{r6_count - 1}/{r6_count - 1} inherited R14 rows"
    if readme_text.count(local_anchor) != 1:
        raise AdjacentRowError(
            f"SELF_TEST_LOCAL_ANCHOR:expected=1:observed={readme_text.count(local_anchor)}"
        )
    locally_restated = _replace_row(readme_text, local_row_id, None).replace(
        local_anchor, restated_anchor, 1
    )
    if refuses(f"ADJACENT_ROW_MISSING:{local_row_id}", locally_restated):
        control_families.add("local-restatement")

    limitation = next(row for row in baseline if row["disposition"] == "LIMITATION")
    row_id = limitation["row_id"]
    line = next(
        line
        for line in readme_text.splitlines(keepends=True)
        if line.startswith(f"| {row_id} |")
    )
    mutated_line = line.replace("| LIMITATION |", "| ENFORCED |", 1)
    if refuses(
        f"ADJACENT_ROW_DISPOSITION_MISMATCH:{row_id}",
        _replace_row(readme_text, row_id, mutated_line),
    ):
        control_families.add("disposition-flip")

    target = baseline[-6]
    row_id = target["row_id"]
    line = next(
        line
        for line in readme_text.splitlines(keepends=True)
        if line.startswith(f"| {row_id} |")
    )
    old = f"`{target['authority_sources'][0]}`"
    mutated_line = line.replace(
        old, "`tests/check_reproducible_build.py::wrong-authority`", 1
    )
    if refuses(
        f"ADJACENT_ROW_AUTHORITY_MISMATCH:{row_id}",
        _replace_row(readme_text, row_id, mutated_line),
    ):
        control_families.add("authority-retarget")

    duplicate_id = baseline[0]["row_id"]
    duplicate_line = next(
        line
        for line in readme_text.splitlines(keepends=True)
        if line.startswith(f"| {duplicate_id} |")
    )
    duplicated = readme_text.replace(duplicate_line, duplicate_line + duplicate_line, 1)
    duplicate_refused = refuses(f"ADJACENT_ROW_DUPLICATE:{duplicate_id}", duplicated)

    alias_id = "ADJ-R14-R6-99-ALIAS"
    alias_line = duplicate_line.replace(duplicate_id, alias_id, 1)
    aliased = readme_text.replace(END, alias_line + END, 1)
    alias_refused = refuses(f"ADJACENT_ROW_UNEXPECTED:{alias_id}", aliased)
    if duplicate_refused and alias_refused:
        control_families.add("duplicate-alias")

    mechanism_row_id = "ADJ-R14-R6-04-WHEEL-RECORD"
    mechanism_locator = "tests/check_reproducible_build.py::record_audit"
    mechanism_row = next(
        row for row in ledger["rows"] if row["row_id"] == mechanism_row_id
    )
    if mechanism_locator not in mechanism_row["authority_sources"]:
        raise AdjacentRowError("SELF_TEST_MECHANISM_LOCATOR:expected=1:observed=0")
    mechanism_path = mechanism_locator.split("::", 1)[0]
    mechanism_raw = (source_root / mechanism_path).read_bytes()
    needle = b"def record_audit("
    if mechanism_raw.count(needle) != 1:
        raise AdjacentRowError(
            "SELF_TEST_MECHANISM_MUTATION:"
            f"expected=1:observed={mechanism_raw.count(needle)}"
        )
    mechanism_mutated = mechanism_raw.replace(needle, b"def removed_record_audit(", 1)
    if refuses(
        f"ADJACENT_ROW_EFFECT_UNOBSERVED:{mechanism_row_id}",
        readme_text,
        source_overrides={mechanism_path: mechanism_mutated},
    ):
        control_families.add("mechanism-removal")

    controls = len(control_families)
    if controls != 5:
        raise AdjacentRowError(
            f"SELF_TEST_BOUNDARY_CONTROLS:expected=5:observed={controls}"
        )
    return {
        "authority_locators": authority_sources["resolved"],
        "authority_locators_required": authority_sources["required"],
        "boundary_controls": controls,
        "deletion_controls": deletion_rejections,
        "rows": len(baseline),
    }


def summary(
    ledger: dict[str, Any],
    observed: list[dict[str, Any]],
    controls: dict[str, int] | None = None,
) -> str:
    rows = ledger["rows"]
    ledger_sha256 = hashlib.sha256(_canonical_json(ledger)).hexdigest()
    observed_ids = ",".join(row["row_id"] for row in observed)
    by_table = {
        table: sum(row["source_table"] == table for row in rows)
        for table in SOURCE_TABLES
    }
    message = (
        "PASS (R16-15 static facility only; trusted-path acceptance not run): "
        f"{len(rows)}/{ledger['row_count']} rows match; "
        f"{by_table['r14-r6-adjacent-property']}/{by_table['r14-r6-adjacent-property']} inherited R6 rows; "
        f"{by_table['r14-r9-wheel-sdist-parity']}/{by_table['r14-r9-wheel-sdist-parity']} inherited R9 rows; "
        f"{by_table['r15-registry-boundary']}/{by_table['r15-registry-boundary']} R15 boundary rows; "
        f"external-ledger-sha256={ledger_sha256}; "
        f"observed-row-ids={observed_ids}"
    )
    if controls is not None:
        message += (
            f"; {controls['deletion_controls']}/{ledger['row_count']} deletion controls refused by row ID; "
            f"{controls['boundary_controls']}/5 distinct local-restatement/disposition/authority/duplicate-alias/mechanism-removal controls refused; "
            f"{controls['authority_locators']}/{controls['authority_locators_required']} authority locators resolved"
        )
    return message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--readme", type=Path, default=DEFAULT_README)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    ledger = load_ledger(arguments.ledger.resolve(strict=True))
    readme_text = arguments.readme.resolve(strict=True).read_text(encoding="utf-8")
    observed = validate(ledger, readme_text, source_root=ROOT)
    controls = run_self_test(ledger, readme_text, ROOT) if arguments.self_test else None
    print(summary(ledger, observed, controls))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AdjacentRowError, OSError, UnicodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
