"""Static and causal-control tests for the isolated R16-16 leaf."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests import f100_u1_r16_16_fixtures as fixtures


PROJECT = Path(__file__).resolve().parents[1]
TOOL_PATH = PROJECT / "tools" / "f100_u1_r16_16_accounting.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("r16_16_accounting", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ACCOUNTING = load_tool()


class R16SixteenAccountingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kilix-r16-16-test-")
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        authority_value = fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA)
        self.authority_path = self.root / "external-authority.json"
        self.authority_path.write_bytes(ACCOUNTING.canonical_json(authority_value))
        self.authority_sha256 = ACCOUNTING.sha256(self.authority_path.read_bytes())
        self.authority = ACCOUNTING.load_authority(
            self.authority_path, self.authority_sha256, self.candidate
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mutation_events(self, values=None):
        if values is None:
            values = fixtures.events()
        return tuple(ACCOUNTING.MutationEvent(**value) for value in values)

    def assert_refusal(self, code: str, values) -> None:
        with self.assertRaises(ACCOUNTING.AccountingRefusal) as raised:
            ACCOUNTING.accumulate(self.authority, self.mutation_events(values))
        self.assertEqual(raised.exception.code, code)

    def test_positive_result_separates_all_four_populations(self) -> None:
        result = ACCOUNTING.accumulate(self.authority, self.mutation_events())
        populations = result["populations"]
        expected = {
            "mutation_invocations": 32,
            "presentations": 5,
            "shipped_byte_identities": 2,
            "unique_effect_classes": 12,
        }
        self.assertEqual(set(populations), set(expected))
        for name, denominator in expected.items():
            with self.subTest(population=name):
                self.assertEqual(populations[name]["count"], denominator)
                self.assertEqual(populations[name]["expected_count"], denominator)
                self.assertEqual(len(populations[name]["members"]), denominator)
                self.assertIs(populations[name]["equal"], True)
        self.assertEqual(
            result["derivation"]["families"],
            [
                {
                    "effect_count": 4,
                    "family": "sdist",
                    "invocation_count": 8,
                    "presentation_count": 2,
                },
                {
                    "effect_count": 8,
                    "family": "wheel",
                    "invocation_count": 24,
                    "presentation_count": 3,
                },
            ],
        )
        self.assertEqual(result["derivation"]["invocation_sum"], 32)
        self.assertNotIn("unique-artifact-executions", json.dumps(result))

    def test_count_duplicate_invoke_control(self) -> None:
        values, details = fixtures.control("COUNT-DUP-INVOKE")
        self.assertIs(details["mutation_fired"], True)
        self.assertEqual(details["events_after"], 33)
        self.assert_refusal(
            "COUNT_DUPLICATE_INVOCATION:sdist:sdist.container.gzip-trailing:direct-sdist-1",
            values,
        )

    def test_count_alias_presentation_control(self) -> None:
        values, details = fixtures.control("COUNT-ALIAS-PRESENTATION")
        self.assertIs(details["mutation_fired"], True)
        self.assert_refusal(
            "COUNT_UNEXPECTED_PRESENTATION:direct-sdist-1-alias", values
        )

    def test_count_new_bytes_control(self) -> None:
        values, details = fixtures.control("COUNT-NEW-BYTES")
        self.assertIs(details["mutation_fired"], True)
        self.assert_refusal("COUNT_BYTE_IDENTITY_MISMATCH:wheel-bytes", values)

    def test_count_new_effect_control(self) -> None:
        values, details = fixtures.control("COUNT-NEW-EFFECT")
        self.assertIs(details["mutation_fired"], True)
        self.assert_refusal("COUNT_UNEXPECTED_EFFECT:sdist.unreviewed.effect", values)

    def test_count_delete_effect_control(self) -> None:
        values, details = fixtures.control("COUNT-DELETE-EFFECT")
        self.assertIs(details["mutation_fired"], True)
        self.assertEqual(details["events_after"], 30)
        self.assert_refusal(
            "COUNT_MISSING_EFFECT:sdist.container.gzip-trailing", values
        )

    def test_count_delete_presentation_preserves_total_control(self) -> None:
        values, details = fixtures.control("COUNT-DELETE-PRESENTATION")
        self.assertIs(details["mutation_fired"], True)
        self.assertEqual(details["events_after"], 32)
        self.assert_refusal("COUNT_MISSING_PRESENTATION:direct-wheel-2", values)

    def test_count_same_digest_control(self) -> None:
        values, details = fixtures.control("COUNT-SAME-DIGEST")
        self.assertIs(details["mutation_fired"], True)
        self.assertIs(details["record_population_changed"], True)
        self.assertEqual(details["changed_event_count"], 8)
        prestate = details["prestate_events"]
        self.assertNotEqual(
            ACCOUNTING.canonical_json(prestate),
            ACCOUNTING.canonical_json(values),
        )
        self.assert_refusal("COUNT_BYTE_IDENTITY_MISMATCH:wheel-bytes", prestate)
        result = ACCOUNTING.accumulate(self.authority, self.mutation_events(values))
        presentations = result["populations"]["presentations"]
        identities = result["populations"]["shipped_byte_identities"]
        wheel_presentations = [
            member for member in presentations["members"] if member["family"] == "wheel"
        ]
        self.assertEqual(len(wheel_presentations), 3)
        self.assertEqual(
            len({row["artifact_sha256"] for row in wheel_presentations}), 1
        )
        self.assertEqual(identities["count"], 2)

    def test_all_seven_controls_change_the_retained_record_population(self) -> None:
        cases = (
            "COUNT-DUP-INVOKE",
            "COUNT-ALIAS-PRESENTATION",
            "COUNT-NEW-BYTES",
            "COUNT-NEW-EFFECT",
            "COUNT-DELETE-EFFECT",
            "COUNT-DELETE-PRESENTATION",
            "COUNT-SAME-DIGEST",
        )
        changed = 0
        for case in cases:
            with self.subTest(case=case):
                _, details = fixtures.control(case)
                self.assertIs(details["mutation_fired"], True)
                self.assertIs(details["record_population_changed"], True)
                changed += 1
        self.assertEqual(changed, len(cases))

    def test_missing_single_invocation_refuses_by_exact_member(self) -> None:
        values = fixtures.events()
        values.pop(0)
        self.assert_refusal(
            "COUNT_MISSING_INVOCATION:sdist:sdist.container.gzip-trailing:direct-sdist-1",
            values,
        )

    def test_one_presentation_cannot_report_two_digests(self) -> None:
        values = fixtures.events()
        values[0]["artifact_sha256"] = "4" * 64
        self.assert_refusal(
            "COUNT_PRESENTATION_DIGEST_AMBIGUOUS:direct-sdist-1", values
        )

    def test_two_byte_groups_cannot_collapse_to_one_digest(self) -> None:
        values = fixtures.events()
        for value in values:
            value["artifact_sha256"] = fixtures.SDIST_SHA256
        self.assert_refusal(
            "COUNT_BYTE_IDENTITY_COLLISION:sdist-bytes,wheel-bytes", values
        )

    def test_authority_requires_exact_digest(self) -> None:
        with self.assertRaises(ACCOUNTING.AccountingRefusal) as raised:
            ACCOUNTING.load_authority(self.authority_path, "0" * 64, self.candidate)
        self.assertTrue(
            raised.exception.code.startswith("COUNT_AUTHORITY_DIGEST_MISMATCH:")
        )

    def test_authority_requires_canonical_bytes(self) -> None:
        value = fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA)
        path = self.root / "noncanonical-authority.json"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaises(ACCOUNTING.AccountingRefusal) as raised:
            ACCOUNTING.load_authority(
                path, ACCOUNTING.sha256(path.read_bytes()), self.candidate
            )
        self.assertEqual(raised.exception.code, "COUNT_AUTHORITY_JSON_NONCANONICAL")

    def test_authority_refuses_duplicate_json_keys(self) -> None:
        path = self.root / "duplicate-authority.json"
        path.write_bytes(b'{"families":[],"schema":"x","schema":"y"}\n')
        with self.assertRaises(ACCOUNTING.AccountingRefusal) as raised:
            ACCOUNTING.load_authority(
                path, ACCOUNTING.sha256(path.read_bytes()), self.candidate
            )
        self.assertEqual(
            raised.exception.code, "COUNT_AUTHORITY_DUPLICATE_JSON_KEY:schema"
        )

    def test_candidate_local_authority_is_refused(self) -> None:
        path = self.candidate / "self-authority.json"
        path.write_bytes(
            ACCOUNTING.canonical_json(fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA))
        )
        with self.assertRaises(ACCOUNTING.AccountingRefusal) as raised:
            ACCOUNTING.load_authority(
                path, ACCOUNTING.sha256(path.read_bytes()), self.candidate
            )
        self.assertEqual(raised.exception.code, "COUNT_AUTHORITY_INSIDE_CANDIDATE")

    def test_event_file_binds_authority_and_is_canonical(self) -> None:
        event_path = self.root / "events.json"
        event_path.write_bytes(
            ACCOUNTING.canonical_json(
                {
                    "authority_sha256": self.authority_sha256,
                    "events": fixtures.events(),
                    "schema": ACCOUNTING.EVENTS_SCHEMA,
                }
            )
        )
        loaded = ACCOUNTING.load_events(event_path, self.authority_sha256)
        self.assertEqual(len(loaded), 32)
        value = json.loads(event_path.read_bytes())
        value["authority_sha256"] = "0" * 64
        event_path.write_bytes(ACCOUNTING.canonical_json(value))
        with self.assertRaises(ACCOUNTING.AccountingRefusal) as raised:
            ACCOUNTING.load_events(event_path, self.authority_sha256)
        self.assertEqual(raised.exception.code, "COUNT_EVENTS_AUTHORITY_MISMATCH")

    def test_pipe_bytes_decode_without_a_preservation_file(self) -> None:
        raw = ACCOUNTING.canonical_json(
            {
                "authority_sha256": self.authority_sha256,
                "events": fixtures.events(),
                "schema": ACCOUNTING.EVENTS_SCHEMA,
            }
        )
        loaded = ACCOUNTING.decode_events(raw, self.authority_sha256)
        self.assertEqual(len(loaded), 32)
        result = ACCOUNTING.accumulate(self.authority, loaded)
        self.assertEqual(result["populations"]["mutation_invocations"]["count"], 32)

    def test_cli_writes_canonical_result_once(self) -> None:
        event_path = self.root / "events.json"
        output = self.root / "result.json"
        event_path.write_bytes(
            ACCOUNTING.canonical_json(
                {
                    "authority_sha256": self.authority_sha256,
                    "events": fixtures.events(),
                    "schema": ACCOUNTING.EVENTS_SCHEMA,
                }
            )
        )
        command = [
            sys.executable,
            str(TOOL_PATH),
            "--authority",
            str(self.authority_path),
            "--authority-sha256",
            self.authority_sha256,
            "--candidate-root",
            str(self.candidate),
            "--events",
            str(event_path),
            "--output",
            str(output),
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("invocations=32/32", completed.stdout)
        self.assertIn("effects=12/12", completed.stdout)
        self.assertIn("presentations=5/5", completed.stdout)
        self.assertIn("byte_identities=2/2", completed.stdout)
        value = json.loads(output.read_bytes())
        self.assertEqual(output.read_bytes(), ACCOUNTING.canonical_json(value))
        repeated = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(repeated.returncode, 2)
        self.assertEqual(
            repeated.stderr.strip(), "R16_16_REFUSE:COUNT_OUTPUT_ALREADY_EXISTS"
        )


if __name__ == "__main__":
    unittest.main()
