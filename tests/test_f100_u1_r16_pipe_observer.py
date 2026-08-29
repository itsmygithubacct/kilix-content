"""Tests for OD-20-compliant R16 pipe observation."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from tests import f100_u1_r16_16_fixtures as fixtures


PROJECT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


OBSERVER = load_module(
    "f100_u1_r16_test_pipe_observer",
    PROJECT / "tools" / "f100_u1_r16_pipe_observer.py",
)
R16_14 = load_module(
    "f100_u1_r16_test_pipe_r16_14",
    PROJECT / "tools" / "r16_14" / "sdist_call_set.py",
)
ACCOUNTING = load_module(
    "f100_u1_r16_test_pipe_r16_16",
    PROJECT / "tools" / "f100_u1_r16_16_accounting.py",
)


class R16PipeObserverTests(unittest.TestCase):
    def r16_14_bytes(self) -> bytes:
        ledger = R16_14.load_ledger(
            PROJECT / "tools" / "r16_14" / "fixtures" / "sdist-call-ledger.json"
        )
        return R16_14.canonical_json_bytes(
            {
                "events": R16_14.expected_effect_events(ledger),
                "schema_version": "r16-14-sdist-effect-trace-v1",
            }
        )

    def r16_16_bytes(self) -> bytes:
        authority = fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA)
        authority_sha256 = ACCOUNTING.sha256(ACCOUNTING.canonical_json(authority))
        return ACCOUNTING.canonical_json(
            {
                "authority_sha256": authority_sha256,
                "events": fixtures.events(),
                "schema": ACCOUNTING.EVENTS_SCHEMA,
            }
        )

    def test_child_records_are_observed_directly_from_two_pipes(self) -> None:
        first = self.r16_14_bytes()
        second = self.r16_16_bytes()
        script = (
            "import os;"
            "a=bytes.fromhex(os.environ['FIRST']);"
            "b=bytes.fromhex(os.environ['SECOND']);"
            "os.write(int(os.environ['KILIX_F100_R16_14_TRACE_FD']),a);"
            "os.write(int(os.environ['KILIX_F100_R16_16_EVENTS_FD']),b);"
            "print('reproducible offline build and package audit: PASS (test)')"
        )
        environment = dict(os.environ)
        environment.update({"FIRST": first.hex(), "SECOND": second.hex()})
        result = OBSERVER.run_with_channels(
            [sys.executable, "-c", script],
            cwd=PROJECT,
            environment=environment,
            authority_sha256="0" * 64,
        )
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2], first)
        self.assertEqual(result[3], second)

    def test_r16_14_pipe_parser_requires_canonical_bytes(self) -> None:
        with self.assertRaises(OBSERVER.ObserverRefusal) as raised:
            OBSERVER.decode_r16_14(
                json.dumps(json.loads(self.r16_14_bytes()), indent=2).encode(),
                R16_14,
            )
        self.assertEqual(raised.exception.code, "OBSERVER_R16_14_NONCANONICAL")

    def test_r16_16_pipe_parser_and_accumulator_need_no_event_file(self) -> None:
        raw = self.r16_16_bytes()
        value = json.loads(raw)
        authority_value = fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA)
        authority = ACCOUNTING.AccountingAuthority(
            value["authority_sha256"],
            tuple(
                ACCOUNTING.FamilyAuthority(
                    family=row["id"],
                    effect_ids=tuple(row["effect_ids"]),
                    presentation_ids=tuple(row["presentation_ids"]),
                    byte_identity_group=row["byte_identity_group"],
                )
                for row in authority_value["families"]
            ),
        )
        events = ACCOUNTING.decode_events(raw, value["authority_sha256"])
        result = ACCOUNTING.accumulate(authority, events)
        populations = result["populations"]
        self.assertEqual(populations["mutation_invocations"]["count"], 32)
        self.assertEqual(populations["unique_effect_classes"]["count"], 12)
        self.assertEqual(populations["presentations"]["count"], 5)
        self.assertEqual(populations["shipped_byte_identities"]["count"], 2)

    def test_execution_gate_must_match_the_static_candidate_gate(self) -> None:
        expected = OBSERVER.sha256(
            (PROJECT / "tests" / "check_reproducible_build.py").read_bytes()
        )
        self.assertEqual(OBSERVER.verify_execution_gate(PROJECT, expected), expected)
        with tempfile.TemporaryDirectory(prefix="kilix-r16-pipe-drift-") as name:
            root = Path(name)
            (root / "tests").mkdir()
            (root / "tests" / "check_reproducible_build.py").write_bytes(b"drift\n")
            with self.assertRaises(OBSERVER.ObserverRefusal) as raised:
                OBSERVER.verify_execution_gate(root, expected)
        self.assertTrue(
            raised.exception.code.startswith("OBSERVER_EXECUTION_GATE_DRIFT:")
        )


if __name__ == "__main__":
    unittest.main()
