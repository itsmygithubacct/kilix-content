"""Integration checks for the R16-14 trace and R16-16 accounting emitters."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import f100_u1_r16_16_fixtures as fixtures
from tools.r16_14 import sdist_call_set


PROJECT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GATE = load_module("f100_u1_r16_integrated_gate", PROJECT / "tests/check_reproducible_build.py")
ACCOUNTING = load_module(
    "f100_u1_r16_integrated_accounting",
    PROJECT / "tools/f100_u1_r16_16_accounting.py",
)


class R16GateIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_r16_14 = list(GATE._R16_14_SDIST_EFFECT_EVENTS)
        self.original_r16_16 = list(GATE._R16_16_ACCOUNTING_EVENTS)

    def tearDown(self) -> None:
        GATE._R16_14_SDIST_EFFECT_EVENTS[:] = self.original_r16_14
        GATE._R16_16_ACCOUNTING_EVENTS[:] = self.original_r16_16

    def read_pipe(self, fd: int) -> bytes:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        os.close(fd)
        return b"".join(chunks)

    def test_gate_mirrors_both_leaf_populations_exactly(self) -> None:
        ledger = sdist_call_set.load_ledger(
            PROJECT / "tools/r16_14/fixtures/sdist-call-ledger.json"
        )
        expected_calls = {
            row["identity"]: row
            for row in sdist_call_set.expected_effect_events(ledger)
        }
        self.assertEqual(GATE.R16_14_SDIST_CALL_EVENTS, expected_calls)

        authority = fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA)
        effect_ids = {
            effect
            for family in authority["families"]
            for effect in family["effect_ids"]
        }
        presentation_ids = {
            presentation
            for family in authority["families"]
            for presentation in family["presentation_ids"]
        }
        self.assertEqual(set(GATE.R16_16_ACCOUNTING_EFFECT_IDS), effect_ids)
        self.assertEqual(set(GATE.R16_16_PRESENTATION_IDS.values()), presentation_ids)

    def test_external_records_round_trip_through_both_leaf_consumers(self) -> None:
        ledger = sdist_call_set.load_ledger(
            PROJECT / "tools/r16_14/fixtures/sdist-call-ledger.json"
        )
        GATE._R16_14_SDIST_EFFECT_EVENTS[:] = list(
            GATE.R16_14_SDIST_CALL_EVENTS.values()
        )
        GATE._R16_16_ACCOUNTING_EVENTS[:] = fixtures.events()
        self.assertEqual(
            GATE.r16_16_accounting_populations(),
            {
                "byte_identities": 2,
                "effect_classes": 12,
                "mutation_invocations": 32,
                "presentations": 5,
            },
        )

        with tempfile.TemporaryDirectory(prefix="kilix-r16-integration-") as name:
            root = Path(name)
            authority_path = root / "r16-16-authority.json"
            authority_path.write_bytes(
                ACCOUNTING.canonical_json(fixtures.authority(ACCOUNTING.AUTHORITY_SCHEMA))
            )
            authority_sha256 = hashlib.sha256(authority_path.read_bytes()).hexdigest()
            r16_14_read, r16_14_write = os.pipe()
            r16_16_read, r16_16_write = os.pipe()
            environment = {
                "KILIX_F100_R16_14_TRACE_FD": str(r16_14_write),
                "KILIX_F100_R16_16_ACCOUNTING_AUTHORITY_SHA256": authority_sha256,
                "KILIX_F100_R16_16_EVENTS_FD": str(r16_16_write),
            }
            with patch.dict(os.environ, environment, clear=True):
                GATE.write_r16_runtime_records()

            r16_14_bytes = self.read_pipe(r16_14_read)
            r16_16_bytes = self.read_pipe(r16_16_read)
            r16_14_value = json.loads(r16_14_bytes)
            self.assertEqual(
                r16_14_bytes,
                GATE.canonical_json(r16_14_value, newline=True),
            )
            self.assertEqual(
                sdist_call_set.verify_effect_trace(ledger, r16_14_value)[
                    "observed_effect_count"
                ],
                9,
            )

            authority = ACCOUNTING.load_authority(
                authority_path,
                authority_sha256,
                PROJECT,
            )
            events = ACCOUNTING.decode_events(r16_16_bytes, authority_sha256)
            result = ACCOUNTING.accumulate(authority, events)
            populations = result["populations"]
            self.assertEqual(populations["mutation_invocations"]["count"], 32)
            self.assertEqual(populations["unique_effect_classes"]["count"], 12)
            self.assertEqual(populations["presentations"]["count"], 5)
            self.assertEqual(populations["shipped_byte_identities"]["count"], 2)

    def test_partial_external_record_configuration_refuses(self) -> None:
        with patch.dict(
            os.environ,
            {"KILIX_F100_R16_14_TRACE_FD": "9"},
            clear=True,
        ):
            with self.assertRaisesRegex(
                SystemExit,
                "R16 external runtime record configuration is incomplete: 0/3 accepted",
            ):
                GATE.write_r16_runtime_records()

    def test_legacy_path_configuration_refuses_under_od20(self) -> None:
        with patch.dict(
            os.environ,
            {"KILIX_F100_R16_14_TRACE_OUTPUT": "/tmp/r16-14-trace.json"},
            clear=True,
        ):
            with self.assertRaisesRegex(
                SystemExit,
                "R16 pathname runtime-record channels violate OD-20: "
                "legacy-paths-accepted=0/2",
            ):
                GATE.write_r16_runtime_records()

    def test_regular_file_channel_refuses_under_od20(self) -> None:
        with tempfile.TemporaryFile() as first, tempfile.TemporaryFile() as second:
            environment = {
                "KILIX_F100_R16_14_TRACE_FD": str(first.fileno()),
                "KILIX_F100_R16_16_ACCOUNTING_AUTHORITY_SHA256": "0" * 64,
                "KILIX_F100_R16_16_EVENTS_FD": str(second.fileno()),
            }
            with patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(
                    SystemExit,
                    "R16-14 trace channel violates OD-20: expected pipe/socket",
                ):
                    GATE.write_r16_runtime_records()

    def test_character_device_channel_refuses_under_od20(self) -> None:
        first = os.open("/dev/null", os.O_WRONLY)
        second_read, second_write = os.pipe()
        self.addCleanup(os.close, first)
        self.addCleanup(os.close, second_read)
        self.addCleanup(os.close, second_write)
        environment = {
            "KILIX_F100_R16_14_TRACE_FD": str(first),
            "KILIX_F100_R16_16_ACCOUNTING_AUTHORITY_SHA256": "0" * 64,
            "KILIX_F100_R16_16_EVENTS_FD": str(second_write),
        }
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(
                SystemExit,
                "R16-14 trace channel violates OD-20: expected pipe/socket",
            ):
                GATE.write_r16_runtime_records()

    def test_duplicate_pipe_channel_refuses(self) -> None:
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        environment = {
            "KILIX_F100_R16_14_TRACE_FD": str(write_fd),
            "KILIX_F100_R16_16_ACCOUNTING_AUTHORITY_SHA256": "0" * 64,
            "KILIX_F100_R16_16_EVENTS_FD": str(write_fd),
        }
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(
                SystemExit,
                "R16 runtime-record channels are not distinct: accepted=0/2",
            ):
                GATE.write_r16_runtime_records()


if __name__ == "__main__":
    unittest.main()
