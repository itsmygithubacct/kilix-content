"""Static and causal controls for the R16-5 exact-wheel preflight."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
TOOL_PATH = PROJECT / "tools" / "f100_u1_r16_5_preflight.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("f100_u1_r16_5_preflight", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load_tool()


def regular_info(name: str, mode: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def record_bytes(entries: list[tuple[str, bytes]], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, payload in entries:
        digest = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()
        ).rstrip(b"=").decode("ascii")
        writer.writerow((name, digest, str(len(payload))))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


class R16FivePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kilix-r16-5-preflight-")
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        package = self.candidate / "src" / "kilix_content"
        package.mkdir(parents=True)
        self.init_payload = b"VALUE = 'clean'\n"
        self.install_payload = b"def install():\n    return 'clean'\n"
        (package / "__init__.py").write_bytes(self.init_payload)
        (package / "install.py").write_bytes(self.install_payload)
        (self.candidate / "pyproject.toml").write_text(
            """[project]
name = "kilix-content"
version = "1.0.0"
license-files = []

[tool.setuptools.package-data]
kilix_content = []

[tool.setuptools.data-files]
"""
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_artifact(
        self,
        *,
        install_payload: bytes | None = None,
        init_payload: bytes | None = None,
        metadata_payload: bytes | None = None,
        reference_init_payload: bytes | None = None,
        extra: dict[str, bytes] | None = None,
        stale_record: bool = False,
    ):
        distribution = "kilix_content-1.0.0"
        record_name = f"{distribution}.dist-info/RECORD"
        clean_entries = [
            (
                "kilix_content/__init__.py",
                reference_init_payload or self.init_payload,
            ),
            ("kilix_content/install.py", self.install_payload),
            (f"{distribution}.dist-info/METADATA", b"Metadata-Version: 2.4\n"),
            (f"{distribution}.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            (f"{distribution}.dist-info/top_level.txt", b"kilix_content\n"),
        ]
        hostile_entries = list(clean_entries)
        hostile_entries[0] = (
            "kilix_content/__init__.py",
            init_payload or self.init_payload,
        )
        hostile_entries[1] = (
            "kilix_content/install.py",
            install_payload or self.install_payload + b"# hostile\n",
        )
        if metadata_payload is not None:
            hostile_entries[2] = (
                f"{distribution}.dist-info/METADATA",
                metadata_payload,
            )
        hostile_entries.extend(sorted((extra or {}).items()))

        def write_wheel(
            path: Path, entries: list[tuple[str, bytes]], stale: bool
        ) -> None:
            record = record_bytes(entries, record_name)
            if stale:
                record = record.replace(b"sha256=", b"sha256=x", 1)
            with zipfile.ZipFile(path, "w") as archive:
                for name, payload in entries:
                    archive.writestr(regular_info(name), payload)
                archive.writestr(regular_info(record_name, 0o664), record)

        wheel = self.root / "literal.whl"
        clean_wheel = self.root / "clean.whl"
        write_wheel(wheel, hostile_entries, stale_record)
        write_wheel(clean_wheel, clean_entries, False)
        members = tuple(name for name, _ in hostile_entries) + (record_name,)
        raw = wheel.read_bytes()
        expectation = PREFLIGHT.ArtifactExpectation(
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
            members=members,
            module_members=(
                "kilix_content/__init__.py",
                "kilix_content/install.py",
            ),
            target_member="kilix_content/install.py",
        )
        return wheel, clean_wheel, expectation

    def test_ready_fixture_has_one_target_delta_and_no_member_drift(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact()
        result = PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        self.assertEqual(result["status"], PREFLIGHT.READY)
        self.assertIs(result["campaign_entry"]["ready"], True)
        self.assertEqual(result["campaign_entry"]["blockers"], [])
        self.assertEqual(
            result["comparison"]["equal_non_target_modules"],
            {
                "denominator": 1,
                "members": ["kilix_content/__init__.py"],
                "numerator": 1,
            },
        )
        self.assertEqual(
            result["comparison"]["intended_target_deltas"],
            {
                "denominator": 1,
                "members": ["kilix_content/install.py"],
                "numerator": 1,
            },
        )
        self.assertEqual(
            result["whole_gate_cases_executed"], {"denominator": 30, "numerator": 0}
        )

    def test_extra_artifact_member_blocks_before_campaign(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact(
            extra={"stale.txt": b"stale\n"}
        )
        result = PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        self.assertEqual(result["status"], PREFLIGHT.BLOCKED)
        self.assertEqual(
            [row["code"] for row in result["campaign_entry"]["blockers"]],
            ["AC-R16-5-CANDIDATE-PROJECTION-DRIFT"],
        )
        self.assertEqual(
            result["comparison"]["extra_artifact_members"],
            {"denominator": 7, "members": ["stale.txt"], "numerator": 1},
        )

    def test_non_target_module_delta_blocks_source_projection(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact(
            init_payload=b"VALUE = 'changed'\n"
        )
        result = PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        codes = [row["code"] for row in result["campaign_entry"]["blockers"]]
        self.assertIn("AC-R16-5-SOURCE-PROJECTION-DRIFT", codes)
        self.assertEqual(
            result["comparison"]["differing_non_target_modules"],
            {
                "denominator": 1,
                "members": ["kilix_content/__init__.py"],
                "numerator": 1,
            },
        )

    def test_target_must_differ(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact(
            install_payload=self.install_payload
        )
        result = PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        self.assertEqual(result["status"], PREFLIGHT.BLOCKED)
        self.assertEqual(
            result["comparison"]["target_equal_instead_of_delta"],
            {
                "denominator": 1,
                "members": ["kilix_content/install.py"],
                "numerator": 1,
            },
        )

    def test_non_target_metadata_delta_blocks_payload_projection(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact(
            metadata_payload=b"Metadata-Version: 2.3\n"
        )
        result = PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        self.assertEqual(
            [row["code"] for row in result["campaign_entry"]["blockers"]],
            ["AC-R16-5-CANDIDATE-PAYLOAD-PROJECTION-DRIFT"],
        )
        self.assertEqual(
            result["comparison"]["differing_non_target_member_payloads"],
            {
                "denominator": 4,
                "members": ["kilix_content-1.0.0.dist-info/METADATA"],
                "numerator": 1,
            },
        )

    def test_reference_wheel_must_bind_candidate_source(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact(
            reference_init_payload=b"VALUE = 'not-source'\n"
        )
        with self.assertRaises(PREFLIGHT.PreflightRefusal) as raised:
            PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        self.assertEqual(
            raised.exception.code,
            "R16_5_REFERENCE_SOURCE_PAYLOAD_MISMATCH",
        )

    def test_packaging_glob_parent_escape_refuses(self) -> None:
        (self.candidate / "pyproject.toml").write_text(
            """[project]
name = "kilix-content"
version = "1.0.0"
license-files = []

[tool.setuptools.package-data]
kilix_content = ["../*.txt"]

[tool.setuptools.data-files]
"""
        )
        with self.assertRaises(PREFLIGHT.PreflightRefusal) as raised:
            PREFLIGHT.derive_candidate_projection(self.candidate)
        self.assertEqual(raised.exception.code, "R16_5_PACKAGING_GLOB_UNSAFE")

    def test_reference_uncompressed_budget_refuses_before_payload_reads(self) -> None:
        _wheel, clean_wheel, _expectation = self.build_artifact()
        projection = PREFLIGHT.derive_candidate_projection(self.candidate)
        with (
            mock.patch.object(PREFLIGHT, "MAX_WHEEL_UNCOMPRESSED_BYTES", 1),
            self.assertRaises(PREFLIGHT.PreflightRefusal) as raised,
        ):
            PREFLIGHT.verify_reference_wheel(clean_wheel, projection)
        self.assertEqual(
            raised.exception.code,
            "R16_5_REFERENCE_UNCOMPRESSED_SIZE_OUT_OF_BOUNDS",
        )

    def test_exact_artifact_digest_drift_refuses(self) -> None:
        wheel, _clean_wheel, expectation = self.build_artifact()
        wrong = PREFLIGHT.ArtifactExpectation(
            sha256="0" * 64,
            size=expectation.size,
            members=expectation.members,
            module_members=expectation.module_members,
            target_member=expectation.target_member,
        )
        with self.assertRaises(PREFLIGHT.PreflightRefusal) as raised:
            PREFLIGHT.verify_artifact(wheel, wrong)
        self.assertEqual(raised.exception.code, "R16_5_ARTIFACT_IDENTITY_MISMATCH")

    def test_repaired_record_is_mandatory(self) -> None:
        wheel, _clean_wheel, expectation = self.build_artifact(stale_record=True)
        with self.assertRaises(PREFLIGHT.PreflightRefusal) as raised:
            PREFLIGHT.verify_artifact(wheel, expectation)
        self.assertEqual(raised.exception.code, "R16_5_RECORD_ROW_MISMATCH")

    def test_symlink_artifact_refuses_before_read(self) -> None:
        wheel, _clean_wheel, expectation = self.build_artifact()
        link = self.root / "literal-link.whl"
        link.symlink_to(wheel)
        with self.assertRaises(PREFLIGHT.PreflightRefusal) as raised:
            PREFLIGHT.verify_artifact(link, expectation)
        self.assertEqual(raised.exception.code, "R16_5_ARTIFACT_OPEN_REFUSED")

    def test_current_candidate_projection_is_80_of_80(self) -> None:
        projection = PREFLIGHT.derive_candidate_projection(PROJECT)
        self.assertEqual(projection.distribution, "kilix_content-0.4.0")
        self.assertEqual(len(projection.expected_members), 80)
        self.assertEqual(len(projection.module_payloads), 11)
        self.assertEqual(
            set(projection.module_payloads), set(PREFLIGHT.EXACT_MODULE_MEMBERS)
        )

    def test_result_is_canonical_json(self) -> None:
        wheel, clean_wheel, expectation = self.build_artifact()
        result = PREFLIGHT.analyze(self.candidate, wheel, clean_wheel, expectation)
        raw = PREFLIGHT.canonical_json(result)
        self.assertEqual(raw, PREFLIGHT.canonical_json(json.loads(raw)))
        self.assertNotIn(str(self.root).encode(), raw)


if __name__ == "__main__":
    unittest.main()
