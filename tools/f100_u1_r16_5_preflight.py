#!/usr/bin/env python3
"""Preflight the literal R16-5 wheel against a candidate without executing it.

The frozen R16-5 contract requires the preserved wheel to match the final
candidate's complete wheel projection except for the intended ``install.py``
payload delta.  This tool derives that projection from source and packaging
metadata, verifies the retained wheel bytes and RECORD, and stops before any
contained runtime campaign when the projection has drifted.

It never imports, installs, extracts, or executes a wheel member.  A READY
result is preparation for a later trusted-launcher campaign, not acceptance.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import sys
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn


RESULT_SCHEMA = "kilix.content.f100-u1-r16-5-preflight-result/v1"
READY = "READY_FOR_CONTAINED_CAMPAIGN_NOT_GRADED"
BLOCKED = "BLOCKED_CANDIDATE_PROJECTION_DRIFT_NOT_GRADED"
TARGET_MEMBER = "kilix_content/install.py"
EXACT_SHA256 = "c4789c10ac87291a1e543e39138b88c84847f21b95e49fc64c25517381b4efac"
EXACT_BYTES = 443_824
EXACT_MEMBERS = (
    "kilix_content/__init__.py",
    "kilix_content/catalog/__init__.py",
    "kilix_content/install.py",
    "kilix_content/model.py",
    "kilix_content/receipt.py",
    "kilix_content/u1.py",
    "kilix_content/u1_capacity.py",
    "kilix_content/u1_catalog.py",
    "kilix_content/u1_core.py",
    "kilix_content/u1_profiles.py",
    "kilix_content/u1_retention.py",
    "kilix_content-0.0.0.dist-info/METADATA",
    "kilix_content-0.0.0.dist-info/WHEEL",
    "kilix_content-0.0.0.dist-info/RECORD",
)
EXACT_MODULE_MEMBERS = tuple(name for name in EXACT_MEMBERS if name.endswith(".py"))
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PreflightRefusal(Exception):
    """A named input or verifier refusal, distinct from expected drift."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ArtifactExpectation:
    sha256: str
    size: int
    members: tuple[str, ...]
    module_members: tuple[str, ...]
    target_member: str


@dataclass(frozen=True)
class CandidateProjection:
    distribution: str
    expected_members: frozenset[str]
    module_payloads: dict[str, bytes]
    source_member_payloads: dict[str, bytes]
    source_inputs: dict[str, bytes]


FROZEN_ARTIFACT = ArtifactExpectation(
    sha256=EXACT_SHA256,
    size=EXACT_BYTES,
    members=EXACT_MEMBERS,
    module_members=EXACT_MODULE_MEMBERS,
    target_member=TARGET_MEMBER,
)


def refuse(code: str, detail: str) -> NoReturn:
    raise PreflightRefusal(code, detail)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def population(numerator: int, denominator: int, **extra: Any) -> dict[str, Any]:
    return {"denominator": denominator, "numerator": numerator, **extra}


def _read_retained_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        refuse("R16_5_ARTIFACT_OPEN_REFUSED", str(exc))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            refuse("R16_5_ARTIFACT_NOT_REGULAR", oct(before.st_mode))
        if before.st_size < 0 or before.st_size > maximum:
            refuse(
                "R16_5_ARTIFACT_SIZE_OUT_OF_BOUNDS",
                f"observed={before.st_size} maximum={maximum}",
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum or os.read(descriptor, 1):
            refuse("R16_5_ARTIFACT_SIZE_OUT_OF_BOUNDS", f"maximum={maximum}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if not stable or len(raw) != before.st_size:
        refuse("R16_5_ARTIFACT_CHANGED_DURING_READ", "retained descriptor drift")
    return raw, before


def _safe_member(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or posixpath.normpath(name) != name
    ):
        refuse("R16_5_ARTIFACT_MEMBER_UNSAFE", name)


def _record_rows(
    archive: zipfile.ZipFile,
    names: tuple[str, ...],
) -> dict[str, tuple[str, str]]:
    record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        refuse("R16_5_RECORD_CARDINALITY", f"observed={len(record_names)} expected=1")
    record_name = record_names[0]
    try:
        rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
    except (KeyError, UnicodeDecodeError, csv.Error) as exc:
        refuse("R16_5_RECORD_UNREADABLE", str(exc))
    if len(rows) != len(names) or any(len(row) != 3 for row in rows):
        refuse(
            "R16_5_RECORD_POPULATION_MISMATCH",
            f"rows={len(rows)} members={len(names)}",
        )
    if {row[0] for row in rows} != set(names):
        refuse("R16_5_RECORD_MEMBER_SET_MISMATCH", "RECORD paths differ")
    claims: dict[str, tuple[str, str]] = {}
    for member, encoded, size in rows:
        payload = archive.read(member)
        if member == record_name:
            if encoded or size:
                refuse("R16_5_RECORD_SELF_ROW_NONEMPTY", member)
        else:
            expected_digest = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(payload).digest()
            ).rstrip(b"=").decode("ascii")
            if encoded != expected_digest or size != str(len(payload)):
                refuse("R16_5_RECORD_ROW_MISMATCH", member)
        claims[member] = (encoded, size)
    return claims


def verify_artifact(
    wheel: Path,
    expectation: ArtifactExpectation = FROZEN_ARTIFACT,
) -> tuple[
    bytes,
    dict[str, bytes],
    dict[str, tuple[str, str]],
    dict[str, Any],
]:
    if HEX_SHA256.fullmatch(expectation.sha256) is None or expectation.size <= 0:
        refuse("R16_5_EXPECTATION_INVALID", "invalid frozen identity")
    raw, descriptor_stat = _read_retained_regular(wheel, expectation.size)
    observed_sha256 = sha256_bytes(raw)
    if len(raw) != expectation.size or observed_sha256 != expectation.sha256:
        refuse(
            "R16_5_ARTIFACT_IDENTITY_MISMATCH",
            f"sha256={observed_sha256} bytes={len(raw)}",
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile) as exc:
        refuse("R16_5_ARTIFACT_ZIP_INVALID", str(exc))
    with archive:
        infos = archive.infolist()
        names = tuple(info.filename for info in infos)
        if names != expectation.members or len(names) != len(set(names)):
            refuse(
                "R16_5_ARTIFACT_MEMBER_POPULATION_MISMATCH",
                f"observed={len(names)} expected={len(expectation.members)}",
            )
        for info in infos:
            _safe_member(info.filename)
            mode = info.external_attr >> 16
            if not stat.S_ISREG(mode):
                refuse("R16_5_ARTIFACT_MEMBER_NOT_REGULAR", info.filename)
        bad_crc = archive.testzip()
        if bad_crc is not None:
            refuse("R16_5_ARTIFACT_CRC_MISMATCH", bad_crc)
        record_rows = _record_rows(archive, names)
        payloads = {name: archive.read(name) for name in names}
    details = {
        "bytes": population(len(raw), expectation.size),
        "crc_members": population(len(expectation.members), len(expectation.members)),
        "members": population(len(expectation.members), len(expectation.members)),
        "record_rows": population(len(record_rows), len(expectation.members)),
        "retained_descriptor_stable": population(1, 1),
        "sha256": observed_sha256,
        "source_stat_identity_is_authority": False,
        "wheel_members_executed": population(0, len(expectation.module_members)),
    }
    return raw, payloads, record_rows, details


def _closed_string_list(value: Any, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(
        type(item) is not str or not item for item in value
    ):
        refuse("R16_5_PYPROJECT_INVALID", label)
    return tuple(value)


def _real_files(root: Path, pattern: str, label: str) -> list[Path]:
    paths = sorted(root.glob(pattern))
    if not paths:
        refuse("R16_5_PACKAGING_GLOB_EMPTY", f"{label}:{pattern}")
    result: list[Path] = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            refuse("R16_5_SOURCE_MEMBER_UNSAFE", path.relative_to(root).as_posix())
        result.append(path)
    return result


def derive_candidate_projection(candidate: Path) -> CandidateProjection:
    pyproject_path = candidate / "pyproject.toml"
    try:
        pyproject_raw = pyproject_path.read_bytes()
        pyproject = tomllib.loads(pyproject_raw.decode("utf-8"))
        project = pyproject["project"]
        setuptools = pyproject["tool"]["setuptools"]
        name = project["name"]
        version = project["version"]
    except (
        OSError,
        UnicodeDecodeError,
        KeyError,
        TypeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        refuse("R16_5_PYPROJECT_INVALID", str(exc))
    if type(name) is not str or type(version) is not str or not name or not version:
        refuse("R16_5_PYPROJECT_INVALID", "project name/version")
    distribution = f"{re.sub(r'[-_.]+', '_', name)}-{version}"
    package_root = candidate / "src" / "kilix_content"
    if package_root.is_symlink() or not package_root.is_dir():
        refuse("R16_5_SOURCE_PACKAGE_UNSAFE", "src/kilix_content")

    package_data = setuptools.get("package-data", {})
    if type(package_data) is not dict:
        refuse("R16_5_PYPROJECT_INVALID", "tool.setuptools.package-data")
    patterns = _closed_string_list(package_data.get("kilix_content"), "package-data")
    package_members: set[str] = set()
    source_member_payloads: dict[str, bytes] = {}
    source_inputs: dict[str, bytes] = {"pyproject.toml": pyproject_raw}
    for pattern in patterns:
        for path in _real_files(package_root, pattern, "package-data"):
            relative = path.relative_to(package_root).as_posix()
            member = f"kilix_content/{relative}"
            payload = path.read_bytes()
            package_members.add(member)
            source_member_payloads[member] = payload
            source_inputs[f"src/kilix_content/{relative}"] = payload

    module_payloads: dict[str, bytes] = {}
    for path in sorted(package_root.rglob("*")):
        relative = path.relative_to(package_root)
        if "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            refuse("R16_5_SOURCE_MEMBER_UNSAFE", relative.as_posix())
        if path.is_dir():
            continue
        if not path.is_file():
            refuse("R16_5_SOURCE_MEMBER_UNSAFE", relative.as_posix())
        if path.suffix not in {".py", ".pyi"} and path.name != "py.typed":
            continue
        member = f"kilix_content/{relative.as_posix()}"
        payload = path.read_bytes()
        source_inputs[f"src/{member}"] = payload
        if member not in package_members:
            module_payloads[member] = payload
            source_member_payloads[member] = payload

    data_files = setuptools.get("data-files", {})
    if type(data_files) is not dict:
        refuse("R16_5_PYPROJECT_INVALID", "tool.setuptools.data-files")
    external_members: set[str] = set()
    for destination, value in data_files.items():
        if type(destination) is not str or not destination:
            refuse("R16_5_PYPROJECT_INVALID", "data-files destination")
        for pattern in _closed_string_list(value, f"data-files:{destination}"):
            for path in _real_files(candidate, pattern, f"data-files:{destination}"):
                member = f"{distribution}.data/data/{destination}/{path.name}"
                external_members.add(member)
                payload = path.read_bytes()
                source_member_payloads[member] = payload
                source_inputs[path.relative_to(candidate).as_posix()] = payload

    metadata_names = {"METADATA", "RECORD", "WHEEL", "top_level.txt"}
    scripts = project.get("scripts", {})
    if type(scripts) is not dict:
        refuse("R16_5_PYPROJECT_INVALID", "project.scripts")
    if scripts:
        metadata_names.add("entry_points.txt")
    metadata_members = {f"{distribution}.dist-info/{name}" for name in metadata_names}
    license_patterns = _closed_string_list(
        project.get("license-files", []), "license-files"
    )
    for pattern in license_patterns:
        for path in _real_files(candidate, pattern, "license-files"):
            member = f"{distribution}.dist-info/licenses/{path.name}"
            payload = path.read_bytes()
            metadata_members.add(member)
            source_member_payloads[member] = payload
            source_inputs[path.relative_to(candidate).as_posix()] = payload

    categories = (
        package_members,
        set(module_payloads),
        external_members,
        metadata_members,
    )
    for index, left in enumerate(categories):
        for right in categories[index + 1 :]:
            overlap = left & right
            if overlap:
                refuse("R16_5_CANDIDATE_CATEGORY_OVERLAP", repr(sorted(overlap)))
    expected_members = frozenset().union(*categories)
    return CandidateProjection(
        distribution=distribution,
        expected_members=expected_members,
        module_payloads=module_payloads,
        source_member_payloads=source_member_payloads,
        source_inputs=source_inputs,
    )


def projection_sha256(projection: CandidateProjection) -> str:
    rows = [
        {"path": path, "sha256": sha256_bytes(payload), "size": len(payload)}
        for path, payload in sorted(projection.source_inputs.items())
    ]
    return sha256_bytes(canonical_json(rows))


def verify_reference_wheel(
    wheel: Path,
    projection: CandidateProjection,
) -> tuple[dict[str, bytes], dict[str, tuple[str, str]], dict[str, Any]]:
    raw, _descriptor_stat = _read_retained_regular(wheel, 64 * 1024 * 1024)
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile) as exc:
        refuse("R16_5_REFERENCE_ZIP_INVALID", str(exc))
    with archive:
        infos = archive.infolist()
        names = tuple(info.filename for info in infos)
        if len(names) != len(set(names)) or set(names) != projection.expected_members:
            refuse(
                "R16_5_REFERENCE_MEMBER_POPULATION_MISMATCH",
                f"observed={len(names)} expected={len(projection.expected_members)}",
            )
        for info in infos:
            _safe_member(info.filename)
            if not stat.S_ISREG(info.external_attr >> 16):
                refuse("R16_5_REFERENCE_MEMBER_NOT_REGULAR", info.filename)
        bad_crc = archive.testzip()
        if bad_crc is not None:
            refuse("R16_5_REFERENCE_CRC_MISMATCH", bad_crc)
        record_rows = _record_rows(archive, names)
        payloads = {name: archive.read(name) for name in names}
    mismatched_source_members = sorted(
        member
        for member, expected in projection.source_member_payloads.items()
        if payloads.get(member) != expected
    )
    if mismatched_source_members:
        refuse(
            "R16_5_REFERENCE_SOURCE_PAYLOAD_MISMATCH",
            repr(mismatched_source_members),
        )
    details = {
        "bytes": population(len(raw), len(raw)),
        "crc_members": population(len(payloads), len(projection.expected_members)),
        "members": population(len(payloads), len(projection.expected_members)),
        "record_rows": population(len(record_rows), len(projection.expected_members)),
        "retained_descriptor_stable": population(1, 1),
        "sha256": sha256_bytes(raw),
        "source_bound_members": population(
            len(projection.source_member_payloads),
            len(projection.source_member_payloads),
        ),
        "wheel_members_executed": population(0, len(projection.module_payloads)),
    }
    return payloads, record_rows, details


def analyze(
    candidate: Path,
    wheel: Path,
    reference_wheel: Path,
    expectation: ArtifactExpectation = FROZEN_ARTIFACT,
) -> dict[str, Any]:
    _, artifact_payloads, artifact_records, artifact = verify_artifact(
        wheel, expectation
    )
    projection = derive_candidate_projection(candidate)
    reference_payloads, reference_records, reference = verify_reference_wheel(
        reference_wheel, projection
    )
    artifact_modules = {
        name: artifact_payloads[name] for name in expectation.module_members
    }
    candidate_modules = set(projection.module_payloads)
    expected_modules = set(expectation.module_members)
    missing_modules = sorted(expected_modules - candidate_modules)
    extra_modules = sorted(candidate_modules - expected_modules)
    equal_non_target: list[str] = []
    differing_non_target: list[str] = []
    target_deltas: list[str] = []
    target_equal: list[str] = []
    for member in sorted(expected_modules & candidate_modules):
        equal = artifact_modules[member] == projection.module_payloads[member]
        if member == expectation.target_member:
            (target_equal if equal else target_deltas).append(member)
        elif equal:
            equal_non_target.append(member)
        else:
            differing_non_target.append(member)

    observed_members = set(expectation.members)
    missing_members = sorted(projection.expected_members - observed_members)
    extra_members = sorted(observed_members - projection.expected_members)
    source_module_set_equal = not missing_modules and not extra_modules
    non_target_denominator = len(expected_modules - {expectation.target_member})
    source_delta_ready = (
        source_module_set_equal
        and len(equal_non_target) == non_target_denominator
        and not differing_non_target
        and target_deltas == [expectation.target_member]
        and not target_equal
    )
    member_projection_ready = not missing_members and not extra_members
    candidate_record_names = sorted(
        name
        for name in projection.expected_members
        if name.endswith(".dist-info/RECORD")
    )
    if len(candidate_record_names) != 1:
        refuse(
            "R16_5_CANDIDATE_RECORD_CARDINALITY",
            f"observed={len(candidate_record_names)} expected=1",
        )
    candidate_record_name = candidate_record_names[0]
    comparable_non_target_members = projection.expected_members - {
        expectation.target_member,
        candidate_record_name,
    }
    equal_non_target_member_payloads = sorted(
        member
        for member in comparable_non_target_members & observed_members
        if artifact_payloads[member] == reference_payloads[member]
    )
    differing_non_target_member_payloads = sorted(
        member
        for member in comparable_non_target_members & observed_members
        if artifact_payloads[member] != reference_payloads[member]
    )
    record_comparison_evaluated = member_projection_ready
    target_record_delta = False
    equal_other_record_claims = 0
    if record_comparison_evaluated:
        target_record_delta = (
            artifact_records[expectation.target_member]
            != reference_records[expectation.target_member]
        )
        equal_other_record_claims = sum(
            artifact_records[member] == reference_records[member]
            for member in projection.expected_members
            if member != expectation.target_member
        )
    expected_other_record_claims = len(projection.expected_members) - 1
    payload_join_ready = (
        member_projection_ready
        and not differing_non_target_member_payloads
        and len(equal_non_target_member_payloads) == len(comparable_non_target_members)
        and target_record_delta
        and equal_other_record_claims == expected_other_record_claims
    )
    ready = source_delta_ready and member_projection_ready and payload_join_ready
    blockers: list[dict[str, Any]] = []
    if not source_delta_ready:
        blockers.append(
            {
                "code": "AC-R16-5-SOURCE-PROJECTION-DRIFT",
                "detail": "candidate importable-module projection is not one intended target delta",
            }
        )
    if not member_projection_ready:
        blockers.append(
            {
                "code": "AC-R16-5-CANDIDATE-PROJECTION-DRIFT",
                "detail": "literal artifact member identity differs from final-tip wheel projection",
            }
        )
    elif not payload_join_ready:
        blockers.append(
            {
                "code": "AC-R16-5-CANDIDATE-PAYLOAD-PROJECTION-DRIFT",
                "detail": "literal artifact differs outside the target payload and its RECORD row",
            }
        )
    return {
        "artifact": artifact,
        "campaign_entry": {
            "blockers": blockers,
            "ready": ready,
            "trusted_launcher_campaigns_executed": population(0, 1),
        },
        "candidate": {
            "distribution": projection.distribution,
            "expected_wheel_members": population(
                len(projection.expected_members), len(projection.expected_members)
            ),
            "projection_sha256": projection_sha256(projection),
            "source_modules": population(
                len(candidate_modules), len(candidate_modules)
            ),
        },
        "clean_reference_wheel": reference,
        "comparison": {
            "artifact_members_shared_with_candidate": population(
                len(observed_members & projection.expected_members),
                len(observed_members),
            ),
            "candidate_expected_members_present": population(
                len(projection.expected_members & observed_members),
                len(projection.expected_members),
            ),
            "differing_non_target_modules": population(
                len(differing_non_target),
                non_target_denominator,
                members=differing_non_target,
            ),
            "differing_non_target_member_payloads": population(
                len(differing_non_target_member_payloads),
                len(comparable_non_target_members),
                members=differing_non_target_member_payloads,
            ),
            "equal_non_target_modules": population(
                len(equal_non_target),
                non_target_denominator,
                members=equal_non_target,
            ),
            "equal_non_target_member_payloads": population(
                len(equal_non_target_member_payloads),
                len(comparable_non_target_members),
                members=equal_non_target_member_payloads,
            ),
            "extra_artifact_members": population(
                len(extra_members), len(observed_members), members=extra_members
            ),
            "extra_candidate_modules": population(
                len(extra_modules), len(candidate_modules), members=extra_modules
            ),
            "intended_target_deltas": population(
                len(target_deltas), 1, members=target_deltas
            ),
            "missing_artifact_members": population(
                len(missing_members),
                len(projection.expected_members),
                members=missing_members,
            ),
            "missing_candidate_modules": population(
                len(missing_modules), len(expected_modules), members=missing_modules
            ),
            "target_equal_instead_of_delta": population(
                len(target_equal), 1, members=target_equal
            ),
            "record_comparison_evaluated": record_comparison_evaluated,
            "record_other_claims_equal": population(
                equal_other_record_claims,
                expected_other_record_claims,
            ),
            "record_target_deltas": population(int(target_record_delta), 1),
        },
        "grade": "NOT_GRADED",
        "schema_version": RESULT_SCHEMA,
        "status": READY if ready else BLOCKED,
        "wheel_members_executed": population(0, len(expectation.module_members)),
        "whole_gate_cases_executed": population(0, 30),
    }


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--clean-wheel", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        result = analyze(
            arguments.candidate_root,
            arguments.wheel,
            arguments.clean_wheel,
        )
    except PreflightRefusal as exc:
        error = {
            "code": exc.code,
            "detail": exc.detail,
            "grade": "NOT_GRADED",
            "schema_version": RESULT_SCHEMA,
            "status": "REFUSED_INVALID_PREFLIGHT_INPUT",
            "wheel_members_executed": population(0, len(EXACT_MODULE_MEMBERS)),
            "whole_gate_cases_executed": population(0, 30),
        }
        sys.stdout.buffer.write(canonical_json(error))
        return 2
    sys.stdout.buffer.write(canonical_json(result))
    return 0 if result["campaign_entry"]["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
