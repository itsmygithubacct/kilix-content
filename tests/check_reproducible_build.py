"""Prove empty-cache, offline, reproducible U1 source and wheel authority."""

from __future__ import annotations

import base64
import csv
import fcntl
import functools
import gzip
import io
import hashlib
import importlib.metadata
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
import zlib
from copy import copy
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, Callable


PROJECT = Path(__file__).resolve().parents[1]
TOOLCHAIN_PATH = PROJECT / "build-toolchain.json"
WHEELHOUSE_NAME = "wheelhouse"
U1_MANIFEST = "kilix.content.u1-resources-v1.json"
RESOURCE_TOP_LEVELS = {"catalog", "contracts", "licenses"}
FROZEN_CORESIDENT_HASHES = {
    "catalog/__init__.py": "fdd111610d89ff4fb573206a254661d7c654d58d887aa2c8a24127228b584ba8",
    "catalog/plebian.json": "da40fb625df2438d9f7f079027f476224c7a463e4b3ebbbed4c63729fdde44f7",
    "contracts/kilix.content.asset-v1.schema.json": "89d4865d11d6a537328965a8a903ac07d7dcf0ea14e1b360888f22af7ba5a1a8",
    "contracts/kilix.install.license-v1.schema.json": "2f352856b4bd712e6030b2c74a690f7c0ed250e5730a69aa04b601643dbf1736",
    "contracts/kilix.content.u1-resources-v1.json": "ac2f61600985035664c0ff586455006be5e4bc94952c7d778095c9fdf6941bd2",
}
SOURCE_DATE_EPOCH = "1776729600"
LAUNCHER_FD_ENV = "KILIX_CONTENT_BUILD_LAUNCHER_FD"
_BUILD_LAUNCHER_FD: int | None = None
EXPECTED_TOOLS = {
    "build": "1.3.0",
    "ruff": "0.12.8",
    "setuptools": "77.0.3",
    "wheel": "0.45.1",
}
EXPECTED_WHEEL_DISTRIBUTIONS = {
    "arrow": "1.4.0",
    "attrs": "26.1.0",
    "build": "1.3.0",
    "fqdn": "1.5.1",
    "idna": "3.19",
    "isoduration": "20.11.0",
    "jsonpointer": "3.1.1",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.9.1",
    "packaging": "26.3",
    "pyproject-hooks": "1.2.0",
    "python-dateutil": "2.9.0.post0",
    "referencing": "0.37.0",
    "rfc3339-validator": "0.1.4",
    "rfc3987": "1.3.8",
    "rpds-py": "2026.6.3",
    "ruff": "0.12.8",
    "setuptools": "77.0.3",
    "six": "1.17.0",
    "typing-extensions": "4.16.0",
    "tzdata": "2026.3",
    "uri-template": "1.3.0",
    "webcolors": "25.10.0",
    "wheel": "0.45.1",
}
EXPECTED_WHEEL_FILE_MODE = 0o644
EXPECTED_WHEEL_RECORD_MODE = 0o664
EXPECTED_WHEEL_DIRECTORY_MODE = 0o755
EXPECTED_SDIST_FILE_MODE = 0o644
EXPECTED_SDIST_DIRECTORY_MODE = 0o755
GENERATED_SDIST_FILES = {
    "PKG-INFO",
    "setup.cfg",
    "src/kilix_content.egg-info/PKG-INFO",
    "src/kilix_content.egg-info/SOURCES.txt",
    "src/kilix_content.egg-info/dependency_links.txt",
    "src/kilix_content.egg-info/requires.txt",
    "src/kilix_content.egg-info/top_level.txt",
}
SDIST_DATA_BLOCK_TYPES = frozenset(
    {
        tarfile.DIRTYPE,
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.FIFOTYPE,
    }
)
MAX_SDIST_TAR_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_SDIST_EXPANSION_RATIO = 256
_SDIST_AUDIT_CALLS: set[str] = set()
_REQUIRED_SDIST_AUDIT_CALLS = frozenset(
    {
        "enumerator-container",
        "relative-enumerator",
        "generated-enumerator",
        "extract-container",
        "extract-enumerator",
        "extract-payload",
        "generated-metadata-audit",
        "direct-enumerator",
        "direct-payload",
    }
)
FROZEN_REQUIRED_SDIST_AUDIT_CALL_COUNT = 9
R16_14_SDIST_CALL_EVENTS = {
    "direct-enumerator": {
        "artifact_presentation": "direct-sdist",
        "effect_family": "sdist",
        "effect_kind": "enumerator",
        "identity": "direct-enumerator",
        "phase": "post-build-production-audit",
        "target_function": "assert_sdist_enumerator_agreement",
    },
    "direct-payload": {
        "artifact_presentation": "direct-sdist",
        "effect_family": "sdist",
        "effect_kind": "payload",
        "identity": "direct-payload",
        "phase": "post-build-production-audit",
        "target_function": "sdist_payload_audit",
    },
    "enumerator-container": {
        "artifact_presentation": "sdist-enumerator-input",
        "effect_family": "sdist",
        "effect_kind": "container",
        "identity": "enumerator-container",
        "phase": "enumerator-preflight",
        "target_function": "sdist_container_audit",
    },
    "extract-container": {
        "artifact_presentation": "sdist-under-extraction",
        "effect_family": "sdist",
        "effect_kind": "container",
        "identity": "extract-container",
        "phase": "pre-extraction-container",
        "target_function": "sdist_container_audit",
    },
    "extract-enumerator": {
        "artifact_presentation": "sdist-under-extraction",
        "effect_family": "sdist",
        "effect_kind": "enumerator",
        "identity": "extract-enumerator",
        "phase": "pre-extraction-enumeration",
        "target_function": "assert_sdist_enumerator_agreement",
    },
    "extract-payload": {
        "artifact_presentation": "sdist-under-extraction",
        "effect_family": "sdist",
        "effect_kind": "payload",
        "identity": "extract-payload",
        "phase": "pre-extraction-payload",
        "target_function": "sdist_payload_audit",
    },
    "generated-enumerator": {
        "artifact_presentation": "direct-sdist-pair",
        "effect_family": "sdist",
        "effect_kind": "enumerator",
        "identity": "generated-enumerator",
        "phase": "generated-metadata-read",
        "target_function": "assert_sdist_enumerator_agreement",
    },
    "generated-metadata-audit": {
        "artifact_presentation": "direct-sdist-pair",
        "effect_family": "sdist",
        "effect_kind": "generated-metadata",
        "identity": "generated-metadata-audit",
        "phase": "post-build-reproducibility",
        "target_function": "sdist_generated_metadata_audit",
    },
    "relative-enumerator": {
        "artifact_presentation": "bounded-relative-signature-control",
        "effect_family": "sdist",
        "effect_kind": "enumerator",
        "identity": "relative-enumerator",
        "phase": "negative-control-differential",
        "target_function": "assert_sdist_enumerator_agreement",
    },
}
R16_16_ACCOUNTING_EFFECT_IDS = (
    "sdist.container.gzip-trailing",
    "sdist.enumerator.physical-directory-size",
    "sdist.member.permission",
    "sdist.payload.source-byte",
    "wheel.archive.extra-member",
    "wheel.container.appended-zip",
    "wheel.container.prepend",
    "wheel.container.trailing",
    "wheel.installed.manifest",
    "wheel.module.source-byte",
    "wheel.record.self-row",
    "wheel.resource.byte",
)
R16_16_PRESENTATION_IDS = {
    "direct sdist 1": "direct-sdist-1",
    "direct sdist 2": "direct-sdist-2",
    "direct wheel 1": "direct-wheel-1",
    "direct wheel 2": "direct-wheel-2",
    "sdist-derived wheel": "sdist-derived-wheel",
}

# R14-0: this is the hand-authored acceptance registry.  A row is an
# observable property, one concrete mutation of that property, and the
# refusal that proves the mutation reached the intended audit.  Keep this
# table append-only: adding a production audit without adding its mutation
# evidence is a gate failure, as is adding a mutation without an artifact
# audit.  The literal digest is filled only after the table is frozen.
PROPERTY_MUTATION_REGISTRY: tuple[dict[str, str], ...] = (
    {
        "id": "sdist.container.gzip-trailing",
        "artifact_family": "sdist",
        "audit_kind": "container",
        "property": "gzip framing and tar end marker",
        "mutation": "append bytes after the gzip member",
        "expected_refusal": "sdist gzip container integrity failed",
    },
    {
        "id": "sdist.enumerator.physical-directory-size",
        "artifact_family": "sdist",
        "audit_kind": "enumerator",
        "property": "bounded physical member enumeration",
        "mutation": "declare a directory payload size absent from its physical carrier",
        "expected_refusal": "sdist archive enumerators disagree",
    },
    {
        "id": "sdist.payload.source-byte",
        "artifact_family": "sdist",
        "audit_kind": "payload",
        "property": "source payload equality",
        "mutation": "replace one source-controlled README byte",
        "expected_refusal": "sdist payload differs from source",
    },
    {
        "id": "sdist.member.permission",
        "artifact_family": "sdist",
        "audit_kind": "closure",
        "property": "safe sdist member permissions",
        "mutation": "set one shipped test member setuid",
        "expected_refusal": "sdist member permissions differ",
    },
    {
        "id": "wheel.container.trailing",
        "artifact_family": "wheel",
        "audit_kind": "container",
        "property": "ZIP container end-of-archive integrity",
        "mutation": "append bytes after the ZIP end record",
        "expected_refusal": "wheel container has trailing bytes",
    },
    {
        "id": "wheel.archive.extra-member",
        "artifact_family": "wheel",
        "audit_kind": "archive",
        "property": "exact wheel member closure",
        "mutation": "add an unlisted regular member and repair RECORD",
        "expected_refusal": "wheel complete member set differs",
    },
    {
        "id": "wheel.record.self-row",
        "artifact_family": "wheel",
        "audit_kind": "record",
        "property": "RECORD self-row emptiness",
        "mutation": "make the valid-CRC RECORD self-row nonempty",
        "expected_refusal": "wheel RECORD self-row is not empty",
    },
    {
        "id": "wheel.resource.byte",
        "artifact_family": "wheel",
        "audit_kind": "resource",
        "property": "production resource byte authority",
        "mutation": "change one package production resource byte",
        "expected_refusal": "package production resource digest mismatch",
    },
    {
        "id": "wheel.module.source-byte",
        "artifact_family": "wheel",
        "audit_kind": "module",
        "property": "source module byte equality",
        "mutation": "replace one importable module byte",
        "expected_refusal": "wheel module differs from source",
    },
    {
        "id": "wheel.installed.manifest",
        "artifact_family": "wheel",
        "audit_kind": "installed",
        "property": "installed package manifest integrity",
        "mutation": "tamper the installed package manifest byte",
        "expected_refusal": "external installed-wheel corpus probe failed",
    },
    {
        "id": "wheel.container.prepend",
        "artifact_family": "wheel",
        "audit_kind": "container",
        "property": "no bytes before the ZIP container",
        "mutation": "prepend bytes before the wheel ZIP",
        "expected_refusal": "wheel container has bytes outside the central directory record",
    },
    {
        "id": "wheel.container.appended-zip",
        "artifact_family": "wheel",
        "audit_kind": "container",
        "property": "no second ZIP appended after the container",
        "mutation": "append a complete second ZIP after the wheel",
        "expected_refusal": "wheel container has bytes outside the central directory record",
    },
    {
        "id": "sdist.generated-metadata.byte",
        "artifact_family": "sdist",
        "audit_kind": "generated-metadata",
        "property": "generated sdist metadata reproducibility",
        "mutation": "change one generated metadata byte in one reproducible sdist",
        "expected_refusal": "generated sdist metadata is not reproducible",
    },
    {
        "id": "wheel.resource-authority.sdist-manifest",
        "artifact_family": "wheel",
        "audit_kind": "resource-authority",
        "property": "source and sdist production resource authority equality",
        "mutation": "add a canonical marker to the extracted-sdist resource manifest",
        "expected_refusal": "sdist production authority differs from source",
    },
)
FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256 = "73de594839c5e82b7071540bd14eb9fa9e3089fa3bbc505d9b4224c03cea4c36"
# Existence seal, distinct from the content digest above: a weakening round
# that removes a row and recomputes the digest does not restate this literal
# list, so the superset check below still refuses. Append-only: only add ids.
FROZEN_REQUIRED_ROW_IDS = frozenset(
    {
        "sdist.container.gzip-trailing",
        "sdist.enumerator.physical-directory-size",
        "sdist.payload.source-byte",
        "sdist.member.permission",
        "wheel.container.trailing",
        "wheel.archive.extra-member",
        "wheel.record.self-row",
        "wheel.resource.byte",
        "wheel.module.source-byte",
        "wheel.installed.manifest",
        "wheel.container.prepend",
        "wheel.container.appended-zip",
        "sdist.generated-metadata.byte",
        "wheel.resource-authority.sdist-manifest",
    }
)
FROZEN_MINIMUM_ROW_COUNT = 14
_PROPERTY_MUTATION_EXECUTIONS: set[tuple[str, str]] = set()
_R16_14_SDIST_EFFECT_EVENTS: list[dict[str, str]] = []
_R16_16_ACCOUNTING_EVENTS: list[dict[str, str]] = []
_AUDIT_EFFECTS: set[tuple[str, str, str, str]] = set()
_PRODUCTION_AUDIT_KINDS: set[tuple[str, str]] = set()
_COMPLETE_GATE_REGRESSIONS_OBSERVED: set[str] = set()
_RECORD_SELF_ROW_CONTROL_OBSERVED: set[str] = set()
_REQUIRED_COMPLETE_GATE_REGRESSIONS = frozenset(
    {"r12-reader-reversion", "r13-callsite-wiring"}
)
_SDIST_WIRING_ASSERTED = False
_WHEEL_MEMBER_CLOSURE: set[tuple[str, str]] = set()
_WHEEL_CLOSURE_ASSERTED = False


def property_mutation_registry_bytes() -> bytes:
    return canonical_json(PROPERTY_MUTATION_REGISTRY)


def validate_property_mutation_registry() -> None:
    rows = list(PROPERTY_MUTATION_REGISTRY)
    ids = [row.get("id") for row in rows]
    if len(ids) != len(set(ids)) or any(not isinstance(value, str) or not value for value in ids):
        fail("property/mutation registry ids are not unique and nonempty")
    removed = FROZEN_REQUIRED_ROW_IDS - set(ids)
    if removed:
        fail(
            "append-only property/mutation registry removed a frozen row: "
            f"{sorted(removed)!r}"
        )
    if len(rows) < FROZEN_MINIMUM_ROW_COUNT:
        fail(
            "append-only property/mutation registry shrank below the frozen "
            f"minimum: rows={len(rows)} minimum={FROZEN_MINIMUM_ROW_COUNT}"
        )
    required_keys = {
        "id", "artifact_family", "audit_kind", "property", "mutation", "expected_refusal"
    }
    for row in rows:
        if set(row) != required_keys:
            fail(f"property/mutation registry row is not closed: {row!r}")
        if row["artifact_family"] not in {"sdist", "wheel"}:
            fail(f"property/mutation registry family is unknown: {row!r}")
    if FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256:
        observed = hashlib.sha256(property_mutation_registry_bytes()).hexdigest()
        if observed != FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256:
            fail(
                "property/mutation registry digest differs: "
                f"expected={FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256} observed={observed}"
            )


def register_production_audit(
    family: str,
    artifact_label: str,
    audit_kind: str,
    action: Callable[[], Any],
) -> Any:
    return action()


def records_audit_effect(
    family: str,
    kind: str,
    *,
    artifact_arguments: tuple[int, ...] = (0,),
) -> Callable[[Callable], Callable]:
    """Record, from inside the audit, that it ran to completion on an artifact.

    The effect is keyed on (family, resolved path, content digest, kind): the
    path keeps identical-digest reproducible artifacts independent, and the
    digest ties the record to the exact bytes audited. An audit whose call is
    deleted or whose action is hollowed never reaches this wrapper, so its
    effect is absent and coverage refuses by name.
    """
    def decorate(function: Callable) -> Callable:
        _PRODUCTION_AUDIT_KINDS.add((family, kind))
        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = function(*args, **kwargs)
            for index in artifact_arguments:
                if index >= len(args) or not isinstance(args[index], Path):
                    fail(
                        "production audit artifact argument is absent: "
                        f"family={family} kind={kind} index={index}"
                    )
                artifact = args[index]
                _AUDIT_EFFECTS.add(
                    (family, str(artifact.resolve()), digest(artifact), kind)
                )
            return result

        return wrapper

    return decorate


def assert_production_audit_completeness() -> None:
    """Every enumerated production audit must have a registered mutation, and
    every registered mutation must name a real production audit.

    R14-0's third requirement: a production audit with no registered mutation
    is a gate failure, not a silent gap. installed_wheel_audit was exactly such
    a gap. Enumeration comes from the records_audit_effect decorators, so a new
    production audit cannot be added without either a registry row or a named
    failure here.
    """
    registered = {
        (row["artifact_family"], row["audit_kind"])
        for row in PROPERTY_MUTATION_REGISTRY
    }
    unregistered = _PRODUCTION_AUDIT_KINDS - registered
    if unregistered:
        fail(
            "production audit has no registered mutation: "
            f"{sorted(unregistered)!r}"
        )
    orphaned = registered - _PRODUCTION_AUDIT_KINDS
    if orphaned:
        fail(
            "registered mutation has no production audit: "
            f"{sorted(orphaned)!r}"
        )


def assert_property_registry_coverage(
    artifact_inventory: dict[str, dict[str, Path]],
) -> None:
    validate_property_mutation_registry()
    assert_production_audit_completeness()
    if not _SDIST_WIRING_ASSERTED:
        fail("production sdist audit wiring assertion was not executed")
    if not _WHEEL_CLOSURE_ASSERTED:
        fail("production wheel member-set closure assertion was not executed")
    if not _RECORD_SELF_ROW_CONTROL_OBSERVED:
        fail("record self-row empty parity control was not observed")
    for family, labelled in artifact_inventory.items():
        for label, artifact in labelled.items():
            identity = (family, str(artifact.resolve()), digest(artifact))
            for row in PROPERTY_MUTATION_REGISTRY:
                if row["artifact_family"] != family:
                    continue
                if (*identity, row["audit_kind"]) not in _AUDIT_EFFECTS:
                    fail(
                        "production audit did not run on the shipped artifact: "
                        f"family={family} label={label} kind={row['audit_kind']}"
                    )
                if (row["id"], label) not in _PROPERTY_MUTATION_EXECUTIONS:
                    fail(
                        "property/mutation registry lacks mutation evidence: "
                        f"id={row['id']} label={label}"
                    )


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_fd(fd: int) -> str:
    """Digest an open descriptor rather than a path.

    The bytes measured are the bytes the kernel already holds open, so no
    substitution between the check and any later use can go unnoticed.
    """
    hasher = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1 << 20):
        hasher.update(chunk)
    return hasher.hexdigest()


def open_build_launcher() -> tuple[int, Path]:
    """Open the uv image that actually invoked this gate.

    The documented release command is `uv run ... python
    tests/check_reproducible_build.py`, so uv is this process's parent and
    /proc/<ppid>/exe names its running image. Nested child gates are spawned by
    Python rather than by uv, so they inherit the already-open descriptor; its
    digest is re-verified there, which makes the inherited number validated
    input rather than a trusted claim.

    A path recorded in build-toolchain.json is deliberately not consulted. Such
    a path proves what is installed at that location on this host, not what
    produced the artifacts, so it passes under any uv.
    """
    inherited = os.environ.get(LAUNCHER_FD_ENV)
    if inherited is not None:
        if not inherited.isdigit():
            fail("inherited build-launcher descriptor is not a descriptor number")
        fd = int(inherited)
        try:
            os.fstat(fd)
            resolved = Path(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            fail("inherited build-launcher descriptor is not open")
        return fd, resolved
    exe = Path("/proc") / str(os.getppid()) / "exe"
    try:
        fd = os.open(exe, os.O_RDONLY)
        resolved = Path(os.readlink(exe))
    except OSError:
        fail("this gate was not invoked through the pinned uv launcher")
    os.set_inheritable(fd, True)
    return fd, resolved


def canonical_json(value: Any, *, newline: bool = False) -> bytes:
    suffix = "\n" if newline else ""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + suffix
    ).encode("utf-8")


def run_sdist_audit(label: str, action: Callable[[], None]) -> None:
    if label not in R16_14_SDIST_CALL_EVENTS:
        fail(f"unregistered R16-14 sdist audit event: {label}")
    action()
    _SDIST_AUDIT_CALLS.add(label)
    event = R16_14_SDIST_CALL_EVENTS[label]
    if event not in _R16_14_SDIST_EFFECT_EVENTS:
        _R16_14_SDIST_EFFECT_EVENTS.append(dict(event))


def assert_sdist_audit_wiring() -> None:
    global _SDIST_WIRING_ASSERTED
    if len(_REQUIRED_SDIST_AUDIT_CALLS) < FROZEN_REQUIRED_SDIST_AUDIT_CALL_COUNT:
        fail(
            "required sdist audit call set shrank below its frozen count: "
            f"{len(_REQUIRED_SDIST_AUDIT_CALLS)} < "
            f"{FROZEN_REQUIRED_SDIST_AUDIT_CALL_COUNT}"
        )
    missing = _REQUIRED_SDIST_AUDIT_CALLS - _SDIST_AUDIT_CALLS
    if missing:
        fail(
            "required sdist audit call sites were not reached: "
            f"{sorted(missing)!r}"
        )
    extra = _SDIST_AUDIT_CALLS - _REQUIRED_SDIST_AUDIT_CALLS
    if extra:
        fail(
            "unregistered sdist audit call sites were reached: "
            f"{sorted(extra)!r}"
        )
    expected_events = list(R16_14_SDIST_CALL_EVENTS.values())
    missing_events = [
        event for event in expected_events if event not in _R16_14_SDIST_EFFECT_EVENTS
    ]
    if missing_events:
        fail(
            "required R16-14 sdist audit effect was not observed: "
            f"{missing_events[0]['identity']}"
        )
    if len(_R16_14_SDIST_EFFECT_EVENTS) != len(expected_events):
        fail(
            "R16-14 sdist audit effect population differs: "
            f"observed={len(_R16_14_SDIST_EFFECT_EVENTS)} "
            f"expected={len(expected_events)}"
        )
    _SDIST_WIRING_ASSERTED = True


def assert_wheel_member_closure(wheel_artifacts: dict[str, Path]) -> None:
    global _WHEEL_CLOSURE_ASSERTED
    for label, wheel in wheel_artifacts.items():
        if (str(wheel.resolve()), digest(wheel)) not in _WHEEL_MEMBER_CLOSURE:
            fail(
                "production wheel member-set closure was not performed: "
                f"label={label}"
            )
    _WHEEL_CLOSURE_ASSERTED = True


def run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=capture,
        text=True,
    )
    if result.returncode:
        output = (result.stdout or "") + (result.stderr or "")
        fail(f"{label} failed:\n{output[-8000:]}")
    return result


def load_canonical(path: Path, *, newline: bool = False) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"non-JSON control input: {path}: {exc}")
    if type(value) is not dict or raw != canonical_json(value, newline=newline):
        fail(f"control input is not canonical JSON: {path}")
    return value


def checked_toolchain() -> tuple[dict[str, str], Path, Path]:
    toolchain = load_canonical(TOOLCHAIN_PATH, newline=True)
    if (
        toolchain.get("schema") != "kilix.content.reproducible-build-toolchain/v1"
        or str(toolchain.get("source_date_epoch")) != SOURCE_DATE_EPOCH
    ):
        fail("build-toolchain identity is not frozen")
    environment = toolchain.get("environment")
    if type(environment) is not dict:
        fail("build environment is not a closed object")
    allowlist = environment.get("allowlist")
    assignments = environment.get("assignments")
    if (
        type(allowlist) is not list
        or type(assignments) is not dict
        or set(allowlist) != set(assignments)
        or allowlist != sorted(allowlist)
    ):
        fail("build environment allowlist and assignments differ")
    env = {str(key): str(value) for key, value in assignments.items()}

    actual_tools = {name: importlib.metadata.version(name) for name in EXPECTED_TOOLS}
    if actual_tools != EXPECTED_TOOLS or toolchain.get("tools") != EXPECTED_TOOLS:
        fail(f"running build tools do not match the frozen versions: {actual_tools!r}")
    python = toolchain.get("python")
    if type(python) is not dict:
        fail("Python toolchain identity is absent")
    actual_version = ".".join(str(part) for part in sys.version_info[:3])
    base_python = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if (
        actual_version != python.get("version")
        or str(base_python) != python.get("executable")
        or digest(base_python) != python.get("sha256")
    ):
        fail("running Python does not match build-toolchain.json")
    uv = toolchain.get("uv")
    if type(uv) is not dict:
        fail("uv toolchain identity is absent")
    if "executable" in uv:
        fail("uv executable path is not a build-authority field")
    global _BUILD_LAUNCHER_FD
    uv_fd, uv_path = open_build_launcher()
    if digest_fd(uv_fd) != uv.get("sha256"):
        fail("invoking uv image does not match build-toolchain.json")
    _BUILD_LAUNCHER_FD = uv_fd
    version = run(
        [str(uv_path), "--version"],
        cwd=PROJECT,
        env=env,
        label="uv identity probe",
    ).stdout.split()
    if len(version) < 2 or version[1] != uv.get("version"):
        fail("uv version does not match build-toolchain.json")
    print(f"build-authority launcher: measured_sha256={uv.get('sha256')} image={uv_path}")

    inputs = toolchain.get("inputs")
    expected_inputs = {
        "pyproject_sha256": digest(PROJECT / "pyproject.toml"),
        "requirements_sha256": digest(PROJECT / WHEELHOUSE_NAME / "requirements.txt"),
        "uv_lock_sha256": digest(PROJECT / "uv.lock"),
        "wheelhouse_manifest_sha256": digest(
            PROJECT / WHEELHOUSE_NAME / "manifest.json"
        ),
    }
    if inputs != expected_inputs:
        fail("build-toolchain input hashes are stale")
    return env, uv_path, base_python


def safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    normalized = posixpath.normpath(name.rstrip("/"))
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or normalized != name.rstrip("/")
    ):
        fail("archive contains an unsafe member name")
    return normalized


def verify_wheelhouse(root: Path) -> dict[str, Any]:
    wheelhouse = root / WHEELHOUSE_NAME
    manifest_path = wheelhouse / "manifest.json"
    manifest = load_canonical(manifest_path)
    if (
        manifest.get("schema") != "kilix.content.offline-wheelhouse/v1"
        or manifest.get("python_version") != "3.12.8"
        or manifest.get("platform") != "linux-x86_64-glibc"
        or manifest.get("pyproject_sha256") != digest(root / "pyproject.toml")
        or manifest.get("uv_lock_sha256") != digest(root / "uv.lock")
        or manifest.get("requirements_sha256")
        != digest(wheelhouse / "requirements.txt")
    ):
        fail("offline wheelhouse authority is stale")
    entries = manifest.get("wheels")
    if type(entries) is not list:
        fail("offline wheelhouse inventory is not an array")
    observed_files = {path.name for path in wheelhouse.glob("*.whl")}
    declared_files: set[str] = set()
    distributions: dict[str, str] = {}
    canonical_entries: list[bytes] = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "filename",
            "name",
            "version",
            "tags",
            "size",
            "sha256",
        }:
            fail("offline wheelhouse entry shape is not frozen")
        filename = entry["filename"]
        if type(filename) is not str or filename in declared_files:
            fail("offline wheelhouse filename is invalid or duplicated")
        path = wheelhouse / filename
        if (
            path.parent != wheelhouse
            or not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != entry["size"]
            or digest(path) != entry["sha256"]
        ):
            fail("offline wheelhouse file differs from its manifest")
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                fail("offline wheel has an invalid CRC")
            names = archive.namelist()
            if len(names) != len({safe_member_name(name) for name in names}):
                fail("offline wheel has duplicate normalized members")
        declared_files.add(filename)
        name = entry["name"]
        version = entry["version"]
        if type(name) is not str or type(version) is not str:
            fail("offline wheel distribution identity is not text")
        normalized_name = name.lower().replace("_", "-")
        if normalized_name in distributions:
            fail("offline wheel distribution is duplicated")
        distributions[normalized_name] = version
        canonical_entries.append(canonical_json(entry))
    if (
        declared_files != observed_files
        or distributions != EXPECTED_WHEEL_DISTRIBUTIONS
        or canonical_entries != sorted(canonical_entries)
    ):
        fail("offline wheelhouse inventory is incomplete, extra, or unsorted")
    return manifest


def verify_export(
    root: Path,
    uv_path: Path,
    python: Path,
    env: dict[str, str],
    destination: Path,
) -> None:
    run(
        [
            str(uv_path),
            "export",
            "--locked",
            "--offline",
            "--python",
            str(python),
            "--all-groups",
            "--no-emit-project",
            "--no-annotate",
            "--no-header",
            "--format",
            "requirements.txt",
            "--output-file",
            str(destination),
        ],
        cwd=root,
        env=env,
        label="locked requirement export",
    )
    if (
        destination.read_bytes()
        != (root / WHEELHOUSE_NAME / "requirements.txt").read_bytes()
    ):
        fail("locked requirement export differs from committed wheelhouse input")


def bootstrap_environment(
    root: Path,
    destination: Path,
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    *,
    install_project: bool,
) -> tuple[Path, dict[str, str]]:
    destination.mkdir(parents=True, exist_ok=True)
    wheelhouse = root / WHEELHOUSE_NAME
    cache = destination / "empty-uv-cache"
    environment = dict(base_env)
    environment["UV_CACHE_DIR"] = str(cache)
    venv = destination / "venv"
    run(
        [
            str(uv_path),
            "venv",
            "--no-project",
            "--python",
            str(base_python),
            "--no-python-downloads",
            str(venv),
        ],
        cwd=destination,
        env=environment,
        label="empty-cache venv creation",
    )
    python = venv / "bin" / "python"
    run(
        [
            str(uv_path),
            "pip",
            "install",
            "--python",
            str(python),
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--require-hashes",
            "--requirement",
            str(wheelhouse / "requirements.txt"),
        ],
        cwd=destination,
        env=environment,
        label="empty-cache offline dependency reconstruction",
    )
    if install_project:
        run(
            [
                str(uv_path),
                "pip",
                "install",
                "--python",
                str(python),
                "--no-index",
                "--find-links",
                str(wheelhouse),
                "--no-deps",
                "--no-build-isolation",
                str(root),
            ],
            cwd=destination,
            env=environment,
            label="offline local-project installation",
        )
    return python, environment


def source_gates(root: Path, python: Path, env: dict[str, str]) -> None:
    run(
        [str(python), "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=root,
        env=env,
        label="locked source test suite",
    )
    run(
        [str(python), "tests/update_u1_hashes.py", "--check"],
        cwd=root,
        env=env,
        label="fixture hash check",
    )
    ruff = python.parent / "ruff"
    run(
        [str(ruff), "check", "src", "tests", "tools"],
        cwd=root,
        env=env,
        label="pinned Ruff check",
    )


def build(
    source: Path,
    output: Path,
    python: Path,
    env: dict[str, str],
    *kinds: str,
) -> dict[str, Path]:
    output.mkdir(parents=True)
    run(
        [
            str(python),
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(output),
            *kinds,
            str(source),
        ],
        cwd=source,
        env=env,
        label="pinned offline artifact build",
    )
    artifacts: dict[str, Path] = {}
    for kind, suffix in (("sdist", ".tar.gz"), ("wheel", ".whl")):
        if f"--{kind}" in kinds:
            matches = sorted(output.glob(f"*{suffix}"))
            if len(matches) != 1:
                fail(f"expected exactly one {kind} artifact")
            artifacts[kind] = matches[0]
    return artifacts


def wheel_distribution_root(root: Path) -> str:
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
        name = project["name"]
        version = project["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        fail(f"wheel distribution identity is not source-derived: {exc}")
    if type(name) is not str or type(version) is not str:
        fail("wheel distribution name/version are not text")
    normalized = re.sub(r"[-_.]+", "_", name)
    return f"{normalized}-{version}"


def source_importable_members(
    root: Path,
    package_expected: dict[str, tuple[str, bytes]],
) -> set[str]:
    source = root / "src" / "kilix_content"
    if source.is_symlink() or not source.is_dir():
        fail("source importable package root is not a real directory")
    resource_members = {f"kilix_content/{path}" for path in package_expected}
    observed: set[str] = set()
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            fail(f"source importable tree contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"source importable tree contains a special member: {path}")
        relative = path.relative_to(source)
        if path.suffix not in {".py", ".pyi"} and path.name != "py.typed":
            continue
        member = PurePosixPath("kilix_content", *relative.parts).as_posix()
        if member not in resource_members:
            observed.add(member)
    return observed


def expected_wheel_members(
    root: Path,
    package_expected: dict[str, tuple[str, bytes]],
    external_expected: dict[str, tuple[str, bytes]],
) -> set[str]:
    package = {f"kilix_content/{path}" for path in package_expected}
    importable = source_importable_members(root, package_expected)
    distribution = wheel_distribution_root(root)
    external = {
        f"{distribution}.data/data/share/kilix-content/{path}"
        for path in external_expected
    }
    metadata_names = {
        "licenses/LICENSE",
        "METADATA",
        "WHEEL",
        "top_level.txt",
        "RECORD",
    }
    scripts = tomllib.loads((root / "pyproject.toml").read_text())["project"].get(
        "scripts", {}
    )
    if type(scripts) is not dict:
        fail("project.scripts is not a closed table")
    if scripts:
        metadata_names.add("entry_points.txt")
    metadata = {
        f"{distribution}.dist-info/{path}"
        for path in metadata_names
    }
    categories = {
        "package resource": package,
        "importable package": importable,
        "external data": external,
        "distribution metadata": metadata,
    }
    category_names = list(categories)
    for index, left_name in enumerate(category_names):
        for right_name in category_names[index + 1 :]:
            overlap = categories[left_name] & categories[right_name]
            if overlap:
                fail(
                    "wheel member categories overlap: "
                    f"{left_name}/{right_name}={sorted(overlap)!r}"
                )
    expected = set().union(*categories.values())
    expected_count = sum(len(category) for category in categories.values())
    if len(expected) != expected_count:
        fail(
            "source-derived wheel closure has an unexpected member count: "
            f"derived={expected_count} observed={len(expected)}"
        )
    return expected


def sdist_distribution_root(root: Path) -> str:
    return wheel_distribution_root(root)


def source_sdist_files(root: Path) -> set[str]:
    excluded_parts = {
        ".git",
        ".venv",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        ".eggs",
    }
    observed: set[str] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(
            part in excluded_parts or part.endswith(".egg-info")
            for part in relative.parts
        ):
            continue
        if path.is_symlink():
            fail(f"sdist source tree contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"sdist source tree contains a special member: {relative}")
        if path.name == ".gitignore" or path.suffix == ".pyc":
            continue
        observed.add(PurePosixPath(*relative.parts).as_posix())
    observed.update(GENERATED_SDIST_FILES)
    return observed


def expected_sdist_members(root: Path) -> set[str]:
    top = sdist_distribution_root(root)
    files = source_sdist_files(root)
    directories: set[str] = set()
    for file_name in files:
        parts = PurePosixPath(file_name).parts
        directories.update(
            PurePosixPath(*parts[:index]).as_posix() + "/"
            for index in range(1, len(parts))
        )
    return {top} | {f"{top}/{member}" for member in files | directories}


def compare_member_sets(
    label: str,
    observed: set[str],
    expected: set[str],
) -> None:
    if observed == expected:
        return
    fail(
        f"{label} complete member set differs: "
        f"expected_count={len(expected)} observed_count={len(observed)} "
        f"missing={sorted(expected - observed)!r} "
        f"extra={sorted(observed - expected)!r}"
    )


@records_audit_effect("sdist", "payload")
def sdist_payload_audit(
    archive: Path,
    source_root: Path,
    top: str,
) -> None:
    with tarfile.open(archive, "r:gz") as handle:
        for member in read_sdist_members(handle):
            key = safe_member_name(member.name)
            if member.isdir() or key == top:
                continue
            relative = key.removeprefix(top + "/")
            if relative in GENERATED_SDIST_FILES:
                continue
            source = source_root / relative
            if source.is_symlink() or not source.is_file():
                fail(f"sdist payload source member is absent: {relative}")
            payload = sdist_member_payload(handle, member)
            expected = source.read_bytes()
            if (
                len(payload) != len(expected)
                or hashlib.sha256(payload).hexdigest()
                != hashlib.sha256(expected).hexdigest()
                or payload != expected
            ):
                fail(f"sdist payload differs from source: {relative}")


@records_audit_effect("sdist", "closure")
def sdist_member_closure_audit(archive: Path) -> None:
    with tarfile.open(archive, "r:gz") as handle:
        members = read_sdist_members(handle)
    if not members:
        fail("sdist is empty")
    top = PurePosixPath(members[0].name).parts[0]
    expected_top = sdist_distribution_root(PROJECT)
    if top != expected_top:
        fail(f"sdist root identity differs: expected={expected_top!r} observed={top!r}")
    observed: set[str] = set()
    for member in members:
        key = safe_member_name(member.name)
        if PurePosixPath(member.name).parts[0] != top:
            fail("sdist has a split-root member")
        if not (member.isdir() or member.isfile()):
            fail("sdist contains a linked or special member")
        expected_mode = (
            EXPECTED_SDIST_DIRECTORY_MODE
            if member.isdir()
            else EXPECTED_SDIST_FILE_MODE
        )
        if stat.S_IMODE(member.mode) != expected_mode:
            relative = key if key == top else key.removeprefix(top + "/")
            fail(
                f"sdist member permissions differ: {relative} "
                f"expected={oct(expected_mode)} observed={oct(stat.S_IMODE(member.mode))}"
            )
        if member.isdir() and member.size != 0:
            fail(f"sdist directory member is nonempty: {key}")
        observed.add(key if key == top or not member.isdir() else key + "/")
    compare_member_sets("sdist", observed, expected_sdist_members(PROJECT))


def sdist_relative_member_signature(
    archive: Path,
) -> tuple[str, set[tuple[str, bytes, int, int, bytes]]]:
    run_sdist_audit(
        "relative-enumerator",
        lambda: assert_sdist_enumerator_agreement(archive),
    )
    with tarfile.open(archive, "r:gz") as handle:
        members = read_sdist_members(handle)
        if not members:
            fail("sdist is empty")
        roots = {PurePosixPath(safe_member_name(member.name)).parts[0] for member in members}
        if len(roots) != 1:
            fail(f"sdist signature has multiple roots: {sorted(roots)!r}")
        top = next(iter(roots))
        signatures: set[tuple[str, bytes, int, int, bytes]] = set()
        for member in members:
            key = safe_member_name(member.name)
            relative = "" if key == top else key.removeprefix(top + "/")
            payload = sdist_member_payload(handle, member)
            signatures.add(
                (
                    relative,
                    member.type,
                    stat.S_IMODE(member.mode),
                    member.size,
                    payload,
                )
            )
        return top, signatures


def sdist_generated_metadata_payloads(
    archive: Path,
) -> dict[str, tuple[str, bytes]]:
    run_sdist_audit(
        "generated-enumerator",
        lambda: assert_sdist_enumerator_agreement(archive),
    )
    with tarfile.open(archive, "r:gz") as handle:
        members = read_sdist_members(handle)
        if not members:
            fail("sdist is empty")
        top = PurePosixPath(safe_member_name(members[0].name)).parts[0]
        payloads: dict[str, tuple[str, bytes]] = {}
        for member in members:
            key = safe_member_name(member.name)
            relative = key.removeprefix(top + "/")
            if relative not in GENERATED_SDIST_FILES:
                continue
            payload = sdist_member_payload(handle, member)
            payloads[relative] = (hashlib.sha256(payload).hexdigest(), payload)
        if set(payloads) != GENERATED_SDIST_FILES:
            fail(
                "generated sdist metadata closure differs: "
                f"expected={sorted(GENERATED_SDIST_FILES)!r} "
                f"observed={sorted(payloads)!r}"
            )
        return payloads


@records_audit_effect(
    "sdist", "generated-metadata", artifact_arguments=(0, 1)
)
def sdist_generated_metadata_audit(first: Path, second: Path) -> None:
    first_payloads = sdist_generated_metadata_payloads(first)
    second_payloads = sdist_generated_metadata_payloads(second)
    for relative in sorted(GENERATED_SDIST_FILES):
        if first_payloads[relative] != second_payloads[relative]:
            fail(f"generated sdist metadata is not reproducible: {relative}")
    print("generated sdist metadata reproducibility audit: PASS")


def read_sdist_members(handle: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    while True:
        member = handle.next()
        if member is None:
            return members
        if type(member.size) is not int or member.size < 0:
            fail(f"sdist member has a noncanonical negative size: {member.name!r}")
        members.append(member)
        physical_size = physical_sdist_member_size(handle, member)
        if physical_size < 0:
            fail(f"sdist member has a noncanonical physical size: {member.name!r}")
        if physical_size != member.size:
            fail(
                "sdist member logical size differs from physical header size: "
                f"{member.name!r} logical={member.size} physical={physical_size}"
            )
        if member.type in SDIST_DATA_BLOCK_TYPES and physical_size:
            if handle.fileobj is None or member.offset_data is None:
                fail("sdist carrier payload has no readable data offset")
            blocks = (physical_size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
            handle.offset = member.offset_data + blocks * tarfile.BLOCKSIZE
            if handle.offset > handle.fileobj.seek(0, os.SEEK_END):
                fail("sdist carrier payload exceeds archive bounds")
            handle.fileobj.seek(handle.offset)


def physical_sdist_member_size(
    handle: tarfile.TarFile, member: tarfile.TarInfo
) -> int:
    if handle.fileobj is None or member.offset_data is None:
        fail("sdist member has no physical data offset")
    header_offset = member.offset_data - tarfile.BLOCKSIZE
    if header_offset < 0:
        fail("sdist member has an invalid physical header offset")
    resume = handle.fileobj.tell()
    try:
        handle.fileobj.seek(header_offset)
        raw_header = handle.fileobj.read(tarfile.BLOCKSIZE)
    finally:
        handle.fileobj.seek(resume)
    if len(raw_header) != tarfile.BLOCKSIZE:
        fail("sdist member physical header is truncated")
    try:
        physical = tarfile.TarInfo.frombuf(
            raw_header, encoding="utf-8", errors="surrogateescape"
        )
    except (tarfile.TarError, ValueError) as exc:
        fail(f"sdist member physical header is invalid: {exc}")
    return physical.size


def sdist_member_payload(handle: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    physical_size = physical_sdist_member_size(handle, member)
    if physical_size != member.size:
        fail(
            "sdist member logical size differs from physical header size: "
            f"{member.name!r} logical={member.size} physical={physical_size}"
        )
    if member.type in SDIST_DATA_BLOCK_TYPES:
        if not physical_size:
            return b""
        if handle.fileobj is None or member.offset_data is None:
            fail("sdist carrier payload has no readable data offset")
        resume = handle.offset
        handle.fileobj.seek(member.offset_data)
        payload = handle.fileobj.read(physical_size)
        handle.fileobj.seek(resume)
        if len(payload) != physical_size:
            fail("sdist carrier payload is truncated")
        return payload
    payload_file = handle.extractfile(member)
    if payload_file is None:
        fail(f"sdist member payload cannot be read: {member.name}")
    payload = payload_file.read()
    if len(payload) != physical_size:
        fail(f"sdist member payload is truncated: {member.name}")
    return payload


@records_audit_effect("sdist", "enumerator")
def assert_sdist_enumerator_agreement(
    archive: Path, *, check_container: bool = True
) -> None:
    """The stock parser is a negative control, never production authority."""
    if check_container:
        run_sdist_audit(
            "enumerator-container",
            lambda: sdist_container_audit(archive),
        )
    with tarfile.open(archive, "r:gz") as handle:
        stock = handle.getmembers()
        if not stock:
            fail("sdist archive is empty")
    with tarfile.open(archive, "r:gz") as handle:
        bounded = read_sdist_members(handle)
    stock_names = [safe_member_name(member.name) for member in stock]
    bounded_names = [safe_member_name(member.name) for member in bounded]
    if stock_names != bounded_names:
        fail(
            "sdist archive enumerators disagree: "
            f"getmembers_count={len(stock_names)} "
            f"bounded_count={len(bounded_names)}"
        )


@records_audit_effect("sdist", "container")
def sdist_container_audit(archive: Path) -> None:
    """Verify gzip framing and that tar has no bytes after its end marker."""
    try:
        compressed = io.BytesIO(archive.read_bytes())
        with gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
            chunks: list[bytes] = []
            output_size = 0
            compressed_size = max(1, len(compressed.getbuffer()))
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                output_size += len(chunk)
                if output_size > MAX_SDIST_TAR_PAYLOAD_BYTES:
                    fail("sdist gzip expansion exceeds the absolute limit")
                if output_size > compressed_size * MAX_SDIST_EXPANSION_RATIO:
                    fail("sdist gzip expansion ratio exceeds the limit")
            tar_payload = b"".join(chunks)
        if compressed.read():
            fail("sdist gzip has trailing bytes")
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error, MemoryError) as exc:
        fail(f"sdist gzip container integrity failed: {exc}")
    if len(tar_payload) == 0 or len(tar_payload) % tarfile.BLOCKSIZE:
        fail("sdist tar payload is not block-aligned")
    zero_block = b"\0" * tarfile.BLOCKSIZE
    offset = 0
    end_offset: int | None = None
    try:
        while offset + 2 * tarfile.BLOCKSIZE <= len(tar_payload):
            header = tar_payload[offset : offset + tarfile.BLOCKSIZE]
            if header == zero_block and tar_payload[
                offset + tarfile.BLOCKSIZE : offset + 2 * tarfile.BLOCKSIZE
            ] == zero_block:
                end_offset = offset + 2 * tarfile.BLOCKSIZE
                break
            member = tarfile.TarInfo.frombuf(
                header, encoding="utf-8", errors="surrogateescape"
            )
            if type(member.size) is not int or member.size < 0:
                fail("sdist tar contains a noncanonical negative member size")
            blocks = (member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
            offset += tarfile.BLOCKSIZE + blocks * tarfile.BLOCKSIZE
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        fail(f"sdist tar container integrity failed: {exc}")
    if end_offset is None:
        fail("sdist tar has no end-of-archive marker")
    if end_offset > len(tar_payload) or any(tar_payload[end_offset:]):
        fail("sdist tar has bytes after its end-of-archive marker")


def ordered_sdist_member_records(
    archive: Path,
) -> list[tuple[str, bytes, int, int, bytes]]:
    with tarfile.open(archive, "r:gz") as handle:
        records: list[tuple[str, bytes, int, int, bytes]] = []
        for member in read_sdist_members(handle):
            payload = sdist_member_payload(handle, member)
            records.append(
                (
                    safe_member_name(member.name),
                    member.type,
                    stat.S_IMODE(member.mode),
                    member.size,
                    payload,
                )
            )
        return records


def raw_sdist_member_payload(archive: Path, target: str) -> bytes:
    with tarfile.open(archive, "r:gz") as handle:
        matches = [
            member
            for member in read_sdist_members(handle)
            if safe_member_name(member.name) == target
        ]
        if len(matches) != 1:
            fail(
                "sdist raw-payload control requires exactly one target member: "
                f"{target!r}"
            )
        member = matches[0]
        return sdist_member_payload(handle, member)


def assert_sdist_nonempty_directory_control(
    source: Path,
    mutated: Path,
    target: str,
    declared_payload: bytes,
) -> None:
    source_records = ordered_sdist_member_records(source)
    mutated_records = ordered_sdist_member_records(mutated)
    if len(source_records) != len(mutated_records):
        fail("sdist nonempty-directory control changed member count")
    changed = 0
    for source_record, mutated_record in zip(source_records, mutated_records):
        if source_record[0] != mutated_record[0]:
            fail("sdist nonempty-directory control changed member ordering")
        if source_record[0] != target:
            if source_record != mutated_record:
                fail("sdist nonempty-directory control changed another member")
            continue
        if source_record[1] != tarfile.DIRTYPE or mutated_record[1] != tarfile.DIRTYPE:
            fail("sdist nonempty-directory control lost directory type")
        if source_record[2] != mutated_record[2] or source_record[3] != 0:
            fail("sdist nonempty-directory control changed directory mode")
        if mutated_record[3] != len(declared_payload):
            fail("sdist nonempty-directory control is not nonempty")
        changed += 1
    if changed != 1:
        fail("sdist nonempty-directory control did not change exactly one record")
    if raw_sdist_member_payload(mutated, target) != declared_payload:
        fail("sdist nonempty-directory control payload is not physically encoded")


def add_sdist_member_with_payload(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    payload: bytes,
) -> None:
    if member.isfile():
        archive.addfile(member, io.BytesIO(payload))
        return
    if member.isdir():
        # tarfile does not consume data blocks for directory-typed members.
        # Write the declared bytes explicitly so the control exercises the
        # physical tar payload rather than only the header size.
        if archive.fileobj is None:
            fail("sdist archive has no writable file object")
        header = member.tobuf(
            format=archive.format,
            encoding=archive.encoding,
            errors=archive.errors,
        )
        archive.fileobj.write(header)
        archive.offset += len(header)
        archive.fileobj.write(payload)
        archive.offset += len(payload)
        padding = (-len(payload)) % tarfile.BLOCKSIZE
        if padding:
            archive.fileobj.write(b"\0" * padding)
            archive.offset += padding
        return
    if archive.fileobj is None:
        fail("sdist archive has no writable file object")
    header = member.tobuf(
        format=archive.format,
        encoding=archive.encoding,
        errors=archive.errors,
    )
    archive.fileobj.write(header)
    archive.offset += len(header)
    archive.fileobj.write(payload)
    archive.offset += len(payload)
    padding = (-len(payload)) % tarfile.BLOCKSIZE
    if padding:
        archive.fileobj.write(b"\0" * padding)
        archive.offset += padding


def extract_sdist(archive: Path, destination: Path) -> Path:
    run_sdist_audit(
        "extract-container",
        lambda: sdist_container_audit(archive),
    )
    with tarfile.open(archive, "r:gz") as handle:
        members = read_sdist_members(handle)
        if not members:
            fail("sdist is empty")
        top = PurePosixPath(members[0].name).parts[0]
        expected_top = sdist_distribution_root(PROJECT)
        if top != expected_top:
            fail(
                "sdist root identity differs: "
                f"expected={expected_top!r} observed={top!r}"
            )
        normalized: set[str] = set()
        observed: set[str] = set()
        for member in members:
            key = safe_member_name(member.name)
            if key in normalized or PurePosixPath(member.name).parts[0] != top:
                fail("sdist has duplicate or split-root members")
            normalized.add(key)
            if not (member.isdir() or member.isfile()):
                fail("sdist contains a linked or special member")
            expected_mode = (
                EXPECTED_SDIST_DIRECTORY_MODE
                if member.isdir()
                else EXPECTED_SDIST_FILE_MODE
            )
            if stat.S_IMODE(member.mode) != expected_mode:
                relative = key if key == top else key.removeprefix(top + "/")
                fail(
                    f"sdist member permissions differ: {relative} "
                    f"expected={oct(expected_mode)} "
                    f"observed={oct(stat.S_IMODE(member.mode))}"
                )
            if member.isdir() and member.size != 0:
                fail(f"sdist directory member is nonempty: {key}")
            if member.isdir():
                observed.add(key if key == top else key + "/")
            else:
                observed.add(key)
        compare_member_sets(
            "sdist",
            observed,
            expected_sdist_members(PROJECT),
        )
        run_sdist_audit(
            "extract-enumerator",
            lambda: assert_sdist_enumerator_agreement(archive),
        )
        run_sdist_audit(
            "extract-payload",
            lambda: sdist_payload_audit(archive, PROJECT, top),
        )
        handle.extractall(destination, members=members, filter="data")
    root = destination / top
    required = (
        ".python-version",
        "build-toolchain.json",
        "pyproject.toml",
        "uv.lock",
        "wheelhouse/manifest.json",
        "wheelhouse/requirements.txt",
        "tests/fixtures/u1/index.json",
        "tests/fixtures/u1/SHA256SUMS",
        "tests/check_reproducible_build.py",
    )
    if any(not (root / name).is_file() for name in required):
        fail("sdist lacks a mandatory locked input or security corpus authority")
    return root


def classify_wheel_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    check_permissions: bool = True,
) -> int:
    name = info.filename
    safe_member_name(name)
    if info.create_system != 3:
        fail(f"wheel member creator/type is ambiguous: {name}")
    mode_word = info.external_attr >> 16
    kind = stat.S_IFMT(mode_word)
    if kind not in (stat.S_IFREG, stat.S_IFDIR):
        fail(f"wheel member has an unsupported or unknown type: {name}")
    permissions = stat.S_IMODE(mode_word)
    if check_permissions:
        if kind == stat.S_IFREG:
            expected_mode = (
                EXPECTED_WHEEL_RECORD_MODE
                if name.endswith(".dist-info/RECORD")
                else EXPECTED_WHEEL_FILE_MODE
            )
        else:
            expected_mode = EXPECTED_WHEEL_DIRECTORY_MODE
        if permissions != expected_mode:
            fail(
                f"wheel member permissions differ: {name} "
                f"expected={oct(expected_mode)} observed={oct(permissions)}"
            )
    is_directory_name = name.endswith("/")
    if kind == stat.S_IFREG:
        if is_directory_name:
            fail(f"wheel regular member has a directory spelling: {name}")
    else:
        if not is_directory_name or name != name.rstrip("/") + "/":
            fail(f"wheel directory member has a noncanonical spelling: {name}")
        if archive.read(name):
            fail(f"wheel directory member is nonempty: {name}")
    return kind


@records_audit_effect("wheel", "container")
def wheel_container_audit(wheel: Path) -> None:
    """Reject bytes outside the final ZIP end record before zipfile parsing."""
    raw = wheel.read_bytes()
    if len(raw) < 22:
        fail("wheel container is truncated")
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(raw):
        fail("wheel container has no complete end record")
    comment_length = int.from_bytes(raw[eocd + 20 : eocd + 22], "little")
    end = eocd + 22 + comment_length
    if end != len(raw):
        fail("wheel container has trailing bytes")
    cd_size = int.from_bytes(raw[eocd + 12 : eocd + 16], "little")
    cd_offset = int.from_bytes(raw[eocd + 16 : eocd + 20], "little")
    if cd_offset + cd_size != eocd:
        fail("wheel container has bytes outside the central directory record")
    if raw[cd_offset : cd_offset + 4] != b"PK\x01\x02":
        fail("wheel container central directory offset is displaced")


@records_audit_effect("wheel", "archive")
def wheel_archive_audit(
    wheel: Path,
    expected_members: set[str] | None = None,
) -> set[str]:
    wheel_container_audit(wheel)
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            fail("wheel CRC check failed")
        infos = archive.infolist()
        names = [info.filename for info in infos]
        normalized = {safe_member_name(name) for name in names}
        if len(normalized) != len(names):
            fail("wheel has duplicate normalized members")
        for info in infos:
            classify_wheel_member(archive, info, check_permissions=False)
        if expected_members is not None:
            compare_member_sets("wheel", set(names), expected_members)
            _WHEEL_MEMBER_CLOSURE.add((str(wheel.resolve()), digest(wheel)))
        for info in infos:
            classify_wheel_member(archive, info)
        forbidden = (
            "tests/",
            "fixtures/",
            "u1_vectors",
            "wheelhouse/",
            "fixture-index",
            "synthetic",
        )
        if any(any(token in name.lower() for token in forbidden) for name in names):
            fail("wheel contains test, wheelhouse, or fixture authority")
    return set(names)


@records_audit_effect("wheel", "record")
def record_audit(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            fail("wheel CRC check failed")
        names = [info.filename for info in archive.infolist()]
        records = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            fail("wheel does not contain exactly one RECORD")
        rows = list(csv.reader(archive.read(records[0]).decode("utf-8").splitlines()))
        if len(rows) != len(names) or {row[0] for row in rows} != set(names):
            fail("wheel RECORD membership is not exact")
        for path, encoded, size in rows:
            data = archive.read(path)
            if path == records[0]:
                if encoded or size:
                    fail("wheel RECORD self-row is not empty")
                continue
            expected = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(data).digest()
            ).rstrip(b"=").decode("ascii")
            if encoded != expected or size != str(len(data)):
                fail("wheel RECORD digest or size is inconsistent")


def record_self_row_empty_control(
    wheel: Path,
    expected_members: set[str],
    temporary: Path,
) -> None:
    temporary.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel) as archive:
        record_names = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/RECORD")
        ]
        if len(record_names) != 1:
            fail("RECORD self-row control requires exactly one RECORD")
        record_name = record_names[0]
        rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
    bad_rows: list[tuple[str, str, str]] = []
    changed = 0
    for row in rows:
        if len(row) != 3:
            fail("RECORD self-row control found a malformed source row")
        if row[0] == record_name:
            encoded = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(b"nonempty-record-self-row").digest()
            ).rstrip(b"=").decode("ascii")
            bad_rows.append((row[0], encoded, "24"))
            changed += 1
        else:
            bad_rows.append((row[0], row[1], row[2]))
    if changed != 1:
        fail("RECORD self-row control did not mutate exactly one self-row")
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(bad_rows)
    mutated = temporary / "record-self-row-nonempty.whl"
    rewrite_wheel(wheel, mutated, replace={record_name: output.getvalue().encode("utf-8")})
    wheel_archive_audit(mutated, expected_members)
    expect_audit_failure(
        "wheel RECORD self-row empty control",
        lambda: record_audit(mutated),
        "wheel RECORD self-row is not empty",
    )
    _RECORD_SELF_ROW_CONTROL_OBSERVED.add("record-self-row")
    print("wheel RECORD self-row empty parity control: PASS")


def rewrite_wheel_nonempty_record_self_row(
    wheel: Path, destination: Path
) -> None:
    with zipfile.ZipFile(wheel) as archive:
        record_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/RECORD")
        ]
        if len(record_names) != 1:
            fail("RECORD mutation requires exactly one RECORD")
        record_name = record_names[0]
        rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
    changed = 0
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for row in rows:
        if len(row) != 3:
            fail("RECORD mutation found a malformed source row")
        if row[0] == record_name:
            row = [row[0], "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(b"r14-nonempty-record").digest()
            ).rstrip(b"=").decode("ascii"), "19"]
            changed += 1
        writer.writerow(row)
    if changed != 1:
        fail("RECORD mutation did not find exactly one self-row")
    rewrite_wheel(wheel, destination, replace={record_name: output.getvalue().encode("utf-8")})


def production_resources(root: Path) -> tuple[bytes, dict[str, tuple[str, bytes]]]:
    manifest_path = root / "contracts" / U1_MANIFEST
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if raw != canonical_json(manifest):
        fail("production resource manifest is not canonical")
    resources: dict[str, tuple[str, bytes]] = {}
    for entry in manifest["resources"]:
        package_path = entry["path"]
        root_copy = root / package_path
        source_path = (
            root_copy
            if root_copy.is_file()
            else root / "src" / "kilix_content" / package_path
        )
        packaged_source = root / "src" / "kilix_content" / package_path
        payload = source_path.read_bytes()
        if (
            payload != packaged_source.read_bytes()
            or len(payload) != entry["size"]
            or hashlib.sha256(payload).hexdigest() != entry["sha256"]
        ):
            fail("source production resource copies diverge")
        resources[package_path] = (entry["sha256"], payload)
    if len(resources) != 28:
        fail("production resource manifest is not exhaustive")
    return raw, resources


def coresident_resources(
    root: Path,
    manifest_resources: dict[str, tuple[str, bytes]],
) -> tuple[dict[str, tuple[str, bytes]], dict[str, tuple[str, bytes]]]:
    package = dict(manifest_resources)
    package_sources = {
        "catalog/__init__.py": root / "src/kilix_content/catalog/__init__.py",
        "catalog/plebian.json": root / "src/kilix_content/catalog/plebian.json",
        "contracts/kilix.content.asset-v1.schema.json": root / "src/kilix_content/contracts/kilix.content.asset-v1.schema.json",
        "contracts/kilix.install.license-v1.schema.json": root / "src/kilix_content/contracts/kilix.install.license-v1.schema.json",
        "contracts/kilix.content.u1-resources-v1.json": root / "src/kilix_content/contracts/kilix.content.u1-resources-v1.json",
    }
    for path, source in package_sources.items():
        payload = source.read_bytes()
        expected_digest = FROZEN_CORESIDENT_HASHES[path]
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            fail(f"frozen co-resident source differs: {path}")
        package[path] = (expected_digest, payload)

    external = dict(manifest_resources)
    external_sources = {
        "contracts/kilix.content.asset-v1.schema.json": root / "contracts/kilix.content.asset-v1.schema.json",
        "contracts/kilix.install.license-v1.schema.json": root / "contracts/kilix.install.license-v1.schema.json",
        "contracts/kilix.content.u1-resources-v1.json": root / "contracts/kilix.content.u1-resources-v1.json",
    }
    for path, source in external_sources.items():
        payload = source.read_bytes()
        expected_digest = FROZEN_CORESIDENT_HASHES[path]
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            fail(f"frozen co-resident source differs: {path}")
        external[path] = (expected_digest, payload)
    if len(package) != 33 or len(external) != 31:
        fail("co-resident production allowlist is not 33/31 files")
    return package, external


def wheel_distribution_name(archive: zipfile.ZipFile) -> str:
    metadata_roots = {
        PurePosixPath(name).parts[0]
        for name in archive.namelist()
        if name.endswith(".dist-info/METADATA")
        and len(PurePosixPath(name).parts) == 2
    }
    if len(metadata_roots) != 1:
        fail("wheel distribution metadata root is ambiguous")
    root = next(iter(metadata_roots))
    return root.removesuffix(".dist-info")


def wheel_resource_prefixes(
    archive: zipfile.ZipFile,
) -> tuple[str, str]:
    distribution = wheel_distribution_name(archive)
    package_prefix = "kilix_content/"
    external_prefix = f"{distribution}.data/data/share/kilix-content/"
    observed_external = {
        "/".join(PurePosixPath(name.rstrip("/")).parts[:4]) + "/"
        for name in archive.namelist()
        if len(PurePosixPath(name.rstrip("/")).parts) >= 4
        and PurePosixPath(name.rstrip("/")).parts[1:4]
        == ("data", "share", "kilix-content")
    }
    if observed_external != {external_prefix}:
        fail(
            "external production resource roots are not exactly one: "
            f"expected={[external_prefix]!r} observed={sorted(observed_external)!r}"
        )
    return package_prefix, external_prefix


def expected_resource_directories(
    expected: dict[str, tuple[str, bytes]],
) -> set[str]:
    directories: set[str] = set()
    for path in expected:
        parts = PurePosixPath(path).parts
        directories.update(
            PurePosixPath(*parts[:index]).as_posix()
            for index in range(1, len(parts))
        )
    return directories


def parent_directories(path: PurePosixPath) -> set[str]:
    return {
        PurePosixPath(*path.parts[:index]).as_posix()
        for index in range(1, len(path.parts))
    }


def audit_resource_tree(
    label: str,
    observed_files: dict[str, bytes],
    observed_directories: set[str],
    expected: dict[str, tuple[str, bytes]],
) -> None:
    expected_paths = set(expected)
    if set(observed_files) != expected_paths:
        missing = sorted(expected_paths - set(observed_files))
        extra = sorted(set(observed_files) - expected_paths)
        fail(
            f"{label} production resource set differs: "
            f"missing={missing!r} extra={extra!r}"
        )
    expected_directories = expected_resource_directories(expected)
    if observed_directories != expected_directories:
        missing = sorted(expected_directories - observed_directories)
        extra = sorted(observed_directories - expected_directories)
        fail(
            f"{label} production resource directories differ: "
            f"missing={missing!r} extra={extra!r}"
        )
    for path, (expected_digest, expected_payload) in expected.items():
        payload = observed_files[path]
        if len(payload) != len(expected_payload):
            fail(f"{label} production resource size mismatch: {path}")
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            fail(f"{label} production resource digest mismatch: {path}")
        if payload != expected_payload:
            fail(f"{label} production resource byte mismatch: {path}")


def archive_resource_mapping(
    archive: zipfile.ZipFile,
    prefix: str,
    *,
    package_subtrees: bool,
) -> tuple[dict[str, bytes], set[str]]:
    observed_files: dict[str, bytes] = {}
    observed_directories: set[str] = set()
    for info in archive.infolist():
        name = info.filename
        if not name.startswith(prefix):
            continue
        relative_name = name[len(prefix) :]
        if not relative_name:
            continue
        relative = PurePosixPath(safe_member_name(relative_name))
        if package_subtrees and relative.parts[0] not in RESOURCE_TOP_LEVELS:
            continue
        if name.endswith("/"):
            observed_directories.add(relative.as_posix())
        else:
            observed_files[relative.as_posix()] = archive.read(name)
        observed_directories.update(parent_directories(relative))
    return observed_files, observed_directories


def filesystem_resource_mapping(
    root: Path,
    *,
    package_subtrees: bool,
) -> tuple[dict[str, bytes], set[str]]:
    observed_files: dict[str, bytes] = {}
    observed_directories: set[str] = set()

    def visit(path: Path, relative: PurePosixPath) -> None:
        if path.is_symlink():
            fail(f"installed production resource is a symlink: {relative}")
        if path.is_dir():
            observed_mode = stat.S_IMODE(path.lstat().st_mode)
            if observed_mode != EXPECTED_WHEEL_DIRECTORY_MODE:
                fail(
                    f"installed production resource permissions differ: {relative} "
                    f"expected={oct(EXPECTED_WHEEL_DIRECTORY_MODE)} "
                    f"observed={oct(observed_mode)}"
                )
            if relative.parts:
                observed_directories.add(relative.as_posix())
            for child in sorted(path.iterdir()):
                visit(child, relative / child.name)
            return
        if not path.is_file():
            fail(f"installed production resource is not regular: {relative}")
        observed_mode = stat.S_IMODE(path.lstat().st_mode)
        if observed_mode != EXPECTED_WHEEL_FILE_MODE:
            fail(
                f"installed production resource permissions differ: {relative} "
                f"expected={oct(EXPECTED_WHEEL_FILE_MODE)} "
                f"observed={oct(observed_mode)}"
            )
        observed_files[relative.as_posix()] = path.read_bytes()

    if package_subtrees:
        for top_name in sorted(RESOURCE_TOP_LEVELS):
            top = root / top_name
            if not top.is_dir():
                fail(f"installed package resource subtree is missing: {top_name}")
            visit(top, PurePosixPath(top_name))
    else:
        if not root.is_dir():
            fail("installed external production resource root is missing")
        visit(root, PurePosixPath())
    return observed_files, observed_directories


def wheel_presentation_payloads(
    archive: zipfile.ZipFile,
    prefix: str,
    expected: dict[str, tuple[str, bytes]],
    label: str,
    *,
    package_subtrees: bool,
) -> tuple[dict[str, bytes], set[str]]:
    observed_files, observed_directories = archive_resource_mapping(
        archive, prefix, package_subtrees=package_subtrees
    )
    audit_resource_tree(label, observed_files, observed_directories, expected)
    return observed_files, observed_directories


def compare_cross_presentation_bytes(
    package_payloads: dict[str, bytes],
    external_payloads: dict[str, bytes],
    manifest_paths: set[str],
) -> None:
    for path in sorted(manifest_paths):
        if package_payloads.get(path) != external_payloads.get(path):
            fail(f"package/external production resource byte mismatch: {path}")


@records_audit_effect("wheel", "resource")
def wheel_resource_audit(
    wheel: Path,
    package_expected: dict[str, tuple[str, bytes]],
    external_expected: dict[str, tuple[str, bytes]],
    manifest_expected: dict[str, tuple[str, bytes]],
) -> None:
    wheel_archive_audit(wheel)
    with zipfile.ZipFile(wheel) as archive:
        package_prefix, external_prefix = wheel_resource_prefixes(archive)
        package_payloads, _ = wheel_presentation_payloads(
            archive,
            package_prefix,
            package_expected,
            "package",
            package_subtrees=True,
        )
        external_payloads, _ = wheel_presentation_payloads(
            archive,
            external_prefix,
            external_expected,
            "external",
            package_subtrees=False,
        )
        compare_cross_presentation_bytes(
            package_payloads, external_payloads, set(manifest_expected)
        )


@records_audit_effect("wheel", "module")
def wheel_module_source_audit(wheel: Path, source_root: Path) -> None:
    """Byte-compare every importable module in the wheel to its source.

    wheel_resource_audit freezes declared resources and coresident files and
    record_audit proves RECORD is internally consistent, but no wheel audit
    binds the shipped importable ``.py`` module bytes to their source. A wheel
    whose ``install.py`` carries a backdoor with exports preserved and RECORD
    repaired therefore clears the whole gate and is imported and executed by
    installed_wheel_audit. This is the wheel sibling of sdist_payload_audit.
    """
    package_prefix = "kilix_content/"
    source_package = source_root / "src" / "kilix_content"
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith("/") or not name.startswith(package_prefix):
                continue
            if not name.endswith(".py"):
                continue
            relative = name[len(package_prefix):]
            source = source_package / relative
            if source.is_symlink() or not source.is_file():
                fail(f"wheel module source is absent: {relative}")
            payload = archive.read(name)
            expected = source.read_bytes()
            if (
                len(payload) != len(expected)
                or hashlib.sha256(payload).hexdigest()
                != hashlib.sha256(expected).hexdigest()
                or payload != expected
            ):
                fail(f"wheel module differs from source: {relative}")


@records_audit_effect("wheel", "resource-authority")
def resource_audit(
    wheel: Path,
    source_root: Path,
    sdist_root: Path,
) -> str:
    source_manifest, source_resources = production_resources(source_root)
    sdist_manifest, sdist_resources = production_resources(sdist_root)
    if source_manifest != sdist_manifest or source_resources != sdist_resources:
        fail("sdist production authority differs from source")
    source_package, source_external = coresident_resources(
        source_root, source_resources
    )
    sdist_package, sdist_external = coresident_resources(
        sdist_root, sdist_resources
    )
    if source_package != sdist_package or source_external != sdist_external:
        fail("sdist co-resident production files differ from source")
    manifest_digest = hashlib.sha256(source_manifest).hexdigest()
    with zipfile.ZipFile(wheel) as archive:
        wheel_manifest = archive.read(f"kilix_content/contracts/{U1_MANIFEST}")
        if wheel_manifest != source_manifest:
            fail(f"{wheel.name} production manifest differs from source")
    wheel_resource_audit(
        wheel, source_package, source_external, source_resources
    )
    return manifest_digest


@records_audit_effect("wheel", "installed")
def installed_wheel_audit(
    wheel: Path,
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    temporary: Path,
    manifest_digest: str,
    package_expected: dict[str, tuple[str, bytes]],
    external_expected: dict[str, tuple[str, bytes]],
    manifest_expected: dict[str, tuple[str, bytes]],
) -> None:
    destination = temporary / "installed-wheel"
    destination.mkdir(parents=True, exist_ok=True)
    python, environment = bootstrap_environment(
        PROJECT,
        destination,
        uv_path,
        base_python,
        base_env,
        install_project=False,
    )
    install_command = [
        str(uv_path),
        "pip",
        "install",
        "--python",
        str(python),
        "--no-index",
        "--find-links",
        str(PROJECT / WHEELHOUSE_NAME),
        "--no-deps",
        str(wheel),
    ]
    previous_umask = os.umask(0o022)
    try:
        run(
            install_command,
            cwd=destination,
            env=environment,
            label="isolated wheel installation",
        )
    finally:
        os.umask(previous_umask)
    external = temporary / "external-cwd"
    external.mkdir(parents=True, exist_ok=True)
    probe = r"""
import hashlib, importlib.resources as resources, json, pathlib, sys, sysconfig
from kilix_content import U1ContractError, packaged_release_capability, validate_u1_bytes, verify_packaged_u1_manifest
expected_manifest = sys.argv[1]
fixture_root = pathlib.Path(sys.argv[2])
forbidden_roots = [pathlib.Path(item).resolve() for item in sys.argv[3:]]
for forbidden in sys.argv[3:]:
    assert forbidden not in sys.path
verify_packaged_u1_manifest()
resource_root = resources.files("kilix_content")
package_path = pathlib.Path(__import__("kilix_content").__file__).resolve().parent
resource_root_path = pathlib.Path(str(resource_root)).resolve()
assert resource_root_path == package_path
package_manifest = resource_root.joinpath("contracts", "kilix.content.u1-resources-v1.json").read_bytes()
assert hashlib.sha256(package_manifest).hexdigest() == expected_manifest
data_root = pathlib.Path(sysconfig.get_path("data")).resolve()
external_root = data_root / "share" / "kilix-content"
assert external_root.is_dir()
assert all(not package_path.is_relative_to(item) for item in forbidden_roots)
assert all(not resource_root_path.is_relative_to(item) for item in forbidden_roots)
assert all(not data_root.is_relative_to(item) for item in forbidden_roots)
assert all(not external_root.is_relative_to(item) for item in forbidden_roots)
external_manifest = external_root.joinpath("licenses", "u1-0.2.1.json")
license_manifest = json.loads(external_manifest.read_bytes())
for license_entry in license_manifest["licenses"]:
    license_path = external_root.joinpath(*license_entry["path"].split("/"))
    assert hashlib.sha256(license_path.read_bytes()).hexdigest() == license_entry["text_sha256"]
index = json.loads((fixture_root / "index.json").read_bytes())
capability = packaged_release_capability()
source_only_route_code = "U1_ADMISSION_EXPECTED_SCHEMA_IS_OUTSIDE_THE_FROZEN_ROUTE_TABLE"
for entry in index["entries"]:
    raw = (fixture_root / entry["path"]).read_bytes()
    if entry.get("disposition", {}).get("source_only") is True:
        assert entry["schema_id"].startswith("test-only.")
        assert entry["expected_stage"] in {"admission", "join", "operation"}
        try:
            validate_u1_bytes(entry["schema_id"], raw, capability)
        except U1ContractError as exc:
            assert exc.code == source_only_route_code
        else:
            raise AssertionError(entry["id"])
        continue
    if entry["expected_stage"] == "accepted":
        validate_u1_bytes(entry["schema_id"], raw, capability)
    else:
        try:
            validate_u1_bytes(entry["schema_id"], raw, capability)
        except U1ContractError as exc:
            assert exc.code == entry["expected_code"]
        else:
            raise AssertionError(entry["id"])
print(json.dumps({"external_root": str(external_root), "package_root": str(resource_root_path)}, sort_keys=True))
"""
    result = run(
        [
            str(python),
            "-I",
            "-c",
            probe,
            manifest_digest,
            str(PROJECT / "tests" / "fixtures" / "u1"),
            str(PROJECT),
            str(PROJECT / "src"),
            str(external),
        ],
        cwd=external,
        env=environment,
        label="external installed-wheel corpus probe",
    )
    try:
        roots = json.loads(result.stdout.strip())
        package_root = Path(roots["package_root"]).resolve()
        external_root = Path(roots["external_root"]).resolve()
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        fail(f"installed-wheel probe did not return resource roots: {exc}")
    package_observed_files, package_observed_directories = filesystem_resource_mapping(
        package_root, package_subtrees=True
    )
    external_observed_files, external_observed_directories = filesystem_resource_mapping(
        external_root, package_subtrees=False
    )
    audit_resource_tree(
        "installed package",
        package_observed_files,
        package_observed_directories,
        package_expected,
    )
    audit_resource_tree(
        "installed external",
        external_observed_files,
        external_observed_directories,
        external_expected,
    )
    compare_cross_presentation_bytes(
        package_observed_files, external_observed_files, set(manifest_expected)
    )
    print("installed-wheel external corpus and resources: PASS")


def regular_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def directory_zip_info(name: str) -> zipfile.ZipInfo:
    if not name.endswith("/") or name != name.rstrip("/") + "/":
        fail(f"test directory member is not canonical: {name}")
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFDIR | 0o755) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def build_record_payload(
    entries: list[tuple[zipfile.ZipInfo, bytes]],
    record_name: str,
) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for info, payload in entries:
        encoded = "" if info.filename == record_name else "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()
        ).rstrip(b"=").decode("ascii")
        size = "" if info.filename == record_name else str(len(payload))
        writer.writerow((info.filename, encoded, size))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


def rewrite_wheel(
    source: Path,
    destination: Path,
    *,
    remove: set[str] | None = None,
    remove_prefixes: tuple[str, ...] = (),
    replace: dict[str, bytes] | None = None,
    extra: dict[str, bytes] | None = None,
    duplicate: tuple[str, ...] = (),
    rename: dict[str, str] | None = None,
    mutate: dict[str, Callable[[zipfile.ZipInfo], None]] | None = None,
    extra_directories: tuple[str, ...] = (),
    extra_modes: dict[str, int] | None = None,
    rebuild_record: bool = False,
) -> None:
    removed = remove or set()
    replacements = replace or {}
    additions = extra or {}
    addition_modes = extra_modes or {}
    renames = rename or {}
    mutations = mutate or {}
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED
    ) as destination_archive:
        record_names = [
            info.filename
            for info in source_archive.infolist()
            if info.filename.endswith(".dist-info/RECORD")
        ]
        if rebuild_record and len(record_names) != 1:
            fail("cannot rebuild a wheel without exactly one source RECORD")
        record_name = record_names[0] if record_names else ""
        entries: list[tuple[zipfile.ZipInfo, bytes]] = []
        for info in source_archive.infolist():
            name = info.filename
            if name in removed or any(name.startswith(prefix) for prefix in remove_prefixes):
                continue
            if rebuild_record and name == record_name:
                continue
            rewritten = copy(info)
            rewritten.filename = renames.get(name, name)
            if name in mutations:
                mutations[name](rewritten)
            payload = replacements.get(name, source_archive.read(name))
            entries.append((rewritten, payload))
        for name in duplicate:
            source_info = next(
                (info for info in source_archive.infolist() if info.filename == name),
                None,
            )
            if source_info is None:
                fail(f"cannot duplicate absent wheel member: {name}")
            entries.append((copy(source_info), source_archive.read(name)))
        for name, payload in additions.items():
            info = regular_zip_info(name)
            if name in addition_modes:
                info.external_attr = (stat.S_IFREG | addition_modes[name]) << 16
            entries.append((info, payload))
        for name in extra_directories:
            entries.append((directory_zip_info(name), b""))
        if rebuild_record:
            if any(info.filename == record_name for info, _ in entries):
                fail("rebuilt wheel RECORD name collides with a mutation")
            record_info = next(
                copy(info)
                for info in source_archive.infolist()
                if info.filename == record_name
            )
            record_info.create_system = 3
            record_info.external_attr = (stat.S_IFREG | EXPECTED_WHEEL_RECORD_MODE) << 16
            entries.append(
                (record_info, build_record_payload(entries, record_name))
            )
        for info, payload in entries:
            destination_archive.writestr(info, payload)


def rewrite_sdist(
    source: Path,
    destination: Path,
    *,
    remove: set[str] | None = None,
    duplicate: tuple[str, ...] = (),
    extra_files: dict[str, bytes] | None = None,
    extra_directories: tuple[str, ...] = (),
    replace: dict[str, bytes] | None = None,
    modes: dict[str, int] | None = None,
) -> None:
    removals = remove or set()
    additions = extra_files or {}
    replacements = replace or {}
    mode_changes = modes or {}
    with tarfile.open(source, "r:gz") as source_archive, tarfile.open(
        destination, "w:gz"
    ) as destination_archive:
        members = read_sdist_members(source_archive)
        if not members:
            fail("cannot rewrite an empty sdist")
        top = PurePosixPath(members[0].name).parts[0]
        for member in members:
            copied = copy(member)
            key = safe_member_name(member.name)
            relative = key.removeprefix(top + "/")
            if key in removals or relative in removals:
                continue
            if relative in mode_changes:
                copied.mode = mode_changes[relative]
            if relative in replacements:
                payload = replacements[relative]
                copied.size = len(payload)
                add_sdist_member_with_payload(destination_archive, copied, payload)
            elif copied.isfile() or (copied.isdir() and copied.size):
                payload = sdist_member_payload(source_archive, member)
                copied.size = len(payload)
                add_sdist_member_with_payload(destination_archive, copied, payload)
            else:
                destination_archive.addfile(copied)
        for relative, payload in additions.items():
            info = tarfile.TarInfo(f"{top}/{relative}")
            info.mode = 0o644
            info.size = len(payload)
            destination_archive.addfile(info, io.BytesIO(payload))
        for relative in extra_directories:
            name = relative.rstrip("/") + "/"
            info = tarfile.TarInfo(f"{top}/{name}")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            destination_archive.addfile(info)
        for member_name in duplicate:
            source_member = next(
                (member for member in members if member.name == member_name),
                None,
            )
            if source_member is None:
                fail(f"cannot duplicate absent sdist member: {member_name}")
            copied = copy(source_member)
            if copied.isfile() or (copied.isdir() and copied.size):
                payload = sdist_member_payload(source_archive, source_member)
                copied.size = len(payload)
                add_sdist_member_with_payload(destination_archive, copied, payload)
            else:
                destination_archive.addfile(copied)


def rewrite_sdist_root(
    source: Path,
    destination: Path,
    new_root: str,
) -> None:
    with tarfile.open(source, "r:gz") as source_archive, tarfile.open(
        destination, "w:gz"
    ) as destination_archive:
        members = read_sdist_members(source_archive)
        if not members:
            fail("cannot rewrite an empty sdist")
        old_root = PurePosixPath(members[0].name).parts[0]
        for member in members:
            copied = copy(member)
            copied.name = new_root + member.name[len(old_root) :]
            copied.pax_headers = dict(copied.pax_headers)
            copied.pax_headers.pop("path", None)
            if copied.isfile() or (copied.isdir() and copied.size):
                payload = sdist_member_payload(source_archive, member)
                copied.size = len(payload)
                add_sdist_member_with_payload(destination_archive, copied, payload)
            else:
                destination_archive.addfile(copied)


def expect_audit_failure(label: str, action: Any, fragment: str) -> None:
    try:
        action()
    except SystemExit as caught:
        detail = str(caught)
        if fragment not in detail:
            fail(f"{label} failed for the wrong reason: {detail}")
        return
    fail(f"{label} unexpectedly passed")


def rewrite_sdist_type_carrier(
    source: Path,
    destination: Path,
    typeflag: bytes,
    label: str,
) -> None:
    payload = (f"R12-{label}-carrier\n".encode() * 64)[:512]
    with tarfile.open(source, "r:gz") as source_archive, tarfile.open(
        destination, "w:gz"
    ) as destination_archive:
        members = read_sdist_members(source_archive)
        if not members:
            fail("cannot create a carrier from an empty sdist")
        top = PurePosixPath(members[0].name).parts[0]
        carrier = tarfile.TarInfo(f"{top}/r12-{label}-carrier")
        carrier.type = typeflag
        carrier.mode = 0o644
        carrier.size = len(payload)
        if typeflag in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
            carrier.linkname = "r12-carrier-target"
        if typeflag in {tarfile.CHRTYPE, tarfile.BLKTYPE}:
            carrier.devmajor = 1
            carrier.devminor = 3
        inserted = False
        for member in members:
            if not inserted and member.name.endswith(
                "src/kilix_content.egg-info/PKG-INFO"
            ):
                add_sdist_member_with_payload(
                    destination_archive, carrier, payload
                )
                inserted = True
            copied = copy(member)
            if copied.isfile() or (copied.isdir() and copied.size):
                member_payload = sdist_member_payload(source_archive, member)
                copied.size = len(member_payload)
                add_sdist_member_with_payload(
                    destination_archive, copied, member_payload
                )
            else:
                destination_archive.addfile(copied)
        if not inserted:
            fail("carrier insertion anchor is absent from the sdist")


def rewrite_sdist_untruthful_directory_size(
    source: Path, destination: Path, declared_size: int
) -> None:
    with tarfile.open(source, "r:gz") as source_archive, tarfile.open(
        destination, "w:gz"
    ) as destination_archive:
        members = read_sdist_members(source_archive)
        if not members:
            fail("cannot corrupt an empty sdist")
        top = PurePosixPath(members[0].name).parts[0]
        for member in members:
            copied = copy(member)
            if copied.name == top:
                copied.size = declared_size
                add_sdist_member_with_payload(destination_archive, copied, b"")
            elif copied.isfile() or (copied.isdir() and copied.size):
                member_payload = sdist_member_payload(source_archive, member)
                copied.size = len(member_payload)
                add_sdist_member_with_payload(
                    destination_archive, copied, member_payload
                )
            else:
                destination_archive.addfile(copied)


def rewrite_sdist_pax_zero_size(source: Path, destination: Path) -> None:
    target = "README.md"
    with tarfile.open(source, "r:gz") as source_archive, tarfile.open(
        destination, "w:gz", format=tarfile.PAX_FORMAT
    ) as destination_archive:
        members = read_sdist_members(source_archive)
        if not members:
            fail("cannot corrupt an empty sdist")
        changed = False
        for member in members:
            copied = copy(member)
            if copied.name.removeprefix(
                PurePosixPath(members[0].name).parts[0] + "/"
            ) == target:
                payload = sdist_member_payload(source_archive, member)
                copied.size = len(payload)
                copied.pax_headers = dict(copied.pax_headers)
                copied.pax_headers["size"] = "0"
                destination_archive.addfile(copied, io.BytesIO(payload))
                changed = True
            elif copied.isfile() or (copied.isdir() and copied.size):
                payload = sdist_member_payload(source_archive, member)
                copied.size = len(payload)
                add_sdist_member_with_payload(
                    destination_archive, copied, payload
                )
            else:
                destination_archive.addfile(copied)
        if not changed:
            fail(f"sdist PAX size control target is absent: {target}")


def rewrite_sdist_bad_gzip_footer(
    source: Path, destination: Path, footer_offset: int
) -> None:
    raw = bytearray(source.read_bytes())
    if len(raw) < 8:
        fail("cannot corrupt a short gzip archive")
    if footer_offset not in {0, 4}:
        fail(f"unsupported gzip footer offset: {footer_offset}")
    raw[-8 + footer_offset] ^= 1
    destination.write_bytes(raw)


def rewrite_sdist_with_trailing_member(source: Path, destination: Path) -> None:
    tar_payload = gzip.decompress(source.read_bytes())
    extra = io.BytesIO()
    with tarfile.open(fileobj=extra, mode="w:") as archive:
        member = tarfile.TarInfo("r12-smuggled-member")
        payload = b"R12 smuggled member\n"
        member.mode = 0o644
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    destination.write_bytes(gzip.compress(tar_payload + extra.getvalue()))


def rewrite_sdist_with_gzip_trailing_bytes(
    source: Path, destination: Path
) -> None:
    destination.write_bytes(source.read_bytes() + b"R12-gzip-trailing-bytes")


def rewrite_sdist_negative_member_size(source: Path, destination: Path) -> None:
    payload = bytearray(gzip.decompress(source.read_bytes()))
    if len(payload) < tarfile.BLOCKSIZE:
        fail("negative-size control source tar is too short")
    payload[124:136] = b"-00000000001"
    payload[148:156] = b"        "
    checksum = sum(payload[:512])
    payload[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    destination.write_bytes(gzip.compress(bytes(payload)))


def write_sdist_expansion_ratio_control(destination: Path) -> None:
    payload = b"\0" * (1024 * 1024)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:") as archive:
        member = tarfile.TarInfo("r14-expansion-ratio")
        member.mode = 0o644
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    destination.write_bytes(gzip.compress(stream.getvalue()))


def sdist_container_and_type_controls(
    archive: Path, temporary: Path
) -> None:
    temporary.mkdir(parents=True, exist_ok=True)
    type_cases = (
        ("dir", tarfile.DIRTYPE),
        ("symlink", tarfile.SYMTYPE),
        ("hardlink", tarfile.LNKTYPE),
        ("char", tarfile.CHRTYPE),
        ("block", tarfile.BLKTYPE),
        ("fifo", tarfile.FIFOTYPE),
    )
    for label, typeflag in type_cases:
        mutated = temporary / f"sdist-type-{label}.tar.gz"
        rewrite_sdist_type_carrier(archive, mutated, typeflag, label)
        expect_audit_failure(
            f"sdist {label} carrier agreement control",
            lambda mutated=mutated: assert_sdist_enumerator_agreement(mutated),
            "sdist archive enumerators disagree",
        )
    untruthful = temporary / "sdist-untruthful-directory-size.tar.gz"
    rewrite_sdist_untruthful_directory_size(archive, untruthful, tarfile.BLOCKSIZE)
    expect_audit_failure(
        "sdist untruthful directory-size control",
        lambda: assert_sdist_enumerator_agreement(
            untruthful, check_container=False
        ),
        "sdist archive enumerators disagree",
    )
    pax_zero = temporary / "sdist-pax-zero-size.tar.gz"
    rewrite_sdist_pax_zero_size(archive, pax_zero)
    expect_audit_failure(
        "sdist PAX logical-zero physical-payload control",
        lambda: assert_sdist_enumerator_agreement(pax_zero),
        "sdist member logical size differs from physical header size",
    )
    bad_crc = temporary / "sdist-bad-gzip-crc.tar.gz"
    rewrite_sdist_bad_gzip_footer(archive, bad_crc, 0)
    expect_audit_failure(
        "sdist gzip CRC control",
        lambda: sdist_container_audit(bad_crc),
        "sdist gzip container integrity failed",
    )
    bad_isize = temporary / "sdist-bad-gzip-isize.tar.gz"
    rewrite_sdist_bad_gzip_footer(archive, bad_isize, 4)
    expect_audit_failure(
        "sdist gzip ISIZE control",
        lambda: sdist_container_audit(bad_isize),
        "sdist gzip container integrity failed",
    )
    gzip_trailing = temporary / "sdist-gzip-trailing-bytes.tar.gz"
    rewrite_sdist_with_gzip_trailing_bytes(archive, gzip_trailing)
    expect_audit_failure(
        "sdist gzip trailing-bytes control",
        lambda: sdist_container_audit(gzip_trailing),
        "sdist gzip container integrity failed",
    )
    negative_size = temporary / "sdist-negative-size.tar.gz"
    rewrite_sdist_negative_member_size(archive, negative_size)
    expect_audit_failure(
        "sdist negative-size control",
        partial(sdist_container_audit, negative_size),
        "sdist tar contains a noncanonical negative member size",
    )
    expansion_ratio = temporary / "sdist-expansion-ratio.tar.gz"
    write_sdist_expansion_ratio_control(expansion_ratio)
    expect_audit_failure(
        "sdist expansion-ratio control",
        partial(sdist_container_audit, expansion_ratio),
        "sdist gzip expansion ratio exceeds the limit",
    )
    trailing = temporary / "sdist-trailing-member.tar.gz"
    rewrite_sdist_with_trailing_member(archive, trailing)
    expect_audit_failure(
        "sdist trailing-member control",
        lambda: sdist_container_audit(trailing),
        "sdist tar has bytes after its end-of-archive marker",
    )
    empty = temporary / "sdist-empty.tar.gz"
    with tarfile.open(empty, "w:gz"):
        pass
    expect_audit_failure(
        "sdist empty agreement control",
        lambda: assert_sdist_enumerator_agreement(empty),
        "sdist archive is empty",
    )
    print("sdist container, carrier-type, PAX-size, and empty-archive controls: PASS")


def expect_repaired_wheel_failure(
    label: str,
    wheel: Path,
    action: Any,
    fragment: str,
) -> None:
    record_audit(wheel)
    expect_audit_failure(label, action, fragment)


def set_zip_mode(mode: int) -> Callable[[zipfile.ZipInfo], None]:
    def mutate(info: zipfile.ZipInfo) -> None:
        info.external_attr = mode << 16

    return mutate


def materialize_resource_tree(
    root: Path,
    expected: dict[str, tuple[str, bytes]],
) -> None:
    root.mkdir(parents=True, exist_ok=True, mode=EXPECTED_WHEEL_DIRECTORY_MODE)
    root.chmod(EXPECTED_WHEEL_DIRECTORY_MODE)
    for path, (_, payload) in expected.items():
        destination = root / path
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=EXPECTED_WHEEL_DIRECTORY_MODE,
        )
        destination.parent.chmod(EXPECTED_WHEEL_DIRECTORY_MODE)
        destination.write_bytes(payload)
        destination.chmod(EXPECTED_WHEEL_FILE_MODE)
    for directory in root.rglob("*"):
        if directory.is_dir() and not directory.is_symlink():
            directory.chmod(EXPECTED_WHEEL_DIRECTORY_MODE)


def legacy_r5_member_audit_for_control(wheel: Path) -> None:
    """Model the pre-R6 acceptance surface for the installation control only."""
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            fail("legacy R5 control wheel has an invalid CRC")
        names = [info.filename for info in archive.infolist()]
        if len(names) != len({safe_member_name(name) for name in names}):
            fail("legacy R5 control wheel has duplicate normalized members")
        for info in archive.infolist():
            classify_wheel_member(archive, info, check_permissions=False)
        forbidden = (
            "tests/",
            "fixtures/",
            "u1_vectors",
            "wheelhouse/",
            "fixture-index",
            "synthetic",
        )
        if any(any(token in name.lower() for token in forbidden) for name in names):
            fail("legacy R5 control wheel has forbidden test authority")


def wheel_member_closure_negative_controls(
    wheel: Path,
    expected_members: set[str],
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    temporary: Path,
) -> None:
    temporary.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel) as archive:
        package_prefix, external_prefix = wheel_resource_prefixes(archive)
        distribution = wheel_distribution_name(archive)

    cases: tuple[tuple[str, str, bytes], ...] = (
        (
            "data-scripts",
            f"{distribution}.data/scripts/kilix-content-helper",
            b"#!/bin/sh\nexit 0\n",
        ),
        (
            "data-purelib",
            f"{distribution}.data/purelib/r6-extra.py",
            b"# extra purelib\n",
        ),
        (
            "data-platlib",
            f"{distribution}.data/platlib/r6-extra.py",
            b"# extra platlib\n",
        ),
        (
            "data-headers",
            f"{distribution}.data/headers/r6-extra.h",
            b"/* extra header */\n",
        ),
        (
            "data-other-share",
            f"{distribution}.data/data/share/other/r6-extra.txt",
            b"extra\n",
        ),
        (
            "data-profile",
            f"{distribution}.data/data/etc/profile.d/r6-extra.sh",
            b"# extra profile\n",
        ),
        ("wheel-root-module", "r6_extra.py", b"# extra root module\n"),
        (
            "wheel-root-package",
            "r6_extra/__init__.py",
            b"# extra root package\n",
        ),
        (
            "package-module",
            "kilix_content/r6_extra.py",
            b"# extra package module\n",
        ),
        (
            "dist-info-extra",
            f"{distribution}.dist-info/r6-extra.txt",
            b"extra metadata\n",
        ),
        (
            "dist-info-entry-points",
            f"{distribution}.dist-info/entry_points.txt",
            b"[console_scripts]\nkilix-content-helper = r6_extra:main\n",
        ),
        (
            "external-root-file-without-slash",
            external_prefix.rstrip("/"),
            b"not a directory\n",
        ),
        ("package-root-file-without-slash", package_prefix.rstrip("/"), b"root\n"),
        (
            "data-root-file-without-slash",
            f"{distribution}.data",
            b"root\n",
        ),
        (
            "metadata-root-file-without-slash",
            f"{distribution}.dist-info",
            b"root\n",
        ),
        (
            "external-purelib-root",
            f"{distribution}.data/purelib/share/kilix-content/",
            b"",
        ),
        (
            "external-purelib-file",
            f"{distribution}.data/purelib/share/kilix-content/r6.txt",
            b"extra\n",
        ),
        (
            "external-data-stray-file",
            f"{distribution}.data/data/share/stray.txt",
            b"extra\n",
        ),
    )
    for label, name, payload in cases:
        mutated = temporary / f"member-{label}.whl"
        if name.endswith("/"):
            rewrite_wheel(
                wheel,
                mutated,
                extra_directories=(name,),
                rebuild_record=True,
            )
        else:
            rewrite_wheel(
                wheel,
                mutated,
                extra={name: payload},
                rebuild_record=True,
            )
        expect_repaired_wheel_failure(
            f"wheel member closure {label}",
            mutated,
            lambda mutated=mutated: wheel_archive_audit(mutated, expected_members),
            "wheel complete member set differs",
        )

    external_stray_directory = temporary / "member-external-data-stray-directory.whl"
    rewrite_wheel(
        wheel,
        external_stray_directory,
        extra_directories=(f"{distribution}.data/data/share/stray/",),
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "wheel member closure external stray directory",
        external_stray_directory,
        lambda: wheel_archive_audit(external_stray_directory, expected_members),
        "wheel complete member set differs",
    )

    script_wheel = temporary / "kilix_content-0.4.0-py3-none-any.whl"
    script_name = f"{distribution}.data/scripts/kilix-content-helper"
    rewrite_wheel(
        wheel,
        script_wheel,
        extra={script_name: b"#!/bin/sh\nexit 0\n"},
        extra_modes={script_name: 0o755},
        rebuild_record=True,
    )
    legacy_r5_member_audit_for_control(script_wheel)
    record_audit(script_wheel)
    install_root = temporary / "pre-r6-script-install"
    install_root.mkdir()
    environment = dict(base_env)
    environment["UV_CACHE_DIR"] = str(install_root / "empty-uv-cache")
    venv = install_root / "venv"
    run(
        [
            str(uv_path),
            "venv",
            "--no-project",
            "--python",
            str(base_python),
            "--no-python-downloads",
            str(venv),
        ],
        cwd=install_root,
        env=environment,
        label="pre-R6 script installation venv",
    )
    python = venv / "bin" / "python"
    run(
        [
            str(uv_path),
            "pip",
            "install",
            "--python",
            str(python),
            "--no-index",
            "--no-deps",
            str(script_wheel),
        ],
        cwd=install_root,
        env=environment,
        label="pre-R6 executable PATH installation control",
    )
    installed_script = venv / "bin" / "kilix-content-helper"
    if not installed_script.is_file() or not installed_script.stat().st_mode & 0o111:
        fail("pre-R6 script installation control did not reach executable PATH")
    print("pre-R6 executable PATH placement control: PASS")
    expect_audit_failure(
        "global wheel closure rejects executable PATH member",
        lambda: wheel_archive_audit(script_wheel, expected_members),
        "wheel complete member set differs",
    )


def sdist_member_closure_negative_controls(
    archive: Path,
    temporary: Path,
) -> None:
    temporary.mkdir(parents=True, exist_ok=True)
    renamed_root = temporary / "sdist-wrong-root.tar.gz"
    rewrite_sdist_root(archive, renamed_root, "reviewer-r7-unbound-root")
    renamed_name, renamed_signature = sdist_relative_member_signature(renamed_root)
    _, source_signature = sdist_relative_member_signature(archive)
    if renamed_name != "reviewer-r7-unbound-root":
        fail(f"sdist root rename control has the wrong root: {renamed_name!r}")
    if (
        len(renamed_signature) != len(source_signature)
        or renamed_signature != source_signature
    ):
        fail("sdist root rename control changed relative member content")
    expect_audit_failure(
        "sdist distribution-root identity control",
        lambda: extract_sdist(renamed_root, temporary / "extract-wrong-root"),
        "sdist root identity differs",
    )
    print("sdist root rename precondition and diagnostic control: PASS")

    with tarfile.open(archive, "r:gz") as handle:
        expected_top = sdist_distribution_root(PROJECT)
        top_members = [
            member
            for member in read_sdist_members(handle)
            if safe_member_name(member.name) == expected_top and member.isdir()
        ]
        if len(top_members) != 1:
            fail(f"sdist does not have one explicit top-directory member: {top_members!r}")
        top_member_name = top_members[0].name
    missing_top = temporary / "sdist-missing-top-directory.tar.gz"
    rewrite_sdist(archive, missing_top, remove={expected_top})
    expect_audit_failure(
        "sdist top-directory absence control",
        lambda: extract_sdist(missing_top, temporary / "extract-missing-top"),
        "sdist complete member set differs",
    )
    duplicate_top = temporary / "sdist-duplicate-top-directory.tar.gz"
    rewrite_sdist(archive, duplicate_top, duplicate=(top_member_name,))
    expect_audit_failure(
        "sdist top-directory duplicate control",
        lambda: extract_sdist(duplicate_top, temporary / "extract-duplicate-top"),
        "sdist has duplicate or split-root members",
    )
    print("sdist top-directory closure controls: PASS")

    nonempty_top = temporary / "sdist-nonempty-top-directory.tar.gz"
    directory_payload = b"F100-R10-DIRECTORY-PAYLOAD-SENTINEL-9f3b2c1a\n"
    if any(
        directory_payload in record[4]
        for record in ordered_sdist_member_records(archive)
    ):
        fail("sdist directory control sentinel already exists in the source archive")
    rewrite_sdist(
        archive,
        nonempty_top,
        replace={expected_top: directory_payload},
    )
    assert_sdist_nonempty_directory_control(
        archive,
        nonempty_top,
        expected_top,
        directory_payload,
    )
    expect_audit_failure(
        "sdist nonempty directory control",
        lambda: extract_sdist(nonempty_top, temporary / "extract-nonempty-top"),
        f"sdist directory member is nonempty: {expected_top}",
    )
    print("sdist nonempty-directory diagnostic control: PASS")
    expect_audit_failure(
        "sdist getmembers directory-payload differential control",
        lambda: assert_sdist_enumerator_agreement(nonempty_top),
        "sdist archive enumerators disagree",
    )
    readme = "README.md"
    source_readme = (PROJECT / readme).read_bytes()
    altered_readme = bytes([source_readme[0] ^ 1]) + source_readme[1:]
    payload_reversion = temporary / "sdist-payload-reader-reversion.tar.gz"
    rewrite_sdist(
        archive,
        payload_reversion,
        replace={
            expected_top: directory_payload,
            readme: altered_readme,
        },
    )
    expect_audit_failure(
        "sdist payload reader differential control",
        lambda: sdist_payload_audit(
            payload_reversion,
            PROJECT,
            expected_top,
        ),
        "sdist payload differs from source: README.md",
    )
    print("sdist enumerator agreement control: PASS")

    cases = (
        ("root", "r6-unmanifested.py"),
        ("source", "src/kilix_content/r6-unmanifested.py"),
        ("tests", "tests/r6-unmanifested.py"),
        ("wheelhouse", "wheelhouse/r6-unmanifested.whl"),
        ("data", "kilix_content-0.4.0.data/r6-unmanifested"),
    )
    for label, relative in cases:
        mutated = temporary / f"sdist-{label}.tar.gz"
        rewrite_sdist(
            archive,
            mutated,
            extra_files={relative: b"unlisted\n"},
        )
        expect_audit_failure(
            f"sdist member closure {label}",
            lambda mutated=mutated, label=label: extract_sdist(
                mutated, temporary / f"extract-{label}"
            ),
            "sdist complete member set differs",
        )
    directory = temporary / "sdist-directory-extra.tar.gz"
    rewrite_sdist(
        archive,
        directory,
        extra_directories=("tests/r6-unmanifested/",),
    )
    expect_audit_failure(
        "sdist member closure directory",
        lambda: extract_sdist(directory, temporary / "extract-directory"),
        "sdist complete member set differs",
    )
    print("exact sdist member closure controls: PASS")

    payload_cases = (
        ("source", "src/kilix_content/u1.py"),
        ("tests", "tests/test_u1_contracts.py"),
        ("tooling", "tools/render_u1_fixtures.py"),
        ("documentation", "README.md"),
        ("contract-documentation", "contracts/README.md"),
    )
    for label, relative in payload_cases:
        original = (PROJECT / relative).read_bytes()
        altered = bytes([original[0] ^ 1]) + original[1:]
        mutated = temporary / f"sdist-payload-{label}.tar.gz"
        rewrite_sdist(archive, mutated, replace={relative: altered})
        expect_audit_failure(
            f"sdist payload {label} control",
            lambda mutated=mutated, label=label: extract_sdist(
                mutated, temporary / f"extract-payload-{label}"
            ),
            f"sdist payload differs from source: {relative}",
        )
    print("sdist source-payload byte controls: PASS")

    mode_cases = (
        ("setuid", 0o4755),
        ("setgid", 0o2755),
        ("sticky", 0o1755),
        ("world-writable", 0o777),
        ("unreadable", 0o000),
    )
    mode_target = "tests/test_u1_contracts.py"
    for label, mode in mode_cases:
        mutated = temporary / f"sdist-mode-{label}.tar.gz"
        rewrite_sdist(archive, mutated, modes={mode_target: mode})
        expect_audit_failure(
            f"sdist {label} mode control",
            lambda mutated=mutated: extract_sdist(
                mutated, temporary / f"extract-mode-{label}"
            ),
            f"sdist member permissions differ: {mode_target}",
        )
    print("sdist member mode controls: PASS")


def r12_reader_reversion_regression(
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    temporary: Path,
) -> None:
    """Run the complete gate after reverting the load-bearing R12 reader line."""
    temporary.mkdir(parents=True, exist_ok=True)
    candidate = temporary / "r12-reverted-reader"
    shutil.copytree(
        PROJECT,
        candidate,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".ruff_cache",
            "__pycache__",
            "*.pyc",
            "*.egg-info",
            "build",
            "dist",
        ),
    )
    canonical_checker = candidate / "tests" / "check_reproducible_build.py"
    checker = candidate / "tests" / "r12_reader_reversion_gate.py"
    source = canonical_checker.read_text()
    start = source.index("def sdist_payload_audit(")
    end = source.index("\ndef sdist_relative_member_signature", start)
    function = source[start:end]
    old = "for member in read_sdist_members(handle):"
    if function.count(old) != 1:
        fail("R12 reader-reversion control could not find exactly one load-bearing line")
    checker.write_text(
        source[:start]
        + function.replace(old, "for member in handle.getmembers():")
        + source[end:]
    )
    child_python, child_env = bootstrap_environment(
        candidate,
        temporary / "environment",
        uv_path,
        base_python,
        base_env,
        install_project=False,
    )
    if _BUILD_LAUNCHER_FD is None:
        fail("build-authority launcher descriptor is absent for the child gate")
    result = subprocess.run(
        [
            str(child_python),
            str(checker),
            "--r13-skip-regressions",
        ],
        cwd=candidate,
        env={**child_env, LAUNCHER_FD_ENV: str(_BUILD_LAUNCHER_FD)},
        pass_fds=(_BUILD_LAUNCHER_FD,),
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        fail("R12 reader-reversion complete gate unexpectedly passed")
    expected = "sdist payload reader differential control unexpectedly passed"
    if expected not in output:
        fail(
            "R12 reader-reversion gate failed without the intended causal control: "
            + output[-8000:]
        )
    print("R12 reader-reversion complete-gate regression: FAIL-CLOSED/PASS")
    _COMPLETE_GATE_REGRESSIONS_OBSERVED.add("r12-reader-reversion")


def r13_callsite_wiring_regression(
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    temporary: Path,
) -> None:
    """Run one complete gate with its anchored sdist audit wiring removed."""
    temporary.mkdir(parents=True, exist_ok=True)
    candidate = temporary / "all-sdist-audit-calls-removed"
    shutil.copytree(
        PROJECT,
        candidate,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".ruff_cache",
            "__pycache__",
            "*.pyc",
            "*.egg-info",
            "build",
            "dist",
        ),
    )
    canonical_checker = candidate / "tests" / "check_reproducible_build.py"
    checker = candidate / "tests" / "r13_callsite_wiring_gate.py"
    source = canonical_checker.read_text()
    removed_callsite_blocks = {
        "generated-metadata-audit": (
            '        register_production_audit(\n'
            '            "sdist",\n'
            '            "direct sdist pair",\n'
            '            "generated-metadata",\n'
            '            lambda: run_sdist_audit(\n'
            '                "generated-metadata-audit",\n'
            '                lambda: sdist_generated_metadata_audit(\n'
            '                    direct_one["sdist"], direct_two["sdist"]\n'
            '                ),\n'
            '            ),\n'
            '        )'
        ),
        "direct-enumerator": (
            '            register_production_audit(\n'
            '                "sdist",\n'
            '                label,\n'
            '                "enumerator",\n'
            '                lambda archive=archive: run_sdist_audit(\n'
            '                    "direct-enumerator",\n'
            '                    lambda: assert_sdist_enumerator_agreement(archive),\n'
            '                ),\n'
            '            )'
        ),
        "direct-payload": (
            '            register_production_audit(\n'
            '                "sdist",\n'
            '                label,\n'
            '                "payload",\n'
            '                lambda archive=archive: run_sdist_audit(\n'
            '                    "direct-payload",\n'
            '                    lambda: sdist_payload_audit(\n'
            '                        archive,\n'
            '                        PROJECT,\n'
            '                        sdist_distribution_root(PROJECT),\n'
            '                    ),\n'
            '                ),\n'
            '            )'
        ),
        "sdist-wiring-assertion": "        " + "assert_sdist_audit_wiring()",
    }
    preserved_callsite_blocks = {
        "wheel-container-audit": (
            '            register_production_audit(\n'
            '                "wheel",\n'
            '                label,\n'
            '                "container",\n'
            '                lambda wheel=wheel: wheel_container_audit(wheel),\n'
            '            )'
        ),
        "wheel-archive-audit": (
            '            register_production_audit(\n'
            '                "wheel",\n'
            '                label,\n'
            '                "archive",\n'
            '                lambda wheel=wheel: wheel_archive_audit(wheel, expected_members),\n'
            '            )'
        ),
        "wheel-record-audit": (
            '            register_production_audit(\n'
            '                "wheel",\n'
            '                label,\n'
            '                "record",\n'
            '                lambda wheel=wheel: record_audit(wheel),\n'
            '            )'
        ),
        "wheel-module-audit": (
            '            register_production_audit(\n'
            '                "wheel",\n'
            '                label,\n'
            '                "module",\n'
            '                lambda wheel=wheel: wheel_module_source_audit(wheel, PROJECT),\n'
            '            )'
        ),
    }
    callsite_blocks = {**removed_callsite_blocks, **preserved_callsite_blocks}
    for label, block in callsite_blocks.items():
        if source.count(block) != 1:
            fail(f"R13 call-site control found {source.count(block)} {label} blocks")
    # R14 added the wheel blocks above to this source-integrity census. Keep
    # checking that they exist exactly once, but do not remove them in the
    # sdist wiring child: R15's earlier wheel-closure guard would correctly
    # refuse first and mask the sdist property-registry guard tested here.
    for block in removed_callsite_blocks.values():
        indent = len(block) - len(block.lstrip())
        source = source.replace(block, " " * indent + "pass", 1)
    checker.write_text(source)
    child_python, child_env = bootstrap_environment(
        candidate,
        temporary / "environment",
        uv_path,
        base_python,
        base_env,
        install_project=False,
    )
    if _BUILD_LAUNCHER_FD is None:
        fail("build-authority launcher descriptor is absent for the child gate")
    result = subprocess.run(
        [
            str(child_python),
            str(checker),
            "--r13-skip-regressions",
        ],
        cwd=candidate,
        env={**child_env, LAUNCHER_FD_ENV: str(_BUILD_LAUNCHER_FD)},
        pass_fds=(_BUILD_LAUNCHER_FD,),
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        fail("R13 sdist call-site removal complete gate unexpectedly passed")
    if "production sdist audit wiring assertion was not executed" in output:
        print(
            "R13 sdist call-site wiring complete-gate regression: "
            "FAIL-CLOSED/PASS (property registry wiring guard)"
        )
        _COMPLETE_GATE_REGRESSIONS_OBSERVED.add("r13-callsite-wiring")
        return
    fail(
        "R13 call-site removal gate failed without the property registry wiring guard: "
        + output[-8000:]
    )


def honest_entrypoint_control(
    source_package: dict[str, tuple[str, bytes]],
    source_external: dict[str, tuple[str, bytes]],
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    source_python: Path,
    source_env: dict[str, str],
    temporary: Path,
) -> None:
    """Prove a declared script is expected, installed, and mode-bounded."""
    source_copy = temporary / "honest-entrypoint-source"
    shutil.copytree(
        PROJECT,
        source_copy,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".ruff_cache",
            "__pycache__",
            "*.pyc",
            "*.egg-info",
            "build",
            "dist",
        ),
    )
    pyproject = source_copy / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text()
        + '\n[project.scripts]\nkilix-content-admin = "kilix_content.u1:packaged_release_capability"\n'
    )
    artifact = build(
        source_copy,
        temporary / "honest-entrypoint-wheel",
        source_python,
        source_env,
        "--wheel",
    )["wheel"]
    expected = expected_wheel_members(
        source_copy, source_package, source_external
    )
    record_audit(artifact)
    wheel_archive_audit(artifact, expected)
    install_root = temporary / "honest-entrypoint-install"
    install_root.mkdir()
    environment = dict(base_env)
    environment["UV_CACHE_DIR"] = str(install_root / "empty-uv-cache")
    venv = install_root / "venv"
    run(
        [
            str(uv_path),
            "venv",
            "--no-project",
            "--python",
            str(base_python),
            "--no-python-downloads",
            str(venv),
        ],
        cwd=install_root,
        env=environment,
        label="honest entrypoint installation venv",
    )
    python = venv / "bin" / "python"
    run(
        [
            str(uv_path),
            "pip",
            "install",
            "--python",
            str(python),
            "--no-index",
            "--no-deps",
            str(artifact),
        ],
        cwd=install_root,
        env=environment,
        label="honest entrypoint installation",
    )
    wrapper = venv / "bin" / "kilix-content-admin"
    if not wrapper.is_file() or stat.S_IMODE(wrapper.stat().st_mode) != 0o711:
        fail("honest entrypoint wrapper is absent or not mode 0711")
    print("honest entrypoint expectation and mode-0711 installation: PASS")


def source_module_derivation_controls(
    package_expected: dict[str, tuple[str, bytes]],
    external_expected: dict[str, tuple[str, bytes]],
    manifest_expected: dict[str, tuple[str, bytes]],
    source_python: Path,
    source_env: dict[str, str],
    temporary: Path,
) -> None:
    def copy_source(destination: Path) -> None:
        shutil.copytree(
            PROJECT,
            destination,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                ".ruff_cache",
                "__pycache__",
                "*.pyc",
                "*.egg-info",
                "build",
                "dist",
            ),
        )

    added_source = temporary / "module-added-source"
    copy_source(added_source)
    (added_source / "src/kilix_content/r7_added.py").write_text(
        "R7_ADDED_MODULE = True\n"
    )
    added_wheel = build(
        added_source,
        temporary / "module-added-wheel",
        source_python,
        source_env,
        "--wheel",
    )["wheel"]
    added_expected = expected_wheel_members(
        added_source, package_expected, external_expected
    )
    record_audit(added_wheel)
    wheel_archive_audit(added_wheel, added_expected)
    wheel_resource_audit(
        added_wheel, package_expected, external_expected, manifest_expected
    )

    removed_source = temporary / "module-removed-source"
    copy_source(removed_source)
    removed_module = removed_source / "src/kilix_content/u1_profiles.py"
    if not removed_module.is_file():
        fail("module derivation control source fixture is missing")
    removed_module.unlink()
    removed_wheel = build(
        removed_source,
        temporary / "module-removed-wheel",
        source_python,
        source_env,
        "--wheel",
    )["wheel"]
    removed_expected = expected_wheel_members(
        removed_source, package_expected, external_expected
    )
    record_audit(removed_wheel)
    wheel_archive_audit(removed_wheel, removed_expected)
    wheel_resource_audit(
        removed_wheel, package_expected, external_expected, manifest_expected
    )
    if len(added_expected) != len(removed_expected) + 2:
        fail("module derivation controls did not move the source closure")
    print("source-derived module add/remove controls: PASS")


def resource_negative_controls(
    wheel: Path,
    package_expected: dict[str, tuple[str, bytes]],
    external_expected: dict[str, tuple[str, bytes]],
    manifest_expected: dict[str, tuple[str, bytes]],
    temporary: Path,
) -> None:
    temporary.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel) as archive:
        package_prefix, external_prefix = wheel_resource_prefixes(archive)
        external_names = [
            name for name in archive.namelist() if name.startswith(external_prefix)
        ]
    wheel_resource_audit(wheel, package_expected, external_expected, manifest_expected)
    trailing_container = temporary / "wheel-container-trailing.whl"
    trailing_container.write_bytes(wheel.read_bytes() + b"R14-wheel-container-trailing")
    expect_audit_failure(
        "wheel container trailing-byte control",
        partial(wheel_container_audit, trailing_container),
        "wheel container has trailing bytes",
    )
    mit_member = external_prefix + "licenses/MIT.txt"

    special_types = (
        ("symlink", stat.S_IFLNK | 0o777),
        ("fifo", stat.S_IFIFO | 0o644),
        ("socket", stat.S_IFSOCK | 0o644),
        ("character device", stat.S_IFCHR | 0o600),
        ("block device", stat.S_IFBLK | 0o600),
        ("ambiguous mode-less", 0),
    )
    for type_name, mode in special_types:
        special = temporary / f"special-{type_name.replace(' ', '-')}.whl"
        rewrite_wheel(
            wheel,
            special,
            mutate={mit_member: set_zip_mode(mode)},
        )
        expect_repaired_wheel_failure(
            f"{type_name} member control",
            special,
            lambda special=special: wheel_resource_audit(
                special, package_expected, external_expected, manifest_expected
            ),
            "wheel member has an unsupported or unknown type",
        )

    permission_types = (
        ("setuid", stat.S_IFREG | 0o4755),
        ("world-writable", stat.S_IFREG | 0o777),
        ("unreadable", stat.S_IFREG | 0o000),
    )
    for permission_name, mode in permission_types:
        unsafe_permissions = temporary / f"unsafe-permissions-{permission_name}.whl"
        rewrite_wheel(
            wheel,
            unsafe_permissions,
            mutate={mit_member: set_zip_mode(mode)},
        )
        expect_repaired_wheel_failure(
            f"{permission_name} permission control",
            unsafe_permissions,
            lambda unsafe_permissions=unsafe_permissions: wheel_resource_audit(
                unsafe_permissions,
                package_expected,
                external_expected,
                manifest_expected,
            ),
            "wheel member permissions differ",
        )

    regular_with_directory_spelling = temporary / "regular-directory-spelling.whl"
    rewrite_wheel(
        wheel,
        regular_with_directory_spelling,
        rename={mit_member: mit_member + "/"},
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "regular type with directory spelling control",
        regular_with_directory_spelling,
        lambda: wheel_resource_audit(
            regular_with_directory_spelling,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "wheel regular member has a directory spelling",
    )

    directory_with_regular_spelling = temporary / "directory-regular-spelling.whl"
    rewrite_wheel(
        wheel,
        directory_with_regular_spelling,
        replace={mit_member: b""},
        mutate={mit_member: set_zip_mode(stat.S_IFDIR | 0o755)},
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "directory type with regular spelling control",
        directory_with_regular_spelling,
        lambda: wheel_resource_audit(
            directory_with_regular_spelling,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "wheel directory member has a noncanonical spelling",
    )

    nonempty_directory = temporary / "nonempty-directory.whl"
    rewrite_wheel(
        wheel,
        nonempty_directory,
        rename={mit_member: mit_member + "/"},
        mutate={mit_member: set_zip_mode(stat.S_IFDIR | 0o755)},
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "nonempty directory member control",
        nonempty_directory,
        lambda: wheel_resource_audit(
            nonempty_directory, package_expected, external_expected, manifest_expected
        ),
        "wheel directory member is nonempty",
    )

    expected_directories = sorted(expected_resource_directories(package_expected))
    explicit_directories = tuple(
        [package_prefix + path + "/" for path in expected_directories]
        + [external_prefix + path + "/" for path in expected_directories]
    )
    explicit_directory_wheel = temporary / "explicit-expected-directories.whl"
    rewrite_wheel(
        wheel,
        explicit_directory_wheel,
        extra_directories=explicit_directories,
        rebuild_record=True,
    )
    record_audit(explicit_directory_wheel)
    wheel_resource_audit(
        explicit_directory_wheel,
        package_expected,
        external_expected,
        manifest_expected,
    )

    fourth_directory = temporary / "external-fourth-directory.whl"
    rewrite_wheel(
        wheel,
        fourth_directory,
        extra_directories=(external_prefix + "fourth/",),
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "external fourth directory control",
        fourth_directory,
        lambda: wheel_resource_audit(
            fourth_directory, package_expected, external_expected, manifest_expected
        ),
        "external production resource directories differ",
    )

    nested_external_directory = temporary / "nested-external-directory.whl"
    rewrite_wheel(
        wheel,
        nested_external_directory,
        extra_directories=(external_prefix + "contracts/unmanifested/",),
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "nested external directory control",
        nested_external_directory,
        lambda: wheel_resource_audit(
            nested_external_directory,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "external production resource directories differ",
    )

    package_empty_directory = temporary / "package-empty-directory.whl"
    rewrite_wheel(
        wheel,
        package_empty_directory,
        extra_directories=(package_prefix + "licenses/unmanifested/",),
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "package empty directory control",
        package_empty_directory,
        lambda: wheel_resource_audit(
            package_empty_directory,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "package production resource directories differ",
    )

    alternate_external_root = temporary / "alternate-empty-external-root.whl"
    rewrite_wheel(
        wheel,
        alternate_external_root,
        extra_directories=("alternate.data/data/share/kilix-content/",),
        rebuild_record=True,
    )
    expect_repaired_wheel_failure(
        "empty alternate external root control",
        alternate_external_root,
        lambda: wheel_resource_audit(
            alternate_external_root,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "external production resource roots are not exactly one",
    )

    installed_external = temporary / "installed-external"
    materialize_resource_tree(installed_external, external_expected)
    installed_external.joinpath("fourth").mkdir()
    installed_external.joinpath("fourth").chmod(EXPECTED_WHEEL_DIRECTORY_MODE)
    external_files, external_directories = filesystem_resource_mapping(
        installed_external, package_subtrees=False
    )
    expect_audit_failure(
        "installed external fourth directory control",
        lambda: audit_resource_tree(
            "installed external",
            external_files,
            external_directories,
            external_expected,
        ),
        "installed external production resource directories differ",
    )

    installed_package = temporary / "installed-package"
    materialize_resource_tree(installed_package, package_expected)
    installed_package.joinpath("licenses", "unmanifested").mkdir()
    installed_package.joinpath("licenses", "unmanifested").chmod(
        EXPECTED_WHEEL_DIRECTORY_MODE
    )
    package_files, package_directories = filesystem_resource_mapping(
        installed_package, package_subtrees=True
    )
    expect_audit_failure(
        "installed package empty directory control",
        lambda: audit_resource_tree(
            "installed package",
            package_files,
            package_directories,
            package_expected,
        ),
        "installed package production resource directories differ",
    )

    installed_mode_cases = (
        ("setuid", 0o4755),
        ("setgid", 0o2755),
        ("sticky", 0o1755),
        ("world-writable", 0o777),
        ("unreadable", 0o000),
    )
    for presentation, expected, package_subtrees in (
        ("external", external_expected, False),
        ("package", package_expected, True),
    ):
        for mode_name, mode in installed_mode_cases:
            mode_root = temporary / f"installed-{presentation}-{mode_name}"
            materialize_resource_tree(mode_root, expected)
            target = mode_root / "licenses" / "MIT.txt"
            target.chmod(mode)
            expect_audit_failure(
                f"installed {presentation} {mode_name} mode control",
                lambda mode_root=mode_root, package_subtrees=package_subtrees: filesystem_resource_mapping(
                    mode_root, package_subtrees=package_subtrees
                ),
                "installed production resource permissions differ: licenses/MIT.txt",
            )
    print("installed-tree resource mode controls: PASS")

    missing_external = temporary / "missing-external-mit.whl"
    rewrite_wheel(
        wheel,
        missing_external,
        remove={external_prefix + "licenses/MIT.txt"},
    )
    expect_audit_failure(
        "missing external MIT control",
        lambda: wheel_resource_audit(
            missing_external, package_expected, external_expected, manifest_expected
        ),
        "external production resource set differs: missing=['licenses/MIT.txt']",
    )

    absent_external = temporary / "absent-external-root.whl"
    rewrite_wheel(wheel, absent_external, remove_prefixes=(external_prefix,))
    expect_audit_failure(
        "absent external root control",
        lambda: wheel_resource_audit(
            absent_external, package_expected, external_expected, manifest_expected
        ),
        "external production resource roots are not exactly one",
    )

    duplicate_external = temporary / "duplicate-external-root.whl"
    duplicate_prefix = "duplicate.data/data/share/kilix-content/"
    with zipfile.ZipFile(wheel) as archive:
        duplicate_files = {
            duplicate_prefix + name[len(external_prefix) :]: archive.read(name)
            for name in external_names
            if not name.endswith("/")
        }
    rewrite_wheel(wheel, duplicate_external, extra=duplicate_files)
    expect_audit_failure(
        "duplicate external root control",
        lambda: wheel_resource_audit(
            duplicate_external, package_expected, external_expected, manifest_expected
        ),
        "external production resource roots are not exactly one",
    )

    duplicate_member = temporary / "duplicate-resource-member.whl"
    rewrite_wheel(
        wheel,
        duplicate_member,
        duplicate=(external_prefix + "licenses/MIT.txt",),
    )
    expect_audit_failure(
        "duplicate normalized member control",
        lambda: wheel_resource_audit(
            duplicate_member, package_expected, external_expected, manifest_expected
        ),
        "duplicate normalized members",
    )

    extra_package = temporary / "extra-package-resource.whl"
    rewrite_wheel(
        wheel,
        extra_package,
        extra={package_prefix + "licenses/UNMANIFESTED.txt": b"extra"},
    )
    expect_audit_failure(
        "extra package resource control",
        lambda: wheel_resource_audit(
            extra_package, package_expected, external_expected, manifest_expected
        ),
        "package production resource set differs",
    )

    extra_external = temporary / "extra-external-resource.whl"
    rewrite_wheel(
        wheel,
        extra_external,
        extra={external_prefix + "licenses/UNMANIFESTED.txt": b"extra"},
    )
    expect_audit_failure(
        "extra external resource control",
        lambda: wheel_resource_audit(
            extra_external, package_expected, external_expected, manifest_expected
        ),
        "external production resource set differs",
    )

    extra_external_top_level = temporary / "extra-external-top-level.whl"
    rewrite_wheel(
        wheel,
        extra_external_top_level,
        extra={external_prefix + "UNMANIFESTED.txt": b"extra"},
    )
    expect_audit_failure(
        "top-level external resource control",
        lambda: wheel_resource_audit(
            extra_external_top_level,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "external production resource set differs",
    )

    renamed_path = temporary / "renamed-external-resource.whl"
    with zipfile.ZipFile(wheel) as archive:
        mit = archive.read(external_prefix + "licenses/MIT.txt")
    rewrite_wheel(
        wheel,
        renamed_path,
        remove={external_prefix + "licenses/MIT.txt"},
        extra={external_prefix + "licenses/MIT-renamed.txt": mit},
    )
    expect_audit_failure(
        "renamed external resource control",
        lambda: wheel_resource_audit(
            renamed_path, package_expected, external_expected, manifest_expected
        ),
        "external production resource set differs",
    )

    missing_package = temporary / "missing-package-mit.whl"
    rewrite_wheel(
        wheel,
        missing_package,
        remove={package_prefix + "licenses/MIT.txt"},
    )
    expect_audit_failure(
        "missing package MIT root-isolation control",
        lambda: wheel_resource_audit(
            missing_package, package_expected, external_expected, manifest_expected
        ),
        "package production resource set differs: missing=['licenses/MIT.txt']",
    )

    size_mismatch = temporary / "external-size-mismatch.whl"
    rewrite_wheel(
        wheel,
        size_mismatch,
        replace={external_prefix + "licenses/MIT.txt": b"not-the-license"},
    )
    expect_audit_failure(
        "external size mismatch control",
        lambda: wheel_resource_audit(
            size_mismatch, package_expected, external_expected, manifest_expected
        ),
        "external production resource size mismatch: licenses/MIT.txt",
    )

    digest_mismatch = temporary / "package-digest-mismatch.whl"
    original_mit = external_expected["licenses/MIT.txt"][1]
    altered_mit = bytes([original_mit[0] ^ 1]) + original_mit[1:]
    rewrite_wheel(
        wheel,
        digest_mismatch,
        replace={package_prefix + "licenses/MIT.txt": altered_mit},
    )
    expect_audit_failure(
        "package digest mismatch control",
        lambda: wheel_resource_audit(
            digest_mismatch, package_expected, external_expected, manifest_expected
        ),
        "package production resource digest mismatch: licenses/MIT.txt",
    )

    legacy_asset = "contracts/kilix.content.asset-v1.schema.json"
    legacy_rename = temporary / "renamed-external-legacy-resource.whl"
    with zipfile.ZipFile(wheel) as archive:
        legacy_payload = archive.read(external_prefix + legacy_asset)
    rewrite_wheel(
        wheel,
        legacy_rename,
        remove={external_prefix + legacy_asset},
        extra={external_prefix + "contracts/legacy-asset.schema.json": legacy_payload},
    )
    expect_audit_failure(
        "renamed external co-resident control",
        lambda: wheel_resource_audit(
            legacy_rename, package_expected, external_expected, manifest_expected
        ),
        "external production resource set differs",
    )

    legacy_duplicate = temporary / "duplicate-package-legacy-resource.whl"
    rewrite_wheel(
        wheel,
        legacy_duplicate,
        duplicate=(package_prefix + "catalog/plebian.json",),
    )
    expect_audit_failure(
        "duplicate package co-resident control",
        lambda: wheel_resource_audit(
            legacy_duplicate, package_expected, external_expected, manifest_expected
        ),
        "duplicate normalized members",
    )

    package_marker = package_expected["catalog/__init__.py"][1]
    marker_mutation = bytes([package_marker[0] ^ 1]) + package_marker[1:]
    legacy_byte_mutation = temporary / "mutated-package-legacy-resource.whl"
    rewrite_wheel(
        wheel,
        legacy_byte_mutation,
        replace={package_prefix + "catalog/__init__.py": marker_mutation},
    )
    expect_audit_failure(
        "mutated package co-resident control",
        lambda: wheel_resource_audit(
            legacy_byte_mutation,
            package_expected,
            external_expected,
            manifest_expected,
        ),
        "package production resource digest mismatch: catalog/__init__.py",
    )

    package_projection = {
        path: item[1] for path, item in manifest_expected.items()
    }
    external_projection = dict(package_projection)
    external_projection["licenses/MIT.txt"] = b"reachable cross-presentation mismatch"
    expect_audit_failure(
        "cross-presentation byte mismatch control",
        lambda: compare_cross_presentation_bytes(
            package_projection, external_projection, set(manifest_expected)
        ),
        "package/external production resource byte mismatch: licenses/MIT.txt",
    )

    print("dual-root resource negative controls: PASS")


def run_property_mutation_registry(
    sdist_artifacts: dict[str, Path],
    sdist_source_root: Path,
    wheel_artifacts: dict[str, Path],
    expected_members: set[str],
    package_expected: dict[str, tuple[str, bytes]],
    external_expected: dict[str, tuple[str, bytes]],
    manifest_expected: dict[str, tuple[str, bytes]],
    temporary: Path,
    uv_path: Path,
    base_python: Path,
    install_environment: dict[str, str],
    manifest_digest: str,
) -> None:
    """Execute every hand-authored mutation against every shipped artifact."""
    validate_property_mutation_registry()
    temporary.mkdir(parents=True, exist_ok=True)

    def run_one(row: dict[str, str], label: str, archive: Path) -> None:
        case = temporary / row["id"].replace(".", "-") / label.replace(" ", "-")
        case.mkdir(parents=True, exist_ok=True)
        identifier = row["id"]
        if identifier == "sdist.container.gzip-trailing":
            mutated = case / "mutated.tar.gz"
            rewrite_sdist_with_gzip_trailing_bytes(archive, mutated)
            action = partial(sdist_container_audit, mutated)
        elif identifier == "sdist.enumerator.physical-directory-size":
            mutated = case / "mutated.tar.gz"
            rewrite_sdist_untruthful_directory_size(
                archive, mutated, tarfile.BLOCKSIZE
            )
            action = partial(
                assert_sdist_enumerator_agreement, mutated, check_container=False
            )
        elif identifier == "sdist.payload.source-byte":
            mutated = case / "mutated.tar.gz"
            top = sdist_distribution_root(PROJECT)
            original = raw_sdist_member_payload(archive, top + "/README.md")
            rewrite_sdist(
                archive,
                mutated,
                replace={"README.md": bytes([original[0] ^ 1]) + original[1:]},
            )
            action = partial(
                sdist_payload_audit, mutated, PROJECT, sdist_distribution_root(PROJECT)
            )
        elif identifier == "sdist.member.permission":
            mutated = case / "mutated.tar.gz"
            rewrite_sdist(
                archive,
                mutated,
                modes={"tests/test_u1_contracts.py": 0o4755},
            )
            action = partial(extract_sdist, mutated, case / "extract")
        elif identifier == "sdist.generated-metadata.byte":
            mutated = case / "mutated.tar.gz"
            relative = "PKG-INFO"
            original = raw_sdist_member_payload(
                archive, sdist_distribution_root(PROJECT) + "/" + relative
            )
            rewrite_sdist(
                archive,
                mutated,
                replace={relative: bytes([original[0] ^ 1]) + original[1:]},
            )
            action = partial(sdist_generated_metadata_audit, mutated, archive)
        elif identifier == "wheel.container.trailing":
            mutated = case / "mutated.whl"
            mutated.write_bytes(archive.read_bytes() + b"R14-wheel-trailing")
            action = partial(wheel_container_audit, mutated)
        elif identifier == "wheel.archive.extra-member":
            mutated = case / "mutated.whl"
            rewrite_wheel(
                archive,
                mutated,
                extra={"r14-unregistered.txt": b"unregistered\n"},
                rebuild_record=True,
            )
            action = partial(wheel_archive_audit, mutated, expected_members)
        elif identifier == "wheel.record.self-row":
            mutated = case / "mutated.whl"
            rewrite_wheel_nonempty_record_self_row(archive, mutated)
            action = partial(record_audit, mutated)
        elif identifier == "wheel.resource.byte":
            mutated = case / "mutated.whl"
            path = "kilix_content/catalog/__init__.py"
            original = package_expected["catalog/__init__.py"][1]
            rewrite_wheel(
                archive,
                mutated,
                replace={path: bytes([original[0] ^ 1]) + original[1:]},
                rebuild_record=True,
            )
            action = partial(
                wheel_resource_audit,
                mutated,
                package_expected,
                external_expected,
                manifest_expected,
            )
        elif identifier == "wheel.module.source-byte":
            mutated = case / "mutated.whl"
            path = "kilix_content/install.py"
            original = (PROJECT / "src" / "kilix_content" / "install.py").read_bytes()
            rewrite_wheel(
                archive,
                mutated,
                replace={path: bytes([original[0] ^ 1]) + original[1:]},
                rebuild_record=True,
            )
            action = partial(wheel_module_source_audit, mutated, PROJECT)
        elif identifier == "wheel.installed.manifest":
            mutated = case / archive.name
            manifest_member = f"kilix_content/contracts/{U1_MANIFEST}"
            with zipfile.ZipFile(archive) as source_zip:
                original = source_zip.read(manifest_member)
            rewrite_wheel(
                archive,
                mutated,
                replace={manifest_member: bytes([original[0] ^ 1]) + original[1:]},
                rebuild_record=True,
            )
            action = partial(
                installed_wheel_audit,
                mutated,
                uv_path,
                base_python,
                install_environment,
                case / "install",
                manifest_digest,
                package_expected,
                external_expected,
                manifest_expected,
            )
        elif identifier == "wheel.container.prepend":
            mutated = case / "mutated.whl"
            mutated.write_bytes(b"R15-container-prepend" + archive.read_bytes())
            action = partial(wheel_container_audit, mutated)
        elif identifier == "wheel.container.appended-zip":
            mutated = case / "mutated.whl"
            appended = io.BytesIO()
            with zipfile.ZipFile(appended, "w") as appended_zip:
                appended_zip.writestr("r15-appended.txt", b"appended complete zip")
            mutated.write_bytes(archive.read_bytes() + appended.getvalue())
            action = partial(wheel_container_audit, mutated)
        elif identifier == "wheel.resource-authority.sdist-manifest":
            mutated_root = case / "sdist-root"
            shutil.copytree(sdist_source_root, mutated_root)
            manifest_path = mutated_root / "contracts" / U1_MANIFEST
            manifest = json.loads(manifest_path.read_bytes())
            manifest["r16-mutation"] = True
            manifest_path.write_bytes(canonical_json(manifest))
            action = partial(resource_audit, archive, PROJECT, mutated_root)
        else:
            fail(f"property/mutation registry has no executor: {identifier}")
        expect_audit_failure(
            f"registered mutation {identifier} on {label}",
            action,
            row["expected_refusal"],
        )
        _PROPERTY_MUTATION_EXECUTIONS.add((identifier, label))
        if identifier in R16_16_ACCOUNTING_EFFECT_IDS:
            presentation_id = R16_16_PRESENTATION_IDS.get(label)
            if presentation_id is None:
                fail(f"R16-16 mutation presentation is unregistered: {label}")
            event = {
                "artifact_sha256": digest(archive),
                "effect_id": identifier,
                "family": row["artifact_family"],
                "presentation_id": presentation_id,
            }
            invocation = (row["artifact_family"], identifier, presentation_id)
            if any(
                (
                    observed["family"],
                    observed["effect_id"],
                    observed["presentation_id"],
                )
                == invocation
                for observed in _R16_16_ACCOUNTING_EVENTS
            ):
                fail(
                    "R16-16 duplicate mutation invocation: "
                    f"{row['artifact_family']}:{identifier}:{presentation_id}"
                )
            _R16_16_ACCOUNTING_EVENTS.append(event)

    for label, archive in sdist_artifacts.items():
        for row in PROPERTY_MUTATION_REGISTRY:
            if row["artifact_family"] == "sdist":
                run_one(row, label, archive)
    for label, archive in wheel_artifacts.items():
        for row in PROPERTY_MUTATION_REGISTRY:
            if row["artifact_family"] == "wheel":
                run_one(row, label, archive)
    expected_invocations = sum(
        2 if row["artifact_family"] == "sdist" else 3
        for row in PROPERTY_MUTATION_REGISTRY
    )
    accounting = r16_16_accounting_populations()
    print(
        "append-only property/mutation registry: PASS "
        f"rows={len(PROPERTY_MUTATION_REGISTRY)}/{len(PROPERTY_MUTATION_REGISTRY)} "
        f"mutation-invocations={len(_PROPERTY_MUTATION_EXECUTIONS)}/"
        f"{expected_invocations} "
        f"effect-classes={len(PROPERTY_MUTATION_REGISTRY)}/"
        f"{len(PROPERTY_MUTATION_REGISTRY)}; "
        "R16-16 frozen R15 topology: PASS "
        f"mutation-invocations={accounting['mutation_invocations']}/32 "
        f"effect-classes={accounting['effect_classes']}/12 "
        f"presentations={accounting['presentations']}/5 "
        f"shipped-byte-identities={accounting['byte_identities']}/2"
    )


def r16_16_accounting_populations() -> dict[str, int]:
    events = _R16_16_ACCOUNTING_EVENTS
    invocations = {
        (event["family"], event["effect_id"], event["presentation_id"])
        for event in events
    }
    effects = {event["effect_id"] for event in events}
    presentations = {event["presentation_id"] for event in events}
    byte_identities = {event["artifact_sha256"] for event in events}
    observed = {
        "byte_identities": len(byte_identities),
        "effect_classes": len(effects),
        "mutation_invocations": len(invocations),
        "presentations": len(presentations),
    }
    expected = {
        "byte_identities": 2,
        "effect_classes": 12,
        "mutation_invocations": 32,
        "presentations": 5,
    }
    if len(events) != len(invocations):
        fail(
            "R16-16 accounting events contain a duplicate invocation: "
            f"events={len(events)} invocations={len(invocations)}"
        )
    if observed != expected:
        fail(f"R16-16 accounting population differs: {observed!r}")
    return observed


def _runtime_record_fd(configured: str, label: str) -> int:
    if re.fullmatch(r"[0-9]+", configured) is None:
        fail(f"{label} channel fd is not a canonical nonnegative integer")
    fd = int(configured)
    if fd <= 2:
        fail(f"{label} channel fd must be greater than 2")
    try:
        metadata = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        fail(f"{label} channel fd is unavailable: {exc}")
    if not (
        stat.S_ISFIFO(metadata.st_mode)
        or stat.S_ISSOCK(metadata.st_mode)
        or stat.S_ISCHR(metadata.st_mode)
    ):
        fail(
            f"{label} channel violates OD-20: expected pipe/socket/character-device, "
            f"observed-mode={oct(stat.S_IFMT(metadata.st_mode))}"
        )
    if flags & os.O_ACCMODE == os.O_RDONLY:
        fail(f"{label} channel fd is not writable")
    return fd


def _write_runtime_record(fd: int, payload: bytes, label: str) -> None:
    remaining = memoryview(payload)
    try:
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                fail(f"{label} channel made no write progress")
            remaining = remaining[written:]
        os.close(fd)
    except OSError as exc:
        fail(f"{label} channel write failed: {exc}")


def write_r16_runtime_records() -> None:
    legacy_paths = (
        os.environ.get("KILIX_F100_R16_14_TRACE_OUTPUT"),
        os.environ.get("KILIX_F100_R16_16_EVENTS_OUTPUT"),
    )
    if any(legacy_paths):
        fail(
            "R16 pathname runtime-record channels violate OD-20: "
            "legacy-paths-accepted=0/2"
        )
    r16_14_channel = os.environ.get("KILIX_F100_R16_14_TRACE_FD")
    r16_16_channel = os.environ.get("KILIX_F100_R16_16_EVENTS_FD")
    accounting_sha256 = os.environ.get(
        "KILIX_F100_R16_16_ACCOUNTING_AUTHORITY_SHA256"
    )
    configured = (r16_14_channel, r16_16_channel, accounting_sha256)
    if not any(configured):
        print("R16 external runtime records: NOT_EMITTED channels=0/2")
        return
    if not all(configured):
        fail("R16 external runtime record configuration is incomplete: 0/3 accepted")
    assert r16_14_channel is not None
    assert r16_16_channel is not None
    assert accounting_sha256 is not None
    if re.fullmatch(r"[0-9a-f]{64}", accounting_sha256) is None:
        fail("R16-16 accounting authority SHA-256 is invalid")

    r16_14_fd = _runtime_record_fd(r16_14_channel, "R16-14 trace")
    r16_16_fd = _runtime_record_fd(r16_16_channel, "R16-16 events")
    if r16_14_fd == r16_16_fd:
        fail("R16 runtime-record channels are not distinct: accepted=0/2")
    r16_14_record = {
        "events": sorted(
            _R16_14_SDIST_EFFECT_EVENTS,
            key=lambda event: event["identity"],
        ),
        "schema_version": "r16-14-sdist-effect-trace-v1",
    }
    r16_16_record = {
        "authority_sha256": accounting_sha256,
        "events": list(_R16_16_ACCOUNTING_EVENTS),
        "schema": "kilix.content.f100-u1-r16-16-accounting-events/v1",
    }
    r16_14_bytes = canonical_json(r16_14_record, newline=True)
    r16_16_bytes = canonical_json(r16_16_record, newline=True)
    _write_runtime_record(r16_14_fd, r16_14_bytes, "R16-14 trace")
    _write_runtime_record(r16_16_fd, r16_16_bytes, "R16-16 events")
    print(
        "R16 external runtime records: EMITTED channels=2/2 "
        f"r16-14-sha256={hashlib.sha256(r16_14_bytes).hexdigest()} "
        f"r16-16-sha256={hashlib.sha256(r16_16_bytes).hexdigest()}"
    )


def configure_temporary_root() -> Path:
    configured = os.environ.get("TMPDIR")
    if not configured:
        fail("TMPDIR must be explicitly set for the reproducible-build gate")
    root = Path(configured)
    if not root.is_absolute():
        fail("TMPDIR must be an absolute path")
    root = root.resolve()
    if root == Path("/tmp") or root.is_relative_to(Path("/tmp")):
        fail("TMPDIR must not be /tmp for the reproducible-build gate")
    root.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage("/tmp")
    tempfile.tempdir = str(root)
    print(f"TMPDIR={root} /tmp-free-bytes={usage.free}")
    return root


def assert_complete_gate_regressions() -> None:
    """The default gate must observe every complete-gate regression run.

    R14 moved these behind --r14-slow-regressions, which nothing in the tree
    invokes, so the controls never ran on the release path. The default path
    now runs them and this asserts they were observed; a regression whose call
    is deleted, or that returns without launching its nested complete gate, is
    refused by name.
    """
    missing = _REQUIRED_COMPLETE_GATE_REGRESSIONS - _COMPLETE_GATE_REGRESSIONS_OBSERVED
    if missing:
        fail(
            "required complete-gate regression was not observed: "
            f"{sorted(missing)!r}"
        )


def main() -> int:
    modes = set(sys.argv[1:])
    allowed_modes = {
        "--r13-skip-regressions",
    }
    if not modes <= allowed_modes:
        fail(f"unknown checker mode: {sorted(modes)!r}")
    environment, uv_path, base_python = checked_toolchain()
    temporary_root = configure_temporary_root()
    environment["TMPDIR"] = str(temporary_root)
    verify_wheelhouse(PROJECT)
    run(
        [str(uv_path), "lock", "--check", "--offline", "--python", str(base_python)],
        cwd=PROJECT,
        env=environment,
        label="uv lock check",
    )
    skip_regressions = "--r13-skip-regressions" in modes
    if not skip_regressions:
        with tempfile.TemporaryDirectory(prefix="kilix-u1-regressions-") as name:
            regression_root = Path(name)
            r12_reader_reversion_regression(
                uv_path,
                base_python,
                environment,
                regression_root / "r12-reader",
            )
            r13_callsite_wiring_regression(
                uv_path,
                base_python,
                environment,
                regression_root / "r13-wiring",
            )
        assert_complete_gate_regressions()
    with tempfile.TemporaryDirectory(prefix="kilix-u1-r7-") as temporary_name:
        temporary = Path(temporary_name)
        verify_export(
            PROJECT,
            uv_path,
            base_python,
            environment,
            temporary / "requirements.txt",
        )
        source_python, source_env = bootstrap_environment(
            PROJECT,
            temporary / "source-environment",
            uv_path,
            base_python,
            environment,
            install_project=True,
        )
        print("empty-cache offline source reconstruction: PASS")
        source_gates(PROJECT, source_python, source_env)
        print("locked source tests and lint: PASS")

        direct_one = build(
            PROJECT,
            temporary / "direct-one",
            source_python,
            source_env,
            "--sdist",
            "--wheel",
        )
        direct_two = build(
            PROJECT,
            temporary / "direct-two",
            source_python,
            source_env,
            "--sdist",
            "--wheel",
        )
        for label, archive in (
            ("direct sdist 1", direct_one["sdist"]),
            ("direct sdist 2", direct_two["sdist"]),
        ):
            register_production_audit(
                "sdist",
                label,
                "container",
                lambda archive=archive: sdist_container_audit(archive),
            )
            register_production_audit(
                "sdist",
                label,
                "enumerator",
                lambda archive=archive: run_sdist_audit(
                    "direct-enumerator",
                    lambda: assert_sdist_enumerator_agreement(archive),
                ),
            )
            register_production_audit(
                "sdist",
                label,
                "payload",
                lambda archive=archive: run_sdist_audit(
                    "direct-payload",
                    lambda: sdist_payload_audit(
                        archive,
                        PROJECT,
                        sdist_distribution_root(PROJECT),
                    ),
                ),
            )
            register_production_audit(
                "sdist",
                label,
                "closure",
                lambda archive=archive: sdist_member_closure_audit(archive),
            )
            print(f"{label} enumeration and payload audit: PASS")
        register_production_audit(
            "sdist",
            "direct sdist pair",
            "generated-metadata",
            lambda: run_sdist_audit(
                "generated-metadata-audit",
                lambda: sdist_generated_metadata_audit(
                    direct_one["sdist"], direct_two["sdist"]
                ),
            ),
        )
        sdist_member_closure_negative_controls(
            direct_one["sdist"], temporary / "sdist-controls"
        )
        sdist_container_and_type_controls(
            direct_one["sdist"], temporary / "sdist-container-controls"
        )
        source_root = extract_sdist(direct_one["sdist"], temporary / "extracted-sdist")
        verify_wheelhouse(source_root)
        verify_export(
            source_root,
            uv_path,
            base_python,
            environment,
            temporary / "sdist-requirements.txt",
        )
        sdist_python, sdist_env = bootstrap_environment(
            source_root,
            temporary / "sdist-environment",
            uv_path,
            base_python,
            environment,
            install_project=True,
        )
        print("empty-cache offline exact-sdist reconstruction: PASS")
        source_gates(source_root, sdist_python, sdist_env)
        print("exact-sdist tests and lint: PASS")
        rebuilt = build(
            source_root,
            temporary / "from-sdist",
            sdist_python,
            sdist_env,
            "--wheel",
        )

        _, source_resources = production_resources(PROJECT)
        source_package, source_external = coresident_resources(
            PROJECT, source_resources
        )
        expected_members = expected_wheel_members(
            PROJECT, source_package, source_external
        )
        wheel_artifacts = {
            "direct wheel 1": direct_one["wheel"],
            "direct wheel 2": direct_two["wheel"],
            "sdist-derived wheel": rebuilt["wheel"],
        }
        for label, wheel in wheel_artifacts.items():
            register_production_audit(
                "wheel",
                label,
                "container",
                lambda wheel=wheel: wheel_container_audit(wheel),
            )
            register_production_audit(
                "wheel",
                label,
                "archive",
                lambda wheel=wheel: wheel_archive_audit(wheel, expected_members),
            )
            register_production_audit(
                "wheel",
                label,
                "record",
                lambda wheel=wheel: record_audit(wheel),
            )
            register_production_audit(
                "wheel",
                label,
                "module",
                lambda wheel=wheel: wheel_module_source_audit(wheel, PROJECT),
            )
        record_self_row_empty_control(
            direct_one["wheel"],
            expected_members,
            temporary / "record-self-row-control",
        )
        wheels = wheel_artifacts
        manifest_digests = {
            register_production_audit(
                "wheel",
                label,
                "resource-authority",
                lambda wheel=wheel: resource_audit(wheel, PROJECT, source_root),
            )
            for label, wheel in wheels.items()
        }
        if len(manifest_digests) != 1:
            fail(f"production resource manifest digests differ: {manifest_digests!r}")
        manifest_digest = next(iter(manifest_digests))
        for label, wheel in wheels.items():
            register_production_audit(
                "wheel",
                label,
                "resource",
                lambda wheel=wheel: wheel_resource_audit(
                    wheel, source_package, source_external, source_resources
                ),
            )
        wheel_member_closure_negative_controls(
            direct_one["wheel"],
            expected_members,
            uv_path,
            base_python,
            environment,
            temporary / "member-controls",
        )
        honest_entrypoint_control(
            source_package,
            source_external,
            uv_path,
            base_python,
            environment,
            source_python,
            source_env,
            temporary / "entrypoint-control",
        )
        source_module_derivation_controls(
            source_package,
            source_external,
            source_resources,
            source_python,
            source_env,
            temporary / "module-controls",
        )
        resource_negative_controls(
            direct_one["wheel"],
            source_package,
            source_external,
            source_resources,
            temporary / "resource-controls",
        )
        wheel_resource_audit(
            direct_one["wheel"], source_package, source_external, source_resources
        )
        for label, wheel in wheels.items():
            register_production_audit(
                "wheel",
                label,
                "installed",
                lambda wheel=wheel, label=label: installed_wheel_audit(
                    wheel,
                    uv_path,
                    base_python,
                    environment,
                    temporary / f"installed-{label.replace(' ', '-')}",
                    manifest_digest,
                    source_package,
                    source_external,
                    source_resources,
                ),
            )

        checks = {
            "direct sdist 1 == direct sdist 2": digest(direct_one["sdist"])
            == digest(direct_two["sdist"]),
            "direct wheel 1 == direct wheel 2": digest(direct_one["wheel"])
            == digest(direct_two["wheel"]),
            "direct wheel 1 == exact-sdist wheel": digest(direct_one["wheel"])
            == digest(rebuilt["wheel"]),
        }
        if not all(checks.values()):
            fail(f"reproducibility failure: {checks!r}")
        assert_sdist_audit_wiring()
        assert_wheel_member_closure(wheels)
        run_property_mutation_registry(
            {
                "direct sdist 1": direct_one["sdist"],
                "direct sdist 2": direct_two["sdist"],
            },
            source_root,
            wheels,
            expected_members,
            source_package,
            source_external,
            source_resources,
            temporary / "property-mutation-registry",
            uv_path,
            base_python,
            environment,
            manifest_digest,
        )
        assert_property_registry_coverage(
            {
                "sdist": {
                    "direct sdist 1": direct_one["sdist"],
                    "direct sdist 2": direct_two["sdist"],
                },
                "wheel": wheels,
            }
        )
        if skip_regressions:
            print(
                "R16 external runtime records: NOT_EMITTED "
                "nested-diagnostic outputs=0/2"
            )
        else:
            write_r16_runtime_records()
        print(f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}")
        for label, artifact in (
            ("direct-sdist", direct_one["sdist"]),
            ("direct-wheel", direct_one["wheel"]),
            ("sdist-derived-wheel", rebuilt["wheel"]),
        ):
            print(f"{label}={digest(artifact)}")
        regression_mode = (
            "complete-gate regressions skipped by --r13-skip-regressions"
            if skip_regressions
            else "complete-gate regressions observed: "
            + ", ".join(sorted(_COMPLETE_GATE_REGRESSIONS_OBSERVED))
        )
        print(
            "reproducible offline build and package audit: PASS "
            f"({regression_mode})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
