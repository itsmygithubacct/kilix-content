"""Prove empty-cache, offline, reproducible U1 source and wheel authority."""

from __future__ import annotations

import base64
import csv
import io
import hashlib
import importlib.metadata
import json
import posixpath
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from copy import copy
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


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    uv_path = Path(str(uv.get("executable")))
    if not uv_path.is_file() or digest(uv_path) != uv.get("sha256"):
        fail("uv executable digest does not match build-toolchain.json")
    version = run(
        [str(uv_path), "--version"],
        cwd=PROJECT,
        env=env,
        label="uv identity probe",
    ).stdout.split()
    if len(version) < 2 or version[1] != uv.get("version"):
        fail("uv version does not match build-toolchain.json")

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


def extract_sdist(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
        if not members:
            fail("sdist is empty")
        top = PurePosixPath(members[0].name).parts[0]
        normalized: set[str] = set()
        for member in members:
            key = safe_member_name(member.name)
            if key in normalized or PurePosixPath(member.name).parts[0] != top:
                fail("sdist has duplicate or split-root members")
            normalized.add(key)
            if not (member.isdir() or member.isfile()) or member.mode & 0o444 != 0o444:
                fail("sdist contains a linked, special, or unreadable member")
        handle.extractall(destination, filter="data")
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


def classify_wheel_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    name = info.filename
    safe_member_name(name)
    if info.create_system != 3:
        fail(f"wheel member creator/type is ambiguous: {name}")
    mode_word = info.external_attr >> 16
    kind = stat.S_IFMT(mode_word)
    if kind not in (stat.S_IFREG, stat.S_IFDIR):
        fail(f"wheel member has an unsupported or unknown type: {name}")
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


def wheel_archive_audit(wheel: Path) -> set[str]:
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            fail("wheel CRC check failed")
        infos = archive.infolist()
        names = [info.filename for info in infos]
        normalized = {safe_member_name(name) for name in names}
        if len(normalized) != len(names):
            fail("wheel has duplicate normalized members")
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
            if relative.parts:
                observed_directories.add(relative.as_posix())
            for child in sorted(path.iterdir()):
                visit(child, relative / child.name)
            return
        if not path.is_file():
            fail(f"installed production resource is not regular: {relative}")
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


def resource_audit(
    source_root: Path,
    sdist_root: Path,
    wheels: dict[str, Path],
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
    for label, wheel in wheels.items():
        with zipfile.ZipFile(wheel) as archive:
            wheel_manifest = archive.read(f"kilix_content/contracts/{U1_MANIFEST}")
            if wheel_manifest != source_manifest:
                fail(f"{label} wheel production manifest differs from source")
        wheel_resource_audit(
            wheel, source_package, source_external, source_resources
        )
    return manifest_digest


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
    destination.mkdir()
    python, environment = bootstrap_environment(
        PROJECT,
        destination,
        uv_path,
        base_python,
        base_env,
        install_project=False,
    )
    run(
        [
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
        ],
        cwd=destination,
        env=environment,
        label="isolated wheel installation",
    )
    external = temporary / "external-cwd"
    external.mkdir()
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
    rebuild_record: bool = False,
) -> None:
    removed = remove or set()
    replacements = replace or {}
    additions = extra or {}
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
            entries.append((regular_zip_info(name), payload))
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
            record_info.external_attr = (stat.S_IFREG | 0o644) << 16
            entries.append(
                (record_info, build_record_payload(entries, record_name))
            )
        for info, payload in entries:
            destination_archive.writestr(info, payload)


def expect_audit_failure(label: str, action: Any, fragment: str) -> None:
    try:
        action()
    except SystemExit as caught:
        detail = str(caught)
        if fragment not in detail:
            fail(f"{label} failed for the wrong reason: {detail}")
        return
    fail(f"{label} unexpectedly passed")


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
    root.mkdir(parents=True, exist_ok=True)
    for path, (_, payload) in expected.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


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


def main() -> int:
    environment, uv_path, base_python = checked_toolchain()
    verify_wheelhouse(PROJECT)
    run(
        [str(uv_path), "lock", "--check", "--offline", "--python", str(base_python)],
        cwd=PROJECT,
        env=environment,
        label="uv lock check",
    )
    with tempfile.TemporaryDirectory(prefix="kilix-u1-r3-") as temporary_name:
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

        for wheel in (direct_one["wheel"], direct_two["wheel"], rebuilt["wheel"]):
            wheel_archive_audit(wheel)
            record_audit(wheel)
        wheels = {
            "direct wheel 1": direct_one["wheel"],
            "direct wheel 2": direct_two["wheel"],
            "sdist-derived wheel": rebuilt["wheel"],
        }
        manifest_digest = resource_audit(PROJECT, source_root, wheels)
        _, source_resources = production_resources(PROJECT)
        source_package, source_external = coresident_resources(
            PROJECT, source_resources
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
        installed_wheel_audit(
            direct_one["wheel"],
            uv_path,
            base_python,
            environment,
            temporary,
            manifest_digest,
            source_package,
            source_external,
            source_resources,
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
        print(f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}")
        for label, artifact in (
            ("direct-sdist", direct_one["sdist"]),
            ("direct-wheel", direct_one["wheel"]),
            ("sdist-derived-wheel", rebuilt["wheel"]),
        ):
            print(f"{label}={digest(artifact)}")
        print("reproducible offline build and package audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
