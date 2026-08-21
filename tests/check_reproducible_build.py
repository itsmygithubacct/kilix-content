"""Prove empty-cache, offline, reproducible U1 source and wheel authority."""

from __future__ import annotations

import base64
import csv
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
from pathlib import Path, PurePosixPath
from typing import Any


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
            mode = (info.external_attr >> 16) & 0o7777
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                fail("wheel contains a special or linked member")
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
        "/".join(PurePosixPath(name).parts[:4]) + "/"
        for name in archive.namelist()
        if len(PurePosixPath(name).parts) >= 5
        and PurePosixPath(name).parts[1:4]
        == ("data", "share", "kilix-content")
    }
    if observed_external != {external_prefix}:
        fail(
            "external production resource roots are not exactly one: "
            f"expected={[external_prefix]!r} observed={sorted(observed_external)!r}"
        )
    return package_prefix, external_prefix


def audit_resource_mapping(
    label: str,
    observed: dict[str, bytes],
    expected: dict[str, tuple[str, bytes]],
) -> None:
    expected_paths = set(expected)
    if set(observed) != expected_paths:
        missing = sorted(expected_paths - set(observed))
        extra = sorted(set(observed) - expected_paths)
        fail(
            f"{label} production resource set differs: "
            f"missing={missing!r} extra={extra!r}"
        )
    for path, (expected_digest, expected_payload) in expected.items():
        payload = observed[path]
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
) -> dict[str, bytes]:
    observed: dict[str, bytes] = {}
    for name in archive.namelist():
        if not name.startswith(prefix) or name.endswith("/"):
            continue
        relative = name[len(prefix) :]
        if package_subtrees and PurePosixPath(relative).parts[0] not in RESOURCE_TOP_LEVELS:
            continue
        observed[relative] = archive.read(name)
    return observed


def filesystem_resource_mapping(
    root: Path,
    *,
    package_subtrees: bool,
) -> dict[str, bytes]:
    observed: dict[str, bytes] = {}

    def visit(path: Path, relative: PurePosixPath) -> None:
        if path.is_symlink():
            fail(f"installed production resource is a symlink: {relative}")
        if path.is_dir():
            for child in sorted(path.iterdir()):
                visit(child, relative / child.name)
            return
        if not path.is_file():
            fail(f"installed production resource is not regular: {relative}")
        observed[relative.as_posix()] = path.read_bytes()

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
    return observed


def wheel_presentation_payloads(
    archive: zipfile.ZipFile,
    prefix: str,
    expected: dict[str, tuple[str, bytes]],
    label: str,
    *,
    package_subtrees: bool,
) -> dict[str, bytes]:
    observed = archive_resource_mapping(
        archive, prefix, package_subtrees=package_subtrees
    )
    audit_resource_mapping(label, observed, expected)
    return observed


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
        package_payloads = wheel_presentation_payloads(
            archive,
            package_prefix,
            package_expected,
            "package",
            package_subtrees=True,
        )
        external_payloads = wheel_presentation_payloads(
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
source_only_route_code = "U1_U1_ADMISSION_EXPECTED_SCHEMA_IS_OUTSIDE_THE_FROZEN_ROUTE_TAB"
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
    package_observed = filesystem_resource_mapping(
        package_root, package_subtrees=True
    )
    external_observed = filesystem_resource_mapping(
        external_root, package_subtrees=False
    )
    audit_resource_mapping("installed package", package_observed, package_expected)
    audit_resource_mapping("installed external", external_observed, external_expected)
    compare_cross_presentation_bytes(
        package_observed, external_observed, set(manifest_expected)
    )
    print("installed-wheel external corpus and resources: PASS")


def rewrite_wheel(
    source: Path,
    destination: Path,
    *,
    remove: set[str] | None = None,
    remove_prefixes: tuple[str, ...] = (),
    replace: dict[str, bytes] | None = None,
    extra: dict[str, bytes] | None = None,
    duplicate: tuple[str, ...] = (),
) -> None:
    removed = remove or set()
    replacements = replace or {}
    additions = extra or {}
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED
    ) as destination_archive:
        for info in source_archive.infolist():
            name = info.filename
            if name in removed or any(name.startswith(prefix) for prefix in remove_prefixes):
                continue
            payload = replacements.get(name, source_archive.read(name))
            destination_archive.writestr(info, payload)
        for name in duplicate:
            destination_archive.writestr(name, source_archive.read(name))
        for name, payload in additions.items():
            destination_archive.writestr(name, payload)


def expect_audit_failure(label: str, action: Any, fragment: str) -> None:
    try:
        action()
    except SystemExit as caught:
        detail = str(caught)
        if fragment not in detail:
            fail(f"{label} failed for the wrong reason: {detail}")
        return
    fail(f"{label} unexpectedly passed")


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
