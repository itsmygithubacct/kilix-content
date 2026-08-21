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


def resource_audit(
    source_root: Path,
    sdist_root: Path,
    direct_wheel: Path,
    rebuilt_wheel: Path,
) -> tuple[str, dict[str, str]]:
    source_manifest, source_resources = production_resources(source_root)
    sdist_manifest, sdist_resources = production_resources(sdist_root)
    if source_manifest != sdist_manifest or source_resources != sdist_resources:
        fail("sdist production authority differs from source")
    manifest_digest = hashlib.sha256(source_manifest).hexdigest()
    expected = {path: item[0] for path, item in source_resources.items()}
    with (
        zipfile.ZipFile(direct_wheel) as direct,
        zipfile.ZipFile(rebuilt_wheel) as rebuilt,
    ):
        for archive in (direct, rebuilt):
            wheel_manifest = archive.read(f"kilix_content/contracts/{U1_MANIFEST}")
            if wheel_manifest != source_manifest:
                fail("wheel production manifest differs from source")
            for path, (expected_digest, payload) in source_resources.items():
                wheel_payload = archive.read(f"kilix_content/{path}")
                if (
                    wheel_payload != payload
                    or hashlib.sha256(wheel_payload).hexdigest() != expected_digest
                ):
                    fail("wheel production resource differs from source")
    return manifest_digest, expected


def installed_wheel_audit(
    wheel: Path,
    uv_path: Path,
    base_python: Path,
    base_env: dict[str, str],
    temporary: Path,
    manifest_digest: str,
    resource_hashes: dict[str, str],
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
import hashlib, importlib.resources as resources, json, pathlib, sys
from kilix_content import U1ContractError, packaged_release_capability, validate_u1_bytes, verify_packaged_u1_manifest
expected_manifest = sys.argv[1]
expected_resources = json.loads(sys.argv[2])
fixture_root = pathlib.Path(sys.argv[3])
for forbidden in sys.argv[4:]:
    assert forbidden not in sys.path
verify_packaged_u1_manifest()
root = resources.files("kilix_content")
manifest = root.joinpath("contracts", "kilix.content.u1-resources-v1.json").read_bytes()
assert hashlib.sha256(manifest).hexdigest() == expected_manifest
for path, expected in expected_resources.items():
    payload = root.joinpath(*path.split("/")).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == expected
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
package_path = pathlib.Path(__import__("kilix_content").__file__).resolve()
assert all(not package_path.is_relative_to(pathlib.Path(item)) for item in sys.argv[4:])
print("installed-wheel external corpus and resources: PASS")
"""
    result = run(
        [
            str(python),
            "-I",
            "-c",
            probe,
            manifest_digest,
            json.dumps(resource_hashes, sort_keys=True),
            str(PROJECT / "tests" / "fixtures" / "u1"),
            str(PROJECT),
            str(PROJECT / "src"),
            str(external),
        ],
        cwd=external,
        env=environment,
        label="external installed-wheel corpus probe",
    )
    print(result.stdout.strip())


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
        manifest_digest, resource_hashes = resource_audit(
            PROJECT, source_root, direct_one["wheel"], rebuilt["wheel"]
        )
        installed_wheel_audit(
            direct_one["wheel"],
            uv_path,
            base_python,
            environment,
            temporary,
            manifest_digest,
            resource_hashes,
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
