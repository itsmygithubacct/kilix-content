"""Prove the pinned offline U1 source/wheel build is reproducible."""

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


PROJECT = Path(__file__).resolve().parents[1]
TOOLCHAIN_PATH = PROJECT / "build-toolchain.json"
SOURCE_DATE_EPOCH = "1776729600"
EXPECTED_TOOLS = {"build": "1.3.0", "setuptools": "77.0.3", "wheel": "0.45.1"}


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def checked_toolchain() -> tuple[dict[str, object], dict[str, str], Path]:
    raw = TOOLCHAIN_PATH.read_bytes()
    toolchain = json.loads(raw)
    if raw != canonical_json(toolchain):
        fail("build-toolchain.json is not canonical JSON")
    if toolchain["schema"] != "kilix.content.reproducible-build-toolchain/v1":
        fail("unexpected build-toolchain schema")
    if str(toolchain["source_date_epoch"]) != SOURCE_DATE_EPOCH:
        fail("SOURCE_DATE_EPOCH is not the frozen value")
    environment = toolchain["environment"]
    assignments = environment["assignments"]
    if set(environment["allowlist"]) != set(assignments):
        fail("build environment allowlist and assignments differ")
    env = {str(key): str(value) for key, value in assignments.items()}
    actual_tools = {name: importlib.metadata.version(name) for name in EXPECTED_TOOLS}
    if actual_tools != EXPECTED_TOOLS or toolchain["tools"] != EXPECTED_TOOLS:
        fail(f"unexpected build toolchain: {actual_tools!r}")
    python = toolchain["python"]
    actual_version = ".".join(str(part) for part in sys.version_info[:3])
    base = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if actual_version != python["version"] or str(base) != python["executable"]:
        fail("running Python does not match build-toolchain.json")
    if digest(base) != python["sha256"]:
        fail("running Python executable digest does not match build-toolchain.json")
    uv = toolchain["uv"]
    uv_path = Path(uv["executable"])
    if not uv_path.is_file() or digest(uv_path) != uv["sha256"]:
        fail("uv executable digest does not match build-toolchain.json")
    version = subprocess.run([str(uv_path), "--version"], env=env, check=True, capture_output=True, text=True).stdout.split()
    if len(version) < 2 or version[1] != uv["version"]:
        fail("uv version does not match build-toolchain.json")
    return toolchain, env, uv_path


def run(argv: list[str], *, cwd: Path, env: dict[str, str], capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env=env, check=False, capture_output=capture, text=True)


def build(source: Path, output: Path, env: dict[str, str], *kinds: str) -> dict[str, Path]:
    output.mkdir(parents=True)
    result = run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output), *kinds, str(source)], cwd=PROJECT, env=env, capture=True)
    if result.returncode:
        fail(f"build failed:\n{result.stderr[-4000:]}")
    artifacts: dict[str, Path] = {}
    for kind, suffix in (("sdist", ".tar.gz"), ("wheel", ".whl")):
        if f"--{kind}" in kinds:
            matches = sorted(output.glob(f"*{suffix}"))
            if len(matches) != 1:
                fail(f"expected one {kind}, found {matches!r}")
            artifacts[kind] = matches[0]
    return artifacts


def safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    normalized = posixpath.normpath(name.rstrip("/"))
    if path.is_absolute() or ".." in path.parts or normalized != name.rstrip("/"):
        fail(f"unsafe archive member {name!r}")
    return normalized


def archive_safety(sdist: Path, wheel: Path) -> list[str]:
    wheel_names: list[str] = []
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            fail("wheel CRC check failed")
        normalized: set[str] = set()
        for info in archive.infolist():
            key = safe_member_name(info.filename)
            if key in normalized:
                fail(f"wheel has duplicate normalized member {key!r}")
            normalized.add(key)
            mode = (info.external_attr >> 16) & 0o7777
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or mode & 0o444 != 0o444:
                fail(f"wheel has unsafe member mode/type: {info.filename!r}")
            wheel_names.append(info.filename)
    with tarfile.open(sdist, "r:gz") as archive:
        normalized = set()
        for member in archive.getmembers():
            key = safe_member_name(member.name)
            if key in normalized:
                fail(f"sdist has duplicate normalized member {key!r}")
            normalized.add(key)
            if not (member.isdir() or member.isfile()):
                fail(f"sdist has a special/link member: {member.name!r}")
            if member.mode & 0o444 != 0o444:
                fail(f"sdist member is not readable: {member.name!r}")
    forbidden = ("tests/", "fixtures/", "test_", "golden", "fixture", "synthetic", "receipt_storage", "receipt_store", "run_receipt")
    if any(any(token in name.lower() for token in forbidden) or name.endswith("SHA256SUMS") for name in wheel_names):
        fail("wheel contains test or fixture authority")
    return wheel_names


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
            expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            if encoded != expected or size != str(len(data)):
                fail(f"wheel RECORD digest/size mismatch for {path!r}")


def extract_sdist(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
        if not members:
            fail("sdist is empty")
        top_parts = Path(members[0].name).parts
        top = top_parts[0] if top_parts else ""
        if not top or top in {".", ".."}:
            fail("sdist has no safe top-level directory")
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or Path(member.name).parts[0] != top:
                fail("sdist contains an unsafe member")
        for member in members:
            handle.extract(member, destination)
    root = destination / top
    if not (root / "pyproject.toml").is_file() or not (root / "uv.lock").is_file():
        fail("sdist lacks project lock/input files")
    return root


def resource_map(root: Path) -> dict[str, str]:
    manifest = json.loads((root / "contracts" / "kilix.content.u1-resources-v1.json").read_text())
    return {entry["name"]: entry["sha256"] for entry in manifest["resources"]}


def tree_resource(root: Path, name: str) -> bytes:
    return (root / "src/kilix_content/licenses" / name if name == "MIT.txt" else root / "contracts" / name).read_bytes()


def wheel_resource(archive: zipfile.ZipFile, name: str) -> bytes:
    path = f"kilix_content/licenses/{name}" if name == "MIT.txt" else f"kilix_content/contracts/{name}"
    return archive.read(path)


def resource_audit(source_root: Path, sdist_root: Path, direct_wheel: Path, sdist_wheel: Path) -> dict[str, str]:
    expected = resource_map(source_root)
    if resource_map(sdist_root) != expected:
        fail("sdist production manifest differs from source")
    with zipfile.ZipFile(direct_wheel) as direct, zipfile.ZipFile(sdist_wheel) as rebuilt:
        for name, expected_digest in expected.items():
            values = [
                hashlib.sha256(tree_resource(source_root, name)).hexdigest(),
                hashlib.sha256(tree_resource(sdist_root, name)).hexdigest(),
                hashlib.sha256(wheel_resource(direct, name)).hexdigest(),
                hashlib.sha256(wheel_resource(rebuilt, name)).hexdigest(),
            ]
            if values != [expected_digest] * len(values):
                fail(f"production resource mismatch for {name!r}")
    return expected


def installed_wheel_audit(wheel: Path, expected: dict[str, str], uv_path: Path, env: dict[str, str], temporary: Path) -> None:
    venv = temporary / "installed-venv"
    external = temporary / "external-cwd"
    external.mkdir()
    result = run([sys.executable, "-m", "venv", "--without-pip", str(venv)], cwd=PROJECT, env=env, capture=True)
    if result.returncode:
        fail(f"venv creation failed:\n{result.stderr}")
    python = venv / "bin/python"
    result = run([str(uv_path), "pip", "install", "--no-index", "--no-deps", "--python", str(python), str(wheel)], cwd=external, env=env, capture=True)
    if result.returncode:
        fail(f"offline wheel install failed:\n{result.stderr}")
    probe = """
import hashlib, importlib.resources as resources, json, pathlib, sys
from kilix_content import verify_packaged_u1_manifest
expected = json.loads(sys.argv[1])
project, source, cwd = sys.argv[2:]
verify_packaged_u1_manifest()
root = resources.files("kilix_content")
for name, expected_digest in expected.items():
    path = root.joinpath("licenses", name) if name == "MIT.txt" else root.joinpath("contracts", name)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_digest
assert project not in sys.path and source not in sys.path and cwd not in sys.path
assert not str(pathlib.Path(__import__("kilix_content").__file__).resolve()).startswith(source)
print("installed external wheel resources: PASS")
"""
    result = run([str(python), "-I", "-c", probe, json.dumps(expected, sort_keys=True), str(PROJECT), str(PROJECT / "src"), str(external)], cwd=external, env=env, capture=True)
    if result.returncode:
        fail(f"external installed-wheel probe failed:\n{result.stderr}")
    print(result.stdout.strip())


def sdist_tests(source_root: Path, uv_path: Path, env: dict[str, str]) -> None:
    result = run([str(uv_path), "run", "--project", str(source_root), "--locked", "--offline", "--group", "test", "python", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], cwd=source_root, env=env)
    if result.returncode:
        fail("exact-sdist locked test suite failed")


def empty_cache_gate(archive: Path, uv_path: Path, env: dict[str, str], temporary: Path) -> None:
    source_root = extract_sdist(archive, temporary / "empty-source")
    empty_cache = temporary / "empty-cache"
    empty_cache.mkdir()
    empty_env = dict(env)
    empty_env["UV_CACHE_DIR"] = str(empty_cache)
    result = run([str(uv_path), "run", "--project", str(source_root), "--locked", "--offline", "--group", "test", "python", "-c", "print('unexpected empty-cache success')"], cwd=source_root, env=empty_env, capture=True)
    if result.returncode == 0:
        fail("empty-cache offline gate unexpectedly succeeded")
    failure = result.stdout + result.stderr
    if "Network connectivity is disabled" not in failure and "not found in the cache" not in failure:
        fail("empty-cache gate failed for an unrecognized reason")
    print("empty-cache offline gate: EXPECTED FAILURE (no reviewed wheelhouse)")


def main() -> int:
    _, environment, uv_path = checked_toolchain()
    with tempfile.TemporaryDirectory(prefix="kilix-u1-repro-") as temporary_name:
        temporary = Path(temporary_name)
        direct_one = build(PROJECT, temporary / "direct-one", environment, "--sdist", "--wheel")
        direct_two = build(PROJECT, temporary / "direct-two", environment, "--sdist", "--wheel")
        empty_cache_gate(direct_one["sdist"], uv_path, environment, temporary)
        source_root = extract_sdist(direct_one["sdist"], temporary / "extracted")
        sdist_tests(source_root, uv_path, environment)
        rebuilt = build(source_root, temporary / "from-sdist", environment, "--wheel")
        archive_safety(direct_one["sdist"], direct_one["wheel"])
        archive_safety(direct_two["sdist"], direct_two["wheel"])
        archive_safety(direct_one["sdist"], rebuilt["wheel"])
        record_audit(direct_one["wheel"])
        record_audit(rebuilt["wheel"])
        expected = resource_audit(PROJECT, source_root, direct_one["wheel"], rebuilt["wheel"])
        installed_wheel_audit(direct_one["wheel"], expected, uv_path, environment, temporary)
        checks = {
            "direct sdist 1 == direct sdist 2": digest(direct_one["sdist"]) == digest(direct_two["sdist"]),
            "direct wheel 1 == direct wheel 2": digest(direct_one["wheel"]) == digest(direct_two["wheel"]),
            "direct wheel 1 == exact-sdist wheel": digest(direct_one["wheel"]) == digest(rebuilt["wheel"]),
        }
        if not all(checks.values()):
            fail(f"reproducibility failure: {checks!r}")
        print(f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}")
        for label, artifact in (("direct-sdist", direct_one["sdist"]), ("direct-wheel", direct_one["wheel"]), ("sdist-derived-wheel", rebuilt["wheel"])):
            print(f"{label}={digest(artifact)}")
        print("reproducible build and package audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
