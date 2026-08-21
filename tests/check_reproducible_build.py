"""Prove the pinned offline U1 source/wheel build is reproducible."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SOURCE_DATE_EPOCH = "1776729600"
EXPECTED_TOOLS = {
    "build": "1.3.0",
    "setuptools": "77.0.3",
    "wheel": "0.45.1",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_toolchain() -> None:
    actual = {
        name: importlib.metadata.version(name) for name in EXPECTED_TOOLS
    }
    if actual != EXPECTED_TOOLS:
        raise SystemExit(f"unexpected build toolchain: {actual!r}")


def build(source: Path, output: Path, *kinds: str) -> dict[str, Path]:
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(output),
            *kinds,
            str(source),
        ],
        cwd=PROJECT,
        env=environment,
        check=True,
    )
    artifacts = {}
    for kind, suffix in (("sdist", ".tar.gz"), ("wheel", ".whl")):
        if f"--{kind}" in kinds:
            matches = sorted(output.glob(f"*{suffix}"))
            if len(matches) != 1:
                raise SystemExit(f"expected one {kind}, found {matches!r}")
            artifacts[kind] = matches[0]
    return artifacts


def extract_sdist(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as handle:
        members = handle.getmembers()
        if not members:
            raise SystemExit("sdist is empty")
        top = Path(members[0].name).parts[0]
        if not top or top in {".", ".."}:
            raise SystemExit("sdist has no safe top-level directory")
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise SystemExit("sdist contains an unsafe path")
            if member.issym() or member.islnk() or Path(member.name).parts[0] != top:
                raise SystemExit("sdist contains an unsafe member")
        for member in members:
            handle.extract(member, destination)
    root = destination / top
    if not (root / "pyproject.toml").is_file():
        raise SystemExit("sdist root is not a project")
    return root


def main() -> int:
    checked_toolchain()
    with tempfile.TemporaryDirectory(prefix="kilix-u1-repro-") as temporary:
        root = Path(temporary)
        direct_one = build(PROJECT, root / "direct-one", "--sdist", "--wheel")
        direct_two = build(PROJECT, root / "direct-two", "--sdist", "--wheel")
        extracted = root / "extracted"
        source_root = extract_sdist(direct_one["sdist"], extracted)
        rebuilt = build(source_root, root / "from-sdist", "--wheel")
        checks = {
            "direct sdist 1 == direct sdist 2": (
                digest(direct_one["sdist"]) == digest(direct_two["sdist"])
            ),
            "direct wheel 1 == direct wheel 2": (
                digest(direct_one["wheel"]) == digest(direct_two["wheel"])
            ),
            "direct wheel 1 == exact-sdist wheel": (
                digest(direct_one["wheel"]) == digest(rebuilt["wheel"])
            ),
        }
        if not all(checks.values()):
            raise SystemExit(f"reproducibility failure: {checks!r}")
        print(f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}")
        for label, artifact in (
            ("direct-sdist", direct_one["sdist"]),
            ("direct-wheel", direct_one["wheel"]),
            ("sdist-derived-wheel", rebuilt["wheel"]),
        ):
            print(f"{label}={digest(artifact)}")
        print("reproducible build: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
