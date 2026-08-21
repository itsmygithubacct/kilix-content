"""Render the exact, platform-scoped offline wheelhouse manifest."""

from __future__ import annotations

import email.parser
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WHEELHOUSE = ROOT / "wheelhouse"
MANIFEST = WHEELHOUSE / "manifest.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def wheel_identity(path: Path) -> tuple[str, str, list[str]]:
    with zipfile.ZipFile(path) as archive:
        metadata_names = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/METADATA") and name.count("/") == 1
        ]
        wheel_names = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/WHEEL") and name.count("/") == 1
        ]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise SystemExit(f"wheel metadata inventory is ambiguous: {path.name}")
        metadata = email.parser.BytesParser().parsebytes(
            archive.read(metadata_names[0]), headersonly=True
        )
        wheel = email.parser.BytesParser().parsebytes(
            archive.read(wheel_names[0]), headersonly=True
        )
    name = metadata.get("Name")
    version = metadata.get("Version")
    tags = sorted(wheel.get_all("Tag", []))
    if not name or not version or not tags:
        raise SystemExit(f"wheel identity is incomplete: {path.name}")
    return name, version, tags


def build_manifest() -> dict[str, Any]:
    wheels = []
    for path in sorted(WHEELHOUSE.glob("*.whl"), key=lambda item: item.name):
        name, version, tags = wheel_identity(path)
        wheels.append(
            {
                "filename": path.name,
                "name": name,
                "version": version,
                "tags": tags,
                "size": path.stat().st_size,
                "sha256": digest(path),
            }
        )
    if not wheels:
        raise SystemExit("wheelhouse is empty")
    return {
        "schema": "kilix.content.offline-wheelhouse/v1",
        "python_version": "3.12.8",
        "platform": "linux-x86_64-glibc",
        "pyproject_sha256": digest(ROOT / "pyproject.toml"),
        "uv_lock_sha256": digest(ROOT / "uv.lock"),
        "requirements_sha256": digest(WHEELHOUSE / "requirements.txt"),
        "wheels": wheels,
    }


def main() -> int:
    payload = canonical(build_manifest())
    MANIFEST.write_bytes(payload)
    print(f"wheels={len(json.loads(payload)['wheels'])}")
    print(f"manifest_sha256={hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
