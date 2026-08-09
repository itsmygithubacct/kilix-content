"""Maintained catalog, checkout, and download microbenchmark."""

from __future__ import annotations

import hashlib
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPOSITORY = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else Path(__file__).resolve().parents[1]
)
if len(sys.argv) > 2:
    raise SystemExit("usage: benchmark_content.py [SOURCE_ROOT]")
sys.path.insert(0, str(REPOSITORY / "src"))

from kilix_content import (
    Catalog,
    ContentSpec,
    Installer,
    default_catalog,
    download,
    verify_git_checkout,
)


def median_ns(operation, iterations: int, rounds: int = 7) -> float:
    samples = []
    for _ in range(rounds):
        started = time.perf_counter_ns()
        for _iteration in range(iterations):
            operation()
        samples.append((time.perf_counter_ns() - started) / iterations)
    return statistics.median(samples)


catalog_path = REPOSITORY / "src/kilix_content/catalog/plebian.json"
catalog = default_catalog()
lookup_checksum = 0


def lookup() -> None:
    global lookup_checksum
    lookup_checksum += len(catalog.require("terminal-lander").ref)


with tempfile.TemporaryDirectory(prefix="kilix-content-bench-") as temporary:
    root = Path(temporary)
    repository = root / "fixture"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Fixture"], cwd=repository, check=True
    )
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=repository,
        check=True,
    )
    executable = repository / "fixture"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    subprocess.run(["git", "add", "fixture"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "--quiet", "-m", "fixture"], cwd=repository, check=True
    )
    subprocess.run(
        ["git", "remote", "add", "origin", "fixture-origin"], cwd=repository, check=True
    )
    ref = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    subprocess.run(
        ["git", "checkout", "--quiet", "--detach"], cwd=repository, check=True
    )

    spec = ContentSpec.from_mapping(
        {
            "id": "fixture",
            "label": "Fixture",
            "source": {"type": "git", "repository": "fixture-origin", "ref": ref},
            "binary": "fixture",
        }
    )
    installer = Installer(str(root))

    payload = root / "payload"
    block = bytes(range(256)) * 256
    digest = hashlib.sha256()
    with payload.open("wb") as stream:
        for _ in range(512):
            stream.write(block)
            digest.update(block)
    payload_digest = digest.hexdigest()
    downloaded = root / "downloaded"

    def parse_catalog() -> None:
        Catalog.load(catalog_path)

    def verify() -> None:
        verify_git_checkout("fixture-origin", ref, str(repository))

    def ready() -> None:
        if installer.ready(spec) is None:
            raise RuntimeError("fixture unexpectedly not ready")

    def fetch() -> None:
        download(payload.as_uri(), str(downloaded), expected_sha256=payload_digest)

    print(f"default_catalog_ns={median_ns(default_catalog, 2000):.3f}")
    print(f"catalog_parse_ns={median_ns(parse_catalog, 1000):.3f}")
    print(f"catalog_require_ns={median_ns(lookup, 200000):.3f}")
    print(f"verify_git_ns={median_ns(verify, 20):.3f}")
    print(f"ready_git_ns={median_ns(ready, 20):.3f}")
    print(f"download_32m_ns={median_ns(fetch, 3, rounds=5):.3f}")
    print(f"checksum={lookup_checksum}:{payload_digest}:{os.path.getsize(downloaded)}")
