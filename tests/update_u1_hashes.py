"""Verify the deterministic U1 fixture index and corpus hash manifest."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "u1"
MANIFEST = FIXTURES / "SHA256SUMS"


def expected_manifest() -> str:
    paths = sorted(
        [FIXTURES / "index.json", *(FIXTURES / "corpus").rglob("*.json")],
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    return "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
        f"{path.relative_to(ROOT).as_posix()}\n"
        for path in paths
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest = expected_manifest()
    if args.check:
        if MANIFEST.read_text(encoding="ascii") != manifest:
            print("U1 fixture hash manifest is stale", file=sys.stderr)
            return 1
        return 0
    MANIFEST.write_text(manifest, encoding="ascii", newline="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
