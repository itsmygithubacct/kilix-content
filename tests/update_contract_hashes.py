from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"
PATHS = sorted((ROOT / "contracts").glob("*.schema.json")) + sorted(
    FIXTURES.glob("*/*.json")
)

manifest = "".join(
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
    f"{path.relative_to(ROOT).as_posix()}\n"
    for path in PATHS
)
(FIXTURES / "SHA256SUMS").write_text(manifest, encoding="ascii")
