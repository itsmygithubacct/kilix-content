"""Store roots for first-use assets. Never the NSS-home live store."""

from __future__ import annotations

import os
from pathlib import Path
import sys


def license_src() -> Path:
    """Vendored kilix-license src from the LIC2 git archive pin."""
    here = Path(__file__).resolve()
    root = here.parents[2]
    return root / "third_party" / "kilix-license" / "src"


def ensure_license_importable() -> None:
    src = str(license_src())
    if src not in sys.path:
        sys.path.insert(0, src)


ensure_license_importable()

from kilix_license.errors import LiveStoreForbidden
from kilix_license.paths import refuse_live_store


def asset_store_root() -> Path:
    """Require an explicit XDG_STATE_HOME; refuse NSS-home fallback (R4-048)."""
    state = os.environ.get("XDG_STATE_HOME")
    if not state or not os.path.isabs(state):
        raise LiveStoreForbidden(
            "XDG_STATE_HOME must be set to an absolute path; NSS home is refused"
        )
    root = Path(state) / "kilix-content"
    refuse_live_store(root)
    return root


def require_isolated_env(temp_root: str | os.PathLike[str]) -> None:
    """Refuse to start a first-use fixture unless store env vars sit under temp_root."""
    root = os.path.realpath(os.path.abspath(os.fspath(temp_root)))
    required = (
        "XDG_STATE_HOME",
        "KILIX_DATA_HOME",
        "KILIX_STORAGE_HOME",
        "GPU_TERMINAL_HOME",
    )
    for key in required:
        value = os.environ.get(key)
        if not value or not os.path.isabs(value):
            raise LiveStoreForbidden(f"{key} must be an absolute path under the test root")
        real = os.path.realpath(value)
        if real != root and not real.startswith(root + os.sep):
            raise LiveStoreForbidden(f"{key} must be under the test root")
    refuse_live_store(root)
