"""Isolate this suite from the invoking user's live Kilix store and network."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
_ROOT = _TESTS.parent
_SUPPORT = _TESTS / "support"
_LICENSE_SRC = _ROOT / "third_party" / "kilix-license" / "src"
# make test discovers with -t . so this package runs first; test modules then
# import their fixtures (first_use_fixture, fake_store) as top-level modules.
for _path in (_TESTS, _SUPPORT, _ROOT / "src", _LICENSE_SRC):
    text = str(_path)
    if text not in sys.path:
        sys.path.insert(0, text)

from network_guard import install as _install_network_guard  # noqa: E402

_install_network_guard()

_SCRATCH = Path(tempfile.mkdtemp(prefix="kilix-content-suite-"))
for _key, _name in (
    ("XDG_CACHE_HOME", "xdg-cache"),
    ("XDG_CONFIG_HOME", "xdg-config"),
    ("XDG_DATA_HOME", "xdg-data"),
    ("XDG_STATE_HOME", "xdg-state"),
    ("XDG_RUNTIME_DIR", "xdg-runtime"),
    ("KILIX_DATA_HOME", "kilix-data"),
    ("KILIX_STORAGE_HOME", "kilix-storage"),
    ("KILIX_HOME", "kilix-home"),
    ("GPU_TERMINAL_HOME", "gpu-terminal"),
    ("CANDIDATE_SCRATCH_ROOT", "candidate"),
):
    _path = _SCRATCH / _name
    _path.mkdir(parents=True, exist_ok=True)
    os.environ[_key] = str(_path)

# Forced, not defaulted: a caller's proxy on loopback would pass the audit hook
# (loopback is allowed) and then reach the network on the suite's behalf.
DEAD_PROXY = "http://127.0.0.1:9"
LOOPBACK_NO_PROXY = "localhost,127.0.0.1,::1"
for _key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
    os.environ[_key] = DEAD_PROXY
for _key in ("no_proxy", "NO_PROXY"):
    os.environ[_key] = LOOPBACK_NO_PROXY
for _key in ("all_proxy", "ALL_PROXY"):
    os.environ.pop(_key, None)

try:
    from live_store_guard import install as _install_live_store_guard
except ImportError:
    pass
else:
    _install_live_store_guard()
