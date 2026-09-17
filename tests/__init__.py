"""Isolate this suite from the invoking user's live Kilix store and network."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SUPPORT = Path(__file__).resolve().parent / "support"
_LICENSE_SRC = _ROOT / "third_party" / "kilix-license" / "src"
for _path in (_SUPPORT, _ROOT / "src", _LICENSE_SRC):
    text = str(_path)
    if text not in sys.path:
        sys.path.insert(0, text)

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

os.environ.setdefault("https_proxy", "http://127.0.0.1:9")
os.environ.setdefault("HTTPS_PROXY", "http://127.0.0.1:9")
os.environ.setdefault("no_proxy", "localhost,127.0.0.1,::1")
os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1,::1")

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def _audit(event: str, args: tuple[object, ...]) -> None:
    if event == "socket.connect" and len(args) >= 2:
        address = args[1]
        if isinstance(address, tuple) and address:
            host = address[0]
            if isinstance(host, str) and host not in _LOOPBACK:
                raise OSError(f"non-loopback connect refused: {host}")
    if event == "socket.getaddrinfo" and args:
        host = args[0]
        if isinstance(host, str) and host not in _LOOPBACK:
            raise OSError(f"non-loopback DNS refused: {host}")


sys.addaudithook(_audit)

try:
    from live_store_guard import install as _install_live_store_guard
except ImportError:
    pass
else:
    _install_live_store_guard()
