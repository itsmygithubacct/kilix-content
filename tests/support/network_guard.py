"""Refuse non-loopback name lookups and connections in this process (R4-048).

Installed by tests/__init__.py and by sitecustomize.py, which Python loads in
every process that has tests/support on PYTHONPATH (make test exports it). So
the refusal holds under any discovery mode, in any test order, and in Python
children that inherit PYTHONPATH. It never depends on a proxy variable or a
leaked certificate path.

KILIX_CONTENT_NETWORK_AUDIT_LOG, when set, receives one line per socket
lookup or connect event this hook sees: allowed (loopback) or refused.
"""

from __future__ import annotations

import os
import sys

LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
AUDIT_LOG_ENV = "KILIX_CONTENT_NETWORK_AUDIT_LOG"

# CPython audit event -> (index of the host or address argument, whether that
# argument is an address tuple). gethostbyname_ex raises socket.gethostbyname.
_EVENTS = {
    "socket.getaddrinfo": (0, False),
    "socket.gethostbyname": (0, False),
    "socket.gethostbyaddr": (0, False),
    "socket.getnameinfo": (0, True),
    "socket.connect": (1, True),
    "socket.sendto": (1, True),
    "socket.sendmsg": (1, True),
}
_REFUSAL = {
    "socket.getaddrinfo": "DNS",
    "socket.gethostbyname": "DNS",
    "socket.gethostbyaddr": "DNS",
    "socket.getnameinfo": "DNS",
    "socket.connect": "connect",
    "socket.sendto": "send",
    "socket.sendmsg": "send",
}

_installed = False


def _host(value: object) -> str | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("ascii", "backslashreplace")
    if isinstance(value, str):
        return value
    return None


def _log(line: str) -> None:
    path = os.environ.get(AUDIT_LOG_ENV)
    if not path:
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, (line + "\n").encode("utf-8", "backslashreplace"))
    finally:
        os.close(descriptor)


def _audit(event: str, args: tuple[object, ...]) -> None:
    spec = _EVENTS.get(event)
    if spec is None:
        return
    index, is_address = spec
    if len(args) <= index:
        return
    target = args[index]
    if is_address:
        # AF_UNIX paths and unconnected sendmsg (None) are not network hosts.
        if not isinstance(target, tuple) or not target:
            return
        host = _host(target[0])
    else:
        host = _host(target)
    if host is None:
        return
    if host in LOOPBACK:
        _log(f"pid={os.getpid()} allowed {event} {target!r}")
        return
    _log(f"pid={os.getpid()} refused {event} {target!r}")
    raise OSError(f"non-loopback {_REFUSAL[event]} refused: {host}")


def installed() -> bool:
    return _installed


def install() -> None:
    global _installed
    if _installed:
        return
    sys.addaudithook(_audit)
    _installed = True
