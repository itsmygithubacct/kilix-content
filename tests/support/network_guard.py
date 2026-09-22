"""Refuse non-loopback name lookups and connections in this process (R4-048).

**What this hook observes, exactly.** It is a CPython audit hook. It sees the
seven socket audit events listed in `COVERED_EVENTS` and **nothing else**, in
**this interpreter only**. An empty audit log therefore means "none of those
seven events happened here". It does **not** mean "no socket activity": the
routes in `NOT_COVERED` leave the interpreter without raising any of them, and
three of them were measured making real, completed TCP connections to a
listener in this same process while this log stayed empty
(`tests/test_network_guard_coverage.py` runs that battery on every suite run,
so the boundary is measured rather than assumed).

**The namespace is the real control, not this hook.** What makes a zero
meaningful is running inside `unshare -cn` with `lo` DOWN and an empty route
table: there is then no interface and no route for *any* route out, hooked or
not. This hook is corroboration -- it says which name lookups and connections
Python itself attempted, and it refuses the non-loopback ones -- and it is not
proof of the absence of network activity. Do not report an empty log as one.

Installed by tests/__init__.py and by sitecustomize.py, which Python loads in
every process that has tests/support on PYTHONPATH. sitecustomize installs
*this* guard first and unconditionally, before anything that imports a
third-party module, because an import failure there would otherwise kill
sitecustomize with a one-line warning and leave the hook uninstalled while the
process looked guarded. So the refusal holds under any discovery mode, in any
test order, and in a Python child that inherits PYTHONPATH -- but only in the
Python parts of that child: an `exec` of a non-Python program, and anything the
child does through the routes in `NOT_COVERED`, are outside it either way. It
never depends on a proxy variable or a leaked certificate path.

KILIX_CONTENT_NETWORK_AUDIT_LOG, when set, receives one line per socket
lookup or connect event this hook sees: allowed (loopback) or refused. Every
line, and every refusal this hook raises, carries `COVERAGE` so that a line
lifted into a report carries its own scope with it.
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

#: The events this hook sees. Everything else is invisible to it.
COVERED_EVENTS = tuple(sorted(_EVENTS))

#: Routes out of this interpreter that raise none of COVERED_EVENTS. Each name
#: is exercised in tests/test_network_guard_coverage.py, which measures whether
#: it is logged and whether it reaches a listener.
NOT_COVERED = (
    "ctypes/FFI (libc connect called directly)",
    "child processes (subprocess, os.exec*, os.posix_spawn)",
    "shell redirections (bash /dev/tcp)",
    "AF_UNIX sockets (deliberate: not a network host)",
    "NSS lookups outside Python (getent, nscd)",
    "anything issuing the syscall without going through the socket module",
)

#: One line, carried by every log line and every refusal this hook raises.
COVERAGE = (
    "scope=7-cpython-socket-audit-events-in-this-interpreter; "
    "not-covered=ctypes/FFI,child-processes,bash-/dev/tcp,AF_UNIX,getent,"
    "raw-syscalls; a zero here is not proof of no network -- the namespace is"
)

_installed = False


def coverage_note() -> str:
    """The instrument's scope in full, for a report that quotes the log."""
    covered = "\n".join(f"  - {name}" for name in COVERED_EVENTS)
    escapes = "\n".join(f"  - {name}" for name in NOT_COVERED)
    return (
        "network_guard observes these CPython audit events, in this "
        "interpreter only:\n"
        f"{covered}\n"
        "It does NOT observe:\n"
        f"{escapes}\n"
        "An empty audit log is evidence about the events above and about "
        "nothing else.\n"
        "What excludes the rest is the namespace: `unshare -cn` with `lo` "
        "DOWN and an empty\nroute table. This hook corroborates that; it does "
        "not prove it."
    )


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
        _log(f"pid={os.getpid()} allowed {event} {target!r} | {COVERAGE}")
        return
    _log(f"pid={os.getpid()} refused {event} {target!r} | {COVERAGE}")
    raise OSError(f"non-loopback {_REFUSAL[event]} refused: {host} [{COVERAGE}]")


def installed() -> bool:
    return _installed


def install() -> None:
    global _installed
    if _installed:
        return
    sys.addaudithook(_audit)
    _installed = True
