"""Loaded when tests/support is on PYTHONPATH: refuse the network and the live store.

**The order below is load-bearing, and it used to be the other way round.**
`live_store_guard` imports `kilix_license`, which is on PYTHONPATH only under
`make test`. With just `tests/support` on the path that import fails, and a
failing import at the top of sitecustomize kills the whole module: Python
prints one line (`Error in sitecustomize; set PYTHONVERBOSE for traceback`)
that nothing reads, and the *network* guard is never installed either -- a
guard that fails open, silently, in a process that looks guarded.

So `network_guard` is installed first and unconditionally. It imports nothing
outside the standard library, so no unrelated import failure can disable it.
`live_store_guard` is then installed inside a `try`, and a failure is reported
loudly, naming exactly which guard is missing, rather than left to a one-line
warning.
"""

import sys

from network_guard import install as install_network_guard

install_network_guard()

try:
    from live_store_guard import install as install_live_store_guard
except BaseException as error:  # pragma: no cover - only without kilix_license
    sys.stderr.write(
        "sitecustomize: LIVE STORE GUARD NOT INSTALLED -- "
        f"{type(error).__name__}: {error}\n"
        "sitecustomize: the network guard IS installed; writes to the live\n"
        "sitecustomize: receipt store are NOT refused in this process.\n"
        "sitecustomize: put src and third_party/kilix-license/src on "
        "PYTHONPATH (make test does).\n"
    )
else:
    install_live_store_guard()
