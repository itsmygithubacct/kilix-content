# Installer and Python API

The installer half of kilix-content: how it fetches, builds, verifies and
selects catalog content, and the Python calls consumers make. This text was
the opening of the README before the README became a short entry point.

## Overview

`kilix-content` is the unprivileged content catalog and installer shared by
Kilix-hosted desktops. It gives games and applications one declarative record
for identity, immutable source, build command, capabilities, launch mode, and
preferred geometry. Schema version 2 can separate an immutable package from
the applications it provides, so one checkout and build can expose several
catalog IDs without duplicating source or installation state. Schema version 3
adds argv-only named actions, accepted input types, host command vectors, and
lifecycle/fallback policy.

The installer accepts only argument arrays; it never invokes a shell. Managed
Git content is fetched at an exact 40-character commit into a private staging
directory, checked out detached, initialized recursively, built, verified, and
atomically selected. Every fetch and build command is bounded by the
installer's `command_timeout` (an hour by default), so a stalled network peer
or wedged build fails with a diagnostic instead of blocking forever; pass
`command_timeout=None` to wait without bound. Concurrent installations of one
package are serialized through a transient lock file below the content root,
so simultaneous launchers share a single fetch and build: the waiter adopts
the winner's selected result instead of repeating it. Readiness checks bind the default managed directory and
any configured Git checkout to the expected origin, commit, detached state,
clean tracked state, and initialized submodules. An explicitly different plain
directory remains a trusted user-managed executable override. Archive helpers
require an exact SHA-256, reject absolute paths, traversal, links, and special
files, and default to at most 100,000 members and 8 GiB of expanded regular-file
data.

This is deliberately a user-level component. Plebian-OS may pin the catalog and
install declared operating-system capabilities, but privileged provisioning
must not execute catalog build commands. Kilix performs content builds as the
desktop user below its application data directory.

## Use

```python
from kilix_content import Installer, default_catalog

catalog = default_catalog()
game = catalog.require("terminal-lander")
installer = Installer("/absolute/user/data/games")

executable = installer.ready(game) or installer.ensure(game, print)
```

Package-provided applications use the same API. Given a schema-version-2
catalog named `shared_catalog`, each flattened `ContentSpec` carries the
package source/build metadata for compatibility, while `install_id` selects
the shared directory:

```python
files = shared_catalog.require("kilix-file")
system = shared_catalog.require("kilix-system-center")

assert files.install_id == system.install_id == "kilix-tui-utils"
assert shared_catalog.provided_by("kilix-tui-utils") == (files, system)

files_executable = installer.ensure(files, print)
system_executable = installer.ready(system)

# One package verification, one independent executable result per app.
readiness = installer.ready_provided(
    shared_catalog.provided_by("kilix-tui-utils")
)
```

Schema-version-3 application metadata stays data all the way to the host:

```python
files = default_catalog().require("kilix-file")
open_action = files.require_action("open")

assert open_action.argv == ("--open",)
assert open_action.accepts_input
assert "application/pdf" in files.accepts
assert files.lifecycle.degrades_inplace
```

`command` is an argv vector for a system-owned application such as
`["kilix", "bonsai"]`; it is mutually exclusive with a package-relative
`binary`. Actions add only trusted fixed argv and declare separately whether
one caller-supplied input may be appended. They are never shell strings.

Kilix Lander and Kilix Brokeout retain the catalog IDs `terminal-lander` and
`kitty-brokeout`, respectively, so existing installations and preferences do
not need migration.

Applications with specialized licensed payloads can use a `custom` catalog
entry while reusing `download()`, `safe_extract_tar()`, and
`safe_extract_zip()` for their bounded setup procedure.

`download()` writes a private sibling of its destination, computes SHA-256 as
bytes arrive, and uses one atomic replacement only after validation succeeds.
A failed mirror therefore leaves any existing destination intact, and a
destination symlink is replaced rather than followed.
