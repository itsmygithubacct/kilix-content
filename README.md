# kilix-content

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
atomically selected. Readiness checks bind the default managed directory and
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

## Catalog contract

The packaged `plebian.json` catalog uses schema version 3. Schema version 2
added a top-level `packages` array. Each package owns an installable Git/archive
source, build argv, and dependency hint. A content entry may reference it by
`package` and owns its own ID, executable path, label, capabilities, launch
mode, and geometry. Package references cannot override source/build fields;
unknown, duplicate, unused, non-installable, or conflicting package identities
are rejected. Schema version 1 and direct `ContentSpec` construction remain
compatible. Schema version 3 adds `command`, `actions`, `accepts`, and
`lifecycle`; older schemas reject those fields instead of silently dropping
host policy.

Installable Git entries and packages require an immutable commit, relative
executable path, and optional build argv. Make-based entries always name their
intended target explicitly so an included dependency fragment cannot silently
become the build's default target. Most use `all`; Kilix PDF Conversion uses
its pinned `runtime` target. Capabilities are
declarative labels for the host; they are not commands or package names. Launch
modes are `terminal`, `run`, `xpane`, `browse`, `window`, or `custom`.
Lifecycle metadata covers single-instance intent, Kilix-session requirements,
in-place degradation, failure preservation, and bounded startup timeouts.

Catalog parsing rejects duplicate or unknown fields, unknown source/launch
modes, duplicate or unsafe IDs, mismatched package metadata, wrong scalar
types, mutable Git refs, malformed digests, absolute executable paths, and
parent-path escapes before any installation begins. JSON input is limited to
1 MiB and to 4,096 package/content records apiece. The packaged catalog is
immutable and cached after its first validated load.

## Test

```sh
make test
make benchmark
```

Tests use local Git repositories and in-memory archives. They cover catalog
validation, shared-package installation/readiness, fragmented installation
failures, recursive dependency checkout, dirty/wrong-origin refusal, atomic
replacement, traversal and symlink rejection, checksum enforcement, bounded
child diagnostics, and executable readiness. The benchmark records cached and
cold catalog cost, indexed lookup, managed Git verification/readiness, and a
verified 32 MiB download.

## Scope

The package does not resolve system packages, elevate privileges, define game
logic, choose UI policy, or update Pleb/Kilix themselves. Those responsibilities
remain with Plebian-OS, the desktop provider, and each application.

## License

MIT. See [LICENSE](LICENSE).
