# kilix-content

`kilix-content` is the unprivileged content catalog and installer shared by
Kilix-hosted desktops. It gives games and applications one declarative record
for identity, immutable source, build command, capabilities, launch mode, and
preferred geometry.

The installer accepts only argument arrays; it never invokes a shell. Managed
Git content is fetched at an exact 40-character commit into a private staging
directory, checked out detached, initialized recursively, built, verified, and
atomically selected. Readiness checks bind the executable to the expected
origin, commit, clean tracked state, and initialized submodules. Archive helpers
require an exact SHA-256 and reject absolute paths, traversal, and links.

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

Kilix Lander and Kilix Brokeout retain the catalog IDs `terminal-lander` and
`kitty-brokeout`, respectively, so existing installations and preferences do
not need migration.

Applications with specialized licensed payloads can use a `custom` catalog
entry while reusing `download()`, `safe_extract_tar()`, and
`safe_extract_zip()` for their bounded setup procedure.

## Catalog contract

The packaged `plebian.json` catalog uses schema version 1. Installable Git
entries require an immutable commit, relative executable path, and optional
build argv. Make-based entries name `all` explicitly so an included dependency
fragment cannot silently become the build's default target. Capabilities are
declarative labels for the host; they are not commands or package names. Launch
modes are `terminal`, `run`, `xpane`, `browse`, `window`, or `custom`.

Catalog parsing rejects unknown source/launch modes, duplicate or unsafe IDs,
mutable Git refs, malformed digests, absolute executable paths, and parent-path
escapes before any installation begins.

## Test

```sh
python3 -m unittest discover -s tests -v
```

Tests use local Git repositories and in-memory archives. They cover catalog
validation, fragmented installation failures, recursive dependency checkout,
dirty/wrong-origin refusal, atomic replacement, traversal and symlink rejection,
checksum enforcement, and executable readiness.

## Scope

The package does not resolve system packages, elevate privileges, define game
logic, choose UI policy, or update Pleb/Kilix themselves. Those responsibilities
remain with Plebian-OS, the desktop provider, and each application.

## License

MIT. See [LICENSE](LICENSE).
