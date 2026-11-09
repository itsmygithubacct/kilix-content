# kilix-content

The pinned catalog of games, applications and model assets that Kilix can
install, and the unprivileged installer that fetches, builds, verifies and
selects them for the desktop user.

Ships in Plebian-OS 0.2.3 as a submodule of
[Kilix](https://github.com/itsmygithubacct/kilix#readme)
(`third_party/kilix-content`). Users reach it through `kilix install`,
`kilix app`, `kilix games play` and `kilix models`, and through every desktop's
application and game menus.

## What it does

- Holds one catalog, [`src/kilix_content/catalog/plebian.json`](src/kilix_content/catalog/plebian.json):
  at this commit 1 package, 55 content entries (37 applications, 16 games,
  2 tools) and 43 model assets. See [docs/catalog.md](docs/catalog.md) for the
  full list.
- Installs Git content at an exact 40-character commit, builds it with an
  argv-only command (never a shell), verifies the checkout and atomically
  selects the result below a user-owned directory.
- Shares one checkout and build between applications that one package
  provides: the `kilix-tui-utils` package (built with `make runtime`) provides
  16 of the applications.
- Installs model assets only after their licence screen has been shown and,
  where the licence requires it, an explicit agreement has been recorded as a
  receipt. Every file is checked against its recorded size and SHA-256.
- Verifies its own catalog bytes against a pinned digest before anything acts
  on them.
- Never elevates privileges or resolves system packages; Kilix runs catalog
  builds as the desktop user.

## Quick start

As a Kilix user, the catalog is reached through the `kilix` command:

```sh
kilix install                      # list everything installable, marked if installed
kilix install kilix-graphs         # install one catalog entry by ID
kilix install --update kilix-graphs
kilix games play terminal-lander   # install a game if needed, then start it
kilix models list                  # model assets and their licence identities
kilix models install <asset>       # show the licence screen, ask, then install
```

As a library (the package declares Python 3.10 or newer and no third-party
dependencies; it puts its vendored kilix-license on `sys.path` itself):

```python
from kilix_content import Installer, default_catalog

game = default_catalog().require("terminal-lander")
installer = Installer("/absolute/user/data/games")
executable = installer.ready(game) or installer.ensure(game, print)
```

To run the tests from a checkout:

```sh
make test      # unit tests with HOME, XDG_* and KILIX_* inside a scratch directory
make pins      # the catalog and schema digests match the generator
make benchmark
```

## Usage

| Command (in Kilix) | What it does |
|---|---|
| `kilix install [--json]` | One table of catalog applications, games and tools, coding agents, runtimes, soundbanks and drivers |
| `kilix install <id> [--yes]` | Install one entry with this installer |
| `kilix install --update <id>` | Update one entry to the pinned commit |
| `kilix app run\|window\|install\|ref <id>` | Install if needed and launch an application in place or in a window, install only, or print its pinned commit |
| `kilix games play <id> [--setup-only]` | Install if needed and start a game |
| `kilix models list\|show\|verify <asset>` | Inspect model assets and existing receipts without changing anything |
| `kilix models install <asset> [--from DIR]` | Licence screen, a yes/no agreement where the licence needs one, receipt, then download (or copy from `DIR`) |

| Python entry point | Use |
|---|---|
| `default_catalog()` | Parse the packaged catalog for metadata only (cached, not digest-checked) |
| `verified_packaged_catalog()` | Parse the packaged catalog from bytes checked against the pinned digest; use it before acting |
| `Installer(root).ready(spec)` / `.ensure(spec, report)` | Readiness check / install for one content entry |
| `Installer.ready_provided(specs)` | One package verification for every application it provides |
| `first_use.install_with_agreement(...)` | Screen, agreement, receipt, then install a model asset |
| `Installer.ensure_supplied_asset(...)` | Install a model asset from files already on disk, with no network |

## How it works

```
plebian.json ──verify digest──> Catalog ──require(id)──> ContentSpec / AssetSpec
                                                 │
       content (git/package) ────────────────────┤
         fetch exact commit -> detached checkout -> submodules -> build argv
         -> verify origin, commit, clean tree -> atomic select
                                                 │
       model asset ──────────────────────────────┘
         kilix-license: record -> screen -> yes/no -> receipt
         -> HTTPS fetch (or supplied dir, or offline archive cache)
         -> size + SHA-256 per file -> notices from the authority -> atomic select
```

Each content entry names its source (`git`, `archive`, `system` or `custom`)
or the shared `package` that provides it, an executable path relative to its
checkout or a host command vector, a launch mode and optional actions. Git
sources must be immutable commits. The
installer stages a fetch in a private directory, builds with the declared argv
under a timeout (an hour by default), checks that the checkout has the
expected origin, commit, detached state, clean tracked files and initialised
submodules, and only then swaps it into place. A lock serialises concurrent
installs of one package, and the waiter adopts the winner's result. Kilix
installs applications under `~/.local/gpu_terminal/kilix/data/desktop-apps/`
and games under `.../desktop-games/` (both follow `GPU_TERMINAL_HOME`,
`KILIX_STORAGE_HOME` and `KILIX_DATA_HOME`). Details:
[docs/installer.md](docs/installer.md).

Model assets are asset/v3 records with exact file lists, sizes and digests,
a source mode (`upstream-files`, `upstream-archive`, `upstream-convert` or
`registry-manifest`), the provider program and the licence records they cite.
Licence records, the first-use screen, agreement capture and receipts belong
to [kilix-license](https://github.com/itsmygithubacct/kilix-license#readme),
vendored here under `third_party/kilix-license` at a pinned commit. A licence
whose decision is `affirmative` needs a yes before a receipt is written; an
`informational` one is shown and recorded without a typed agreement. The
installer refuses to select an asset unless a stored receipt covers that exact
record and manifest. Receipts live in one store,
`~/.local/gpu_terminal/license-receipts` by default. Plebian-OS can stage
upstream archives in `/usr/local/share/kilix/model-archives/` and Git sources
in a digest-bound source carrier, so an install can work offline. The archive
cache creates no receipt and does not bypass the agreement. Details: [docs/model-assets.md](docs/model-assets.md).

## Scope

The package does not resolve system packages, elevate privileges, define game
logic, choose UI policy, or update Pleb/Kilix themselves. Those responsibilities
remain with Plebian-OS, the desktop provider, and each application.

## Documentation

| Document | Contents |
|---|---|
| [docs/catalog.md](docs/catalog.md) | Catalog schema contract and a generated table of every package, entry and asset group |
| [docs/installer.md](docs/installer.md) | Installer behaviour (staging, locking, readiness, archive limits) and the Python API with examples |
| [docs/model-assets.md](docs/model-assets.md) | Installing from supplied bytes, converter prerequisites, packaged catalog verification, offline archive cache |
| [docs/development.md](docs/development.md) | What the test suite and benchmark cover |
| [CHANGELOG.md](CHANGELOG.md) | Catalog and installer changes by release |

## Related repositories

- [kilix](https://github.com/itsmygithubacct/kilix#readme): the host that
  vendors this package and provides `kilix install`, `kilix app`,
  `kilix games` and `kilix models`.
- [kilix-license](https://github.com/itsmygithubacct/kilix-license#readme):
  licence records, the verbatim first-use screen, agreements and receipts.
- [kilix-tui-utils](https://github.com/itsmygithubacct/kilix-tui-utils#readme):
  the catalog's one package.
- [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme),
  [kilix-needle](https://github.com/itsmygithubacct/kilix-needle#readme),
  [kilix-amp](https://github.com/itsmygithubacct/kilix-amp#readme) and the
  other repositories listed in [docs/catalog.md](docs/catalog.md): content
  the catalog installs.
- [kilix-95](https://github.com/itsmygithubacct/kilix-95#readme): the desktop
  whose Start menu launches catalog entries through Kilix.

## Part of Plebian-OS

kilix-content is one of the repositories behind
[Plebian-OS](https://github.com/itsmygithubacct/plebian-os#readme), a Debian
install whose desktop is [Kilix](https://github.com/itsmygithubacct/kilix#readme)
running the [Kilix 95](https://github.com/itsmygithubacct/kilix-95#readme)
desktop through [Pleb](https://github.com/itsmygithubacct/pleb#readme).
It ships inside Kilix as the `third_party/kilix-content` submodule, and every
game, catalog application and model a user installs goes through it. The map
of every repository and how it ships is on the
[components page](https://github.com/itsmygithubacct/plebian-os/blob/main/docs/components.md).

## License

MIT. See [LICENSE](LICENSE).
