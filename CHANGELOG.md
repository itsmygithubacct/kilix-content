# Changelog

All notable user-visible changes are recorded here. The public API remains
pre-1.0.

## Unreleased

### Added

- Render every packaged first-use screen through the consumer's terminal
  guard, so a licence text that a `kilix models install` would refuse to
  print fails here instead of at a user's terminal. One does today:
  `bonsai-8b`'s screen carries three CR characters, inside a byte-exact
  upstream `NOTICE.txt` quotation that the pinned licence authority keeps
  CRLF on purpose, so `kilix models install bonsai-8b` refuses before the
  prompt and the asset cannot be installed. The authority's vendored bytes
  are hash-chained to its pinned commit and cannot be corrected from here;
  the exception is declared, pinned to the exact text blob, and asserted by
  set equality so it has to be removed when the authority is re-vendored.
- Catalog Kilix Land, the cross-game conversation room and training range,
  at an immutable commit with the shared `make all` game build.
- Catalog the Tmux Sessions manager as a system entry dispatched through
  `kilix tmux`, with its pinned first-run install timeout.
- Stage a DOSBox Kilix entry as a validated test fixture: it ships in the
  catalog once its pinned one-command terminal build is public.
- Stage a Tmux Browse entry as a validated test fixture: it ships in the
  catalog once its pinned loopback-only launcher is public.

### Changed

- Advance the `kilix-amp` and `kilix-tui-utils` selections to the EnCodec
  playback wave, and select `make all ENCODEC=1` for Amp. Both values were
  older here than on the line the release currently pins, so advancing the
  content gitlink would have rolled them backwards -- Amp silently, because no
  consumer test bound its build arguments. The catalog digest changes; no asset
  record, licence record or receipt byte does.
- Advance `kilix-tui-utils` to the desktop wave that derives the Games place
  from the host catalog, remembers recent and pinned Home rows, adds the
  Launchers and Manual places, and gives the Tmux manager row a `kilix`
  fallback.

### Fixed

- A supplied install follows no symlink below the supplied directory: every
  path component is opened relative to its parent without following links,
  where only the last one was before.
- A supplied directory whose path holds a terminal control character (C0,
  DEL or C1, including CR, LF, TAB and ESC) is refused before the licence
  screen is written, naming the path, rather than printed onto the consent
  screen.
- Advance `kilix-tui-utils` to relocatable runtime launchers so atomic package
  selection does not leave Start-menu applications pointing at staging paths.

## 0.4.0 - 2026-08-10

### Added

- Add schema version 3 named argv actions, accepted input types, system command
  vectors, and lifecycle/fallback metadata.
- Catalog File Manager, System Center, Kilix Settings, Software Center,
  Session Center, Model Store, Region Painter, Voice Studio, Camera Manager,
  VirtualBox Manager, and the shared terminal accessories.
- Install all TUI-provided applications from one immutable
  `kilix-tui-utils` package and explicit `make runtime` build.
- Add the terminal-native PDF Viewer with retained-scroll presentation,
  complete CPU rasterization, and an Evince fallback.

### Changed

- Describe PDF conversion input and its fixed conversion action through the
  shared application contract.
- Advance PDF Conversion to the revision whose development checks provision
  their tools through `uv`.
- Add `Installer.ready_provided()` so callers verify one shared package source
  once while retaining independent executable readiness for every app.

## 0.3.0 - 2026-08-10

### Added

- Add catalog schema version 2 packages: one immutable Git/archive source and
  build can provide multiple independently named application/content entries.
- Add `PackageSpec`, `ContentSpec.install_id`, package lookup, and
  `Catalog.provided_by()` for hosts and installers.

### Changed

- Key managed installation directories and staging paths by the package
  install identity while preserving schema version 1 and direct specifications.
- Reject duplicate, unused, unknown, non-installable, conflicting, or
  ambiguously overridden package declarations before installation begins.

## 0.2.2 - 2026-08-10

### Changed

- Advance PDF Conversion to its uv-managed runtime and declare the preferred
  desktop-window geometry used by graphical Kilix providers.

## 0.2.1 - 2026-08-10

### Added

- Add the public Kilix PDF Conversion provider at an immutable commit, with its
  explicit hash-verified `runtime` build target and terminal launch contract.

## 0.2.0 - 2026-08-08

### Added

- Bounded archive extraction defaults and a maintained catalog, checkout, and
  download benchmark.
- Typed-package metadata for callers that run static analysis.

### Changed

- Catalog JSON is limited to 1 MiB, rejects duplicate and unknown fields, and
  validates every scalar before constructing an immutable model.
- Packaged catalog discovery is cached, and managed Git verification combines
  HEAD, detached state, and tracked cleanliness in one status query.
- Build diagnostics retain a bounded tail instead of buffering unlimited child
  output.
- Distribution metadata uses the current SPDX license and typed-package
  declarations, source archives include the changelog and benchmark, and
  public artifacts remain readable when built from a private checkout.
  `SOURCE_DATE_EPOCH` builds now produce byte-reproducible wheels and source
  archives.

### Fixed

- Verify configured Git checkouts and canonical aliases of the managed
  destination while preserving explicit non-Git user-managed overrides.
- Preserve untracked files in interrupted Git directories and reject attached
  branches, symlinked Git metadata, inherited Git configuration, hooks, helper
  executables, redirected environments, and unsafe paths from directly
  constructed specifications.
- Download to a private sibling and atomically replace the destination only
  after its streaming SHA-256 succeeds, so failures preserve existing data and
  destination symlinks are never followed.
- Normalize archive, process-spawn, root, and selection failures as
  `InstallError`, and align the runtime/package versions.
