# Changelog

All notable user-visible changes are recorded here. The public API remains
pre-1.0.

## Unreleased

### Added

- Catalog `needle2`, the Cactus Compute Needle 2 engine for kilix-needle, as
  an `upstream-files` asset at revision `32e9e3a9` (one 14,888,896-byte
  executable with the model built in, plus the Apache-2.0 notice). Its licence
  record is the first in kilix-license's application authority, so it moved no
  release record digest: the other 27 assets are byte-identical, and only
  `_CATALOG_SHA256` and the weights digest list gained the new asset. The
  vendored kilix-license moves to `24bc70fd` (129 files to 133), by
  `tools/vendored_kilix_license.py --repin` under its old-value guard.
- Catalog `needle2-runtime` and `needle2-train` for kilix-needle, both
  `upstream-files` at revision `32e9e3a9`. `needle2-runtime` is the
  manylinux x86_64 wheel byte-exact (13,283,977 bytes), because Hugging Face
  publishes `libneedle.so` (the library that can load a fine-tuned model) only
  inside it, and archive mode needs a single top-level root that a wheel does
  not have; a consumer reads `needle/libneedle.so` out of the verified wheel
  bytes. `needle2-train` is the base checkpoint `checkpoints/needle2.pkl` (a
  pickle: verify it against this manifest before loading it) and the two
  tokenizer files. Each has its own application licence record with
  `needle2`'s licence text and licensor. `_CATALOG_SHA256` moves
  `2a788ee4` -> `a5aafcd6` for the two assets only; the other 28 assets are
  byte-identical; the weights digest list gains the four new files (190 ->
  194). The vendored kilix-license moves `24bc70fd` -> `50bdf72a` (133 files
  to 135) by `--repin` under its old-value guard.
- Catalog Kilix Land, the cross-game conversation room and training range,
  at an immutable commit with the shared `make all` game build.
- Catalog the Tmux Sessions manager as a system entry dispatched through
  `kilix tmux`, with its pinned first-run install timeout.
- Stage a DOSBox Kilix entry as a validated test fixture: it ships in the
  catalog once its pinned one-command terminal build is public.
- Stage a Tmux Browse entry as a validated test fixture: it ships in the
  catalog once its pinned loopback-only launcher is public.

### Changed

- Advance `kilix-tui-utils` to the desktop wave that derives the Games place
  from the host catalog, remembers recent and pinned Home rows, adds the
  Launchers and Manual places, and gives the Tmux manager row a `kilix`
  fallback.

### Fixed

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
