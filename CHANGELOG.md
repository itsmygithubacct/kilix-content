# Changelog

All notable user-visible changes are recorded here. The public API remains
pre-1.0.

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
