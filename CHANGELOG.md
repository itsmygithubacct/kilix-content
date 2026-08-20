# Changelog

All notable user-visible changes are recorded here. The public API remains
pre-1.0.

## Unreleased

### Added

- Add frozen schema-v4 non-executable asset records, mirrored atomic asset
  installation, and golden language-neutral asset/license contract fixtures.
- Add a private immutable receipt store with exact release/catalog/asset/text
  bindings, strict decision parsing, redacted export, verified user-input file
  handles, crash recovery, no-overwrite concurrency, and typed refusal states.
- Add durable pending-transaction reconciliation, crash-atomic store-format
  initialization, shared-instance thread serialization, post-fork refusal, and
  atomic private redacted-export output.
- Add operator-only whole-guest power-loss and real-filesystem storage-error
  acceptance runners with atomic machine-readable evidence.
- Add typed user-supplied acquisition requirements, descriptor-pinned input
  staging, bounded local conversion through pinned catalog tools, and the
  explicit one-file identity path for records that require no conversion.
- Add canonical `AssetSpec.to_mapping()` serialization so public acquisition
  inputs can be round-tripped through the frozen parser before use.
- Add code-pinned packaged release authority: the packaged catalog ships as
  canonical schema-v4 bytes pinned by a digest constant, alongside a packaged
  release-ID constant, and `ReleaseContext.packaged()` is the only construction
  path that production authorization accepts.
- Add `verified_packaged_catalog()`, which verifies the packaged catalog digest
  before parsing so unauthenticated bytes never reach the parser, and extend the
  frozen self-check to cover the packaged asset schema as well as the license
  schema.
- Add exact catalog-membership proof at both `record()` and `require_asset()`:
  a caller's asset record must be byte/field-identical to the packaged
  catalog's record for the same id, so a verified release context alone never
  authorizes.
- Add `AssetSpec.canonicalized()`, which reparses through the base
  implementations so a subclass cannot substitute a different mapping for the
  record actually being authorized.

### Changed

- Refuse a catalog in which one id names both an asset and a content entry;
  resolution order must never decide which record a name means.
- Refuse production authorization for synthetic `ReleaseContext.from_catalog()`
  contexts permanently, including one built from the exact packaged bytes.

- Require exact receipt authorization for every public asset readiness and
  installation path, including informational licenses, and recheck immediately
  before atomic selection.
- Keep production receipt authorization disabled until the immutable release
  catalog snapshot loader supplies catalog-bound artifact handles; no shipped
  factory, test subclass or mutable store flag can enable it. Synthetic
  authority lives only in test-suite code excluded from the installed wheel.
- Bound every catalog construction path by explicit text, sequence, nesting
  and aggregate limits; enforce unique mirrors and the frozen conversion-argv
  maximum at runtime.
- Serialize each asset version through a private install lock, recheck input
  and receipt bindings before selection, and bind conversion executables to a
  private source-and-binary install attestation checked immediately before use.
- Canonicalize every resolved `ContentSpec` before readiness or acquisition and
  retain the unreaped converter leader until all same-group descendants stop,
  preventing process-group identity reuse during lifecycle cleanup.

### Fixed

- Reject duplicate asset-license identifiers instead of choosing between
  contradictory decision classes.
- Keep visible-but-unconfirmed receipts non-authorizing across reopen until an
  explicit durable reconciliation succeeds; normalize hostile bounded JSON to
  typed refusals and prevent URL tokens, digests and terminal controls from
  reaching default diagnostics.
- Suppress untrusted unknown and duplicate field names in diagnostics, retain
  the required license/asset binding digests in redacted exports, refuse
  overwrite, symlink, wrong-owner, permissive or multiply-linked export
  destinations, and normalize unsafe or missing export parents to typed
  fixed-category refusals.
- Advance `kilix-tui-utils` to relocatable runtime launchers so atomic package
  selection does not leave Start-menu applications pointing at staging paths.
- Refuse special-file user inputs without blocking, partial placeholder
  substitution, unpinned conversion providers, inherited converter state and
  descriptors, unbounded or terminal-active diagnostics, and timed-out process
  groups including descendants.
- Refuse empty, short, uppercase, or non-hex archive pins and missing, mutable,
  short, uppercase, or non-hex Git refs from directly constructed converter
  records before acquisition; terminate closed-stdio descendants after zero or
  nonzero converter-parent exits as well as timeouts.
- Reject asset-manifest files with foreign ownership or multiple hard links so
  a selected tree cannot retain an undeclared mutable alias.

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
