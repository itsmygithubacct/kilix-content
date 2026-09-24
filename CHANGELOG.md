# Changelog

All notable user-visible changes are recorded here. The public API remains
pre-1.0.

## Unreleased

### Added

- Render every packaged first-use screen through the consumer's terminal
  guard, so a licence text that a `kilix models install` would refuse to
  print fails here instead of at a user's terminal. All 27 pass.
- `verified_catalog_bytes()`: the packaged catalog bytes, read once and
  returned only after they match the pinned digest.
- Catalog Solitaire, the terminal Klondike from the `kilix-games` monorepo
  (`solitaire-tui/bin/solitaire-tui`, pure Python, no build step), under the
  shared `solitaire` game id. It replaces kilix's desktop-window Solitaire.
- Merge `main` into the 0.2.2 rc2 line. Solitaire is labelled `Solitaire TUI`
  in the catalog, since Kilix 95 keeps its own built-in Solitaire window; the
  shared `solitaire` id and settings toggle are unchanged. `kilix-tui-utils`
  moves to `785a62e`, which descends from both rc1's `af7e848` and its main.
- Offer kilix-needle (OD-BV, 0.2.2 rc2): drive panes and tabs from plain
  requests with Cactus Compute's Needle 2. The app entry pins
  `cc461313` with the shared `make all`. Its three first-use assets are
  `upstream-files` at Hugging Face revision `32e9e3a9`, all Apache-2.0,
  Cactus Compute, Inc.:
  - `needle2`: the engine, one 14,888,896-byte executable with the model
    built in;
  - `needle2-runtime`: the manylinux x86_64 wheel, byte-exact, which carries
    `libneedle.so` for a fine-tuned model;
  - `needle2-train`: the base checkpoint, a pickle to verify against this
    manifest before loading it, and the two tokenizer files.
  Each has its own record in kilix-license's application authority, so no
  release record digest moves. The vendored kilix-license moves `a58c6f4c` ->
  `78417e40` (132 files to 138) by `--repin` under its old-value guard. That
  commit merges the Pocket first-use terms (`a58c6f4c`), the needle2 records
  with the review fixes that hold application licence-text identities to
  every release rule (`a1f5d077`), and kilix-license's `main`.
  `_CATALOG_SHA256` and the weights digest list (190 -> 195) are regenerated
  by their tools.
- Re-pin kilix-needle to `acaf84ff`, its fixes for the 0.2.2 review (R1: two
  High close-target and negation misreads, four Medium). Declare
  `settings-write` (`kilix-needle setup` edits shell, Kilix and harness
  settings when run) and x86-64 Linux only.
- Re-pin kilix-needle to `33eea829` (0.2.2 reviews R2 to R9). Pane and tab
  names match without regard to case. A pane in the current tab is chosen
  over another tab's pane of the same name, but a yes given in advance does
  not cover that choice; two tabs of one name are refused, and a pane or tab
  called "next", "previous" or a side makes that word ambiguous. Every action in a request is resolved
  against the desktop the request was made on and performed by id, so "close
  tab 2 and close tab 3" closes the tabs that were 2 and 3. A yes given in
  advance (`--yes`, MCP `confirm_risky`) covers only a plain instruction, as
  the kilix-needle README defines it rule by rule; other requests wait for a
  person who sees the resolved target. When the requester's pane is known,
  a yes given in advance never closes it or its tab; it never acts on a name
  found only as a word of a title; a pane is read again before anything is
  typed into it, and with emacs-style editing a half-typed one-line prompt is
  cut to the kill ring first. Known issue (named in its README): at a
  continuation prompt, in vi editing mode or with a reverse search pending,
  that clear is not enough, and typed text can join what is there.
- Catalog Kilix Land, the cross-game conversation room and training range,
  at an immutable commit with the shared `make all` game build.
- Catalog the Tmux Sessions manager as a system entry dispatched through
  `kilix tmux`, with its pinned first-run install timeout.
- Stage a DOSBox Kilix entry as a validated test fixture: it ships in the
  catalog once its pinned one-command terminal build is public.
- Stage a Tmux Browse entry as a validated test fixture: it ships in the
  catalog once its pinned loopback-only launcher is public.

### Changed

- Type the EnCodec converters' selected kilix-encodec commit, `684b010b`, in
  the consumer-selection tests, as Amp's already is, so rolling either
  converter or both back fails a test. `tools/generate_encodec_pins.py` now
  defaults to that commit. The catalog and its digest are unchanged.
- Advance both EnCodec converters to the kilix-encodec admission fixes and
  `kilix-amp` to its asset/v3 admission fixture and receipt-store README. Each
  new commit descends from the one it replaces, Amp keeps
  `make all ENCODEC=1`, and the converters' upstream pins are unchanged at the
  new commit. The catalog digest changes; no asset record, licence record or
  receipt byte does.
- Advance the `kilix-amp` and `kilix-tui-utils` selections to the EnCodec
  playback wave, and select `make all ENCODEC=1` for Amp. Both values were
  older here than on the line the release currently pins, so advancing the
  content gitlink would have rolled them backwards -- Amp silently, because no
  consumer test bound its build arguments. The catalog digest changes; no asset
  record, licence record or receipt byte does.
- Move ten games to the kilix-games monorepo at c746a5b: Kilix Lander,
  Joustix, Kilix Brokeout, Bashed Earth, Kilix Lights, Kilix JPAK, Kilix
  Pong, Chess Bash, Kilix Rancher and Kilix Fishtank. Each entry keeps its
  id and label, names `<game>/<binary>`, and builds with `make -C <game>
  all` against the repository's one shared kilix-game-sdk. This also
  advances each game from its old pin to its reviewed main (the 0.1.9 SDK
  stack), and Kilix Pong to its beatable CPU levels and neural player.
  Solitaire moves to the same commit.

- Advance `kilix-tui-utils` to the desktop wave that derives the Games place
  from the host catalog, remembers recent and pinned Home rows, adds the
  Launchers and Manual places, and gives the Tmux manager row a `kilix`
  fallback.

### Fixed

- `bonsai-8b` can be installed. Its attribution statement is a byte-exact
  quotation of an upstream `NOTICE.txt` written with CRLF line ends, and the
  consumer refuses to print a carriage return during consent. CRLF is now
  normalised to LF where the first-use screen is rendered; the stored
  quotation and every digest are unchanged, and a bare carriage return is
  still refused.
- `verified_packaged_catalog()` parses the bytes it verified. It used to
  verify one read of the file and parse a second, cached one, so a catalog
  changed between the two reads -- or parsed earlier by an unverified caller
  -- was returned without a refusal.
- A supplied install whose final verification fails now removes what it
  selected before refusing, so nothing that does not match the manifest is
  left at the installed path.
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
