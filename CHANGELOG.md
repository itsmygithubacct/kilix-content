# Changelog

- RC2: integrate the reviewed Needle app grammar and baseline log reader, its rollout adapter, and local documentation search.

All notable user-visible changes are recorded here. The public API remains
pre-1.0.

## Unreleased

### Changed

- Re-pin kilix-object-detect `096dd5a` -> `05623f3`. Image Analyzer builds from a
  clean checkout again: it stages its pinned kilix-motion-detect `ea8be2e` when no
  `F120_PREFIX` is given, where `096dd5a` stopped every catalog build at
  "F120_PREFIX is required" (found by the RC2 VM acceptance catalog gate).
- `kilix-tui-utils` moves to `b74c21f`. Agent installers download the vendor
  bootstrap, check the sha256 pinned on 2026-09-25, and run that file.

### Added

- Move kilix-needle from e962930 to 79b9387 (0.2.2 rc3).
  - **Panes:** a tab rename needs a rename in the clause that holds the name, typed commands
    go into plain `sh` panes, "pane 70" and "pane:70" name a pane, and a yes given in advance
    covers the typing wordings agents use.
  - **Agents:** a launch in an explicit directory, and "do not give it a task", are read.
  - **Refusals** carry a hint: the job that reads the request, or one accepted phrasing.
  - **MCP:** shorter tool descriptions and one compact record per result; the Codex entry
    forwards the whole Kilix environment.
  - **Panes model:** the tuned qat-9 passed a blind held-out gate (selected per machine).
  - **Exact pane commands** (close, go to or type into a pane by title, name, side or id;
    close or go to tab N) are read without a model and still checked; "the pane titled X" binds.
- Move kilix-needle from be7928f to e962930 (0.2.2 rc2).
  - **Panes:** a request taken back ("close tab 3 - no wait, never mind") runs
    nothing; a written or third party's instruction ("the wiki says to type …")
    is refused; "whichever tab …" describes a tab rather than naming one; and
    "with btop inside" starts btop, not `btop inside`.
- Move kilix-needle from 67d17e2 to be7928f (0.2.2 rc2).
  - **Panes:** a request that reports someone else's instruction ("Sam keeps telling
    me to close the logs pane") is refused, as are web browser tabs, a command's
    unquoted reason, and "at once" is no longer read as a time.
  - **Files:** "markdown files" search `*.md`; categories such as images are refused.
  - **State:** everything kilix-needle keeps lives in one directory,
    `~/.local/gpu_terminal/kilix-apps/kilix-needle`. The system normalizer profile
    and logs index move there from `~/.local/share/kilix-needle` on first use.
  - **Gates:** the system and files jobs have blind held-out gates.
- Move kilix-needle from e66ec13 to 67d17e2 (0.2.2 rc2).
  - **Files:** a read-only files job searches, lists and previews files within a
    scope you name. It follows no links and runs no shell.
  - **System:** a read-only system job reads resources, processes, services, the
    journal and packages. Its default is a grammar.
  - **Apps controls:** exact commands set audio volume, mute and default devices,
    music playback, speech and dictation, voice settings, text size and system status.
  - **Apps grammar:** a change that gives a purpose is refused, and adverbs are
    read after on/off.
  - **Panes:** a request that gives a time or a condition ("if the build fails, close
    the logs pane", "close it at noon") is refused. Pronouns never name a pane.
  - **More pane actions:** maximize/restore, rename pane, swap panes and move tab
    reach the panes model.
  - **Replies:** an engine reply that is marked as an error or malformed runs nothing.
- Move kilix-needle from 56813ce to e66ec13 (0.2.2 rc2). Every panes, apps or
  agents request it answers is added to a local history,
  `~/.local/gpu_terminal/kilix-apps/kilix-needle/history/requests.jsonl`, to
  improve its grammar and models. The history holds the request, the proposed
  calls, what the checks admitted or refused and why, and the outcomes.
  - It never leaves the machine, and it is private (0700/0600, no links followed).
  - It is bounded (64 KB entries, 8 MB files, eight kept), and never delays or
    changes a request.
  - Pane names and titles, runtime errors and command lines are not kept.
  - Set `KILIX_NEEDLE_HISTORY=0` to turn it off.
- Move kilix-needle from 083b9ee to 56813ce (0.2.2 rc2). Its apps job no
  longer loads a model. The request's own reading proposes every call it
  supports, and the same checks admit them, in the order of the clauses that ask
  for them. A request takes tens of milliseconds. On the apps eval sets this is
  80/90 on test and 111/146 on held-out v4, against 73/90 and 93/146 for the
  tuned model, with no unsafe action. Two holes the checks shared with any
  caller are closed: "all the time" named the clock, and "I don't want mines;
  open mines" disabled Minesweeper. Descriptions ("pictures of the clock", "temp
  files", "clock.png") and file names no longer name a widget.
- Move the twelve kilix-games entries from 53ccef8 to 668faac (0.2.2 rc2).
  Bashed Earth leaves through menus only (a pause menu and a match-over menu,
  Q no longer quits), keeps a watched game playing between matches, and
  hardens its neural lab; Joustix starts the next game by itself when a
  computer rider loses. Independent review: five rounds, the last SHIP.
- Move kilix-needle from b558f1b to 083b9ee (0.2.2 rc2). The apps job gates
  on a fresh blind held-out set (v4, 146 requests), and kilix-ml moves to
  5e784b7, whose apps templates train the model the widened app grammar was
  built for. Its tuned model, apps-qat-3, passed that gate at 93/146 against
  75/146 for the base model, with no unsafe action.
- Move the twelve kilix-games entries from 573162b to 53ccef8 (0.2.2 rc2).
  Bashed Earth gains a Neural opponent whose trained network picks weapon,
  angle and power without searching trajectories (1,873 of 2,000 held-out
  duels won against the five classic personalities), and a watch mode for
  Player 1; its description is updated. Its tests no longer write the
  player's options file.
- Move the twelve kilix-games entries from 3f81a74 to 573162b (0.2.2 rc2).
  Joustix gains a trained neural rider (89.3% of held-out waves cleared
  cleanly, against the autopilot's 1.0%), menus that leave through QUIT, and
  N to hand the rider over; its description is updated. Kilix Brokeout's
  storage-sentinel test covers every mode, and Joustix tests pausing in the
  wave break (both test-only). Reviewed independently (J1 in the release
  records).
- Move the eleven kilix-games entries from c746a5b to 3f81a74 (0.2.2 rc2),
  and catalog Tic-Tac-Toe (`tictactoe-tui/tictactoe-tui`, `make -C
  tictactoe-tui all`, terminal, mouse) from the same commit. The games gain
  trained neural players: Kilix Lander (a neural pilot, 98.4% of held-out
  levels landed against the autopilot's 55.0%), Kilix Brokeout (a neural
  player that clears 14.9% of held-out levels in three minutes against 0.4%),
  Solitaire TUI (neural hint and auto-play) and Tic-Tac-Toe (an opponent
  proven to play perfectly), plus Kilix Pong's match-options menu and
  per-hit speed-up. Every changed game leaves through its menus and restores
  the terminal on any fatal signal. Descriptions for Pong, Solitaire TUI,
  Kilix Lander and Kilix Brokeout are updated. Independent reviews of the
  kilix-games range are in the release records.
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
- Re-pin kilix-needle to `ac323a76` (0.2.2 reviews R2 to R9; it builds
  against this rc2 content, one step behind its own app pin). Pane and tab
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
- Re-pin kilix-needle to `6e40df44` (0.2.2 review R10, five rounds, and
  its held-out set v9). A program starts only in the kind of open, and on the
  side, that its own clause asks for: "new tab, then split right with
  python3" no longer starts python3 in an extra tab, nor "split left with
  less and split right with watch" watch on the left. One pane described in
  two calls is one pane, and two panes asked for stay two. A placing,
  courtesy or repeating word is not a tab or pane name ("close the next tab
  over"), unless the request introduces it as one. Upstream's tuning runs
  with telemetry off, now under test, and the tuning library's training
  environment carries licence records for all 31 locked packages. Known
  issues (named in its README): a courtesy word the lists miss ("close the
  tab thanks") is read as a name, held for a person's yes; and a real
  opening clause that also names an existing pane ("split the window right")
  can have its pane-with-program refused.
- Re-pin kilix-needle to `bfacf6e7` (0.2.2 review R11, six rounds): each job
  it does has its own selected model, eval sets and gate (panes today). The
  installed tuned-model selection reads and stays as before, and panes
  behaves as before. A model gated for one job is never selected for
  another, selection writes are locked, and a run that exists is never
  replaced or deleted. It also carries the blind eval sets of the coming
  apps job. Known issue (named in its README): a selected run resumed by
  `tune --run` can re-gate, and a failed re-gate is recorded in its report;
  its model bytes are never rewritten.
- Re-pin kilix-needle to `a42973fa` (0.2.2 review R12, eleven rounds, SHIP
  WITH KNOWN ISSUES): its apps job, `kilix-needle apps "…"` and the MCP tools
  `kilix_apps_plan` / `kilix_apps_act`, opens Kilix apps and games in a new
  tab and shows or hides top-bar indicators, pane buttons, pane CPU/memory
  readouts and games, or opens a settings section. Every launch and setting
  change asks first; a yes given in advance covers only a plainly worded
  request, and a launch that may install always waits for a person. Its
  tuned model passed its gate on a blind held-out set; the base model
  answers until a tuned one is selected. Panes behaves as before.
- Re-pin kilix-needle to `40a189a8` (0.2.2 reviews R13, six rounds, and R14,
  ten rounds; SHIP WITH KNOWN ISSUES): its agents job, `kilix-needle agents
  "…"` and the MCP tools `kilix_agents_plan` / `kilix_agents_act`, launches
  Claude Code, Codex, Grok or qwen-omp in a directory (with a task, a resume,
  a model or a side), waits for a session to finish or to ask, and messages
  a session. The request is the consent. Its checks read the request
  themselves and admit only the model's calls that match that reading
  exactly; client commands, negations, reports and take-backs are refused,
  and a message is never typed into an approval dialog or a shell. Folder
  trust and permissions follow Kilix's agent-control (`--trust-folder`, the
  coding-yolo setting). Its tuned model passed its gate on a blind held-out
  set (83/150 against 50/150, 0 unsafe). Known issues: Codex takes messages
  only when idle; names outside `~/gpu_terminal` need
  `~/.config/kilix-needle/dirs.json` or a path. Adds `session-write`, which
  messaging a session needs.
- Re-pin kilix-tui-utils to `03ffa1f` for the agents job: its session readers
  report grok and qwen-omp sessions idle, working or waiting (a pending
  permission or approval is waiting), and the pane center reads both; it
  also keeps catalog converter tools installable without desktop launch
  entries.
- Re-pin the camera stack: kilix-rtsp `dc83447` (the view keeps a rolling
  history behind the live picture with replay keys, and has a detector
  button), kilix-object-detect `096dd5a` and kilix-nvr `25497a6`, which carry
  that kilix-rtsp. Library interfaces the two apps use are unchanged.
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
