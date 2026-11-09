# The content catalog

The catalog is one JSON file, [`src/kilix_content/catalog/plebian.json`](../src/kilix_content/catalog/plebian.json),
parsed and validated by [`src/kilix_content/model.py`](../src/kilix_content/model.py).
Its SHA-256 is pinned in [`src/kilix_content/receipt.py`](../src/kilix_content/receipt.py),
so any change to the file is also a change to that pin.
[`tools/generate_upstream_records.py`](../tools/generate_upstream_records.py)
builds the `assets` array from the pins in
[`tools/upstream-pins/`](../tools/upstream-pins/), writes the catalog and
re-pins the digest (`--old <previous sha256>` guards the replacement).
`make pins` runs it with `--check` and fails on a hand-edited record or pin.

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

Schema version 4 adds the top-level `assets` array: asset/v3 model records,
validated against [`contracts/kilix.content.asset-v3.schema.json`](../contracts/kilix.content.asset-v3.schema.json).
Older schemas reject an `assets` array. See [model-assets.md](model-assets.md).

## What the packaged catalog holds

At this commit `plebian.json` is schema version 4 and holds 1 package, 55 content entries (37 applications, 16 games, 2 tools) and 43 model assets. The tables below are generated from the file; the file is the authority.

### Packages

| Package | Source | Build | Provides |
|---|---|---|---|
| `kilix-tui-utils` | [kilix-tui-utils](https://github.com/itsmygithubacct/kilix-tui-utils#readme) at `b6321de9` | `make runtime` | 16 applications |

### Content entries

| ID | Kind | Source | Launch |
|---|---|---|---|
| `doom` | game | custom (host-owned setup) | run |
| `dosbox` | app | custom (host-owned setup) | run |
| `bashed-earth` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `kilix-jpak` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `kilix-rancher` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `kilix-pong` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `solitaire` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `tictactoe-tui` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `pleb-tower` | game | [pleb-tower](https://github.com/itsmygithubacct/pleb-tower#readme) at `9e4595ee` | terminal |
| `kilix-lights` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `super-kilix` | game | [super-kilix](https://github.com/itsmygithubacct/super-kilix#readme) at `e47f6687` | terminal |
| `joustix` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `chess-bash` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `kilix-fishtank` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `terminal-lander` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `kitty-brokeout` | game | [kilix-games](https://github.com/itsmygithubacct/kilix-games#readme) at `668faacf` | terminal |
| `kilix-land` | game | [kilix-land](https://github.com/itsmygithubacct/kilix-land#readme) at `710d73ef` | terminal |
| `kilix-file` | app | package `kilix-tui-utils` | terminal |
| `kilix-system-center` | app | package `kilix-tui-utils` | terminal |
| `kilix-settings-center` | app | package `kilix-tui-utils` | terminal |
| `kilix-software-center` | app | package `kilix-tui-utils` | terminal |
| `kilix-session-center` | app | package `kilix-tui-utils` | terminal |
| `kilix-model-store` | app | system command `kilix bonsai` | terminal |
| `kilix-camera-wall` | app | system command `kilix nvr view` | terminal |
| `kilix-region-painter` | app | system command `kilix mask` | terminal |
| `kilix-voice-studio` | app | package `kilix-tui-utils` | terminal |
| `kilix-camera-manager` | app | package `kilix-tui-utils` | terminal |
| `kilix-virtualbox-manager` | app | package `kilix-tui-utils` | terminal |
| `kilix-weather` | app | package `kilix-tui-utils` | terminal |
| `kilix-calculator` | app | package `kilix-tui-utils` | terminal |
| `kilix-music-control` | app | package `kilix-tui-utils` | terminal |
| `kilix-chawan` | app | system command `kilix chawan` | terminal |
| `kilix-rollout-resume` | app | package `kilix-tui-utils` | terminal |
| `kilix-character-map` | app | package `kilix-tui-utils` | terminal |
| `kilix-notepad` | app | package `kilix-tui-utils` | terminal |
| `kilix-find-files` | app | package `kilix-tui-utils` | terminal |
| `kilix-session-log` | app | package `kilix-tui-utils` | terminal |
| `kilix-power-controls` | app | [kilix-power-controls](https://github.com/itsmygithubacct/kilix-power-controls#readme) at `6558f802` | xpane |
| `kilix-amp` | app | [kilix-amp](https://github.com/itsmygithubacct/kilix-amp#readme) at `eff203a7` | xpane |
| `kilix-pdf` | app | [kilix-pdf](https://github.com/itsmygithubacct/kilix-pdf#readme) at `d59ff451` | terminal |
| `kilix-pdf-conversion` | app | [kilix-pdf-conversion](https://github.com/itsmygithubacct/kilix-pdf-conversion#readme) at `e841241b` | terminal |
| `kilix-rtsp` | app | [kilix-rtsp](https://github.com/itsmygithubacct/kilix-rtsp#readme) at `bf5128f2` | terminal |
| `kilix-nvr` | app | [kilix-nvr](https://github.com/itsmygithubacct/kilix-nvr#readme) at `e68b5d14` | terminal |
| `kilix-object-detect` | app | [kilix-object-detect](https://github.com/itsmygithubacct/kilix-object-detect#readme) at `ee8ca067` | terminal |
| `kilix-tmux-manager` | app | system command `kilix tmux` | terminal |
| `playalong` | app | [kilix-playalong](https://github.com/itsmygithubacct/kilix-playalong#readme) at `a11a0219` | terminal |
| `kilix-find` | app | [kilix-find](https://github.com/itsmygithubacct/kilix-find#readme) at `3fa55931` | terminal |
| `kilix-graphs` | app | [kilix-graphs](https://github.com/itsmygithubacct/kilix-graphs#readme) at `720af007` | terminal |
| `kilix-techno` | app | [kilix-techno](https://github.com/itsmygithubacct/kilix-techno#readme) at `0992edcb` | terminal |
| `kilix-encodec-convert-24khz` | tool | [kilix-encodec](https://github.com/itsmygithubacct/kilix-encodec#readme) at `22290fb4` | terminal |
| `kilix-encodec-convert-48khz` | tool | [kilix-encodec](https://github.com/itsmygithubacct/kilix-encodec#readme) at `22290fb4` | terminal |
| `kilix-needle` | app | [kilix-needle](https://github.com/itsmygithubacct/kilix-needle#readme) at `a887e2fa` | terminal |
| `kilix-claudex` | app | [kilix-claudex](https://github.com/itsmygithubacct/kilix-claudex#readme) at `8346512b` | terminal |
| `kilix-help-llm` | app | [kilix-help-llm](https://github.com/itsmygithubacct/kilix-help-llm#readme) at `4abc52e9` | terminal |
| `kilix-waydroid` | app | [kilix-waydroid](https://github.com/itsmygithubacct/kilix-waydroid#readme) at `9d1803df` | xpane |

### Model assets

Each asset is an asset/v3 record: exact files with sizes and SHA-256
digests, a source mode, the program that uses it (`provider`), and the
licence records that must be covered before it is installed.

| Source mode | Assets |
|---|---|
| `upstream-files` | 30 |
| `upstream-archive` | 5 |
| `upstream-convert` | 4 |
| `registry-manifest` | 4 |

| Provider | Assets |
|---|---|
| `kilix-bonsai` | 6 |
| `kilix-needle` | 6 |
| `kilix-ollama` | 5 |
| `kilix-voice` | 4 |
| `kilix-object-detect` | 3 |
| `kilix-pdf-conversion` | 3 |
| `kilix-qwen-tts` | 3 |
| `kilix-encodec` | 2 |
| `kilix-piper-tts` | 2 |
| `kilix-playalong` | 2 |
| `kilix-transcribe` | 2 |
| `kilix-whisper-stt` | 2 |
| `kilix-sound-detect` | 1 |
| `kilix-split` | 1 |
| `paradee` | 1 |

| Licence decision | Licence records cited |
|---|---|
| `affirmative` | 43 |
| `informational` | 2 |
