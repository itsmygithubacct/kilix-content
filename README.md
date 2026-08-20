# kilix-content

`kilix-content` is the unprivileged content catalog and installer shared by
Kilix-hosted desktops. It gives games and applications one declarative record
for identity, immutable source, build command, capabilities, launch mode, and
preferred geometry. Schema version 2 can separate an immutable package from
the applications it provides, so one checkout and build can expose several
catalog IDs without duplicating source or installation state. Schema version 3
adds argv-only named actions, accepted input types, host command vectors, and
lifecycle/fallback policy. Schema version 4 adds immutable non-executable asset
records; the packaged catalog ships at version 4 in canonical form with an
explicit empty `assets` array, and the release's first real assets arrive later
with the F101 hand-in.

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

# One package verification, one independent executable result per app.
readiness = installer.ready_provided(
    shared_catalog.provided_by("kilix-tui-utils")
)
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

Schema version 4 adds immutable non-executable assets alongside applications.
Assets have version-qualified manifests, per-file SHA-256 and size, mirrored or
user-supplied acquisition, exact license decisions, compatibility bounds, and
explicit stream/provider ownership. `Catalog.require_asset()` returns the typed
record; `Installer.asset_ready()` performs an offline, side-effect-free check
of the exact non-executable installed tree and returns resolved file paths only
after `ReceiptStore.require_asset()` proves every license requirement against
the exact release-catalog and asset binding. `Installer.ensure_asset()` has the
same mandatory store/context parameters and repeats authorization immediately
before atomic selection; informational licenses are not a bypass.

The frozen public `kilix.install.license/v1` decision/receipt contract is
packaged with the library and verified against its pinned SHA-256 at runtime.
`LicenseDecision.loads()` provides bounded UTF-8 JSON parsing with duplicate-key
rejection. A `ReceiptStore` derives account, UID and time itself, hashes the
exact rendered license bytes, and retains the public receipt inside a private
`kilix.install.license-store/v1` envelope bound to canonical asset records,
manifests, release ID and catalog digest. Receipts are immutable, mode `0600`,
created without overwrite below a mode-`0700`
`${XDG_STATE_HOME}/kilix-content/license-receipts/v1` directory, and made
durable before success is reported. The store refuses root, UID transitions,
post-fork reuse, links, wrong ownership/modes, unknown generations and
visible-but-unconfirmed writes. A durable `.pending` marker keeps an
interrupted publication non-authorizing across fresh reopen; callers must run
`ReceiptStore.reconcile()` successfully before retrying. One store instance
serializes its threads in addition to using `flock` across independent opens.
`export_redacted()` omits account, presenter, time, URLs, input fingerprints
and private envelope digests while retaining the release, license-text digest
and exact asset record/manifest binding digests required for a useful audit;
it lists every removed field. `export_redacted_to()` creates a new mode-`0600`
file atomically inside an exact mode-`0700` caller-owned directory and refuses
every existing destination, including links and unsafe files.

The 0.2.1 trust boundary includes processes already running as the same UID;
hashes bind official callers and detect corruption, but are not a MAC against a
compromised desktop account. Synthetic authority exists only in test-suite code
that is excluded from the installed wheel; the runtime module ships no test
store or synthetic-authority factory.

Production authorization is rooted in the packaged bytes this component
shipped. The packaged catalog is canonical schema-v4 JSON pinned by a code
digest constant, alongside a packaged release-ID constant, and both frozen
schemas ship as importable package resources whose digests the runtime
self-check verifies on every authority call. `ReleaseContext.packaged()` is the
only construction path that production accepts: it verifies both schemas, then
verifies the catalog digest *before* parsing, and stamps a provenance marker no
other constructor can set. `ReleaseContext.from_catalog()` remains synthetic and
is refused permanently — including a context built from the exact packaged
bytes, which carries an identical release ID and digest and is still denied,
because provenance rather than field equality is what separates them.

A verified context is not by itself authorization. `ReceiptStore.record()` and
`ReceiptStore.require_asset()` each additionally require the caller's
`AssetSpec` to be byte- and field-identical to the packaged catalog's record for
the same id; an absent id or any difference fails closed without writing state.
Records are reparsed through the base implementations, so an `AssetSpec`
subclass cannot present one mapping for the membership check and different
fields to everything downstream.

F106 is neither the authority nor a dependency of this path: it supplies asset
record *content* as a later build-time input. There is no legacy import or
implicit migration: v1 is the first store generation, and a future generation
must copy forward under the stable lock without deleting v1.

Catalog text, arrays, nesting and direct mappings have explicit semantic
budgets equivalent to the one-MiB JSON boundary. Runtime validation also
enforces frozen asset-schema uniqueness and maximums, including unique mirrors
and at most 256 bounded conversion arguments.

For a `user-supplied` asset, `Installer.required_input()` returns a frozen
`AcquisitionRequired` value containing only catalog-derived URL, reason, size,
digest and conversion facts. The spec is first serialized canonically and
round-tripped through the frozen parser, so direct unvalidated dataclass
construction cannot spoof those UI facts. After a presenting UI has recorded
the exact license decision, it calls `ensure_user_supplied_asset()` with the
same catalog, receipt store, release context and a user-selected path. The
installer opens that path once without following its final symlink, refuses
non-regular files,
hashes and copies from the pinned descriptor, and never passes the original
path or descriptor to the converter. Replacing the pathname after it is opened
therefore does not change the consumed bytes; mutating the opened inode blocks
selection at the final revalidation.

Conversion tools resolve only through `Catalog.require()` to pinned Git or
archive `ContentSpec` entries. Every resolved content object is serialized as a
flattened canonical mapping and reparsed before readiness, acquisition, build,
attestation, or execution; archive digests and Git commits remain exact
lowercase 64- and 40-hex pins even for directly constructed dataclasses. Their
argv begins with the resolved absolute program and substitutes only whole
`{input}` and `{output}` elements. A private source-and-binary attestation covers
build outputs that Git itself treats as untracked and is checked again
immediately before execution. Converters receive an empty stdin, closed
inherited descriptors, a private working directory and minimal environment;
output diagnostics retain only a sanitized bounded tail. The process leader is
observed without reaping so its process-group identity cannot be reused, then
TERM/KILL cleanup removes descendants after every parent exit, including
successful and ordinary failing exits whose descendants close captured stdio.
One private lock per asset version prevents duplicate conversion. Both receipt
checks and the final input check precede atomic selection. A record without
conversion is accepted only when its one declared output is byte-identical to
the input; archives are never expanded implicitly. Manifest files must also
remain caller-owned, non-executable regular files with one link.

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

The packaged `plebian.json` catalog ships at schema version 4, in canonical
form — sorted keys, compact separators, UTF-8 — with an explicit empty top-level
`assets` array. Canonical bytes are what the code-pinned digest constant
covers, so the shipped file can be verified before it is parsed. The empty
array is deliberate: the asset record type is available to readers now, and the
release's first real assets arrive later with the F101 hand-in. Readers accept
schema versions 1 through 4; a catalog that declares assets below version 4 is
rejected rather than reinterpreted. Schema version 2 added a top-level
`packages` array. Each package owns an installable Git/archive
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
uv sync --locked --group test --no-install-project
uv run --locked --no-sync python -m unittest discover -s tests -v
uv run --locked --no-sync python benchmarks/benchmark_content.py
```

Tests use local Git repositories, private temporary stores, and in-memory
archives. They cover catalog validation, shared-package installation/readiness,
fragmented installation
failures, recursive dependency checkout, dirty/wrong-origin refusal, atomic
replacement, traversal and symlink rejection, checksum enforcement, bounded
child diagnostics, executable readiness, exact receipt/release/artifact
bindings, mandatory authorization, malformed/private-store attacks, input path
swaps, same-instance and multi-process no-overwrite concurrency, killed lock
holders, post-fork refusal, crash-atomic initialization, persistent durability
fault injection and reconciliation, bounded hostile JSON, safe diagnostics,
private redacted export, production-context refusal, pinned user-input
conversion, malformed direct tool pins, converter replacement, descendant
cleanup after timeout/success/failure, lock serialization and abrupt failure at
every staging boundary. The benchmark records cached and cold
catalog cost, indexed lookup, managed Git verification/readiness, and a verified
32 MiB download.

F100's language-neutral JSON Schema contracts live in [`contracts/`](contracts/).
Their canonical valid and intentionally invalid examples are under
`tests/fixtures/contracts/`; the tests validate every example with Draft
2020-12 plus format checking, reject unknown fixture classes, require canonical
JSON serialization, and verify the byte-for-byte `SHA256SUMS` manifest.

Operator-run receipt durability qualification lives in
`tests/receipt_storage_acceptance.py` and
`tests/run_receipt_storage_errors.py`. It is intentionally separate from unit
discovery because it removes power from a disposable QEMU guest and creates
isolated loop/FUSE/device-mapper filesystems with passwordless test-VM sudo.
The host controller is the `kilix-storage-acceptance` entry point in the local
`kilix-benchmark` development project. Run it only against a validated
disposable image; it refuses root, reused run paths and an unverified QEMU PID.

## Scope

The package does not resolve system packages, elevate privileges, define game
logic, choose UI policy, or update Pleb/Kilix themselves. Those responsibilities
remain with Plebian-OS, the desktop provider, and each application.

## License

MIT. See [LICENSE](LICENSE).
