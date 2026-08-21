# Kilix content contracts

These Draft 2020-12 JSON Schemas are the frozen F100 v1 contracts for 0.2.1.
The cross-consumer review and complete structural/semantic fixture matrix
passed on 2026-08-19. They are language-neutral and are also enforced by the
schema-v4 catalog parser.

- `kilix.content.asset-v1.schema.json` describes immutable, non-executable
  assets. Exactly one source mode is allowed: mirrored or user-supplied.
- `kilix.install.license-v1.schema.json` describes UI-originated decisions and
  retained receipts. A restricted decision can only decline and can never
  become a receipt.

Portable JSON Schema cannot express several cross-field rules. They are still
normative v1 requirements and every implementation must enforce them:

- asset manifest paths are unique;
- `sizes.installed_bytes` equals the sum of manifest file sizes;
- `compatibility.minimum` is not greater than `maximum`;
- conversion argv contains `{input}` and `{output}` exactly once each, as
  separate argv elements; no other element contains a brace, and substitution
  never invokes a shell; and
- a user-supplied source links at least one `user-supplied` license decision.

The fixture suite executes these rules independently of structural schema
validation. Future non-Python readers must pass the same golden fixtures.

## F100 Step-6 U1 freeze

U1 adds the closed catalog-v5 authority shape. `install.version` is opaque
upstream text. An installable package or directly installable content record
owns one `install` object and one stable slot; a package-provided alias is only
the read-only `package_id`/`member_path` mapping. The install object binds the
source mode, bounded byte/file/memory quotas, dependency DAG roles, licenses,
and the exact `{id, manifest_sha256}` system-requirement references. Git
installations omit `source_bytes`; archive, mirrored, and user-supplied
installations require it and it must not exceed `source_bytes_max`.

The packaged U1 resource set includes separate closed schemas for:

- system-requirement manifests (`id`, distribution/version/architecture,
  package manifest and package digests);
- toolchain profiles (Debian snapshot, architecture, package/executable/
  library manifests, Python and uv identities, fixed environment, and ABI);
- sandbox profiles (mount manifest, namespaces, capabilities, seccomp,
  resource limits, and enforced quota backend); and
- install/output bindings, authorization/v2, capacity-v2, and the R11--R13
  retention intent, envelope, journal, capacity-state, count/admission,
  directory-phase, accounted, handoff-proof, terminal-reuse, and impossible
  records.

`kilix.content.u1-resources-v1.json` externally roots exactly 28 production
resources: 25 schemas, the canonical empty catalog-v5 record for Plebian OS
0.2.1, its license-manifest/v1 record, and the genuine packaged `MIT.txt`.
The U1 catalog deliberately contains no package, content, asset, alias, system,
toolchain, or sandbox members. It therefore authorizes no installation before
the later reviewed catalog-assembly handoff and does not replace the preserved
schema-v4 desktop catalog.

Manifest admission is two-pass and set-equal. Every path, role, size and digest
is checked before the data graph is followed; then the catalog and license
manifest are validated through their externally rooted schemas and semantic
validators, and every manifest license path/digest is joined to exact packaged
text. The wheel has two supported presentations: the importable
`kilix_content/<manifest path>` root and exactly one
`<distribution>.data/data/share/kilix-content/<manifest path>` external root.
Root source copies, package copies, sdist, both reproducible wheels and both
installed presentations must contain the same 28-resource set, with identical
sizes, digests and bytes. The external license manifest must resolve
`licenses/MIT.txt` locally. The wheel contains no fixture,
requirements-ledger, synthetic catalog or other test authority.
The physical allowlists deliberately retain co-resident legacy files: the
package `catalog`/`contracts`/`licenses` subtrees contain exactly 33 files, and
the external root contains exactly 31. The checker applies the 28-member U1
manifest projection separately, so these historical files are preserved while
any unlisted file—including one directly below the external root—is refused.

The U1 implementation is pure parsing/canonicalization/validation: it does not
open a store, acquire locks, recover a transaction, or sequence authorization.
`validate_u1_bytes` proves only that supplied bytes satisfy one rooted schema
and semantic route; it does not prove membership in the empty production
catalog. Dict-level derivation and cross-authorization helpers are private,
test-only implementation details and are not exported.

The U1 fixture matrix is regenerated and checked with:

```sh
uv run --locked --no-sync python tests/update_u1_hashes.py --check
uv run --locked --no-sync python -m unittest tests.test_u1_contracts -v
```

The canonical source-only requirement-to-vector ledger is authored separately
from the fixture renderer and has a literal SHA-256 gate in the test suite. The
renderer may prove that every ledger requirement names present fixture IDs; it
cannot generate or weaken the ledger. Large boundary records remain in source
and sdist and are never packaged in a wheel.

## Reproducible U1 build toolchain

The component version `kilix-content 0.4.0` is independent of the Plebian OS
release identifier `0.2.1`. The project continues to declare Python `>=3.10`,
but the only qualified M4 environment is CPython 3.12.8 on Linux x86-64/glibc;
all other declared interpreters and platforms remain explicitly unqualified.

The build backend and wheel tooling are pinned in both `build-system` and the
`build` dependency group: setuptools 77.0.3, wheel 0.45.1, and build 1.3.0.
`.python-version` pins CPython 3.12.8. The committed `build-toolchain.json`
records the exact Python and `/usr/local/bin/uv` executable digests plus the
closed build/test environment. The reviewed offline wheelhouse contains 24
wheels; its canonical manifest SHA-256 is
`56eb2a5734937a7b2e0eab03df36ef77387d6c91e9724ef03cd054d1e21e776c`,
and `uv.lock` is
`fd20b7915e3e198f65e236964426b6803dea61434d593f52ede9fa104da8b8af`.

Run the long gate only from a disposable export of the exact candidate commit,
never from the candidate worktree:

```sh
candidate_commit="$(git rev-parse HEAD)"
review_export="$(mktemp -d /tmp/kilix-content-u1-r3-review.XXXXXX)"
git archive "$candidate_commit" | tar -x -C "$review_export"
cd "$review_export"
/usr/local/bin/uv run --python 3.12.8 --locked --offline --all-groups \
  python tests/check_reproducible_build.py
```

`tests/check_reproducible_build.py` owns the release epoch
`SOURCE_DATE_EPOCH=1776729600`, runs two direct source builds, extracts the
first exact sdist, runs the full locked test suite from that sdist, rebuilds its
wheel, installs the wheel with `uv pip --no-index` into a disposable venv, and
probes it from a controlled external cwd/import path. It audits archive CRCs,
the complete upper ZIP mode word and Unix creator/type, canonical
regular-file/directory names with empty directory payloads, special files,
duplicate normalized members, modes, wheel RECORD digest/size rows, exact
package and external production-resource roots across
source/sdist/direct-wheel/sdist-wheel/installed-wheel, and forbidden test
authority. The shared resource audit compares both the exact file map and the
mechanically derived semantic directory set (`catalog`, `catalog/u1`,
`contracts`, `contracts/u1`, `licenses`); archive checks include explicit
directory entries and empty alternate external roots. The same audit has
causal controls for absent or duplicate external roots, missing `MIT.txt`,
extra or renamed resources, package-root fallback, path/size/digest
mismatches, every disallowed ZIP type, name/type/payload mismatch, and
unexpected installed directories. It invokes
`python -m build --no-isolation`, so the synchronized uv environment—not an
unbounded backend resolver—owns every build tool. Its source and exact-sdist
bootstrap directories each contain a newly created `empty-uv-cache`; dependency
installation uses only `wheelhouse/requirements.txt` with `--no-index`,
`--find-links`, and `--require-hashes`. A successful gate must report both
`empty-cache offline ... reconstruction: PASS` lines, byte-identical direct
artifacts, an identical exact-sdist-derived wheel, installed-wheel resource and
corpus probes, and the final package audit. Ignored residue in a development
worktree is never candidate identity or acceptable review evidence.

Frozen schema SHA-256 values:

- `kilix.content.asset/v1`: `89d4865d11d6a537328965a8a903ac07d7dcf0ea14e1b360888f22af7ba5a1a8`
- `kilix.install.license/v1`: `2f352856b4bd712e6030b2c74a690f7c0ed250e5730a69aa04b601643dbf1736`

Built wheels install the schemas below `share/kilix-content/contracts` for
external consumers, and additionally carry importable package-resource copies
at `kilix_content/contracts/`. The importable copies are byte-identical to the
frozen sources in this directory and are the ones the runtime self-check reads:
authorization refuses unless both match the digests recorded above. Source
archives retain this complete `contracts/` directory.

`tests/fixtures/contracts/valid` contains canonical accepted instances;
`invalid` contains one rejected condition per file. `SHA256SUMS` pins every
schema and fixture byte. After this freeze, any semantic contract change
requires a new schema version rather than silently changing these files.

Fixture names begin with the schema they exercise (`asset-` or `license-`).
Every JSON file is UTF-8, uses two-space indentation and sorted object keys,
and ends with one newline. Regenerate the manifest only after reviewing the
semantic diff:

```sh
uv run --locked --no-sync python tests/update_contract_hashes.py
```

Run the contract gate from the repository root with:

```sh
uv sync --locked --group test --no-install-project
uv run --locked --no-sync \
  python -m unittest discover -s tests -p 'test_contracts.py' -v
```

The validator enables JSON Schema format checking, so malformed HTTPS URIs and
timestamps fail rather than being treated as annotations. A valid fixture must
pass exactly its named schema. Each invalid fixture pins its expected failing
instance path and validator keyword so rejection for an unrelated reason does
not conceal a schema regression.
