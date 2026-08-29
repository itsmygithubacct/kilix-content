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

The reproducible-build gate treats an sdist as a bounded container, not merely
as a list returned by one tar parser. It verifies gzip integrity, the tar
end-of-archive boundary, a nonempty archive, and agreement between the stock
enumerator and the bounded reader. The bounded reader advances over physical
data blocks for directory, symbolic-link, hard-link, character-device,
block-device, and FIFO type flags, and extraction passes that bounded member
list explicitly. Archive and installed resource audits retain separate file
and semantic-directory sets; all direct and sdist-derived artifacts, including
the isolated installed presentation, use the same production-resource
allowlists and the 28-member authority projection.

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

R14 adds a separate append-only property/mutation registry in
`tests/check_reproducible_build.py`. Each row names the artifact family,
property, exact mutation, and expected refusal. The gate executes every row
against every direct sdist and direct/sdist-derived wheel. Each production
audit records, on completion, that it was reached on that artifact (keyed on the
artifact's content digest, not on a wrapper label); `assert_property_registry_coverage`
refuses if that reachability record is absent, if an enumerated production audit
lacks a registered mutation, or if a mutation was not executed. The body-level
property of each audit is exercised by its registered mutation. Its literal
registry digest is
`d0c05c659548a256072a4cc7cee8794555cccce03a9c3fc56c8b05bb454a019d`.

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
review_export="$(mktemp -d /var/tmp/kilix-content-u1-r14-review.XXXXXX)"
git archive "$candidate_commit" | tar -x -C "$review_export"
cd "$review_export"
TMPDIR=/var/tmp/kilix-content-u1-r14-tmp \
  /usr/local/bin/uv run --python 3.12.8 --locked --offline --all-groups \
  python tests/check_reproducible_build.py
```

The default invocation above passes no flags and runs the complete-gate
regressions on the release path: the production property/mutation registry,
all archive/resource controls, and the two nested child-gate regressions that
prove the wiring fails closed. `assert_complete_gate_regressions` refuses if
either regression is not observed, so the controls cannot silently stop
running. `--r13-skip-regressions` is the recursion guard the nested child
gates use, and an explicit diagnostic skip only; it is never part of the
documented release command. Child gates inherit the frozen environment,
including `TMPDIR`.

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

<!-- R16-15-ADJACENT-ROWS:BEGIN -->

R6 adjacent-property disposition (13/13 inherited R14 rows):

| Row ID | Disposition | Normalized claim | Bounded authority source | Production/control population | Disposition and bounded authority |
| --- | --- | --- | --- | --- | --- |
| ADJ-R14-R6-01-WHEEL-MEMBER-SET | ENFORCED | Complete wheel member set | `tests/check_reproducible_build.py::expected_wheel_members`<br>`tests/check_reproducible_build.py::wheel_archive_audit` | `wheel:direct-1`<br>`wheel:direct-2`<br>`wheel:sdist-derived` | Enforced by the disjoint source-derived category sets: currently 80 members comprising 33 package resources, importable modules, five exact `.dist-info` members, and 31 external data files; only `kilix_content/`, the matching `.data/`, and the matching `.dist-info/` roots are admitted. This project declares no `[project.scripts]`, so `entry_points.txt` is refused; an honest declaration causes the derived expectation to include it. |
| ADJ-R14-R6-02-SDIST-MEMBER-SET | ENFORCED | Complete sdist member set and distribution root | `tests/check_reproducible_build.py::expected_sdist_members`<br>`tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist:direct-1`<br>`sdist:direct-2` | Enforced by the source-derived file/canonical-parent closure, exactly one canonical top-directory record, and the exact normalized project-name/version root, including five generated egg-info members and two backend root metadata members. Absence and duplicate top-directory controls are causal. |
| ADJ-R14-R6-03-ZIP-MODE-TYPE-COHERENCE | ENFORCED | Upper ZIP mode word, creator/type, name/type/payload coherence | `tests/check_reproducible_build.py::classify_wheel_member`<br>`tests/check_reproducible_build.py::wheel_archive_audit` | `wheel:direct-1`<br>`wheel:direct-2`<br>`wheel:sdist-derived`<br>`wheel-control:archive-member-types` | Enforced by the archive classifier; only regular `0644` files, `0664` `RECORD`, and empty canonical `0755` directories are admitted. Symlinks, special/ambiguous types, unsafe names, noncanonical directory spellings, nonempty directories, setuid, world-writable, and unreadable members are rejected. |
| ADJ-R14-R6-04-WHEEL-RECORD | ENFORCED | Wheel RECORD membership, SHA-256 digest, and size | `tests/check_reproducible_build.py::record_audit`<br>`tests/check_reproducible_build.py::record_self_row_empty_control` | `wheel:direct-1`<br>`wheel:direct-2`<br>`wheel:sdist-derived`<br>`wheel-control:record` | Enforced for every untouched and repaired control wheel. |
| ADJ-R14-R6-05-RESOURCE-PROJECTION | ENFORCED | Exact 28-member production-resource projection | `contracts/kilix.content.u1-resources-v1.json`<br>`tests/check_reproducible_build.py::production_resources`<br>`tests/check_reproducible_build.py::wheel_resource_audit` | `resource-manifest-members:28/28`<br>`wheel-presentations:3/3`<br>`wheel-resource-roots:2/2` | Enforced by the manifest digest/size/byte audit in both package and external presentations. |
| ADJ-R14-R6-06-CORESIDENT-ALLOWLISTS | ENFORCED | Exact 33/31 co-resident resource allowlists and semantic directories | `tests/check_reproducible_build.py::coresident_resources`<br>`tests/check_reproducible_build.py::wheel_resource_audit` | `package-resource-files:33/33`<br>`external-resource-files:31/31`<br>`wheel-presentations:3/3` | Enforced independently of the 28-member projection, preserving the five legacy/package co-residents and the three external co-residents. |
| ADJ-R14-R6-07-NONRESOURCE-DIGESTS | LIMITATION | Non-resource wheel member digests versus source | `tests/check_reproducible_build.py::expected_wheel_members`<br>`tests/check_reproducible_build.py::reproducibility-checks` | `wheel-presentations:3/3`<br>`non-resource-wheel-members:source-derived-closure` | Not separately asserted; bounded by the source-derived member closure, the pinned clean build, and direct-wheel/sdist-derived-wheel byte identity. |
| ADJ-R14-R6-08-EXPECTED-ARTIFACT-DIGEST | LIMITATION | Recorded expected artifact digest | `tests/check_reproducible_build.py::digest`<br>`tests/check_reproducible_build.py::reproducibility-checks` | `sdist-byte-identities:1/1`<br>`wheel-byte-identities:1/1` | Not enforced as a pinned value; the gate compares two direct builds and the exact-sdist-derived wheel. A release evidence bundle must record the resulting hashes. |
| ADJ-R14-R6-09-ZIP-COMMENT-EXTRA | OUT_OF_SCOPE | ZIP archive comment and per-entry extra fields | `tests/check_reproducible_build.py::reproducibility-checks` | `wheel-presentations:3/3` | Out of scope; not used by installation or U1 resource authority, and bounded only by reproducible direct/sdist-derived artifact identity. |
| ADJ-R14-R6-10-SDIST-SOURCE-PAYLOAD | ENFORCED | Sdist source-managed payload bytes | `tests/check_reproducible_build.py::sdist_payload_audit` | `sdist:direct-1`<br>`sdist:direct-2`<br>`source-managed-sdist-members:all` | Enforced by `sdist_payload_audit`, which checks size, SHA-256 and bytes against the exact source tree for every non-generated member; causal source, test, tooling and documentation mutations refuse. |
| ADJ-R14-R6-11-INSTALLED-RESOURCE-MODES | ENFORCED | Installed production-resource file and directory modes | `tests/check_reproducible_build.py::filesystem_resource_mapping`<br>`tests/check_reproducible_build.py::installed_wheel_audit` | `installed-wheel-presentations:3/3`<br>`installed-resource-roots:2/2` | Enforced by the shared `filesystem_resource_mapping`: regular files must be `0644` and directories `0755`; setuid, setgid, sticky, world-writable and unreadable controls refuse. |
| ADJ-R14-R6-12-SDIST-COMPRESSION-METADATA | OUT_OF_SCOPE | Sdist compression metadata beyond member safety/closure | `tests/check_reproducible_build.py::sdist_container_audit`<br>`tests/check_reproducible_build.py::reproducibility-checks` | `sdist-presentations:2/2` | Out of scope; the candidate gate owns exact source membership, root identity, safe types/modes, source-managed bytes, and byte-reproducible derived wheels. |
| ADJ-R14-R6-13-TOOLCHAIN-IDENTITY | ENFORCED | Interpreter/toolchain identity | `build-toolchain.json`<br>`tests/check_reproducible_build.py::checked_toolchain` | `qualified-toolchain-profile:1/1` | Enforced separately by `build-toolchain.json`, uv lock/export checks, and the pinned R02 build gate; this R6 audit does not alter that authority. |

R9 wheel/sdist member-rule parity (19/19 inherited R14 rows):

| Row ID | Disposition | Normalized claim | Bounded authority source | Production/control population | Disposition and bounded authority |
| --- | --- | --- | --- | --- | --- |
| ADJ-R14-R9-01-MEMBER-CLOSURE | ENFORCED | Complete member-set closure against a source-derived expectation | `tests/check_reproducible_build.py::expected_sdist_members`<br>`tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-presentations:2/2` | Enforced by `expected_sdist_members`, including the normalized project root, exactly one top-directory record, every source-managed file, and every canonical parent directory. |
| ADJ-R14-R9-02-CONTAINER-INTEGRITY | ENFORCED | Archive container integrity | `tests/check_reproducible_build.py::sdist_container_audit`<br>`tests/check_reproducible_build.py::wheel_container_audit` | `sdist-presentations:2/2`<br>`wheel-presentations:3/3` | Enforced independently for both families: `sdist_container_audit` verifies gzip CRC32/ISIZE, bounded expansion, rejects gzip trailing bytes, requires block alignment and an end-of-archive marker, and rejects bytes after that marker; `wheel_container_audit` rejects bytes after the ZIP end record before `zipfile` parses members. |
| ADJ-R14-R9-03-ENUMERATOR-AGREEMENT | ENFORCED | Archive member enumeration agreement | `tests/check_reproducible_build.py::assert_sdist_enumerator_agreement`<br>`tests/check_reproducible_build.py::PROPERTY_MUTATION_REGISTRY` | `sdist-presentations:2/2`<br>`sdist-enumerator-controls:all` | Enforced by `assert_sdist_enumerator_agreement`; its deliberate `getmembers()` call is only a negative control, while the bounded `read_sdist_members` reader uses physical header sizes. The append-only property/mutation registry records the corresponding sdist and wheel property, mutation, expected refusal, and per-artifact execution. |
| ADJ-R14-R9-04-COMPRESSION-TIMESTAMP | LIMITATION | Compression method and per-entry DOS timestamp | `tests/check_reproducible_build.py::reproducibility-checks` | `sdist-presentations:2/2`<br>`wheel-presentations:3/3` | Not semantically audited; tar/gzip has different container and member metadata, and the family is bounded by whole-artifact reproducibility. |
| ADJ-R14-R9-05-SAFE-NAMES | ENFORCED | Safe member names | `tests/check_reproducible_build.py::safe_member_name`<br>`tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-members:all` | Enforced by the same `safe_member_name` grammar for every sdist member. |
| ADJ-R14-R9-06-NORMALIZED-DUPLICATE | ENFORCED | Normalized-duplicate rejection | `tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-members:all` | Enforced by the normalized sdist-name set before closure comparison. |
| ADJ-R14-R9-07-CREATOR-TYPE-METADATA | NOT_TRANSFERABLE | Unambiguous creator/type metadata | `tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-members:all` | Cannot transfer literally: ZIP's creator and upper mode word have no tar equivalent. Sdist instead rejects linked and special tar types and requires regular-file or directory type. |
| ADJ-R14-R9-08-TYPE-CORRECTNESS | ENFORCED | Regular-versus-directory type correctness | `tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-members:all` | Enforced by `TarInfo.isfile()`/`TarInfo.isdir()` and the source-derived closure. |
| ADJ-R14-R9-09-CANONICAL-NAME-SPELLING | LIMITATION | Canonical name spelling | `tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-directory-members:all` | Deliberately not enforced as a ZIP-equivalent slash rule: tar permits a directory type with or without a trailing slash, and the sdist closure canonicalizes the relative directory member; type, root, safe name, and closure remain authoritative. |
| ADJ-R14-R9-10-DIRECTORY-EMPTY | ENFORCED | Directory members empty | `tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-directory-members:all`<br>`sdist-control:nonempty-directory` | Enforced: every directory tar member must have size zero; the R9 control keeps directory type and changes only its size/payload. |
| ADJ-R14-R9-11-PERMISSIONS | ENFORCED | Permission validation | `tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-members:all`<br>`sdist-control:permission` | Enforced as exact regular-file `0644` and directory `0755` modes. |
| ADJ-R14-R9-12-PAYLOAD-BYTES | ENFORCED | Payload size, digest, and bytes | `tests/check_reproducible_build.py::sdist_payload_audit`<br>`tests/check_reproducible_build.py::sdist_member_closure_audit` | `source-managed-sdist-members:all`<br>`sdist-directory-members:all` | Enforced for every source-managed regular-file member by `sdist_payload_audit`; directory payloads are separately required to be empty. |
| ADJ-R14-R9-13-ROOT-IDENTITY | ENFORCED | Root/prefix identity | `tests/check_reproducible_build.py::sdist_distribution_root`<br>`tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-presentations:2/2` | Enforced by the normalized project-name/version root check; the one-root PAX-safe rename control retains identical relative members before the diagnostic. |
| ADJ-R14-R9-14-RECORD-MEMBERSHIP | NOT_TRANSFERABLE | RECORD membership, digest, and size | `tests/check_reproducible_build.py::sdist_generated_metadata_audit` | `generated-sdist-members:7/7`<br>`sdist-pair:2/2` | Cannot transfer: sdist has no ZIP `RECORD`; generated sdist metadata is instead closed and reproducibility-bound by `sdist_generated_metadata_audit`. |
| ADJ-R14-R9-15-RECORD-SELF-ROW | NOT_TRANSFERABLE | RECORD self-row digest and size empty | `tests/check_reproducible_build.py::record_self_row_empty_control`<br>`tests/check_reproducible_build.py::sdist_generated_metadata_audit` | `wheel-control:record-self-row:1/1`<br>`generated-sdist-members:7/7` | Cannot transfer: sdist has no ZIP `RECORD`; the wheel-only branch is exercised independently by the valid-CRC self-row mutation control. |
| ADJ-R14-R9-16-FORBIDDEN-TEST-AUTHORITY | NOT_TRANSFERABLE | Forbidden test/fixture authority paths | `tests/check_reproducible_build.py::expected_sdist_members`<br>`tests/check_reproducible_build.py::wheel_archive_audit` | `sdist-source-authority-members:all`<br>`wheel-presentations:3/3` | Deliberately not transferred: the sdist must contain tests, fixtures, wheelhouse inputs, and checker authority for reproducible source testing; the wheel alone refuses those paths. |
| ADJ-R14-R9-17-ZIP-PREFIX-GRAMMAR | NOT_TRANSFERABLE | ZIP data-root and dist-info prefix grammar | `tests/check_reproducible_build.py::sdist_distribution_root`<br>`tests/check_reproducible_build.py::sdist_member_closure_audit` | `sdist-root-presentations:2/2` | Cannot transfer literally: tar has one project root rather than ZIP's `.data`/`.dist-info` presentation roots; the normalized root and exact source closure are the sdist authority. |
| ADJ-R14-R9-18-RESOURCE-PRESENTATIONS | ENFORCED | Package/external resource projections and semantic directories | `tests/check_reproducible_build.py::resource_audit`<br>`tests/check_reproducible_build.py::wheel_resource_audit` | `source-and-sdist-authority:2/2`<br>`wheel-presentations:3/3`<br>`wheel-resource-roots:2/2` | Enforced after extraction by the shared production-resource audit and source/sdist equality checks; the sdist itself carries the complete source authority rather than two wheel presentations. |
| ADJ-R14-R9-19-ZIP-METADATA | NOT_TRANSFERABLE | ZIP comments and per-entry metadata | `tests/check_reproducible_build.py::sdist_container_audit`<br>`tests/check_reproducible_build.py::reproducibility-checks` | `sdist-presentations:2/2` | Literal ZIP comments and extra fields do not transfer; tar has per-member metadata equivalents such as uid/gid/uname/gname/mtime and PAX headers. PAX logical size is cross-checked against the physical member header; other metadata remains bounded by whole-artifact reproducibility. |

R14/R15 registry-mechanism disposition (6/6 new R15 boundary rows):

| Row ID | Disposition | Normalized claim | Bounded authority source | Production/control population | Disposition and bounded authority |
| --- | --- | --- | --- | --- | --- |
| ADJ-R15-B01-REGISTRY-FAMILY | ENFORCED | Which registry covers which family | `tests/check_reproducible_build.py::PROPERTY_MUTATION_REGISTRY`<br>`tests/check_reproducible_build.py::_REQUIRED_SDIST_AUDIT_CALLS`<br>`tests/check_reproducible_build.py::assert_production_audit_completeness` | `artifact-families:2/2`<br>`production-audit-kinds:12/12`<br>`sdist-call-identities:9/9` | The property/mutation registry (`PROPERTY_MUTATION_REGISTRY`, sealed by a content digest, the literal `FROZEN_REQUIRED_ROW_IDS` existence set, and the `FROZEN_MINIMUM_ROW_COUNT` floor) covers both sdist and wheel families by `(family, audit_kind)` row. The call-site wiring registry (`_REQUIRED_SDIST_AUDIT_CALLS`, sealed by `FROZEN_REQUIRED_SDIST_AUDIT_CALL_COUNT` and bidirectional membership) covers only the sdist enumeration/payload/extraction/generated-metadata call sites. `assert_production_audit_completeness` requires the enumerated production audits and the registry rows to be a bijection on `(family, kind)`, so a production audit with no registered mutation, or a mutation with no production audit, is a named gate failure. |
| ADJ-R15-B02-COVERAGE-BINDING | ENFORCED | What the coverage assertion binds | `tests/check_reproducible_build.py::records_audit_effect`<br>`tests/check_reproducible_build.py::assert_property_registry_coverage` | `artifact-presentations:5/5`<br>`production-audit-kinds:12/12` | Coverage binds each production audit's reachability, recorded from inside the audit on completion and keyed on the artifact's path and content digest, not on a wrapper label. The audit's body-level property is bound by its registered mutation; `assert_production_audit_completeness` reconciles the two so no reached audit body is left unexercised. |
| ADJ-R15-B03-PRODUCTION-REGISTRATION | ENFORCED | Production audits and their registration | `tests/check_reproducible_build.py::register_production_audit`<br>`tests/check_reproducible_build.py::assert_production_audit_completeness` | `artifact-presentations:5/5`<br>`production-audit-kinds:12/12` | Every production audit is enumerated by its `records_audit_effect` decorator and carries a registry mutation: sdist container/enumerator/payload/closure and wheel container/archive/record/resource/module/installed. `installed_wheel_audit` and the `resource_audit`-driven `wheel_resource_audit` run on all three shipped wheels and are registered; none audits a shipped artifact outside the registry. |
| ADJ-R15-B04-WHEEL-DECOMPRESSION | LIMITATION | Wheel decompression bound | `tests/check_reproducible_build.py::MAX_SDIST_TAR_PAYLOAD_BYTES`<br>`tests/check_reproducible_build.py::MAX_SDIST_EXPANSION_RATIO`<br>`tests/check_reproducible_build.py::wheel_archive_audit` | `sdist-reader-bounds:2/2`<br>`wheel-presentations:3/3` | Not separately enforced, recorded as a limitation. `MAX_SDIST_TAR_PAYLOAD_BYTES`/`MAX_SDIST_EXPANSION_RATIO` bound the sdist reader; the wheel reader (`archive.testzip()` and the `archive.read(...)` sites) has no equivalent decompression cap. The shipped wheel is bounded by reproducible direct/sdist-derived byte identity (`52d55153...`), the source-derived member closure, and the pinned clean build from pinned source rather than attacker-supplied bytes; a wheel decompression cap is a residual, not an enforced property. |
| ADJ-R15-B05-COMPLETE-GATE | ENFORCED | Complete-gate regressions on the release path | `tests/check_reproducible_build.py::_REQUIRED_COMPLETE_GATE_REGRESSIONS`<br>`tests/check_reproducible_build.py::assert_complete_gate_regressions` | `nested-complete-gate-regressions:2/2`<br>`release-path:default-no-flags` | Enforced: the default no-flag invocation runs both nested complete-gate regressions and `assert_complete_gate_regressions` refuses if either is not observed. `--r13-skip-regressions` is the nested-gate recursion guard and a diagnostic skip, and the terminal line states its regression mode positively rather than by the absence of PASS lines. |
| ADJ-R15-B06-APPEND-ONLY | ENFORCED | Append-only enforcement | `tests/check_reproducible_build.py::FROZEN_REQUIRED_ROW_IDS`<br>`tests/check_reproducible_build.py::FROZEN_MINIMUM_ROW_COUNT`<br>`tests/check_reproducible_build.py::FROZEN_PROPERTY_MUTATION_REGISTRY_SHA256` | `property-mutation-rows:14/14` | Enforced by the declared existence set (`FROZEN_REQUIRED_ROW_IDS`) and count floor (`FROZEN_MINIMUM_ROW_COUNT`) alongside the content digest, so a row removal that recomputes the digest is refused by name; a same-commit edit of the declared anchors is a visible weakening, not a silent one. |

<!-- R16-15-ADJACENT-ROWS:END -->

The reproducible-build gate requires an execution `TMPDIR` outside `/tmp`,
prints `/tmp` free space at startup, and injects that same directory into the
environment passed to every uv, build, test, lint, and nested regression
process. `TMPDIR` is intentionally not a frozen build-toolchain authority
assignment: it is run-specific scratch placement, while the toolchain's
allowlisted assignments remain reproducible inputs. A qualification record
must retain the printed `/tmp` baseline free-space value and the exact TMPDIR.

The `check_container=False` argument is a test-only differential seam. It is
used solely to isolate the stock-versus-bounded enumeration control after the
independent container audit has already been exercised; no production archive
path invokes the bypass. The call-site wiring registry (`_REQUIRED_SDIST_AUDIT_CALLS`)
requires the production enumeration, payload, extraction, and generated-metadata
audits; the container and member-closure audits are not members of it - they are
covered by their `container` and `closure` property/mutation registry rows. The
`relative-enumerator` label is a member of the call-site registry but is reached
through a negative control, not a production path.

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
