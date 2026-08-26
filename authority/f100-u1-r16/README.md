# F100 U1 R16 external-authority candidate

This directory is a builder-produced correction candidate for **R16-6, R16-7,
R16-9, R16-12 and R16-13**. It is not a grade, admission or release verdict.
Its verifier deliberately returns `VERIFIED_NOT_GRADED`; an independent session
must ratify the population and digest, and the trusted operator launcher must
consume the ratified external copy before any candidate process starts.

## Authority boundary

The copy of this directory in a candidate export is never authority. Materialize
the candidate and the authority commit into disjoint exports, obtain the exact
`authority.json` SHA-256 from a release-owner record outside the candidate, and
execute the verifier from the authority export:

```sh
python3 -I -B /external-authority/tools/f100_u1_r16_external_authority.py verify \
  --candidate-root /disposable-candidate \
  --authority-root /external-authority/authority/f100-u1-r16 \
  --authority-sha256 "$OWNER_PINNED_AUTHORITY_SHA256"
```

The verifier refuses a Git worktree, a candidate-local authority path, a
non-canonical manifest, or a missing/mismatched explicit digest pin. It parses
the candidate gate as data and never imports or executes candidate code. An
exact public archive commit plus an owner-published manifest digest is the
intended immutable carrier. A work ref or an unpinned local copy is insufficient.

This preflight still needs integration into the shared trusted launcher. Direct
invocation proves the facility's comparison result only; it is not yet the full
operator path and cannot close any row by itself.

## Bounded populations

### R16-6 / R16-7 — external append-only history

The historical population is the ordered 12-row registry at candidate gate SHA
`b6688d289db61d2c2dabe0e0a4a6a65a6ed5cb4c8d214600ca8a984fc8d20386`.
It was enumerated from five Git snapshots spanning R14 through the final R15
candidate: row counts 8, 9, 10, 12 and 12. Order is semantic. The external
manifest freezes every field of every row, every snapshot's commit/tree/gate
and registry digest, and five history-critical definitions, including the
row-to-mutation executor. Removal of an old R14 row, removal of the new R15
wheel-module row, reorder, alias, duplicate ID, same-ID semantic change, or
no-op executor replacement therefore fails closed without trusting restatable
candidate constants.

The builder tests establish those structural refusals. The frozen requirement's
full-operator-path mutations remain dependent on the trusted launcher consuming
this separately pinned preflight. `f100_u1_r16_authority_mutations.py` makes the
seven pre-registered history shapes reproducible in exact disposable exports;
the old- and new-row removal cases recompute the candidate-local digest, ID set
and count floor, proving those restatable anchors cannot satisfy the external
comparison.

### R16-9 — independently frozen P3 input

The proposed P3 population has 10 audit definitions: four sdist and six wheel.
It was not derived from decorators or registry rows. Starting at `main`, the
enumerator forms a fixed point over direct calls and module-function references
passed through arguments/callbacks, then inventories every syntactic call in
the reached owners, including nested functions and lambdas. That produces
1,603 structural call sites in 94 reached owners, digest
`00960881be2a27fe548c6eacfc50aacb3cb847846551b6e62cb0f5866e25e6eb`.
Only after freezing that population are the 10 audit bodies classified and
joined to the registry's 10 `(family, kind)` pairs.

The tests exercise both required directions for all 10 entries: 10 cases with
the production audit call hollowed while its registration/label remains, and
10 cases with the audit retained while every assignment for its pair is
removed. They also add one reachable, undecorated audit to prove the population
does not depend on decorator self-declaration. These are 20 structural
preflight cases plus the added-audit case; none is represented as a completed
full-operator run. Independent ratification of the proposed P3 classification
is mandatory because its builder cannot grade its own census.

Together with the seven history shapes, the reusable mutation generator has a
closed 27-case preflight population. All 27 were executed against the external
verifier in disposable exports and refused by their registered history/P3 code;
that facility-level result still awaits launcher-path execution and independent
grading.

### R16-12 — digest-bound transcript and lane census

The evidence population is explicitly one lane execution of the R15
candidate-owned gate or setup harness. It contains 17 unique lane IDs: arms
1–12, the pre-arm10 wrapper, both P0 lanes and both P1 lanes. Fourteen entered
the gate. It is not the whole-R15 population, which is at least 20 once the
three separately reported independent full gates are included.

Both the transcript snapshot and canonical census travel by byte count and
SHA-256 in `authority.json`. Digest-binding preserves evidence; it does not
turn prose into truth. The transcript's lines 157–166 assert arm12 `rc=0`, while
the later adjudication correctly records that no run-bound exit status exists.
The census retains `rc=null`, declares this as one evidence conflict, and gives
the transcript no credit on that point. The transcript is also not a raw-log
entry for all 17 lanes. Therefore this bundle makes the bounded evidence stable
for re-review but does not retroactively satisfy predicate 3.

### R16-13 — necessity/sufficiency pair

The pair population is exactly the two ordered obligations in R15-3, frozen in
`r15-3-pair-plan.json` before either full gate began:

1. necessity: keep the wheel-RECORD decorator, registration and labels, hollow
   `record_audit` only after both nested regressions, and require the exact
   self-row negative control to report that the hollow audit unexpectedly
   passed; and
2. sufficiency: keep the exact `record_audit` body running directly on all three
   production wheels, remove only its three registration/lambda labels, and
   require the complete gate to remain green rather than falsely reporting the
   audit absent.

The mutation tool accepts only the exact input gate, refuses a Git worktree and
writes only a requested disposable export. The execution population is three:
two valid obligation cases and one preserved invalid construction. Necessity
returned `rc=1` by the exact pre-registered `wheel RECORD self-row empty control
unexpectedly passed` refusal after both nested regressions; no terminal overall
PASS appeared. The first sufficiency construction was discarded when its R13
source needle occurred twice. Amendment 1 was frozen before v2, and v2 returned
`rc=0` with the exact terminal overall PASS, all three installed-wheel probes,
and no false `production audit did not run` refusal. `r15-3-pair-results.json`
cross-pins all three logs, patches, mutation records, exit codes and plan hashes.

These are direct full-gate builder results on the exact R15 subject gate. They
remain evidence for independent review, never self-credit, and they do not
substitute for the still-unadmitted trusted-launcher operator path.

## Current disposition

No R16 row is admitted by this bundle. External owner publication, independent
population ratification, trusted-launcher integration, and independent grading
remain separate acts. The arm12 transcript/census conflict is intentionally
visible rather than reconciled by editing historical bytes.
