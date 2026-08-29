# F100 U1 R16 external-authority candidate

This directory is a builder-produced correction candidate for **R16-6, R16-7,
R16-9, R16-12, R16-13, R16-14, R16-15 and R16-16**. It is not a grade,
admission or release verdict.
Its verifier deliberately returns `VERIFIED_NOT_GRADED`; an independent session
must ratify the population and digest, and the trusted operator launcher must
consume the ratified external copy before any candidate process starts.

## Authority boundary

The copy of this directory in a candidate export is never authority. Materialize
the candidate and the authority commit into disjoint exports, obtain the exact
`authority.json` SHA-256 from a release-owner record outside the candidate, and
execute the verifier from the authority export:

```sh
python3.12 -I -B /external-authority/tools/f100_u1_r16_external_authority.py verify \
  --candidate-root /disposable-candidate \
  --authority-root /external-authority/authority/f100-u1-r16 \
  --authority-sha256 "$OWNER_PINNED_AUTHORITY_SHA256"
```

The credited interpreter envelope is CPython 3.12 and 3.13. Generic
`python3` and the project's broader Python 3.10 support range are not claims
for this verifier.

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

The historical population is the ordered 14-row registry at candidate gate SHA
`a3eddb7eeaad5f0f838f40f2a20e432ef4264b31936cbedff4c87b48306dd2f0`.
It was enumerated from eight Git snapshots spanning R14 through the corrected
R16 candidate: row counts 8, 9, 10, 12, 12, 14, 14 and 14. Order is semantic.
The external
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

The proposed P3 population has 12 audit definitions: five sdist and seven wheel.
It was not derived from decorators or registry rows. Starting at `main`, the
enumerator forms a fixed point over direct calls and module-function references
passed through arguments/callbacks, then inventories every syntactic call in
the reached owners, including nested functions and lambdas. That produces
1,625 structural call sites in 94 reached owners, digest
`6566ea1d0780192c464450bcaf84177bd6fec8ba71a522b8ab47b8602f1db81a`.
Only after freezing that population are the 12 audit bodies classified and
joined to the registry's 12 `(family, kind)` pairs. The correction includes
`sdist_generated_metadata_audit` and `resource_audit`, each with a distinct
append-only mutation assignment.

The tests exercise both required directions for all 12 entries: 12 cases with
the production audit definition made absent while its registration/label and
all calls remain, and 12 cases with the audit retained while every assignment
for its pair is removed. Definition absence is causal: no nested route can
still resolve to the named audit. They also add one reachable, undecorated
audit to prove the population does not depend on decorator self-declaration. These are 24 structural
preflight cases plus the added-audit case; none is represented as a completed
full-operator run. Independent ratification of the proposed P3 classification
is mandatory because its builder cannot grade its own census.

Together with the seven history shapes, the reusable mutation generator has a
closed 31-case preflight population. All 31 were executed against the external
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

The verifier also binds every one of the 17 frozen disposition labels to its
exact `(gate_started, rc)` state. Unknown labels refuse, and changing any clean,
expected-refusal, defect, harness-invalid or retired lane to a disposition that
contradicts its recorded state refuses even if the census and all enclosing
digests are canonically repinned. This generalized semantic check corrects the
ordinary-lane upgrade gap; it does not repair the historical evidence boundary
described above.

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

The verifier's semantic log population is all three retained executions:
necessity, discarded sufficiency v1 and final sufficiency v2. In each log the
declared terminal must occur exactly once and be the final nonempty line, the
case's planned forbidden fragment must be absent, and `Traceback` must be
absent. The causal log calibration population is 6 of 6 canonically repinned
mutations: 2 of 2 final obligations crossed with 3 of 3 forbidden-fragment,
traceback and post-terminal wrong-reason classes.

The 3 of 3 retained mutation records now use the same complete-field AST encoder
under 2 of 2 credited interpreters. For every record, the verifier applies the
retained patch to the candidate gate by exact hunk content and independently
recomputes 2 of 2 claimed `record_audit` definition hashes, before and after the
patch. Its 2 of 2 causal controls replace either hash, canonically repin every
enclosing record, and refuse under distinct before/after definition-drift codes.
This corrects R16-13-M02 and M03; it does not repair M01's historical
chronology/exit-status boundary.

These are direct full-gate builder results on the exact R15 subject gate. They
remain evidence for independent review, never self-credit, and they do not
substitute for the still-unadmitted trusted-launcher operator path.

### R16-14 — pinned nine-call candidate mirror

The manifest pins the 9-of-9 sdist-call ledger and the external copy of its
inert-source enumerator. The verifier independently re-enumerates the exact
candidate gate, checks exact call-set equality, and binds the gate's 9-of-9
runtime-event mirror. The ledger remains marked
`candidate-mirror-not-final-authority`: an independent final freeze is 0 of 1,
trusted-path runtime traces are 0 of 9, and the 14-of-14 causal campaign has not
run through the trusted default path.

### R16-15 — externally pinned adjacent-row population

The manifest pins the separately prepared `r16-15-adjacent-row-ledger.json`
and the external copy of `tools/f100_u1_r16_15_adjacent_rows.py`. The disjoint
verifier uses those external bytes to compare the candidate README; it never
imports or executes the candidate's checker. The exact population is 38 of 38
rows: 13 of 38 inherited R6 rows, 19 of 38 inherited R9 rows and 6 of 38 R15
boundary rows.

The verifier executes 38 of 38 named row-deletion mutations and 5 of 5 static
boundary mutations covering local count restatement, disposition change,
authority retarget, duplicate ID and alias ID. Those 43 of 43 facility-level
mutations are not trusted-launcher results. The acceptance criteria's distinct
mechanism-removal control remains 0 of 1, the eligible reviewer's independent
38-of-38-row re-derivation remains 0 of 1, and runtime acceptance remains 0 of
1.

### R16-16 — separated accounting populations

The manifest pins the proposed accounting authority, the external accumulator
and the external pipe observer. It binds 32 of 32 mutation invocations, 12 of
12 effect classes, 5 of 5 presentations and 2 of 2 shipped byte-identity groups,
and checks that the candidate gate's event scope and presentation map are
exactly equal. Under OD-20 the gate accepts only 2 of 2 distinct writable
pipe/socket descriptors; it refuses the 2 of 2 legacy path variables, regular
files, character devices and duplicate channels. The external observer validates
both records directly from the 2 of 2 pipe byte streams before any preservation
copy exists. Runtime results remain 0 of 1 and all 7 of 7 trusted-path causal
controls remain outstanding; the leaf tests are static facility evidence only.

## Current disposition

No R16 row is admitted by this bundle. External owner publication, independent
population ratification, trusted-launcher integration, and independent grading
remain separate acts. The arm12 transcript/census conflict is intentionally
visible rather than reconciled by editing historical bytes.
