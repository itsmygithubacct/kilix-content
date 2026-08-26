# R15 mutation transcripts (R15-10 evidence)

Per-control mutation evidence against the final code tip. The recorded
mutations reach the stated exact refusals, with the known nulls and discards
below. Function-level; gate-level transcripts are the arm runs (arm2 R15-1
end-to-end, arm4 R15-2/3, arm7 R15-4). Registry: 12 rows,
FROZEN=d0c05c659548a256...

## R15-10 predicate 1 — UNPROVABLE from machine-recorded order

**Disposition: UNPROVABLE for R15; do not credit predicate 1.**

This disposition was derived from Git objects, not author attestation or file
times. The inspected ancestry is
`5c2817f4c7d69c7c31b3d3acd72e23dc93de45fc..ebd7d7f43399aa05fbacd57b3a0d66739891eded`
on `work/0.2.1-content-u1-r15-core`; the final tree is
`ef1dfe0069acb8446fe223bbca5a22f2f1d92bc6`. For each stable source marker,
`git log --reverse -S` was used to locate its first changed checker blob. The
branch reflog and unreachable commit objects were also inspected so that the
two pre-amend R15 commits were not silently omitted.

| Item | Machine-recorded Git order | Result |
| --- | --- | --- |
| R15-1 | The `wheel.module.source-byte` mutation executor and `wheel_module_source_audit` first appear together in `c5a86aabd98bfd5eae93bd375d362c465d508870`. | Same snapshot; no before relation is recorded. |
| R15-2 | `assert_wheel_member_closure` first appears in pre-amend commit `8bb9dac9485c850a8f9fb133f02f1422798f725e` and remains in amended commit `b3827a5ed197b1df43733d8c65cfb5a4e41bea46`. The earlier object already contains the control; there is no committed mutation-only predecessor. | No pre-control mutation object. |
| R15-3 | `records_audit_effect` first appears in `ac799480d3cf8f5e72346b40b181147eb7ad3403`; the narrated hollow/no-op mutation has no committed snapshot. | No machine-recorded mutation order. |
| R15-4 | The `wheel.installed.manifest` mutation executor/row and `assert_production_audit_completeness` first appear together in `2066af2870b3ec2133fa91835fa0aceecd47abd4`. | Same snapshot; no before relation is recorded. |
| R15-5 | `FROZEN_REQUIRED_ROW_IDS` and the count anchor first appear in `8b0c0843a2afc87afa5e787a865f92db2a301f0b`; no committed row-removal-plus-digest-rewrite mutation precedes them. | No pre-control mutation object. |
| R15-6 | The observation set and `assert_complete_gate_regressions` first appear in pre-amend commit `d5a056bbeb2f170a5d8823679802a8756c551502` and remain in amended commit `9475c384eab550ed5d3f10e38de4f9519187003c`. The earlier object already contains the control; no committed deleted/no-launch mutation precedes it. | No pre-control mutation object. |
| R15-7 | The prepend/appended-ZIP mutation executors and the new central-directory invariant first appear together in `a45dde44af13cd0ee140adf1637c03330d87abef`. | Same snapshot; no before relation is recorded. |
| R15-8 | The code-side count, execution-accounting and self-row-observation controls first appear in `31e5b5f7bd7d664e4bd7a6ea78f8e2dd09b2c70c`; no earlier mutation-only commit records the narrated deletion cases. The later documentation commit `2284957bf40f736d08da577e9d0ee594a62d745a` does not supply code-authoring order. | No pre-control mutation object. |

Git records whole file blobs at commit boundaries, not the order in which lines
were written inside one commit. A same-commit pair therefore cannot prove
mutation-before-control, and the after-the-fact transcript cannot fill that
gap. Because predicate 1 requires the relation for **each** added control, the
missing machine record makes the predicate unprovable for this R15 round rather
than pending or satisfied.

## R15-1 / F3 - wheel importable-module bytes bound to source
```
MUTATION: backdoored install.py (exports preserved, RECORD repaired, single ZIP)
  (see per-wheel below)
  backdoored install.py -> REFUSED -> wheel module source is absent: __init__.py
NULL/DISCARD: GI-marshalling hypothesis discarded - get() returns real bytes, not a list
```

## R15-2 / CTL-R14-01 - wheel member-set closure absence observable
```
MUTATION: extra wheel member; closure optional (the R13-M01 hole)
  wheel_archive_audit(mut) [expected OMITTED] -> PASS (no refusal)
  wheel_archive_audit(mut, expected)          -> REFUSED -> wheel complete member set differs: expected_count=14 observed_count=15 missing=[] extra=['evil.txt']
  assert_wheel_member_closure (closure absent) -> REFUSED -> production wheel member-set closure was not performed: label=direct wheel 1
NULL/DISCARD: label-only keying rejected - would collapse under identical digests (root note)
```

## R15-3 / CTL-R14-02 - coverage binds audit reachability, not the label
```
MUTATION: record audit hollowed (action never reaches the audit) -> its effect absent
  coverage {wheel:{label:clean}} -> REFUSED -> production audit did not run on the shipped artifact: family=wheel label=direct wheel 1 kind=record
FRAMING: reachability only; a reached no-op body still records - the registry
mutation catches a hollow body, R15-4 reconciles the two.
```

## R15-4 / CTL-R14-03 - unregistered production audit is a named failure
```
MUTATION: an enumerated production audit with no registry row (installed, before its row)
  assert_production_audit_completeness -> REFUSED -> production audit has no registered mutation: [('wheel', 'installed')]
  restored (installed has its row) -> PASS (no refusal)
GATE-LEVEL: arm7 exercises the install-based mutation end to end (its own reason).
```

## R15-5 / CTL-R14-04 - append-only existence + count anchor
```
MUTATION: remove a row AND recompute the content digest (the R14 3-edit weakening)
  digest matches shrunken registry: True; rows=11
  validate -> REFUSED -> append-only property/mutation registry removed a frozen row: ['wheel.record.self-row']

HONEST SCOPE: this demonstrates the three-edit weakening (remove row + delete
audit + recompute the content digest) being REFUSED - not the anchor being
unforgeable. A five-edit weakening that also deletes the id from
FROZEN_REQUIRED_ROW_IDS and lowers FROZEN_MINIMUM_ROW_COUNT passes: both are
in-file values a same-commit edit can restate. The win is turning a silent
three-edit weakening into a visible five-edit one with explicit deletions from a
constant named FROZEN_REQUIRED_ROW_IDS (root recorded this as a boundary, not a
finding). No self-contained gate is unforgeable against a commit that edits it.
```

## R15-6 / CTL-R14-05 - complete-gate regression observation
```
MUTATION: a regression call deleted / returns without launching its nested gate
  none observed -> REFUSED -> required complete-gate regression was not observed: ['r12-reader-reversion', 'r13-callsite-wiring']
  only r12      -> REFUSED -> required complete-gate regression was not observed: ['r13-callsite-wiring']
  both observed -> PASS (no refusal)
```

## R15-7 / F2 - physical wheel container invariant
```
MUTATION: prepend bytes / append a complete ZIP (both pass the old end==len check)
  clean       -> PASS (no refusal)
  prepend     -> REFUSED -> wheel container has bytes outside the central directory record
  appended-zip-> REFUSED -> wheel container has bytes outside the central directory record
```

## R15-8 - the five Lows (each on its own evidence)
```
CTL-R14-07 seal _REQUIRED_SDIST_AUDIT_CALLS:
  clean -> PASS (no refusal)
  remove 1 required (len 8<9) -> REFUSED -> required sdist audit call set shrank below its frozen count: 8 < 9
  extra unregistered call     -> REFUSED -> unregistered sdist audit call sites were reached: ['extra']
CTL-R14-11a execution accounting: 3 invocations over 1 unique artifact -> executions=3 unique=1
CTL-R14-11b record self-row control observed:
  control deleted -> REFUSED -> append-only property/mutation registry removed a frozen row: ['wheel.record.self-row']
CTL-R14-11c _PRODUCTION_ARTIFACTS present: False
CTL-R14-08/09/10: README overclaims corrected + disposition table added (doc audit)
```

## R15-10 discarded harness probes

Exactly four discarded executions are enumerated below: the pre-arm10
archive/setup wrapper, arm10, arm11, and paired-runtime launch P0. All four are
void as candidate or runtime evidence because each failed in the harness before
it could supply the evidence sought:

- **pre-arm10 archive/setup wrapper — discarded:** the wrapper invoked
  `git archive` with the empty disposable directory as its cwd rather than the
  candidate repository. Git refused `not a git repository`, tar rejected the
  empty stream, and no `uv` or checker process launched. This proves only that
  the setup wrapper used the wrong cwd; it supplies no candidate evidence.
- **arm10 — discarded:** `TMPDIR` was a directory beneath the export root.
  The R12 nested regression copied `PROJECT` into that directory, then copied
  the growing destination back into itself until `shutil.copytree` raised
  `ENAMETOOLONG`. This proves only that an in-export scratch root recursively
  contaminates the regression copy. It neither supports nor contradicts any
  candidate property.
- **arm11 — discarded:** `gate.log` was written at the export root. The R12
  child therefore enumerated `kilix_content-0.4.0/gate.log` as an expected
  source member while the built sdist correctly excluded the log, and the
  child refused on that harness-created member-set difference. This proves
  that the sdist closure noticed the extra source file. It does not qualify
  the candidate and is not a candidate defect.
- **paired-runtime launch P0 — discarded:** the parent and tip wrapper jobs
  started within the same millisecond, but the wrapper failed to change into
  either archive export. Both `uv run` processes therefore ran from the corpus
  directory and exited rc=2 because `tests/check_reproducible_build.py` was not
  present there. The external observer also terminated immediately because
  its awk program used a reserved builtin name. Neither gate started, both
  verified exports and both empty external `TMPDIR`s remained unchanged. This
  proves only that the first pair harness was invalid; it supplies no runtime
  or candidate evidence.

The corrected arm12 layout places the export, `TMPDIR`, and transcript in
three sibling paths so neither run-state path is beneath the export.

## Qualification and paired-runtime harness probes

- **arm12 — valid clean qualification probe:** commit `ebd7d7f` ran from
  `/var/tmp/r15-impl-arm12.g4Fv0U/export`; its scratch root was the sibling
  `/var/tmp/r15-impl-arm12.g4Fv0U/tmp` and its transcript was the sibling
  `/var/tmp/r15-impl-arm12.g4Fv0U/gate.log`. The directly captured process
  status was rc=0. The terminal claim was `reproducible offline build and
  package audit: PASS (complete-gate regressions observed:
  r12-reader-reversion, r13-callsite-wiring)`, both wheel paths reported
  `52d551532f280bb5eb9e3da2c47d7078c2967e521bbe882b482fd67935527810`,
  and no traceback or wrong-reason line appeared. This is a green clean
  qualification execution; by itself it does not re-prove each R15 credit or
  supply R15-9's paired runtime.
- **paired-runtime launch P1 — valid but work-asymmetric probe:** parent
  `5c2817f` and tip `ebd7d7f` started on the same host with the same default,
  no-flag invocation 236,586 ns apart according to their `start_ns` records.
  Parent completed rc=0 in 1,224.810776548 s; tip completed rc=0 in
  2,604.146298803 s; the observed difference was 1,379.335522255 s. This is
  not a like-for-like performance comparison: the parent default path did not
  run the R12/R13 complete-gate regressions, while R15-6 made the tip default
  path run both. A one-second-cadence external process observer measured the
  tip's R12 child active for an observed 399.983912706 s span and its R13 child
  for an observed 1,159.649630785 s span. The tip reported both regressions
  `FAIL-CLOSED/PASS`, the same wheel digest as arm12, and no traceback or
  wrong-reason line. Original archive-file manifests remained equal to their
  untouched sibling references after the run (`733cf46b...` parent,
  `d81f2c3a...` tip). Logs, status files, observer timeline, and both `TMPDIR`s
  were outside the exports. This controlled but work-asymmetric measurement is
  evidence for reviewer evaluation; it is not recorded here as satisfying
  frozen R15-9 requirement 4.
