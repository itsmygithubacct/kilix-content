# R16-14 leaf interface

`sdist_call_set.py` parses `tests/check_reproducible_build.py` as inert source
and enumerates every `run_sdist_audit()` call. It never imports or executes the
audited tree. Each observed row binds the literal identity to its enclosing
function, resolved lambda target, decorator-declared audit effect, and a stable
SHA-256 locator over the exact call AST. Any indirect reference to the
`run_sdist_audit` wrapper is a refusal, so assigning it to an alias cannot hide
an unregistered tenth call from the enumerator.

`fixtures/sdist-call-ledger.json` is the 9-of-9 implementation input copied from
the controlling criteria and bound to the isolated candidate source. Its
`candidate-mirror-not-final-authority` status is intentional: changing the
candidate-local required set or floor does not alter the external authority.

A preparation freeze of the external authority now exists outside the candidate:

```text
0.2.1-F100-R16-14-SDIST-CALL-LEDGER-R1.json
sha256=3292721b7da3b7af40bf5035fc9e8c1f5799576c0bc4e03a745f02fac1587dc3
```

**It was authored by the R16-14 row implementer, so it is preparation, not an
independent seal.** An eligible non-implementer must still ratify or replace it
before the row is graded. What it does establish is checkable now: its nine
semantic bindings were re-derived by a second, independently written AST
enumerator that does not import this leaf, agreeing 36/36 on
`enclosing_function`, `target_function`, `effect_family` and `effect_kind`
across all 9/9 identities, and every one of the 14/14 section 2.3 controls
refuses against it — including `SCALL-RESTATE`, where the candidate-local view
is edited to a self-consistent 8 members and still refuses
`SDIST_CALL_MISSING:direct-payload` against the external file.

The integration lane may use the same schema with
`external-frozen-authority`, then wire the trusted default gate to emit the
events returned by `expected_effect_events()`. Supplying that independently
captured trace to `verify_effect_trace()` proves 9-of-9 required effects were
observed. This leaf does not perform final-gate wiring, create final evidence,
or make a packaging decision.

Run the static check from the repository root:

```sh
python tools/r16_14/sdist_call_set.py \
  --source tests/check_reproducible_build.py \
  --ledger tools/r16_14/fixtures/sdist-call-ledger.json
```
