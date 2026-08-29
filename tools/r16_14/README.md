# R16-14 leaf interface

`sdist_call_set.py` parses `tests/check_reproducible_build.py` as inert source
and enumerates every `run_sdist_audit()` call. It never imports or executes the
audited tree. Each observed row binds the literal identity to its enclosing
function, resolved lambda target, decorator-declared audit effect, and a stable
SHA-256 locator over the exact call AST.

`fixtures/sdist-call-ledger.json` is the 9-of-9 implementation input copied from
the controlling criteria and bound to the isolated candidate source. Its
`candidate-mirror-not-final-authority` status is intentional: an eligible
non-implementer must freeze the final external authority after serial
integration. Changing the candidate-local required set or floor does not alter
this input.

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
