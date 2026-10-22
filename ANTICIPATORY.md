# White Hats anticipatory instruments

Three optional, local instruments in `anticipatory.py`, with no network calls,
credentials, telemetry, registration, or third-party runtime dependencies.

## Run the workflow forecaster

```sh
python anticipatory.py examples/anticipatory-plan.json
python -m unittest discover -s validation -p 'test_*.py' -v
```

The supplied model enumerates six paths and returns two findings with the complete
trace up to each denial. A finding exits 1; clean completion exits 0; malformed
input exits 2. `--max-paths 1` demonstrates INCOMPLETE, also exit 1. The default
bound is 256 paths; maximum 4096, 64 steps, 64 alternatives per step and 1 MB JSON.
Alternatives are application-declared possibilities, not estimated probabilities.
The monitor stops each modelled path on its first denied action.

## Durable provenance and tool pinning

```python
from anticipatory import ProvenanceLedger

ledger = ProvenanceLedger('provenance.sqlite')  # trusted host-owned local file
ledger.register('statement-1', b'account data',
                classification='confidential', trusted=True)
ledger.derive('summary-1', b'summary bytes', parents=['statement-1'])
decision = ledger.check('summary-1', b'summary bytes', audience='public-site',
                        audiences={'public-site': 'public'})
assert decision == {'allowed': False,
                    'reason': 'classification_exceeds_clearance'}

manifest = {'server': 'statements', 'tool': 'read_statement',
            'endpoint': 'local-adapter', 'version': '1',
            'description': 'Read account statement',
            'input_schema': {'type': 'object'}}
ledger.pin('statements-v1', manifest)  # trusted review/installation operation
assert ledger.check_tool('statements-v1', manifest)['allowed']
assert not ledger.check_tool('statements-v1',
                              {**manifest, 'version': '2'})['allowed']
```

Use fresh artifact IDs and a fresh database when rerunning this example. Registered
IDs and pins cannot be replaced through this API. Store only content hashes and
provenance metadata, not the supplied content itself. Protect metadata as sensitive
where identifiers reveal information. SHA-256 binds bytes; it is not encryption or
proof that the original classification or tool description is truthful.

## Host wiring and exact boundaries

1. The host authenticates actor/task and derives labels and ancestry from actual
   reads, transformations and tool execution. Treat all external text as data.
   `trusted=True` means approved as an instruction source by the host; a factual
   bank statement is not automatically such a source.
2. Record every actual input parent for each output, including cross-task inputs.
   Sharing the host's chosen ledger preserves that ancestry across tasks. Missing
   parents, model-invented labels, registering a derived artifact as a new trusted
   source, or unrecorded copies can bypass the model. The module cannot discover
   hidden data dependencies or implicit flows; instrumentation must supply them.
3. At the side-effect boundary, check the exact immutable bytes being sent, the
   independently approved destination clearance and the currently observed tool
   descriptor. Refuse a denied result; never let model output override it. These
   decisions complement the existing principal/grant checks and do not issue them.
4. Bind the checked bytes/descriptor to the same host adapter used for execution.
   Pinning catches descriptor changes, not a malicious server changing behavior
   while advertising the same descriptor. Transport authentication, code/package
   integrity, destination resolution and confinement remain adapter responsibilities.
5. The forecaster is an offline analyser. It performs no transfer or dispatch.
   A clean result means only NO_FINDINGS_IN_MODEL for the enumerated paths. An
   INCOMPLETE result must not be treated as an approval.

For each derived artifact v with parents p, the implemented invariants are
`level(v) = max(level(p))` and `trusted(v) = all(trusted(p))`. Immutable parent IDs
and insert-only registration give a directed acyclic ancestry graph. Audience
clearance checks therefore preserve explicit sensitivity transitively. There is
no automatic declassification. The host retains authority over all issuance,
classification and execution decisions.

## Reuse

Copy `anticipatory.py` into an existing Python 3.10+ project or install this checkout
with `python -m pip install .`, then use `white-hats-forecast PLAN.json`.
See [the survey and threat-to-test mapping](research/ANTICIPATORY_DEFENSE_SURVEY.md).
The repository's existing LICENSE and NOTICE apply; retain their attribution when
redistributing. No global service or shared supervisory authority is required.
