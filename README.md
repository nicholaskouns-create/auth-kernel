# Authorization kernel

> **Main entry portal:** [The Mathematical City](https://nicholaskouns-create.github.io/website/) — explore the districts, interactive labs, and research index.
>
> **[Explore PiP Manta](https://nicholaskouns-create.github.io/E47-Kartekeya/interfaces/pip-manta/embed.html)**

Invoke requires Candidate, the syntactic gate, a live nonce, an active subject, and a requester who is that subject's bound principal.

A valid signature observes. It does not derive Invoke.

One ledger holds authority. ALLOW checks, re-verifies HMAC-SHA256, and spends the nonce in one locked step, so a spent nonce, a revocation, or an amnesty binds every later decision. Refusal does not write.

The issue record stores the canonical JSON body, including arguments.

```
python auth_kernel.py
python validation/authorization_invariant_20261008.py
```

Rules: `RULES.txt`. Implementation: `auth_kernel.py`. Reference model and invariant tests: `validation/`.

## Transaction intent defense

[Transaction intent preservation](proofs/TRANSACTION_INTENT_DEFENSE.md) applies
this kernel to agent-initiated payments, states the invariant and integration
obligations, and distinguishes authorization from external settlement.

Run the transaction regression checks against the implementation:

```sh
python -m unittest discover -s validation -p 'test_transaction_intent.py' -v
```
