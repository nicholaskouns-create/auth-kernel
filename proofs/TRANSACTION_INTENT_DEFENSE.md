# Transaction intent preservation at the confused-deputy boundary

Status: application of the existing authorization kernel, with executable
regression checks; not a production banking integration. 2026-10-22.

## Threat and defense

An agent may possess valid credentials and use an encrypted channel while
requesting a transfer its principal never authorized. Authentication identifies
an actor; it does not establish permission for this particular transaction.
Retrieved text, invoices, tool responses, and model-generated plans are proposals,
not sources of authority. Neither a valid signature nor semantic coherence alone
implies Invoke.

The defense binds each approved operation to an exact transaction description and
checks the live authorization ledger at the side-effect boundary. It extends the
existing confused-deputy formulation to transaction arguments without replacing
cryptography or introducing a separate governing authority.

## Formal statement

Let an approved record contain the canonical argument tuple

    T = (task_id, source_account, recipient, currency, amount_minor)

and the existing subject, tool, issuer, nonce, and validity window. The trusted
issuer must validate this tuple against the principal's actual authorization
before issuing it. Amounts are positive integer minor units of an explicitly
specified currency; account and recipient identifiers must identify resolved
accounts, not mutable display names.

For the existing ledger Sigma, the executable kernel enforces:

    ALLOW(d, requester, Sigma)
      => Issued(d) and InWindow(d) and ToolOk(d) and ArgsOk(d)
         and Active(subject(d)) and Bound(d, requester)
         and Fresh(d) and ValidSig(d)

Issued compares the entire canonical record with the stored issue record. Thus
changing any component of T invalidates that issue record, even if the changed
record is freshly signed by the same issuer. Successful ALLOW atomically spends
the nonce under the ledger lock; another use of that nonce cannot succeed.

For a sequence of actions, the conditional invariant is:

    Every dispatched action equals its own independently authorized record,
    and each authorization nonce is consumed at most once.

The induction is per action: if the dispatcher checks and consumes authority for
the exact action it sends, adding that action preserves the property for the
sequence. A previous approval never authorizes the next action by implication.
This is a logical constraint invariant; it does not require projecting a payment
into the E47 spectral kernel.

## Integration obligations (not implemented by this repository)

1. The issuer, principal authentication, keys, ledger, clock, and dispatcher must
   be outside agent-controlled input. A requester string supplied by the model
   is not authenticated identity. Issuing whatever the model proposes defeats
   the defense even when all signatures verify.
2. Bind task_id to trusted execution context as well as the signed arguments.
   The kernel preserves the argument value but cannot detect replay into another
   task before first use if the adapter ignores the actual task context.
3. Validate the complete transaction schema before issuance. The core ArgsOk
   checks required keys and size; it does not enforce banking types, balances,
   account ownership, currency semantics, or cumulative spending limits.
4. Dispatch an immutable snapshot of precisely the validated arguments. The
   Record's nested dictionary is mutable; do not share it with an agent or allow
   mutation between verification and dispatch. No alternate transfer path may
   bypass this check.
5. Keep nonce consumption and a durable dispatch/outbox record in one database
   transaction, and pass a bound idempotency key to the payment provider. The
   current in-memory lock only establishes at-most-once authorization in one
   process. It does not guarantee exactly-once external settlement or survive
   restart. An uncertain provider result needs reconciliation, not a new nonce.
6. Enforce any cumulative budget atomically across all relevant records. Exact
   amount binding prevents substitution, but two separately issued records can
   still exceed a budget if the trusted issuer/ledger does not reserve it.

Revocation is evaluated at authorization time. A later revocation cannot undo an
already submitted payment. Prompt injection remains possible in the agent's
reasoning; under these integration assumptions it cannot expand execution
rights merely by rewriting a plan or presenting a signed credential.

## Reproduce the bounded evidence

From the repository root:

    python -m unittest discover -s validation -p 'test_transaction_intent.py' -v
    python auth_kernel.py
    python validation/authorization_invariant_20261008.py

The added tests exercise the actual auth_kernel implementation: exact transfer
acceptance, individual field substitutions (including re-signed substitutions),
wrong principal, time boundaries, revocation, invalid signatures, refusal without
nonce consumption, and concurrent replay. These are regression checks of the
stated kernel properties, not evidence that a bank deployment or cryptographic
primitive has been secured or broken.
