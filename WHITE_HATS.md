# Auth Kernel — White Hats

An optional durable authorization instrument for agent-initiated transfers.
`white_hats.py` adds SQLite-backed grants and an outbox alongside `auth_kernel.py`.
The existing kernel and its signature rules remain independently usable.

## Enforced properties

- **Durability:** unique nonces, budget debits, and immutable serialized dispatch
  payloads commit together in one SQLite transaction. Restart preserves them.
- **Restricted delegation:** children inherit principal, task, account, recipient,
  and currency; their expiry and budget cannot expand the parent's scope.
  Revoking an ancestor prevents new preparations by any descendant.
- **Sequence budget:** each preparation debits every ancestor. Sibling grants
  share their parent's budget, even with concurrent workers and different nonces.
- **Immutable dispatch:** the adapter receives only the persisted payload and
  original nonce as its idempotency key. Caller arguments cannot replace it.

For every grant g, successful preparations maintain
`0 <= spent(g) <= budget(g)`. A child inherits fixed scope and has no later expiry.
Each accepted transfer increments spent on its entire ancestor chain and inserts
one unique outbox record atomically. SQLite serializes writers, so the invariant
holds inductively across concurrent prepares and survives committed restarts.

## Host integration

The Store is a trusted host API, not an agent tool interface. The issuer must
verify actual user authorization before calling `root`. Authenticated principal,
actor, and task come from the host session; model-supplied identity strings are
not authentication. Never expose DB write access, root issuance, delegation, or
revocation to untrusted content. Delegation requires the authenticated parent actor.
Keep the DB on protected local storage with reliable SQLite locking and backups.
One database coordinates one instrument, not all independent research tools.

A root authorizes a cumulative budget for the specified scope, not one exact
amount. The `Transfer.amount` at issuance must fit the budget; subsequent amounts
may vary within its remaining balance. Use budget equal to the exact approved
amount when that is the principal's intent. Validate resolved account ownership,
currency codes, and provider-specific limits in the trusted issuer/adapter.
Amounts must be positive integers in currency minor units, never floats or booleans.

`prepare` is the authorization/commit boundary. Revocation or expiry after prepare
prevents new preparations but does not cancel a committed outbox entry. Budget
is reserved even if delivery fails. Refunds/cancellation require a separate,
authenticated reconciliation operation; this module does not silently release funds.

`dispatch` may retry after a crash or uncertain provider result. The provider must
atomically deduplicate the same idempotency key and payload across concurrent
requests, with retention covering the application's retry lifetime. Exactly-once
settlement depends on that provider contract. Use globally unique nonces across
instruments sharing a provider account. The send adapter must raise unless it has
an authenticated successful provider result; agent-generated success text is not
confirmation. Independent settlement reconciliation remains an integration task.

## Coverage and evidence

These controls address scope escalation, substitutions, replay, and cumulative
overspending regardless of whether a proposal arose from prompt injection or
ordinary code. Tests use local synthetic transfers and a fake provider; no external
financial or physical operation occurs. Device interlocks, malicious firmware,
compromised host credentials, and independent sensor verification require their
own integration-specific defenses.

Run `python -m unittest discover -s validation -p 'test_*.py' -v`.
