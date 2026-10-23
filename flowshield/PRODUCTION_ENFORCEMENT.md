# FlowShield production integration contract

The E47 clock produces **simulated proper time**, not independently authenticated UTC. A signed security receipt must bind both to a verified GitHub OIDC identity.

## Existing components
- `Time/security/e47-signed-tick.mjs`: NodeClock-derived signed receipts (Ed25519).
- `Time/tests/e47-signed-tick.test.js`: tamper, scope and in-process replay tests.
- `auth-kernel/flowshield/tick-ledger.mjs`: append-only receipt primitive.
- `flowshield_private.replay_receipts` in connected Supabase: private RLS-protected durable nonce store, primary key (issuer, nonce).

## Enforcement contract
1. Obtain and validate GitHub OIDC token against GitHub JWKS: issuer, audience, exp, nbf, repository, ref, workflow and run claims. Never trust repository/run fields from a caller alone.
2. Bind validated OIDC claims to the receipt repository, commit and run.
3. Verify Ed25519 signature against an explicitly trusted, rotated issuer public key. Ephemeral keys generated inside the untrusted workflow are NOT sufficient.
4. Validate nonce format, issued time window, clock simulation state and action intent against the existing authorization kernel.
5. Atomically INSERT (issuer, nonce, repository, commit_sha, workflow_run, receipt_digest, tick, observed_at) into the private database. A uniqueness conflict MUST deny the operation. No read-before-write check.
6. Execute the protected action only after steps 1-5 succeed; make the protected action idempotent by receipt digest.
7. Persist decision, denial, and revocation telemetry; do not store secrets or raw tokens in GitHub artifacts.
8. Configure protected GitHub environments and required status checks for deployment. Merely adding a workflow does NOT gate pushes or deployments.

## Security boundaries
- `NodeClock` can supply reproducible phase/proper-time evidence, not wall-clock authenticity.
- In-memory `seen` sets are only test aids; production requires durable atomic replay storage.
- CI receipts are not signed or authenticated until a trusted signer and OIDC verifier are deployed.
- No public API grants exist for the private Supabase table.
- Use short-lived credentials; keep signing secrets off GitHub Pages.
