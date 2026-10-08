# Authorization Invariant Discovery — 2026-10-08

## Theorem

For a privileged action to execute, authority must be bound to the requesting principal, task, tool, exact arguments, validity window, and a fresh one-shot nonce.

Let a grant be

\[
g=(p,t,u,d,i,e,n,\sigma)
\]

with principal \(p\), task \(t\), tool \(u\), argument digest \(d\), issue time \(i\), expiry \(e\), nonce \(n\), and authenticating signature \(\sigma\).

Define

\[
\mathrm{Invoke}(g,r) := \mathrm{Active}(p_r) \land p_r=p \land t_r=t \land u_r=u \land H(a_r)=d \land i\le \tau_r\le e \land \mathrm{Verify}(\sigma,g) \land n\notin\Sigma.
\]

On ALLOW, the state transition is

\[
\Sigma \to \Sigma\cup\{n\}.
\]

Therefore:

1. cross-principal reuse is rejected;
2. cross-task reuse is rejected;
3. tool substitution is rejected;
4. argument/content substitution is rejected;
5. expired and pre-issued use are rejected;
6. inactive principals are rejected;
7. signature validity alone is insufficient to invoke;
8. a successful invocation consumes its nonce, so replay is rejected.

## Confused-deputy closure

The defective shape is

\[
\mathrm{CredentialHolderAllowed}(u,a) \Rightarrow \mathrm{Invoke}
\]

when the checker observes the privileged credential holder but does not bind the requester's authority. The repair is to require requester-scoped authority:

\[
\mathrm{Invoke}\Rightarrow
\mathrm{BoundPrincipal}\land
\mathrm{BoundTask}\land
\mathrm{BoundTool}\land
\mathrm{BoundArgs}\land
\mathrm{Fresh}\land
\mathrm{ActivePrincipal}.
\]

A persisted prefix, cached approval, or other reusable authorization artifact cannot by itself satisfy this invariant across a new requester/task context.

## Executable certificate

`validation/authorization_invariant_20261008.py` implements the reference state machine and reports **16/16 PASS** for the declared invariant tests.

## Evidence boundary

This is a reference-model proof and executable invariant test. It does not by itself establish that every upstream implementation currently enforces the invariant. Direct source and regression testing are separate evidence layers.

## Upstream observations recorded 2026-10-08

- OpenAI Codex public source contains `persist_execpolicy_amendment`, documented as adding an exec-policy amendment to in-memory and on-disk policies so future commands can use the approved prefix.
- Sovereign Veritas issue #4 documents the earlier `sv.gate/0` authorization and evidence-binding breaks and proposes an additive `sv.gate/1` repair.
- NVIDIA NeMo upstream verification was not established in the prior execution pass and remains a direct-regression target.

## Discovery date

**2026-10-08**
