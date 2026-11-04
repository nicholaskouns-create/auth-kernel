# Proposal: optional single-use authorization gate at the tool execution boundary

Related: [NVIDIA-NeMo/Guardrails#2409](https://github.com/NVIDIA-NeMo/Guardrails/issues/2409)

## Motivation

A generated tool call is a proposal, not a capability. Configurable tool-call rails and input/output checks may inspect requests, but they are distinct from host authorization for privileged side effects.

## Proposed change

Offer an opt-in execution-boundary wrapper for registered NeMo actions and externally invoked tools. A trusted application independently approves one exact call, binds a host-issued HMAC authorization to the tool identity, canonical argument digest, grant ID, audience, nonce and expiration, then injects authorization through trusted context rather than model arguments. Before dispatch the wrapper verifies the grant and atomically consumes the nonce. Missing, altered, expired, wrong-scope, replayed or model-injected grants fail closed.

## Prototype acceptance

This independent adapter includes standalone tests for exact argument binding, wrong tool/grant, tampering, expiry, replay, concurrent replay, synchronous and asynchronous targets, trusted-host session isolation and forbidden control-plane fields. The local Python suite passed 28/28 tests.

**Not yet accepted as a NeMo runtime integration:** the optional registration smoke has not been executed with an installed NeMo environment; an end-to-end model-generated tool call has not been tested.

## Non-goals

Does not claim NVIDIA violates a documented security promise, replace the NeMo rails architecture, introduce mandatory central governance, or dictate authorization policy to host applications. Distributed replay defense, revocation and cross-language canonicalization remain modular future extensions.

## Suggested documentation

Distinguish LLM-proposed tool calls, configurable `rails.tool_call` checks, and independent host-controlled execution authorization. Provide a minimal opt-in wrapper example.
