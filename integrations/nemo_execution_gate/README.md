# NeMo Execution Gate v2 (independent prototype)

Optional exact-call HMAC-SHA256 execution authorization for NVIDIA NeMo Guardrails actions and externally invoked tools. **Independent, not an NVIDIA upstream release or an installed production integration.**

## Security property

A model-proposed tool call is never sufficient for privileged execution. The trusted host must issue an exact-argument, single-use authorization before dispatch. Verification happens inside the action wrapper, at execution time.

```
Host independently approves an exact tool + arguments
  -> HostSession.approve(...) issues signed grant out of model reach
  -> model proposes business arguments
  -> nemo_host_action obtains matching approval from trusted host context
  -> ExecutionGate verifies HMAC, scope, expiry, and atomically spends nonce
  -> execute once or refuse
```

## Standalone tests (no NeMo dependency)

```sh
cd integrations/nemo_execution_gate
python -m unittest discover -s tests -v
```

At initial preparation, 28/28 standalone unit tests passed. This is evidence for the local prototype only, not for actual NeMo integration.

## Trusted-host action registration example

```python
from nemoguardrails import LLMRails, RailsConfig
from gate import ExecutionGate, NonceStore
from trusted_host import HostSession, nemo_host_action

rails = LLMRails(RailsConfig.from_path("./config"))
gate = ExecutionGate(secret_key_from_host_secret_store(), NonceStore("/secure/nonces.db"))

async def send_notice(recipient: str):
    return await trusted_notice_service(recipient)

rails.register_action(nemo_host_action(gate, "send_notice", send_notice), name="send_notice")

host = HostSession(gate)
args = {"recipient": "approved@example.org"}
# Independently authorize exact operation; never grant merely because the LLM asked.
host.approve("send_notice", args, grant_id="host-policy-1")
with host.activate():
    result = await rails.generate_async(messages=messages)
```

The model must **not** be able to call `HostSession.approve`, access the HMAC key, impersonate trusted code, or replace the dispatch wrapper.

`ExecutionGate.nemo_action` is a **legacy demonstrator** that accepts an `authorization_token` keyword. It MUST NOT be exposed directly to model-controlled argument injection. For action registration use `nemo_host_action` instead.

## Optional installed-runtime smoke

```sh
pip install nemoguardrails
python nemo_runtime_smoke.py
```

This smoke registers an action using a real `LLMRails` instance when available. It calls the wrapper directly and does **not** exercise an LLM-generated tool call. **It has not been executed successfully in the original build environment** because `nemoguardrails` could not be installed there.

## Limitations

- `contextvars` isolates cooperating async execution contexts; it does not sandbox untrusted code that runs inside the host process.
- External tools invoked outside the wrapped action must be guarded at their actual executor.
- SQLite nonce state is single-host / shared-filesystem only; no distributed transactional store.
- No host grant revocation or cross-language RFC 8785 canonicalization.
- Authorization decisions are made by the trusted host, not by the model or this prototype.
- Expired nonce cleanup and lifecycle hardening are left to deployment owners.
- No demonstrated NVIDIA vulnerability or CVE claim.

See [integration status](submissions/integration_status.md) and [open-source proposal](submissions/open_source_proposal.md). The conditional private security disclosure draft is intentionally **not published** to this public repository.
