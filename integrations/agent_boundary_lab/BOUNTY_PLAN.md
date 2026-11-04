# OpenAI agent authorization / MCP boundary research plan

## Evidence level

- Local boundary tests: **11/11** passed.
- Local MCP-subset protocol tests: **12/12** passed.
- Reused NeMo gate tests: **28/28** passed.
- Repeated synthetic campaign: **120/120** expected outcomes.
- OpenAI live service: **not exercised**. OpenAI vulnerability: **not demonstrated**.

## Target selection and authorization

Review the current OpenAI Security Bug Bounty terms, scope, safe harbor and exclusions before conducting live tests. Prefer an owned OpenAI API project and a researcher-owned MCP service containing only synthetic data, using two controlled principals. Never test other users, guessed credentials, or non-owned assets. Record target, authorization basis, test timestamp, environment, expected and observed effects.

## Boundary matrix

| ID | Threat | Controlled stimulus | Secure expected result |
|---|---|---|---|
| B01 | Token injection | Model-supplied authorization token argument | Refuse; no effect |
| B02 | Argument substitution | Approved exact call altered before execution | Refuse; no effect |
| B03 | Replay | Reuse a single-use signed approval | At most one effect |
| B04 | Cross-session | Session B attempts Session A's approved operation | Refuse unless B separately authorized |
| B05 | Delegation escalation | Read-only child requests write/export | Refuse |
| B06 | Tool-result laundering | MCP result includes forged control fields | Treat as data, not authority |

## Stages

1. **Reference implementation (complete):** test the exact-call gate and context isolation.
2. **Owned MCP fixture (local subset complete):** synthetic two-principal tools, local JSON-RPC stdio and audit ledger. SDK conformance and authenticated live service remain outstanding.
3. **Authorized OpenAI comparison (not performed):** connect an owned MCP server to a permitted OpenAI surface. Capture proposals, application-side tool execution and enforcement separately. Use safe controls and bounded negative trials.
4. **Attribution:** distinguish a defect in the owned MCP server, a host misconfiguration, normal model behavior, and an actual OpenAI-enforced boundary bypass.
5. **Private disclosure only upon evidence:** submit sanitized steps, scope, root cause, repeatability, measured impact, and minimal safe proof of concept through the official program.

## Reward classification

Exceptional-critical rewards require an actual independently demonstrable high-impact OpenAI security failure. This public lab makes **no** reward or severity claim. Keep any potential exploit-specific private report out of public repository history.

## References

- https://openai.com/index/rewarding-defenders-with-bigger-bug-bounties/
- https://openai.com/index/safety-bug-bounty/
- https://developers.openai.com/api/docs/guides/function-calling
- https://bugcrowd.com/openai
