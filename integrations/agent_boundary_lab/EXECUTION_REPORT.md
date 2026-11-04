# Authorization boundary campaign: execution report

## Scope and attribution

All executions were local, against a researcher-owned synthetic JSON-RPC stdio MCP-subset fixture. **No OpenAI API endpoint, ChatGPT connector, production MCP host, or third-party account was exercised.** There is **no demonstrated OpenAI vulnerability** and no bounty submission has been made.

## Implemented and executed

- `mcp_fixture.py`: MCP-style JSON-RPC `initialize`, `tools/list`, `tools/call` over stdio; synthetic `alice` and `bob` records; tools `read_record`, `write_record`, `export_record`; host-controlled principal, session, delegation role; local audit ledger.
- `test_mcp_protocol.py`: **12/12** executable protocol-subset tests passed.
- `test_boundaries.py`: **11/11** trusted-host boundary tests passed.
- Sibling `../nemo_execution_gate/tests`: **28/28** adapter regression tests passed.
- `run_campaign.py`: six cases each repeated 20 times, **120/120** local expected outcomes; results in `campaign_results.json`.
- Existing gate tests emitted SQLite connection-cleanup `ResourceWarning` messages; security assertions still passed.

## Important limits

- Minimal MCP protocol subset, not conformance-tested with the official MCP Python SDK; SDK installation was unavailable in the original execution environment.
- Fixture environment variables supply test identity; this does not constitute a production authentication design.
- Replay/single-use grants are exercised in the existing gate, not enforced by the standalone MCP fixture. Real deployments must protect the actual executor.
- Fixture has no network endpoint reachable from OpenAI's hosted MCP connector.
- No OpenAI API key was configured in the original execution environment, and no live OpenAI Responses API comparison was performed.
- Repeated deterministic runs are not a measurement of real-model prompt-injection reliability.

## Live experiment prerequisites

1. Confirm current program scope and permission for a researcher-owned OpenAI project and connected MCP service.
2. Run an SDK-backed server with authenticated host principal binding, synthetic-only effects, and an audit trail.
3. Supply API credentials via a secret manager, never via tool arguments or the repository.
4. Compare model proposals, host execution decisions, and any OpenAI-enforced boundaries using separate controlled principals.
5. Submit privately only after independently attributable, in-scope, reproducible product impact is demonstrated.
