# Agent Authorization Boundary Lab

A reproducible, offline, researcher-owned synthetic MCP-style lab for authorization at AI agent/tool execution boundaries.

This module reuses the sibling [NeMo execution gate](../nemo_execution_gate/). It does not change the repository's existing authorization kernel and does not claim an OpenAI vulnerability.

## Run

From `integrations/agent_boundary_lab`:

```sh
python -m unittest discover -s . -p 'test_boundaries.py' -v
python -m unittest discover -s . -p 'test_mcp_protocol.py' -v
cd ../nemo_execution_gate
python -m unittest discover -s tests -v
cd ../agent_boundary_lab
python run_campaign.py
```

Local execution verified **11/11** boundary harness tests, **12/12** synthetic protocol tests, **28/28** inherited gate tests (51 total), and **120/120** expected trial outcomes. Existing gate tests emitted SQLite unclosed-connection `ResourceWarning` messages.

## Scope

- `boundary_lab.py`: trusted-host exact-call approval fixture; session and delegated permission checks.
- `test_boundaries.py`: 11 local boundary tests for injection, substitution, replay, separation and delegation.
- `mcp_fixture.py`: minimal JSON-RPC stdio MCP *subset*, with synthetic `alice` and `bob` records, read/write/export tools, and a local audit ledger.
- `test_mcp_protocol.py`: 12 local protocol-subset tests.
- `run_campaign.py`: six cases repeated 20 times each; `campaign_results.json` contains the resulting counts.
- `EXECUTION_REPORT.md`: tested claims and limitations.
- `BOUNTY_PLAN.md`: staged plan and attribution rules for authorized OpenAI tests.

## Limitations

The fixture is not SDK-backed, conformance-tested, network-accessible, or connected to OpenAI. Identity and role are supplied via environment variables solely as local test-fixture controls. This is *not* production identity or authentication. Replay/nonce enforcement occurs in the existing gate, not the minimal MCP fixture. No real-model or hosted-agent prompt-injection reliability has been measured.

The source and reports are public defensive engineering materials. A conditional private vulnerability report is deliberately not published.
