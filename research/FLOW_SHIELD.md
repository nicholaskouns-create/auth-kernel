# FlowShield: sequence-aware defensive reference monitor

Optional standalone module alongside auth_kernel.py and white_hats.py.

## Purpose
Detect composition hazards that individual per-tool permission checks miss. This is a conservative local prototype, not a production firewall.

## Usage
```python
from flow_shield import Action, FlowShield
f = FlowShield("audit", "agent", frozenset({"approved"}))
f.record(Action("agent", "audit", "read", "customer", labels=frozenset({"sensitive"})))
# The next action is rejected even though its destination is approved:
f.record(Action("agent", "audit", "send", "summary", recipient="approved"))
```

## Trust boundary
Host must authenticate actor/task and derive trusted_origin and labels from trusted provenance and data-classification machinery. Never accept model-authored labels or authorization as authoritative. A new monitor is needed for each authenticated task. Persist history securely if decisions must survive restarts. An allow decision is not a transfer authorization and must still pass the existing auth kernel.

## Limits
This module does not track transformed data, cross-task flows, concurrent histories, cryptographic provenance, or implicit information flows. A future extension should use an explicit information-flow lattice, durable causal event graph, immutable origin receipts, and replay-safe host-enforced action adapters.

## Local tests
`python -m unittest discover -s validation -p 'test_flow_shield.py' -v`
