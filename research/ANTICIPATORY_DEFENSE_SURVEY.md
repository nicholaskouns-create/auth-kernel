# White Hats anticipatory defense survey — 2026-10-22

## Trigger

[Axios, October 22](https://www.axios.com/2026/10/22/ai-agents-banks-unauthorized-accounts-access)
and [Reuters, October 22](https://www.reuters.com/legal/government/us-banks-detect-unauthorized-ai-agents-customer-accounts-axios-reports-2026-10-22/)
report banks restricting third-party agents accessing customer accounts, including
with customer-provided credentials. The practical threat motivating this work is
an authenticated agent taking an action beyond the customer's instructions.
These reports do not establish a general cryptographic break.

## Survey method

Reviewed the public repository descriptions and README material of five projects
on the date above. This is a documented capability survey, not a source-code audit,
benchmark, or claim that competitors cannot implement these controls. No external
project code was copied or executed. Links identify the reviewed primary sources;
the source repositories may evolve after this snapshot.

| Project | Observed documented capability | Complementary integration work in White Hats |
|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Agent/MCP/skill scanning, prompt-injection and component-risk indicators | Retain explicit approved-descriptor digests and refuse silent descriptor drift |
| [Microsoft PyRIT](https://github.com/microsoft/PyRIT) | Framework for identifying generative-AI risks and red teaming | Deterministically enumerate application-declared workflow alternatives without a target model or service |
| [NVIDIA garak](https://github.com/NVIDIA/garak) | LLM vulnerability probes and detectors | Track sensitivity and trust through explicit transformations, independent of output wording |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | General-purpose context-aware policy evaluation | Supply durable content-bound provenance facts to an application's policy evaluation |
| [Cedar](https://github.com/cedar-policy/cedar) | Fine-grained authorization language, schema validation and automated-reasoning tooling | Supply ancestry and tool-change evidence; retain existing principal authorization separately |

The inferred opportunity is the integration between these capabilities: risk
scanning, policy decisions, provenance persistence and actual effect dispatch.
This survey does not establish exclusive novelty or absence of equivalent tools
elsewhere. Each addition is independently usable alongside the surveyed projects.

## Repository review at a7ac9c1

- `auth_kernel.py` binds principal, issue record, arguments, validity and nonce.
- `white_hats.py` persists shared delegation budgets and dispatch intent.
- `flow_shield.py` detects sensitive-read/export composition within a task.
- `research/FLOW_SHIELD.md` explicitly identifies transformed-data provenance,
  cross-task flows and persistence as extension points.
- The browser FlowShield engine and its tests already exist; additions do not
  replace them or claim that a browser visualization intercepts external tools.

The added `anticipatory.py` addresses declared transformation ancestry and durable
content identity, plus approved tool-descriptor binding and offline workflow
enumeration. Existing caller authentication, dispatch, and budget instruments
remain the places where actual execution authority is exercised.

## Threat-to-test mapping

| Anticipated failure class | Defensive property | Regression evidence |
|---|---|---|
| Sensitive data laundered through summaries/translations | Sensitivity is the maximum over declared parents | Multi-generation derivation remains restricted after restart |
| Web/tool content promoted to instructions | Trust is conjunction over declared parents | Mixed ancestry refused for instruction use |
| Content swapped after classification | Exact bytes must match registered SHA-256 | Changed and unknown content refused |
| MCP/tool definition silently changed | Entire JSON descriptor is pinned | Server, endpoint, schema, version, description and extensions checked |
| New combinations of individually plausible actions | Enumerate declared alternative paths | Two hazardous compositions found across six bundled paths |
| Analysis cut short but reported safe | Explicit completeness state | Truncation returns INCOMPLETE even when no findings appeared yet |

These are anticipatory because they constrain future compositions and detect
modelled hazards before execution without needing a signature for a particular
attack phrase. They do not predict undisclosed vulnerabilities or assign incident
probabilities. Coverage is exactly the declared operations, alternatives and facts.
