# FlowShield Web Laboratory
This is an additive site to auth-kernel. Source: `docs/index.html` and `docs/flowshield-engine.js`.

- Bounded symbolic reachability (BFS) over deliberately simplified authority states
- Deterministic per-action policy simulation; trace and reproducible JSON receipt download
- Native navigation to Mathematical City, Linear, Notion, Drive and Supabase
- No secret keys, production account access, live crawling or external transactional actions
- No iframe attempts against third-party pages
- Authenticated edge backend maintained separately as `flowshield-predict` (requires valid user JWT)

To publish this independent site under GitHub Pages: Settings → Pages → Deploy from a branch → main → /docs. Alternatively the canonical hosted mirror is `https://nicholaskouns-create.github.io/flowshield.html`.

## Model boundary
The engine tracks sensitive reads, delegation and destinations. It does not taint-track arbitrary transformations, manage concurrent task history, verify external credentials, or prove an unbounded safety property. Use auth-kernel for actual authorization decisions.
