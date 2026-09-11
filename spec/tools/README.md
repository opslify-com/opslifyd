# spec/tools

## specgraph.py — deterministic requirements graph

Parses every feature file (`phases/*/features/F*.md`) and inline feature
(`### F*.` in `phases/*/README.md`), extracts the dependency data already written
in the specs (`id`, `Phase`, `Status`, `Owner`, `Depends on`, `Blocks`), and emits:

- **`spec/graph.json`** — machine-readable graph the orchestrator reads (nodes, edges,
  `topological_order`, per-node `depends_on_resolved`). Single source of truth for build order.
- **`spec/graph.mmd`** — Mermaid dependency diagram for humans.

It **validates** and exits non-zero on:
- a dependency **cycle**,
- a `Depends on:` / `Blocks:` pointing at a **feature id that doesn't exist**,
- (advisory warning) blocks/depends **asymmetry**.

This is the anti-hallucination layer: the graph is *generated from the files every run*,
so agents ground on exact, current requirements instead of recall. **Never hand-edit
`graph.json` / `graph.mmd`.**

### Usage
```bash
python3 spec/tools/specgraph.py          # generate + validate (run from repo root)
python3 spec/tools/specgraph.py --check  # validate only, no writes (CI)
```

Run it after any change to a feature's `Depends on:`, `Blocks:`, or `Status:`, and in CI.
