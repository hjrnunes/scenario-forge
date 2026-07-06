# Mayor Dashboard

**Updated**: 2026-07-06T19:55
**Resume**: `You are the mayor for this repository.`

## Needs operator now

- **Brainstorm ready**: HTML report improvements at `ai/findings/html-report-brainstorm.md` — remaining tiers (1a-1e quick wins, 2a attack tree viz, 2f dual severity encoding, 3a-3e larger features).
- **Design decision**: Attack Flow STIX export — file a bead or discuss scope first?

## In-flight work

None — all workers completed.

### Open beads

0 open / 169 closed — quiescent.

### Open PRs

None.

### Recent commits / merges

- `ae43a1d` PR #83 — Provenance steps 4-6 as parallel inputs layout *(merged this session)*
- `23255ce` PR #82 — Show attack pattern selection in provenance tab *(merged this session)*
- `daff510` PR #81 — Provenance chain tab with input derivation flowchart *(merged this session)*
- `fbba989` PR #80 — Dashboard stats, coverage heatmap, chip filters, card collapse *(merged this session)*
- `3adf099` PR #79 — Jinja templates *(merged this session)*

### Findings (gitignored, for operator review)

- `ai/findings/html-report-brainstorm.md` — Improvement roadmap (4 tiers, recommended sprints)
- `ai/findings/taxonomy-browser-research.md` — ATT&CK Navigator, D3FEND, STRIDE/LINDDUN patterns
- `ai/findings/attack-flow-stix-research.md` — Attack Flow STIX data model mapping
- `ai/findings/kill-chain-visualization-research.md` — Kill chain viz patterns
- `ai/findings/bloom-petri-pattern-analysis.md` — Bloom + Petri framework analysis
- `ai/data-flow-diagrams.md` — Current architecture data flow (13 sections, 815 lines) *(updated this session)*

## Posture

- **Stance**: Pre-alpha, correctness-first. Iterating on prompt quality and evaluation metrics.
- **Latest pushed**: `ae43a1d` (PR #83 merge)
- **Local-only commits**: 2 (chore: dashboard + CSS fix — unpushed)
- **Uncommitted**: `ai/data-flow-diagrams.md` (untracked)
- **Worktrees**: 0 (clean)
- **Open PRs**: 0
- **Tracker**: 0 open, quiescent

## Loops (session-only, 7d auto-expire)

| Loop | Interval | Schedule |
|------|----------|----------|
| Dashboard refresh | 10m | :03,:13,... |
| Cluster review | 30m | :07,:37 |
| Merge PRs | 30m | :12,:42 |
| Dispatch pass | 30m | :17,:47 |
| Reread/reassert | 60m | :22 |
| Worktree hygiene | 60m | :27 |
| Experiment hygiene | 60m | :52 |
