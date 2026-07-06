# Mayor Dashboard

**Updated**: 2026-07-06T12:30
**Resume**: `You are the mayor for this repository.`

## Needs operator now

- **Untracked file**: `ai/data-flow-diagrams.md` — commit, gitignore, or discard?
- **Awaiting approval**: `scenario-forge-i6t` (Jinja templates) — dispatch worker?

## In-flight work

| Worker | Bead | Surface | Worktree |
|--------|------|---------|----------|
| a8561972b | `0q1` Run manifest | `pipeline/runner.py` | `agent-a8561972b0d9b37e6` |

### Open beads

- `scenario-forge-i6t` P2 — Extract prompts to Jinja templates *(open, not dispatched)*

### Open PRs

None (expecting PR from `0q1` worker).

### Recent commits

- `eebe23b` fix(report): tab-bar CSS selector + mechanism→attack_pattern fallbacks *(this session, unpushed)*
- `0c1b500` PR #77 — Rename mechanism → attack_pattern + glossary
- `87cf91d` PR #76 — Goal-threat affinity weighted selection
- `4f93f40` PR #75 — Tabbed scenario cards
- `3d937a1` PR #74 — Per-call Generation Inputs tables

## Posture

- **Stance**: Pre-alpha, correctness-first. Iterating on prompt quality and evaluation metrics.
- **Latest commit**: `eebe23b` on master (unpushed; `0c1b500` pushed)
- **Uncommitted**: `ai/data-flow-diagrams.md` (untracked), `dashboard.md`, `.beads/interactions.jsonl`
- **Worktrees**: 1 (manifest worker)
- **Open PRs**: 0
- **Tracker**: 1 open, 1 in-progress

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
