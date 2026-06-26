# Mayor Dashboard

**Updated**: 2026-06-26 22:00
**Resume**: `You are the mayor for this repository.`

## Needs operator now

**Operator decision pending**: Scoring diversity fix strategy. The wave 8 heuristic threshold fix failed — the LLM always generates 9-14 node trees, so all scenarios score "high" complexity. Options:
- **(a)** Prompt-level: vary tree complexity in generation prompt (simpler trees for simple attacks)
- **(b)** Threshold recalibration: fit thresholds to empirical distribution (9-14 nodes)
- **(c)** Both

## Stance

Pre-alpha prototype, validated end-to-end. Python library + thin CLI (typer). OpenAI-compatible LLM endpoint (Gemma 4 via OpenShift). Merge on green. Remote: `origin` (github). LLM API calls unconstrained. First-person adversarial voice confirmed for narratives.

## In-flight work

_None._

## Pipeline quality progression

| Run | Seeds | Success | Gaps | Score | Fixes |
|-----|-------|---------|------|-------|-------|
| ebay-v3 | 138 | 31 (22%) | n/a | 3.1/5 | none |
| ebay-v4 | 31 | 28 (90%) | 2 | 3.6/5 | waves 1-6 |
| ebay-v5 | 31 | 32 (103%) | 0 | 4.07/5 | waves 1-7 |
| ebay-v6 | 31 | 32 (103%) | 1 | 3.93/5 | waves 1-8 |
| police v1 | 237 | 36 (15%) | n/a | 3.1/5 | none |
| police v2 | 37 | 33 (89%) | 1 | 4.0/5 | waves 1-6 |
| police v3 | 37 | 37 (100%) | 0 | 4.3/5 | waves 1-7 |
| police v4 | 37 | 38 (103%) | 1 | 4.3/5 | waves 1-8 |

**Scoring diversity remains the drag** — attack_complexity locked at "high" (97-100%) because the LLM generates deep/wide trees regardless of the heuristic thresholds.

## Posture

- **Latest commit**: `89e3627` — origin/master in sync
- **Worktrees**: 0 active
- **PRs**: 0 open, 15 merged total
- **Tests**: 270 pass (all green)
- **Tracker**: 0 open, 58 closed

## Session summary (2026-06-26)

- 8 waves of fixes dispatched and merged (15 PRs total, 58 beads closed)
- 8 pipeline runs across 2 use cases (eBay, Leicestershire Police)
- Quality improved from 3.1/5 baseline to 4.0-4.3/5
- Key wins: seed deduplication, coverage gap detection + remediation, narrative diversity, SSSOM filtering, entry point coverage
- Remaining: scoring diversity (complexity heuristic needs upstream prompt-level fix)
