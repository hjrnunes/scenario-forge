# Mayor Dashboard

**Updated**: 2026-06-26 12:00
**Resume**: `You are the mayor for this repository.`

## Needs operator now

Wave 1 dispatched: 4 fix workers running in parallel (disjoint surfaces). Policy-mapper audit also in flight. Wave 2 (gfk: entry point diversity) queued after wave 1 merges. Remaining decisions: attacker model diversity, HITL depth (scenario-forge-0xu).

## Stance

Pre-alpha prototype, validated end-to-end. Python library + thin CLI (typer). OpenAI-compatible LLM endpoint (Gemma 4 via OpenShift). Merge on green. Remote: `origin` (github). LLM API calls unconstrained. First-person adversarial voice confirmed for narratives.

## In-flight work

| Bead | Type | Surface | Status |
|------|------|---------|--------|
| scenario-forge-hg4 | Fix (P1) | loaders.py / validation | Running in worktree |
| scenario-forge-010 | Fix (P2) | threats.py + mappings YAML | Running in worktree |
| scenario-forge-890 | Fix (P2) | threat_gating.py | Running in worktree |
| scenario-forge-p4g | Docs (P2) | README.md | Running in worktree |
| scenario-forge-f3y | Audit (P2) | policy-mapper data (read-only) | Running in worktree |

## Posture

- **Latest commit**: `8d3d5da` merge of YAML colon sanitization fix
- **Mayor loops**: All 7 active.
  - Reread @:03 | Worktree hygiene @:17 | Cluster review @:07,:37 | Merge PRs @:12,:42 | Dispatch pass @:22,:52 | Experiment hygiene @:47 | Dashboard every 11m
- **Worktrees**: 5 active (wave 1 fixes + policy-mapper audit).
- **PRs**: No open PRs.
- **Tests**: 24 tests pass (8 attack tree repair + 16 YAML colon sanitization).

## Recent merges

| Commit | Description | Bead |
|--------|-------------|------|
| `8d3d5da` | Handle unquoted colons in LLM-generated attack tree YAML | scenario-forge-a4n |
| `2ff4202` | Slim Stage1Profile for structured output + max_completion_tokens | scenario-forge-ejf |
| `da24ad1` | Auto-repair single-child AND/OR nodes before validation | scenario-forge-4hq |
| `0c23ed6` | Initial commit: full prototype (64 files, 47k lines) | -- |

## Open beads

| ID | P | Title | Status |
|----|---|-------|--------|
| scenario-forge-hg4 | P1 | Fix: risk card validation | in_progress (wave 1) |
| scenario-forge-010 | P2 | Fix: direct T-threat mappings | in_progress (wave 1) |
| scenario-forge-890 | P2 | Fix: silent generation failures | in_progress (wave 1) |
| scenario-forge-p4g | P2 | Create project README.md | in_progress (wave 1) |
| scenario-forge-f3y | P2 | Audit: policy-mapper risk card coverage | in_progress |
| scenario-forge-gfk | P2 | Fix: hybrid entry point diversity | queued (wave 2) |
| scenario-forge-dzf | P2 | Update HTML report template | blocked by n63, gfk |
| scenario-forge-0xu | P2 | Decision: attacker model diversity, HITL depth | partially decided |
| scenario-forge-n63 | P3 | Feature: coverage gap flagging | queued (wave 3) |
| scenario-forge-0kv | P3 | Fix: CJK output sanitization | queued (wave 3) |
| scenario-forge-twz | P3 | Fix: scoring formula degeneracy | blocked by hg4, 010, gfk |

## Tracker

11 open. 35 closed. 46 total.
