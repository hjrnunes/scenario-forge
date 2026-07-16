# Mayor Dashboard

**Updated**: 2026-07-16T11:00
**Resume**: `You are the mayor for this repository.`

## Needs operator now

**Discussing Stage 4 architecture changes.** Two proposals from the generation flow audit:
1. Tree-anchored flow — deterministic skeleton from pinned techniques, LLM fills in structure (option A proposed)
2. Deterministic Gherkin — template mechanical parts, LLM writes only Then/But/* assertions

Awaiting operator decision on approach before filing beads.

**Also pending:**
- Dispatch 8dqn + s15f (ready, disjoint surfaces, can go parallel)
- v17 QA triage priorities 4-6 undiscussed
- Parsimony approach: superseded if tree-anchored flow adopted

## In-flight work

None. Quiescent.

### Open PRs: 0

### Tracker: 3 open / 272 closed

| Bead | Task | Priority | Status |
|------|------|----------|--------|
| scenario-forge-8dqn | Gate T3-01 seeds with KCX-PRIV prerequisite | P2 | open, dispatchable |
| scenario-forge-s15f | Expand phantom checker for code gen patterns | P2 | open, dispatchable |
| scenario-forge-7ls4 | Cross-artifact consistency + parsimony validation passes | P2 | open |

### Recently closed

| Bead | Result |
|------|--------|
| es23 | BDI voice experiment — rejected (phantom reduction modest, plausibility regressed) |

### Recently merged

| PR | Title | Bead |
|----|-------|------|
| #167 | feat(pipeline): log all LLM calls and show in report | 24be |
| #166 | fix(report): streamline capability profile section | ght7 |
| #165 | fix(prompts): clean up user prompt structure | 6gyn |

## Posture

- **Stance**: Pre-alpha, correctness-first. Merge-on-green.
- **Latest pushed**: `82ce86f`
- **Branch**: master (clean)
- **Local-only commits**: 0
- **Worktrees**: 0
- **Uncommitted files**: dashboard, beads, CLAUDE.md, mayor commands, QA checklist
