# Mayor Dashboard

**Updated**: 2026-07-25T11:45
**Resume**: `You are the mayor for this repository.`

## Needs operator

**Full prompt audit pass landed.** 8 PRs merged (#247-#254), addressing all 4 HIGH + 8 Medium findings from `ai/findings/prompt-template-audit.md` plus the original 4 QA-driven fixes. 22 files changed, 29 new tests (2395 total, all green).

Next: run pipeline on all 3 use cases to validate prompt changes, then QA.

## Audit pass summary

| PR | Scope | Key findings |
|----|-------|-------------|
| #247 | validation.py | Actor-type / entry-point controllability check |
| #248 | call2 prompts | T4: delete spraying clause, T1: advisory zone coverage, Fix 1A: non-actionable leaves |
| #249 | filter prompts + candidates.py | F1: thread controllability to filter, F2: calibrate acceptance |
| #250 | call3 prompts + gherkin.py | G5: pass control_points to Call 3 |
| #251 | call0 prompts | A5: expert black-box formulation |
| #252 | profile prompts | P1: remove boolean flag instructions, P2: clarify controllability |
| #253 | call1 prompts | N1: replace entry-point override, Fix 2A: technique discipline |
| #254 | constants + tree + assembly | C1: fix violation category map, Fix 1B: non-actionable leaf check, C3: leaf budget constant |

## In-flight work

None.

## Tracker: 3 open, 3 deferred

| Bead | P | Title | Status |
|------|---|-------|--------|
| hjy3 | P3 | Extract patterns from remaining sources | open |
| 5ywl | P3 | Extract P2+P3 ATLAS case study patterns (8) | open |
| jj5a | P3 | Extract duplicated constraint blocks to Jinja includes (C4) | open |

**Deferred:** 9t4c, 7ov6, is98

## Posture

- **Stance**: Pre-alpha, correctness-first. Merge-on-green.
- **HEAD**: `5dd902c` (master, clean, pushed)
- **Tests**: 2395 passed, 3 skipped
- **Next**: Pipeline runs + QA to validate audit fixes
