# Mayor Dashboard

**Updated**: 2026-06-25 15:35
**Resume**: `You are the mayor for this repository.`

## Needs operator now

DHS ICE pipeline run complete. 13 scenarios generated at `output/dhs-ice/`. Review the report at `output/dhs-ice/report.html`.

Uncommitted code changes in mayor checkout (Stage1Profile fix + max_completion_tokens). `git diff` to review.

## Stance

Pre-alpha prototype, validated end-to-end. Python library + thin CLI (typer). OpenAI-compatible LLM endpoint (Gemma 4 via OpenShift). Merge on green. No remote. LLM API calls unconstrained.

## In-flight work

None.

## Posture

- **Latest commit**: `da24ad1` — auto-repair single-child AND/OR attack tree nodes
- **Uncommitted**: `capability_profile.py` (Stage1Profile model), `profile.py` (use slim model), `client.py` (max_completion_tokens=16384)
- **Mayor loops**: Active (reread @:03, dashboard @:33).
- **Worktrees**: Clean.
- **PRs**: No remote configured; no PRs.
- **Tests**: 8 tests pass.

## Recent completed work

| Bead | Description | Result |
|------|-------------|--------|
| `scenario-forge-ejf` | DHS ICE pipeline run | 13 scenario pairs (T2/T3/T11/T17), 13 governance-only, 1 failed (T2-S5 YAML parse) |

## Tracker

1 open (P3 bug). 31 closed. 32 total.

| Bead | Priority | Description |
|------|----------|-------------|
| `scenario-forge-a4n` | P3 | Fix YAML serialization: unquoted colons in scenario values |

## Known issues (not beads -- LLM output quality)

- 2/7 eBay scenarios previously failed attack tree validation due to single-child AND nodes. Now auto-repaired.
- vLLM structured output with large Pydantic schemas causes runaway generation. Fixed by using Stage1Profile slim model.
