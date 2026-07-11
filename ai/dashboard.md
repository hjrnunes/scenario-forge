# Mayor Dashboard

**Updated**: 2026-07-11T01:15
**Resume**: `You are the mayor for this repository.`

## Needs operator now

**KC taxonomy Phase 2 — complete, uncommitted.** All code + tests done, 493/493 tests pass. Needs commit + PR.

Changes:
- `threat_gating.py`: hardcoded 6-gate system replaced with KC→T lookup (`_compute_kc_enabled_threats`)
- `threats.py`: removed `_matches_profile_directly`, simplified `_resolve_direct_threats` to 2-arg, ATLAS gating uses KC6 sub-codes
- `cross-taxonomy-mappings.yaml`: `profile_match` removed from all 7 t_direct entries
- 5 AP YAML files: all 58 attack patterns annotated with `kc_requires`
- Tests rewritten for KC-based gating (55 tests across 2 files)

Still uncommitted from before Phase 2: `template.py` (operator edits), `ai/extended-context/quality-assessment-checklist.md`.

**Next phase** (not started):
- Phase 3: migrate prompts/templates/output from zones to KC sub-codes

**Housekeeping**: 130 `__pycache__` dirs — consider cleanup.

## In-flight work

None.

### Open beads: 0 / 208 closed

### Open PRs: 0

## Recent merges

- `57434e3` **PR #115** feat(models): add OWASP KC sub-code taxonomy (Phase 1)
- `e3f1a5b` **PR #114** feat(pipeline): seed-level min_complexity and required_capabilities
- `b8aa8d7` **PR #113** fix(pipeline): negligent-insider prompt reinforcement + BDI validation
- `2373dc6` **PR #112** fix(pipeline): technique semantic constraints in Call 2 prompt
- `a19fb7c` **PR #111** feat(report): warn if eval scorecard missing or stale

## Posture

- **Stance**: Pre-alpha, correctness-first. Merge-on-green.
- **Latest pushed**: `57434e3`
- **Local-only commits**: 0 (Phase 2 changes uncommitted)
- **Worktrees**: 0
- **Tracker**: 0 open, 208 closed
- **Uncommitted files**: `threat_gating.py`, `threats.py`, `cross-taxonomy-mappings.yaml`, 5 AP YAMLs, 2 test files, `template.py`, `ai/dashboard.md`, `ai/extended-context/quality-assessment-checklist.md`
