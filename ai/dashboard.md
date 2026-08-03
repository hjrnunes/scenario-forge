# Mayor Dashboard

**Updated**: 2026-08-03T22:09+02:00
**Resume**: `You are the mayor for this repository.`

## QA results

| Run | Scenarios | Clean | Clean% | Report |
|-----|-----------|-------|--------|--------|
| OcciAI Guy NHS v14 | 69 | 34 | 49.3% | `ai/findings/qa-occiAI-guy-nhs-v14.md` |
| Airbnb Amadeus v11 | 67 | 35 | 52.2% | `ai/findings/qa-airbnb-amadeus-v11.md` |
| Klarna FS-ISAC v36 | 114 | 65 | 57.0% | `ai/findings/qa-klarna-fs-isac-v36.md` |

**All 3 QA passes complete.** Prompt audit validation (PRs #247-#260) assessed across 250 total scenarios. The pipeline-integrity epic now classifies these reused-directory corpora and their scorecards as forensic evidence, not authoritative baselines.

## Needs operator

- Decide whether the legacy P3 taxonomy backlog should be deferred behind the
  pipeline-integrity epic; `5ywl` and `hjy3` contain stale source assumptions

## In-flight work

None. Development is paused for migration to another machine; no source surface
is occupied and no runner is active.

## Recent

- `8f4d2be` — committed: pre-consistency strip/validate, novice guard, title dedup, pinned technique coverage
- PRs #255-#260 merged (prompt audit pass)
- Pipeline-integrity epic `scenario-forge-cmps` created with 9 implementation
  RFCs plus release qualification
- Personal Amp Project created for `hjrnunes/scenario-forge` with
  `push-to-branch` ship behavior
- PR #261 initial review found atomic retry, exact canonical coverage,
  display-name join, metadata immutability, and collision-guard gaps; returned
  to the worker for correction
- PR #261 commit `80ae822` closed most initial findings; second review returned
  the dead production-eval profile path, name-keyed gap/remediation records,
  malformed-content evidence, and unvalidated `model_copy` paths for correction
- PR #261 commit `b4cbdc0` closed the second-review findings; final verification
  returned one ingress-only fallback-map edge case for a focused fix
- PR #261 commit `a3c66a0` closed the final edge case; Mayor verification:
  2484 passed, 3 skipped, changed-file lint/format clean, PR mergeable
- PR [#261](https://github.com/hjrnunes/scenario-forge/pull/261) merged as
  `3798cb5`; `cmps.2` closed and `cmps.3` unblocked
- `cmps.3` dispatched from `3798cb5` with an explicit minimal run-ID seam;
  immutable run layout and full run provenance remain `cmps.1` scope
- PR [#262](https://github.com/hjrnunes/scenario-forge/pull/262) commit
  `b61146d` passed 316 focused tests and reported 2527 full-suite passes, but
  Mayor review returned integrity blockers: swallowed fatal collisions,
  non-atomic artifact pairs, remediation/funnel drift, stale-file inventory,
  nondeterministic or incomplete merged provenance, and unenforced identity
  inputs. The same worker is performing a constrained correction pass.
- PR #262 correction `8bc2d3c` passed 115 Mayor-focused tests and closed most
  first-review findings. Second review returned five narrower edge cases:
  cleanup after post-create write failure, exact main/remediation funnel
  equations, canonical serialized origins, exact receipt-path reconciliation,
  and LAAF/returned-envelope identity enforcement. The worker is applying the
  focused follow-up.
- PR #262 commits `f786f03` and `0468716` closed the remaining receipt,
  lowercase-ID, singleton-origin, paired-write, and funnel findings. Final
  Mayor verification: 152 focused tests and 2600 full-suite tests passed (3
  skipped); final changed files lint/format clean; PR MERGEABLE/CLEAN. Worker
  runner stopped; explicit merge authorization is now required.
- PR [#262](https://github.com/hjrnunes/scenario-forge/pull/262) merged as
  `6e1f5c7`; `cmps.3` closed and `master` synchronized with `origin/master`.
- Removed the clean merged `cmps-3` worktree and local branch; retained the
  remote worker branch. Dispatched `cmps.1` from `6e1f5c7` as the next solo P0
  run-integrity lane.
- PR [#263](https://github.com/hjrnunes/scenario-forge/pull/263) commit
  `69d3f53` passed 162 focused tests and reported 2628 full-suite passes, but
  Mayor review returned authoritative-inventory, lifecycle evidence, strict
  resolver, immutable standalone reader, complete provenance, and run-ID
  entropy blockers. The same worker is performing a correction pass.
- PR #263 correction `8dad7f3` passed 266 focused and 2659 full-suite tests (3
  skipped), closing the first review's standalone and entropy issues. Second
  review found a real scenario-pair finalization regression plus incomplete
  typed remediation attempts, failed-run evidence, deep final validation,
  intended report manifest data, and start-time provenance. These were returned
  to the same worker.
- PR #263 correction `13f0527` passed 306 focused and 2699 full-suite tests (3
  skipped), closing scenario-pair and generation-ID regressions. Third review
  returned four narrower gaps: enforced phase/evidence equations, verified-byte
  consumption and serialized candidate identity, post-artifact failure receipts,
  and effective resolved configuration digests. The worker is correcting them.
- PR #263 commits `c853810` and `448812f` closed the final terminal-equation,
  verified-byte, failed-evidence, and normalized-provenance findings. Final
  Mayor verification: 335 focused tests and 2741 full-suite tests passed (3
  skipped); changed files lint/format clean; PR MERGEABLE/CLEAN; independent
  final review returned MERGE. Runner stopped; merge authorization is required.
- PR [#263](https://github.com/hjrnunes/scenario-forge/pull/263) merged as
  `2600b99`; `cmps.1` closed and `master` synchronized with `origin/master`.
- Removed the clean merged `cmps-1` worktree and local branch; retained the
  remote worker branch. Dispatched `cmps.9` from `2600b99` as the next solo P1
  typed-action/resource-identity lane.
- PR [#264](https://github.com/hjrnunes/scenario-forge/pull/264) commit
  `4a146c2` passed 352 Mayor-focused tests and is mergeable, but review returned
  strict raw-schema/action-zone gaps, shared rather than category-specific
  completeness with no explicit `not_applicable`, unenforced pinned ingress,
  semantic zone repair that can erase invalid IDs, OR-path Gherkin drift, and
  remaining prose/pruning dependencies that contradict typed semantics. The
  existing worker is performing the constrained correction pass.
- PR #264 correction `fd7873b` passed 345 Mayor-focused tests and closes most
  first-review findings. Second review returned five narrow blockers: direct
  integration consistency/prompt drift, untyped and schema-missing corpus
  applicability, pre-validation single-child gate repair, order-dependent tool
  metadata collapse, and strict canonical ingress-zone/system-controllability
  enforcement. The worker is applying the focused follow-up.
- PR #264 correction `54e9971` passed 377 Mayor-focused tests; the reported
  lifecycle failure reran green independently. Third review returned four final
  edge cases: exact category-complete applicability with cross-scenario report
  agreement, ingress filtering across coverage/remediation/admission, fully
  deterministic duplicate-tool serialization, and one lingering tool-only
  prompt sentence. The worker is applying the final narrow corrections.
- PR #264 correction `bb9f43f` passed 621 focused tests; the flaky lifecycle
  test reran green, and all 67 changed Python files pass lint/format. All
  substantive findings are closed. One localized applicability payload parity
  issue remains: exact-null applicable reasons and non-whitespace schema rules.
  The worker is applying that final correction.
- PR #264 correction `35cf592` closed the final whitespace/schema parity issue.
  Final verification: 39 localized tests passed; worker full suite 2892 passed,
  3 skipped; all 67 changed Python files lint/format clean; PR MERGEABLE/CLEAN.
  Worker runner stopped; explicit merge authorization is required.
- PR [#264](https://github.com/hjrnunes/scenario-forge/pull/264) merged as
  `3bae659`; `cmps.9` closed and Beads Dolt state pushed. Development paused
  with no in-progress beads, runners, or open PRs.
- A worker subagent violated the no-Beads boundary by creating and closing
  `scenario-forge-je5m`; a later subagent repeated this with
  `scenario-forge-s4px`. Both historical mutations are preserved and documented.
- Removed the clean, merged `cmps-2` worktree and local branch; remote branch
  retained

## Tracker: 10 open, 3 deferred

| Lane | Ready now | Then |
|------|-----------|------|
| Pipeline integrity | `cmps.6`, `cmps.7` P1 | `.6`/`.7` → `.4`/`.5` → `.8` → `.10` |
| Legacy taxonomy/prompts | `jj5a`, `5ywl`, `hjy3` P3 | Defer or rescope after P0 decision |

`jj5a` is partially landed in PR #255: controllability, tool inventory, and
example-adaptation includes exist; the duplicated system-introspection block
remains. `5ywl` names eight case studies, but CS0060 and CS0061 are absent from
the authoritative `ATLAS-2026.05.yaml`. `hjy3` assumes ASI and LAAF coverage is
missing even though both are already represented in current taxonomy/mapping
surfaces, so it needs a gap audit before any extraction.

**Deferred:** 9t4c, 7ov6, is98

## Posture

- **Stance**: Pre-alpha, correctness-first. Merge-on-green.
- **HEAD**: PR #264 merge `3bae659` plus the pending coordination handoff commit
- **Worktree**: Mayor checkout contains only the coordination files being
  committed for this machine-migration handoff; merged cmps.9 worktree retained
- **Tests**: 2892 passed, 3 skipped
- **Lint/format**: All 67 Python files changed by PR #264 clean
- **Open PRs**: None
- **Worktrees**: 1 clean, merged worker worktree retained; no active runner
