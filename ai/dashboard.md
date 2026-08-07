# Mayor Dashboard

**Updated**: 2026-08-05
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

| Bead | Executor / thread | Branch | Occupied surface | State |
|------|-------------------|--------|------------------|-------|
| `422o.4` | Small orb / [Amp thread](https://ampcode.com/threads/T-019fd38e-15cf-76f8-8405-28e4b0017f9c), built-in Low mode | `worker/projection-traceability-422o.4` | Scenario envelope; projection realization schemas; Calls 0–3 constraints; narrative/tree/Gherkin/behavior traceability; deterministic validation and affected tests | Correcting PR #279 production wiring, mandatory projection cutover, standalone derivation, actual-artifact correspondence, and per-step semantic validation blockers |

The six authoring waves and corrected lineage were integrated atomically in
PR #277 and merged as `20e5341`. Final bead `422o.2.9` independently
qualified all 49 records; it and parent RFC `422o.2` are closed.
`422o.4` and `cmps.4` explicitly depend on completed `422o.3.1`; candidate-v2
now derives requirements only from independently audited authoritative links.

PR #278 merged as `c9e714b`; `422o.3.1` and independent semantic audit
`422o.3.2` are closed. `422o.4` is active; `cmps.4` is intentionally held to
avoid overlapping generation/pipeline integration surfaces.

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
- Mayor pass reconciled live state: no in-progress beads, open PRs, worker
  worktrees, or runners. Proposed `cmps.6` before `cmps.7` because structured
  ingress/access evidence is an input to the later attack-complexity policy.
- Operator approved the plan. Claimed and dispatched `cmps.6` to a solo Low-mode
  orb; created and dispatched read-only kill-chain status audit `etie` in a
  separate Low-mode orb.
- Kill-chain audit `etie` completed and closed: schema/data/prompt plumbing is
  merged and tested; 46/71 patterns carry 321 scaffold steps, but generated-tree
  conformance is wholly advisory and absent from validation/eval/reporting.
  Mayor reproduced the counts and sent the actor-perspective boundary to the
  `cmps.6` worker.
- Refreshed-local-environment verification `8cxu` completed and closed: Jinja2
  3.1.6 imports successfully; both verifier and Mayor independently ran the
  exact focused suite with 177 passed and 3 skipped. Counts, ATLAS references,
  commit ancestry, and advisory-only conformance findings reconciled. Duplicate
  bead `oj5k`, persisted by an interrupted create command, was superseded.
- PR #265 initial commit `3d5d2d5` reported 460 focused test passes, but Mayor
  review returned acceptance blockers: controllability/access-class conflation,
  retained indirect actor allowlist, optional/non-candidate-owned ingress ID,
  unresolvable prose provenance, omitted downstream evidence, incompatible
  diversity forcing, unproven quarantine, and missing report contract. The same
  worker is applying a constrained correction pass; merge is not authorized.
- PR #265 correction `2e7ee23` closed effective-controllability and much of the
  schema/prompt plumbing. Second review returned relational canonicality,
  Call-1 realization/retry, a real divergent-tree validation crash, pre-write
  candidate ownership, actual quarantine exclusion, persisted diversity limits,
  and schema-valid report test blockers. The same worker is correcting them.
- PR #265 corrections `09b4e88` and `be62a95` closed the crash, final
  eval/report partition, typed narrative realization, and persisted
  diversity/report findings. Third review returned four production-path gaps:
  non-unique trust-boundary identity plus missing canonical IDs in Call 0,
  title-retry bypass of realization validation, remediation bypass of the
  ownership gate, and quarantine occurring after invalid scenarios have
  influenced diversity and coverage remediation. The same worker is applying
  the bounded correction; merge remains unauthorized.
- PR #265 correction `cb947eb` closed all four third-review findings.
  Independent Low-orb verification returned MERGE: focused cmps.6 suites and
  507 affected existing tests passed, changed-file Ruff passed, and three
  endpoint-dependent full-suite failures reproduced on `origin/master`. Mayor
  confirmed the remote head, clean diff, and MERGEABLE/CLEAN PR state. Explicit
  operator authorization is still required.
- PR [#265](https://github.com/hjrnunes/scenario-forge/pull/265) was authorized
  and merged as `0faa642`; `cmps.6` is closed. The implementation worker was
  stopped and `cmps.7` is unblocked.
- Universal kill-chain design interview completed and operator-approved. Filed
  P0 epic `422o` with RFC children `.1` canonical contract, `.2` full catalog
  requalification, `.3` deterministic projection/resource binding/candidate
  v2, `.4` envelope/artifact traceability, and `.5` catalog qualification.
  Amended `cmps.4/.5/.7/.8/.10` instead of creating duplicate planning,
  finalization, evaluation, or real-corpus release machinery; dependency graph
  is acyclic.
- Operator approved the first dispatch. Claimed `422o.1` and started one
  isolated Medium orb from `origin/master`; all catalog, projection-engine,
  generation, finalization, and evaluation work remains blocked pending review.
- PR #266 initial head `180f5ad` established the strict legacy/authoritative
  boundary, bounded condition types, canonical digests, and structural schema
  parity. Mayor review returned five foundational blockers: invalid projection
  omissions/unresolved states, unpinned generated evidence and generic resource
  IDs, contradictory role/control mapping semantics, manually authored rather
  than projection-derived execution requirements, and optional taxonomy
  qualification. The same worker is applying a bounded correction.
- PR #266 correction `cf49f59` closed projection partition/order/terminal
  invariants, canonical ID shapes, role/control/start/mapping coherence, and
  mandatory taxonomy qualification. Re-review returned three remaining
  contract blockers: recorded condition results are not computed from complete
  evidence, evidence/bindings are not qualified against the pinned capability
  fact snapshot, and `ExecutionRequirementSummary` remains freely authored
  rather than derivable (including an integration-only upstream-source domain
  that excludes indirect entry points). The same worker is applying a final
  bounded correction; merge remains unauthorized.
- PR #266 final correction `16b148d` closes the remaining contract blockers:
  pure complete-evidence tri-state evaluation determines every condition
  result; a mandatory pinned capability-snapshot resolver qualifies every fact
  reading and resource binding; premature `ExecutionRequirementSummary` was
  deferred to `422o.3`; and upstream-source identity supports entry points and
  integrations. Mayor independently reproduced 157 passed/3 skipped, clean
  changed-file Ruff/format/diff checks, and valid Draft 2020-12 schemas. PR is
  MERGEABLE/CLEAN and ready for explicit operator authorization.
- Operator authorized and Mayor merged PR #266 as `3af4192`; `422o.1` is
  closed. Canonical contract verification remains 157 passed/3 skipped with
  clean changed-file Ruff/format/diff checks. Catalog requalification `422o.2`
  and deterministic projection/candidate work `422o.3` are now unblocked and
  may proceed in parallel after dispatch approval.
- Operator approved parallel dispatch. `422o.2` is running in a Low orb as a
  read-only 71-record migration audit and child-wave decomposition;
  `422o.3` is running in a Medium orb implementing deterministic projection,
  resource binding, requirement derivation, and candidate v2. The requested
  Fireworks Kimi K3 model was not available through this workspace's exposed
  agent modes.
- `422o.2` audit completed after a Mayor-requested correction: 71 records split
  into 16 retain, 24 narrow, 25 construct, 5 split-eval, and 1
  supersede-eval. All current SSSOM links are only `skos:relatedMatch` and
  cannot become canonical exact mappings without semantic review. External
  source verification found the cited LAAF repositories unavailable; the only
  inspectable Qorvex LAAF is a different taxonomy and ID set. Catalog waves are
  paused for an operator decision on whether LAAF remains authoritative in v1.
- Operator chose ATLAS-only authority for v1: LAAF pins are optional, legacy
  LAAF IDs remain unqualified hints, and unsupported patterns are deferred or
  retired rather than weakly mapped. Filed `422o.2.1`–`.2.9`: taxonomy
  infrastructure, final lineage, six parallel source-file authoring waves, and
  final catalog validation. `422o.2.1` is next but will wait for active
  `422o.3` to settle to avoid overlapping canonical-model edits.
- Operator authorized and Mayor merged PR #267 as `5930b70`; `422o.3` is
  complete. Mayor review rejected heuristic execution-requirement inference and
  ambiguous duplicate pattern IDs; merged correction head `d982d8f` fails
  closed when the canonical contract lacks step/resource/observation linkage
  and rejects divergent records sharing one pattern ID. Independent re-review
  reproduced 332 passed with clean changed-file Ruff/format/diff checks.
  Explicit linkage remains a prerequisite before activating v2, not inferred
  semantics.
- Kimi K3, GLM 5.2, and Grok 4.5 custom modes were published as user plugins,
  but that dispatch policy is superseded: the operator now prohibits K3 and all
  plugin modes. Mayor work uses only built-in Amp modes on tiny/small orbs.
- `422o.2.1` Kimi K3 implementation is complete in open, unmerged PR #268 at
  `d4ec1d3`. Reported scope includes optional fail-closed LAAF authority,
  production ATLAS pin/resolver and normalized mapping-set digest
  infrastructure, candidate-v2 placeholder removal, and the duplicate
  pattern-ID loader guard. Worker reports 106 focused tests passed and a full
  2969 passed/3 skipped/11 endpoint-dependent failures matching pristine base.
  Mayor review found two blockers: omitted-LAAF digest framing and fail-open
  mapping-set pinning. Worker correction head `de67abd` reportedly canonicalizes
  omission to null without mutation and adds a strict six-file SSSOM v1 profile
  that rejects empty/incomplete manifests, duplicates, malformed rows, unknown
  columns, and unsupported metadata while pinning supported metadata. Reported
  correction checks are 114 focused passed and 2977 passed/3 skipped/11
  endpoint-dependent base failures. Mayor reproduced the focused and static
  checks but found one final small fail-closed gap: contradictory supported
  metadata across file partitions was accepted rather than rejected. Final
  correction head `fc38d17` adds global keyed metadata coherence with origins
  and a golden bundled digest. Mayor independently reproduced 117 focused
  tests and clean Ruff/format/diff checks; operator standing authorization was
  applied and PR #268 merged as `8f3ab95`. `422o.2.1` is closed. Catalog YAML
  and lineage remain out of scope.
- `422o.2.2` lineage resolution was reviewed at `54a6040` and merged through
  PR #269 as `6e33dc8`. The versioned artifact pins all 71 historical source
  records and resolves them to 49 authoritative resulting records; the bead is
  closed.
- `cmps.7` immutable actor capability and deterministic versioned attack
  complexity was reviewed at `b1ec8aa` and merged through PR #270 as
  `a852987`; the bead is closed.

## Tracker: 23 active (21 open, 2 in progress), 3 deferred

| Lane | Ready now | Then |
|------|-----------|------|
| Universal kill chains | Catalog RFC `.2` complete: 49/49 qualified, 71-source lineage preserved | Continue projection/conformance work under remaining `422o` children |
| Pipeline integrity | `cmps.7` merged | `cmps.4` remains gated by its declared dependencies |
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
- **HEAD**: local `master` at `cc460ce`, one coordination-doc commit ahead and
  42 commits behind `origin/master` at `20e5341`; local operator/Mayor
  changes prevent a routine fast-forward
- **Worktree**: no worker worktrees; Mayor checkout has local state in
  `.beads/interactions.jsonl`, `ai/amp-mayor.md`, `ai/dashboard.md`,
  `docs/superpowers/`, and the operator-refreshed `uv.lock`
- **Tests**: PR #277 exact-head clean-worktree affected suite 520 passed;
  worker full suite 3364 passed with 11 baseline missing-endpoint failures
- **Lint/format**: PR #277 changed Python files passed Ruff check/format and
  `git diff --check`
- **Open PRs**: none
- **Workers**: none active
