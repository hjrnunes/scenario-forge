# Acceptance suite staleness analysis (beads er9q + in8d)

Baseline: `uv run pytest acceptance/generated/ -q` → **25 failed, 45 passed**

Captured by the orchestrator at HEAD `a9734ac`, after stage1-split-reorder (tgs3+82t5) and
stage2-restructure (w5tp) both landed.

## Classification

### Category A — LLM-endpoint blocked (7 tests) — OUT OF SCOPE, not fixable without an endpoint

These are the *new* feature files from the two completed work items. Their static scenarios pass;
only the pipeline-mode scenarios fail, all with the identical message
`LLM endpoint not configured (pipeline-mode scenario requires LLM)`.

- `stage1_ordering`
- `stage1a_split`
- `stage1b_revision`
- `stage2_assembly`
- `stage2_call2a`
- `stage2_call2b`
- `stage2_call3`

Leave these alone. Do not weaken or delete their pipeline-mode scenarios.

### Category B — Stale from stage2-restructure (11 tests) — IN SCOPE (bead in8d)

| Test | Failure |
|---|---|
| `sp1_capability_profile_injection` | `TemplateNotFound: 'stage2_call2_user.j2'` (template deleted) |
| `sp1_id_namespace_validation` | `TemplateNotFound: 'stage2_call2_system.j2'` (template deleted) |
| `sp1_run_orchestration` | `Missing template: stage2_call2_system.j2` |
| `sp2_run_orchestration` | `Missing template: stage2_call2_system.j2` |
| `sp3_run_orchestration` | `Missing template: stage2_call2_system.j2` |
| `sp1_control_structure_derivation` | `AttributeError: 'ResponsibilitySet' has no attribute 'controlled_processes'` (moved to `ControlElementSet`) |
| `sp1_critic_id_sanitization` | `ImportError: cannot import name 'ConnectionSet'` (class removed) |
| `sp1_orphan_pm_repair` | `ImportError: cannot import name 'ConnectionSet'` (class removed) |
| `sp1_connection_set_merge` | step `call_3_connections` renamed `call_3_coordination`; CP model changed |
| `sp1_merge_fallback_degradation` | step `merge_connection_set` removed |
| `sp1_merge_fallback_sanitize` | Sanitize-04 `feedback_source`/`target`/`source` nullified; Sanitize-09 `CP-1 not found`; Sanitize-10 `Expected CL-1 but got set()` |

### Category C — Stale from stage1-split-reorder (4 tests) — IN SCOPE (bead er9q)

| Test | Failure |
|---|---|
| `sp1_entry_point_checklist` | EPCL-02/03/04 expect the five entry-point categories in `stage1b_system.j2`; that checklist was intentionally REMOVED |
| `sp1_prompt_quality_fixes` | `stage1a_system.j2` not found (split into `stage1a_risk_*` + `stage1a_gap_*`) |
| `sp1_security_constraints_contamination` | asserts old `stage1b_system.j2` content |
| `sp1_prompt_bug_fixes` | mixed: `stage1a_system.j2` (Stage 1) + `stage2_call2_system.j2` (Stage 2) + stage2_call3 text mismatch |

### Category D — Mixed-stage staleness (1 test) — IN SCOPE (both beads)

`gd_stage_error_ir`:
- GD-08/example_1: `Expected step 'loss_analysis', got 'risk_derivation'` (Stage 1 rename)
- GD-08/example_2: `Expected StageError, got TypeError`
- GD-08/example_4: `Expected step 'call_2_responsibilities', got 'call_2a_responsibilities'` (Stage 2)
- GD-08/example_5: `Expected step 'call_3_connections', got 'call_2b_control_elements'` (Stage 2)
- GD-09/example_1: `capability_profile is not None`

### Category E — Pre-existing, unrelated (2 tests) — OUT OF SCOPE

- `sp3_attack_tree` — SP3-TREE-01 `Expected 1 LLM call, got 0` (all other scenarios pass)
- `stage6_jpkw_gherkin_structured_output` — Stage 6 feature content (most scenarios pass)

Do not fix these here; they belong to SP3/Stage 6 work items.

## Target outcome

In-scope: **16 tests** (Categories B + C + D). After this work item:

- `uv run pytest acceptance/generated/ -q` → **10 failed, 60 passed**
  (10 = 7 Category A LLM-endpoint + 2 Category E pre-existing + 1 genuine
  source defect, below)

### Category F — genuine source regression uncovered by this refresh

`sp1_merge_fallback_sanitize` (7 scenarios) is **expected to stay red** until
`scenario-forge-32aa` (P1) is fixed. The Stage 2 restructure left
`_assemble_with_fallback` discarding every control action and feedback channel on
the degraded path (it carries `controlled_processes` over from the Call 2b
`ControlElementSet` but not `control_actions`/`feedback_channels`), so a single
invalid LLM reference costs the whole control loop rather than just the bad
reference. Repro: `tmp/probe_fallback.py`.

This red test is correct and load-bearing. A workaround that masked it by
reimplementing the merge inside `_h_ar_assemble` was deliberately reverted in
`87e08de`; **do not reintroduce it** and do not "fix" this test by changing the
handler.

## Symbol/name mapping reference

### Stage 1 (from stage1-split-reorder)
- `stage1a_system.j2` / `stage1a_user.j2` → DELETED, split into `stage1a_risk_system.j2` / `stage1a_risk_user.j2` and `stage1a_gap_system.j2` / `stage1a_gap_user.j2`
- `stage1b_system.j2` / `stage1b_user.j2` → REWRITTEN (KC taxonomy present; entry-point checklist REMOVED; loss-analysis context REMOVED)
- Call-log step `loss_analysis` → `risk_derivation`
- Stage order is now 1b → 1a-1 → 1a-2 → Stage 2
- `Stage1Profile` bool fields removed from `capability_profile.py`

### Stage 2 (from stage2-restructure)
- `ConnectionSet` → REMOVED, replaced by `CoordinationAnalysis` (`.coordination_links`, `.integrity_findings`)
- `merge_connection_set` / `_merge_with_fallback` → REMOVED, replaced by `_assemble_control_structure`, `_assemble_with_fallback`, `_add_coordination_links_with_fallback`, `_assign_elements_to_responsibilities`
- `ResponsibilitySet` now has ONLY `responsibilities` (no `controlled_processes` — those moved to `ControlElementSet`)
- New models: `ControlElementSet`, `Requirement`, `RequirementSet`
- Call fns: `_call_1_requirements`, `_call_2a_responsibilities`, `_call_2b_control_elements`, `_call_3_coordination`
- Call-log steps: `call_2_responsibilities` → `call_2a_responsibilities` + `call_2b_control_elements`; `call_3_connections` → `call_3_coordination`
- Templates: `stage2_call2_*` DELETED → `stage2_call2a_*` + `stage2_call2b_*`
- `STAGE_2_CALL_COUNT = 4` exported from `control_structure.py`

## Pipeline artifacts to regenerate

Feature files live in `tests/stpa/features/`. The generated artifacts are:
- IR: `acceptance/ir/<name>.json` — regenerate via `bb gherkin-parser <feature> <out.json>`
  (APS clone is at `tmp/Acceptance-Pipeline-Specification/`)
- Entry points: `acceptance/generated/<name>_acceptance_test.py` — regenerate via
  `acceptance/generate_entrypoints.py`
- Step handlers: `acceptance/acceptance_runtime.py` (already partly updated by the hardender
  in `a9734ac`; it added backward-compat wrappers that may now be removable)

## Note on prior misreporting

The hardender's report for w5tp claimed all 25 acceptance failures were "pre-existing LLM-endpoint
errors." That is incorrect — only 7 are. QA corrected this to 12 stale + 4 Stage 1, which is closer
but still undercounts: the true in-scope figure is 16. Trust this document's classification, which
was produced by running each failing test individually and reading the actual assertion messages.
