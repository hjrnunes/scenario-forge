Feature: Runtime split compatibility
  The split preserves the acceptance runtime facade, executable IR coverage,
  handler behavior, and known baseline without contacting a live LLM.

  Background:
    Given the runtime split test workspace is isolated

  # Runtime split compatibility — 01 facade exports remain compatible
  Scenario: Runtime split compatibility — 01 facade exports remain compatible
    When the acceptance facade is imported in a fresh process
    Then it exports execute_ir, execute_step, STEP_PATTERNS, find_pattern_conflicts, _register, _register_first, and _derive_feature_tag
    And the public export signatures match the pre-split baseline

  # Runtime split compatibility — 02 executable IR entrypoints remain one-to-one
  Scenario: Runtime split compatibility — 02 executable IR entrypoints remain one-to-one
    When all canonical executable IR files are enumerated
    Then every executable IR file has exactly one generated acceptance entrypoint
    And each generated entrypoint points to one existing canonical IR file
    And dry-checker report JSON files are excluded from executable IR coverage

  # Runtime split compatibility — 03 every IR step resolves
  Scenario: Runtime split compatibility — 03 every IR step resolves
    When every example-expanded background and scenario step is resolved in its IR feature scope
    Then every step resolves to exactly one selected handler under first-match lookup
    And no step reports Unsupported step

  # Runtime split compatibility — 04 representative module behaviors are unchanged
  Scenario: Runtime split compatibility — 04 representative module behaviors are unchanged
    When the no-LLM representative matrix is executed
      | module | IR files |
      | foundation | loss_analysis_validation, control_structure_validation, ica_enumeration_validation, enriched_threat_set_validation, scenario_spec_validation |
      | infrastructure | stpa_infrastructure, stpa_fixtures, model_profiles, calls_html_rendering |
      | scenario-envelope | scenario_envelope, envelope_8b06_consumer_hints, envelope_umcf_system_context |
      | sp1-core | sp1_loss_analysis, sp1_control_structure_derivation, sp1_completeness_critic, sp1_capability_profile |
      | sp1-revision | sp1_revision, sp1_revision_delta, sp1_revision_strip_empty, sp1_revision_runaway_output, sp1_revision_cmid_dedup |
      | parallel-llm | parallel_llm_calls, parallel_max_workers_config, parallel_sp1_compatibility, parallel_sp2_sp3_design |
      | stage2-restructure | stage2_assembly, stage2_call2a, stage2_call2b, stage2_call3 |
      | sp2 | sp2_catalog_enrichment, sp2_na_quality, sp2_run_orchestration, sp2_slot_creation, sp2_slot_filling, sp2_technology_context |
      | sp3 | sp3_attack_tree, sp3_bdi_generation, sp3_coverage_gaps, sp3_eval_metrics, sp3_gherkin, sp3_narrative, sp3_run_orchestration, sp3_validators, stage6_gddi_loss_id_validation, stage6_jpkw_gherkin_structured_output, stage6_v689_attack_tree_root_label |
      | report | attack_tree_visual, eval_scorecard_gauges, gherkin_highlighting, hero_summary, llm_call_inspector, report_generation, run_manifest, sp1_flow_card, sp2_flow_card, sp3_flow_card, sticky_nav |
      | stage1-split | stage1_ordering, stage1a_split, stage1b_revision |
      | acceptance-refresh | stage1b-entry-point-guidance, stage1b-grounding, stage2-assembly-fallback, stage2-coordination-analysis |
      | critic-revision-fix | critic-gap-detection, critic-prompt-context, revision-gap-dismissal, revision-next-cm-id, revision-prompt-context, revision-token-ceiling |
      | shadow-cleanup | class-b-decisions, duplicate-assertion, no-shadowing-invariant, registration-priority |
    Then every selected no-LLM representative scenario preserves its pre-split result
    And the two revision delegation functions remain callable and preserve delegated outcomes

  # Runtime split compatibility — 05 import order is safe
  Scenario: Runtime split compatibility — 05 import order is safe
    When facade-first and module-first imports are probed in separate fresh processes
    Then neither order raises an import or circular-import error
    And both processes produce the same ordered registry digest

  # Runtime split compatibility — 06 repeated imports are idempotent
  Scenario: Runtime split compatibility — 06 repeated imports are idempotent
    When a second import of the facade and every manifest module is attempted in a fresh process
    Then the process exits successfully
    And the registry length, key set, ordered patterns, and feature tags are unchanged

  # Runtime split compatibility — 07 known baseline is preserved
  Scenario: Runtime split compatibility — 07 known baseline is preserved
    When acceptance and unit baselines are measured without a live LLM endpoint
    Then acceptance remains 72 passed and 9 known failures
    And unit remains 5899 passed, 11 known failures, and 15 skipped
    And source ruff remains clean
    And the 14 test-ruff findings remain classified as pre-existing
    And live-LLM checks are reported as SKIP rather than FAIL
