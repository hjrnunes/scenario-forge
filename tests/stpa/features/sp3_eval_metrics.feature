Feature: SP3 Stage 7 — Diagnostic eval metrics
  Six diagnostic metrics measure structural properties of the scenario set.
  They are diagnostic, not success criteria. The metrics are: structural
  consideration (from SP2), N/A quality (from SP2), BDI grounding, tree branch
  coverage, traceability depth, and diversity. All are deterministic (0 LLM
  calls).

  Background:
    Given the SP3 eval metrics module is importable
    And a control structure with responsibilities RESP-1 and RESP-2, each with PM parts and control actions
    And a set of 5 scenario envelopes with various properties

  # SP3-EVAL-01
  Scenario: SP3-EVAL-01 structural consideration is imported from SP2 coverage analysis
    Given an enriched threat set with structural_consideration total_slots 40, considered 40, rate 1.0
    When the structural consideration metric is computed
    Then the metric value total_slots is 40
    And the metric value considered is 40
    And the metric value rate is 1.0

  # SP3-EVAL-02
  Scenario: SP3-EVAL-02 N/A quality is imported from SP2 coverage analysis
    Given an enriched threat set with na_quality na_count 5, quality_count 4, quality_rate 0.8
    When the N/A quality metric is computed
    Then the metric value na_count is 5
    And the metric value quality_count is 4
    And the metric value quality_rate is 0.8

  # SP3-EVAL-03
  Scenario: SP3-EVAL-03 BDI grounding metric computes belief, desire, and intention grounding rates
    Given 5 scenarios where 4 of 10 beliefs reference valid PM IDs, 5 of 5 desires reference valid RESP IDs, and 8 of 10 intentions reference valid CA IDs
    When the BDI grounding metric is computed
    Then belief_grounding_rate is 0.4
    And desire_grounding_rate is 1.0
    And intention_grounding_rate is 0.8

  # SP3-EVAL-04
  Scenario: SP3-EVAL-04 BDI grounding metric handles zero scenarios gracefully
    Given an empty set of scenarios
    When the BDI grounding metric is computed
    Then belief_grounding_rate is 0
    And desire_grounding_rate is 0
    And intention_grounding_rate is 0

  # SP3-EVAL-05
  Scenario: SP3-EVAL-05 tree branch coverage metric counts scenarios with 2-plus categories
    Given 5 scenarios where 3 have 2 or more branch categories and 2 have only 1
    When the tree branch coverage metric is computed
    Then total_scenarios is 5
    And scenarios_with_2plus_categories is 3
    And coverage_rate is 0.6

  # SP3-EVAL-06
  Scenario: SP3-EVAL-06 tree branch coverage metric handles zero scenarios gracefully
    Given an empty set of scenarios
    When the tree branch coverage metric is computed
    Then total_scenarios is 0
    And coverage_rate is 0

  # SP3-EVAL-07
  Scenario: SP3-EVAL-07 traceability depth metric counts complete chains
    Given 5 scenarios where 4 have complete unbroken provenance chains and 1 has a broken link
    When the traceability depth metric is computed
    Then total_scenarios is 5
    And complete_chains is 4
    And traceability_rate is 0.8

  # SP3-EVAL-08
  Scenario: SP3-EVAL-08 traceability depth metric handles zero scenarios gracefully
    Given an empty set of scenarios
    When the traceability depth metric is computed
    Then total_scenarios is 0
    And traceability_rate is 0

  # SP3-EVAL-09
  Scenario: SP3-EVAL-09 diversity metric counts by responsibility
    Given 5 scenarios where 3 target RESP-1 and 2 target RESP-2
    When the diversity metric is computed
    Then by_responsibility has RESP-1 3
    And by_responsibility has RESP-2 2

  # SP3-EVAL-10
  Scenario: SP3-EVAL-10 diversity metric counts by ICA type
    Given 5 scenarios with 3 NOT_PROVIDED and 2 INCORRECT
    When the diversity metric is computed
    Then by_ica_type has NOT_PROVIDED 3
    And by_ica_type has INCORRECT 2

  # SP3-EVAL-11
  Scenario: SP3-EVAL-11 diversity metric counts by branch category
    Given 5 scenarios where controller_side appears in 4, path_side in 3, and coordination_gap in 1
    When the diversity metric is computed
    Then by_branch_category has controller_side 4
    And by_branch_category has path_side 3
    And by_branch_category has coordination_gap 1

  # SP3-EVAL-12
  Scenario: SP3-EVAL-12 diversity metric computes Shannon entropy for responsibility distribution
    Given 5 scenarios where 3 target RESP-1 and 2 target RESP-2
    When the diversity metric is computed
    Then responsibility_diversity is a non-negative float

  # SP3-EVAL-13
  Scenario: SP3-EVAL-13 diversity metric computes Shannon entropy for ICA type distribution
    Given 5 scenarios with 3 NOT_PROVIDED and 2 INCORRECT
    When the diversity metric is computed
    Then ica_type_diversity is a non-negative float

  # SP3-EVAL-14
  Scenario: SP3-EVAL-14 diversity metric counts unique attack mechanisms
    Given 5 scenarios with 4 unique attack mechanisms across their attack trees
    When the diversity metric is computed
    Then unique_attack_mechanisms is 4

  # SP3-EVAL-15
  Scenario: SP3-EVAL-15 all eval metrics are deterministic with zero LLM calls
    Given 5 scenario envelopes and the enriched threat set and control structure and loss analysis
    When all 6 metrics are computed
    Then no LLM calls are made

  # SP3-EVAL-16
  Scenario: SP3-EVAL-16 eval scorecard is written to eval-scorecard.yaml
    Given a run directory for output
    When all 6 metrics are computed and the scorecard is written
    Then a file eval-scorecard.yaml exists in the run directory
    And the scorecard contains metrics for structural_consideration
    And the scorecard contains metrics for na_quality
    And the scorecard contains metrics for bdi_grounding
    And the scorecard contains metrics for tree_branch_coverage
    And the scorecard contains metrics for traceability_depth
    And the scorecard contains metrics for diversity

  # SP3-EVAL-17
  Scenario: SP3-EVAL-17 eval scorecard includes validation errors
    Given 5 scenarios with 2 stage-local validation errors and 1 traceability error
    When the scorecard is written
    Then the scorecard validation section has 2 stage_local_errors
    And the scorecard validation section has 1 traceability_error
