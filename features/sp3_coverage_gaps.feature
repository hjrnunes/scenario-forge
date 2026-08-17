Feature: SP3 Stage 7 — Coverage gap analysis
  Coverage gap analysis aggregates the three-way partition from SP2 with
  end-to-end coverage. It detects orphan elements (control structure elements
  not referenced by any ICA), orphan ICAs (ICAs not concretized into scenarios),
  and traceability errors. The result is written to coverage-gaps.json.

  Background:
    Given the SP3 coverage module is importable
    And a control structure with responsibilities RESP-1 and RESP-2, PM-1-1, PM-1-2, CA-1-1, CA-2-1
    And an enriched threat set with structural coverage data
    And a loss analysis with losses, hazards, and constraints

  # SP3-COV-01
  Scenario: SP3-COV-01 coverage gap analysis includes structural coverage from SP2
    Given an enriched threat set with structural_coverage total_slots 40, non_na 32, na 8
    When coverage gap analysis is computed
    Then the result structural_coverage total_slots is 40
    And the result structural_coverage non_na is 32
    And the result structural_coverage na is 8

  # SP3-COV-02
  Scenario: SP3-COV-02 coverage gap analysis partitions by ICA type
    Given an enriched threat set with by_ica_type NOT_PROVIDED 15 and INCORRECT 10
    When coverage gap analysis is computed
    Then by_ica_type has NOT_PROVIDED 15
    And by_ica_type has INCORRECT 10

  # SP3-COV-03
  Scenario: SP3-COV-03 coverage gap analysis partitions by controller
    Given an enriched threat set with by_controller RESP-1 12 and RESP-2 8
    When coverage gap analysis is computed
    Then by_controller has RESP-1 12
    And by_controller has RESP-2 8

  # SP3-COV-04
  Scenario: SP3-COV-04 coverage gap analysis includes catalog correspondence
    Given an enriched threat set with catalog_correspondence structural_with_match 10, structural_unmapped 5
    When coverage gap analysis is computed
    Then catalog_correspondence structural_with_match is 10
    And catalog_correspondence structural_unmapped is 5
    And catalog_correspondence catalog_only_supplements is 0

  # SP3-COV-05
  Scenario: SP3-COV-05 coverage gap analysis lists uncovered OWASP threats
    Given an enriched threat set where no ICA matches OWASP threat T10
    When coverage gap analysis is computed
    Then uncovered_owasp_threats includes T10
    And uncovered_reason is not empty

  # SP3-COV-06
  Scenario: SP3-COV-06 orphan detection finds control structure elements not referenced by any ICA
    Given a control structure where PM-1-2 is not referenced by any ICA in the enriched threat set
    When coverage gap analysis is computed
    Then orphan_elements includes PM-1-2

  # SP3-COV-07
  Scenario: SP3-COV-07 orphan detection finds ICAs not concretized into scenarios
    Given an enriched threat set with 10 structural threats and only 7 scenarios produced
    When coverage gap analysis is computed
    Then orphan_icas has 3 entries

  # SP3-COV-08
  Scenario: SP3-COV-08 coverage gap analysis records traceability errors
    Given 7 scenarios where 2 have broken traceability chains
    When coverage gap analysis is computed
    Then traceability_errors has 2 entries

  # SP3-COV-09
  Scenario: SP3-COV-09 coverage gap analysis records N/A reconciliation flags
    Given an enriched threat set with 2 N/A reconciliation flags
    When coverage gap analysis is computed
    Then na_reconciliation_flags has 2 entries

  # SP3-COV-10
  Scenario: SP3-COV-10 coverage gap analysis is deterministic with zero LLM calls
    Given an enriched threat set, control structure, loss analysis, and 7 scenario envelopes
    When coverage gap analysis is computed
    Then no LLM calls are made

  # SP3-COV-11
  Scenario: SP3-COV-11 coverage gaps are written to coverage-gaps.json
    Given a run directory for output
    When coverage gap analysis is computed and written
    Then a file coverage-gaps.json exists in the run directory
    And the file contains structural_coverage
    And the file contains orphan_elements
    And the file contains orphan_icas
    And the file contains traceability_errors
