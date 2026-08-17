# stpa-report-hero-summary
Feature: STPA Report Hero Summary
  The hero summary appears at the top of the report and shows the use case
  name, run timestamp, scenario count, and key eval metrics at a glance.

  Scenario: Hero summary displays run metadata
    Given a combined output directory containing STPA artifacts with run-manifest.yaml:
      | run_id              | created_at                  | scenario_count |
      | sp3-20260810T111600Z | 2026-08-10T11:16:00+00:00 | 28             |
    When I generate the STPA report
    Then the hero summary section contains the run ID "sp3-20260810T111600Z"
    And the hero summary section contains the timestamp "2026-08-10T11:16:00+00:00"
    And the hero summary section contains the scenario count "28"

  Scenario: Hero summary displays key eval metrics
    Given a combined output directory with eval-scorecard.yaml containing:
      | metric                    | value |
      | traceability_rate         | 1.0   |
      | tree_branch_coverage_rate | 0.0   |
    When I generate the STPA report
    Then the hero summary section shows a traceability rate of "100%"
    And the hero summary section shows a tree branch coverage rate of "0%"

  Scenario: Hero summary is present even when eval scorecard is missing
    Given a combined output directory without eval-scorecard.yaml
    When I generate the STPA report
    Then the hero summary section is present
    And the hero summary section shows "N/A" for eval metrics
