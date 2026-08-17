# stpa-report-eval-scorecard-gauges
Feature: STPA Report Eval Scorecard Gauges
  The eval scorecard displays each metric as a colored gauge/bar:
  green for scores >= 80%, yellow for scores >= 60%, red for scores < 60%.

  Background:
    Given a combined output directory containing eval-scorecard.yaml with metrics:
      | metric                    | rate  |
      | structural_consideration   | 1.0   |
      | na_quality                 | 1.0   |
      | bdi_grounding              | 1.0   |
      | tree_branch_coverage       | 0.0   |
      | traceability_depth        | 1.0   |
      | diversity                  | 0.65  |

  Scenario: Score >= 80% renders green gauge
    When I generate the STPA report
    Then the eval scorecard gauge for "traceability_depth" is colored green
    And the eval scorecard gauge for "bdi_grounding" is colored green

  Scenario: Score >= 60% and < 80% renders yellow gauge
    When I generate the STPA report
    Then the eval scorecard gauge for "diversity" is colored yellow

  Scenario: Score < 60% renders red gauge
    When I generate the STPA report
    Then the eval scorecard gauge for "tree_branch_coverage" is colored red

  Scenario Outline: Gauge color thresholds
    Given eval-scorecard.yaml contains a metric "<metric>" with rate "<rate>"
    When I generate the STPA report
    Then the eval scorecard gauge for "<metric>" is colored "<color>"

    Examples:
      | metric              | rate | color  |
      | metric_a            | 0.80 | green  |
      | metric_b            | 0.79 | yellow |
      | metric_c            | 0.60 | yellow |
      | metric_d            | 0.59 | red    |
      | metric_e            | 0.0  | red    |
