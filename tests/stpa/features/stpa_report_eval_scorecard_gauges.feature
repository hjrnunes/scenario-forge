# mutation-stamp: sha256=a470c56fbde09b3fb8c39fa48a2330ae8cf91064ee0a1237cbf9b786f3116797
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T13:22:13.956908Z","feature_name":"STPA Report Eval Scorecard Gauges","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/stpa_report_eval_scorecard_gauges.feature","background_hash":"c6feb91fb6e4d16412a5649e064a8dc42d7ab1cd02a855b3861b9693e0d9c9f8","implementation_hash":"unknown","scenarios":[{"index":3,"name":"Gauge color thresholds","scenario_hash":"e5e98105280cbc670b54c5c6e9e4bb269010502f77e2afac5a1d9fe3aeb0c78f","mutation_count":15,"result":{"Total":15,"Killed":15,"Survived":0,"Errors":0},"tested_at":"2026-08-10T13:22:13.956908Z"}]}
# acceptance-mutation-manifest-end

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
