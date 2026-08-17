# stpa-report-run-manifest
Feature: STPA Report Run Manifest
  The run manifest section displays input hashes, timing, and configuration
  from run-manifest.yaml at the bottom of the report.

  Background:
    Given a combined output directory containing run-manifest.yaml with:
      | run_id              | created_at                  | model          | max_workers |
      | sp3-20260810T111600Z | 2026-08-10T11:16:00+00:00 | gemma-4-26b    | 4           |

  Scenario: Run manifest section is present
    When I generate the STPA report
    Then the run manifest section exists in the report
    And the run manifest section is labeled "Manifest"

  Scenario: Run manifest displays input hashes
    Given run-manifest.yaml contains input_hashes for "loss_analysis" and "control_structure"
    When I generate the STPA report
    Then the run manifest section shows input hash for "loss_analysis"
    And the run manifest section shows input hash for "control_structure"

  Scenario: Run manifest displays timing and config
    When I generate the STPA report
    Then the run manifest section shows the model name "gemma-4-26b"
    And the run manifest section shows max_workers "4"
    And the run manifest section shows the created_at timestamp

  Scenario: Run manifest includes collapsible raw YAML
    When I generate the STPA report
    Then the run manifest section contains a collapsible raw YAML section for "run-manifest.yaml"
