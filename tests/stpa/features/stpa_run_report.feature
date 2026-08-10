Feature: STPA Run — Report generation
  The stpa-run command auto-generates stpa-report.html from all artifacts
  in the output directory after SP3 completes. The report always runs,
  even if some stages had degraded results.

  Background:
    Given the stpa-run pipeline runner module is importable
    And an output directory for artifacts

  # STPA-RUN-RPT-01
  Scenario: STPA-RUN-RPT-01 stpa-report.html is generated after all stages
    Given an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with all required flags
    Then a file stpa-report.html exists in the output directory

  # STPA-RUN-RPT-02
  Scenario: STPA-RUN-RPT-02 report is generated even when SP3 had degraded results
    Given an LLM that returns valid SP1 and SP2 responses but degraded SP3 results
    When the stpa-run command is invoked with all required flags
    Then a file stpa-report.html exists in the output directory

  # STPA-RUN-RPT-03
  Scenario: STPA-RUN-RPT-03 report is generated even when SP2 had degraded results
    Given an LLM that returns valid SP1 responses but degraded SP2 results
    When the stpa-run command is invoked with all required flags
    Then a file stpa-report.html exists in the output directory

  # STPA-RUN-RPT-04
  Scenario: STPA-RUN-RPT-04 report is always generated as the final stage
    Given an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with all required flags
    Then the report generation runs after SP3
