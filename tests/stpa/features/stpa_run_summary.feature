Feature: STPA Run — Summary output
  The stpa-run command prints a combined summary table showing results
  from all stages: SP1, SP2, SP3, and the report path.

  Background:
    Given the stpa-run pipeline runner module is importable
    And an LLM that returns valid responses for all stages
    And an output directory for artifacts

  # STPA-RUN-SUM-01
  Scenario: STPA-RUN-SUM-01 summary includes SP1 metrics
    When the stpa-run command is invoked with all required flags
    Then the console output includes SP1 losses count
    And the console output includes SP1 hazards count
    And the console output includes SP1 constraints count
    And the console output includes SP1 responsibilities count
    And the console output includes SP1 control actions count

  # STPA-RUN-SUM-02
  Scenario: STPA-RUN-SUM-02 summary includes SP2 metrics
    When the stpa-run command is invoked with all required flags
    Then the console output includes SP2 total slots
    And the console output includes SP2 N/A slots
    And the console output includes SP2 fill rate
    And the console output includes SP2 structural threats count
    And the console output includes SP2 mapped and unmapped counts

  # STPA-RUN-SUM-03
  Scenario: STPA-RUN-SUM-03 summary includes SP3 metrics
    When the stpa-run command is invoked with all required flags
    Then the console output includes SP3 scenario specs count
    And the console output includes SP3 scenario envelopes count
    And the console output includes SP3 validation errors count
    And the console output includes SP3 eval metrics summary

  # STPA-RUN-SUM-04
  Scenario: STPA-RUN-SUM-04 summary includes report path
    When the stpa-run command is invoked with all required flags
    Then the console output includes the path to stpa-report.html

  # STPA-RUN-SUM-05
  Scenario: STPA-RUN-SUM-05 summary includes stage errors when present
    Given an LLM that returns valid responses but with some stage errors
    When the stpa-run command is invoked with all required flags
    Then the console output includes stage error counts for affected stages
