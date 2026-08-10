Feature: STPA Run — Resume behavior
  With the --resume flag, the stpa-run command checks for existing artifacts
  in the output directory before each stage and skips completed stages.
  Without --resume, all stages run from scratch. The report is always
  generated, even when all stages are skipped.

  Background:
    Given the stpa-run pipeline runner module is importable
    And a use-case text file and risk extraction JSON are available

  # STPA-RUN-RES-01
  Scenario: STPA-RUN-RES-01 --resume skips SP1 when all SP1 artifacts exist
    Given an output directory with existing loss-analysis.yaml and capability-profile.yaml and control-structure.yaml
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --resume
    Then SP1 is not executed
    And SP1 artifacts are loaded from disk

  # STPA-RUN-RES-02
  Scenario: STPA-RUN-RES-02 --resume skips SP2 when SP2 artifacts exist
    Given an output directory with existing SP1 and SP2 artifacts including ica-enumeration.yaml and enriched-threats.yaml
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --resume
    Then SP2 is not executed
    And SP2 artifacts are loaded from disk

  # STPA-RUN-RES-03
  Scenario: STPA-RUN-RES-03 --resume skips SP3 when scenarios exist
    Given an output directory with existing SP1, SP2, and SP3 artifacts including scenarios with .yaml files
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --resume
    Then SP3 is not executed

  # STPA-RUN-RES-04
  Scenario: STPA-RUN-RES-04 report is always generated with --resume even if all stages skipped
    Given an output directory with existing SP1, SP2, and SP3 artifacts
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --resume
    Then a file stpa-report.html exists in the output directory

  # STPA-RUN-RES-05
  Scenario: STPA-RUN-RES-05 without --resume all stages run from scratch
    Given an output directory with existing SP1, SP2, and SP3 artifacts
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked without --resume
    Then SP1 is executed
    And SP2 is executed
    And SP3 is executed

  # STPA-RUN-RES-06
  Scenario: STPA-RUN-RES-06 --resume runs SP1 when SP1 artifacts are incomplete
    Given an output directory with only loss-analysis.yaml but no capability-profile.yaml or control-structure.yaml
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --resume
    Then SP1 is executed

  # STPA-RUN-RES-07
  Scenario: STPA-RUN-RES-07 --resume runs SP2 when SP2 artifacts are missing
    Given an output directory with complete SP1 artifacts but no SP2 artifacts
    And an LLM that returns valid responses for all stages
    When the stpa-run command is invoked with --resume
    Then SP2 is executed
