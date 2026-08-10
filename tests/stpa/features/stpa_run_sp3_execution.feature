Feature: STPA Run — SP3 execution
  The stpa-run command executes SP3 as the third stage, loading SP1 and
  SP2 artifacts from the output directory. SP3 produces scenarios/*.yaml,
  scenarios/*.feature, eval-scorecard.yaml, coverage-gaps.json, and appends
  to calls.jsonl. The capability_profile is passed to SP3 only when
  --capability-profile was explicitly provided by the user.

  Background:
    Given the stpa-run pipeline runner module is importable
    And an output directory with completed SP1 and SP2 artifacts

  # STPA-RUN-SP3-01
  Scenario: STPA-RUN-SP3-01 SP3 runs after SP2 and writes expected artifacts
    Given an LLM that returns valid BDI generation, narrative, attack tree, and Gherkin results
    When the stpa-run command is invoked with all required flags
    Then a directory scenarios exists in the output directory
    And at least one file *.yaml exists in the scenarios directory
    And at least one file *.feature exists in the scenarios directory
    And a file eval-scorecard.yaml exists in the output directory
    And a file coverage-gaps.json exists in the output directory

  # STPA-RUN-SP3-02
  Scenario: STPA-RUN-SP3-02 SP3 loads SP1 and SP2 artifacts from the output directory
    Given an LLM that returns valid results for all SP3 stages
    When the stpa-run command is invoked with all required flags
    Then the SP3 run receives the enriched threat set from enriched-threats.yaml
    And the SP3 run receives the control structure from control-structure.yaml
    And the SP3 run receives the loss analysis from loss-analysis.yaml

  # STPA-RUN-SP3-03
  Scenario: STPA-RUN-SP3-03 capability_profile is passed to SP3 when --capability-profile is provided
    Given an LLM that returns valid results for all SP3 stages
    And a pre-built capability-profile.yaml at a known path
    When the stpa-run command is invoked with --capability-profile <path>
    Then the SP3 run receives a non-None capability_profile

  # STPA-RUN-SP3-04
  Scenario: STPA-RUN-SP3-04 capability_profile is not passed to SP3 without --capability-profile
    Given an LLM that returns valid results for all SP3 stages
    When the stpa-run command is invoked without --capability-profile
    Then the SP3 run receives capability_profile as None

  # STPA-RUN-SP3-05
  Scenario: STPA-RUN-SP3-05 SP3 calls are appended to calls.jsonl
    Given an LLM that returns valid results for all SP3 stages
    When the stpa-run command is invoked with all required flags
    Then the file calls.jsonl contains entries from SP1, SP2, and SP3

  # STPA-RUN-SP3-06
  Scenario: STPA-RUN-SP3-06 --max-workers is forwarded to SP3
    Given an LLM that returns valid results for all SP3 stages
    When the stpa-run command is invoked with --max-workers 4
    Then the SP3 run is executed with max_workers 4
