Feature: STPA Run — SP2 execution
  The stpa-run command executes SP2 as the second stage, loading SP1
  artifacts (control-structure.yaml, capability-profile.yaml,
  loss-analysis.yaml) from the output directory. SP2 produces
  ica-enumeration.yaml, enriched-threats.yaml, and appends to calls.jsonl.

  Background:
    Given the stpa-run pipeline runner module is importable
    And an output directory with completed SP1 artifacts

  # STPA-RUN-SP2-01
  Scenario: STPA-RUN-SP2-01 SP2 runs after SP1 and writes expected artifacts
    Given an LLM that returns valid slot fill results for all responsibilities
    When the stpa-run command is invoked with all required flags
    Then a file ica-enumeration.yaml exists in the output directory
    And a file enriched-threats.yaml exists in the output directory

  # STPA-RUN-SP2-02
  Scenario: STPA-RUN-SP2-02 SP2 loads SP1 artifacts from the output directory
    Given an LLM that returns valid slot fill results for all responsibilities
    When the stpa-run command is invoked with all required flags
    Then the SP2 run receives the control structure from control-structure.yaml
    And the SP2 run receives the capability profile from capability-profile.yaml
    And the SP2 run receives the loss analysis from loss-analysis.yaml

  # STPA-RUN-SP2-03
  Scenario: STPA-RUN-SP2-03 SP2 calls are appended to calls.jsonl
    Given an LLM that returns valid slot fill results for all responsibilities
    When the stpa-run command is invoked with all required flags
    Then the file calls.jsonl contains entries from both SP1 and SP2

  # STPA-RUN-SP2-04
  Scenario: STPA-RUN-SP2-04 --max-workers is forwarded to SP2
    Given an LLM that returns valid slot fill results for all responsibilities
    When the stpa-run command is invoked with --max-workers 4
    Then the SP2 run is executed with max_workers 4
