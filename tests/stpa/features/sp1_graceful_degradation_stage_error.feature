# mutation-stamp: sha256=2ba0d3330482e428fb34879d727b13488b54f09ef035a1c0eb9f9a88db81c576
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T18:22:32.289547Z","feature_name":"SP1 — Stage failure raises StageError and run returns partial results","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/sp1_graceful_degradation_stage_error.feature","background_hash":"d764efea6f065a70d9294f99c588c6fa177f1dcd4982c88652b061ac822f7a71","implementation_hash":"unknown","scenarios":[{"index":0,"name":"SP1-GD-08 derivation stage failure raises StageError with context","scenario_hash":"65922bae67a1b7bda29878c74bdb118dd2bed2ce0e902285497a4101aad40303","mutation_count":15,"result":{"Total":15,"Killed":15,"Survived":0,"Errors":0},"tested_at":"2026-08-08T18:22:32.289547Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 — Stage failure raises StageError and run returns partial results
  If a derivation stage's LLM call fails validation or raises an
  exception, the stage raises a StageError carrying stage and step
  context. The run orchestrator catches StageError and returns a partial
  SP1RunResult with stage_errors populated, artifacts produced before
  the failure preserved, and remaining artifacts as None. The run
  manifest is still written with available info. The failed call is
  logged with success=false and an error message.

  Background:
    Given the STPA system model run module is importable
    And a use-case description and risk extraction JSON are available as input
    And a run directory for output

  # SP1-GD-08
  Scenario Outline: SP1-GD-08 derivation stage failure raises StageError with context
    Given an LLM that returns an invalid response for <stage>
    When the <stage> derivation is attempted
    Then a StageError is raised
    And the StageError carries stage <stage_name>
    And the StageError carries step <step_name>
    And the failed call is logged with success=false

    Examples:
      | stage          | stage_name | step_name               |
      | stage_1a       | stage_1a   | loss_analysis           |
      | stage_1b       | stage_1b   | capability_profile      |
      | stage_2_call_1 | stage_2    | call_1_requirements     |
      | stage_2_call_2 | stage_2    | call_2_responsibilities |
      | stage_2_call_3 | stage_2    | call_3_connections      |

  # SP1-GD-09
  Scenario: SP1-GD-09 Stage 1a failure produces partial result with all artifacts None
    Given an LLM that returns an invalid response for stage_1a
    When the full SP1 run is executed
    Then the run returns a partial SP1RunResult
    And the stage_errors list contains the stage_1a failure
    And loss_analysis is None
    And capability_profile is None
    And control_structure is None
    And a run manifest is written

  # SP1-GD-10
  Scenario: SP1-GD-10 Stage 1b failure preserves loss_analysis and sets profile to None
    Given an LLM that returns valid responses for stage_1a
    And an LLM that returns an invalid response for stage_1b
    When the full SP1 run is executed
    Then the run returns a partial SP1RunResult
    And the stage_errors list contains the stage_1b failure
    And loss_analysis is not None
    And capability_profile is None
    And control_structure is None
    And a run manifest is written

  # SP1-GD-11
  Scenario: SP1-GD-11 Stage 2 failure preserves loss_analysis and profile
    Given an LLM that returns valid responses for stage_1a and stage_1b
    And an LLM that returns an invalid response for stage_2
    When the full SP1 run is executed
    Then the run returns a partial SP1RunResult
    And the stage_errors list contains the stage_2 failure
    And loss_analysis is not None
    And capability_profile is not None
    And control_structure is None
    And a run manifest is written

  # SP1-GD-12
  Scenario: SP1-GD-12 failed derivation call logged with success=false and error message
    Given an LLM that returns an invalid response for stage_1a
    When the full SP1 run is executed
    Then a call log entry exists with success=false
    And the call log entry stage is stage_1a
    And the call log entry step is loss_analysis
    And the call log entry has an error message field

  # SP1-GD-13
  Scenario: SP1-GD-13 pipeline does not crash on any single stage validation failure
    Given an LLM that returns an invalid response for stage_2
    When the full SP1 run is executed
    Then the pipeline does not raise an exception
    And a partial SP1RunResult is returned

  # SP1-GD-14
  Scenario: SP1-GD-14 derivation stage LLM exception raises StageError and logs failure
    Given an LLM that raises a RuntimeError during stage_1a
    When the full SP1 run is executed
    Then the run returns a partial SP1RunResult
    And the stage_errors list contains the stage_1a failure
    And a call log entry exists with success=false

  # SP1-GD-15
  Scenario: SP1-GD-15 run manifest records stage_errors on partial failure
    Given an LLM that returns an invalid response for stage_1b
    When the full SP1 run is executed
    Then a run manifest is written
    And the manifest contains a stage_errors field
    And the stage_errors field includes the stage_1b failure description
