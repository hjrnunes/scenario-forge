# mutation-stamp: sha256=5c1085977273c48b25dff7516ccf4f4c45911eca1b72c4dcb560bfb2883ac0ab
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T11:27:44.349587Z","feature_name":"Parallel infrastructure SP1 backwards compatibility","feature_path":"features/parallel_sp1_compatibility.feature","background_hash":"93a4ff32b850b092ffae476f5b2cf2ed3be0d0926c0e21bf8b7b001706738bd9","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: Parallel infrastructure SP1 backwards compatibility
  SP1 calls remain sequential due to data dependencies between stages.
  With max_workers=1 (the default), the parallel infrastructure must
  not alter existing SP1 behavior: output artifacts, call log entries,
  and stage execution order are identical to the pre-parallel baseline.
  The parallel_safe_llm_calls module is available for future SP1 use
  but does not change current stage logic.

  Background:
    Given the STPA system model run module is importable
    And a use-case description and risk extraction JSON are available as input

  # ParallelSP1-01
  Scenario: ParallelSP1-01 max_workers=1 produces identical output artifacts
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed with max_workers 1
    Then a file loss-analysis.yaml exists in the run directory
    And a file capability-profile.yaml exists in the run directory
    And a file control-structure.yaml exists in the run directory

  # ParallelSP1-02
  Scenario: ParallelSP1-02 stage execution order preserved with max_workers=1
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed with max_workers 1
    Then Stage 1a loss analysis is produced first
    And Stage 1b capability profile is produced second
    And Stage 2 control structure is produced third

  # ParallelSP1-03
  Scenario: ParallelSP1-03 call log identical with max_workers=1
    Given an LLM that returns valid responses for all stages
    And a run directory for output
    When the full SP1 run is executed with max_workers 1
    Then a file calls.jsonl exists in the run directory
    And the file contains entries for stage_1a, stage_1b, and stage_2 in order

  # ParallelSP1-04
  Scenario: ParallelSP1-04 SP1 does not call parallel_safe_llm_calls when max_workers=1
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed with max_workers 1
    Then all LLM calls go through safe_llm_call directly
    And no parallel_safe_llm_calls invocation occurs

  # ParallelSP1-05
  Scenario: ParallelSP1-05 SP1 data dependencies prevent parallelization
    Given the SP1 pipeline stage dependencies
    Then Stage 1b depends on the output of Stage 1a
    And Stage 2 Call 1 depends on the output of Stage 1b
    And Stage 2 Call 2 depends on the output of Stage 2 Call 1
    And Stage 2 Call 3 depends on the output of Stage 2 Call 2
    And the critic depends on the output of Stage 2 Call 3
    And the revision depends on the output of the critic

  # ParallelSP1-06
  Scenario: ParallelSP1-06 existing SP1 tests pass with parallel module present
    Given the parallel_llm module is installed in stpa/infra
    When the existing SP1 test suite is run
    Then no new failures are introduced
