# mutation-stamp: sha256=39ea7db016dfc9c55ac82eea6b940217fdb2f338e91fab021b9758a0237cfd3d
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T11:27:44.485578Z","feature_name":"Parallel infrastructure design for SP2 and SP3","feature_path":"features/parallel_sp2_sp3_design.feature","background_hash":"6a26a5a0bb987366fdf605765229a72fe30b81f3fbcce87cd1233f2be363ba42","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: Parallel infrastructure design for SP2 and SP3
  The parallel_safe_llm_calls infrastructure is designed to support
  future parallelization in SP2 and SP3. This feature specifies the
  independence properties that enable parallel execution, without
  implementing SP2 or SP3 themselves.

  Background:
    Given the STPA parallel LLM module is importable
    And a mock LLM client that records call order

  # ParallelSP2-01
  Scenario: ParallelSP2-01 SP2 Stage 3 slot-filling calls are independent per responsibility
    Given a control structure with 3 responsibilities
    And one LLM call specification per responsibility for Stage 3 slot-filling
    When parallel_safe_llm_calls is called with max_workers 3
    Then three LLMCallResult objects are returned
    And each result corresponds to a different responsibility

  # ParallelSP2-02
  Scenario: ParallelSP2-02 SP2 Stage 3 parallel calls produce same results as sequential
    Given a control structure with 3 responsibilities
    And one LLM call specification per responsibility for Stage 3 slot-filling
    When parallel_safe_llm_calls is called with max_workers 1
    Then the results are identical to calling parallel_safe_llm_calls with max_workers 3

  # ParallelSP3-01
  Scenario: ParallelSP3-01 SP3 Stage 5 BDI calls are independent per scenario
    Given 5 scenario seeds
    And one LLM call specification per scenario for Stage 5 BDI generation
    When parallel_safe_llm_calls is called with max_workers 4
    Then five LLMCallResult objects are returned in input order
    And each result corresponds to a different scenario

  # ParallelSP3-02
  Scenario: ParallelSP3-02 SP3 Stage 6 calls are independent within a scenario
    Given one scenario with a fixed ScenarioSpec
    And three LLM call specifications for narrative, attack_tree, and gherkin
    When parallel_safe_llm_calls is called with max_workers 3
    Then three LLMCallResult objects are returned in input order
    And the first result is for the narrative call
    And the second result is for the attack_tree call
    And the third result is for the gherkin call

  # ParallelSP3-03
  Scenario: ParallelSP3-03 SP3 different scenarios can run concurrently
    Given 3 scenario seeds
    And 4 LLM call specifications per scenario (1 BDI + 3 concretization)
    When parallel_safe_llm_calls is called with max_workers 4
    Then twelve LLMCallResult objects are returned in input order
    And all results for scenario 1 precede results for scenario 2 in the result list
    And all results for scenario 2 precede results for scenario 3 in the result list

  # ParallelSP3-04
  Scenario: ParallelSP3-04 SP3 Stage 5 failure for one scenario does not block others
    Given 3 scenario seeds
    And one LLM call specification per scenario for Stage 5 BDI generation
    And the mock LLM raises an exception for scenario 2
    When parallel_safe_llm_calls is called with max_workers 3
    Then three LLMCallResult objects are returned
    And the result for scenario 1 has no error
    And the result for scenario 2 has an error message
    And the result for scenario 3 has no error
