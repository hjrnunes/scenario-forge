# mutation-stamp: sha256=5d64136c89e002a601a93900e4735c9db0879716bd466261fb971a24ee5a0709
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T11:27:43.223702Z","feature_name":"Parallel LLM call infrastructure","feature_path":"features/parallel_llm_calls.feature","background_hash":"bf0860e283cbaeb15bb53b4f6fb541b10b8d12f2c260e0f79feca08df993ea87","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: Parallel LLM call infrastructure
  A new module `parallel_llm.py` in `stpa/infra/` provides
  `parallel_safe_llm_calls()`, which executes multiple independent
  `safe_llm_call()` invocations concurrently in a thread pool. Each call
  runs in its own thread. Failed calls do not kill other calls. Call log
  entries are written atomically. Results are returned in the same order
  as the input call specifications, regardless of execution order.

  Background:
    Given the STPA parallel LLM module is importable
    And a mock LLM client that records call order
    And a run directory for output

  # ParallelLLM-01
  Scenario: ParallelLLM-01 multiple calls execute and return results
    Given three LLM call specifications with stages stage_3, stage_3, stage_3
    When parallel_safe_llm_calls is called with max_workers 2
    Then three LLMCallResult objects are returned
    And each result contains the validated model from the mock LLM

  # ParallelLLM-02
  Scenario: ParallelLLM-02 results returned in input order regardless of execution order
    Given three LLM call specifications with steps slot_a, slot_b, slot_c
    And the mock LLM delays step slot_c by 100ms and step slot_a by 0ms
    When parallel_safe_llm_calls is called with max_workers 3
    Then the first result has step slot_a
    And the second result has step slot_b
    And the third result has step slot_c

  # ParallelLLM-03
  Scenario: ParallelLLM-03 failed call does not affect other calls
    Given three LLM call specifications with steps good_1, bad_1, good_2
    And the mock LLM raises an exception for step bad_1
    When parallel_safe_llm_calls is called with max_workers 3
    Then three LLMCallResult objects are returned
    And the result for step good_1 has no error
    And the result for step bad_1 has an error message
    And the result for step good_2 has no error

  # ParallelLLM-04
  Scenario: ParallelLLM-04 all call log entries written thread-safe
    Given five LLM call specifications with steps s1, s2, s3, s4, s5
    When parallel_safe_llm_calls is called with max_workers 4
    Then the calls.jsonl file contains five valid JSON lines
    And each line has a valid stage, step, model, and timestamp

  # ParallelLLM-05
  Scenario: ParallelLLM-05 max_workers controls concurrency level
    Given four LLM call specifications
    And the mock LLM records the number of concurrent in-flight calls
    When parallel_safe_llm_calls is called with max_workers 2
    Then the maximum observed concurrent in-flight calls is at most 2

  # ParallelLLM-06
  Scenario: ParallelLLM-06 single call works as degenerate case
    Given one LLM call specification with stage stage_3 and step slot_a
    When parallel_safe_llm_calls is called with max_workers 1
    Then one LLMCallResult object is returned
    And the result contains the validated model from the mock LLM

  # ParallelLLM-07
  Scenario: ParallelLLM-07 empty call list returns empty result list
    Given zero LLM call specifications
    When parallel_safe_llm_calls is called with max_workers 4
    Then an empty list of LLMCallResult objects is returned
    And no calls.jsonl file is created

  # ParallelLLM-08
  Scenario: ParallelLLM-08 LLMCallSpec bundles call arguments
    Given an LLMCallSpec with system_prompt sys, user_prompt usr, response_format LossAnalysis, stage stage_3, step slot_a, and temperature 0.7
    Then the spec has system_prompt sys
    And the spec has user_prompt usr
    And the spec has response_format LossAnalysis
    And the spec has stage stage_3
    And the spec has step slot_a
    And the spec has temperature 0.7

  # ParallelLLM-09
  Scenario: ParallelLLM-09 LLMCallResult bundles result with call_spec
    Given a successful parallel call execution for one specification
    Then the LLMCallResult has model set to the LLM client model
    And the LLMCallResult has result set to the validated model
    And the LLMCallResult has error set to None
    And the LLMCallResult has call_spec set to the original specification

  # ParallelLLM-10
  Scenario: ParallelLLM-10 failed call result has model None and error set
    Given a failed parallel call execution for one specification
    Then the LLMCallResult has model set to None
    And the LLMCallResult has error set to the exception message
    And the LLMCallResult has call_spec set to the original specification

  # ParallelLLM-11
  Scenario: ParallelLLM-11 call log entries include success and failure entries
    Given two LLM call specifications with steps good_1 and bad_1
    And the mock LLM raises an exception for step bad_1
    When parallel_safe_llm_calls is called with max_workers 2
    Then the calls.jsonl file contains two lines
    And the first line has success true
    And the second line has success false and a non-empty error field

  # ParallelLLM-12
  Scenario: ParallelLLM-12 temperature propagated to each call
    Given two LLM call specifications with temperatures 0.2 and 0.7
    When parallel_safe_llm_calls is called with max_workers 2
    Then the mock LLM received temperature 0.2 for the first call
    And the mock LLM received temperature 0.7 for the second call
