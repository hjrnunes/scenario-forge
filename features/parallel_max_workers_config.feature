# mutation-stamp: sha256=7a9d5e314c4009d78e367c650f8f80774264cdf209c45bb0e1a67a197ed1b31b
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T12:52:08.983849Z","feature_name":"Parallel max_workers configuration and manifest recording","feature_path":"features/parallel_max_workers_config.feature","background_hash":"93a4ff32b850b092ffae476f5b2cf2ed3be0d0926c0e21bf8b7b001706738bd9","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: Parallel max_workers configuration and manifest recording
  The `run_sp1()` function accepts a `max_workers` parameter (default 1
  for backwards compatibility). The runner script `scripts/run_sp1.py`
  gains a `--max-workers <N>` CLI flag. The run manifest records the
  `max_workers` value used for the run.

  Background:
    Given the STPA system model run module is importable
    And a use-case description and risk extraction JSON are available as input

  # ParallelConfig-01
  Scenario: ParallelConfig-01 run_sp1 accepts max_workers parameter
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed with max_workers 4
    Then the run completes without error

  # ParallelConfig-02
  Scenario: ParallelConfig-02 max_workers default is 1 for backwards compatibility
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed without specifying max_workers
    Then the run completes without error
    And the run manifest records max_workers as 1

  # ParallelConfig-03
  Scenario: ParallelConfig-03 run manifest records max_workers value
    Given an LLM that returns valid responses for all stages
    When the full SP1 run is executed with max_workers 4
    Then the run manifest records max_workers as 4

  # ParallelConfig-04
  Scenario: ParallelConfig-04 --max-workers CLI flag passes value to run_sp1
    Given the SP1 runner script is available
    When the runner is invoked with --max-workers 8
    Then run_sp1 is called with max_workers 8

  # ParallelConfig-05
  Scenario: ParallelConfig-05 --max-workers CLI flag defaults to 1
    Given the SP1 runner script is available
    When the runner is invoked without --max-workers
    Then run_sp1 is called with max_workers 1

  # ParallelConfig-06
  # The parametrized variants (workers=1,2,4,8,16) are covered by the
  # unit test test_parallel_config_06_cli_accepts_valid_values.  The
  # Gherkin scenario verifies pass-through with a single representative
  # value to avoid tautological example-table mutations.
  Scenario: ParallelConfig-06 --max-workers accepts a valid positive integer
    Given the SP1 runner script is available
    When the runner is invoked with --max-workers 4
    Then run_sp1 is called with max_workers 4
