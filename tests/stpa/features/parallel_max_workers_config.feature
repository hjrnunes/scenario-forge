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
  Scenario: ParallelConfig-06 --max-workers accepts valid values
    Given the SP1 runner script is available
    When the runner is invoked with --max-workers <workers>
    Then run_sp1 is called with max_workers <workers>

    Examples:
      | workers |
      | 1       |
      | 2       |
      | 4       |
      | 8       |
      | 16      |
