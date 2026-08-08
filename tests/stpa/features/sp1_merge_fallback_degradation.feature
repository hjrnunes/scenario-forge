Feature: SP1 — Merge fallback degradation for ConnectionSet validation failures
  If the merge of ResponsibilitySet (Call 2) and ConnectionSet (Call 3)
  fails because the ConnectionSet contains invalid cross-references, the
  pipeline falls back to building a ControlStructure from the
  ResponsibilitySet alone — without coordination links.  The fallback
  structure preserves Call 2 responsibilities and controlled processes,
  is written to control-structure.yaml, passes through heuristics and
  critic, and the pipeline completes without crashing.  The merge failure
  is logged and recorded in the run manifest stage_errors.  In the normal
  case where the merge succeeds, the full ControlStructure with coordination
  links is produced unchanged.

  Background:
    Given the STPA system model module is importable
    And a loss analysis with security constraints SC-1 and SC-2 is available
    And a use-case description is available
    And a valid ResponsibilitySet from Call 2 with responsibilities RESP-1 and RESP-2
    And a run directory for output and call logging

  # MergeFallback-01
  Scenario Outline: MergeFallback-01 invalid ConnectionSet triggers fallback to ResponsibilitySet-only ControlStructure
    Given an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with <violation>
    When Stage 2 control structure derivation is run
    Then a ControlStructure model is produced
    And the control structure passes foundation validation
    And the pipeline does not crash

    Examples:
      | violation                                                             |
      | namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID |
      | coordination link source referencing a non-existent responsibility    |
      | coordination link shared_pm referencing a non-existent PM             |

  # MergeFallback-02
  Scenario: MergeFallback-02 fallback ControlStructure has empty coordination_links
    Given an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When Stage 2 control structure derivation is run
    Then the ControlStructure coordination_links list is empty

  # MergeFallback-03
  Scenario: MergeFallback-03 fallback ControlStructure preserves responsibilities from Call 2
    Given an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains responsibility RESP-1
    And the ControlStructure contains responsibility RESP-2

  # MergeFallback-04
  Scenario: MergeFallback-04 fallback ControlStructure preserves controlled_processes from Call 2
    Given an LLM that returns valid responses for Call 1 and Call 2
    And a ResponsibilitySet from Call 2 with controlled process CP-1
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains controlled process CP-1

  # MergeFallback-05
  Scenario: MergeFallback-05 merge failure is logged to calls.jsonl
    Given an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When Stage 2 control structure derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is merge_connection_set
    And the call log entry success is false
    And the call log entry has an error message field

  # MergeFallback-06
  Scenario: MergeFallback-06 merge failure recorded in run manifest stage_errors
    Given an LLM that returns valid responses for stage_1a and stage_1b
    And an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When the full SP1 run is executed
    Then a run manifest is written
    And the manifest contains a stage_errors field
    And the stage_errors field includes the merge failure description

  # MergeFallback-07
  Scenario: MergeFallback-07 fallback ControlStructure is written to control-structure.yaml
    Given an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When Stage 2 control structure derivation is run
    Then a file control-structure.yaml exists in the run directory
    And the file contains a valid ControlStructure model when read back

  # MergeFallback-08
  Scenario: MergeFallback-08 fallback ControlStructure passes through heuristics with possible warnings
    Given an LLM that returns valid responses for stage_1a and stage_1b
    And an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When the full SP1 run is executed
    Then the SP1RunResult control_structure is not None
    And the heuristic result is available
    And the pipeline does not crash

  # MergeFallback-09
  Scenario: MergeFallback-09 pipeline does not crash on merge failure during full SP1 run
    Given an LLM that returns valid responses for stage_1a and stage_1b
    And an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a ConnectionSet with namespace confusion: feedback_source uses a FeedbackChannel ID as a ControlledProcess ID
    When the full SP1 run is executed
    Then the pipeline does not crash
    And the SP1RunResult control_structure is not None
    And the SP1RunResult stage_errors contains the merge failure

  # MergeFallback-10
  Scenario: MergeFallback-10 successful merge produces full ControlStructure with coordination links
    Given an LLM that returns valid responses for Call 1 and Call 2
    And an LLM that returns a valid ConnectionSet with coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When Stage 2 control structure derivation is run
    Then the ControlStructure contains coordination link CL-1
    And CL-1 has source RESP-1 and target RESP-2
    And the control structure passes foundation validation
    And no merge failure is logged
