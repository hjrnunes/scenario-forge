Feature: SP1 Stage 2 — Structural heuristics
  Structural heuristics are deterministic post-checks run after Stage 2 Call 3
  assembles the ControlStructure. They catch mechanical errors: responsibilities
  missing PM/CA/FB elements, hazards not traced to any responsibility, orphan
  controlled processes, and orphan PM parts. These are separate from foundation
  schema validation and are the same checks defined in the foundation's
  check_structural_heuristics function, invoked from SP1's heuristics module.

  Background:
    Given the STPA system model heuristics module is importable
    And a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1

  # SP1-HEUR-01
  Scenario: SP1-HEUR-01 valid control structure passes all heuristics
    Given a control structure where RESP-1 has PM-1-1, CA-1-1, and FB-1-1
    When structural heuristics are checked
    Then the heuristic check passes with no errors

  # SP1-HEUR-02
  Scenario Outline: SP1-HEUR-02 responsibility missing an element type fails
    Given a responsibility RESP-1 with zero <element_type>
    When structural heuristics are checked
    Then the heuristic check fails with error containing <error_fragment>

    Examples:
      | element_type        | error_fragment         |
      | process_model_parts | process model part     |
      | control_actions     | control action         |
      | feedback_channels   | feedback channel       |

  # SP1-HEUR-03
  Scenario: SP1-HEUR-03 orphan PM not updated by any feedback produces warning
    Given a responsibility RESP-1 with PM-1-1 and PM-1-2 where only PM-1-1 is updated by FB-1-1
    When structural heuristics are checked
    Then a warning is produced for orphan PM PM-1-2

  # SP1-HEUR-04
  Scenario: SP1-HEUR-04 controlled process not referenced by any feedback or CA fails
    Given a controlled process CP-1 not referenced by any feedback channel source or control action target
    When structural heuristics are checked
    Then the heuristic check fails with error containing controlled process

  # SP1-HEUR-05
  Scenario: SP1-HEUR-05 hazard not traced to any responsibility fails
    Given a loss analysis with hazard H-1 and constraint SC-1
    And a control structure where no responsibility references constraint SC-1
    When structural heuristics are checked with the loss analysis
    Then the heuristic check fails with error containing hazard

  # SP1-HEUR-06
  Scenario: SP1-HEUR-06 hazard traced to a responsibility passes
    Given a loss analysis with hazard H-1 and constraint SC-1
    And a control structure where responsibility RESP-1 references constraint SC-1
    When structural heuristics are checked with the loss analysis
    Then the heuristic check passes with no errors

  # SP1-HEUR-07
  Scenario: SP1-HEUR-07 heuristics run automatically after Call 3 assembly
    Given an LLM that returns valid responses for all three Stage 2 calls
    When Stage 2 control structure derivation is run
    Then structural heuristics are checked on the assembled ControlStructure
    And the heuristic results are available

  # SP1-HEUR-08
  Scenario: SP1-HEUR-08 heuristics are re-run after revision
    Given a control structure that fails structural heuristics
    And a revision call that produces a corrected control structure
    When the revision is applied
    Then structural heuristics are re-run on the revised ControlStructure

  # SP1-HEUR-09
  Scenario: SP1-HEUR-09 heuristic errors after revision are flagged but pipeline proceeds
    Given a revision call that produces a control structure with a structural error
    When the revision is applied
    Then the structural error is flagged in the run manifest
    And the pipeline proceeds without looping
