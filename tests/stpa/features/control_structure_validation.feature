Feature: ControlStructure boundary schema validation
  The ControlStructure model validates cross-references between responsibilities,
  process model parts, control actions, feedback channels, controlled processes,
  and coordination links. It also enforces structural heuristics as deterministic
  post-checks and rejects duplicate IDs.

  Background:
    Given the STPA boundary schema module is importable
    And a minimal valid control structure with responsibility RESP-1, process model part PM-1-1, control action CA-1-1, and feedback channel FB-1-1

  # ControlStructure-01
  Scenario: ControlStructure-01 valid control structure passes validation
    Given a control structure with responsibility RESP-1 having PM-1-1, CA-1-1, and FB-1-1
    When the control structure is validated
    Then validation succeeds

  # ControlStructure-02
  Scenario Outline: ControlStructure-02 process model part feedback_source referencing non-existent element fails
    Given a process model part PM-1-1 with feedback_source referencing <ref_type> <bad_ref>
    When the control structure is validated
    Then validation fails with error containing feedback_source

    Examples:
      | ref_type        | bad_ref |
      | responsibility  | RESP-99 |
      | controlled_process | CP-99 |

  # ControlStructure-03
  Scenario Outline: ControlStructure-03 control action target referencing non-existent element fails
    Given a control action CA-1-1 with target referencing <ref_type> <bad_ref>
    When the control structure is validated
    Then validation fails with error containing target

    Examples:
      | ref_type        | bad_ref |
      | responsibility  | RESP-99 |
      | controlled_process | CP-99 |

  # ControlStructure-04
  Scenario: ControlStructure-04 feedback channel updates referencing non-existent PM fails
    Given a feedback channel FB-1-1 with updates referencing PM-99-1
    When the control structure is validated
    Then validation fails with error containing updates

  # ControlStructure-05
  Scenario: ControlStructure-05 feedback channel updates referencing PM in different responsibility fails
    Given a control structure with responsibilities RESP-1 and RESP-2 where FB-1-1 updates PM-2-1
    When the control structure is validated
    Then validation fails with error containing updates

  # ControlStructure-06
  Scenario Outline: ControlStructure-06 feedback channel source referencing non-existent element fails
    Given a feedback channel FB-1-1 with source referencing <ref_type> <bad_ref>
    When the control structure is validated
    Then validation fails with error containing source

    Examples:
      | ref_type        | bad_ref |
      | responsibility  | RESP-99 |
      | controlled_process | CP-99 |

  # ControlStructure-07
  Scenario: ControlStructure-07 coordination link with valid source and target passes
    Given a control structure with responsibilities RESP-1 and RESP-2 and coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When the control structure is validated
    Then validation succeeds

  # ControlStructure-08
  Scenario Outline: ControlStructure-08 coordination link referencing non-existent responsibility fails
    Given a coordination link CL-1 with <field> referencing RESP-99
    When the control structure is validated
    Then validation fails with error containing <field>

    Examples:
      | field  |
      | source |
      | target |

  # ControlStructure-09
  Scenario: ControlStructure-09 coordination link shared_pm referencing non-existent PM fails
    Given a coordination link CL-1 with shared_pm referencing PM-99-1
    When the control structure is validated
    Then validation fails with error containing shared_pm

  # ControlStructure-10
  Scenario Outline: ControlStructure-10 duplicate IDs fail validation
    Given a control structure with duplicate <id_field> value <dup_value>
    When the control structure is validated
    Then validation fails with error containing duplicate

    Examples:
      | id_field     | dup_value |
      | resp_id      | RESP-1    |
      | cp_id        | CP-1      |
      | pm_id        | PM-1-1    |
      | ca_id        | CA-1-1    |
      | fb_id        | FB-1-1    |
      | link_id      | CL-1      |

  # ControlStructure-11
  Scenario: ControlStructure-11 responsibility with no process model parts fails structural heuristic
    Given a responsibility RESP-1 with zero process model parts
    When the control structure structural heuristics are checked
    Then the heuristic check fails with error containing process model part

  # ControlStructure-12
  Scenario: ControlStructure-12 responsibility with no control actions fails structural heuristic
    Given a responsibility RESP-1 with zero control actions
    When the control structure structural heuristics are checked
    Then the heuristic check fails with error containing control action

  # ControlStructure-13
  Scenario: ControlStructure-13 responsibility with no feedback channels fails structural heuristic
    Given a responsibility RESP-1 with zero feedback channels
    When the control structure structural heuristics are checked
    Then the heuristic check fails with error containing feedback channel

  # ControlStructure-14
  Scenario: ControlStructure-14 orphan PM not updated by any feedback channel produces warning
    Given a responsibility RESP-1 with PM-1-1 and PM-1-2 where only PM-1-1 is updated by FB-1-1
    When the control structure structural heuristics are checked
    Then a warning is produced for orphan PM PM-1-2

  # ControlStructure-15
  Scenario: ControlStructure-15 controlled process not referenced by any feedback or control action fails structural heuristic
    Given a controlled process CP-1 not referenced by any feedback channel source or control action target
    When the control structure structural heuristics are checked
    Then the heuristic check fails with error containing controlled process

  # ControlStructure-16
  Scenario: ControlStructure-16 hazard not traced to any responsibility fails structural heuristic
    Given a loss analysis with hazard H-1 and constraint SC-1
    And a control structure where no responsibility references constraint SC-1
    When the control structure structural heuristics are checked with the loss analysis
    Then the heuristic check fails with error containing hazard

  # ControlStructure-17
  Scenario: ControlStructure-17 hazard traced to a responsibility passes structural heuristic
    Given a loss analysis with hazard H-1 and constraint SC-1
    And a control structure where responsibility RESP-1 references constraint SC-1
    When the control structure structural heuristics are checked with the loss analysis
    Then the heuristic check succeeds
