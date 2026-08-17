# mutation-stamp: sha256=08e887a618d5b71836f915d8a980b9826ca62d93a8c47087fc524250eb251dea
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T12:24:13.413762Z","feature_name":"ControlStructure boundary schema validation","feature_path":"features/control_structure_validation.feature","background_hash":"2bf1436efa332d986f9c85b88441f1957e0fed6f32d03591991136a914831c0a","implementation_hash":"unknown","scenarios":[{"index":1,"name":"ControlStructure-02 process model part feedback_source referencing non-existent element fails","scenario_hash":"6394906dc153425daba462513f7adeb6a639eece84ab13f2c2951960623d3467","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:13.413762Z"},{"index":2,"name":"ControlStructure-03 control action target referencing non-existent element fails","scenario_hash":"493f61aff3724d672e6274436cef7e8bfa46b7bbe13f7913f8efc3193a761961","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:13.413762Z"},{"index":5,"name":"ControlStructure-06 feedback channel source referencing non-existent element fails","scenario_hash":"2489ddc0b8c0e71f9499c5a2afda3aafdce565e0585b380e438ca685605d6342","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:13.413762Z"},{"index":7,"name":"ControlStructure-08 coordination link referencing non-existent responsibility fails","scenario_hash":"530b53a9df5a787ac51bc2c7881b35cb3eeffd643ec5cd5cb40feb3c734b26bd","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:13.413762Z"},{"index":9,"name":"ControlStructure-10 duplicate IDs fail validation","scenario_hash":"7f6fe6da9651a657e721ac5f233794aa95bfb2e32eae505361bc08aadf9b6cf9","mutation_count":12,"result":{"Total":12,"Killed":12,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:13.413762Z"}]}
# acceptance-mutation-manifest-end

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
