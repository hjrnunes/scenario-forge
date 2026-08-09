Feature: SP2 Stage 3 Phase 1 — Deterministic slot creation
  Slot creation is a deterministic mechanical process that creates one slot per
  (responsibility × control_action × UCA_type) triple plus one slot per
  (coordination_link × UCA_type). Four UCA types: NOT_PROVIDED, INCORRECT,
  WRONG_TIMING, WRONG_DURATION. No LLM calls. The slot count formula is
  (sum of control_actions per responsibility × 4) + (N_coordination_links × 4).

  Background:
    Given the SP2 slot creation module is importable

  # SP2-SLOT-01
  Scenario Outline: SP2-SLOT-01 responsibility slot count matches the formula
    Given a control structure with <n_responsibilities> responsibilities having <cas_per_resp> control actions each
    And <n_coord_links> coordination links in the control structure
    When slots are created from the control structure
    Then the number of responsibility slots is <expected_resp_slots>

    Examples:
      | n_responsibilities | cas_per_resp | n_coord_links | expected_resp_slots |
      | 1                  | 1            | 0             | 4                   |
      | 2                  | 3            | 0             | 24                  |
      | 4                  | 2            | 0             | 32                  |
      | 5                  | 3            | 2             | 60                  |

  # SP2-SLOT-02
  Scenario Outline: SP2-SLOT-02 coordination link slot count matches the formula
    Given a control structure with <n_responsibilities> responsibilities having <cas_per_resp> control actions each
    And <n_coord_links> coordination links in the control structure
    When slots are created from the control structure
    Then the number of coordination link slots is <expected_link_slots>

    Examples:
      | n_responsibilities | cas_per_resp | n_coord_links | expected_link_slots |
      | 1                  | 1            | 1             | 4                   |
      | 2                  | 3            | 2             | 8                   |
      | 4                  | 2            | 3             | 12                  |

  # SP2-SLOT-03
  Scenario Outline: SP2-SLOT-03 total slot count is responsibility slots plus coordination link slots
    Given a control structure with <n_responsibilities> responsibilities having <cas_per_resp> control actions each
    And <n_coord_links> coordination links in the control structure
    When slots are created from the control structure
    Then the total number of slots is <expected_total_slots>

    Examples:
      | n_responsibilities | cas_per_resp | n_coord_links | expected_total_slots |
      | 1                  | 1            | 0             | 4                    |
      | 2                  | 2            | 1             | 20                   |
      | 4                  | 2            | 2             | 40                   |
      | 5                  | 3            | 2             | 68                   |

  # SP2-SLOT-04
  Scenario: SP2-SLOT-04 each control action produces all four UCA types
    Given a control structure with 1 responsibility having 1 control action and 0 coordination links
    When slots are created from the control structure
    Then the slots include UCA types NOT_PROVIDED, INCORRECT, WRONG_TIMING, and WRONG_DURATION

  # SP2-SLOT-05
  Scenario: SP2-SLOT-05 responsibility slot_id format is RESP-X:CA-Y:UCA_TYPE
    Given a control structure with responsibility RESP-1 and control action CA-1-1
    When slots are created from the control structure
    Then a slot has slot_id RESP-1:CA-1-1:NOT_PROVIDED
    And the slot has responsibility RESP-1
    And the slot has coordination_link null
    And the slot has control_action CA-1-1

  # SP2-SLOT-06
  Scenario: SP2-SLOT-06 coordination link slot_id format is CL-X:CM-Y:UCA_TYPE
    Given a control structure with coordination link CL-1 and coordination mechanism CM-1
    When slots are created from the control structure
    Then a slot has slot_id CL-1:CM-1:NOT_PROVIDED
    And the slot has responsibility null
    And the slot has coordination_link CL-1
    And the slot has control_action CM-1

  # SP2-SLOT-07
  Scenario: SP2-SLOT-07 initial slot state has is_na false and empty icas
    Given a control structure with 2 responsibilities having 2 control actions each and 1 coordination link
    When slots are created from the control structure
    Then every slot has is_na false
    And every slot has an empty icas list
    And every slot has na_justification null

  # SP2-SLOT-08
  Scenario: SP2-SLOT-08 slot creation makes no LLM calls
    Given a control structure with 2 responsibilities having 2 control actions each and 1 coordination link
    When slots are created from the control structure
    Then no LLM calls are made

  # SP2-SLOT-09
  Scenario: SP2-SLOT-09 slot creation is deterministic
    Given a control structure with 2 responsibilities having 2 control actions each and 1 coordination link
    When slots are created from the control structure twice
    Then both runs produce identical slot lists

  # SP2-SLOT-10
  Scenario: SP2-SLOT-10 no duplicate slot IDs
    Given a control structure with 3 responsibilities having 2 control actions each and 2 coordination links
    When slots are created from the control structure
    Then all slot IDs are unique

  # SP2-SLOT-11
  Scenario: SP2-SLOT-11 responsibilities with different control action counts
    Given a control structure with responsibility RESP-1 having 3 control actions and responsibility RESP-2 having 1 control action and 0 coordination links
    When slots are created from the control structure
    Then the number of responsibility slots is 16
    And 12 slots have responsibility RESP-1
    And 4 slots have responsibility RESP-2
