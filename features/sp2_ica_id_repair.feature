Feature: SP2 ICA identifier repair
  SP2 publishes each ICA identifier as its deterministic slot identifier
  followed by the ICA's one-based position. Identifiers supplied by the LLM
  cannot omit the UCA type, select another slot, or select another position.

  Background:
    Given deterministic SP2 slot placeholders exist for responsibility RESP-3 and control action CA-3-1

  # SP2-ICA-ID-REPAIR-01
  Scenario: SP2-ICA-ID-REPAIR-01 restores an omitted UCA type
    Given slot RESP-3:CA-3-1:NOT_PROVIDED is filled with one ICA identified as RESP-3:CA-3-1:1
    When the filled slots are merged with their placeholders
    Then the ICA identifier is RESP-3:CA-3-1:NOT_PROVIDED:1

  # SP2-ICA-ID-REPAIR-02
  Scenario: SP2-ICA-ID-REPAIR-02 preserves a correct identifier
    Given slot RESP-3:CA-3-1:INCORRECT is filled with one ICA identified as RESP-3:CA-3-1:INCORRECT:1
    When the filled slots are merged with their placeholders
    Then the ICA identifier is RESP-3:CA-3-1:INCORRECT:1

  # SP2-ICA-ID-REPAIR-03
  Scenario: SP2-ICA-ID-REPAIR-03 assigns one-based identifiers by ICA position
    Given slot RESP-3:CA-3-1:WRONG_TIMING is filled with 3 ICAs whose identifiers do not match their positions
    When the filled slots are merged with their placeholders
    Then the ICA identifiers in order are RESP-3:CA-3-1:WRONG_TIMING:1, RESP-3:CA-3-1:WRONG_TIMING:2, and RESP-3:CA-3-1:WRONG_TIMING:3
    And every ICA retains its original non-identifier fields

  # SP2-ICA-ID-REPAIR-04
  Scenario: SP2-ICA-ID-REPAIR-04 separates duplicate identifiers across UCA types
    Given the NOT_PROVIDED, INCORRECT, and WRONG_TIMING slots for RESP-3 and CA-3-1 each contain one ICA identified as RESP-3:CA-3-1:1
    When the filled slots are merged with their placeholders
    Then those ICA identifiers are RESP-3:CA-3-1:NOT_PROVIDED:1, RESP-3:CA-3-1:INCORRECT:1, and RESP-3:CA-3-1:WRONG_TIMING:1
    And all ICA identifiers in the enumeration are unique

  # SP2-ICA-ID-REPAIR-05
  Scenario: SP2-ICA-ID-REPAIR-05 publishes a valid full enumeration
    Given a full ICA enumeration response contains correct identifiers, omitted UCA types, wrong slot prefixes, wrong indexes, and duplicate identifiers
    When the filled slots are merged with their placeholders
    Then every ICA identifier equals its slot identifier followed by its one-based position
    And all ICA identifiers in the enumeration are unique
    And the ICA enumeration is valid
