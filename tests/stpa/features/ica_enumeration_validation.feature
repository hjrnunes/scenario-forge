Feature: ICAEnumeration boundary schema validation
  The ICAEnumeration model validates slot-level N/A vs ICA mutual exclusivity,
  hazard and constraint reference validity, and rejects duplicate slot IDs.

  Background:
    Given the STPA boundary schema module is importable
    And a loss analysis with loss L-1, hazard H-1, and constraint SC-1
    And a control structure with responsibility RESP-1, control action CA-1-1, and PM-1-1

  # ICAEnumeration-01
  Scenario: ICAEnumeration-01 valid slot with ICA passes validation
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na false and one ICA referencing hazard H-1 and constraint SC-1
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation succeeds

  # ICAEnumeration-02
  Scenario: ICAEnumeration-02 valid N/A slot passes validation
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na true and na_justification no hazardous context
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation succeeds

  # ICAEnumeration-03
  Scenario: ICAEnumeration-03 N/A slot without na_justification fails
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na true and no na_justification
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing na_justification

  # ICAEnumeration-04
  Scenario: ICAEnumeration-04 N/A slot with ICAs fails
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na true, na_justification none, and one ICA
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing icas

  # ICAEnumeration-05
  Scenario: ICAEnumeration-05 non-N/A slot with empty ICAs fails
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na false and zero ICAs
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing icas

  # ICAEnumeration-06
  Scenario: ICAEnumeration-06 non-N/A slot with na_justification fails
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na false, one ICA, and na_justification set
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing na_justification

  # ICAEnumeration-07
  Scenario: ICAEnumeration-07 ICA referencing non-existent hazard fails
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na false and one ICA referencing hazard H-99
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing related_hazards

  # ICAEnumeration-08
  Scenario: ICAEnumeration-08 ICA referencing non-existent constraint fails
    Given an ICA slot RESP-1:CA-1-1:NOT_PROVIDED with is_na false and one ICA referencing constraint SC-99
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing related_constraints

  # ICAEnumeration-09
  Scenario: ICAEnumeration-09 duplicate slot IDs fail
    Given two ICA slots with the same slot_id RESP-1:CA-1-1:NOT_PROVIDED
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation fails with error containing duplicate

  # ICAEnumeration-10
  Scenario Outline: ICAEnumeration-10 all UCA types are accepted
    Given an ICA slot RESP-1:CA-1-1:<uca_type> with is_na false and one ICA
    When the ICA enumeration is validated against the loss analysis and control structure
    Then validation succeeds

    Examples:
      | uca_type      |
      | NOT_PROVIDED  |
      | INCORRECT     |
      | WRONG_TIMING  |
      | WRONG_DURATION |
