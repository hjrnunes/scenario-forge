# ica-definitions-na-requirements
Feature: SP2 Stage 3 ICA type definitions and N/A structural justification
  The system prompt retains definitions for all four ICA types
  (NOT_PROVIDED, INCORRECT, WRONG_TIMING, WRONG_DURATION) and the
  requirements for structural N/A justification. Each definition
  includes the type name so the LLM can map the uca_type enum value
  to its meaning.

  Background:
    Given the SP2 slot-filling prompt templates are renderable
    And a minimal control structure with one responsibility
    And a minimal loss analysis with hazard H-1 and constraint SC-1
    And a technology context block text

  # SP2-PR-10
  Scenario: SP2-PR-10 system prompt defines all four ICA types
    When the system prompt is rendered
    Then the system prompt contains the ICA type name <type_name>
    Examples:
      | type_name       |
      | NOT_PROVIDED    |
      | INCORRECT       |
      | WRONG_TIMING    |
      | WRONG_DURATION  |

  # SP2-PR-11
  Scenario: SP2-PR-11 each ICA type definition includes a concrete description
    When the system prompt is rendered
    Then the system prompt contains a description for ICA type <type_name>
    Examples:
      | type_name       |
      | NOT_PROVIDED    |
      | INCORRECT       |
      | WRONG_TIMING    |
      | WRONG_DURATION  |

  # SP2-PR-12
  Scenario: SP2-PR-12 N/A justification requirements are present in the system prompt
    When the system prompt is rendered
    Then the system prompt contains the field name na_justification
    And the system prompt contains the field name is_na
    And the system prompt requires citing a structural property for N/A slots

  # SP2-PR-13
  Scenario: SP2-PR-13 N/A justification must not be declared for inability to think of a scenario
    When the system prompt is rendered
    Then the system prompt prohibits declaring N/A because no scenario can be thought of
