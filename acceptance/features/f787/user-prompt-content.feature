# user-prompt-content
Feature: SP2 Stage 3 user prompt content and non-duplication
  The user prompt includes the technology context block, the slot
  schema, a concise task directive, a note about valid H-*/SC-*
  references, and a REQ-*/SC-* mapping note. It does not duplicate
  the full ICA type definitions or system-prompt instructions.

  Background:
    Given the SP2 slot-filling prompt templates are renderable
    And a minimal control structure with one responsibility
    And a minimal loss analysis with hazard H-1 and constraint SC-1
    And a technology context block text
    And slots for responsibility RESP-1

  # SP2-PR-20
  Scenario: SP2-PR-20 user prompt includes the technology context block
    When the user prompt is rendered
    Then the user prompt contains the heading Technology Context
    And the user prompt contains the technology context block text

  # SP2-PR-21
  Scenario: SP2-PR-21 user prompt includes the slot schema
    When the user prompt is rendered
    Then the user prompt contains the slot IDs for responsibility RESP-1

  # SP2-PR-22
  Scenario: SP2-PR-22 user prompt includes a concise task directive
    When the user prompt is rendered
    Then the user prompt contains a task directive heading
    And the user prompt contains the word Fill or fill

  # SP2-PR-23
  Scenario: SP2-PR-23 user prompt includes a valid H-*/SC-* reference note
    When the user prompt is rendered
    Then the user prompt contains a note referencing valid hazard IDs
    And the user prompt contains a note referencing valid constraint IDs

  # SP2-PR-24
  Scenario: SP2-PR-24 user prompt includes a REQ-*/SC-* mapping note
    When the user prompt is rendered
    Then the user prompt contains a mapping note mentioning REQ- and SC-

  # SP2-PR-25
  Scenario: SP2-PR-25 user prompt does not duplicate ICA type definitions from system prompt
    When the user prompt is rendered
    And the system prompt is rendered
    Then the user prompt does not contain the heading Four ICA Types
    And the user prompt does not contain the Type 1 NOT_PROVIDED definition block
    And the user prompt does not contain the Type 2 INCORRECT definition block
    And the user prompt does not contain the Type 3 WRONG_TIMING definition block
    And the user prompt does not contain the Type 4 WRONG_DURATION definition block

  # SP2-PR-26
  Scenario: SP2-PR-26 user prompt does not duplicate system-prompt requirement instructions
    When the user prompt is rendered
    Then the user prompt does not contain the heading Requirements
    And the user prompt does not repeat the N/A justification structural-property requirement from the system prompt
