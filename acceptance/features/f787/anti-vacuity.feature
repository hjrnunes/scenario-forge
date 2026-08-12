# anti-vacuity
Feature: SP2 Stage 3 anti-vacuity checks for prompt specification
  Deliberately removing a required element from the prompt template
  or technology context builder must cause the QA suite to fail.
  This proves the QA checks are not vacuously passing.

  Background:
    Given the SP2 slot-filling prompt templates are renderable
    And a minimal control structure with one responsibility
    And a minimal loss analysis with hazard H-1 and constraint SC-1
    And a technology context block text
    And slots for responsibility RESP-1

  # SP2-PR-50
  Scenario: SP2-PR-50 removing an ICA type definition from a copy of the system prompt causes QA failure
    Given a copy of the system prompt with the NOT_PROVIDED definition removed
    When the copied system prompt is checked against the ICA definition requirements
    Then the check fails because NOT_PROVIDED is missing

  # SP2-PR-51
  Scenario: SP2-PR-51 removing the REQ-*/SC-* mapping note from a copy of the user prompt causes QA failure
    Given a copy of the user prompt with the REQ-*/SC-* mapping note removed
    When the copied user prompt is checked against the mapping note requirement
    Then the check fails because the REQ-*/SC-* mapping note is missing

  # SP2-PR-52
  Scenario: SP2-PR-52 removing the capability classification branch from a copy of the technology context builder causes QA failure
    Given a copy of the technology context builder with the write/execute classification branch removed
    When a write/execute tool is classified by the copied builder
    Then the classification fails because the write/execute suffix is missing
