Feature: SP1 Stage 2 — Control Structure derivation
  Stage 2 applies Poh's Behavioral Design Process in three sequential LLM
  calls: Call 1 derives requirements from security constraints, Call 2
  derives responsibilities with PM/CA/FB elements and controlled processes,
  and Call 3 identifies coordination links and assembles the final
  ControlStructure. Each call produces a structured internal model that
  feeds the next.

  Background:
    Given the STPA system model module is importable
    And a loss analysis with security constraints SC-1 and SC-2 is available
    And a use-case description is available

  # SP1-S2-01
  Scenario: SP1-S2-01 Call 1 produces a valid RequirementSet
    Given an LLM that returns a valid RequirementSet JSON with requirements REQ-1 and REQ-2
    When Stage 2 Call 1 requirements derivation is run
    Then a RequirementSet model is produced
    And each requirement has a req_id, description, classification, and source_constraint

  # SP1-S2-02
  Scenario: SP1-S2-02 requirements are classified as control or constraint
    Given an LLM that returns a RequirementSet with REQ-1 classified as control and REQ-2 classified as constraint
    When Stage 2 Call 1 requirements derivation is run
    Then REQ-1 has classification control
    And REQ-2 has classification constraint

  # SP1-S2-03
  Scenario Outline: SP1-S2-03 requirement with invalid classification fails
    Given an LLM that returns a RequirementSet with REQ-1 classified as <bad_class>
    When Stage 2 Call 1 requirements derivation is run
    Then validation fails with error containing classification

    Examples:
      | bad_class    |
      | enforcement  |
      | policy       |

  # SP1-S2-04
  Scenario: SP1-S2-04 each requirement references a source constraint
    Given an LLM that returns a RequirementSet where REQ-1 references SC-1 and REQ-2 references SC-2
    When Stage 2 Call 1 requirements derivation is run
    Then REQ-1 has source_constraint SC-1
    And REQ-2 has source_constraint SC-2

  # SP1-S2-05
  Scenario: SP1-S2-05 Call 1 is logged with stage stage_2 and step call_1_requirements
    Given an LLM that returns a valid RequirementSet JSON
    And a run directory for call logging
    When Stage 2 Call 1 requirements derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is call_1_requirements

  # SP1-S2-06
  Scenario: SP1-S2-06 Call 2 produces a valid ResponsibilitySet
    Given an LLM that returns a valid ResponsibilitySet JSON with responsibilities RESP-1 and RESP-2 and controlled process CP-1
    When Stage 2 Call 2 responsibilities derivation is run
    Then a ResponsibilitySet model is produced
    And each responsibility has at least one process model part, one control action, and one feedback channel

  # SP1-S2-07
  Scenario: SP1-S2-07 controlled processes are identified in Call 2
    Given an LLM that returns a ResponsibilitySet with controlled process CP-1 referenced by a feedback source
    When Stage 2 Call 2 responsibilities derivation is run
    Then the ResponsibilitySet contains controlled process CP-1

  # SP1-S2-08
  Scenario: SP1-S2-08 ElementRef references in Call 2 are valid
    Given an LLM that returns a ResponsibilitySet where feedback sources reference RESP-1 and CP-1
    When Stage 2 Call 2 responsibilities derivation is run
    Then all ElementRef references in the ResponsibilitySet point to valid responsibilities or controlled processes

  # SP1-S2-09
  Scenario: SP1-S2-09 Call 2 is logged with stage stage_2 and step call_2_responsibilities
    Given an LLM that returns a valid ResponsibilitySet JSON
    And a run directory for call logging
    When Stage 2 Call 2 responsibilities derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is call_2_responsibilities

  # SP1-S2-10
  Scenario: SP1-S2-10 Call 3 produces a valid ControlStructure
    Given a valid ResponsibilitySet from Call 2
    And an LLM that returns a valid ControlStructure JSON with coordination links
    When Stage 2 Call 3 connections derivation is run
    Then a ControlStructure model is produced
    And the control structure passes foundation validation

  # SP1-S2-11
  Scenario: SP1-S2-11 coordination links are identified in Call 3
    Given a valid ResponsibilitySet from Call 2
    And an LLM that returns a ControlStructure with coordination link CL-1 from RESP-1 to RESP-2 sharing PM-1-1
    When Stage 2 Call 3 connections derivation is run
    Then the ControlStructure contains coordination link CL-1
    And CL-1 has source RESP-1 and target RESP-2

  # SP1-S2-12
  Scenario: SP1-S2-12 Call 3 is logged with stage stage_2 and step call_3_connections
    Given a valid ResponsibilitySet from Call 2
    And an LLM that returns a valid ControlStructure JSON
    And a run directory for call logging
    When Stage 2 Call 3 connections derivation is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is call_3_connections

  # SP1-S2-13
  Scenario: SP1-S2-13 control structure is written to control-structure.yaml
    Given an LLM that returns valid responses for all three Stage 2 calls
    And a run directory for output
    When Stage 2 control structure derivation is run
    Then a file control-structure.yaml exists in the run directory
    And the file contains a valid ControlStructure model when read back

  # SP1-S2-14
  Scenario: SP1-S2-14 Call 2 receives requirements from Call 1
    Given an LLM that returns a valid RequirementSet for Call 1
    And an LLM that returns a valid ResponsibilitySet for Call 2
    When Stage 2 calls 1 through 2 are run in sequence
    Then the Call 2 user prompt contains the requirements from Call 1

  # SP1-S2-15
  Scenario: SP1-S2-15 Call 3 receives responsibilities and controlled processes from Call 2
    Given an LLM that returns a valid RequirementSet for Call 1
    And an LLM that returns a valid ResponsibilitySet for Call 2
    And an LLM that returns a valid ControlStructure for Call 3
    When Stage 2 calls 1 through 3 are run in sequence
    Then the Call 3 user prompt contains responsibilities and controlled processes from Call 2
