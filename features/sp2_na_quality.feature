# mutation-stamp: sha256=77dc422d4d39002bb3bc71acb2fbc98f589c182f318be9ded13c99dfc196f44f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T07:32:42.966531Z","feature_name":"SP2 Stage 3 \u2014 N/A quality gates","feature_path":"features/sp2_na_quality.feature","background_hash":"81d51fbec80937836da350943ee2623afbd4332f366e0c0e5bb4ccc4b52aa25d","implementation_hash":"unknown","scenarios":[{"index":0,"name":"SP2-NA-01 N/A justification with structural keyword passes","scenario_hash":"747e40d6c5535b4f31d4d8db2ca6705985701fcd2504201c92b1cc8f0adf2cfe","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-10T00:47:08.602640Z"}]}
# acceptance-mutation-manifest-end

Feature: SP2 Stage 3 — N/A quality gates
  N/A quality gates are deterministic post-fill checks that catch LLM laziness
  in declaring slots not applicable. Two mechanisms: structural keyword check
  (N/A justifications must reference a specific structural property) and ratio
  monitoring (responsibilities with more than 75 percent N/A slots are flagged).
  No LLM calls.

  Background:
    Given the SP2 N/A quality module is importable

  # SP2-NA-01
  Scenario Outline: SP2-NA-01 N/A justification with structural keyword passes
    Given an N/A slot with na_justification containing the word <keyword>
    When the structural N/A quality check is run
    Then the slot passes the structural check

    Examples:
      | keyword        |
      | discrete       |
      | continuous     |
      | stateless      |
      | stateful       |
      | atomic         |
      | one-shot       |

  # SP2-NA-02
  Scenario: SP2-NA-02 N/A justification without structural keyword is flagged
    Given an N/A slot with na_justification this control action has no hazardous context
    When the structural N/A quality check is run
    Then the slot is flagged for missing structural keyword

  # SP2-NA-03
  Scenario: SP2-NA-03 N/A justification with no duration keyword passes
    Given an N/A slot with na_justification the action has no duration component
    When the structural N/A quality check is run
    Then the slot passes the structural check

  # SP2-NA-04
  Scenario: SP2-NA-04 ratio monitoring flags responsibility above 75 percent N/A
    Given a responsibility RESP-1 with 4 total slots where 4 slots are N/A
    When the N/A ratio check is run with threshold 0.75
    Then a flag is raised for RESP-1

  # SP2-NA-05
  Scenario: SP2-NA-05 ratio monitoring does not flag responsibility at exactly 75 percent
    Given a responsibility RESP-1 with 4 total slots where 3 slots are N/A
    When the N/A ratio check is run with threshold 0.75
    Then no flag is raised for RESP-1

  # SP2-NA-06
  Scenario: SP2-NA-06 ratio monitoring does not flag responsibility below 75 percent
    Given a responsibility RESP-1 with 8 total slots where 2 slots are N/A
    When the N/A ratio check is run with threshold 0.75
    Then no flag is raised for RESP-1

  # SP2-NA-07
  Scenario: SP2-NA-07 ratio monitoring only counts responsibility slots not coordination link slots
    Given a responsibility RESP-1 with 4 total slots where 4 slots are N/A
    And a coordination link CL-1 with 4 total slots where 4 slots are N/A
    When the N/A ratio check is run with threshold 0.75
    Then a flag is raised for RESP-1
    And no flag is raised for CL-1

  # SP2-NA-08
  Scenario: SP2-NA-08 ratio monitoring produces a descriptive flag message
    Given a responsibility RESP-1 with 8 total slots where 7 slots are N/A
    When the N/A ratio check is run with threshold 0.75
    Then the flag message contains RESP-1
    And the flag message contains the N/A count
    And the flag message contains the threshold percentage

  # SP2-NA-09
  Scenario: SP2-NA-09 structural check and ratio monitoring make no LLM calls
    Given a responsibility RESP-1 with 4 total slots where 3 slots are N/A with structural keywords
    When the structural N/A quality check is run
    And the N/A ratio check is run with threshold 0.75
    Then no LLM calls are made

  # SP2-NA-10
  Scenario: SP2-NA-10 multiple responsibilities flagged independently
    Given a responsibility RESP-1 with 4 total slots where 4 slots are N/A
    And a responsibility RESP-2 with 4 total slots where 1 slot is N/A
    When the N/A ratio check is run with threshold 0.75
    Then a flag is raised for RESP-1
    And no flag is raised for RESP-2

  # SP2-NA-11
  Scenario: SP2-NA-11 empty slot list produces no flags
    Given no slots
    When the N/A ratio check is run with threshold 0.75
    Then no flags are raised
