Feature: SP3 Stage 6 Call A — Attack narrative
  The attack narrative is a dialectic between attacker and defender BDIs.
  It follows a 7-step structure tracking the evolution of beliefs on both
  sides. One LLM call per scenario. The response is raw narrative prose.

  Background:
    Given the SP3 narrative module is importable
    And a ScenarioSpec with defender BDI and attacker BDI for scenario SCN-001
    And an ICA with ica_text and loss_scenario

  # SP3-NAR-01
  Scenario: SP3-NAR-01 one LLM call produces narrative prose
    Given an LLM that returns a 7-step narrative text
    When the narrative LLM call is executed
    Then exactly 1 LLM call is made
    And the call is labeled with stage stage_6
    And the call step is narrative

  # SP3-NAR-02
  Scenario: SP3-NAR-02 narrative follows the 7-step dialectic structure
    Given an LLM that returns a narrative with 7 distinct steps
    When the narrative LLM call is executed
    Then the narrative contains a step where the defender process model starts correct
    And the narrative contains a step where the attacker manipulates a control loop element
    And the narrative contains a step where the process model diverges from reality
    And the narrative contains a step where the defender acts on false beliefs
    And the narrative contains a step where the ICA occurs
    And the narrative contains a step where the hazard is realized
    And the narrative contains a step where the loss follows

  # SP3-NAR-03
  Scenario: SP3-NAR-03 user prompt includes ScenarioSpec and ICA and loss scenario
    Given an LLM that records the user prompt
    When the narrative LLM call is executed
    Then the user prompt contains the defender BDI
    And the user prompt contains the attacker BDI
    And the user prompt contains the ICA text
    And the user prompt contains the loss scenario

  # SP3-NAR-04
  Scenario: SP3-NAR-04 system prompt defines the 7-step dialectic structure
    When the narrative LLM call is executed
    Then the system prompt contains instructions for the 7-step structure
    And the system prompt requires tracking belief evolution on both sides

  # SP3-NAR-05
  Scenario: SP3-NAR-05 narrative response is raw text
    Given an LLM that returns narrative prose
    When the narrative LLM call is executed
    Then the narrative result is a non-empty string

  # SP3-NAR-06
  Scenario: SP3-NAR-06 narrative call is parallelizable with attack tree and Gherkin calls
    Given a ScenarioSpec and 3 LLM call specifications for narrative, attack_tree, and gherkin
    When the 3 calls are executed in parallel
    Then results are returned in the same order as the input specifications
    And the number of LLM calls equals 3

  # SP3-NAR-07
  Scenario: SP3-NAR-07 all LLM calls are logged to calls.jsonl
    Given a run directory for output
    When the narrative LLM call is executed
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_6 and step narrative
