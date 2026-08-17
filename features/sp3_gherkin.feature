Feature: SP3 Stage 6 Call C — Gherkin behavior specification
  The Gherkin spec uses a should/but structure mapping to control structure
  state transitions. The "should" is derivable from the security constraint.
  The "But" shows the ICA. Given steps reference process model states. One
  LLM call per scenario. The response is raw Gherkin .feature text.

  Background:
    Given the SP3 Gherkin module is importable
    And a ScenarioSpec with defender BDI for scenario SCN-001
    And an ICA with ica_type NOT_PROVIDED and control action CA-1-1
    And a security constraint SC-1 related to hazard H-1

  # SP3-GHK-01
  Scenario: SP3-GHK-01 one LLM call produces Gherkin feature text
    Given an LLM that returns valid Gherkin with should/but structure
    When the Gherkin LLM call is executed
    Then exactly 1 LLM call is made
    And the call is labeled with stage stage_6
    And the call step is gherkin
    And the result is a non-empty string

  # SP3-GHK-02
  Scenario: SP3-GHK-02 Gherkin contains a Then-should line and a But line
    Given an LLM that returns Gherkin with a should line and a but line
    When the Gherkin LLM call is executed
    Then the Gherkin text contains a Then line with should
    And the Gherkin text contains a But line

  # SP3-GHK-03
  Scenario: SP3-GHK-03 the should clause is derivable from the security constraint
    Given a security constraint SC-1 with description "The orchestrator shall reject revoked users"
    When the Gherkin LLM call is executed
    Then the should clause reflects the security constraint

  # SP3-GHK-04
  Scenario: SP3-GHK-04 the But clause references the ICA type and control action
    Given an ICA with ica_type NOT_PROVIDED and control action CA-1-1
    When the Gherkin LLM call is executed
    Then the But clause references ICA type NOT_PROVIDED
    And the But clause references control action CA-1-1

  # SP3-GHK-05
  Scenario: SP3-GHK-05 Given steps reference process model states
    Given an LLM that returns Gherkin with Given steps referencing PM-1-1
    When the Gherkin LLM call is executed
    Then at least one Given step references a process model state

  # SP3-GHK-06
  Scenario: SP3-GHK-06 post-call validation checks for should/but structure
    Given an LLM that returns Gherkin without a But line
    When Gherkin structure validation is performed
    Then validation fails with error containing but

  # SP3-GHK-07
  Scenario: SP3-GHK-07 post-call validation checks for Then-should line
    Given an LLM that returns Gherkin without a should keyword in the Then line
    When Gherkin structure validation is performed
    Then validation fails with error containing should

  # SP3-GHK-08
  Scenario: SP3-GHK-08 post-call validation checks for Given step referencing PM
    Given an LLM that returns Gherkin with no Given step referencing a process model
    When Gherkin structure validation is performed
    Then validation fails with error containing process model

  # SP3-GHK-09
  Scenario: SP3-GHK-09 valid Gherkin with should/but and PM references passes validation
    Given an LLM that returns Gherkin with Then-should, But, and Given referencing PM-1-1
    When Gherkin structure validation is performed
    Then validation succeeds

  # SP3-GHK-10
  Scenario: SP3-GHK-10 user prompt includes ScenarioSpec, security constraint, and ICA
    Given an LLM that records the user prompt
    When the Gherkin LLM call is executed
    Then the user prompt contains the ScenarioSpec
    And the user prompt contains the security constraint
    And the user prompt contains the ICA

  # SP3-GHK-11
  Scenario: SP3-GHK-11 system prompt defines the Given-When-Then-Should-But structure
    When the Gherkin LLM call is executed
    Then the system prompt contains instructions for the should/but structure
    And the system prompt requires referencing process model states in Given steps
    And the system prompt requires referencing the ICA in the But line

  # SP3-GHK-12
  Scenario: SP3-GHK-12 all LLM calls are logged to calls.jsonl
    Given a run directory for output
    When the Gherkin LLM call is executed
    Then a file calls.jsonl exists in the run directory
    And the file contains entries with stage stage_6 and step gherkin
