# prompt-opener-terminology
Feature: SP2 Stage 3 prompt opener and ICA terminology consistency
  The system prompt for Stage 3 ICA slot-filling opens with task-oriented
  security-analyst framing instead of STPA-Sec jargon. The term ICA
  (Insecure Control Action) is defined once and used consistently in
  descriptive prose. The uca_type schema field name is preserved as-is
  because it is a machine-readable enum value, not prose.

  Background:
    Given the SP2 slot-filling prompt templates are renderable
    And a minimal control structure with one responsibility
    And a minimal loss analysis with hazard H-1 and constraint SC-1
    And a technology context block text

  # SP2-PR-01
  Scenario: SP2-PR-01 system prompt opener uses task-oriented security-analyst framing
    When the system prompt is rendered
    Then the system prompt does not contain the string STPA-Sec
    And the system prompt contains the word security analyst
    And the system prompt contains the word slot

  # SP2-PR-02
  Scenario: SP2-PR-02 ICA is defined exactly once in the system prompt
    When the system prompt is rendered
    Then the system prompt contains the expansion of ICA as Insecure Control Action
    And the string Insecure Control Action appears exactly once in the system prompt

  # SP2-PR-03
  Scenario: SP2-PR-03 system prompt uses ICA not UCA in descriptive prose
    When the system prompt is rendered
    Then the system prompt does not contain the phrase Unsafe Control Action
    And the system prompt does not contain the standalone word UCA outside the field name uca_type

  # SP2-PR-04
  Scenario: SP2-PR-04 uca_type schema field name is preserved in the system prompt
    When the system prompt is rendered
    Then the system prompt contains the field name uca_type

  # SP2-PR-05
  Scenario: SP2-PR-05 user prompt uses ICA not UCA in descriptive prose
    When the user prompt is rendered
    Then the user prompt does not contain the phrase Unsafe Control Action
    And the user prompt does not contain the standalone word UCA outside the field name uca_type

  # SP2-PR-06
  Scenario: SP2-PR-06 uca_type schema field name is preserved in the user prompt
    When the user prompt is rendered
    Then the user prompt contains the field name uca_type
