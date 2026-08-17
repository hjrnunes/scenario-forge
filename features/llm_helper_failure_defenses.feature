Feature: LLM helper failure defenses
  Failed LLM calls produce deterministic diagnostics without concealing
  unrelated client defects. Compatibility retry is limited to clients that
  reject the explicitly requested tolerant-decoding argument.

  Background:
    Given a temporary run directory for LLM call logging

  # LLM-HELPER-FAILURE-DEFENSES-01
  Scenario Outline: LLM-HELPER-FAILURE-DEFENSES-01 defaults absent failure telemetry to zero
    When an LLM call failure is logged without usage telemetry
    Then the failure log entry records zero for <telemetry_field>

    Examples:
      | telemetry_field   |
      | prompt_tokens     |
      | completion_tokens |
      | duration_ms       |

  # LLM-HELPER-FAILURE-DEFENSES-02
  Scenario Outline: LLM-HELPER-FAILURE-DEFENSES-02 retries only an allowed compatibility rejection
    Given an LLM client raises TypeError <client_error> on its first completion attempt
    When a safe structured LLM call is made with tolerant decoding <tolerant_decoding>
    Then the completion attempt count is <attempt_count>
    And the safe call outcome is <outcome>

    Examples:
      | client_error                                      | tolerant_decoding | attempt_count | outcome   |
      | "unexpected keyword argument 'allow_unvalidated'" | true              | 2             | recovered |
      | "unexpected keyword argument 'allow_unvalidated'" | false             | 1             | failed    |

  # LLM-HELPER-FAILURE-DEFENSES-02B
  Scenario: LLM-HELPER-FAILURE-DEFENSES-02B does not retry an unrelated type error
    Given an LLM client raises TypeError "response_format is the wrong type" on its first completion attempt
    When a safe structured LLM call is made with tolerant decoding true
    Then the completion attempt count is 1
    And the safe call outcome is failed

  # LLM-HELPER-FAILURE-DEFENSES-03
  Scenario: LLM-HELPER-FAILURE-DEFENSES-03 keeps tolerant decoding disabled by default
    When the safe structured LLM call signature is inspected
    Then the tolerant-decoding argument defaults to false

  # LLM-HELPER-FAILURE-DEFENSES-04
  Scenario Outline: LLM-HELPER-FAILURE-DEFENSES-04 retains available usage after response parsing fails
    Given an LLM result reports <prompt_tokens> prompt tokens, <completion_tokens> completion tokens, and <duration_ms> milliseconds
    And its content cannot be parsed as the response model
    When the result is processed by a safe structured LLM call
    Then the failure log entry records prompt_tokens 17, completion_tokens 4, and duration_ms 230

    Examples:
      | prompt_tokens | completion_tokens | duration_ms |
      | 17            | 4                 | 230         |
