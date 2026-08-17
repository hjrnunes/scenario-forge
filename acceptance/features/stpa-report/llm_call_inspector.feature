# stpa-report-llm-call-inspector
Feature: STPA Report LLM Call Inspector
  The LLM Call Inspector is a collapsible list of all LLM calls logged in
  calls.jsonl. Each call shows metadata (stage, step, model, tokens,
  duration, success/failure) and has expandable sections for the system
  prompt, user prompt, and response content. There is no search box.

  Background:
    Given a combined output directory containing calls.jsonl with entries:
      | stage    | step              | model         | prompt_tokens | completion_tokens | duration_ms | success |
      | stage_5  | call_bdi          | gemma-4-26b   | 3000          | 800               | 5000        | true    |
      | stage_6  | call_narrative    | gemma-4-26b   | 4500          | 1200              | 8500        | true    |
      | stage_6  | call_attack_tree  | gemma-4-26b   | 5000          | 900               | 6000        | false   |

  Scenario: LLM call inspector is present in the report
    When I generate the STPA report
    Then the LLM call inspector section exists in the report
    And the LLM call inspector section is labeled "Calls"

  Scenario: LLM call inspector has no search box
    When I generate the STPA report
    Then the LLM call inspector section does not contain a search input field

  Scenario: Each call is a collapsible entry showing metadata
    When I generate the STPA report
    Then the LLM call inspector contains 3 call entries
    And the first call entry shows stage "stage_5" and step "call_bdi"
    And the first call entry shows model "gemma-4-26b"
    And the first call entry shows token counts "3000" prompt and "800" completion
    And the first call entry shows duration "5000ms"

  Scenario: Failed calls are visually distinguished
    When I generate the STPA report
    Then the third call entry shows a failure indicator
    And the third call entry is visually distinguished from successful calls

  Scenario: Each call has expandable prompt and response sections
    When I generate the STPA report
    Then each call entry contains a collapsible section for "system_prompt"
    And each call entry contains a collapsible section for "user_prompt"
    And each call entry contains a collapsible section for "response_content"

  Scenario: LLM call inspector shows summary statistics
    When I generate the STPA report
    Then the LLM call inspector shows a summary with total calls "3"
    And the LLM call inspector shows a summary with successful calls "2"
    And the LLM call inspector shows a summary with failed calls "1"
