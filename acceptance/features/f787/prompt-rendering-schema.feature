# prompt-rendering-schema
Feature: SP2 Stage 3 prompt rendering and output schema compatibility
  Rendered prompts must contain no unresolved Jinja placeholders.
  All Jinja template variables are preserved in the template source.
  The uca_type field remains accepted in the slot schema and the
  filled_slots response shape is unchanged.

  Background:
    Given the SP2 slot-filling prompt templates are renderable
    And a minimal control structure with one responsibility
    And a minimal loss analysis with hazard H-1 and constraint SC-1
    And a technology context block text
    And slots for responsibility RESP-1

  # SP2-PR-40
  Scenario: SP2-PR-40 rendered system prompt has no unresolved Jinja placeholders
    When the system prompt is rendered
    Then the rendered system prompt does not contain the pattern open-brace open-brace
    And the rendered system prompt does not contain the pattern close-brace close-brace

  # SP2-PR-41
  Scenario: SP2-PR-41 rendered user prompt has no unresolved Jinja placeholders
    When the user prompt is rendered
    Then the rendered user prompt does not contain the pattern open-brace open-brace
    And the rendered user prompt does not contain the pattern close-brace close-brace

  # SP2-PR-42
  Scenario: SP2-PR-42 user prompt template preserves all required Jinja variables
    When the user prompt template source is inspected
    Then the template contains the variable control_structure_yaml
    And the template contains the variable loss_analysis_yaml
    And the template contains the variable technology_context
    And the template contains the variable slots_yaml
    And the template contains the variable resp_id

  # SP2-PR-43
  Scenario: SP2-PR-43 uca_type field is accepted in the slot schema
    When a slot fill result with uca_type NOT_PROVIDED is parsed
    Then the parsed result has a filled_slots list
    And the first slot has uca_type equal to NOT_PROVIDED

  # SP2-PR-44
  Scenario: SP2-PR-44 filled_slots response shape is unchanged
    When a slot fill result with one filled slot is parsed
    Then the parsed result has a filled_slots list of length 1
    And the first slot has the field slot_id
    And the first slot has the field responsibility
    And the first slot has the field control_action
    And the first slot has the field uca_type
    And the first slot has the field is_na
    And the first slot has the field icas
    And the first slot has the field na_justification
