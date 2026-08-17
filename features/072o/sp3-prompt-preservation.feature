# sp3-prompt-preservation
Feature: SP3 prompt variable and output schema preservation
  The SP3 prompt templates preserve all required Jinja variables and the
  output schemas. Rendered prompts have no unresolved placeholders.

  Background:
    Given the SP3 Stage 5, Stage 6a, Stage 6b, and Stage 6c prompt templates are renderable
    And a minimal SP3 scenario fixture

  # SP3-072o-30
  Scenario: SP3-072o-30 Stage 5 user prompt preserves required variables
    When the Stage 5 user prompt template source is inspected
    Then the template contains the variable "defender_bdi_yaml"
    And the template contains the variable "ica_text"
    And the template contains the variable "hazardous_context"
    And the template contains the variable "loss_scenario"
    And the template contains the variable "control_structure_yaml"
    And the template contains the variable "target_resp_id"
    And the template contains the variable "catalog_context"

  # SP3-072o-31
  Scenario: SP3-072o-31 Stage 6a user prompt preserves required variables
    When the Stage 6a user prompt template source is inspected
    Then the template contains the variable "scenario_spec_yaml"
    And the template contains the variable "ica_text"
    And the template contains the variable "loss_scenario"

  # SP3-072o-32
  Scenario: SP3-072o-32 Stage 6b user prompt preserves required variables
    When the Stage 6b user prompt template source is inspected
    Then the template contains the variable "scenario_spec_yaml"
    And the template contains the variable "control_structure_yaml"
    And the template contains the variable "ica_type"
    And the template contains the variable "control_action"

  # SP3-072o-33
  Scenario: SP3-072o-33 Stage 6c user prompt preserves required variables
    When the Stage 6c user prompt template source is inspected
    Then the template contains the variable "scenario_spec_yaml"
    And the template contains the variable "security_constraint"
    And the template contains the variable "ica_type"
    And the template contains the variable "control_action"
    And the template contains the variable "ica_text"
    And the template contains the variable "valid_loss_ids"

  # SP3-072o-34
  Scenario: SP3-072o-34 rendered prompts have no unresolved Jinja placeholders
    When all SP3 Stage 5 through Stage 6c prompts are rendered
    Then no rendered prompt contains the pattern "{{"
    And no rendered prompt contains the pattern "}}"
