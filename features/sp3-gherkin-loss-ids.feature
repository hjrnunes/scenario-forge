# sp3-gherkin-loss-ids
Feature: SP3 Stage 6c Gherkin prompt loss ID constraints
  The Stage 6c Gherkin user prompt instructs the model to reference only
  valid L-* loss IDs in the consequences, explicitly not H-* hazard IDs.
  The prompt template no longer includes the "valid_hazard_ids" variable.

  Background:
    Given the SP3 Stage 6c prompt templates are renderable
    And a minimal SP3 loss analysis with loss L-1 and hazard H-1

  # SP3-072o-10
  Scenario: SP3-072o-10 Stage 6c user prompt lists valid loss IDs near the task instruction
    When the Stage 6c user prompt is rendered
    Then the Stage 6c user prompt contains the valid loss IDs
    And the Stage 6c user prompt contains the task instruction heading
    And the valid loss IDs appear before the task instruction ends

  # SP3-072o-11
  Scenario: SP3-072o-11 Stage 6c user prompt explicitly restricts consequence references to L-* loss IDs
    When the Stage 6c user prompt is rendered
    Then the Stage 6c user prompt contains a restriction that loss references use only L-* IDs
    And the Stage 6c user prompt contains a statement that consequence references must not use H-* IDs

  # SP3-072o-12
  Scenario: SP3-072o-12 Stage 6c user prompt template does not include the valid_hazard_ids variable
    When the Stage 6c user prompt template source is inspected
    Then the template does not contain the variable "valid_hazard_ids"

  # SP3-072o-13
  Scenario: SP3-072o-13 Stage 6c rendered user prompt does not list valid hazard IDs
    When the Stage 6c user prompt is rendered
    Then the Stage 6c user prompt does not contain the heading "Valid Hazard IDs"
    And the Stage 6c user prompt does not list the hazard IDs
