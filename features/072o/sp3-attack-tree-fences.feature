# sp3-attack-tree-fences
Feature: SP3 Stage 6b attack tree prompt forbids Markdown code fences
  The Stage 6b attack tree system prompt directly instructs the model not
  to wrap the output in Markdown code fences. The YAML output format and
  attack tree taxonomy remain unchanged.

  Background:
    Given the SP3 Stage 6b prompt templates are renderable
    And a minimal SP3 scenario fixture
    When the Stage 6b system prompt is rendered

  # SP3-072o-20
  Scenario: SP3-072o-20 Stage 6b system prompt forbids Markdown code fences
    Then the Stage 6b system prompt contains a direct instruction not to use Markdown code fences
    And the Stage 6b system prompt contains the phrase "Return the YAML directly"
    And the Stage 6b system prompt contains the phrase "code fence"

  # SP3-072o-21
  Scenario: SP3-072o-21 Stage 6b system prompt still requires YAML output
    Then the Stage 6b system prompt contains the YAML output format
    And the Stage 6b system prompt contains the attack tree structure
