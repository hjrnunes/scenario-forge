# stage1b-grounding
Feature: Stage 1b Grounding Without Loss Analysis Context
  Security constraints previously contaminated the Stage 1b tool inventory:
  the prompt included the full LossAnalysis, and the model read prescriptive
  constraints ("must implement X") as descriptions of existing capabilities.
  The Stage 1b reorder removes the contamination source structurally —
  Stage 1b now runs BEFORE Stage 1a, so no loss analysis exists yet and
  stage1b_user.j2 receives only the use-case text. Grounding is enforced by
  explicit rules in stage1b_system.j2 instead of by a caveat on a security
  constraints section.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # stage1b-grounding-01
  Scenario Outline: stage1b-grounding-01 stage1b_user.j2 carries no loss-analysis context
    Given the template stage1b_user.j2 is loaded
    Then the template text does not contain "<retired_context>"

    Examples:
      | retired_context      |
      | Security Constraints |
      | Loss Analysis        |
      | loss_analysis        |
      | all_losses           |

  # stage1b-grounding-02
  Scenario Outline: stage1b-grounding-02 stage1b_user.j2 provides only the use-case text
    Given the template stage1b_user.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header          |
      | ## Use-Case Description |
      | {{ use_case_text }}     |
      | ## Your Task            |

  # stage1b-grounding-03
  Scenario Outline: stage1b-grounding-03 stage1b_system.j2 states the grounding rules
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<grounding_rule>"

    Examples:
      | grounding_rule                                                                                          |
      | every KC code, entry point, and tool must be traceable to a specific capability described in the use-case text |
      | Do not infer capabilities speculatively                                                                 |

  # stage1b-grounding-04
  Scenario Outline: stage1b-grounding-04 stage1b_system.j2 constrains the tool inventory to described tools
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<tool_rule>"

    Examples:
      | tool_rule                                                                     |
      | every tool must be explicitly mentioned or directly implied by the use-case description |
      | Do not invent tools based on what a system like this might have                |

  # stage1b-grounding-05
  Scenario Outline: stage1b-grounding-05 the retired security-constraint caveat text is absent
    Given the template stage1b_system.j2 is loaded
    Then the template text does not contain "<retired_caveat>"

    Examples:
      | retired_caveat                                                     |
      | Security constraints describe what SHOULD exist, not what DOES exist |
      | Do not infer tools from security constraints                        |

  # stage1b-grounding-06
  Scenario: stage1b-grounding-06 stage1b_user.j2 renders from the use-case text alone
    Given the template stage1b_user.j2 is loaded
    When the template is rendered with use_case_text "A patient chatbot integrated with EHR systems"
    Then the rendered text contains "A patient chatbot integrated with EHR systems"
    And the rendered text does not contain "Security Constraints"

  # stage1b-grounding-07
  Scenario: stage1b-grounding-07 stage1b_system.j2 renders with no unresolved placeholders
    Given the template stage1b_system.j2 is loaded
    When the template is rendered with no variables
    Then the rendered text contains "Do not invent tools based on what a system like this might have"
    And the rendered text does not contain "{{"
