# mutation-stamp: sha256=df4866e1c142b0918b2969c6988aafb49657ce192b6674c68d860264780603f1
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:44:58.280028Z","feature_name":"Stage 1b Grounding Without Loss Analysis Context","feature_path":"features/acceptance-refresh/stage1b-grounding.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"sha256:0ff3faab8d3ba952c5a285b0de8b8d2f37d995498c5eecb252460b7fcb16e240","scenarios":[{"index":0,"name":"stage1b-grounding-01 stage1b_user.j2 carries no loss-analysis context","scenario_hash":"ee3854df0eac8b86b8d833b098decb2bc91251cecdd4a159bb330c2be4611fff","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:44:58.280028Z"},{"index":4,"name":"stage1b-grounding-05 the retired security-constraint caveat text is absent","scenario_hash":"8034f0d827568b79c1f54bd5749cfd5d115fb7756ee09913c0e2d7a7b23af9dd","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:44:58.280028Z"},{"index":1,"name":"stage1b-grounding-02 stage1b_user.j2 provides only the use-case text","scenario_hash":"e911f7cdf3b24b9a7b6f681c12effaf43a137e80989b5736ca20f7074957d614","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:06.046096Z"},{"index":2,"name":"stage1b-grounding-03 stage1b_system.j2 states the grounding rules","scenario_hash":"dbc0e7e10f0ff814ff1e1eb8955a7bc7cd5608282cb359ebaddbe617205d3386","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:06.046096Z"},{"index":3,"name":"stage1b-grounding-04 stage1b_system.j2 constrains the tool inventory to described tools","scenario_hash":"5e5f1b4284cfe3d07fd1a59816ccb56f578598998b784060ecc6f4f949969a9f","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:06.046096Z"}]}
# acceptance-mutation-manifest-end

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
