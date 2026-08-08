# mutation-stamp: sha256=60ee0177717d007badb3eab42a7b035987754f1328cc6dc5330a8ab187b31fba
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:20:30.522309Z","feature_name":"SP1 Stage 1 prompt quality fixes","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/.factory/swarmforge/aps/../../../tests/stpa/features/sp1_prompt_quality_fixes.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"unknown","scenarios":[{"index":1,"name":"PQF-02 stage1a_system.j2 contains Hazard specificity patterns","scenario_hash":"c13ba2157fe05bf4d67e22220b506cdf0139ce941ae51c19198fd99483342706","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T23:20:30.522309Z"},{"index":8,"name":"PQF-09 system templates render quality requirements content without errors","scenario_hash":"5b647ebd71ff39a4c04307279cda34de9947c2fc543e951ff38e179509ef1036","mutation_count":14,"result":{"Total":14,"Killed":14,"Survived":0,"Errors":0},"tested_at":"2026-08-08T23:20:30.522309Z"},{"index":7,"name":"PQF-08 stage1b_system.j2 contains Quality requirements section with acronym expansion","scenario_hash":"c72dab78c166bcebd47d5d0045fe7837bbc954272e8873165aaf6868ce8070b6","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-08T23:19:13.810267Z"},{"index":11,"name":"PQF-12 stage1a_system.j2 preserves existing sections","scenario_hash":"ed36b7419f5b08e48252986c7a226810090e3bf8cfd2334aed471bdd0cea39ff","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T23:19:13.810267Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 1 prompt quality fixes
  Three combined fixes improve Stage 1a/1b prompt templates for better
  LLM output quality: hazard specificity and loss specificity requirements,
  use-case loss gap analysis procedure, and acronym expansion rules. All
  changes are to Jinja2 prompt template files — no source code logic changes.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # PQF-01
  Scenario: PQF-01 stage1a_system.j2 Quality requirements section exists after Structural requirements
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "## Quality requirements"
    And the Quality requirements section appears after the Structural requirements section

  # PQF-02
  Scenario Outline: PQF-02 stage1a_system.j2 contains Hazard specificity patterns
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "### Hazard specificity"
    And the template text contains "at least one specific component"
    And the template text contains "too generic"
    And the template text contains "<pattern_text>"

    Examples:
      | pattern_text                                                              |
      | LLM outputs are manipulated via prompt injection to bypass security controls |
      | System generates biased or discriminatory content                         |
      | patient chatbot generates an inaccurate surgical procedure explanation    |
      | refund processing API executes an unauthorized refund amount              |

  # PQF-03
  Scenario: PQF-03 stage1a_system.j2 contains Loss specificity sub-section
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "### Loss specificity"
    And the template text contains "concrete consequences"
    And the template text contains "not restatements of the risk card"

  # PQF-04
  Scenario: PQF-04 stage1a_system.j2 contains Acronym expansion sub-section
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "### Acronym expansion"
    And the template text contains "Personally Identifiable Information (PII)"
    And the template text contains "first expansion"
    And the template text contains "short form alone is acceptable"

  # PQF-05
  Scenario: PQF-05 stage1a_system.j2 contains gap analysis procedure for use-case losses
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "gap analysis"
    And the template text contains "key capabilities, integration points, and operational characteristics"
    And the template text contains "unaddressed capability failure is a use-case-derived loss"
    And the template text contains "empty use_case_losses list should be rare"
    And the template text does not contain "losses identified from the use-case description that no risk card covers"

  # PQF-06
  Scenario: PQF-06 stage1a_user.j2 contains updated hazards instruction
    Given the template stage1a_user.j2 is loaded
    Then the template text contains "grounded in this system's specific architecture and mission"
    And the template text contains "concrete component, data flow, or integration point"
    And the template text does not contain "System-level hazards, each linking to at least one loss."

  # PQF-07
  Scenario: PQF-07 stage1a_user.j2 contains updated use_case_losses instruction with gap analysis
    Given the template stage1a_user.j2 is loaded
    Then the template text contains "explicit gap analysis"
    And the template text contains "architectural component, integration point, and operational characteristic"
    And the template text contains "empty list is acceptable only if"
    And the template text does not contain "Losses from the use-case that no risk card covers."

  # PQF-08
  Scenario Outline: PQF-08 stage1b_system.j2 contains Quality requirements section with acronym expansion
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "## Quality requirements"
    And the template text contains "<content_fragment>"

    Examples:
      | content_fragment                       |
      | Retrieval-Augmented Generation (RAG)   |
      | first expansion                        |
      | short form alone is acceptable         |
      | KC sub-code identifiers                |
      | KCX-HITL                               |

  # PQF-09
  Scenario Outline: PQF-09 system templates render quality requirements content without errors
    Given the template <template_name> is loaded
    When the template is rendered with no variables
    Then the rendered text contains "<content_fragment>"

    Examples:
      | template_name       | content_fragment                       |
      | stage1a_system.j2   | Quality requirements                   |
      | stage1a_system.j2   | Hazard specificity                     |
      | stage1a_system.j2   | Loss specificity                       |
      | stage1a_system.j2   | Acronym expansion                      |
      | stage1a_system.j2   | gap analysis                           |
      | stage1b_system.j2   | Quality requirements                   |
      | stage1b_system.j2   | Retrieval-Augmented Generation (RAG)   |

  # PQF-10
  Scenario: PQF-10 stage1a_user.j2 renders with use_case_text and risk_cards variables
    Given the template stage1a_user.j2 is loaded
    When the template is rendered with use_case_text "A patient chatbot integrated with EHR systems" and an empty risk_cards list
    Then the rendered text contains "grounded in this system's specific architecture"
    And the rendered text contains "explicit gap analysis"
    And the rendered text contains "A patient chatbot integrated with EHR systems"

  # PQF-11
  Scenario: PQF-11 stage1a_user.j2 preserves Jinja2 template variables
    Given the template stage1a_user.j2 is loaded
    Then the template text contains "{{ use_case_text }}"
    And the template text contains "{% if risk_cards %}"

  # PQF-12
  Scenario Outline: PQF-12 stage1a_system.j2 preserves existing sections
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header              |
      | ## Structural requirements  |
      | ## ID conventions           |
      | ## Definitions              |
      | ## Output categories (four) |

  # PQF-13
  Scenario: PQF-13 stage1b_system.j2 Quality requirements section appears after Emphasis section
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "## Emphasis"
    And the Quality requirements section appears after the Emphasis section in stage1b_system.j2
