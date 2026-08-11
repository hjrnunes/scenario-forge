Feature: SP1 Stage 1 prompt quality fixes
  Hazard specificity, loss specificity, and acronym expansion requirements
  live in stage1a_risk_system.j2 — the risk-derivation half of the split
  Stage 1a. The use-case gap analysis procedure moved to its own call and
  now lives in stage1a_gap_system.j2 / stage1a_gap_user.j2. All changes are
  to Jinja2 prompt template files — no source code logic changes.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # PQF-01
  Scenario: PQF-01 stage1a_risk_system.j2 Quality requirements section exists after Structural requirements
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "## Quality requirements"
    And the Quality requirements section appears after the Structural requirements section

  # PQF-02
  Scenario Outline: PQF-02 stage1a_risk_system.j2 contains Hazard specificity patterns
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "### Hazard specificity"
    And the template text contains "at least one specific component"
    And the template text contains "too generic"
    And the template text contains "<pattern_text>"

    Examples:
      | pattern_text                                                                 |
      | LLM outputs are manipulated via prompt injection to bypass security controls  |
      | System generates biased or discriminatory content                            |
      | patient chatbot generates an inaccurate surgical procedure explanation        |
      | refund processing API executes an unauthorized refund amount                 |

  # PQF-03
  Scenario Outline: PQF-03 stage1a_risk_system.j2 contains Loss specificity sub-section
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<loss_fragment>"

    Examples:
      | loss_fragment                |
      | ### Loss specificity         |
      | concrete consequences        |
      | not restatements of the risk |

  # PQF-04
  Scenario Outline: PQF-04 stage1a_risk_system.j2 contains Acronym expansion sub-section
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<acronym_fragment>"

    Examples:
      | acronym_fragment                         |
      | ### Acronym expansion                    |
      | Personally Identifiable Information (PII) |
      | first expansion                          |
      | short form alone is acceptable           |

  # PQF-05
  Scenario Outline: PQF-05 stage1a_gap_system.j2 contains the gap analysis procedure
    Given the template stage1a_gap_system.j2 is loaded
    Then the template text contains "<gap_fragment>"

    Examples:
      | gap_fragment                    |
      | ## Gap analysis method          |
      | **Architectural components**    |
      | **Integration points**          |
      | **Domain-specific features**    |
      | **Stakeholder groups**          |
      | **Attack surfaces**             |
      | ### When no gaps exist          |
      | Do not invent gaps to fill a quota |

  # PQF-06
  Scenario Outline: PQF-06 stage1a_risk_user.j2 contains the hazard grounding instruction
    Given the template stage1a_risk_user.j2 is loaded
    Then the template text contains "<hazard_fragment>"

    Examples:
      | hazard_fragment                                          |
      | grounded in this specific system's architecture and domain |
      | concrete component, data flow, or integration point       |

  # PQF-07
  Scenario Outline: PQF-07 stage1a_gap_user.j2 drives the gap analysis from the capability profile
    Given the template stage1a_gap_user.j2 is loaded
    Then the template text contains "<gap_user_fragment>"

    Examples:
      | gap_user_fragment             |
      | ## Capability Profile Context |
      | kc_subcodes                   |
      | ## ID Numbering               |
      | L-{{ next_loss_num }}         |

  # PQF-08
  Scenario Outline: PQF-08 the retired monolithic Stage 1a templates are absent
    Then the prompts directory does not contain `<retired_template>`

    Examples:
      | retired_template  |
      | stage1a_system.j2 |
      | stage1a_user.j2   |

  # PQF-09
  Scenario Outline: PQF-09 Stage 1a system templates render quality content without errors
    Given the template <template_name> is loaded
    When the template is rendered with no variables
    Then the rendered text contains "<content_fragment>"

    Examples:
      | template_name          | content_fragment       |
      | stage1a_risk_system.j2 | Quality requirements   |
      | stage1a_risk_system.j2 | Hazard specificity     |
      | stage1a_risk_system.j2 | Loss specificity       |
      | stage1a_risk_system.j2 | Acronym expansion      |
      | stage1a_gap_system.j2  | Gap analysis method    |
      | stage1a_gap_system.j2  | Acronym expansion      |

  # PQF-10
  Scenario: PQF-10 stage1a_risk_user.j2 renders with use_case_text and risk_cards variables
    Given the template stage1a_risk_user.j2 is loaded
    When the template is rendered with use_case_text "A patient chatbot integrated with EHR systems" and an empty risk_cards list
    Then the rendered text contains "grounded in this specific system's architecture"
    And the rendered text contains "A patient chatbot integrated with EHR systems"

  # PQF-11
  Scenario Outline: PQF-11 stage1a_risk_user.j2 preserves Jinja2 template variables
    Given the template stage1a_risk_user.j2 is loaded
    Then the template text contains "<jinja_expression>"

    Examples:
      | jinja_expression      |
      | {{ use_case_text }}   |
      | {% if risk_cards %}   |

  # PQF-12
  Scenario Outline: PQF-12 stage1a_risk_system.j2 preserves existing sections
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header             |
      | ## Definitions             |
      | ## Structural requirements |
      | ## ID conventions          |
      | ## Quality requirements    |
