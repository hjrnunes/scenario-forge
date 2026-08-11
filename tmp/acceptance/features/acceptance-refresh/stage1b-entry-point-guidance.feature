# stage1b-entry-point-guidance
Feature: Stage 1b Entry Point Guidance
  Stage 1b derives entry points from the KC sub-code taxonomy rather than
  from a fixed five-category checklist. The stage1b_system.j2 prompt names
  the three entry-point fields, maps individual KC capabilities to the
  ingress paths they imply, and states that a component may appear in both
  tool_inventory and entry_points. The five-category checklist (User input
  surfaces / RAG-retrieval data sources / Tool execution results / External
  data feeds / Admin-config interfaces) was removed and must not return.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory
    And the template stage1b_system.j2 is loaded

  # stage1b-entry-point-guidance-01
  Scenario: stage1b-entry-point-guidance-01 stage1b_system.j2 declares the Entry Points section
    Then the template text contains "## Entry Points"
    And the template text contains "Identify every attacker-accessible ingress path"

  # stage1b-entry-point-guidance-02
  Scenario Outline: stage1b-entry-point-guidance-02 each entry-point field is specified
    Then the template text contains "<field_spec>"

    Examples:
      | field_spec                                                                |
      | **name**: short description of the entry point                            |
      | **direction**: "input" (attacker sends data in)                            |
      | **controllability**: "direct" (attacker types input)                       |

  # stage1b-entry-point-guidance-03
  Scenario Outline: stage1b-entry-point-guidance-03 KC capabilities map to implied ingress paths
    Then the template text contains "<kc_mapping>"

    Examples:
      | kc_mapping                                                                             |
      | KC6.3.3 (RAG) implies an indirect entry point at the knowledge base / document store    |
      | KC6.1.2 (extensive API access) implies entry points at API response surfaces           |
      | KC4.3+ (cross-session memory) implies entry points at the memory store                 |
      | KC2.3 (multi-agent) implies entry points at inter-agent message channels               |

  # stage1b-entry-point-guidance-04
  Scenario: stage1b-entry-point-guidance-04 a component may appear in both tool_inventory and entry_points
    Then the template text contains "A component can appear in both tool_inventory and entry_points"

  # stage1b-entry-point-guidance-05
  Scenario Outline: stage1b-entry-point-guidance-05 the removed five-category checklist is absent
    Then the template text does not contain "<retired_category>"

    Examples:
      | retired_category           |
      | User input surfaces        |
      | RAG/retrieval data sources |
      | Tool execution results     |
      | External data feeds        |
      | Admin/config interfaces    |

  # stage1b-entry-point-guidance-06
  Scenario: stage1b-entry-point-guidance-06 stage1b_system.j2 renders with no unresolved placeholders
    When the template is rendered with no variables
    Then the rendered text contains "KC6.3.3 (RAG) implies an indirect entry point"
    And the rendered text does not contain "{{"

  # stage1b-entry-point-guidance-07
  Scenario Outline: stage1b-entry-point-guidance-07 surviving template sections are present
    Then the template text contains "<section_header>"

    Examples:
      | section_header           |
      | ## KC Sub-Code Taxonomy  |
      | ## Entry Points          |
      | ## Tool Inventory        |
      | ## Rules                 |

  # stage1b-entry-point-guidance-08
  Scenario Outline: stage1b-entry-point-guidance-08 sections removed by the Stage 1b rewrite are absent
    Then the template text does not contain "<retired_section>"

    Examples:
      | retired_section         |
      | ## Schneider zones      |
      | ## Emphasis             |
      | ## Quality requirements |
