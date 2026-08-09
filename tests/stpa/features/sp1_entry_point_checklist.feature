Feature: SP1 Stage 1b — Entry point category checklist in stage1b_system.j2
  The stage1b_system.j2 prompt defines entry point fields structurally but
  provides no category checklist, no examples, and no guidance. All SP1
  runs consistently miss RAG/retrieval data sources and tool execution
  results as entry points. The fix adds a 5-category checklist with
  concrete examples and a note clarifying that a component can appear in
  both tool_inventory and entry_points.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # EPCL-01
  Scenario: EPCL-01 stage1b_system.j2 contains entry point category checklist
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "entry point" category checklist

  # EPCL-02
  Scenario Outline: EPCL-02 stage1b_system.j2 contains all five entry point categories with examples
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<category_name>"
    And the template text contains "<example_text>"

    Examples:
      | category_name               | example_text      |
      | User input surfaces         | chat interface    |
      | RAG/retrieval data sources  | knowledge base    |
      | Tool execution results      | API call          |
      | External data feeds         | third-party       |
      | Admin/config interfaces     | admin dashboard   |

  # EPCL-03
  Scenario Outline: EPCL-03 each category specifies controllability and direction
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<category_name>" with controllability "<controllability>"

    Examples:
      | category_name               | controllability |
      | User input surfaces         | direct          |
      | RAG/retrieval data sources  | indirect        |
      | Tool execution results      | indirect        |
      | External data feeds         | indirect        |
      | Admin/config interfaces     | direct          |

  # EPCL-04
  Scenario: EPCL-04 RAG retrieval category notes indirect ingress via poisoned content
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "RAG/retrieval data sources"
    And the template text contains "indirect ingress"
    And the template text contains "poisoned"

  # EPCL-05
  Scenario: EPCL-05 template notes component can appear in both tool_inventory and entry_points
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "both" and "tool_inventory" and "entry_points"

  # EPCL-06
  Scenario: EPCL-06 template renders without errors with checklist content
    Given the template stage1b_system.j2 is loaded
    When the template is rendered with no variables
    Then the rendered text contains "User input surfaces"
    And the rendered text contains "RAG/retrieval data sources"
    And the rendered text contains "Tool execution results"
    And the rendered text contains "External data feeds"
    And the rendered text contains "Admin/config interfaces"

  # EPCL-07
  Scenario Outline: EPCL-07 checklist preserves existing template sections
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header              |
      | ## Schneider zones          |
      | ## Rules                    |
      | ## Emphasis                 |
      | ## Quality requirements     |

  # EPCL-08
  Scenario: EPCL-08 checklist section appears after Rules section
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "## Rules"
    And the entry point category checklist section appears after the Rules section in stage1b_system.j2
