# mutation-stamp: sha256=f5a297c5735c5e864abacca623761698f2424a806d7dde2477be5bb96200d747
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T17:45:11.980066Z","feature_name":"SP1 Stage 1b — Entry point category checklist in stage1b_system.j2","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/sp1_entry_point_checklist.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"unknown","scenarios":[{"index":1,"name":"EPCL-02 stage1b_system.j2 contains all five entry point categories with examples","scenario_hash":"afdea3ccecb0f9876615471989be04a11e99f57ff5a214cc141558f196f99c9f","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:45:11.980066Z"},{"index":2,"name":"EPCL-03 each category specifies controllability and direction","scenario_hash":"404a2fdabf1e6d8819055a56bcc30b6399955f29329166def68fb686a08f27e8","mutation_count":10,"result":{"Total":10,"Killed":10,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:45:11.980066Z"},{"index":6,"name":"EPCL-07 checklist preserves existing template sections","scenario_hash":"a031414e4851ab1db941cc45af9f121bff192dcea460f3888265952218126e39","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-09T17:45:11.980066Z"}]}
# acceptance-mutation-manifest-end

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
