# mutation-stamp: sha256=3ec1267d93e5093afbe2967a2814670df4c86f085a47afe945071ce6f359253e
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:44:57.087271Z","feature_name":"Stage 1b Entry Point Guidance","feature_path":"features/acceptance-refresh/stage1b-entry-point-guidance.feature","background_hash":"a3f643d0fc590c50d3c5168108dca0b3a8c11b874d89b2127433a41206b62eda","implementation_hash":"sha256:5d5deb20dd4a4e1101e3a54b534c641b5488d0e9c18f2c9709ad8d10f0f6df4e","scenarios":[{"index":4,"name":"stage1b-entry-point-guidance-05 the removed five-category checklist is absent","scenario_hash":"c248ed188d6342e771a502f8e84e4850769e15e0065d1c34a48ef7accd6b94db","mutation_count":5,"result":{"Total":5,"Killed":5,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:44:57.087271Z"},{"index":7,"name":"stage1b-entry-point-guidance-08 sections removed by the Stage 1b rewrite are absent","scenario_hash":"30bad54b0b2e2989ff3810c091ca88fdd1d30d24966649b68c000310b369b1eb","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:44:57.087271Z"},{"index":1,"name":"stage1b-entry-point-guidance-02 each entry-point field is specified","scenario_hash":"8dde06df966b8b5089902669ebb1852a42900f105cb7a62072db097e28c44d22","mutation_count":3,"result":{"Total":3,"Killed":3,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:03.933484Z"},{"index":2,"name":"stage1b-entry-point-guidance-03 KC capabilities map to implied ingress paths","scenario_hash":"62295e9ae0c9502e5c4e5d847a865570b4af93c90d0dcec8ef35576d6228c00d","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:03.933484Z"},{"index":6,"name":"stage1b-entry-point-guidance-07 surviving template sections are present","scenario_hash":"6ae7437c213caf87092a14c7b79798cc8322a61fc4b746492f2c76a7ff008b72","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-11T21:43:03.933484Z"}]}
# acceptance-mutation-manifest-end

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
