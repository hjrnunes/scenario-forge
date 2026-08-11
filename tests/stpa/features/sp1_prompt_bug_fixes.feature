Feature: SP1 prompt bug fixes
  Stage 1 prompts constrain generated content to the use case, and Stage 2
  prompts require complete, discrete control-structure responsibilities and
  connections. After the Stage 1a split and the Stage 2 restructure these
  behaviors are spread across more templates: Stage 1a grounding lives in
  stage1a_risk_system.j2, zone-driven responsibilities in
  stage2_call2a_system.j2, discrete control actions in
  stage2_call2b_system.j2, and coordination links in
  stage2_call3_system.j2. These behaviors are specified at the Jinja2
  prompt boundary.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SP1 prompt bug fixes-01
  Scenario Outline: SP1 prompt bug fixes-01 Stage 1a grounds losses and hazards in the use case
    Given the template stage1a_risk_system.j2 is loaded
    Then the template text contains "<grounding_text>"

    Examples:
      | grounding_text                                                  |
      | Every loss must cite its source risk IDs in `source_risk_cards`. |
      | Each hazard MUST name at least one specific component            |

  # SP1 prompt bug fixes-02
  Scenario Outline: SP1 prompt bug fixes-02 Stage 1b prohibits hallucinated tools and entry points
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<grounding_text>"

    Examples:
      | grounding_text                                                                         |
      | every tool must be explicitly mentioned or directly implied by the use-case description |
      | every KC code, entry point, and tool must be traceable to a specific capability          |

  # SP1 prompt bug fixes-03
  Scenario Outline: SP1 prompt bug fixes-03 Stage 2 Call 3 defines coordination links
    Given the template stage2_call3_system.j2 is loaded
    Then the template text contains "<coordination_text>"

    Examples:
      | coordination_text                                                                                       |
      | Coordination links are required when                                                                    |
      | lateral coordination mechanism between controllers that share state                                     |
      | Two responsibilities share a process model part not connected by a control action                       |
      | Two responsibilities need to agree on a shared resource                                                 |
      | An empty coordination_links list is acceptable only when no two responsibilities share state, data, or control flow |

  # SP1 prompt bug fixes-04
  Scenario Outline: SP1 prompt bug fixes-04 Call 2a requires zone-driven responsibilities
    Given the template stage2_call2a_system.j2 is loaded
    Then the template text contains "<zone_rule>"

    Examples:
      | zone_rule                                                                                                  |
      | Check the capability profile's active zones                                                                |
      | When `tool_execution` is active: require a responsibility governing tool parameter validation and action selection |
      | When `memory` is active: require a responsibility for context management and memory lifecycle               |
      | When `hitl` is true: require a responsibility for escalation and human oversight                            |
      | When `inter_agent` is active: require a responsibility for inter-agent coordination and message validation  |
      | This is a hard requirement, not a suggestion                                                               |

  # SP1 prompt bug fixes-05
  Scenario Outline: SP1 prompt bug fixes-05 Call 2b requires discrete control actions
    Given the template stage2_call2b_system.j2 is loaded
    Then the template text contains "<discrete_ca_rule>"

    Examples:
      | discrete_ca_rule                                                                     |
      | Each CA is a single discrete action                                                   |
      | Split composite actions into separate CAs                                            |
      | approve or reject request                                                            |
      | CA-X-1 Approve request                                                               |
      | CA-X-2 Reject request                                                                 |
      | A CA containing "or", "and", or similar conjunctions is likely composite and should be split |

  # SP1 prompt bug fixes-06
  Scenario Outline: SP1 prompt bug fixes-06 updated system prompts render successfully
    Given the template <template_name> is loaded
    When the template is rendered with no variables
    Then the rendered text contains "<rendered_text>"

    Examples:
      | template_name           | rendered_text                        |
      | stage1a_risk_system.j2  | Every loss must cite its source risk IDs |
      | stage1b_system.j2       | every tool must be explicitly mentioned  |
      | stage2_call2a_system.j2 | Check the capability profile's active zones |
      | stage2_call2b_system.j2 | Each CA is a single discrete action   |
      | stage2_call3_system.j2  | Coordination links are required when  |

  # SP1 prompt bug fixes-07
  Scenario Outline: SP1 prompt bug fixes-07 existing prompt sections remain present
    Given the template <template_name> is loaded
    Then the template text contains "<section_header>"

    Examples:
      | template_name           | section_header                |
      | stage1a_risk_system.j2  | ## Quality requirements       |
      | stage1b_system.j2       | ## Rules                      |
      | stage2_call2a_system.j2 | ## ID conventions             |
      | stage2_call2b_system.j2 | ## ID conventions             |
      | stage2_call3_system.j2  | ## Connection integrity checks |

  # SP1 prompt bug fixes-08
  Scenario Outline: SP1 prompt bug fixes-08 templates retired by the restructures are absent
    Then the prompts directory does not contain `<retired_template>`

    Examples:
      | retired_template       |
      | stage1a_system.j2      |
      | stage1a_user.j2        |
      | stage2_call2_system.j2 |
      | stage2_call2_user.j2   |
