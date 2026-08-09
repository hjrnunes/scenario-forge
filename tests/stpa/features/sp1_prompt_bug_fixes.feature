# mutation-stamp: sha256=0bcf1c02147657081ed1f0a56c8fda526bf5fab7938c921856cb590508b4e296
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T13:29:38.018279Z","feature_name":"SP1 prompt bug fixes","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/sp1_prompt_bug_fixes.feature","background_hash":"a7bc2ec77d4defafedaa1fd7aa346715ff439a68ae3d8c13e3a536e3d7527613","implementation_hash":"sha256:8541625e632df38d4f39832db786b407e4157f24d11ee7e03c7dfafdeb51130f","scenarios":[{"index":5,"name":"SP1 prompt bug fixes-06 updated system prompts render successfully","scenario_hash":"8795f5bfba5ba6954b393bf5558999ea46aa942911f618c0e2d831fb4d8b0e46","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-09T13:29:38.018279Z"},{"index":6,"name":"SP1 prompt bug fixes-07 existing prompt sections remain present","scenario_hash":"30cf34caa8120e53d399095ee8cf33d6dc4286c86b675614b3d7c1356dcdca61","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-09T13:29:38.018279Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 prompt bug fixes
  Stage 1 prompts constrain generated content to the use case, and Stage 2
  prompts require complete, discrete control-structure responsibilities and
  connections. These behaviors are specified at the Jinja2 prompt boundary.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SP1 prompt bug fixes-01
  Scenario: SP1 prompt bug fixes-01 Stage 1a prohibits hallucinated losses and hazards
    Given the template stage1a_system.j2 is loaded
    Then the template text contains "Every loss must be traceable to either a risk card or a specific feature described in the use-case text"
    And the template text contains "Every hazard must reference a concrete component, data flow, or capability from the use-case description"

  # SP1 prompt bug fixes-02
  Scenario: SP1 prompt bug fixes-02 Stage 1b prohibits hallucinated tools and entry points
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "Every tool in tool_inventory must be explicitly mentioned or directly implied by the use-case description"
    And the template text contains "Every entry point must correspond to an actual interface described in the use case"

  # SP1 prompt bug fixes-03
  Scenario: SP1 prompt bug fixes-03 Stage 2 Call 3 defines coordination links
    Given the template stage2_call3_system.j2 is loaded
    Then the template text contains "Coordination links capture dependencies between responsibilities"
    And the template text contains "share state, data, or control flow"
    And the template text contains "inter-controller coordination"
    And the template text contains "Two responsibilities sharing a process model part not connected by a control action"
    And the template text contains "One responsibility's feedback channel updates a PM part that another responsibility controls"
    And the template text contains "Two responsibilities need to agree on a shared resource"
    And the template text contains "An empty coordination_links list is acceptable only when no two responsibilities share state, data, or control flow"

  # SP1 prompt bug fixes-04
  Scenario: SP1 prompt bug fixes-04 Call 2 requires zone-driven responsibilities
    Given the template stage2_call2_system.j2 is loaded
    Then the template text contains "Check the capability profile's active zones"
    And the template text contains "When `tool_execution` is active: require a responsibility governing tool parameter validation and action selection"
    And the template text contains "When `memory` is active: require a responsibility for context management and memory lifecycle"
    And the template text contains "When `hitl` is true: require a responsibility for escalation and human oversight"
    And the template text contains "When `inter_agent` is active: require a responsibility for inter-agent coordination and message validation"
    And the template text contains "This should be a hard requirement, not a suggestion"

  # SP1 prompt bug fixes-05
  Scenario: SP1 prompt bug fixes-05 Call 2 requires discrete control actions
    Given the template stage2_call2_system.j2 is loaded
    Then the template text contains "Each control action must describe a single discrete action"
    And the template text contains "Split composite actions into separate CAs"
    And the template text contains "Approve or reject request"
    And the template text contains "CA-X-1 Approve request"
    And the template text contains "CA-X-2 Reject request"
    And the template text contains "Execute or deny command"
    And the template text contains "A control action that contains 'or', 'and', or similar conjunctions is likely composite and should be split"

  # SP1 prompt bug fixes-06
  Scenario Outline: SP1 prompt bug fixes-06 updated system prompts render successfully
    Given the template <template_name> is loaded
    When the template is rendered with no variables
    Then the rendered text contains "<rendered_text>"

    Examples:
      | template_name       | rendered_text                         |
      | stage1a_system.j2   | Every loss must be traceable          |
      | stage1b_system.j2   | Every tool in tool_inventory          |
      | stage2_call2_system.j2 | Each control action must describe   |
      | stage2_call3_system.j2 | Coordination links capture dependencies |

  # SP1 prompt bug fixes-07
  Scenario Outline: SP1 prompt bug fixes-07 existing prompt sections remain present
    Given the template <template_name> is loaded
    Then the template text contains "<section_header>"

    Examples:
      | template_name          | section_header                |
      | stage1a_system.j2      | ## Quality requirements       |
      | stage1b_system.j2      | ## Quality requirements       |
      | stage2_call2_system.j2  | ## ID conventions             |
      | stage2_call3_system.j2  | ## Structural requirements    |
