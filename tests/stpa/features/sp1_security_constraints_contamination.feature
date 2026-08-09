Feature: SP1 — Prevent security constraints from contaminating tool inventory
  The stage1b_user.j2 template includes the full LossAnalysis with security
  constraints. The LLM treats prescriptive security constraints ("must
  implement X") as descriptions of existing capabilities, generating phantom
  tools that do not exist in the use-case description. The fix adds an
  explicit instruction in stage1b_system.j2 that security constraints
  describe what SHOULD exist, not what DOES exist, and relabels the Security
  Constraints section in stage1b_user.j2 to clarify they are requirements,
  not existing capabilities.

  Background:
    Given the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SecCon-01
  Scenario: SecCon-01 stage1b_system.j2 instructs not to infer tools from security constraints
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "Security constraints describe what SHOULD exist, not what DOES exist"
    And the template text contains "Do not infer tools from security constraints"

  # SecCon-02
  Scenario: SecCon-02 stage1b_system.j2 instructs to list only existing capabilities
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "Only list tools explicitly described as existing capabilities in the use-case description"

  # SecCon-03
  Scenario: SecCon-03 stage1b_user.j2 relabels Security Constraints section
    Given the template stage1b_user.j2 is loaded
    Then the template text contains "Security Constraints (requirements for future control structure, NOT existing capabilities)"

  # SecCon-04
  Scenario: SecCon-04 stage1b_user.j2 does not contain the old unlabeled Security Constraints header
    Given the template stage1b_user.j2 is loaded
    Then the template text does not contain a bare "### Security Constraints" without the clarification

  # SecCon-05
  Scenario: SecCon-05 stage1b_user.j2 still renders the security constraint listings
    Given the template stage1b_user.j2 is loaded
    When the template is rendered with use_case_text, loss_analysis, and all_losses
    Then the rendered text contains "Security Constraints"
    And the rendered text contains the constraint_id from the loss analysis

  # SecCon-06
  Scenario Outline: SecCon-06 stage1b_system.j2 preserves existing quality requirement sections
    Given the template stage1b_system.j2 is loaded
    Then the template text contains "<section_header>"

    Examples:
      | section_header              |
      | ## Quality requirements     |
      | ## Schneider zones          |
      | ## Rules                    |
      | ## Emphasis                 |

  # SecCon-07
  Scenario: SecCon-07 stage1b_system.j2 renders successfully with the new instruction
    Given the template stage1b_system.j2 is loaded
    When the template is rendered with no variables
    Then the rendered text contains "Security constraints describe what SHOULD exist"
    And the rendered text does not contain "{{"

  # SecCon-08
  Scenario: SecCon-08 stage1b_user.j2 preserves other loss analysis sections
    Given the template stage1b_user.j2 is loaded
    Then the template text contains "Loss Analysis Context"
    And the template text contains "Losses"
    And the template text contains "Hazards"
    And the template text contains "Your Task"
