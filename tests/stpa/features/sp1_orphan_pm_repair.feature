# mutation-stamp: sha256=b441d31cfca7f9a659d3acd6c5987438713169a97953b8ecddcec53f5cd59c31
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T22:07:12.415819Z","feature_name":"SP1 orphan PM repair and PM-FB correspondence","feature_path":"/Users/hjrnunes/workspace/redhat/hjrnunes/scenario-forge/tests/stpa/features/sp1_orphan_pm_repair.feature","background_hash":"c6df38b85fa703573d71d942f46439097f2759d8b0123031e17deef752748362","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 orphan PM repair and PM-FB correspondence
  Every process model part (PM-X-Y) must have at least one feedback
  channel (FB-X-Y) whose updates field references that PM. When the
  Call 2 LLM produces fewer FBs than PMs, orphan PM parts remain. The
  fix has two parts: (A) the Call 2 system and user prompts enforce
  1:1 PM-FB correspondence, and (B) a repair_orphan_pms() function
  auto-generates stub FB channels for any orphan PMs after Call 2
  output parsing, before Call 3.

  Background:
    Given the STPA system model control structure module is importable
    And the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SP1-PMFB-01
  Scenario: SP1-PMFB-01 Call 2 system prompt requires PM-FB correspondence
    Given the template stage2_call2_system.j2 is loaded
    Then the template text contains "Every process model part (PM-X-Y) MUST have at least one feedback channel"
    And the template text contains "whose updates field references that PM"
    And the template text contains "No orphan PMs"

  # SP1-PMFB-02
  Scenario: SP1-PMFB-02 Call 2 system prompt requires N FBs for N PMs
    Given the template stage2_call2_system.j2 is loaded
    Then the template text contains "If a responsibility has N process model parts, it must have at least N feedback channels"

  # SP1-PMFB-03
  Scenario: SP1-PMFB-03 Call 2 user prompt strengthens step 5 with one FB per PM
    Given the template stage2_call2_user.j2 is loaded
    Then the template text contains "One FB per PM part at minimum"
    And the template text contains "Each PM-X-Y must appear in at least one FB"

  # SP1-PMFB-04
  Scenario: SP1-PMFB-04 repair finds orphan PM with no FB referencing it
    Given a ResponsibilitySet with responsibility RESP-1 having PM-1-1 and PM-1-2 but only FB-1-1 updating PM-1-1
    When repair_orphan_pms is called
    Then the repaired ResponsibilitySet has a feedback channel updating PM-1-2

  # SP1-PMFB-05
  Scenario: SP1-PMFB-05 repair generates stub FB with correct id pattern
    Given a ResponsibilitySet with responsibility RESP-2 having orphan PM-2-1 and existing FB-2-1
    When repair_orphan_pms is called
    Then the repaired ResponsibilitySet has a feedback channel with id FB-2-2

  # SP1-PMFB-06
  Scenario: SP1-PMFB-06 repair FB description indicates auto-generation
    Given a ResponsibilitySet with responsibility RESP-1 having orphan PM-1-3
    When repair_orphan_pms is called
    Then the new feedback channel description contains "Auto-generated feedback for orphan PM-1-3"

  # SP1-PMFB-07
  Scenario: SP1-PMFB-07 repair FB updates references the orphan PM
    Given a ResponsibilitySet with responsibility RESP-1 having orphan PM-1-2
    When repair_orphan_pms is called
    Then the new feedback channel updates field equals "PM-1-2"

  # SP1-PMFB-08
  Scenario: SP1-PMFB-08 no orphan PMs means no changes and no warnings
    Given a ResponsibilitySet where every PM has a corresponding FB
    When repair_orphan_pms is called
    Then the ResponsibilitySet is unchanged
    And no warnings are returned

  # SP1-PMFB-09
  Scenario: SP1-PMFB-09 repair returns a warning for each repaired orphan
    Given a ResponsibilitySet with responsibility RESP-1 having two orphan PMs PM-1-2 and PM-1-3
    When repair_orphan_pms is called
    Then the warnings list contains two entries
    And each warning mentions the orphan PM id

  # SP1-PMFB-10
  Scenario: SP1-PMFB-10 multiple orphans in same responsibility get sequential FB numbers
    Given a ResponsibilitySet with responsibility RESP-3 having orphans PM-3-1 and PM-3-2 with no existing FBs
    When repair_orphan_pms is called
    Then the repaired ResponsibilitySet has feedback channels FB-3-1 and FB-3-2

  # SP1-PMFB-11
  Scenario: SP1-PMFB-11 orphans across multiple responsibilities are all repaired
    Given a ResponsibilitySet with responsibility RESP-1 having orphan PM-1-2 and responsibility RESP-2 having orphan PM-2-1
    When repair_orphan_pms is called
    Then the repaired ResponsibilitySet has a FB updating PM-1-2 in RESP-1
    And the repaired ResponsibilitySet has a FB updating PM-2-1 in RESP-2

  # SP1-PMFB-12
  Scenario: SP1-PMFB-12 repaired ResponsibilitySet has no orphan PMs
    Given a ResponsibilitySet with multiple orphan PMs across responsibilities
    When repair_orphan_pms is called
    Then every PM part in the repaired ResponsibilitySet is referenced by at least one FB

  # SP1-PMFB-13
  Scenario: SP1-PMFB-13 repair is called after Call 2 and before Call 3
    Given a use case text and loss analysis available for Stage 2
    When derive_control_structure runs
    Then repair_orphan_pms is called after Call 2 responsibilities are parsed
    And repair_orphan_pms is called before Call 3 connections are derived
