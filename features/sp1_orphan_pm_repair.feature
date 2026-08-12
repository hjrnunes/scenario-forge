# mutation-stamp: sha256=2797e6ae73010e0dae3c83a87db98f24c56944e1fd15255d24be476335c5c93e
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-11T21:22:56.817433Z","feature_name":"SP1 orphan PM repair and PM-FB correspondence","feature_path":"features/sp1_orphan_pm_repair.feature","background_hash":"c6df38b85fa703573d71d942f46439097f2759d8b0123031e17deef752748362","implementation_hash":"sha256:b96e22d4b98f7d0fa2f452960ef767f0b0c7deeea2f25e864cd4656037ec38c4","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 orphan PM repair and PM-FB correspondence
  Every process model part (PM-X-Y) must have at least one feedback
  channel (FB-X-Y) whose updates field references that PM. When the
  Call 2b LLM produces fewer FBs than PMs, orphan PM parts remain, so
  repair_orphan_pms() auto-generates stub FB channels for any orphan PMs.
  Repair operates on the assembled ControlStructure — after Call 2a and
  Call 2b are merged, and before Call 3. The prompt-level PM-FB
  correspondence instructions are specified in stage2-call2b.feature and
  are not restated here.

  Background:
    Given the STPA system model control structure module is importable
    And the STPA system model prompts directory is available
    And the TemplateLoader can load templates from the prompts directory

  # SP1-PMFB-04
  Scenario: SP1-PMFB-04 repair finds orphan PM with no FB referencing it
    Given a ControlStructure with responsibility RESP-1 having PM-1-1 and PM-1-2 but only FB-1-1 updating PM-1-1
    When repair_orphan_pms is called
    Then the repaired ControlStructure has a feedback channel updating PM-1-2

  # SP1-PMFB-05
  Scenario: SP1-PMFB-05 repair generates stub FB with correct id pattern
    Given a ControlStructure with responsibility RESP-2 having orphan PM-2-1 and existing FB-2-1
    When repair_orphan_pms is called
    Then the repaired ControlStructure has a feedback channel with id FB-2-2

  # SP1-PMFB-06
  Scenario: SP1-PMFB-06 repair FB description indicates auto-generation
    Given a ControlStructure with responsibility RESP-1 having orphan PM-1-3
    When repair_orphan_pms is called
    Then the new feedback channel description contains "Auto-generated feedback for orphan PM-1-3"

  # SP1-PMFB-07
  Scenario: SP1-PMFB-07 repair FB updates references the orphan PM
    Given a ControlStructure with responsibility RESP-1 having orphan PM-1-2
    When repair_orphan_pms is called
    Then the new feedback channel updates field equals "PM-1-2"

  # SP1-PMFB-08
  Scenario: SP1-PMFB-08 no orphan PMs means no changes and no warnings
    Given a ControlStructure where every PM has a corresponding FB
    When repair_orphan_pms is called
    Then the ControlStructure is unchanged
    And no warnings are returned

  # SP1-PMFB-09
  Scenario: SP1-PMFB-09 repair returns a warning for each repaired orphan
    Given a ControlStructure with responsibility RESP-1 having two orphan PMs PM-1-2 and PM-1-3
    When repair_orphan_pms is called
    Then the warnings list contains two entries
    And each warning mentions the orphan PM id

  # SP1-PMFB-10
  Scenario: SP1-PMFB-10 multiple orphans in same responsibility get sequential FB numbers
    Given a ControlStructure with responsibility RESP-3 having orphans PM-3-1 and PM-3-2 with no existing FBs
    When repair_orphan_pms is called
    Then the repaired ControlStructure has feedback channels FB-3-1 and FB-3-2

  # SP1-PMFB-11
  Scenario: SP1-PMFB-11 orphans across multiple responsibilities are all repaired
    Given a ControlStructure with responsibility RESP-1 having orphan PM-1-2 and responsibility RESP-2 having orphan PM-2-1
    When repair_orphan_pms is called
    Then the repaired ControlStructure has a FB updating PM-1-2 in RESP-1
    And the repaired ControlStructure has a FB updating PM-2-1 in RESP-2

  # SP1-PMFB-12
  Scenario: SP1-PMFB-12 repaired ControlStructure has no orphan PMs
    Given a ControlStructure with multiple orphan PMs across responsibilities
    When repair_orphan_pms is called
    Then every PM part in the repaired ControlStructure is referenced by at least one FB

  # SP1-PMFB-13
  Scenario: SP1-PMFB-13 repair runs after assembly and before Call 3
    Given a use case text and loss analysis available for Stage 2
    When derive_control_structure runs
    Then repair_orphan_pms is called after the control structure is assembled
    And repair_orphan_pms is called before Call 3 coordination is derived
