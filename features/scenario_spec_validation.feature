Feature: ScenarioSpec boundary schema validation
  The ScenarioSpec model validates that defender BDI references (beliefs,
  desires, intentions) point to valid control structure elements, and that
  the target controller and target control action are consistent.

  Background:
    Given the STPA boundary schema module is importable
    And a control structure with responsibility RESP-1, process model part PM-1-1, and control action CA-1-1

  # ScenarioSpec-01
  Scenario: ScenarioSpec-01 valid scenario spec passes validation
    Given a scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1
    And defender belief referencing PM-1-1, desire referencing RESP-1, intention referencing CA-1-1
    When the scenario spec is validated against the control structure
    Then validation succeeds

  # ScenarioSpec-02
  Scenario: ScenarioSpec-02 defender belief referencing non-existent PM fails
    Given a scenario spec with defender belief referencing PM-99-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing pm_id

  # ScenarioSpec-03
  Scenario: ScenarioSpec-03 defender desire referencing non-existent RESP fails
    Given a scenario spec with defender desire referencing RESP-99
    When the scenario spec is validated against the control structure
    Then validation fails with error containing resp_id

  # ScenarioSpec-04
  Scenario: ScenarioSpec-04 defender intention referencing non-existent CA fails
    Given a scenario spec with defender intention referencing CA-99-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing ca_id

  # ScenarioSpec-05
  Scenario: ScenarioSpec-05 target_controller referencing non-existent RESP fails
    Given a scenario spec with target_controller RESP-99
    When the scenario spec is validated against the control structure
    Then validation fails with error containing target_controller

  # ScenarioSpec-06
  Scenario: ScenarioSpec-06 target_control_action referencing non-existent CA fails
    Given a scenario spec with target_control_action CA-99-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing target_control_action

  # ScenarioSpec-07
  Scenario: ScenarioSpec-07 target_control_action not belonging to target_controller fails
    Given a control structure with responsibilities RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2
    And a scenario spec with target_controller RESP-1 and target_control_action CA-2-1
    When the scenario spec is validated against the control structure
    Then validation fails with error containing target_control_action

  # ScenarioSpec-08
  Scenario: ScenarioSpec-08 threat source with structural provenance passes
    Given a scenario spec with threat source ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED and provenance structural
    When the scenario spec is validated against the control structure
    Then validation succeeds

  # ScenarioSpec-09
  Scenario: ScenarioSpec-09 threat source with catalog_only provenance passes
    Given a scenario spec with threat source ica_slot_id RESP-1:CA-1-1:NOT_PROVIDED and provenance catalog_only
    When the scenario spec is validated against the control structure
    Then validation succeeds

  # ScenarioSpec-10
  Scenario: ScenarioSpec-10 attacker BDI with free-form strings passes
    Given a scenario spec with attacker beliefs, desires, and intentions as free-form strings
    When the scenario spec is validated against the control structure
    Then validation succeeds

  # ScenarioSpec-11
  Scenario: ScenarioSpec-11 scenario spec with catalog context passes
    Given a scenario spec with catalog context containing OWASP_AGENTIC mapping T2-T3 confidence high
    When the scenario spec is validated against the control structure
    Then validation succeeds
