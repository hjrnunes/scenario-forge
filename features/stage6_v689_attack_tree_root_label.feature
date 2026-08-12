# mutation-stamp: sha256=7398e5f52b94ea08d7b2c23c41e6aac61fd6dae9b62170d2dac254a77feaed8f
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-10T14:37:58.560317Z","feature_name":"Stage 6 Attack tree root label ICA type (v689)","feature_path":"features/stage6_v689_attack_tree_root_label.feature","background_hash":"51ef595ce212d9b5440fcaf572995eec3ed642faaab4697994f0ff764100a0da","implementation_hash":"unknown","scenarios":[{"index":1,"name":"V689-02 validator passes when root label matches exact ICA type","scenario_hash":"05c302259c1026d90e4b9bea929a59d1de195cd6ce7740666c9a1d554cae0fed","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:58.560317Z"},{"index":2,"name":"V689-03 validator catches ICA type drift","scenario_hash":"5572f08910d93aac5d86b3177cccba6c01647f5351f64102beb7d297f958bff7","mutation_count":8,"result":{"Total":8,"Killed":8,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:58.560317Z"},{"index":3,"name":"V689-04 validator catches malformed root labels","scenario_hash":"74a096b6d91b8899598cf4d2547ae7c3657257c31d0fe574620eeebd3c002528","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-10T14:37:58.560317Z"}]}
# acceptance-mutation-manifest-end

Feature: Stage 6 Attack tree root label ICA type (v689)
  The attack tree root node must use the exact ICA type enum value from the
  scenario seed. The Stage 6b system prompt explicitly instructs the LLM to
  use the exact ICA type in the format "Induce ICA {ica_type} on {ca_id}".
  A post-generation validator checks the root label matches the expected
  format with the exact ICA type from the scenario spec.

  Background:
    Given the SP3 attack tree module is importable
    And a ScenarioSpec with defender BDI and attacker BDI for scenario SCN-001
    And a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1

  # V689-01
  Scenario: V689-01 system prompt instructs exact ICA type usage
    When the attack tree system prompt is rendered
    Then the system prompt instructs the LLM to use the exact ICA type enum value
    And the system prompt defines the root format as Induce ICA followed by the ICA type and control action
    And the system prompt instructs the LLM not to substitute or paraphrase the ICA type

  # V689-02
  Scenario Outline: V689-02 validator passes when root label matches exact ICA type
    Given a ScenarioSpec with ica_type <ica_type> and target_control_action CA-1-1
    And an attack tree with root "Induce ICA <ica_type> on CA-1-1"
    When attack tree root label validation is performed
    Then validation succeeds

    Examples:
      | ica_type       |
      | NOT_PROVIDED   |
      | INCORRECT      |
      | WRONG_TIMING   |
      | WRONG_DURATION |

  # V689-03
  Scenario Outline: V689-03 validator catches ICA type drift
    Given a ScenarioSpec with ica_type <expected_type> and target_control_action CA-1-1
    And an attack tree with root "Induce ICA <drifted_type> on CA-1-1"
    When attack tree root label validation is performed
    Then validation fails with error containing <expected_type>

    Examples:
      | expected_type   | drifted_type   |
      | NOT_PROVIDED    | NOT_TRIGGERED  |
      | INCORRECT       | WRONG_VALUE    |
      | WRONG_TIMING    | LATE           |
      | WRONG_DURATION  | TOO_LONG       |

  # V689-04
  Scenario Outline: V689-04 validator catches malformed root labels
    Given a ScenarioSpec with ica_type NOT_PROVIDED and target_control_action CA-1-1
    And an attack tree with root "<root_label>"
    When attack tree root label validation is performed
    Then validation fails with error containing <error_keyword>

    Examples:
      | root_label                             | error_keyword |
      | Induce ICA on CA-1-1                   | NOT_PROVIDED  |
      | Induce ICA NOT_PROVIDED on CA-9-9      | CA-1-1        |
      |                                        | root          |

  # V689-05
  Scenario: V689-05 root label validation runs during Stage 6 artifact validation
    Given a ScenarioSpec with ica_type NOT_PROVIDED and target_control_action CA-1-1
    And an LLM that returns an attack tree with root "Induce ICA NOT_TRIGGERED on CA-1-1"
    When the Stage 6 pipeline runs for the scenario
    Then a validation error is reported containing NOT_PROVIDED

  # V689-06
  Scenario: V689-06 root label validation runs during Stage 7 envelope validation
    Given a ScenarioEnvelope with ica_type NOT_PROVIDED and attack_tree root "Induce ICA NOT_TRIGGERED on CA-1-1"
    When Stage 7 envelope validation is performed
    Then validation fails with error containing NOT_PROVIDED

  # V689-07
  Scenario: V689-07 user prompt passes ICA type to the LLM
    When the attack tree user prompt is built
    Then the user prompt contains the scenario spec with ica_type NOT_PROVIDED
