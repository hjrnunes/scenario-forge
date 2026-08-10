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
