Feature: LossAnalysis boundary schema validation
  The LossAnalysis model validates cross-references between losses, hazards,
  and security constraints, enforces provenance consistency, and rejects
  duplicate IDs.

  Background:
    Given the STPA boundary schema module is importable
    And a minimal valid loss analysis with loss L-1, hazard H-1, and constraint SC-1

  # LossAnalysis-01
  Scenario: LossAnalysis-01 valid loss analysis passes validation
    Given a loss analysis with losses L-1 and L-2, hazard H-1 referencing L-1, and constraint SC-1 referencing H-1
    When the loss analysis is validated
    Then validation succeeds

  # LossAnalysis-02
  Scenario Outline: LossAnalysis-02 hazard referencing non-existent loss fails
    Given a loss analysis with loss L-1 and hazard H-1 referencing loss <bad_ref>
    When the loss analysis is validated
    Then validation fails with error containing <error_fragment>

    Examples:
      | bad_ref   | error_fragment |
      | L-99      | related_losses |
      | NONEXIST  | related_losses |

  # LossAnalysis-03
  Scenario Outline: LossAnalysis-03 constraint referencing non-existent hazard fails
    Given a loss analysis with loss L-1, hazard H-1, and constraint SC-1 referencing hazard <bad_ref>
    When the loss analysis is validated
    Then validation fails with error containing <error_fragment>

    Examples:
      | bad_ref   | error_fragment     |
      | H-99      | related_hazards    |
      | NONEXIST  | related_hazards    |

  # LossAnalysis-04
  Scenario: LossAnalysis-04 risk card loss with correct provenance passes
    Given a risk card loss L-1 with provenance risk_card and source_risk_cards atlas-001
    When the loss analysis is validated
    Then validation succeeds

  # LossAnalysis-05
  Scenario: LossAnalysis-05 risk card loss with empty source_risk_cards fails
    Given a risk card loss L-1 with provenance risk_card and empty source_risk_cards
    When the loss analysis is validated
    Then validation fails with error containing source_risk_cards

  # LossAnalysis-06
  Scenario: LossAnalysis-06 risk card loss with wrong provenance fails
    Given a risk card loss L-1 with provenance use_case and source_risk_cards atlas-001
    When the loss analysis is validated
    Then validation fails with error containing provenance

  # LossAnalysis-07
  Scenario: LossAnalysis-07 use case loss with empty source_risk_cards passes
    Given a use case loss L-1 with provenance use_case and empty source_risk_cards
    When the loss analysis is validated
    Then validation succeeds

  # LossAnalysis-08
  Scenario: LossAnalysis-08 use case loss with non-empty source_risk_cards fails
    Given a use case loss L-1 with provenance use_case and source_risk_cards atlas-001
    When the loss analysis is validated
    Then validation fails with error containing source_risk_cards

  # LossAnalysis-09
  Scenario: LossAnalysis-09 critic derived loss with empty source_risk_cards passes
    Given a critic derived loss L-1 with provenance critic_derived and empty source_risk_cards
    When the loss analysis is validated
    Then validation succeeds

  # LossAnalysis-10
  Scenario Outline: LossAnalysis-10 duplicate IDs fail validation
    Given a loss analysis with duplicate <id_field> value <dup_value>
    When the loss analysis is validated
    Then validation fails with error containing <error_fragment>

    Examples:
      | id_field            | dup_value | error_fragment |
      | loss_id             | L-1       | duplicate      |
      | hazard_id           | H-1       | duplicate      |
      | constraint_id       | SC-1      | duplicate      |
