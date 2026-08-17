# mutation-stamp: sha256=71629093e8d8c37fa45b1a47a35467b0d55ba3d07d21d06a8ac65dc8258d6325
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T12:24:06.570051Z","feature_name":"LossAnalysis boundary schema validation","feature_path":"features/loss_analysis_validation.feature","background_hash":"8a10a738fd8f8a34f249c8eba2334395be6589721cb2bf5241bf5b5fc46e4ffa","implementation_hash":"unknown","scenarios":[{"index":1,"name":"LossAnalysis-02 hazard referencing non-existent loss fails","scenario_hash":"1cf03fe8f9b2bcde20fccb9820ed6d8195b4042b2eb48b9c3fc22815b4687f25","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:06.570051Z"},{"index":2,"name":"LossAnalysis-03 constraint referencing non-existent hazard fails","scenario_hash":"972bbcd2b4365cdf6c41fca147f83f8ffc02ad0de07403bbaf98aaa7a46cbaef","mutation_count":4,"result":{"Total":4,"Killed":4,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:06.570051Z"},{"index":9,"name":"LossAnalysis-10 duplicate IDs fail validation","scenario_hash":"5e08e326df034b7a13cd1471469a9093faf732a09d765f6564167d043837ca9b","mutation_count":9,"result":{"Total":9,"Killed":9,"Survived":0,"Errors":0},"tested_at":"2026-08-08T12:24:06.570051Z"}]}
# acceptance-mutation-manifest-end

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
