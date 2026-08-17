# mutation-stamp: sha256=b6935b213cae18e855b41961cc943848283f1bf15151520b283347514c58af96
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T20:48:55.101954Z","feature_name":"SP1 minItems constraints on critical arrays","feature_path":"features/sp1_minitems_constraints.feature","background_hash":"81c3bf7368b8bb21ba0e164acef3809ceba9cb838b29c119d000af660a748e0e","implementation_hash":"unknown","scenarios":[{"index":0,"name":"MinItems-01 empty critical array fails validation","scenario_hash":"488b62a29cae71e7e4a2d7f72e8c4bf5122c120a4db06df68e2b5e55abdbd92b","mutation_count":6,"result":{"Total":6,"Killed":6,"Survived":0,"Errors":0},"tested_at":"2026-08-08T20:48:55.101954Z"},{"index":1,"name":"MinItems-02 empty optional array passes validation","scenario_hash":"8a14f4106ff9c23f797cc1609ddb25723c240b9d613ed219858595a6e25b3cbb","mutation_count":2,"result":{"Total":2,"Killed":2,"Survived":0,"Errors":0},"tested_at":"2026-08-08T20:48:55.101954Z"}]}
# acceptance-mutation-manifest-end

Feature: SP1 minItems constraints on critical arrays
  The LossAnalysis and ControlStructure models enforce min_length=1 on
  arrays that the pipeline assumes are non-empty downstream: LossAnalysis.hazards,
  LossAnalysis.security_constraints, and ControlStructure.responsibilities.
  Fields that can legitimately be empty (risk_card_losses, use_case_losses)
  remain unconstrained so that a loss analysis with no risk cards or no
  use-case losses is still valid.

  Background:
    Given the STPA boundary schema module is importable
    And a minimal valid loss analysis with loss L-1, hazard H-1, and constraint SC-1
    And a minimal valid control structure with responsibility RESP-1

  # MinItems-01
  Scenario Outline: MinItems-01 empty critical array fails validation
    Given a <model> with empty <field>
    When the <model> is validated
    Then validation fails

    Examples:
      | model             | field                |
      | loss analysis     | hazards              |
      | loss analysis     | security_constraints |
      | control structure | responsibilities     |

  # MinItems-02
  Scenario Outline: MinItems-02 empty optional array passes validation
    Given a loss analysis with empty <field> and one use case loss L-1
    When the loss analysis is validated
    Then validation succeeds

    Examples:
      | field            |
      | risk_card_losses |
      | use_case_losses  |

  # MinItems-03
  Scenario: MinItems-03 non-empty critical arrays pass validation
    Given a loss analysis with hazard H-1 and security constraint SC-1
    When the loss analysis is validated
    Then validation succeeds

  # MinItems-04
  Scenario: MinItems-04 ControlStructure with non-empty responsibilities passes validation
    Given a control structure with responsibility RESP-1 having PM-1-1, CA-1-1, and FB-1-1
    When the control structure is validated
    Then validation succeeds
