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
