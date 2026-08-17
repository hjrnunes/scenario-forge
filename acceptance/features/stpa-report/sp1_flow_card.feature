# stpa-report-sp1-flow-card
Feature: STPA Report SP1 Flow Card
  The SP1 flow card is an expandable section showing losses, hazards,
  security constraints, capability profile, and control structure
  from the Stage 1 output artifacts.

  Background:
    Given a combined output directory containing SP1 artifacts:
      | loss-analysis.yaml      |
      | capability-profile.yaml |
      | control-structure.yaml  |

  Scenario: SP1 flow card is collapsed by default
    When I generate the STPA report
    Then the SP1 flow card section exists in the report
    And the SP1 flow card is in a collapsed state by default
    And the SP1 flow card header is labeled "SP1"

  Scenario: SP1 flow card displays losses and hazards
    Given loss-analysis.yaml contains:
      | loss_id | description                | provenance  |
      | L-1     | Patient receives wrong advice | risk_card  |
      | H-1     | Unverified content presented |            |
      | SC-1    | All content must be verified |            |
    When I generate the STPA report
    Then the SP1 flow card contains loss "L-1" with description "Patient receives wrong advice"
    And the SP1 flow card contains hazard "H-1" with description "Unverified content presented"
    And the SP1 flow card contains security constraint "SC-1" with description "All content must be verified"

  Scenario: SP1 flow card displays capability profile
    Given capability-profile.yaml contains zones "input" and "reasoning"
    When I generate the STPA report
    Then the SP1 flow card contains a capability profile subsection
    And the capability profile subsection shows zone "input"
    And the capability profile subsection shows zone "reasoning"

  Scenario: SP1 flow card displays control structure
    Given control-structure.yaml contains responsibility "RESP-1"
    When I generate the STPA report
    Then the SP1 flow card contains a control structure subsection
    And the control structure subsection shows responsibility "RESP-1"

  Scenario: SP1 flow card includes collapsible raw YAML
    When I generate the STPA report
    Then the SP1 flow card contains a collapsible raw YAML section for "loss-analysis.yaml"
    And the SP1 flow card contains a collapsible raw YAML section for "capability-profile.yaml"
    And the SP1 flow card contains a collapsible raw YAML section for "control-structure.yaml"
