# stpa-report-sp3-flow-card
Feature: STPA Report SP3 Flow Card
  The SP3 flow card is an expandable section showing the scenario list
  and eval scorecard. Each scenario is individually collapsible, showing
  BDI, narrative, attack tree, and Gherkin in stacked sections. The eval
  scorecard displays visual gauges for each metric.

  Background:
    Given a combined output directory containing SP3 artifacts:
      | scenarios/SCN-001.yaml    |
      | scenarios/SCN-001.feature |
      | eval-scorecard.yaml        |
      | coverage-gaps.json         |

  Scenario: SP3 flow card is collapsed by default
    When I generate the STPA report
    Then the SP3 flow card section exists in the report
    And the SP3 flow card is in a collapsed state by default
    And the SP3 flow card header is labeled "SP3"

  Scenario: A produces arrow connects SP2 and SP3 flow cards
    When I generate the STPA report
    Then a visual produces arrow exists between the SP2 flow card and the SP3 flow card

  Scenario: SP3 flow card lists scenarios
    Given the output directory contains scenarios "SCN-001" and "SCN-002"
    When I generate the STPA report
    Then the SP3 flow card contains a scenario list with 2 entries
    And the scenario list shows scenario ID "SCN-001"
    And the scenario list shows scenario ID "SCN-002"

  Scenario: Each scenario is individually collapsible
    Given the output directory contains scenario "SCN-001"
    When I generate the STPA report
    Then the SP3 flow card contains a collapsible scenario card for "SCN-001"
    And the scenario card for "SCN-001" is collapsed by default

  Scenario: Scenario card displays BDI in stacked sections
    Given scenario SCN-001.yaml contains defender BDI beliefs and attacker BDI beliefs
    When I generate the STPA report
    Then the scenario card for "SCN-001" contains a BDI section
    And the BDI section shows defender beliefs
    And the BDI section shows attacker beliefs

  Scenario: Scenario card displays narrative
    Given scenario SCN-001.yaml contains a narrative
    When I generate the STPA report
    Then the scenario card for "SCN-001" contains a narrative section
    And the narrative section shows the narrative text

  Scenario: Scenario card displays attack tree
    Given scenario SCN-001.yaml contains an attack tree with branches
    When I generate the STPA report
    Then the scenario card for "SCN-001" contains an attack tree section
    And the attack tree section shows a visual tree with nested nodes

  Scenario: Scenario card displays Gherkin spec
    Given scenario SCN-001.feature contains a Gherkin scenario
    When I generate the STPA report
    Then the scenario card for "SCN-001" contains a Gherkin section
    And the Gherkin section shows the Gherkin steps with syntax highlighting

  Scenario: SP3 flow card displays eval scorecard with gauges
    Given eval-scorecard.yaml contains:
      | metric                    | rate  |
      | traceability_depth        | 1.0   |
      | tree_branch_coverage      | 0.0   |
      | bdi_grounding             | 1.0   |
    When I generate the STPA report
    Then the SP3 flow card contains an eval scorecard subsection
    And the eval scorecard shows a gauge for "traceability_depth"
    And the eval scorecard shows a gauge for "tree_branch_coverage"
    And the eval scorecard shows a gauge for "bdi_grounding"
