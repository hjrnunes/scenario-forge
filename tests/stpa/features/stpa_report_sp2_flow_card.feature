# stpa-report-sp2-flow-card
Feature: STPA Report SP2 Flow Card
  The SP2 flow card is an expandable section showing ICA enumeration,
  catalog enrichment, and coverage analysis from the Stage 2 output
  artifacts. It appears below the SP1 flow card with a produces arrow
  between them.

  Background:
    Given a combined output directory containing SP2 artifacts:
      | ica-enumeration.yaml  |
      | enriched-threats.yaml |

  Scenario: SP2 flow card is collapsed by default
    When I generate the STPA report
    Then the SP2 flow card section exists in the report
    And the SP2 flow card is in a collapsed state by default
    And the SP2 flow card header is labeled "SP2"

  Scenario: A produces arrow connects SP1 and SP2 flow cards
    When I generate the STPA report
    Then a visual produces arrow exists between the SP1 flow card and the SP2 flow card

  Scenario: SP2 flow card displays ICA enumeration
    Given ica-enumeration.yaml contains ICA slot "RESP-1:CA-1-1:NOT_PROVIDED"
    When I generate the STPA report
    Then the SP2 flow card contains an ICA enumeration subsection
    And the ICA enumeration subsection shows slot "RESP-1:CA-1-1:NOT_PROVIDED"

  Scenario: SP2 flow card displays catalog enrichment
    Given enriched-threats.yaml contains a structural threat with catalog mapping "AML.T0051.000"
    When I generate the STPA report
    Then the SP2 flow card contains a catalog enrichment subsection
    And the catalog enrichment subsection shows mapping "AML.T0051.000"

  Scenario: SP2 flow card displays coverage analysis
    Given enriched-threats.yaml contains coverage analysis with coverage_rate "0.778"
    When I generate the STPA report
    Then the SP2 flow card contains a coverage analysis subsection
    And the coverage analysis subsection shows a coverage rate

  Scenario: SP2 flow card includes collapsible raw YAML
    When I generate the STPA report
    Then the SP2 flow card contains a collapsible raw YAML section for "ica-enumeration.yaml"
    And the SP2 flow card contains a collapsible raw YAML section for "enriched-threats.yaml"
