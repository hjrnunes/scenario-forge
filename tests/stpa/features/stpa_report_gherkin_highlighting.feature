# stpa-report-gherkin-highlighting
Feature: STPA Report Gherkin Syntax Highlighting
  Gherkin specs in scenario cards are syntax-highlighted with distinct
  colors for each keyword: Given=blue, When=purple, Then=green, But=red,
  And=indigo.

  Background:
    Given a combined output directory containing scenario SCN-001.feature with Gherkin:
      """
      Scenario: Prompt injection bypasses verification
        Given the system is preparing content for the user
          And the approved guidelines are loaded
        When an attacker performs a direct prompt injection
        Then the system should validate content against guidelines
          But the control action is NOT_PROVIDED
      """

  Scenario: Given keyword is highlighted blue
    When I generate the STPA report
    Then the Gherkin section for "SCN-001" highlights the "Given" keyword with a blue color

  Scenario: When keyword is highlighted purple
    When I generate the STPA report
    Then the Gherkin section for "SCN-001" highlights the "When" keyword with a purple color

  Scenario: Then keyword is highlighted green
    When I generate the STPA report
    Then the Gherkin section for "SCN-001" highlights the "Then" keyword with a green color

  Scenario: But keyword is highlighted red
    When I generate the STPA report
    Then the Gherkin section for "SCN-001" highlights the "But" keyword with a red color

  Scenario: And keyword is highlighted indigo
    When I generate the STPA report
    Then the Gherkin section for "SCN-001" highlights the "And" keyword with an indigo color

  Scenario: Gherkin comments and tags are highlighted
    Given scenario SCN-002.feature contains a Gherkin comment and tag
    When I generate the STPA report
    Then the Gherkin section for "SCN-002" highlights comments with a muted style
    And the Gherkin section for "SCN-002" highlights tags with an amber style
