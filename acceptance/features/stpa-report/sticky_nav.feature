# stpa-report-sticky-nav
Feature: STPA Report Sticky Mini-Navigation
  A sticky mini-navigation bar appears on the right side of the report
  when the user scrolls. It provides quick links to SP1, SP2, SP3, Calls,
  and Manifest sections.

  Background:
    Given a combined output directory containing STPA artifacts

  Scenario: Sticky nav contains links to all major sections
    When I generate the STPA report
    Then the report HTML contains a sticky navigation element
    And the sticky navigation contains a link labeled "SP1"
    And the sticky navigation contains a link labeled "SP2"
    And the sticky navigation contains a link labeled "SP3"
    And the sticky navigation contains a link labeled "Calls"
    And the sticky navigation contains a link labeled "Manifest"

  Scenario: Sticky nav links anchor to the correct sections
    When I generate the STPA report
    Then the "SP1" nav link points to the SP1 flow card section
    And the "SP2" nav link points to the SP2 flow card section
    And the "SP3" nav link points to the SP3 flow card section
    And the "Calls" nav link points to the LLM call inspector section
    And the "Manifest" nav link points to the run manifest section

  Scenario: Sticky nav appears on scroll via JavaScript
    When I generate the STPA report
    Then the report HTML contains JavaScript that shows the sticky nav on scroll
