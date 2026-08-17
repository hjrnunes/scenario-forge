# output-entry-point-ingress-zone-auto-correction
Feature: Output Entry Point Ingress Zone Auto-correction
  Output-only entry points are not ingress paths. When profile data assigns
  an ingress zone to an output-only entry point, profile validation removes
  the contradictory zone instead of rejecting the profile. Other directions
  retain their declared ingress zones.

  Background:
    Given capability profile entry-point validation is available

  # output-entry-point-ingress-zone-auto-correction-01
  Scenario: output-entry-point-ingress-zone-auto-correction-01 output entry with an ingress zone is corrected
    Given an entry point named "Audit Logs" with direction "<direction>" and ingress zone "reasoning"
    When the entry point is validated
    Then entry-point validation succeeds
    And the resulting entry point has direction "<direction>"
    And the resulting entry point has no ingress zone

    Examples:
      | direction |
      | output    |

  # output-entry-point-ingress-zone-auto-correction-02
  Scenario: output-entry-point-ingress-zone-auto-correction-02 output entry without an ingress zone is preserved
    Given an entry point named "Notifications" with direction "<direction>" and no ingress zone
    When the entry point is validated
    Then entry-point validation succeeds
    And the resulting entry point has direction "<direction>"
    And the resulting entry point has no ingress zone

    Examples:
      | direction |
      | output    |

  # output-entry-point-ingress-zone-auto-correction-03
  Scenario Outline: output-entry-point-ingress-zone-auto-correction-03 non-output ingress zones are preserved
    Given an entry point named "Configured Endpoint" with direction "<direction>" and ingress zone "<ingress_zone>"
    When the entry point is validated
    Then entry-point validation succeeds
    And the resulting entry point has direction "<direction>"
    And the resulting entry point retains ingress zone "<ingress_zone>"

    Examples:
      | direction     | ingress_zone |
      | input         | reasoning    |
      | bidirectional | input        |

  # output-entry-point-ingress-zone-auto-correction-04
  Scenario: output-entry-point-ingress-zone-auto-correction-04 corrected output entry is not effective ingress
    Given an entry point named "Audit Logs" with direction "<direction>" and ingress zone "tool_execution"
    When the entry point is validated
    Then its effective ingress zone is absent
    And it is not an attacker-accessible ingress

    Examples:
      | direction |
      | output    |

  # output-entry-point-ingress-zone-auto-correction-05
  Scenario: output-entry-point-ingress-zone-auto-correction-05 Stage 1 accepts contradictory output ingress data
    Given a Stage 1 profile response containing an entry point named "Audit Logs" with direction "<direction>" and ingress zone "reasoning"
    When Stage 1 capability profile inference validates the response
    Then Stage 1 profile loading succeeds
    And the resulting entry point has direction "<direction>"
    And the resulting entry point has no ingress zone

    Examples:
      | direction |
      | output    |
