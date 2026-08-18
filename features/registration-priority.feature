# registration-priority
Feature: Registration priority semantics
  The acceptance runtime uses two registration functions with distinct
  priority semantics. _register appends to the end of STEP_PATTERNS
  (lowest priority, always global and untagged). _register_first inserts
  at index 0 (highest priority, tagged with the current feature tag).
  Lookup takes the first matching pattern, so _register_first always
  beats _register regardless of source line order.

  Among multiple _register_first calls for the same pattern, the LAST
  executed call wins because it inserts at index 0, pushing earlier
  _register_first registrations to higher indices. Among multiple
  _register calls for the same pattern, the FIRST executed call wins
  because it was appended earlier and appears earlier in the list.

  Background:
    Given the acceptance runtime module is importable

  # ShadowCleanup-06
  Scenario: ShadowCleanup-06 _register_first beats _register regardless of line order
    Given a pattern <pattern> is registered with _register by handler handler_a at an earlier line
    And the same pattern <pattern> is registered with _register_first by handler handler_b at a later line
    Then handler handler_b is the live handler for step text matching <pattern>

    Examples:
      | pattern |
      | the revision is run |

  # ShadowCleanup-07
  Scenario: ShadowCleanup-07 among _register_first calls the last executed wins
    Given a pattern <pattern> is registered with _register_first by handler handler_a
    And the same pattern <pattern> is registered with _register_first by handler handler_b
    Then handler handler_b is the live handler for step text matching <pattern>

    Examples:
      | pattern |
      | the revision is run |

  # ShadowCleanup-08
  Scenario: ShadowCleanup-08 among _register calls the first executed wins
    Given a pattern <pattern> is registered with _register by handler handler_a
    And the same pattern <pattern> is registered with _register by handler handler_b
    Then handler handler_a is the live handler for step text matching <pattern>

    Examples:
      | pattern |
      | the heuristic check fails with error containing something |
