# duplicate-assertion
Feature: Exact-duplicate registration is rejected at import time
  The _track_registration function records every (pattern, handler,
  scope) tuple in _REGISTERED_PATTERN_KEYS. If the same tuple is
  registered more than once, a RuntimeError is raised at import time,
  before any test executes. This catches the most obvious shadowing
  bug: the same pattern and handler registered twice in the same scope.

  A different handler with the same pattern in the same scope is a
  more subtle shadowing bug detected at test time by
  find_pattern_conflicts, not by _track_registration.

  Background:
    Given the acceptance runtime module is importable

  # ShadowCleanup-09
  Scenario: ShadowCleanup-09 exact duplicate registration raises RuntimeError
    When a pattern <pattern> is registered with handler <handler> in global scope
    Then registering the same pattern <pattern> with handler <handler> in global scope raises RuntimeError

    Examples:
      | pattern | handler |
      | a test step | _h_test_handler |

  # ShadowCleanup-10
  Scenario: ShadowCleanup-10 the registered keys count equals the step patterns count
    Then the number of entries in _REGISTERED_PATTERN_KEYS equals the length of STEP_PATTERNS
