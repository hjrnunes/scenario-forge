# no-shadowing-invariant
Feature: No same-scope pattern shadowing after cleanup
  The acceptance runtime maintains an ordered STEP_PATTERNS list.
  Lookup takes the first match. When two patterns in the same scope
  register the same raw pattern with different handlers, only the first
  handler executes; the rest is dead code. After the shadowed-registration
  cleanup, no same-scope raw pattern has conflicting handlers. The IR corpus
  and synthetic texts provide witnesses for the duplicate registrations.

  The find_pattern_conflicts function is the verification mechanism:
  it returns a list of (step_text, first_pattern, second_pattern)
  tuples for every same-scope raw pattern with conflicting handlers. An
  empty list means the invariant holds.

  Background:
    Given the acceptance runtime module is importable

  # ShadowCleanup-01
  Scenario: ShadowCleanup-01 no global pattern conflicts on IR step texts
    When all example-expanded step texts from every IR file are collected
    Then find_pattern_conflicts returns an empty list for those step texts

  # ShadowCleanup-02
  Scenario: ShadowCleanup-02 no global pattern conflicts on synthetic step texts
    When synthetic step texts covering known shadowing prefixes are collected
    Then find_pattern_conflicts returns an empty list for those step texts

  # ShadowCleanup-03
  Scenario: ShadowCleanup-03 no per-feature tagged pattern conflicts on IR step texts
    When all example-expanded step texts from every IR file are collected
    Then find_pattern_conflicts returns an empty list for per-feature tagged patterns

  # ShadowCleanup-04
  Scenario: ShadowCleanup-04 the xfail markers on the two property tests are removed
    Given the property test file test_acceptance_harness_property.py is inspected
    Then test_no_global_pattern_conflicts_on_ir_steps has no xfail marker
    And test_no_global_pattern_conflicts_on_synthetic_steps has no xfail marker

  # ShadowCleanup-05
  Scenario: ShadowCleanup-05 the unmarked property tests are not strict xfail
    Given the two property tests have their xfail markers removed
    Then the tests pass rather than xpass
    And the tests are not marked with strict=False
