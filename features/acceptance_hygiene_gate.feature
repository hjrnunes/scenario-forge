Feature: Acceptance hygiene gate
  The project enforces Ruff lint and format checks on both production source
  (`src/`) and acceptance code (`acceptance/`) through a single quality entry
  point. The acceptance test runner cannot bypass this gate. CRAP, DRY, and
  mutation scope remains `src/` only — acceptance handlers are not covered by
  those tools.

  Background:
    Given the project quality entry point is available

  # AHG-01
  Scenario: AHG-01 quality script runs Ruff check on src and acceptance
    When the quality script is invoked
    Then Ruff check runs against src
    And Ruff check runs against acceptance

  # AHG-02
  Scenario: AHG-02 quality script runs Ruff format check on src and acceptance
    When the quality script is invoked
    Then Ruff format check runs against src
    And Ruff format check runs against acceptance

  # AHG-03
  Scenario: AHG-03 acceptance test path enforces the hygiene gate before tests
    When the acceptance test entry point is invoked with --test
    Then the hygiene gate runs before generated acceptance tests
    And generated acceptance tests are not executed if the hygiene gate fails

  # AHG-04
  Scenario: AHG-04 acceptance code is Ruff-clean
    Then Ruff check on acceptance reports zero findings

  # AHG-05
  Scenario: AHG-05 acceptance code is Ruff-formatted
    Then Ruff format check on acceptance reports zero files needing reformatting

  # AHG-06
  Scenario: AHG-06 CRAP DRY and mutation scope is src only
    Then the configured CRAP command targets src
    And the configured DRY command targets src
    And the configured mutation command targets src
    And acceptance handlers are not included in CRAP DRY or mutation scope

  # AHG-07
  Scenario: AHG-07 runtime manifest loads and registers handlers
    When the acceptance runtime manifest is loaded
    Then every runtime feature module is importable
    And every registered handler has a valid step pattern
    And handler registration does not raise

  # AHG-08
  Scenario: AHG-08 generated-output paths remain unchanged
    Then features map to build/acceptance/ir
    And build/acceptance/ir maps to build/acceptance/generated
    And build/acceptance/generated contains metadata with relative paths
    And no generated artifacts are committed to git
