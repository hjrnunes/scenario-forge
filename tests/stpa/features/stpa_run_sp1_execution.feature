Feature: STPA Run — SP1 execution
  The stpa-run command executes SP1 as the first stage, passing use-case
  text, risk cards, and an optional pre-built capability profile. SP1
  produces loss-analysis.yaml, capability-profile.yaml,
  control-structure.yaml, calls.jsonl, and run-manifest.yaml, and
  auto-renders calls.html.

  Background:
    Given the stpa-run pipeline runner module is importable
    And a use-case text file and risk extraction JSON are available
    And an output directory exists

  # STPA-RUN-SP1-01
  Scenario: STPA-RUN-SP1-01 SP1 runs and writes all expected artifacts
    Given an LLM that returns valid responses for all SP1 stages
    When the stpa-run command is invoked with all required flags
    Then a file loss-analysis.yaml exists in the output directory
    And a file capability-profile.yaml exists in the output directory
    And a file control-structure.yaml exists in the output directory
    And a file calls.jsonl exists in the output directory
    And a file run-manifest.yaml exists in the output directory

  # STPA-RUN-SP1-02
  Scenario: STPA-RUN-SP1-02 calls.html is auto-rendered from calls.jsonl
    Given an LLM that returns valid responses for all SP1 stages
    When the stpa-run command is invoked with all required flags
    Then a file calls.html exists in the output directory

  # STPA-RUN-SP1-03
  Scenario: STPA-RUN-SP1-03 use-case text is read and passed to SP1
    Given a use-case file containing "My agentic system use case"
    When the stpa-run command is invoked with all required flags
    Then the SP1 run receives the use-case text "My agentic system use case"

  # STPA-RUN-SP1-04
  Scenario: STPA-RUN-SP1-04 risk cards are loaded and passed to SP1
    Given a risk extraction JSON with 5 risk cards
    When the stpa-run command is invoked with all required flags
    Then the SP1 run receives 5 risk cards

  # STPA-RUN-SP1-05
  Scenario: STPA-RUN-SP1-05 --capability-profile skips SP1 Stage 1b
    Given an LLM that returns valid responses for Stage 1a and Stage 2
    And a pre-built capability-profile.yaml at a known path
    When the stpa-run command is invoked with --capability-profile <path>
    Then the SP1 run receives the profile path
    And no call log entry has stage stage_1b

  # STPA-RUN-SP1-06
  Scenario: STPA-RUN-SP1-06 --max-workers is forwarded to SP1
    Given an LLM that returns valid responses for all SP1 stages
    When the stpa-run command is invoked with --max-workers 4
    Then the SP1 run is executed with max_workers 4
