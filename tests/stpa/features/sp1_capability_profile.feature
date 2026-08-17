Feature: SP1 Stage 1b — Capability Profile inference
  Stage 1b produces a CapabilityProfile via a new STPA-conditioned prompt
  that receives the LossAnalysis from Stage 1a as context. The LLM produces
  a Stage1Profile (slim model), which is promoted to a full CapabilityProfile
  via to_capability_profile(). The --profile flag skips the LLM call and
  loads a pre-built profile instead.

  Background:
    Given the STPA system model module is importable
    And a use-case description and loss analysis are available as input

  # SP1-CP-01
  Scenario: SP1-CP-01 valid LLM response produces a valid CapabilityProfile
    Given an LLM that returns a valid Stage1Profile JSON with zones, entry_points, and kc_subcodes
    When Stage 1b capability profile is run
    Then a CapabilityProfile model is produced
    And the capability profile has zones derived from kc_subcodes
    And the capability profile entry_point_completeness is inferred_partial

  # SP1-CP-02
  Scenario: SP1-CP-02 Stage1Profile is promoted via to_capability_profile
    Given an LLM that returns a valid Stage1Profile JSON
    When Stage 1b capability profile is run
    Then the Stage1Profile is promoted to a CapabilityProfile
    And the promoted profile has zones_active derived from kc_subcodes
    And the promoted profile has has_persistent_memory derived from kc_subcodes

  # SP1-CP-03
  Scenario: SP1-CP-03 profile flag skips the LLM call
    Given a pre-built capability-profile.yaml at a known path
    When Stage 1b is run with the profile flag
    Then no LLM call is made for Stage 1b
    And the loaded CapabilityProfile is returned

  # SP1-CP-04
  Scenario: SP1-CP-04 profile flag still produces loss analysis from Stage 1a
    Given a pre-built capability-profile.yaml at a known path
    And a use-case description and risk cards are available
    When the full SP1 run is executed with the profile flag
    Then a LossAnalysis is produced from Stage 1a
    And no LLM call is made for Stage 1b
    And the pre-built CapabilityProfile is loaded

  # SP1-CP-05
  Scenario: SP1-CP-05 LLM call is logged with stage stage_1b
    Given an LLM that returns a valid Stage1Profile JSON
    And a run directory for call logging
    When Stage 1b capability profile is run
    Then a call log entry is appended with stage stage_1b
    And the call log entry step is capability_profile

  # SP1-CP-06
  Scenario: SP1-CP-06 capability profile is written to capability-profile.yaml
    Given an LLM that returns a valid Stage1Profile JSON
    And a run directory for output
    When Stage 1b capability profile is run
    Then a file capability-profile.yaml exists in the run directory
    And the file contains a valid CapabilityProfile model when read back

  # SP1-CP-07
  Scenario: SP1-CP-07 invalid KC sub-codes in LLM response fail validation
    Given an LLM that returns a Stage1Profile with invalid KC sub-code KC9.9
    When Stage 1b capability profile is run
    Then validation fails with error containing Invalid KC sub-code

  # SP1-CP-08
  Scenario: SP1-CP-08 loss analysis context is passed to the prompt
    Given an LLM that returns a valid Stage1Profile JSON
    And a loss analysis with losses L-1 and L-2 and hazards H-1 and H-2
    When Stage 1b capability profile is run
    Then the user prompt contains loss analysis context
    And the user prompt references losses and hazards from the loss analysis
