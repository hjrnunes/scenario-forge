# mutation-stamp: sha256=f91984c0c1c5b525b13148cddc8d34f0eea052943f7c2f5a342876e27dced29c
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-08T18:22:38.748293Z","feature_name":"SP1 \u2014 Graceful degradation for recoverable LLM failures","feature_path":"features/sp1_graceful_degradation_recoverable.feature","background_hash":"8fd23737835163fe074e6c18bc781fa2bea2e109afaa4112861c1680ffed4969","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 — Graceful degradation for recoverable LLM failures
  If the completeness critic or revision LLM call fails validation or
  raises an exception, the pipeline degrades gracefully instead of crashing.
  The critic returns empty CriticFindings; revision returns the pre-revision
  control structure with a warning. In both cases, the failed call is logged
  with success=false and an error message. The pipeline proceeds to completion.

  Background:
    Given the STPA system model critic module is importable
    And a control structure that passed Call 3 validation is available
    And a capability profile and use-case text are available
    And a run directory for call logging

  # SP1-GD-01
  Scenario: SP1-GD-01 revision validation failure returns pre-revision CS with warning
    Given an LLM that returns an invalid ControlStructure JSON with cross-reference violations
    And critic findings with unjustified gaps
    When the revision is run
    Then the pre-revision ControlStructure is returned
    And the returned warnings include a revision failure message
    And the pipeline does not crash

  # SP1-GD-02
  Scenario: SP1-GD-02 revision failure logs the failed call with success=false
    Given an LLM that returns an invalid ControlStructure JSON
    And critic findings with unjustified gaps
    When the revision is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is revision
    And the call log entry success is false
    And the call log entry has an error message field

  # SP1-GD-03
  Scenario: SP1-GD-03 revision LLM exception returns pre-revision CS with warning
    Given an LLM that raises a RuntimeError during the revision call
    And critic findings with unjustified gaps
    When the revision is run
    Then the pre-revision ControlStructure is returned
    And the returned warnings include a revision failure message
    And a call log entry is appended with stage stage_2
    And the call log entry step is revision
    And the call log entry success is false
    And the call log entry has an error message field

  # SP1-GD-04
  Scenario: SP1-GD-04 critic validation failure returns empty CriticFindings
    Given an LLM that returns an invalid CriticFindings JSON
    When the completeness critic is run
    Then an empty CriticFindings model is returned
    And the gaps list is empty
    And the checklist_results dict is empty
    And the taxonomy_probe_results dict is empty
    And the pipeline does not crash

  # SP1-GD-05
  Scenario: SP1-GD-05 critic failure logs the failed call with success=false
    Given an LLM that returns an invalid CriticFindings JSON
    When the completeness critic is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is critic
    And the call log entry success is false
    And the call log entry has an error message field

  # SP1-GD-06
  Scenario: SP1-GD-06 critic failure does not trigger revision
    Given an LLM that returns an invalid CriticFindings JSON
    When the completeness critic is run
    Then revision is not triggered
    And no revision call is made

  # SP1-GD-07
  Scenario: SP1-GD-07 critic LLM exception returns empty CriticFindings
    Given an LLM that raises a RuntimeError during the critic call
    When the completeness critic is run
    Then an empty CriticFindings model is returned
    And a call log entry is appended with stage stage_2
    And the call log entry step is critic
    And the call log entry success is false
    And the call log entry has an error message field
