# class-b-decisions
Feature: Class B handler decisions exhibit correct behavior
  For each of the 12 Class B cases where the live handler is materially
  smaller than the dead handler it shadows, the chosen (live) handler
  must exhibit the behavior that justifies keeping it over the dead
  one. Each scenario sets up world state, executes the step text, and
  verifies the distinguishing behavior.

  Decision summary:
  - Cases 1-2: live handler delegates to the real _sp1_derive_control_structure
    integration; dead handler uses manual mock calls with hardcoded prompts.
  - Cases 3-4: live handler wraps the revision chain with log capture; dead
    handlers are called internally via delegation, only their registrations
    are dead.
  - Case 5: live handler uses _FC_PROMPTS_DIR directly; dead handler falls
    back to world.template_dir which may point elsewhere.
  - Case 6: both handlers are functionally identical; live handler was
    registered with higher priority.
  - Case 7: live handler checks heuristic_result.passed is False; dead
    handler only checks errors list is non-empty.
  - Case 8: live handler uses SP1 helper; dead handler uses SP3 helper
    with unnecessary conditional RESP-2 logic.
  - Case 9: live handler checks SP1 mock client prompt; dead handler
    checks SP2 LLM client which may not be set in SP1 context.
  - Case 10: live handler is a no-op (correct for graceful-degradation
    "reached this step" semantics); dead handler conflates "did not
    crash" with "produced valid output".
  - Case 11: live handler checks enriched_threat_set model attribute;
    dead handler checks sp3_coverage dict which may not be populated.
  - Case 12: live handler checks in-memory scorecard dict; dead handler
    reads eval-scorecard.yaml from disk requiring file I/O.

  Background:
    Given the acceptance runtime module is importable

  # ShadowCleanup-11 — Case 1
  Scenario: ShadowCleanup-11 Stage 2 calls 1 through 3 live handler produces a control structure via integrated derivation
    Given a use-case description and loss analysis are available
    And an LLM that returns valid responses for Stage 2 calls 1, 2a, and 2b
    When Stage 2 calls 1 through 3 are run in sequence
    Then a ControlStructure model is produced
    But the control structure is not produced by manual mock call sequencing

  # ShadowCleanup-12 — Case 2
  Scenario: ShadowCleanup-12 Stage 2 control structure derivation live handler uses the real derivation function with template loader
    Given a use-case description and loss analysis are available
    And an LLM that returns valid responses for all four Stage 2 calls
    When Stage 2 control structure derivation is run
    Then a ControlStructure model is produced
    And the control structure was derived with a TemplateLoader

  # ShadowCleanup-13 — Cases 3 and 4
  Scenario: ShadowCleanup-13 the revision is run live handler wraps the revision chain with log capture
    Given a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And an LLM that returns a valid RevisionDelta
    When the revision is run
    Then a revised ControlStructure model is produced
    And the critic logger had a log capture handler installed during revision

  # ShadowCleanup-14 — Case 5
  Scenario: ShadowCleanup-14 TemplateLoader live handler creates a loader pointing at the FC prompts directory
    Given the STPA system model prompts directory is available
    When the TemplateLoader can load templates from the prompts directory
    Then the world template_loader is a TemplateLoader instance
    And the template loader source directory is the FC prompts directory

  # ShadowCleanup-15 — Case 6
  Scenario: ShadowCleanup-15 file exists live handler checks the run directory
    Given a run directory for call logging
    Then the handler returns false with a file-not-found message

  # ShadowCleanup-16 — Case 7
  Scenario: ShadowCleanup-16 heuristic check fails live handler verifies the heuristic actually failed
    Given a heuristic result that passed
    Then the handler returns false because the heuristic passed

  # ShadowCleanup-17 — Case 8
  Scenario: ShadowCleanup-17 control structure with RESP-1 live handler uses the SP1 helper
    Given the acceptance runtime module is importable
    When a control structure with responsibility RESP-1 is available
    Then the world control structure has responsibility RESP-1
    And the control structure was created by the SP1 helper function

  # ShadowCleanup-18 — Case 9
  Scenario: ShadowCleanup-18 user prompt contains control structure live handler checks the SP1 mock client
    Given an LLM that returns a valid CriticFindings JSON
    And the SP1 mock client has no calls recorded
    When the user prompt contains the control structure
    Then the handler returns true because no calls were made

  # ShadowCleanup-19 — Case 10
  Scenario: ShadowCleanup-19 pipeline does not crash live handler is a no-op pass
    Given the acceptance runtime module is importable
    When the pipeline does not crash
    Then the handler returns true unconditionally

  # ShadowCleanup-20 — Case 11
  Scenario: ShadowCleanup-20 uncovered_reason live handler checks the enriched threat set coverage analysis
    Given an enriched threat set with an empty uncovered_reason
    Then the handler returns false because uncovered_reason is empty

  # ShadowCleanup-21 — Case 12
  Scenario: ShadowCleanup-21 scorecard validation section live handler checks the in-memory scorecard dict
    Given the in-memory scorecard has a validation section with 2 stage_local_errors
    When the scorecard validation section has 2 stage_local_errors
    Then the handler returns true
    But the handler does not read eval-scorecard.yaml from disk
