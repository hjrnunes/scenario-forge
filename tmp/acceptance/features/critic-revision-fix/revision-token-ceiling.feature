# critic-revision-fix / revision-token-ceiling
Feature: SP1 Stage 2 — Revision completion-token ceiling
  The Stage 2 revision LLM call is capped by
  REVISION_MAX_COMPLETION_TOKENS in critic.py. At 4096 the cap was below
  the size of a RevisionDelta carrying full Responsibility objects
  (nested RCs, PM parts with feedback sources, CAs with targets, FB
  channels with sources and updates). Three production runs on
  2026-08-10 — Klarna (prompt_tokens 1530), Airbnb (2059), and OcciAI
  (2083) — each terminated with LengthFinishReasonError at exactly
  completion_tokens 4096, so revision succeeded 0 times out of 3.

  The delta-only output format is correct; only the cap was wrong. The
  ceiling is raised to 8192. Everything else about the call is
  unchanged: the cap is still forwarded to the LLM client through
  safe_llm_call, and a truncation failure still degrades gracefully to
  the pre-revision control structure with a warning instead of aborting
  the run.

  Background:
    Given the STPA system model critic module is importable
    And a control structure with responsibilities RESP-1 and RESP-2 is available
    And CriticFindings with unjustified gaps are available
    And a run directory for call logging

  # CRTok-01
  Scenario: CRTok-01 the revision completion-token ceiling constant is 8192
    Then the critic module constant REVISION_MAX_COMPLETION_TOKENS equals 8192

  # CRTok-02
  Scenario: CRTok-02 run_revision forwards the raised ceiling to the LLM client
    Given an LLM that returns a valid RevisionDelta
    When the revision is run
    Then the LLM complete call is made with max_completion_tokens 8192

  # CRTok-03
  Scenario Outline: CRTok-03 a revision response larger than the old ceiling is accepted
    Given an LLM that returns a RevisionDelta reporting completion_tokens <completion_tokens>
    When the revision is run
    Then the revision succeeds without a truncation warning
    And a revised ControlStructure model is produced

    Examples:
      | completion_tokens |
      | 4097              |
      | 6000              |
      | 8192              |

  # CRTok-04
  Scenario: CRTok-04 a truncated revision still degrades gracefully
    Given an LLM whose revision call raises LengthFinishReasonError
    When the revision is run
    Then the returned ControlStructure is the pre-revision control structure
    And the pipeline does not crash
    And the warnings list includes a warning that mentions LengthFinishReasonError

  # CRTok-05
  Scenario: CRTok-05 the raised ceiling does not change the critic call budget
    Given a capability profile and use-case text are available
    And an LLM that returns a valid CriticFindings JSON
    When the completeness critic is run
    Then the LLM complete call is made without a max_completion_tokens cap
