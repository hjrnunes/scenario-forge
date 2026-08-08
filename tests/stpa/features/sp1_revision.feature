Feature: SP1 Stage 2 — Revision
  If the completeness critic identifies unjustified gaps, a single revision
  LLM call modifies the control structure to address them. This is not a loop:
  one revision attempt maximum. After revision, structural heuristics are
  re-run. If structural errors remain, they are flagged in the run manifest
  but the pipeline proceeds.

  Background:
    Given the STPA system model revision module is importable
    And a control structure and CriticFindings with unjustified gaps are available

  # SP1-REV-01
  Scenario: SP1-REV-01 revision call produces a valid ControlStructure
    Given an LLM that returns a revised ControlStructure JSON with an added responsibility
    When the revision is run
    Then a revised ControlStructure model is produced
    And the revised control structure passes foundation validation

  # SP1-REV-02
  Scenario: SP1-REV-02 revision call is logged with stage stage_2 and step revision
    Given an LLM that returns a revised ControlStructure JSON
    And a run directory for call logging
    When the revision is run
    Then a call log entry is appended with stage stage_2
    And the call log entry step is revision

  # SP1-REV-03
  Scenario: SP1-REV-03 revision receives current control structure and critic findings
    Given an LLM that returns a revised ControlStructure JSON
    When the revision is run
    Then the user prompt contains the current control structure
    And the user prompt contains the critic findings

  # SP1-REV-04
  Scenario: SP1-REV-04 structural heuristics are re-run after revision
    Given an LLM that returns a revised ControlStructure JSON
    When the revision is run
    Then structural heuristics are re-run on the revised control structure

  # SP1-REV-05
  Scenario: SP1-REV-05 only one revision attempt is made
    Given a critic that identifies unjustified gaps
    And an LLM that returns a revised ControlStructure that still has gaps
    When the revision is run
    Then no second revision call is made

  # SP1-REV-06
  Scenario: SP1-REV-06 no revision when critic finds no unjustified gaps
    Given a critic that finds only justified gaps or no gaps
    When the completeness critic is run
    Then no revision call is made

  # SP1-REV-07
  Scenario: SP1-REV-07 structural errors after revision are flagged in run manifest
    Given an LLM that returns a revised ControlStructure with a missing process model part
    When the revision is run
    Then the structural error is recorded in the run manifest
    And the pipeline proceeds without a second revision

  # SP1-REV-08
  Scenario: SP1-REV-08 revised control structure replaces the original
    Given an LLM that returns a revised ControlStructure with an added responsibility RESP-3
    When the revision is run
    Then the final control structure contains RESP-3
    And the final control structure does not lose existing responsibilities
