# mutation-stamp: sha256=cd4be15b6d7d29b0367c98f1b0a7b4af88edd1c9c6634beba15ccfe230420b01
# acceptance-mutation-manifest-begin
# {"version":1,"tested_at":"2026-08-09T14:08:22.997321Z","feature_name":"SP1 Stage 2 \u2014 Strip empty responsibilities after revision","feature_path":"features/sp1_revision_strip_empty.feature","background_hash":"b2838428c5ee6100a5e0ca6fd3f797e33e40020e1fea2b569761006d26a65fe9","implementation_hash":"unknown","scenarios":[]}
# acceptance-mutation-manifest-end

Feature: SP1 Stage 2 — Strip empty responsibilities after revision
  The Stage 2 revision step sometimes produces skeleton responsibilities
  with a description but no process model parts, no control actions, and
  no feedback channels. Post-revision validation detects and strips these
  empty responsibilities so they do not produce downstream heuristic
  errors. A warning is logged for each stripped responsibility. The
  stripped ControlStructure is what gets written to disk and used
  downstream.

  Background:
    Given the STPA system model revision module is importable
    And a control structure and CriticFindings with unjustified gaps are available

  # SP1-STRIP-01
  Scenario: SP1-STRIP-01 revision with empty responsibilities strips them
    Given an LLM that returns a revised ControlStructure with responsibility RESP-1 having PM parts, CAs, and FB channels
    And the revised ControlStructure also has responsibility RESP-2 with no PM parts, no CAs, and no FB channels
    When the revision is run
    Then the resulting control structure does not contain RESP-2
    And the resulting control structure contains RESP-1

  # SP1-STRIP-02
  Scenario: SP1-STRIP-02 revision with no empty responsibilities keeps all
    Given an LLM that returns a revised ControlStructure where every responsibility has at least one PM part, one CA, and one FB channel
    When the revision is run
    Then all responsibilities are preserved in the resulting control structure

  # SP1-STRIP-03
  Scenario: SP1-STRIP-03 responsibility with some parts is not stripped
    Given an LLM that returns a revised ControlStructure with responsibility RESP-3 having PM parts but no CAs and no FB channels
    When the revision is run
    Then the resulting control structure contains RESP-3

  # SP1-STRIP-04
  Scenario: SP1-STRIP-04 warning logged for each stripped responsibility
    Given an LLM that returns a revised ControlStructure with two empty responsibilities RESP-2 and RESP-4
    When the revision is run
    Then the post-revision warnings include a warning for RESP-2
    And the post-revision warnings include a warning for RESP-4
    And each warning contains the resp_id and description

  # SP1-STRIP-05
  Scenario: SP1-STRIP-05 stripped control structure passes validation
    Given an LLM that returns a revised ControlStructure with empty responsibility RESP-7
    When the revision is run
    Then the resulting control structure does not contain RESP-7
    And the resulting control structure has at least one responsibility

  # SP1-STRIP-06
  Scenario: SP1-STRIP-06 responsibility with only responsibility_constraints but no PM CA or FB is stripped
    Given an LLM that returns a revised ControlStructure with responsibility RESP-5 having responsibility_constraints but no PM parts, no CAs, and no FB channels
    When the revision is run
    Then the resulting control structure does not contain RESP-5
